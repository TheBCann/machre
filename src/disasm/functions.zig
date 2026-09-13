//! disasm/functions.zig — function discovery (function starts > symbols > exports > entry/ObjC IMPs > tertiary).
//! Imports: core/image, core/limits, core/diag, macho/symbols, macho/function_starts, macho/dyld_exports, objc/objc, disasm/insn.
//!
//! Discovery order and naming priority are DESIGN.md §9. Every source only ADDS starts; the `sources`
//! bitset records all of them, `source` the first (highest-priority) one and `name_source` where the name
//! came from. Tertiary heuristics run only when `LC_FUNCTION_STARTS` is absent or `aggressive` is set, so
//! a well-formed binary never pays for them. Everything is bounded by `limits.max_functions` and by the
//! section sizes; no read escapes `Image`'s accessors.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Section = @import("../core/image.zig").Section;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const symbols = @import("../macho/symbols.zig");
const FunctionStarts = @import("../macho/function_starts.zig").FunctionStarts;
const ExportTrie = @import("../macho/dyld_exports.zig").ExportTrie;
const objc_mod = @import("../objc/objc.zig");
const ObjcInfo = objc_mod.ObjcInfo;

pub const Source = enum { function_starts, symbol, export_trie, entry, objc, call_target, unwind, jump_table, heuristic };

/// `sources` bit for one discovery source.
pub fn sourceBit(s: Source) u16 {
    return @as(u16, 1) << @intFromEnum(s);
}

pub const Function = struct {
    start: u64,
    end: u64, // exclusive, best effort (next start in the section, or section end)
    name: []const u8, // symbol | export | "-[Class sel]" | "sub_100000524"
    source: Source, // where the START came from
    name_source: Source,
    section: ?u16,
    sources: u16, // bitset of Source

    pub fn size(f: Function) u64 {
        return if (f.end > f.start) f.end - f.start else 0;
    }
    pub fn hasSource(f: Function, s: Source) bool {
        return f.sources & sourceBit(s) != 0;
    }
    /// True when the name was synthesized from the address ("sub_1000004f8").
    pub fn synthetic(f: Function) bool {
        return f.name_source == .heuristic;
    }
};

pub const FunctionTable = struct {
    functions: []const Function, // sorted by start, non-overlapping
    truncated: bool,
    pub const empty: FunctionTable = .{ .functions = &.{}, .truncated = false };

    /// Last function whose `start <= addr` and whose range covers `addr`.
    pub fn containing(t: *const FunctionTable, addr: u64) ?*const Function {
        const i = t.upperBound(addr);
        if (i == 0) return null;
        const f = &t.functions[i - 1];
        if (addr < f.end or (f.end == f.start and addr == f.start)) return f;
        return null;
    }
    pub fn byName(t: *const FunctionTable, name: []const u8) ?*const Function {
        for (t.functions) |*f| if (std.mem.eql(u8, f.name, name)) return f;
        return null;
    }
    pub fn byStart(t: *const FunctionTable, addr: u64) ?*const Function {
        const i = t.upperBound(addr);
        if (i == 0) return null;
        const f = &t.functions[i - 1];
        return if (f.start == addr) f else null;
    }
    /// Index of the first function whose start is > `addr`.
    fn upperBound(t: *const FunctionTable, addr: u64) usize {
        var lo: usize = 0;
        var hi: usize = t.functions.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.functions[mid].start <= addr) lo = mid + 1 else hi = mid;
        }
        return lo;
    }
};

pub const Inputs = struct {
    syms: *const symbols.SymbolTable,
    index: *const symbols.AddressIndex,
    starts: ?*const FunctionStarts,
    trie: ?*const ExportTrie,
    objc: ?*const ObjcInfo,
    aggressive: bool = false,
};

// ---------------------------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------------------------

const Cand = struct { start: u64, source: Source, sources: u16, section: ?u16 };

const Builder = struct {
    arena: Allocator,
    img: *const Image,
    limits: *const Limits,
    list: std.ArrayList(Cand) = .empty,
    seen: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    truncated: bool = false,

    fn add(b: *Builder, addr: u64, source: Source) Allocator.Error!void {
        const sect = codeSectionOf(b.img, addr) orelse return;
        const g = try b.seen.getOrPut(b.arena, addr);
        if (g.found_existing) {
            b.list.items[g.value_ptr.*].sources |= sourceBit(source);
            return;
        }
        if (b.list.items.len >= b.limits.max_functions) {
            b.truncated = true;
            _ = b.seen.remove(addr);
            return;
        }
        g.value_ptr.* = @intCast(b.list.items.len);
        try b.list.append(b.arena, .{ .start = addr, .source = source, .sources = sourceBit(source), .section = sect.index });
    }
    fn has(b: *const Builder, addr: u64) bool {
        return b.seen.contains(addr);
    }
};

/// First executable, non-zerofill section containing `addr`.
fn codeSectionOf(img: *const Image, addr: u64) ?*const Section {
    for (img.sections) |*s| {
        if (!s.isCode() or s.isZerofill()) continue;
        if (s.containsVm(addr)) return s;
    }
    return null;
}

fn sectionByIndex(img: *const Image, index: ?u16) ?*const Section {
    const i = index orelse return null;
    if (i == 0 or i > img.sections.len) return null;
    return &img.sections[i - 1];
}

fn lessByStart(_: void, a: Cand, b: Cand) bool {
    return a.start < b.start;
}

/// `external` is the incumbent's own externality, which the tie-break below needs and which cannot be
/// recovered from the name (a `.objc`/`.export_trie` hit has no n_type at all).
const NameHit = struct { name: []const u8, source: Source, external: bool };

pub fn discover(arena: Allocator, img: *const Image, in: Inputs, limits: *const Limits, diags: *Diagnostics) Allocator.Error!FunctionTable {
    var b: Builder = .{ .arena = arena, .img = img, .limits = limits };
    var names: std.AutoHashMapUnmanaged(u64, NameHit) = .empty;

    // (1) LC_FUNCTION_STARTS — already restricted to __TEXT by macho/function_starts.zig.
    if (in.starts) |fs| for (fs.addrs) |a| try b.add(a, .function_starts);

    // (2) defined non-stab N_SECT symbols that land in a code section.
    for (in.syms.symbols) |s| {
        if (s.isStab() or s.kind() != .section) continue;
        if (s.name.len == 0) continue;
        if (codeSectionOf(img, s.n_value) == null) continue;
        try b.add(s.n_value, .symbol);
        try noteName(arena, &names, s.n_value, s.name, .symbol, s.isExternal());
    }

    // (3) export-trie entries in code sections.
    if (in.trie) |t| for (t.exports) |x| {
        if (x.reexport != null or x.address == 0) continue;
        if (codeSectionOf(img, x.address) == null) continue;
        try b.add(x.address, .export_trie);
        try noteName(arena, &names, x.address, x.name, .export_trie, false);
    };

    // (4) LC_MAIN / LC_UNIXTHREAD entry.
    if (img.entryVm()) |e| try b.add(e, .entry);

    // (5) ObjC method IMPs.
    if (in.objc) |o| {
        const imps = try objc_mod.methodImps(arena, o);
        for (imps) |imp| {
            try b.add(imp.imp, .objc);
            try noteName(arena, &names, imp.imp, imp.name, .objc, false);
        }
    }

    // (6) tertiary — only when the linker table is missing or the caller asked for it.
    if (in.starts == null or in.aggressive) {
        try unwindStarts(&b, diags);
        try scanCode(&b, diags);
    }

    const cands = try b.list.toOwnedSlice(arena);
    std.mem.sort(Cand, cands, {}, lessByStart);

    const out = try arena.alloc(Function, cands.len);
    for (cands, 0..) |c, i| {
        const sect = sectionByIndex(img, c.section);
        var end: u64 = c.start;
        const sect_end: u64 = if (sect) |s| s.addr +| s.size else c.start;
        if (i + 1 < cands.len and cands[i + 1].start > c.start and cands[i + 1].start <= sect_end) {
            end = cands[i + 1].start;
        } else {
            end = @max(c.start, sect_end);
        }
        var name: []const u8 = "";
        var name_source: Source = .heuristic;
        if (names.get(c.start)) |hit| {
            name = hit.name;
            name_source = hit.source;
        } else if (c.sources & sourceBit(.entry) != 0) {
            name = "entry";
            name_source = .entry;
        } else {
            name = try std.fmt.allocPrint(arena, "sub_{x}", .{c.start});
            name_source = .heuristic;
        }
        out[i] = .{
            .start = c.start,
            .end = end,
            .name = name,
            .source = c.source,
            .name_source = name_source,
            .section = c.section,
            .sources = c.sources,
        };
    }
    if (b.truncated and !diags.has(.functions, .limit_reached))
        diags.warn(.functions, .limit_reached, null, "function table clamped to limits.max_functions {d}", .{limits.max_functions});
    return .{ .functions = out, .truncated = b.truncated };
}

/// Records the best name for `addr`: symbol > export > objc; an external symbol beats a local one.
fn noteName(arena: Allocator, names: *std.AutoHashMapUnmanaged(u64, NameHit), addr: u64, name: []const u8, source: Source, external: bool) Allocator.Error!void {
    if (name.len == 0) return;
    const g = try names.getOrPut(arena, addr);
    if (!g.found_existing) {
        g.value_ptr.* = .{ .name = name, .source = source, .external = external };
        return;
    }
    const cur = g.value_ptr.*;
    if (rank(source) < rank(cur.source)) {
        g.value_ptr.* = .{ .name = name, .source = source, .external = external };
        return;
    }
    // Same rank: prefer an external symbol over a local one (both are `.symbol`). The test is the
    // INCUMBENT'S EXTERNALITY; it used to read `cur.name[0] != '_'`, which tests the incumbent's
    // leading character instead — and since essentially every Mach-O C symbol is `_`-prefixed, the
    // clause almost never fired, so a local symbol that happened to be listed first kept the address
    // and this table disagreed with `AddressIndex.at` (which resolves the same tie the other way, by
    // sorting external first). That made `disasm` print a LABEL naming one symbol above a branch whose
    // OPERAND named the other. With the incumbent's own flag stored, the two rules now agree: first
    // external in symtab order, else first local.
    if (rank(source) == rank(cur.source) and source == .symbol and external and !cur.external) {
        g.value_ptr.* = .{ .name = name, .source = source, .external = external };
    }
}
fn rank(s: Source) u8 {
    return switch (s) {
        .symbol => 0,
        .export_trie => 1,
        .objc => 2,
        else => 3,
    };
}

// ---------------------------------------------------------------------------------------------
// tertiary discovery
// ---------------------------------------------------------------------------------------------

/// `__TEXT,__unwind_info` first-level index entries: each names a function start as an offset from the
/// mach header. The last entry is a sentinel (functionOffset == end of the last range).
fn unwindStarts(b: *Builder, diags: *Diagnostics) Allocator.Error!void {
    const sect = b.img.sectionByClass(.unwind) orelse return;
    const r = b.img.sectionReader(sect) orelse return;
    const e = b.img.hdr.endian;
    const version = r.u32At(0, e) orelse return;
    if (version != 1) {
        if (!diags.has(.functions, .version_unsupported))
            diags.info(.functions, .version_unsupported, sect.offset, "__unwind_info version {d} not understood; first-level entries skipped", .{version});
        return;
    }
    const index_off = r.u32At(20, e) orelse return;
    const index_count = r.u32At(24, e) orelse return;
    const capped = @min(index_count, b.limits.max_functions);
    var i: u32 = 0;
    while (i < capped) : (i += 1) {
        const off: u64 = @as(u64, index_off) + @as(u64, i) * 12;
        const fn_off = r.u32At(off, e) orelse break;
        try b.add(b.img.image_base +| fn_off, .unwind);
    }
}

const arm64_pac_prologues = [_]u32{
    0xd503237f, // pacibsp
    0xd503233f, // paciasp
    0xd503245f, // bti c
    0xd503249f, // bti j
    0xd50324df, // bti jc
};

/// arm64 only: `bl` targets inside code sections, plus PAC/BTI prologues that follow a terminator.
/// Bounded by the section size and `limits.max_functions`; nothing is decoded, only masked.
fn scanCode(b: *Builder, diags: *Diagnostics) Allocator.Error!void {
    if (!b.img.arch.is_64) return;
    switch (b.img.arch.name) {
        .arm64, .arm64e, .arm64v8, .arm64_32 => {},
        else => return, // x86_64 needs a length decoder; the engine adds call targets instead
    }
    var found: u32 = 0;
    for (b.img.sections) |*s| {
        if (!s.isCode() or s.isZerofill() or s.isSymbolStubs()) continue;
        const r = b.img.sectionReader(s) orelse continue;
        const words: u64 = r.len() / 4;
        const e = b.img.hdr.endian;
        var prev_terminator = true;
        var i: u64 = 0;
        while (i < words) : (i += 1) {
            if (found >= b.limits.max_functions) {
                b.truncated = true;
                break;
            }
            const w = r.u32At(i * 4, e) orelse break;
            const pc = s.addr +| (i * 4);
            if (w & 0xfc00_0000 == 0x9400_0000) { // bl imm26
                const imm: i64 = @as(i64, @as(i26, @bitCast(@as(u26, @truncate(w))))) * 4;
                const target: u64 = @bitCast(@as(i64, @bitCast(pc)) +% imm);
                if (!b.has(target) and codeSectionOf(b.img, target) != null) {
                    try b.add(target, .call_target);
                    found += 1;
                }
            } else if (prev_terminator and !b.has(pc)) {
                for (arm64_pac_prologues) |p| if (w == p) {
                    try b.add(pc, .heuristic);
                    found += 1;
                    break;
                };
            }
            prev_terminator = isTerminatorWord(w);
        }
    }
    if (found != 0 and !diags.has(.functions, .heuristic))
        diags.info(.functions, .heuristic, null, "no LC_FUNCTION_STARTS: {d} function start(s) recovered heuristically", .{found});
}

/// `ret`/`retab`/`retaa`/`br`/`b imm`/`brk`/zero padding — the words a function may end on.
fn isTerminatorWord(w: u32) bool {
    if (w == 0) return true;
    if (w & 0xffff_fc1f == 0xd65f_0000) return true; // ret Xn
    if (w == 0xd65f_0bff or w == 0xd65f_0fff) return true; // retaa / retab
    if (w & 0xffff_fc1f == 0xd61f_0000) return true; // br Xn
    if (w & 0xfc00_0000 == 0x1400_0000) return true; // b imm26
    if (w & 0xffe0_001f == 0xd420_0000) return true; // brk #imm
    return false;
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------
const testing = std.testing;
/// The hermetic tests build an Image directly; the reader type comes from the Image itself so this
/// file keeps the exact import set DESIGN.md §4 allows it.
const Reader = @FieldType(Image, "r");

test "functions: table lookups over a hand-built sorted slice" {
    const fns = [_]Function{
        .{ .start = 0x100, .end = 0x120, .name = "a", .source = .symbol, .name_source = .symbol, .section = 1, .sources = sourceBit(.symbol) },
        .{ .start = 0x120, .end = 0x140, .name = "b", .source = .function_starts, .name_source = .heuristic, .section = 1, .sources = sourceBit(.function_starts) },
    };
    const t: FunctionTable = .{ .functions = &fns, .truncated = false };
    try testing.expectEqualStrings("a", t.containing(0x110).?.name);
    try testing.expectEqualStrings("b", t.containing(0x120).?.name);
    try testing.expect(t.containing(0x0) == null);
    try testing.expect(t.containing(0x140) == null);
    try testing.expectEqualStrings("b", t.byStart(0x120).?.name);
    try testing.expect(t.byStart(0x121) == null);
    try testing.expectEqualStrings("a", t.byName("a").?.name);
    try testing.expect(t.byName("zz") == null);
    try testing.expectEqual(@as(u64, 0x20), fns[0].size());
    try testing.expect(fns[0].hasSource(.symbol) and !fns[0].hasSource(.objc));
    try testing.expect(!fns[0].synthetic() and fns[1].synthetic());
    try testing.expectEqual(@as(usize, 0), FunctionTable.empty.functions.len);
}

test "functions: terminator words and the bl mask" {
    try testing.expect(isTerminatorWord(0xd65f03c0)); // ret
    try testing.expect(isTerminatorWord(0xd65f0fff)); // retab
    try testing.expect(isTerminatorWord(0x14000001)); // b
    try testing.expect(isTerminatorWord(0));
    try testing.expect(!isTerminatorWord(0x94000001)); // bl is not a terminator
    try testing.expect(!isTerminatorWord(0xd503201f)); // nop
}

/// header(32) + LC_SEGMENT_64 __TEXT/__text(152) + LC_MAIN(24), 6 words of code at 0x1000000d0.
fn buildTiny(buf: *[256]u8) void {
    @memset(buf, 0);
    const w = struct {
        fn u32At(b: []u8, off: usize, v: u32) void {
            std.mem.writeInt(u32, b[off..][0..4], v, .little);
        }
        fn u64At(b: []u8, off: usize, v: u64) void {
            std.mem.writeInt(u64, b[off..][0..8], v, .little);
        }
    };
    w.u32At(buf, 0, std.macho.MH_MAGIC_64);
    w.u32At(buf, 4, 0x0100000c);
    w.u32At(buf, 12, 2);
    w.u32At(buf, 16, 2);
    w.u32At(buf, 20, 176);
    w.u32At(buf, 32, 0x19);
    w.u32At(buf, 36, 152);
    @memcpy(buf[40..][0..6], "__TEXT");
    w.u64At(buf, 56, 0x100000000);
    w.u64At(buf, 64, 0x100);
    w.u64At(buf, 72, 0);
    w.u64At(buf, 80, 256);
    w.u32At(buf, 88, 5);
    w.u32At(buf, 92, 5);
    w.u32At(buf, 96, 1);
    @memcpy(buf[104..][0..6], "__text");
    @memcpy(buf[120..][0..6], "__TEXT");
    w.u64At(buf, 136, 0x1000000d0);
    w.u64At(buf, 144, 0x18);
    w.u32At(buf, 152, 208);
    w.u32At(buf, 156, 2);
    w.u32At(buf, 168, 0x80000400); // S_ATTR_PURE_INSTRUCTIONS
    w.u32At(buf, 184, 0x80000028); // LC_MAIN
    w.u32At(buf, 188, 24);
    w.u64At(buf, 192, 0xd0);
    // code: pacibsp ; ret ; bl +2 ; ret ; nop ; ret
    w.u32At(buf, 208, 0xd503237f);
    w.u32At(buf, 212, 0xd65f03c0);
    w.u32At(buf, 216, 0x94000002);
    w.u32At(buf, 220, 0xd65f03c0);
    w.u32At(buf, 224, 0xd503201f);
    w.u32At(buf, 228, 0xd65f03c0);
}

test "functions: discovery from starts/symbols/entry and the heuristic fallback" {
    var buf: [256]u8 = undefined;
    buildTiny(&buf);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 64);
    const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);

    const syms: symbols.SymbolTable = .empty;
    const index: symbols.AddressIndex = .{ .order = &.{} };
    // No function starts -> the entry plus the tertiary scan (pacibsp at 0xd0, bl target 0xe0).
    const t = try discover(a, &img, .{ .syms = &syms, .index = &index, .starts = null, .trie = null, .objc = null }, &Limits.default, &d);
    try testing.expect(t.functions.len >= 2);
    try testing.expectEqual(@as(u64, 0x1000000d0), t.functions[0].start);
    try testing.expectEqualStrings("entry", t.functions[0].name);
    try testing.expect(t.byStart(0x1000000e0) != null); // bl target
    // ends are the next start, the last one runs to the section end
    try testing.expectEqual(@as(u64, 0x1000000e8), t.functions[t.functions.len - 1].end);

    // With an explicit start table the tertiary scan does not run.
    const fs: FunctionStarts = .{ .dataoff = 0, .datasize = 0, .addrs = &.{0x1000000d0}, .truncated = false };
    const t2 = try discover(a, &img, .{ .syms = &syms, .index = &index, .starts = &fs, .trie = null, .objc = null }, &Limits.default, &d);
    try testing.expectEqual(@as(usize, 1), t2.functions.len);
    try testing.expectEqual(Source.function_starts, t2.functions[0].source);
    try testing.expect(t2.functions[0].hasSource(.entry));
    try testing.expectEqual(@as(u64, 0x1000000e8), t2.functions[0].end);
}

test "functions: every prefix of the hand-built image discovers without error" {
    var buf: [256]u8 = undefined;
    buildTiny(&buf);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var len: usize = 0;
    while (len <= buf.len) : (len += 1) {
        var d = Diagnostics.init(a, 8);
        const img = Image.parse(a, Reader.init(buf[0..len], 0), 0, 0, &Limits.paranoid, &d) catch |e| switch (e) {
            error.NotMachO, error.Truncated => continue,
            else => return e,
        };
        const syms: symbols.SymbolTable = .empty;
        const index: symbols.AddressIndex = .{ .order = &.{} };
        const t = try discover(a, &img, .{ .syms = &syms, .index = &index, .starts = null, .trie = null, .objc = null, .aggressive = true }, &Limits.paranoid, &d);
        for (t.functions) |f| try testing.expect(f.end >= f.start);
    }
}
