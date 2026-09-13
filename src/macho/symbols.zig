//! macho/symbols.zig — nlist table, string table, dysymtab ranges, indirect symbol table.
//! Imports: core/image, core/reader, core/diag, core/limits, core/sanitize, core/version.
const std = @import("std");
const Allocator = std.mem.Allocator;
const image_mod = @import("../core/image.zig");
const Image = image_mod.Image;
const Section = image_mod.Section;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const Reader = @import("../core/reader.zig").Reader;
const sanitize = @import("../core/sanitize.zig");
const version = @import("../core/version.zig");

const N_STAB: u8 = 0xe0;
const N_PEXT: u8 = 0x10;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;
const N_ABS: u8 = 0x2;
const N_SECT: u8 = 0xe;
const N_PBUD: u8 = 0xc;
const N_INDR: u8 = 0xa;
const N_WEAK_REF: u16 = 0x0040;
const N_WEAK_DEF: u16 = 0x0080;
const REFERENCED_DYNAMICALLY: u16 = 0x0010;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

pub const SymbolKind = enum { undefined, absolute, section, prebound, indirect, stab };

pub const Symbol = struct {
    index: u32,
    name: []const u8, // slice into the string table (never past strsize); "" when n_strx >= strsize (+ one diag)
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,

    pub fn isStab(s: Symbol) bool {
        return s.n_type & N_STAB != 0;
    }
    pub fn isExternal(s: Symbol) bool {
        return !s.isStab() and s.n_type & N_EXT != 0;
    }
    pub fn isPrivateExternal(s: Symbol) bool {
        return !s.isStab() and s.n_type & N_PEXT != 0;
    }
    pub fn kind(s: Symbol) SymbolKind {
        if (s.isStab()) return .stab;
        return switch (s.n_type & N_TYPE) {
            N_UNDF => .undefined,
            N_ABS => .absolute,
            N_SECT => .section,
            N_PBUD => .prebound,
            N_INDR => .indirect,
            else => .undefined,
        };
    }
    /// GET_LIBRARY_ORDINAL(n_desc) — meaningful for undefined symbols in a two-level image.
    pub fn libraryOrdinal(s: Symbol) u8 {
        return @truncate(s.n_desc >> 8);
    }
    pub fn isWeakRef(s: Symbol) bool {
        return !s.isStab() and s.n_desc & N_WEAK_REF != 0;
    }
    pub fn isWeakDef(s: Symbol) bool {
        return !s.isStab() and s.n_desc & N_WEAK_DEF != 0;
    }
    pub fn referencedDynamically(s: Symbol) bool {
        return !s.isStab() and s.n_desc & REFERENCED_DYNAMICALLY != 0;
    }
    /// True for a common symbol (undefined, external, non-zero value = the size).
    pub fn isCommon(s: Symbol) bool {
        return s.kind() == .undefined and s.n_type & N_EXT != 0 and s.n_value != 0;
    }
    /// nm letter: U T t D d S s A a I i C - (nm(1) semantics; needs section classes for T/D/S)
    pub fn nmLetter(s: Symbol, img: *const Image) u8 {
        if (s.isStab()) return '-';
        var c: u8 = switch (s.n_type & N_TYPE) {
            N_UNDF => if (s.n_value != 0) @as(u8, 'c') else @as(u8, 'u'),
            N_ABS => 'a',
            N_INDR => 'i',
            N_PBUD => 'u',
            N_SECT => blk: {
                const sect = sectionOf(img, s.n_sect) orelse break :blk 's';
                if (std.mem.eql(u8, sect.segname, "__TEXT") and std.mem.eql(u8, sect.sectname, "__text")) break :blk 't';
                if (std.mem.eql(u8, sect.segname, "__DATA") and std.mem.eql(u8, sect.sectname, "__data")) break :blk 'd';
                if (std.mem.eql(u8, sect.segname, "__DATA") and std.mem.eql(u8, sect.sectname, "__bss")) break :blk 'b';
                break :blk 's';
            },
            else => '?',
        };
        if (s.n_type & N_EXT != 0) c = std.ascii.toUpper(c);
        return c;
    }
    /// "(__TEXT,__text)", "(undefined)", "(absolute)", "(indirect)", "(common)" — the nm -m location field.
    pub fn nmLocation(s: Symbol, img: *const Image, buf: *[40]u8) []const u8 {
        if (s.isStab()) return "(stab)";
        return switch (s.n_type & N_TYPE) {
            N_UNDF => if (s.n_value != 0) "(common)" else "(undefined)",
            N_PBUD => "(prebound undefined)",
            N_ABS => "(absolute)",
            N_INDR => "(indirect)",
            N_SECT => blk: {
                const sect = sectionOf(img, s.n_sect) orelse break :blk "(?,?)";
                break :blk std.fmt.bufPrint(buf, "({s},{s})", .{ sect.segname, sect.sectname }) catch "(?,?)";
            },
            else => "(?)",
        };
    }
};

fn sectionOf(img: *const Image, n_sect: u8) ?*const Section {
    if (n_sect == 0) return null;
    const i: usize = @as(usize, n_sect) - 1;
    if (i >= img.sections.len) return null;
    return &img.sections[i];
}

pub const Counts = struct { defined: u32 = 0, undefined: u32 = 0, stabs: u32 = 0, external: u32 = 0, local: u32 = 0 };

pub const SymbolTable = struct {
    present: bool, // false when there is no LC_SYMTAB (result is `empty`)
    symbols: []const Symbol, // <= min(nsyms, limits.max_symbols, bytes available / entry size)
    nsyms_declared: u32,
    strtab: []const u8, // clamped view; may be shorter than strsize
    strsize_declared: u32,
    indirect: []const u32, // clamped
    nindirect_declared: u32,
    symtab: ?std.macho.symtab_command,
    dysymtab: ?std.macho.dysymtab_command,
    counts: Counts,
    truncated: bool,
    lossy_names: u32, // names that needed sanitisation

    pub const empty: SymbolTable = .{
        .present = false,
        .symbols = &.{},
        .nsyms_declared = 0,
        .strtab = "",
        .strsize_declared = 0,
        .indirect = &.{},
        .nindirect_declared = 0,
        .symtab = null,
        .dysymtab = null,
        .counts = .{},
        .truncated = false,
        .lossy_names = 0,
    };
    pub fn byName(t: *const SymbolTable, name: []const u8) ?*const Symbol {
        for (t.symbols) |*s| if (std.mem.eql(u8, s.name, name)) return s;
        return null;
    }
    /// INDIRECT_SYMBOL_LOCAL / ABS (possibly OR'd) -> null; out of range -> null.
    pub fn indirectAt(t: *const SymbolTable, i: u32) ?u32 {
        if (i >= t.indirect.len) return null;
        const v = t.indirect[i];
        if (v & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0) return null;
        if (v >= t.symbols.len) return null;
        return v;
    }
    pub fn symbolAt(t: *const SymbolTable, i: u32) ?*const Symbol {
        if (i >= t.symbols.len) return null;
        return &t.symbols[i];
    }
    /// The symbol an indirect-table entry names (null for LOCAL/ABS or out-of-range entries).
    pub fn indirectSymbol(t: *const SymbolTable, i: u32) ?*const Symbol {
        const si = t.indirectAt(i) orelse return null;
        return t.symbolAt(si);
    }
};

pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!SymbolTable {
    var out: SymbolTable = .empty;
    const st_cmd = img.findCmd(.SYMTAB) orelse return out;
    const st = st_cmd.reader().structAt(std.macho.symtab_command, 0, st_cmd.endian) orelse {
        diags.err(.symbols, .cmdsize_invalid, st_cmd.offset, "LC_SYMTAB is shorter than 24 bytes", .{});
        return out;
    };
    out.present = true;
    out.symtab = st;
    out.nsyms_declared = st.nsyms;
    out.strsize_declared = st.strsize;
    if (img.findCmd(.DYSYMTAB)) |dc| out.dysymtab = dc.reader().structAt(std.macho.dysymtab_command, 0, dc.endian);

    // ---- string table (clamped) ----
    var strtab: []const u8 = "";
    if (st.strsize != 0) {
        if (st.stroff >= img.r.len()) {
            diags.err(.symbols, .truncated, st.stroff, "string table at offset {d} size {d} lies past the {d}-byte slice; all names empty", .{ st.stroff, st.strsize, img.r.len() });
            out.truncated = true;
        } else {
            const sub = img.r.subClamped(st.stroff, st.strsize).?;
            strtab = sub.r.bytes;
            if (sub.truncated) {
                diags.warn(.symbols, .truncated, st.stroff, "string table size {d} clamped to {d} bytes", .{ st.strsize, strtab.len });
                out.truncated = true;
            }
        }
    }
    out.strtab = strtab;

    // ---- nlist entries (clamped) ----
    const entsize: u32 = if (img.hdr.is_64) 16 else 12;
    var n: u64 = st.nsyms;
    const avail: u64 = if (st.symoff < img.r.len()) (img.r.len() - st.symoff) / entsize else 0;
    if (n > avail) {
        diags.warn(.symbols, .count_clamped, st.symoff, "nsyms {d} but only {d} {d}-byte entries fit in the slice; clamped", .{ st.nsyms, avail, entsize });
        n = avail;
        out.truncated = true;
    }
    if (n > limits.max_symbols) {
        diags.warn(.symbols, .count_clamped, st.symoff, "nsyms {d} clamped to limits.max_symbols {d}", .{ st.nsyms, limits.max_symbols });
        n = limits.max_symbols;
        out.truncated = true;
    }
    const syms = try arena.alloc(Symbol, @intCast(n));
    const e = img.hdr.endian;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const off: u64 = @as(u64, st.symoff) + @as(u64, i) * entsize;
        var s: Symbol = .{ .index = i, .name = "", .n_type = 0, .n_sect = 0, .n_desc = 0, .n_value = 0 };
        const n_strx = img.r.u32At(off, e) orelse 0;
        s.n_type = img.r.u8At(off + 4) orelse 0;
        s.n_sect = img.r.u8At(off + 5) orelse 0;
        s.n_desc = img.r.u16At(off + 6, e) orelse 0;
        s.n_value = if (img.hdr.is_64) (img.r.u64At(off + 8, e) orelse 0) else (img.r.u32At(off + 8, e) orelse 0);
        if (n_strx != 0) {
            if (n_strx >= strtab.len) {
                // An empty string table already produced one `truncated` diagnostic; do not repeat per symbol.
                if (strtab.len != 0 and !diags.has(.symbols, .string_unterminated))
                    diags.warn(.symbols, .string_unterminated, off, "symbol {d}: n_strx {d} is past the {d}-byte string table; name empty", .{ i, n_strx, strtab.len });
            } else {
                const sr = Reader.init(strtab, 0);
                const c = sr.cstrAt(n_strx, limits.max_symbol_name).?;
                s.name = c.bytes;
                if (!c.terminated and !diags.has(.symbols, .truncated))
                    diags.warn(.symbols, .truncated, off, "symbol {d}: name at n_strx {d} is not NUL-terminated inside the string table", .{ i, n_strx });
            }
        }
        if (s.name.len != 0 and !sanitize.isClean(s.name, .json)) out.lossy_names += 1;
        // counts
        if (s.isStab()) {
            out.counts.stabs += 1;
        } else {
            switch (s.n_type & N_TYPE) {
                N_SECT, N_ABS, N_INDR => out.counts.defined += 1,
                else => out.counts.undefined += 1,
            }
            if (s.n_type & N_EXT != 0) out.counts.external += 1 else out.counts.local += 1;
        }
        syms[i] = s;
    }
    out.symbols = syms;

    // ---- indirect symbol table (clamped) ----
    if (out.dysymtab) |dt| {
        out.nindirect_declared = dt.nindirectsyms;
        var m: u64 = dt.nindirectsyms;
        const iavail: u64 = if (dt.indirectsymoff < img.r.len()) (img.r.len() - dt.indirectsymoff) / 4 else 0;
        if (m > iavail) {
            if (!diags.has(.symbols, .count_clamped))
                diags.warn(.symbols, .count_clamped, dt.indirectsymoff, "nindirectsyms {d} but only {d} entries fit in the slice; clamped", .{ dt.nindirectsyms, iavail });
            m = iavail;
            out.truncated = true;
        }
        if (m > limits.max_indirect_symbols) m = limits.max_indirect_symbols;
        const ind = try arena.alloc(u32, @intCast(m));
        var k: u32 = 0;
        while (k < m) : (k += 1) ind[k] = img.r.u32At(@as(u64, dt.indirectsymoff) + @as(u64, k) * 4, e) orelse 0;
        out.indirect = ind;
    }
    return out;
}

/// Sorted-by-address index (symbol indices) of defined N_SECT/N_ABS non-stab symbols.
pub const AddressIndex = struct {
    order: []const u32,

    const SortCtx = struct {
        t: *const SymbolTable,
        fn lessThan(c: SortCtx, a: u32, b: u32) bool {
            const sa = c.t.symbols[a];
            const sb = c.t.symbols[b];
            if (sa.n_value != sb.n_value) return sa.n_value < sb.n_value;
            const ea = sa.isExternal();
            const eb = sb.isExternal();
            if (ea != eb) return ea; // external first at the same address
            return a < b;
        }
    };

    pub fn build(arena: Allocator, t: *const SymbolTable) Allocator.Error!AddressIndex {
        var list: std.ArrayList(u32) = .empty;
        for (t.symbols) |s| {
            if (s.isStab()) continue;
            switch (s.n_type & N_TYPE) {
                N_SECT, N_ABS => try list.append(arena, s.index),
                else => {},
            }
        }
        const order = try list.toOwnedSlice(arena);
        std.mem.sort(u32, order, SortCtx{ .t = t }, SortCtx.lessThan);
        return .{ .order = order };
    }
    /// Exact match at `vmaddr` (external preferred over local).
    pub fn at(ix: *const AddressIndex, t: *const SymbolTable, vmaddr: u64) ?*const Symbol {
        const i = ix.lowerBound(t, vmaddr);
        if (i >= ix.order.len) return null;
        const s = &t.symbols[ix.order[i]];
        if (s.n_value != vmaddr) return null;
        return s;
    }
    /// Nearest symbol at or below `vmaddr` -> (symbol, delta).
    pub fn nearest(ix: *const AddressIndex, t: *const SymbolTable, vmaddr: u64) ?struct { sym: *const Symbol, delta: u64 } {
        if (ix.order.len == 0) return null;
        var i = ix.lowerBound(t, vmaddr);
        if (i < ix.order.len and t.symbols[ix.order[i]].n_value == vmaddr) {
            return .{ .sym = &t.symbols[ix.order[i]], .delta = 0 };
        }
        if (i == 0) return null;
        i -= 1;
        const s = &t.symbols[ix.order[i]];
        if (s.n_value > vmaddr) return null;
        return .{ .sym = s, .delta = vmaddr - s.n_value };
    }
    /// First position whose value is >= vmaddr.
    fn lowerBound(ix: *const AddressIndex, t: *const SymbolTable, vmaddr: u64) usize {
        var lo: usize = 0;
        var hi: usize = ix.order.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.symbols[ix.order[mid]].n_value < vmaddr) lo = mid + 1 else hi = mid;
        }
        return lo;
    }
};

// ---- tests ----
const Limits_ = Limits;

fn le32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
fn le64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .little);
}

/// header(32) + LC_SEGMENT_64 __TEXT/__text(152) + LC_SYMTAB(24) = 208; symbols at 208, strings at 240.
fn buildSymImage(buf: *[320]u8) void {
    @memset(buf, 0);
    le32(buf, 0, std.macho.MH_MAGIC_64);
    le32(buf, 4, 0x0100000c);
    le32(buf, 12, 2);
    le32(buf, 16, 2);
    le32(buf, 20, 176);
    le32(buf, 24, 0x200085);
    le32(buf, 32, 0x19); // LC_SEGMENT_64
    le32(buf, 36, 152);
    @memcpy(buf[40..][0..6], "__TEXT");
    le64(buf, 56, 0x100000000);
    le64(buf, 64, 0x1000);
    le64(buf, 72, 0);
    le64(buf, 80, 320);
    le32(buf, 88, 5);
    le32(buf, 92, 5);
    le32(buf, 96, 1);
    @memcpy(buf[104..][0..6], "__text");
    @memcpy(buf[120..][0..6], "__TEXT");
    le64(buf, 136, 0x100000100);
    le64(buf, 144, 0x30);
    le32(buf, 184, 0x02); // LC_SYMTAB
    le32(buf, 188, 24);
    le32(buf, 192, 208); // symoff
    le32(buf, 196, 2); // nsyms
    le32(buf, 200, 240); // stroff
    le32(buf, 204, 24); // strsize
    // sym 0: "_main" defined in section 1, external
    le32(buf, 208, 1);
    buf[212] = 0x0e | 0x01;
    buf[213] = 1;
    le64(buf, 216, 0x100000100);
    // sym 1: "_puts" undefined, external, ordinal 1
    le32(buf, 224, 7);
    buf[228] = 0x01;
    std.mem.writeInt(u16, buf[230..232], 0x0100, .little);
    @memcpy(buf[241..][0..6], "_main\x00");
    @memcpy(buf[247..][0..6], "_puts\x00");
}

test "symbols: hand-built symtab, counts, nm letters and address index" {
    var buf: [320]u8 = undefined;
    buildSymImage(&buf);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 32);
    const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
    const t = try parse(a, &img, &Limits.default, &d);
    try std.testing.expect(t.present);
    try std.testing.expectEqual(@as(usize, 2), t.symbols.len);
    try std.testing.expectEqualStrings("_main", t.symbols[0].name);
    try std.testing.expectEqualStrings("_puts", t.symbols[1].name);
    try std.testing.expectEqual(@as(u32, 1), t.counts.defined);
    try std.testing.expectEqual(@as(u32, 1), t.counts.undefined);
    try std.testing.expectEqual(@as(u32, 2), t.counts.external);
    try std.testing.expectEqual(@as(u8, 'T'), t.symbols[0].nmLetter(&img));
    try std.testing.expectEqual(@as(u8, 'U'), t.symbols[1].nmLetter(&img));
    try std.testing.expectEqual(@as(u8, 1), t.symbols[1].libraryOrdinal());
    try std.testing.expect(t.byName("_puts") != null);
    var lb: [40]u8 = undefined;
    try std.testing.expectEqualStrings("(__TEXT,__text)", t.symbols[0].nmLocation(&img, &lb));
    try std.testing.expectEqualStrings("(undefined)", t.symbols[1].nmLocation(&img, &lb));
    const ix = try AddressIndex.build(a, &t);
    try std.testing.expectEqual(@as(usize, 1), ix.order.len);
    try std.testing.expect(ix.at(&t, 0x100000100) != null);
    try std.testing.expect(ix.at(&t, 0x100000104) == null);
    try std.testing.expectEqual(@as(u64, 4), ix.nearest(&t, 0x100000104).?.delta);
    try std.testing.expect(ix.nearest(&t, 0x100000000) == null);
}

test "symbols: every prefix parses, huge nsyms and a past-EOF string table clamp" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    {
        var buf: [320]u8 = undefined;
        buildSymImage(&buf);
        le32(&buf, 196, 0xFFFF_FFFF); // nsyms
        var d = Diagnostics.init(a, 32);
        const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
        const t = try parse(a, &img, &Limits.default, &d);
        try std.testing.expect(d.has(.symbols, .count_clamped));
        try std.testing.expect(t.truncated and t.symbols.len == 7);
    }
    {
        var buf: [320]u8 = undefined;
        buildSymImage(&buf);
        le32(&buf, 200, 0x7FFF_FFF0); // stroff
        var d = Diagnostics.init(a, 32);
        const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
        const t = try parse(a, &img, &Limits.default, &d);
        try std.testing.expect(d.has(.symbols, .truncated));
        for (t.symbols) |s| try std.testing.expectEqualStrings("", s.name);
    }
    {
        var buf: [320]u8 = undefined;
        buildSymImage(&buf);
        var len: usize = 0;
        while (len <= buf.len) : (len += 1) {
            var d = Diagnostics.init(a, 64);
            const img = Image.parse(a, Reader.init(buf[0..len], 0), 0, 0, &Limits.paranoid, &d) catch continue;
            const t = try parse(a, &img, &Limits.paranoid, &d);
            const ix = try AddressIndex.build(a, &t);
            _ = ix.nearest(&t, 0x100000104);
        }
    }
}
