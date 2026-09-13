//! disasm/engine.zig — per-function decode loop. The built-in decoder ALWAYS supplies semantic fields;
//! Capstone (when available) overlays mnemonic/op_str text where (address,size) match; length disagreements
//! keep the built-in boundary and log `backend_disagree`.
//! Imports: disasm/insn, disasm/capstone, disasm/arm64, disasm/x86len, disasm/functions, disasm/symbolize, core/image, core/arch, core/limits, core/diag.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Section = @import("../core/image.zig").Section;
const ArchName = @import("../core/arch.zig").ArchName;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const insn = @import("insn.zig");
const capstone = @import("capstone.zig");
const arm64 = @import("arm64.zig");
const x86len = @import("x86len.zig");
const functions_mod = @import("functions.zig");
const Function = functions_mod.Function;
const FunctionTable = functions_mod.FunctionTable;
const symbolize = @import("symbolize.zig");
const inline_data = @import("inline_data.zig");
const AnnotateCtx = symbolize.AnnotateCtx;

pub const Options = struct {
    backend: ?insn.Backend = null, // null = capstone if available else builtin
    syntax: insn.Syntax = .att, // x86_64 only (otool is AT&T)
    max_insns: u32 = 0,
    annotate: bool = true,
    otool_compat: bool = false,
    show_bytes: bool = false,
};
pub const OpenError = capstone.OpenError || Allocator.Error;

pub const Engine = struct {
    arch: ArchName,
    opts: Options,
    cs: ?capstone.Handle,
    text_backend: insn.Backend,
    semantic_backend: insn.Backend,
    disagreements: u32,
    /// Inline-data runs found in the last `disassembleSection` (arm64); 0 on x86_64.
    data_runs: inline_data.Stats = .{},

    /// `--backend=capstone` on a build without it -> error.CapstoneUnavailable (CLI exit 6).
    pub fn init(arch: ArchName, opts: Options) OpenError!Engine {
        const builtin_backend = insn.builtinBackendFor(arch) orelse return error.UnsupportedArch;
        var e: Engine = .{
            .arch = arch,
            .opts = opts,
            .cs = null,
            .text_backend = builtin_backend,
            .semantic_backend = builtin_backend,
            .disagreements = 0,
            .data_runs = .{},
        };
        const att = opts.syntax == .att;
        if (opts.backend) |b| {
            if (b == .capstone) {
                e.cs = try capstone.Handle.open(arch, att);
                e.text_backend = .capstone;
            }
            return e; // an explicit built-in backend never opens Capstone
        }
        // Auto: `--otool-compat` on arm64 forces the built-in text, whose spelling IS otool's (§13.1/3).
        if (builtin_backend == .builtin_arm64 and opts.otool_compat) return e;
        if (capstone.available) {
            if (capstone.Handle.open(arch, att)) |h| {
                e.cs = h;
                e.text_backend = .capstone;
            } else |_| {}
        }
        return e;
    }
    pub fn deinit(e: *Engine) void {
        if (e.cs) |*h| h.close();
        e.cs = null;
    }
    pub fn decodeRange(e: *Engine, arena: Allocator, code: []const u8, base: u64, max: u32, diags: *Diagnostics) Allocator.Error![]insn.Insn {
        return decodeInner(e, arena, code, base, max, diags, null);
    }
    pub fn backendName(e: *const Engine) []const u8 {
        return insn.backendName(e.text_backend);
    }
    /// True when the listing names only some instructions (built-in x86 length decoder).
    pub fn isPartial(e: *const Engine) bool {
        return e.text_backend == .builtin_x86len;
    }
};

/// Range the x86 jump-table heuristic may treat as inline data (§9, disasm-notes C.4).
const DataCtx = struct { lo: u64, hi: u64 };

fn decodeInner(e: *Engine, arena: Allocator, code: []const u8, base: u64, max: u32, diags: *Diagnostics, dctx: ?DataCtx) Allocator.Error![]insn.Insn {
    if (code.len == 0) return &.{};
    const cap: usize = if (max == 0) std.math.maxInt(usize) else max;
    var out: std.ArrayList(insn.Insn) = .empty;

    // Capstone text for the whole range, indexed by address (semantics stay built-in).
    var text: std.AutoHashMapUnmanaged(u64, capstone.Text) = .empty;
    if (e.cs) |*h| {
        const recs = try capstone.decodeText(h, arena, code, base, 0);
        for (recs) |r| try text.put(arena, r.addr, r);
    }

    var lea_target: ?u64 = null;
    var saw_indirect = false;
    var off: usize = 0;
    while (off < code.len and out.items.len < cap) {
        const pc = base +% off;

        // Inline jump table: the cursor reached the `lea` target after an indirect branch.
        if (dctx != null and lea_target == pc and saw_indirect) {
            off = emitJumpTable(arena, &out, code, base, off, dctx.?, cap) catch |err| return err;
            lea_target = null;
            saw_indirect = false;
            continue;
        }

        var i: insn.Insn = switch (e.semantic_backend) {
            .builtin_arm64 => blk: {
                if (code.len - off < 4) break;
                const w = std.mem.readInt(u32, code[off..][0..4], .little);
                break :blk try arm64.decodeOne(arena, w, pc, if (e.opts.otool_compat) .darwin else .arm);
            },
            else => try x86len.decodeOne(arena, code[off..], pc),
        };
        if (i.size == 0) i.size = 1; // the decoders never return 0; belt and braces for ReleaseSafe

        if (text.get(pc)) |t| {
            if (t.size == i.size) {
                i.mnemonic = t.mnemonic;
                i.operands = t.operands;
                i.text_from = .capstone;
                i.partial = false;
            } else {
                e.disagreements += 1;
                if (!diags.has(.disasm, .backend_disagree))
                    diags.info(.disasm, .backend_disagree, pc, "capstone says {d} bytes at 0x{x} where the built-in decoder says {d}; the built-in boundary is kept", .{ t.size, pc, i.size });
            }
        }

        if (dctx != null) {
            if (i.kind == .lea) {
                if (i.target) |t| if (t > pc and t >= dctx.?.lo and t < dctx.?.hi) {
                    lea_target = t;
                    saw_indirect = false;
                };
            } else if (i.kind == .indirect_branch) saw_indirect = true;
        }

        try out.append(arena, i);
        off += i.size;
    }
    return out.toOwnedSlice(arena);
}

/// Emits `.long` records for a switch table of 32-bit self-relative entries; stops as soon as an entry
/// stops pointing inside the enclosing range, which is what makes the decoder resynchronise on real code.
fn emitJumpTable(arena: Allocator, out: *std.ArrayList(insn.Insn), code: []const u8, base: u64, start_off: usize, d: DataCtx, cap: usize) Allocator.Error!usize {
    const table_base = base +% start_off;
    var off = start_off;
    var entries: usize = 0;
    while (off + 4 <= code.len and out.items.len < cap) {
        const raw = std.mem.readInt(u32, code[off..][0..4], .little);
        const rel: i64 = @as(i32, @bitCast(raw));
        const case: u64 = @bitCast(@as(i64, @bitCast(table_base)) +% rel);
        if (case < d.lo or case >= d.hi) break;
        var bytes: [16]u8 = @splat(0);
        @memcpy(bytes[0..4], code[off..][0..4]);
        try out.append(arena, .{
            .addr = base +% off,
            .size = 4,
            .bytes = bytes,
            .mnemonic = ".long",
            .operands = try std.fmt.allocPrint(arena, "0x{x:0>8}", .{raw}),
            .kind = .data,
            .target = case,
            .reg_write = null,
            .imm = raw,
            .mem_ref = null,
            .valid = true,
            .text_from = .builtin_x86len,
            .semantic_from = .builtin_x86len,
            .partial = false,
        });
        off += 4;
        entries += 1;
    }
    // Nothing looked like a case entry: fall through to one byte of normal decoding.
    if (entries == 0) return start_off;
    return off;
}

fn makeListing(arena: Allocator, e: *Engine, insns: []const insn.Insn, funcs: *const FunctionTable, start: u64, end: u64) Allocator.Error!insn.Listing {
    const labels = try arena.alloc(?[]const u8, insns.len);
    @memset(labels, null);
    for (insns, 0..) |*i, idx| {
        if (funcs.byStart(i.addr)) |f| {
            // otool labels only real symbols; machre's synthesized "sub_<hex>" / "entry" names would
            // otherwise show up as extra lines in an --otool-compat diff of a stripped binary.
            if (e.opts.otool_compat and (f.name_source == .heuristic or f.name_source == .entry)) continue;
            labels[idx] = f.name;
        }
    }
    var partial = e.isPartial();
    for (insns) |*i| if (i.partial) {
        partial = true;
    };
    return .{
        .insns = insns,
        .comments = try arena.alloc(?[]const u8, 0),
        .labels = labels,
        .start = start,
        .end = end,
        .partial = partial,
        .backend_name = e.backendName(),
    };
}

fn decodeSpan(arena: Allocator, e: *Engine, img: *const Image, start: u64, len: u64, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]insn.Insn {
    if (len == 0) return &.{};
    const want = @min(len, limits.max_disasm_bytes);
    const vb = img.bytesAtVm(start, want) orelse {
        if (!diags.has(.disasm, .offset_past_eof))
            diags.warn(.disasm, .offset_past_eof, start, "0x{x} is not backed by file bytes; nothing to disassemble", .{start});
        return &.{};
    };
    if (vb.bytes.len == 0) return &.{};
    const max: u32 = if (e.opts.max_insns != 0) @min(e.opts.max_insns, limits.max_instructions) else limits.max_instructions;
    const dctx: ?DataCtx = if (e.semantic_backend == .builtin_x86len or e.arch == .x86_64 or e.arch == .x86_64h)
        .{ .lo = start, .hi = start +| want }
    else
        null;
    return decodeInner(e, arena, vb.bytes, start, max, diags, dctx);
}

pub fn disassembleFunction(arena: Allocator, e: *Engine, img: *const Image, f: *const Function, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error!insn.Listing {
    const len = if (f.end > f.start) f.end - f.start else 0;
    const insns = try decodeSpan(arena, e, img, f.start, len, limits, diags);
    var listing = try makeListing(arena, e, insns, ctx.funcs, f.start, f.start +| len);
    if (e.opts.annotate) try symbolize.annotate(arena, &listing, ctx, limits);
    return listing;
}

pub fn disassembleRange(arena: Allocator, e: *Engine, img: *const Image, start: u64, len: u64, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error!insn.Listing {
    const insns = try decodeSpan(arena, e, img, start, len, limits, diags);
    var listing = try makeListing(arena, e, insns, ctx.funcs, start, start +| len);
    if (e.opts.annotate) try symbolize.annotate(arena, &listing, ctx, limits);
    return listing;
}

/// One listing per function of the section (functions order); inline jump-table data survives as `.data` records.
pub fn disassembleSection(arena: Allocator, e: *Engine, img: *const Image, sect: *const Section, funcs: *const FunctionTable, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const insn.Listing {
    var out: std.ArrayList(insn.Listing) = .empty;
    const sect_end = sect.addr +| sect.size;
    var covered: u64 = sect.addr;
    // One budget for the whole section so `--all` on a large image stays inside limits.max_instructions.
    const start_budget: u32 = if (e.opts.max_insns != 0) @min(e.opts.max_insns, limits.max_instructions) else limits.max_instructions;
    var budget = start_budget;
    const saved = e.opts.max_insns;
    defer e.opts.max_insns = saved;
    for (funcs.functions) |*f| {
        if (f.start < sect.addr or f.start >= sect_end) continue;
        // A function start behind the cursor means overlapping tables; skip it rather than re-decode.
        if (f.start < covered) continue;
        if (budget == 0) break;
        const end = @min(if (f.end > f.start) f.end else sect_end, sect_end);
        var fixed = f.*;
        fixed.end = end;
        e.opts.max_insns = budget;
        const listing = try disassembleFunction(arena, e, img, &fixed, ctx, limits, diags);
        budget -|= @intCast(@min(listing.insns.len, std.math.maxInt(u32)));
        try out.append(arena, listing);
        covered = end;
    }
    if (out.items.len == 0 and sect.size != 0) {
        // No function starts inside the section: one listing for the whole thing.
        try out.append(arena, try disassembleRange(arena, e, img, sect.addr, sect.size, ctx, limits, diags));
    }

    // Inline data (arm64 only). This has to run AFTER every function in the section is decoded,
    // because the `adr` that names a table routinely sits in a different function from the table.
    // x86_64 already resolves its own inline data during decoding, via the jump-table cursor above.
    if (e.semantic_backend == .builtin_arm64 and out.items.len != 0) {
        const runs = try inline_data.find(arena, out.items, sect.addr, sect_end);
        if (runs.len != 0) {
            const st = try inline_data.mark(out.items, runs, arena);
            e.data_runs = st;
            diags.info(.disasm, .inline_data, sect.addr, "{d} address-taken inline-data run{s} ({d} word{s}) in {s},{s}", .{
                st.runs,  if (st.runs == 1) "" else "s",
                st.words, if (st.words == 1) "" else "s",
                sect.segname, sect.sectname,
            });
        }
    }
    return out.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------
const testing = std.testing;

test "engine: backend selection honours --otool-compat, an explicit backend and availability" {
    var e = try Engine.init(.arm64, .{ .backend = .builtin_arm64 });
    defer e.deinit();
    try testing.expect(e.cs == null);
    try testing.expectEqual(insn.Backend.builtin_arm64, e.text_backend);
    try testing.expect(!e.isPartial());

    var oc = try Engine.init(.arm64e, .{ .otool_compat = true });
    defer oc.deinit();
    try testing.expect(oc.cs == null); // otool spelling comes from the built-in decoder

    var auto = try Engine.init(.x86_64, .{});
    defer auto.deinit();
    try testing.expectEqual(capstone.available, auto.cs != null);
    try testing.expectEqual(capstone.available, !auto.isPartial());

    if (!capstone.available) {
        try testing.expectError(error.CapstoneUnavailable, Engine.init(.arm64, .{ .backend = .capstone }));
    }
    try testing.expectError(error.UnsupportedArch, Engine.init(.ppc, .{}));
}

test "engine: decodeRange decodes arm64 words and stops on a short tail" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 32);
    var e = try Engine.init(.arm64, .{ .backend = .builtin_arm64 });
    defer e.deinit();
    // sub sp, sp, #0x90 ; ret ; two stray bytes
    const code = [_]u8{ 0xff, 0x43, 0x02, 0xd1, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00 };
    const insns = try e.decodeRange(a, &code, 0x100000524, 0, &d);
    try testing.expectEqual(@as(usize, 2), insns.len);
    try testing.expectEqualStrings("sub", insns[0].mnemonic);
    try testing.expectEqual(insn.Kind.ret, insns[1].kind);
    try testing.expectEqual(@as(u64, 0x100000528), insns[1].addr);
    // max caps the count
    const one = try e.decodeRange(a, &code, 0x100000524, 1, &d);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual(@as(usize, 0), (try e.decodeRange(a, &.{}, 0, 0, &d)).len);
}

test "engine: x86 length decoding always advances" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 32);
    var e = try Engine.init(.x86_64, .{ .backend = .builtin_x86len });
    defer e.deinit();
    // pushq %rbp ; movq %rsp,%rbp ; popq %rbp ; retq
    const code = [_]u8{ 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
    const insns = try e.decodeRange(a, &code, 0x100000510, 0, &d);
    try testing.expectEqual(@as(usize, 4), insns.len);
    try testing.expectEqual(@as(u8, 1), insns[0].size);
    try testing.expectEqual(@as(u8, 3), insns[1].size);
    try testing.expectEqual(insn.Kind.ret, insns[3].kind);
    try testing.expect(e.isPartial());
    var total: u64 = 0;
    for (insns) |i| total += i.size;
    try testing.expectEqual(@as(u64, code.len), total);
}

test "engine: every random byte string terminates and covers the input exactly once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 8);
    var prng = std.Random.DefaultPrng.init(0x8ec8_2b1f);
    const rnd = prng.random();
    var buf: [128]u8 = undefined;
    for (0..64) |_| {
        rnd.bytes(&buf);
        inline for (.{ ArchName.x86_64, ArchName.arm64 }) |arch| {
            var e = try Engine.init(arch, .{ .backend = if (arch == .arm64) insn.Backend.builtin_arm64 else insn.Backend.builtin_x86len });
            defer e.deinit();
            const insns = try e.decodeRange(a, &buf, 0x100000000, 0, &d);
            var pos: u64 = 0x100000000;
            for (insns) |i| {
                try testing.expectEqual(pos, i.addr);
                try testing.expect(i.size >= 1);
                pos += i.size;
            }
            try testing.expect(pos <= 0x100000000 + buf.len);
        }
    }
}
