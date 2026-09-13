//! tests/fuzz/disasm.zig — Smith fuzzers + deterministic sweeps for function discovery, stub
//! resolution, annotation and the decode engine (DESIGN §10.5).
//!
//! The invariants under test are the ones the whole listing rests on: a decode sweep always advances,
//! covers its input exactly once and never runs past it; discovery always yields a sorted table whose
//! ranges are inside their sections; stub resolution and the annotator never index outside the image.
//! A trap, an out-of-bounds read or a non-advancing decode fails by crashing, in Debug and ReleaseSafe.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const Limits = machre.Limits;
const Diagnostics = machre.Diagnostics;
const Image = machre.Image;
const Reader = machre.Reader;
const engine_mod = machre.disasm.engine;
const functions_mod = machre.disasm.functions;
const symbolize = machre.disasm.symbolize;
const insn_mod = machre.disasm.insn;
const symbols_mod = machre.macho.symbols;
const fixups_mod = machre.macho.fixups;

/// Decodes `bytes` with both built-in backends and checks that the sweep is total and monotone.
fn sweep(arena: std.mem.Allocator, bytes: []const u8, diags: *Diagnostics) !void {
    inline for (.{ insn_mod.Backend.builtin_arm64, insn_mod.Backend.builtin_x86len }) |backend| {
        const arch: machre.core.arch.ArchName = if (backend == .builtin_arm64) .arm64 else .x86_64;
        var e = try engine_mod.Engine.init(arch, .{ .backend = backend });
        defer e.deinit();
        const insns = try e.decodeRange(arena, bytes, 0x100000000, Limits.paranoid.max_instructions, diags);
        var pos: u64 = 0x100000000;
        for (insns) |i| {
            if (i.addr != pos) return error.NonContiguous;
            if (i.size == 0) return error.ZeroLength;
            if (i.size > 16) return error.OversizedInstruction;
            pos += i.size;
        }
        if (pos > 0x100000000 + bytes.len) return error.RanPastInput;
    }
}

const SweepCtx = struct {
    gpa: std.mem.Allocator,
    fn testOne(ctx: SweepCtx, smith: *std.testing.Smith) anyerror!void {
        var buf: [1024]u8 = undefined;
        const n = smith.slice(&buf);
        var arena = std.heap.ArenaAllocator.init(ctx.gpa);
        defer arena.deinit();
        var diags = Diagnostics.init(arena.allocator(), 16);
        try sweep(arena.allocator(), buf[0..n], &diags);
    }
};

test "fuzz/disasm: engine sweep over arbitrary bytes always advances and covers the input" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const bytes = helpers.readFixture(io, gpa, "hello-c") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    // hello-c's __text starts at file offset 0x4f8 and is 0x134 bytes.
    const text = bytes[0x4f8..][0x0..0x134];
    try std.testing.fuzz(SweepCtx{ .gpa = gpa }, SweepCtx.testOne, .{ .corpus = &.{
        text,
        &[_]u8{ 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 },
        &[_]u8{ 0xff, 0xff, 0xff, 0xff },
        &[_]u8{0},
    } });
}

test "fuzz/disasm: 4096 mutated copies of hello-c __text decode without a trap" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const bytes = helpers.readFixture(io, gpa, "hello-c") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = Diagnostics.init(a, 8);
    var buf: [0x134]u8 = undefined;
    @memcpy(&buf, bytes[0x4f8..][0..0x134]);
    var prng = std.Random.DefaultPrng.init(0x6469_7361_736d_3838);
    const random = prng.random();
    var round: u32 = 0;
    while (round < 4096) : (round += 1) {
        const at = random.uintLessThan(usize, buf.len);
        buf[at] = random.int(u8);
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        try sweep(scratch.allocator(), &buf, &diags);
        // a truncated tail must terminate too
        try sweep(scratch.allocator(), buf[0 .. at + 1], &diags);
    }
}

/// Runs the whole WP8 pipeline (discovery -> stubs -> listings -> annotate -> xrefs) over one image.
fn pipeline(gpa: std.mem.Allocator, bytes: []const u8, limits: *const Limits) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = Diagnostics.init(a, 32);
    const img = Image.parse(a, Reader.init(bytes, 0), 0, 0, limits, &diags) catch |e| switch (e) {
        error.NotMachO, error.Truncated => return,
        else => return e,
    };
    const syms = try symbols_mod.parse(a, &img, limits, &diags);
    const index = try symbols_mod.AddressIndex.build(a, &syms);
    const chained = try machre.macho.dyld_chained.parse(a, &img, limits, &diags);
    const legacy = try machre.macho.dyld_legacy.parse(a, &img, limits, &diags);
    const fix = try fixups_mod.build(a, &img, if (chained) |*c| c else null, if (legacy) |*l| l else null, limits, &diags);
    const starts = try machre.macho.function_starts.parseFunctionStarts(a, &img, limits, &diags);
    const funcs = try functions_mod.discover(a, &img, .{
        .syms = &syms,
        .index = &index,
        .starts = if (starts) |*s| s else null,
        .trie = null,
        .objc = null,
        .aggressive = true,
    }, limits, &diags);
    // the table must be sorted and every range must be sane
    for (funcs.functions, 0..) |f, i| {
        if (i != 0 and funcs.functions[i - 1].start > f.start) return error.Unsorted;
        if (f.end < f.start) return error.InvertedRange;
        _ = funcs.containing(f.start);
        _ = funcs.byName(f.name);
    }
    const stubs = try symbolize.resolveStubs(a, &img, &syms, &fix, null, limits, &diags);
    for (stubs.stubs, 0..) |s, i| {
        if (i != 0 and stubs.stubs[i - 1].addr > s.addr) return error.StubsUnsorted;
        _ = stubs.slotName(s.slot orelse 0);
    }
    var e = engine_mod.Engine.init(img.arch.name, .{ .backend = insn_mod.builtinBackendFor(img.arch.name) orelse return }) catch return;
    defer e.deinit();
    const ctx: symbolize.AnnotateCtx = .{
        .img = &img,
        .syms = &syms,
        .index = &index,
        .fix = &fix,
        .stubs = &stubs,
        .funcs = &funcs,
        .objc = null,
        .strings = null,
    };
    var listings: std.ArrayList(insn_mod.Listing) = .empty;
    for (funcs.functions) |*f| {
        if (listings.items.len >= 64) break;
        try listings.append(a, try engine_mod.disassembleFunction(a, &e, &img, f, ctx, limits, &diags));
    }
    for (listings.items) |l| {
        if (l.comments.len != 0 and l.comments.len != l.insns.len) return error.CommentCountMismatch;
        if (l.labels.len != l.insns.len) return error.LabelCountMismatch;
    }
    var nbuf: [128]u8 = undefined;
    _ = symbolize.nameFor(ctx, img.image_base, &nbuf);
    const xr = try symbolize.buildXrefs(a, listings.items, ctx, .{}, limits);
    for (xr.by_to, 0..) |x, i| {
        if (i != 0 and xr.by_to[i - 1].to > x.to) return error.XrefsUnsorted;
        _ = xr.to(x.to);
        _ = xr.from(x.from);
    }
}

test "fuzz/disasm: the discovery/stub/annotate pipeline survives mutated corpus images" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const names = [_][]const u8{ "hello-c", "legacy-bind", "hello-objc" };
    for (names) |name| {
        const original = helpers.readFixture(io, gpa, name) catch continue;
        defer gpa.free(original);
        const buf = try gpa.dupe(u8, original);
        defer gpa.free(buf);
        var prng = std.Random.DefaultPrng.init(@as(u64, name.len) *% 0x9e37_79b9_7f4a_7c15);
        const random = prng.random();
        var round: u32 = 0;
        while (round < 96) : (round += 1) {
            @memcpy(buf, original);
            var ops = random.uintLessThan(u32, 8) + 1;
            while (ops > 0) : (ops -= 1) {
                switch (random.uintLessThan(u8, 3)) {
                    0 => buf[random.uintLessThan(usize, buf.len)] = random.int(u8),
                    1 => {
                        const at = random.uintLessThan(usize, buf.len / 4) * 4;
                        const pokes = [_]u32{ 0, 0xFFFFFFFF, 0x7FFFFFF0, @intCast(buf.len & 0xffff_ffff) };
                        std.mem.writeInt(u32, buf[at..][0..4], pokes[random.uintLessThan(usize, pokes.len)], .little);
                    },
                    else => {},
                }
            }
            const cut = if (random.boolean()) random.uintLessThan(usize, buf.len) + 1 else buf.len;
            try pipeline(gpa, buf[0..cut], &Limits.paranoid);
        }
    }
}

const PipelineCtx = struct {
    gpa: std.mem.Allocator,
    seed: []const u8,
    fn testOne(ctx: PipelineCtx, smith: *std.testing.Smith) anyerror!void {
        const buf = try ctx.gpa.dupe(u8, ctx.seed);
        defer ctx.gpa.free(buf);
        if (buf.len == 0) return;
        var ops = smith.valueRangeAtMost(u8, 0, 8);
        while (ops > 0) : (ops -= 1) {
            buf[smith.index(buf.len)] = smith.value(u8);
        }
        const n = smith.index(buf.len);
        try pipeline(ctx.gpa, buf[0..@max(n, 1)], &Limits.paranoid);
    }
};

test "fuzz/disasm: Smith-mutated hello-c through the whole pipeline" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const bytes = helpers.readFixture(io, gpa, "hello-c") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    try std.testing.fuzz(PipelineCtx{ .gpa = gpa, .seed = bytes }, PipelineCtx.testOne, .{ .corpus = &.{bytes} });
}

test "fuzz/disasm: every prefix of hello-c runs the pipeline without an error" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const bytes = helpers.readFixture(io, gpa, "hello-c") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    var len: usize = 0;
    while (len < bytes.len) : (len += @max(1, bytes.len / 64)) {
        try pipeline(gpa, bytes[0..len], &Limits.paranoid);
    }
    try pipeline(gpa, bytes, &Limits.default);
}
