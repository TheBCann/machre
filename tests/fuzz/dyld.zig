//! tests/fuzz/dyld.zig — Smith fuzzers + malformed-input expectations for WP2 (symbols, dyld_chained,
//! dyld_exports, dyld_legacy, function_starts, fixups, imports). Every parser must return, never trap.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const Limits = machre.Limits;
const Diagnostics = machre.Diagnostics;
const Image = machre.Image;
const LoadedFile = machre.LoadedFile;
const symbols = machre.macho.symbols;
const dyld_chained = machre.macho.dyld_chained;
const dyld_exports = machre.macho.dyld_exports;
const dyld_legacy = machre.macho.dyld_legacy;
const function_starts = machre.macho.function_starts;
const fixups = machre.macho.fixups;
const imports = machre.macho.imports;

/// Runs every WP2 parser over `bytes` under `limits`; asserts only that it returned.
fn parseAll(gpa: std.mem.Allocator, bytes: []const u8, limits: *const Limits) !void {
    var raw = std.heap.ArenaAllocator.init(gpa);
    defer raw.deinit();
    var budget = machre.core.limits.BudgetAllocator.init(raw.allocator(), limits.max_arena_bytes);
    const a = budget.allocator();
    var diags = Diagnostics.init(a, limits.max_diagnostics);
    var file = LoadedFile.fromBytes(a, "fuzz", bytes, limits, &diags) catch return;
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const r = file.sliceReader(i) orelse continue;
        const img = Image.parse(a, r, file.sliceOffset(i) orelse 0, @intCast(i), limits, &diags) catch continue;
        const t = symbols.parse(a, &img, limits, &diags) catch return;
        _ = symbols.AddressIndex.build(a, &t) catch return;
        const ch = dyld_chained.parse(a, &img, limits, &diags) catch return;
        const lg = dyld_legacy.parse(a, &img, limits, &diags) catch return;
        const tr = dyld_exports.parse(a, &img, limits, &diags) catch return;
        _ = tr;
        _ = function_starts.parseFunctionStarts(a, &img, limits, &diags) catch return;
        _ = function_starts.parseDataInCode(a, &img, limits, &diags) catch return;
        const fx = fixups.build(a, &img, if (ch) |*v| v else null, if (lg) |*v| v else null, limits, &diags) catch return;
        const dl = imports.dylibs(a, &img, limits, &diags) catch return;
        _ = imports.rpaths(a, &img, limits, &diags) catch return;
        _ = imports.imports(a, &img, &t, &fx, dl, limits, &diags) catch return;
        _ = imports.exports(a, &img, &t, null, limits, &diags) catch return;
        // slot resolution over a few addresses, including unmapped ones
        _ = fx.resolveSlot(&img, img.image_base);
        _ = fx.resolveSlot(&img, img.image_base +% 0x4000);
        _ = fx.resolveSlot(&img, 0xFFFF_FFFF_FFFF_FFF0);
    }
}

const Ctx = struct {
    gpa: std.mem.Allocator,
    seed: []const u8,

    fn testOne(ctx: Ctx, smith: *std.testing.Smith) anyerror!void {
        const buf = try ctx.gpa.dupe(u8, ctx.seed);
        defer ctx.gpa.free(buf);
        var len = buf.len;
        const n = smith.valueRangeAtMost(u8, 0, 8);
        var k: u8 = 0;
        while (k < n) : (k += 1) {
            if (len == 0) break;
            switch (smith.valueRangeAtMost(u8, 0, 2)) {
                0 => buf[smith.index(len)] ^= smith.value(u8),
                1 => {
                    const off = smith.index(len) & ~@as(usize, 3);
                    if (off + 4 <= len) std.mem.writeInt(u32, buf[off..][0..4], smith.value(u32), .little);
                },
                else => len = smith.index(len + 1),
            }
        }
        try parseAll(ctx.gpa, buf[0..len], &Limits.paranoid);
    }
};

test "fuzz/dyld: mutated hello-c and legacy-bind through every WP2 parser" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const chained = helpers.readFixture(io, gpa, "hello-c") catch return error.SkipZigTest;
    defer gpa.free(chained);
    const legacy = helpers.readFixture(io, gpa, "legacy-bind") catch return error.SkipZigTest;
    defer gpa.free(legacy);
    try std.testing.fuzz(Ctx{ .gpa = gpa, .seed = chained }, Ctx.testOne, .{ .corpus = &.{ chained[0..512], legacy[0..512] } });
    try std.testing.fuzz(Ctx{ .gpa = gpa, .seed = legacy }, Ctx.testOne, .{ .corpus = &.{legacy[0..512]} });
}

const TrieCtx = struct {
    gpa: std.mem.Allocator,
    fn testOne(ctx: TrieCtx, smith: *std.testing.Smith) anyerror!void {
        var buf: [512]u8 = undefined;
        const n = smith.slice(&buf);
        var raw = std.heap.ArenaAllocator.init(ctx.gpa);
        defer raw.deinit();
        var diags = Diagnostics.init(raw.allocator(), 64);
        _ = dyld_exports.parseBytes(raw.allocator(), buf[0..n], 0x100000000, &Limits.paranoid, &diags) catch return;
    }
};

test "fuzz/dyld: export trie walker on arbitrary bytes" {
    const gpa = std.testing.allocator;
    try std.testing.fuzz(TrieCtx{ .gpa = gpa }, TrieCtx.testOne, .{ .corpus = &.{
        &[_]u8{ 0x00, 0x01, '_', 0x00, 0x05, 0x00, 0x00 },
        &[_]u8{ 0x02, 0x00, 0x00, 0x00 },
        &[_]u8{0xff},
    } });
}

const OpcodeCtx = struct {
    gpa: std.mem.Allocator,
    fn testOne(ctx: OpcodeCtx, smith: *std.testing.Smith) anyerror!void {
        var buf: [512]u8 = undefined;
        const n = smith.slice(&buf);
        var raw = std.heap.ArenaAllocator.init(ctx.gpa);
        defer raw.deinit();
        _ = dyld_legacy.trace(raw.allocator(), buf[0..n], .bind, &Limits.paranoid) catch return;
        _ = dyld_legacy.trace(raw.allocator(), buf[0..n], .rebase, &Limits.paranoid) catch return;
    }
};

test "fuzz/dyld: legacy rebase and bind opcode traces on arbitrary bytes" {
    const gpa = std.testing.allocator;
    try std.testing.fuzz(OpcodeCtx{ .gpa = gpa }, OpcodeCtx.testOne, .{ .corpus = &.{
        &[_]u8{ 0x13, 0x40, '_', 'x', 0x00, 0x51, 0x72, 0x90, 0x01, 0x90, 0x00 },
        &[_]u8{ 0x11, 0x22, 0x50, 0x53, 0x80, 0xc5, 0x01, 0x18 },
        &[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
    } });
}

const PtrCtx = struct {
    fn testOne(_: PtrCtx, smith: *std.testing.Smith) anyerror!void {
        const raw = smith.value(u64);
        const fmt: dyld_chained.PointerFormat = @enumFromInt(smith.valueRangeAtMost(u16, 0, 20));
        _ = dyld_chained.decodePointer(raw, fmt, 0x100000000);
        _ = dyld_chained.nextOf(raw, fmt);
        _ = fmt.stride();
        _ = fmt.is32();
        _ = fmt.describe();
    }
};

test "fuzz/dyld: decodePointer over every pointer format and arbitrary raw words" {
    try std.testing.fuzz(PtrCtx{}, PtrCtx.testOne, .{ .corpus = &.{
        &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x80 },
        &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    } });
}

// ---- DESIGN §10.5 malformed-input expectations for the WP2 parsers ----

const Found = struct { truncated: bool = false, count_clamped: bool = false, chain_broken: bool = false, trie_malformed: bool = false, opcode_malformed: bool = false };

fn scan(diags: *const Diagnostics, module: machre.core.diag.Module) Found {
    var f: Found = .{};
    for (diags.items()) |d| {
        if (d.module != module) continue;
        switch (d.code) {
            .truncated => f.truncated = true,
            .count_clamped => f.count_clamped = true,
            .chain_broken => f.chain_broken = true,
            .trie_malformed => f.trie_malformed = true,
            .opcode_malformed => f.opcode_malformed = true,
            else => {},
        }
    }
    return f;
}

fn loadMalformed(gpa: std.mem.Allocator, io: std.Io, arena: *std.heap.ArenaAllocator, name: []const u8) !struct { file: LoadedFile, img: Image, diags: *Diagnostics } {
    const a = arena.allocator();
    const diags = try a.create(Diagnostics);
    diags.* = Diagnostics.init(a, 128);
    const path = try helpers.fixturePath(a, try std.fmt.allocPrint(a, "malformed/{s}", .{name}));
    var file = try LoadedFile.load(gpa, a, io, path, &Limits.default, diags);
    errdefer file.deinit(gpa);
    const img = try Image.parse(a, file.sliceReader(0).?, 0, 0, &Limits.default, diags);
    return .{ .file = file, .img = img, .diags = diags };
}

test "fuzz/dyld: malformed symtab fixtures clamp and report exactly one diagnostic each" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var p = try loadMalformed(gpa, io, &arena, "symtab-stroff-past-eof.bin");
        defer p.file.deinit(gpa);
        const t = try symbols.parse(arena.allocator(), &p.img, &Limits.default, p.diags);
        try std.testing.expectEqual(@as(usize, 12), t.symbols.len);
        for (t.symbols) |s| try std.testing.expectEqualStrings("", s.name);
        try std.testing.expect(scan(p.diags, .symbols).truncated);
        var n: usize = 0;
        for (p.diags.items()) |d| {
            if (d.module == .symbols) n += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), n);
    }
    {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var p = try loadMalformed(gpa, io, &arena, "symtab-nsyms-huge.bin");
        defer p.file.deinit(gpa);
        const t = try symbols.parse(arena.allocator(), &p.img, &Limits.default, p.diags);
        try std.testing.expect(scan(p.diags, .symbols).count_clamped);
        try std.testing.expect(t.truncated);
        try std.testing.expect(t.symbols.len < t.nsyms_declared);
        // clamped to the bytes that exist: 16-byte entries from symoff to the end of the slice
        try std.testing.expect(t.symbols.len == (p.img.r.len() - t.symtab.?.symoff) / 16);
    }
}

test "fuzz/dyld: malformed chained-fixups fixtures stop with truncated / count_clamped" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var p = try loadMalformed(gpa, io, &arena, "chained-fixups-absurd.bin");
        defer p.file.deinit(gpa);
        const ch = (try dyld_chained.parse(arena.allocator(), &p.img, &Limits.default, p.diags)).?;
        try std.testing.expect(ch.truncated);
        try std.testing.expectEqual(@as(usize, 0), ch.fixups.len);
        try std.testing.expectEqual(@as(usize, 0), ch.imports.len);
        try std.testing.expect(scan(p.diags, .chained).truncated);
        // the image itself is still fully walkable
        try std.testing.expectEqual(@as(usize, 18), p.img.cmds.len);
    }
    {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var p = try loadMalformed(gpa, io, &arena, "chained-starts-segcount-huge.bin");
        defer p.file.deinit(gpa);
        const ch = (try dyld_chained.parse(arena.allocator(), &p.img, &Limits.default, p.diags)).?;
        try std.testing.expect(ch.truncated);
        try std.testing.expectEqual(@as(u32, 0xFFFF_FFFF), ch.seg_count_declared);
        try std.testing.expect(ch.starts.len <= p.img.segments.len);
        try std.testing.expect(scan(p.diags, .chained).count_clamped);
        try std.testing.expectEqual(@as(usize, 18), p.img.cmds.len);
    }
}

test "fuzz/dyld: dyldinfo-bind-past-eof skips the bind stream with a truncated diagnostic" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var p = try loadMalformed(gpa, io, &arena, "dyldinfo-bind-past-eof.bin");
    defer p.file.deinit(gpa);
    const lg = (try dyld_legacy.parse(arena.allocator(), &p.img, &Limits.default, p.diags)).?;
    try std.testing.expect(lg.truncated);
    try std.testing.expectEqual(@as(u32, 0), lg.counts.bind);
    try std.testing.expect(scan(p.diags, .legacy).truncated);
    // the other streams still parse
    try std.testing.expect(lg.counts.lazy > 0 or lg.counts.rebase > 0);
}

test "fuzz/dyld: every prefix of hello-c and legacy-bind parses without trapping" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    for ([_][]const u8{ "hello-c", "legacy-bind" }) |name| {
        const bytes = helpers.readFixture(io, gpa, name) catch return error.SkipZigTest;
        defer gpa.free(bytes);
        var len: usize = 0;
        while (len <= bytes.len) : (len += if (len < 4096) 137 else 4093) {
            try parseAll(gpa, bytes[0..@min(len, bytes.len)], &Limits.paranoid);
            try parseAll(gpa, bytes[0..@min(len, bytes.len)], &Limits.default);
        }
    }
}
