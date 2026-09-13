//! tests/fuzz/plist_bundle.zig — Smith fuzzers + deterministic mutation sweeps for WP-plist_bundle.
//!
//! Every parser here is run under `Limits.paranoid`; the assertion is only that it returned (no trap,
//! no hang, no unbounded allocation). The deterministic sweeps run in plain `zig build test` too, so
//! the coverage does not depend on `--fuzz`.
const std = @import("std");
const Io = std.Io;
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const plist = machre.plist.plist;
const bplist = machre.plist.bplist;
const xml = machre.plist.xml;
const bundle = machre.bundle;
const Limits = machre.core.limits.Limits;
const Diagnostics = machre.core.diag.Diagnostics;

const xml_seed =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    \\<plist version="1.0"><dict>
    \\<key>files2</key><dict><key>Frameworks/x.dylib</key><dict>
    \\<key>cdhash</key><data>QbheIDu4wiSvu1zAK7Sl0oBJt1Q=</data>
    \\<key>requirement</key><string>cdhash H"41b8"</string></dict></dict>
    \\<key>rules2</key><dict><key>^Info\.plist$</key><dict><key>omit</key><true/></dict></dict>
    \\<key>n</key><integer>-1</integer><key>r</key><real>1.5</real>
    \\<key>d</key><date>2001-01-01T00:00:01Z</date><key>a</key><array><string>x&amp;y</string></array>
    \\</dict></plist>
;

/// Runs every plist/bundle parser over `bytes`; the only contract is that it returns.
fn runParsers(gpa: std.mem.Allocator, bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var budget = machre.core.limits.BudgetAllocator.init(arena_state.allocator(), Limits.paranoid.max_arena_bytes);
    const arena = budget.allocator();
    var diags = Diagnostics.init(arena, 32);
    const a = bplist.parse(arena, bytes, &Limits.paranoid, &diags) catch |e| switch (e) {
        error.OutOfMemory => return,
    };
    const b = xml.parse(arena, bytes, &Limits.paranoid, &diags) catch |e| switch (e) {
        error.OutOfMemory => return,
    };
    const c = plist.parseAny(arena, bytes, &Limits.paranoid, &diags) catch |e| switch (e) {
        error.OutOfMemory => return,
    };
    _ = bundle.parseCodeResources(arena, bytes, &Limits.paranoid, &diags) catch |e| switch (e) {
        error.OutOfMemory => return,
    };
    // Walk whatever came out: the walkers must terminate on any parsed tree.
    for ([_]?plist.Value{ a, b, c }) |maybe| {
        const v = maybe orelse continue;
        _ = v.deepEqual(v);
        _ = v.path("a.0.b");
        _ = v.getString("files2");
        var dbuf: [256]u8 = undefined;
        var discard: Io.Writer.Discarding = .init(&dbuf);
        var js: std.json.Stringify = .{ .writer = &discard.writer, .options = .{} };
        js.write(v) catch {};
    }
    _ = bplist.readTrailer(bytes);
}

test "fuzz/plist_bundle: smith over the bplist and XML seeds" {
    const Ctx = struct {
        gpa: std.mem.Allocator,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            const n = smith.slice(&buf);
            try runParsers(ctx.gpa, buf[0..n]);
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = std.testing.allocator }, Ctx.testOne, .{ .corpus = &.{ bplist.tiny, xml_seed, "bplist00", "<plist>" } });
}

/// 1..8 mutations of a seed, chosen by a seeded PRNG so the sweep is reproducible.
fn mutationSweep(gpa: std.mem.Allocator, seed_bytes: []const u8, seed: u64, rounds: u32) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const buf = try gpa.alloc(u8, seed_bytes.len);
    defer gpa.free(buf);
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        @memcpy(buf, seed_bytes);
        var len = buf.len;
        const ops = random.uintLessThan(u32, 8) + 1;
        var op: u32 = 0;
        while (op < ops) : (op += 1) {
            if (len == 0) break;
            switch (random.uintLessThan(u32, 3)) {
                0 => buf[random.uintLessThan(usize, len)] ^= @as(u8, 1) << random.int(u3),
                1 => {
                    const at = random.uintLessThan(usize, len);
                    if (at + 4 <= len) {
                        const choices = [_]u32{ 0, 0xFFFFFFFF, 0x7FFFFFF0, @intCast(len), @intCast(len + 1) };
                        std.mem.writeInt(u32, buf[at..][0..4], choices[random.uintLessThan(usize, choices.len)], .big);
                    }
                },
                else => len = random.uintLessThan(usize, len) + 1,
            }
        }
        try runParsers(gpa, buf[0..len]);
    }
}

test "fuzz/plist_bundle: deterministic mutation sweep over the corpus plists" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var dir = try helpers.openCorpus(io);
    defer dir.close(io);
    const seeds = [_][]const u8{
        "Hello.app/Contents/Info.plist",
        "Hello-Info.plist.xml",
        "Hello.app/Contents/_CodeSignature/CodeResources",
    };
    for (seeds, 0..) |rel, i| {
        const bytes = try dir.readFileAlloc(io, rel, gpa, .limited(1 << 22));
        defer gpa.free(bytes);
        try mutationSweep(gpa, bytes, 0x5eed_0000 + i, 128);
    }
    try mutationSweep(gpa, bplist.tiny, 0xb914, 256);
    try mutationSweep(gpa, xml_seed, 0x111, 256);
}

test "fuzz/plist_bundle: pathological shapes terminate" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 4096 nested arrays in XML: the depth cap stops the stack from growing.
    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(gpa);
    try deep.appendSlice(gpa, "<plist>");
    var i: usize = 0;
    while (i < 4096) : (i += 1) try deep.appendSlice(gpa, "<array>");
    try deep.appendSlice(gpa, "<string>x</string>");
    i = 0;
    while (i < 4096) : (i += 1) try deep.appendSlice(gpa, "</array>");
    try deep.appendSlice(gpa, "</plist>");
    try runParsers(gpa, deep.items);

    // Every prefix of the tiny bplist and of the XML seed.
    var n: usize = 0;
    while (n <= bplist.tiny.len) : (n += 1) try runParsers(gpa, bplist.tiny[0..n]);
    n = 0;
    while (n <= xml_seed.len) : (n += 4) try runParsers(gpa, xml_seed[0..n]);

    // The CodeResources rule matcher on adversarial patterns and long paths.
    var long: [512]u8 = @splat('a');
    const patterns = [_][]const u8{
        "^(a|b|c)*d",         ".*.*.*.*.*.*.*z",      "^[",                  "(((((((((",
        "\\",                 "^$",                   "^.*$",                "[^/]+",
        "^(.*/)?\\.DS_Store$", ".*\\.dSYM($|/)",      "^[^/]+$",             "^(a",
    };
    for (patterns) |p| {
        _ = bundle.regexSearch(p, &long);
        _ = bundle.regexSearch(p, "Frameworks/x.dylib");
        _ = bundle.regexSearch(p, "");
    }
    _ = arena;
}

test "fuzz/plist_bundle: every command survives a non-bundle directory" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dirs = [_][:0]const u8{ "/tmp", "/", "/bin" };
    for (dirs) |d| {
        for ([_][]const u8{ "bundle", "plist" }) |cmd| {
            const argv = [_][:0]const u8{ try arena.dupeSentinel(u8, cmd, 0), "--json", "--paranoid", d };
            const res = try helpers.runMachre(arena, io, &argv);
            try std.testing.expect(res.code == 0 or res.code == 3 or res.code == 4 or res.code == 5);
        }
    }
}
