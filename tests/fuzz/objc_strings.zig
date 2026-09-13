//! tests/fuzz/objc_strings.zig — Smith fuzzers for the WP6 parsers (ObjC metadata, strings, entropy).
//! Each `testOne` copies a corpus seed, applies up to 8 Smith-chosen mutations and runs the parser
//! under `Limits.paranoid`, asserting only that it returns: no trap, no hang, no unbounded growth.
//! Plain `zig build test` runs every corpus entry once; `zig build test-robustness --fuzz` loops.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const Limits = machre.Limits;
const Diagnostics = machre.Diagnostics;

/// Which parser a fuzz run drives (all three share the same mutate-then-parse harness).
const Target = enum { objc, strings, entropy };

const Ctx = struct {
    target: Target,
    runs: *usize,

    fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
        var buf: [96 * 1024]u8 = undefined;
        const n = smith.slice(&buf); // number of bytes written into `buf`
        if (n < 4) return;
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const bytes = try arena.dupe(u8, buf[0..n]);

        // up to 8 mutations: byte flips and aligned u32 pokes with hostile values
        const mutations = smith.valueRangeAtMost(u8, 0, 8);
        var i: u8 = 0;
        while (i < mutations) : (i += 1) {
            const at = smith.index(bytes.len);
            if (smith.value(bool) or at + 4 > bytes.len) {
                bytes[at] ^= smith.value(u8);
            } else {
                const hostile = [_]u32{ 0, 0xffff_ffff, 0x7fff_fff0, @intCast(bytes.len), 0x8000_0000 };
                std.mem.writeInt(u32, bytes[at..][0..4], hostile[smith.index(hostile.len)], .little);
            }
        }

        var diags = Diagnostics.init(arena, 64);
        var file = try machre.LoadedFile.fromBytes(arena, "fuzz", bytes, &Limits.paranoid, &diags);
        defer file.deinit(arena);
        var slice: usize = 0;
        while (slice < file.sliceCount()) : (slice += 1) {
            const r = file.sliceReader(slice) orelse continue;
            const img = machre.Image.parse(arena, r, file.sliceOffset(slice) orelse 0, @intCast(slice), &Limits.paranoid, &diags) catch continue;
            switch (ctx.target) {
                .objc => {
                    const info = try machre.objc.parse(arena, &img, &machre.macho.fixups.FixupTable.empty, &machre.macho.symbols.SymbolTable.empty, &Limits.paranoid, &diags);
                    try std.testing.expect(info.classes.len <= Limits.paranoid.max_objc_classes);
                    for (info.classes) |c| try std.testing.expect(c.methods.len <= Limits.paranoid.max_objc_methods_per_list);
                    _ = try machre.objc.methodImps(arena, &info);
                },
                .strings => {
                    const res = try machre.strings.extract(arena, &img, &machre.macho.fixups.FixupTable.empty, .{ .min_len = 1 }, &Limits.paranoid, &diags);
                    try std.testing.expect(res.strings.len <= Limits.paranoid.max_strings);
                    for (res.strings) |s| try std.testing.expect(s.text.len <= Limits.paranoid.max_string_len);
                },
                .entropy => {
                    const rep = try machre.analysis.entropy.analyze(arena, &img, .{ .symbol_count = 0, .import_count = 0, .encryption = null, .entry_vm = null });
                    try std.testing.expect(rep.file >= 0 and rep.file <= 8.0001);
                    for (rep.segments) |seg| try std.testing.expect(seg.entropy >= 0 and seg.entropy <= 8.0001);
                },
            }
        }
        ctx.runs.* += 1;
    }
};

fn fuzzTarget(target: Target, seeds: []const []const u8) !void {
    var runs: usize = 0;
    try std.testing.fuzz(Ctx{ .target = target, .runs = &runs }, Ctx.testOne, .{ .corpus = seeds });
}

test "fuzz/objc_strings: objc metadata parser" {
    const gpa = std.testing.allocator;
    const objc_seed = try helpers.readFixture(std.testing.io, gpa, "hello-objc");
    defer gpa.free(objc_seed);
    const c_seed = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(c_seed);
    try fuzzTarget(.objc, &.{ objc_seed, c_seed });
}

test "fuzz/objc_strings: string extractor" {
    const gpa = std.testing.allocator;
    const objc_seed = try helpers.readFixture(std.testing.io, gpa, "hello-objc");
    defer gpa.free(objc_seed);
    const zig_seed = try helpers.readFixture(std.testing.io, gpa, "hello-zig");
    defer gpa.free(zig_seed);
    try fuzzTarget(.strings, &.{ objc_seed, zig_seed });
}

test "fuzz/objc_strings: entropy analyzer" {
    const gpa = std.testing.allocator;
    const seed = try helpers.readFixture(std.testing.io, gpa, "high-entropy");
    defer gpa.free(seed);
    try fuzzTarget(.entropy, &.{seed});
}

test "fuzz/objc_strings: raw string scan over arbitrary bytes never exceeds its limits" {
    const Raw = struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [8192]u8 = undefined;
            const bytes = buf[0..smith.slice(&buf)];
            var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const min = smith.valueRangeAtMost(u32, 0, 16);
            const res = try machre.strings.extractRaw(arena, bytes, 0, .{ .min_len = min }, &Limits.paranoid);
            try std.testing.expect(res.strings.len <= Limits.paranoid.max_strings);
            for (res.strings) |s| {
                try std.testing.expect(s.text.len >= @max(min, 1) or s.kind == .generic_utf16);
                try std.testing.expect(s.file_offset <= bytes.len);
            }
        }
    };
    try std.testing.fuzz({}, Raw.testOne, .{ .corpus = &.{ "hello world\x00\xff\xfe", "", "a\x00b\x00c\x00d\x00" } });
}

test "fuzz/objc_strings: classifier never rejects a byte string" {
    const Cls = struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const bytes = buf[0..smith.slice(&buf)];
            _ = machre.strings.classify(bytes);
        }
    };
    try std.testing.fuzz({}, Cls.testOne, .{ .corpus = &.{ "https://x.example/a", "192.168.1.1", "/Library/LaunchAgents/x.plist", "%s %d" } });
}
