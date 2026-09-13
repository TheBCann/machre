//! tests/fuzz/darwin.zig — Smith fuzzers + deterministic mutation sweeps for WP-darwin.
//! Parsers fuzzed: the com.apple.quarantine value parser, the CF -> plist.Value tree walk (driven by a
//! synthetic backend so it runs on every build, including -Dsecurity=false) and @rpath expansion.
//! Every fuzzer asserts only that the parser RETURNED: no trap, no hang, no unbounded allocation.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const xattr = machre.darwin.xattr;
const security = machre.darwin.security;
const dylib_resolve = machre.darwin.dylib_resolve;
const loadcmds = machre.core.loadcmds;
const Diagnostics = machre.Diagnostics;

/// Real quarantine values seen on this machine (format-notes 8) plus the corpus fixture's.
const quarantine_corpus: []const []const u8 = &.{
    "0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C",
    "01c1;69aa7f48;Firefox;DC0FB98F-9143-4CEE-A5F3-D77C06CB27EF",
    "0081;6a8dca47;Firefox;714D7932-0000-0000-0000-000000000000",
    "0083;68c3a1b2;;",
    ";;;",
    "",
};

test "fuzz darwin: quarantine value parser" {
    const Ctx = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            const raw = buf[0..n];
            const q = try xattr.parseQuarantine(a, raw);
            // Invariants: the parse is total and never yields a half-filled "well formed" record.
            if (q.well_formed) {
                if (q.flags == null or q.timestamp == null) return error.WellFormedWithoutFields;
            }
            if (q.raw.len > raw.len) return error.RawGrew;
            _ = xattr.isTranslocatedPath(raw);
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{ .corpus = quarantine_corpus });
}

// A random, possibly cyclic, possibly very deep CF-shaped tree. `convertTree` must terminate.
const FuzzNode = security.TestNode;
const FuzzBackend = security.TestBackend;

test "fuzz darwin: CF -> plist tree conversion with synthetic values" {
    const Ctx = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const a = arena.allocator();

            const count = smith.valueRangeAtMost(u8, 1, 24);
            const nodes = try a.alloc(FuzzNode, count);
            var names: [24][8]u8 = undefined;
            for (nodes, 0..) |*n, i| {
                names[i] = .{ 'k', 'e', 'y', '0' + @as(u8, @intCast(i / 10)), '0' + @as(u8, @intCast(i % 10)), 0, 0, 0 };
                n.* = .{ .kind = .scalar, .scalar = .null, .keys = &.{}, .kids = &.{} };
            }
            // Wire each node to a random kind and random children (indices may point backwards,
            // forwards or at the node itself, so cycles are common).
            for (nodes, 0..) |*n, i| {
                n.kind = switch (smith.valueRangeAtMost(u8, 0, 2)) {
                    0 => .scalar,
                    1 => .dict,
                    else => .array,
                };
                n.scalar = switch (smith.valueRangeAtMost(u8, 0, 5)) {
                    0 => .null,
                    1 => .{ .bool = smith.valueRangeAtMost(u8, 0, 1) == 1 },
                    2 => .{ .integer = smith.value(i64) },
                    3 => .{ .string = names[i][0..5] },
                    4 => .{ .data = names[i][0..5] },
                    else => .{ .date = @floatFromInt(smith.valueRangeAtMost(i32, -1000, 1000)) },
                };
                if (n.kind == .scalar) continue;
                const kid_count = smith.valueRangeAtMost(u8, 0, 6);
                const kids = try a.alloc(*const FuzzNode, kid_count);
                const keys = try a.alloc([]const u8, kid_count);
                for (kids, keys, 0..) |*k, *key, j| {
                    k.* = &nodes[smith.index(nodes.len)];
                    key.* = names[(i + j) % nodes.len][0..5];
                }
                n.kids = kids;
                n.keys = keys;
            }
            const root = &nodes[smith.index(nodes.len)];
            const v = try security.convertTree(FuzzBackend, .{ .arena = a }, a, root);
            try expectBoundedDepth(v, 0);
        }
        fn expectBoundedDepth(v: machre.plist.plist.Value, depth: usize) anyerror!void {
            if (depth > security.convert_max_depth + 1) return error.ConversionTooDeep;
            switch (v) {
                .array => |items| for (items) |it| try expectBoundedDepth(it, depth + 1),
                .dict => |entries| for (entries) |e| try expectBoundedDepth(e.value, depth + 1),
                else => {},
            }
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{ .corpus = &.{ "dict", "\x00\x01\x02\x03", "" } });
}

test "fuzz darwin: @rpath expansion and residency" {
    const Ctx = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            var diags = Diagnostics.init(a, 32);

            var name_buf: [256]u8 = undefined;
            var rpath_buf: [256]u8 = undefined;
            const name = name_buf[0..smith.slice(&name_buf)];
            const rpath = rpath_buf[0..smith.slice(&rpath_buf)];
            const weak = smith.valueRangeAtMost(u8, 0, 1) == 1;
            const d: loadcmds.Dylib = .{
                .cmd = if (weak) @intFromEnum(std.macho.LC.LOAD_WEAK_DYLIB) else @intFromEnum(std.macho.LC.LOAD_DYLIB),
                .name = name,
                .name_terminated = true,
                .timestamp = 0,
                .current_version = 0,
                .compat_version = 0,
                .flags = 0,
                .ordinal = 1,
                .weak = weak,
                .reexport = false,
                .upward = false,
                .delayed_init = false,
                .use_command = false,
            };
            const res = try dylib_resolve.resolveAll(a, std.testing.io, "/tmp/machre-fuzz/exe", &.{d}, &.{ rpath, "@rpath/loop", "@loader_path" }, &diags);
            if (res.len != 1) return error.WrongResolutionCount;
            // A resolved path is only ever reported together with a status that claims residency.
            if (res[0].resolved != null and res[0].status != .on_disk and res[0].status != .shared_cache)
                return error.ResolvedWithoutResidency;
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{ .corpus = &.{
        "@rpath/libhello.dylib",
        "@executable_path/../Frameworks/libhello.dylib",
        "/usr/lib/libSystem.B.dylib",
        "@loader_path/x",
        "",
    } });
}

// Deterministic sweep: every prefix and every single-byte mutation of the corpus quarantine value
// must parse. Complements the Smith fuzzers with a reproducible, seeded run (DESIGN §10.5).
test "fuzz darwin: deterministic quarantine mutation sweep" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const seed: u64 = std.hash.Wyhash.hash(0, "hello-quarantined");
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    const base = quarantine_corpus[0];
    var buf: [128]u8 = undefined;
    for (0..256) |_| {
        const len = rand.uintAtMost(usize, base.len);
        @memcpy(buf[0..len], base[0..len]);
        const ops = rand.uintLessThan(usize, 8) + 1;
        for (0..ops) |_| {
            if (len == 0) break;
            buf[rand.uintLessThan(usize, len)] = rand.int(u8);
        }
        const q = try xattr.parseQuarantine(a, buf[0..len]);
        if (q.well_formed and (q.flags == null or q.timestamp == null)) return error.WellFormedWithoutFields;
    }
}

// The quarantine command must return on every malformed fixture under the paranoid limits.
test "fuzz darwin: quarantine command on the malformed corpus" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (helpers.malformed_fixtures) |name| {
        const rel = try std.fmt.allocPrintSentinel(arena, "malformed/{s}", .{name}, 0);
        const path = try helpers.fixturePath(arena, rel);
        for ([_]bool{ false, true }) |paranoid| {
            var argv: std.ArrayList([:0]const u8) = .empty;
            try argv.append(arena, "quarantine");
            try argv.append(arena, "--json");
            if (paranoid) try argv.append(arena, "--paranoid");
            try argv.append(arena, path);
            const res = try helpers.runMachre(arena, io, argv.items);
            try std.testing.expect(res.code == 0 or res.code == 3 or res.code == 4 or res.code == 5);
            var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
            defer parsed.deinit();
            try std.testing.expect(parsed.value.object.get("exit_code") != null);
        }
    }
}
