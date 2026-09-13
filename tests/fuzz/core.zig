//! tests/fuzz/core.zig — Smith fuzzers and a 10 000-iteration deterministic sweep for the core
//! container/image/load-command parsers (DESIGN.md §10.5). Owned by WP1.
//! Every run is under `Limits.paranoid`; the only assertion is "it returned" — a trap, an out-of-bounds
//! read or an unbounded loop fails the test by crashing or timing out, in Debug and in ReleaseSafe.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const Reader = machre.core.reader.Reader;
const Limits = machre.core.limits.Limits;
const Diagnostics = machre.core.diag.Diagnostics;
const fat = machre.core.fat;
const Image = machre.core.image.Image;
const Arch = machre.core.arch.Arch;

/// File range of slice `idx` (thin = the whole buffer); null when the index has no entry.
fn sliceRange(c: fat.Container, idx: u32, total: usize) ?struct { off: u64, size: u64 } {
    return switch (c) {
        .thin => .{ .off = 0, .size = total },
        .fat => |f| if (idx < f.arches.len) .{ .off = f.arches[idx].offset, .size = f.arches[idx].size } else null,
        .not_macho => null,
    };
}

/// Parses `bytes` as a container, then every slice as an Image and walks its load commands,
/// segments and sections. Returns the number of slices that parsed (so nothing is optimised away).
fn parseAll(arena_state: *std.heap.ArenaAllocator, bytes: []const u8, limits: *const Limits) !usize {
    defer _ = arena_state.reset(.retain_capacity);
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, limits.max_diagnostics);
    const r = Reader.init(bytes, 0);
    const container = try fat.parse(arena, r, limits, &diags);
    var n: usize = 0;
    const sel = fat.selectArches(arena, container, null, true, Arch.host()) catch return n;
    for (sel.indices) |idx| {
        const range = sliceRange(container, idx, bytes.len) orelse continue;
        const sub = r.sub(range.off, range.size) orelse continue;
        const img = Image.parse(arena, sub, range.off, idx, limits, &diags) catch continue;
        n += 1;
        for (img.cmds) |c| {
            std.mem.doNotOptimizeAway(c.cmdsize);
            std.mem.doNotOptimizeAway(c.lc());
        }
        for (img.segments) |seg| {
            std.mem.doNotOptimizeAway(seg.vmaddr);
            std.mem.doNotOptimizeAway(img.segmentByName(seg.name) != null);
        }
        for (img.sections) |sec| {
            std.mem.doNotOptimizeAway(sec.sectType());
            std.mem.doNotOptimizeAway(img.sectionReader(&sec) != null);
        }
        std.mem.doNotOptimizeAway(img.dyldStyle());
        std.mem.doNotOptimizeAway(img.entryVm());
    }
    return n;
}

/// Up to 8 mutations of {byte flip, aligned u32 poke, truncation} applied to a copy of `seed`.
fn mutate(buf: []u8, seed: []const u8, random: std.Random) []u8 {
    @memcpy(buf[0..seed.len], seed);
    var len: usize = seed.len;
    const pokes = [_]u32{ 0, 0xFFFF_FFFF, 0x7FFF_FFF0, @truncate(seed.len), @truncate(seed.len + 1) };
    var k: u8 = 0;
    const ops = random.intRangeAtMost(u8, 1, 8);
    while (k < ops) : (k += 1) {
        if (len == 0) break;
        switch (random.uintLessThan(u8, 3)) {
            0 => buf[random.uintLessThan(usize, len)] ^= random.int(u8),
            1 => {
                if (len < 4) continue;
                const off = random.uintLessThan(usize, len / 4) * 4;
                std.mem.writeInt(u32, buf[off..][0..4], pokes[random.uintLessThan(usize, pokes.len)], .little);
            },
            else => len = random.uintLessThan(usize, len + 1),
        }
    }
    return buf[0..len];
}

test "fuzz/core: 10k mutants of hello-c through fat+image+loadcmds under Limits.paranoid" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(seed_bytes);
    const buf = try gpa.alloc(u8, seed_bytes.len);
    defer gpa.free(buf);
    var limits: Limits = .paranoid;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_0001);
    const random = prng.random();
    var i: u32 = 0;
    var parsed: usize = 0;
    while (i < 10_000) : (i += 1) {
        parsed += try parseAll(&arena_state, mutate(buf, seed_bytes, random), &limits);
    }
    // The unmutated seed must still parse, so the loop really exercised the parsers.
    try std.testing.expectEqual(@as(usize, 1), try parseAll(&arena_state, seed_bytes, &limits));
}

test "fuzz/core: every truncation of the hello-c header region parses without error" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(seed_bytes);
    var limits: Limits = .paranoid;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var n: usize = 0;
    while (n <= 1400) : (n += 1) _ = try parseAll(&arena_state, seed_bytes[0..n], &limits);
}

// `fat.parse` on arbitrary bytes: the fat header is entirely attacker-controlled.
test "fuzz/core: smith fat container" {
    const Ctx = struct {
        gpa: std.mem.Allocator,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            var limits: Limits = .paranoid;
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var diags = Diagnostics.init(arena, limits.max_diagnostics);
            const c = try fat.parse(arena, Reader.init(buf[0..n], 0), &limits, &diags);
            std.mem.doNotOptimizeAway(c.sliceCount());
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = std.testing.allocator }, Ctx.testOne, .{ .corpus = &.{
        "\xca\xfe\xba\xbe\x00\x00\x03\xe8",
        "\xca\xfe\xba\xbf\xff\xff\xff\xff",
        "\xcf\xfa\xed\xfe",
        "",
    } });
}

// `Image.parse` + the load-command walker on Smith-mutated hello-c bytes.
test "fuzz/core: smith image and load commands" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(seed_bytes);
    const head = seed_bytes[0..2048];
    const Ctx = struct {
        gpa: std.mem.Allocator,
        seed: []const u8,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            const buf = try ctx.gpa.alloc(u8, ctx.seed.len);
            defer ctx.gpa.free(buf);
            @memcpy(buf, ctx.seed);
            var k = smith.valueRangeAtMost(u8, 0, 8);
            while (k > 0) : (k -= 1) {
                const i = smith.index(buf.len);
                buf[i] = smith.value(u8);
            }
            const len = if (smith.eos()) buf.len else smith.index(buf.len + 1);
            var limits: Limits = .paranoid;
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            _ = try parseAll(&arena_state, buf[0..len], &limits);
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = gpa, .seed = head }, Ctx.testOne, .{ .corpus = &.{ head, head[0..64], head[0..32] } });
}
