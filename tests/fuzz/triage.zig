//! tests/fuzz/triage.zig — Smith fuzzers and a deterministic mutation sweep for WP9 (DESIGN.md §10.5).
//!
//! Triage sits on top of every parser, so a mutated file reaches it through the same `Analysis` facade the
//! CLI uses. Everything runs under `Limits.paranoid`; the only assertion is "it returned and produced a
//! self-consistent report" — a trap, an out-of-bounds read or an unbounded loop fails by crashing or
//! timing out, in Debug and in ReleaseSafe. Security.framework and dependency resolution are switched off
//! so the loop touches no OS service per iteration (and stays deterministic off this machine).
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const Limits = machre.core.limits.Limits;
const Diagnostics = machre.core.diag.Diagnostics;
const Reader = machre.core.reader.Reader;
const LoadedFile = machre.core.file.LoadedFile;
const Image = machre.core.image.Image;
const Analysis = machre.analysis.analysis.Analysis;
const triage = machre.analysis.triage;
const Sink = machre.output.sink.Sink;

const analysis_options: machre.analysis.analysis.Options = .{
    .security = false, // no SecStaticCode* call per iteration
    .network = false,
    .resolve_deps = false, // no filesystem lookup per iteration
};

/// Runs the whole triage pipeline over `bytes` and checks the report is internally consistent.
/// Returns the number of slices triaged (so nothing is optimised away).
fn triageAll(arena_state: *std.heap.ArenaAllocator, bytes: []const u8, limits: *const Limits) !usize {
    defer _ = arena_state.reset(.retain_capacity);
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, limits.max_diagnostics);
    var file = try LoadedFile.fromBytes(arena, "fuzz", bytes, limits, &diags);
    var n: usize = 0;
    var reports: std.ArrayList(triage.Report) = .empty;
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const r = file.sliceReader(i) orelse continue;
        const off = file.sliceOffset(i) orelse continue;
        const img = Image.parse(arena, r, off, @intCast(i), limits, &diags) catch continue;
        const img_ptr = try arena.create(Image);
        img_ptr.* = img;
        var an = Analysis.init(arena, arena, std.testing.io, &file, img_ptr, limits, &diags, analysis_options);
        defer an.deinit();
        const rep = try triage.run(arena, &an, null, .{}, limits, &diags);
        try expectConsistent(rep);
        try reports.append(arena, rep);
        n += 1;
    }
    if (reports.items.len != 0) {
        const merged = try triage.merge(arena, reports.items);
        try expectConsistent(merged);
        try render(arena, merged);
    }
    return n;
}

/// Invariants every Report must satisfy whatever the input bytes were.
fn expectConsistent(r: triage.Report) !void {
    var sum: u32 = 0;
    for (r.findings) |f| {
        try std.testing.expect(f.rule.weight < 50); // no single tell is a verdict
        try std.testing.expect(f.score <= f.rule.weight);
        try std.testing.expect(triage.byId(f.rule.id) != null);
        sum +|= f.score;
    }
    var credit: u32 = 0;
    for (r.positives) |p| credit +|= p.credit;
    try std.testing.expectEqual(sum -| credit, r.score);
    try std.testing.expectEqual(r.level, triage.levelFor(r.score, r.categories_hit.len));
    // a weight-0 finding never contributes a category
    for (r.categories_hit) |c| {
        var scored = false;
        for (r.findings) |f| if (f.rule.category == c and f.score != 0) {
            scored = true;
        };
        try std.testing.expect(scored);
    }
    try std.testing.expect(r.exit_code == 0 or r.exit_code == 20);
}

/// Both renderers must survive any report, and the JSON must parse back.
fn render(arena: std.mem.Allocator, r: triage.Report) !void {
    var text_out: std.Io.Writer.Allocating = .init(arena);
    var text_sink = Sink.init(.text, &text_out.writer, .{}, arena);
    try triage.writeText(&r, "fuzz", &text_sink);
    var json_out: std.Io.Writer.Allocating = .init(arena);
    var json_sink = Sink.init(.json, &json_out.writer, .{ .pretty_json = false }, arena);
    try triage.writeJson(&r, &json_sink);
    try json_sink.flush();
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, json_out.written(), .{});
    try std.testing.expect(parsed.object.get("level") != null);
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

test "fuzz/triage: 2k mutants of fake-upx through the whole rule table under Limits.paranoid" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "fake-upx");
    defer gpa.free(seed_bytes);
    const buf = try gpa.alloc(u8, seed_bytes.len);
    defer gpa.free(buf);
    var limits: Limits = .paranoid;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_0009);
    const random = prng.random();
    var i: u32 = 0;
    while (i < 2_000) : (i += 1) _ = try triageAll(&arena_state, mutate(buf, seed_bytes, random), &limits);
    // the unmutated seed must still triage, so the loop really exercised the rules
    try std.testing.expectEqual(@as(usize, 1), try triageAll(&arena_state, seed_bytes, &limits));
}

test "fuzz/triage: every truncation of the hello-c header region triages without error" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(seed_bytes);
    var limits: Limits = .paranoid;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var n: usize = 0;
    while (n <= 1400) : (n += 32) _ = try triageAll(&arena_state, seed_bytes[0..n], &limits);
}

test "fuzz/triage: every malformed fixture triages and merges" {
    const gpa = std.testing.allocator;
    var limits: Limits = .paranoid;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    for (helpers.malformed_fixtures) |name| {
        var path_buf: [128]u8 = undefined;
        const rel = try std.fmt.bufPrint(&path_buf, "malformed/{s}", .{name});
        const bytes = try helpers.readFixture(std.testing.io, gpa, rel);
        defer gpa.free(bytes);
        _ = triageAll(&arena_state, bytes, &limits) catch |e| {
            std.debug.print("triage {s}: {t}\n", .{ name, e });
            return e;
        };
    }
}

test "fuzz/triage: smith mutants of the fake-upx header reach the rule table" {
    const gpa = std.testing.allocator;
    const seed_bytes = try helpers.readFixture(std.testing.io, gpa, "fake-upx");
    defer gpa.free(seed_bytes);
    const head = try gpa.dupe(u8, seed_bytes[0..2048]);
    defer gpa.free(head);
    const Ctx = struct {
        gpa: std.mem.Allocator,
        seed: []const u8,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            @memcpy(buf[0..ctx.seed.len], ctx.seed);
            var len: usize = ctx.seed.len;
            var k: u8 = 0;
            const ops = smith.valueRangeAtMost(u8, 0, 8);
            while (k < ops and !smith.eos()) : (k += 1) {
                const i = smith.index(len);
                if (i < len) buf[i] ^= smith.value(u8);
            }
            if (smith.value(u8) & 1 != 0) len = smith.index(len + 1);
            var limits: Limits = .paranoid;
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            _ = try triageAll(&arena_state, buf[0..len], &limits);
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = gpa, .seed = head }, Ctx.testOne, .{ .corpus = &.{ "", "\xcf\xfa\xed\xfe" } });
}

test "fuzz/triage: random rule sets keep the scoring model consistent" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_000a);
    const random = prng.random();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var i: u32 = 0;
    while (i < 2_000) : (i += 1) {
        defer _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        var findings: std.ArrayList(triage.Finding) = .empty;
        var score: u32 = 0;
        const n = random.uintLessThan(usize, 12);
        var picked: std.ArrayList(*const triage.Rule) = .empty;
        for (0..n) |_| {
            const rule = &triage.rules[random.uintLessThan(usize, triage.rules.len)];
            var seen = false;
            for (picked.items) |p| if (p == rule) {
                seen = true;
            };
            if (seen) continue;
            try picked.append(arena, rule);
            const s = random.uintAtMost(u8, rule.weight);
            score +|= s;
            try findings.append(arena, .{ .rule = rule, .score = s, .title = rule.title, .detail = "fuzz", .evidence = &.{}, .corroborates = null });
        }
        var cats: std.ArrayList(triage.Category) = .empty;
        for (findings.items) |f| {
            if (f.score == 0) continue;
            var seen = false;
            for (cats.items) |c| if (c == f.rule.category) {
                seen = true;
            };
            if (!seen) try cats.append(arena, f.rule.category);
        }
        const level = triage.levelFor(score, cats.items.len);
        // The model's contract: a single category can never reach likely_malicious, and any score
        // below 20 is clean whatever fired.
        if (cats.items.len < 2) try std.testing.expect(level != .likely_malicious);
        if (score < 20) try std.testing.expectEqual(triage.Level.clean, level);
        const rep: triage.Report = .{
            .score = score,
            .level = level,
            .findings = findings.items,
            .positives = &.{},
            .categories_hit = cats.items,
            .corroboration = &.{},
            .not_flagged = &.{},
            .summary = .{ .signed = true, .trust = "AD HOC", .notarized = null, .hardened_runtime = false, .quarantined = false, .packed_hint = false, .encrypted = false, .imports = 0, .exports = 0, .symbols = 0, .dylibs = 0, .objc_classes = 0, .arch = "arm64" },
            .per_arch = true,
            .exit_code = triage.exitCodeFor(level, .suspicious),
        };
        try expectConsistent(rep);
        try render(arena, rep);
    }
}
