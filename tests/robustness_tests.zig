//! tests/robustness_tests.zig — malformed x command matrix, deterministic mutation sweep, budget tests,
//! plus imports of every WP's Smith fuzzers. Owned by WP0.
const std = @import("std");
const Io = std.Io;
const machre = @import("machre");
pub const helpers = @import("helpers.zig");
test {
    _ = @import("fuzz/core.zig");
    _ = @import("fuzz/dyld.zig");
    _ = @import("fuzz/codesign.zig");
    _ = @import("fuzz/darwin.zig");
    _ = @import("fuzz/plist_bundle.zig");
    _ = @import("fuzz/objc_strings.zig");
    _ = @import("fuzz/decoders.zig");
    _ = @import("fuzz/disasm.zig");
    _ = @import("fuzz/triage.zig");
}
test "robustness: malformed dir has 16 fixtures" {
    const io = std.testing.io;
    var dir = try helpers.openCorpus(io);
    defer dir.close(io);
    var mal = try dir.openDir(io, "malformed", .{ .iterate = true });
    defer mal.close(io);
    var it = mal.iterate();
    var n: usize = 0;
    while (try it.next(io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".bin")) n += 1;
    }
    try std.testing.expectEqual(@as(usize, 16), n);
}

/// Every command that takes a path (all but `version`).
fn pathCommands() []const machre.context.Command {
    return machre.cli.commands[0 .. machre.cli.commands.len - 1];
}

const Run = struct { code: u8, out: []const u8 };

fn runJson(arena: std.mem.Allocator, io: Io, cmd: []const u8, path: [:0]const u8, paranoid: bool, extra: []const [:0]const u8) !Run {
    var argv: std.ArrayList([:0]const u8) = .empty;
    try argv.append(arena, try arena.dupeSentinel(u8, cmd, 0));
    try argv.append(arena, "--json");
    if (paranoid) try argv.append(arena, "--paranoid");
    for (extra) |e| try argv.append(arena, e);
    try argv.append(arena, path);
    const r = try helpers.runMachre(arena, io, argv.items);
    return .{ .code = r.code, .out = r.out };
}
fn runText(gpa: std.mem.Allocator, io: Io, cmd: []const u8, path: [:0]const u8, paranoid: bool) u8 {
    var buf: [256]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&buf);
    var ebuf: [64]u8 = undefined;
    var err: Io.Writer.Discarding = .init(&ebuf);
    var argv_buf: [4][:0]const u8 = undefined;
    var n: usize = 0;
    argv_buf[n] = @ptrCast(cmd);
    n += 1;
    if (paranoid) {
        argv_buf[n] = "--paranoid";
        n += 1;
    }
    argv_buf[n] = path;
    n += 1;
    return machre.cli.runArgv(gpa, io, argv_buf[0..n], &sink.writer, &err.writer);
}
fn hasCode(root: std.json.Value, code: []const u8) bool {
    const diags = root.object.get("diagnostics") orelse return false;
    for (diags.array.items) |d| {
        if (std.mem.eql(u8, d.object.get("code").?.string, code)) return true;
    }
    return false;
}
fn okExit(code: u8) bool {
    return code == 0 or code == 3 or code == 4 or code == 5;
}

const Expect = struct { file: []const u8, code: ?[]const u8, exit: ?u8 = null };
const expectations = [_]Expect{
    .{ .file = "truncated-header.bin", .code = "truncated", .exit = 3 },
    .{ .file = "bogus-ncmds.bin", .code = "count_clamped" },
    .{ .file = "cmdsize-zero.bin", .code = "cmdsize_invalid" },
    .{ .file = "cmdsize-huge.bin", .code = "cmdsize_invalid" },
    .{ .file = "fat-1000-arches.bin", .code = "count_clamped" },
    .{ .file = "fat-arch-offset-past-eof.bin", .code = "offset_past_eof" },
    .{ .file = "sizeofcmds-too-big.bin", .code = "sizeofcmds_invalid" },
    .{ .file = "section-offset-past-eof.bin", .code = "offset_past_eof" },
    .{ .file = "nsects-huge.bin", .code = "nsects_invalid" },
    .{ .file = "symtab-stroff-past-eof.bin", .code = "offset_past_eof" },
    .{ .file = "symtab-nsyms-huge.bin", .code = "offset_past_eof" },
    .{ .file = "chained-fixups-absurd.bin", .code = null },
    .{ .file = "chained-starts-segcount-huge.bin", .code = null },
    .{ .file = "dyldinfo-bind-past-eof.bin", .code = "offset_past_eof" },
    .{ .file = "bad-magic.bin", .code = "bad_magic", .exit = 3 },
    .{ .file = "empty.bin", .code = "bad_magic", .exit = 3 },
};

test "robustness: malformed matrix (every command, default and paranoid limits, text and JSON)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failures: usize = 0;
    for (helpers.malformed_fixtures) |name| {
        const path = try helpers.fixturePath(arena, try std.fmt.allocPrint(arena, "malformed/{s}", .{name}));
        var exp: ?Expect = null;
        for (expectations) |e| if (std.mem.eql(u8, e.file, name)) {
            exp = e;
        };
        for (pathCommands()) |cmd| {
            for ([_]bool{ false, true }) |paranoid| {
                const tcode = runText(gpa, io, cmd.name, path, paranoid);
                if (!okExit(tcode)) {
                    std.debug.print("text {s} {s} paranoid={} -> exit {d}\n", .{ cmd.name, name, paranoid, tcode });
                    failures += 1;
                }
                const r = try runJson(arena, io, cmd.name, path, paranoid, &.{});
                if (!okExit(r.code)) {
                    std.debug.print("json {s} {s} paranoid={} -> exit {d}\n", .{ cmd.name, name, paranoid, r.code });
                    failures += 1;
                }
                var parsed = std.json.parseFromSlice(std.json.Value, gpa, r.out, .{}) catch |e| {
                    std.debug.print("json {s} {s}: output not JSON ({t})\n", .{ cmd.name, name, e });
                    failures += 1;
                    continue;
                };
                defer parsed.deinit();
                const root = parsed.value;
                const jexit: i64 = root.object.get("exit_code").?.integer;
                if (jexit != r.code) {
                    std.debug.print("json {s} {s}: exit_code {d} != returned {d}\n", .{ cmd.name, name, jexit, r.code });
                    failures += 1;
                }
                if (exp) |e| if (cmd.needs_macho) {
                    if (e.exit) |want| if (r.code != want) {
                        std.debug.print("json {s} {s}: exit {d}, wanted {d}\n", .{ cmd.name, name, r.code, want });
                        failures += 1;
                    };
                    if (e.code) |code| if (!hasCode(root, code)) {
                        std.debug.print("json {s} {s}: diagnostic '{s}' missing\n", .{ cmd.name, name, code });
                        failures += 1;
                    };
                };
            }
        }
    }
    if (failures != 0) return error.MalformedMatrixFailed;
}

test "robustness: specific malformed expectations (§10.5)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const P = struct {
        fn get(root: std.json.Value, path: []const u8) ?std.json.Value {
            var cur = root;
            var it = std.mem.splitScalar(u8, path, '.');
            while (it.next()) |k| cur = switch (cur) {
                .object => |o| o.get(k) orelse return null,
                .array => |a| a.items[std.fmt.parseInt(usize, k, 10) catch return null],
                else => return null,
            };
            return cur;
        }
    };
    // cmdsize-zero: 0 commands after LC[0]; bogus-ncmds and sizeofcmds-too-big: 18 commands
    const cases = [_]struct { file: []const u8, cmd: []const u8, path: []const u8, want: i64 }{
        .{ .file = "cmdsize-zero.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 0 },
        .{ .file = "cmdsize-huge.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 0 },
        .{ .file = "bogus-ncmds.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 18 },
        .{ .file = "sizeofcmds-too-big.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 18 },
        .{ .file = "nsects-huge.bin", .cmd = "segments", .path = "arches.0.segments.1.section_count", .want = 4 },
        .{ .file = "chained-fixups-absurd.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 18 },
        .{ .file = "chained-starts-segcount-huge.bin", .cmd = "loadcmds", .path = "arches.0.loadcmds.ncmds_parsed", .want = 18 },
    };
    for (cases) |c| {
        const path = try helpers.fixturePath(arena, try std.fmt.allocPrint(arena, "malformed/{s}", .{c.file}));
        const r = try runJson(arena, io, c.cmd, path, false, &.{});
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
        defer parsed.deinit();
        const v = P.get(parsed.value, c.path) orelse {
            std.debug.print("{s} {s}: path {s} missing\n", .{ c.cmd, c.file, c.path });
            return error.PathMissing;
        };
        try std.testing.expectEqual(c.want, v.integer);
    }
    // fat-1000-arches: both real arches analysable; fat-arch-offset-past-eof: arch 0 invalid, arch 1 analysed
    {
        const path = try helpers.fixturePath(arena, "malformed/fat-1000-arches.bin");
        const r = try runJson(arena, io, "header", path, false, &.{"--all-archs"});
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(usize, 2), parsed.value.object.get("arches").?.array.items.len);
    }
    {
        const path = try helpers.fixturePath(arena, "malformed/fat-arch-offset-past-eof.bin");
        const r = try runJson(arena, io, "header", path, false, &.{"--all-archs"});
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
        defer parsed.deinit();
        const arches = parsed.value.object.get("arches").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), arches.len);
        try std.testing.expectEqualStrings("arm64", arches[0].object.get("arch").?.string);
        const fat_arches = P.get(parsed.value, "file.fat.arches").?.array.items;
        try std.testing.expect(!fat_arches[0].object.get("valid").?.bool);
        try std.testing.expect(fat_arches[1].object.get("valid").?.bool);
        const tr = try helpers.runMachre(arena, io, &.{ "info", path });
        try std.testing.expectEqual(@as(u8, 0), tr.code);
        try std.testing.expect(std.mem.find(u8, tr.out, "arm64") != null);
    }
}

/// Deterministic mutation sweep: for each healthy fixture, `rounds` mutants from a seeded DefaultPrng
/// (byte flips, u32 pokes with {0, 0xFFFFFFFF, 0x7FFFFFF0, len, len+1}, truncations) through every command.
pub fn mutationSweep(gpa: std.mem.Allocator, io: Io, fixture: []const u8, seed: u64, rounds: u32) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const orig = try helpers.readFixture(io, gpa, fixture);
    defer gpa.free(orig);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f0 = try tmp.dir.createFile(io, "mutant.bin", .{});
        f0.close(io);
    }
    const real = try tmp.dir.realPathFileAlloc(io, "mutant.bin", arena);
    const tmp_path: [:0]const u8 = try arena.dupeSentinel(u8, real, 0);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const mutant = try gpa.alloc(u8, orig.len);
    defer gpa.free(mutant);
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        @memcpy(mutant, orig);
        var len: usize = orig.len;
        const ops = random.intRangeAtMost(u8, 1, 8);
        var k: u8 = 0;
        while (k < ops) : (k += 1) {
            if (len == 0) break;
            switch (random.uintLessThan(u8, 3)) {
                0 => mutant[random.uintLessThan(usize, len)] ^= random.int(u8),
                1 => {
                    if (len < 4) continue;
                    const off = random.uintLessThan(usize, len / 4) * 4;
                    const vals = [_]u32{ 0, 0xFFFFFFFF, 0x7FFFFFF0, @truncate(orig.len), @truncate(orig.len + 1) };
                    std.mem.writeInt(u32, mutant[off..][0..4], vals[random.uintLessThan(usize, vals.len)], .little);
                },
                else => len = random.uintLessThan(usize, len + 1),
            }
        }
        {
            var f = try tmp.dir.createFile(io, "mutant.bin", .{});
            defer f.close(io);
            var wbuf: [8192]u8 = undefined;
            var w = f.writer(io, &wbuf);
            try w.interface.writeAll(mutant[0..len]);
            try w.interface.flush();
        }
        // c_allocator: the leak-checked testing allocator captures a stack trace per allocation, which
        // dominates the 80k runs of this sweep; leak checks are covered by the malformed matrix.
        for (pathCommands()) |cmd| {
            const code = runText(std.heap.c_allocator, io, cmd.name, tmp_path, true);
            if (!okExit(code)) {
                std.debug.print("mutation sweep: {s} round {d} cmd {s} -> exit {d}\n", .{ fixture, round, cmd.name, code });
                return error.MutantCrashedOrInternal;
            }
        }
    }
}

test "robustness: deterministic mutation sweep over the healthy fixtures" {
    const io = std.testing.io;
    for (helpers.healthy_fixtures) |name| {
        const seed = std.hash.Wyhash.hash(0, name);
        try mutationSweep(std.testing.allocator, io, name, seed, 256);
    }
}

test "robustness: budget and size caps map to exit codes, never traps" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-c");
    const r1 = try helpers.runMachre(arena, io, &.{ "info", "--json", "--max-arena-bytes=2048", path });
    try std.testing.expectEqual(@as(u8, 70), r1.code);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, r1.out, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 70), parsed.value.object.get("exit_code").?.integer);
    const r2 = try helpers.runMachre(arena, io, &.{ "info", "--max-file-size=1000", path });
    try std.testing.expectEqual(@as(u8, 5), r2.code);
    const r3 = try helpers.runMachre(arena, io, &.{ "info", "--json", "--max-file-size=1000", path });
    try std.testing.expectEqual(@as(u8, 5), r3.code);
    const r4 = try helpers.runMachre(arena, io, &.{ "info", "--strict", try helpers.fixturePath(arena, "malformed/cmdsize-zero.bin") });
    try std.testing.expectEqual(@as(u8, 4), r4.code);
    const r5 = try helpers.runMachre(arena, io, &.{ "info", "--arch", "arm64e", path });
    try std.testing.expectEqual(@as(u8, 3), r5.code);
}

test "robustness: no raw byte indexing outside core/reader.zig and core/sanitize.zig" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const res = std.process.run(gpa, io, .{ .argv = &.{ "/usr/bin/grep", "-rnE", "\\.bytes\\[", helpers.srcDir() } }) catch return error.SkipZigTest;
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    var bad: usize = 0;
    var it = std.mem.splitScalar(u8, res.stdout, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.find(u8, line, "core/reader.zig") != null or std.mem.find(u8, line, "core/sanitize.zig") != null) continue;
        // doc comments and the fixed-size Insn.bytes copy are allowed
        const colon2 = blk: {
            const c1 = std.mem.findScalar(u8, line, ':') orelse break :blk 0;
            break :blk (std.mem.findScalarPos(u8, line, c1 + 1, ':') orelse 0) + 1;
        };
        const code = std.mem.trimStart(u8, line[colon2..], " ");
        if (std.mem.startsWith(u8, code, "//")) continue;
        if (std.mem.find(u8, code, "insn.bytes[") != null or std.mem.find(u8, code, ".bytes[0..16]") != null) continue;
        std.debug.print("raw byte index: {s}\n", .{line});
        bad += 1;
    }
    if (bad != 0) return error.RawByteIndex;
}
