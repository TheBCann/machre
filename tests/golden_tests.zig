//! tests/golden_tests.zig — table-driven golden tests: machre text vs tests/golden/<fixture>.<cmd>.txt and
//! machre --otool-compat text vs truth/<fixture>.txt sections; JSON key-inventory checks. Owned by WP0.
const std = @import("std");
const build_options = @import("build_options");
pub const helpers = @import("helpers.zig");
pub const truth = @import("truth.zig");

pub const Compare = enum { byte_exact, same_lines, same_line_set, json_keys };
pub const Row = struct {
    fixture: []const u8,
    argv: []const []const u8, // command + flags (fixture path appended)
    /// tests/golden/<golden_file> when compare != json_keys and truth_cmd == null
    golden_file: ?[]const u8 = null,
    /// truth section command prefix (e.g. "/usr/bin/nm -m") -> compare against truth/<fixture>.txt
    truth_cmd: ?[]const u8 = null,
    compare: Compare = .byte_exact,
    /// required JSON keys inside arches[0] (or top level when top_level)
    json_keys: []const []const u8 = &.{},
    top_level: bool = false,
    skip_without_security: bool = false,
};
pub const all_rows: []const []const Row = &.{
    @import("golden/core.rows.zig").rows,
    @import("golden/dyld.rows.zig").rows,
    @import("golden/codesign.rows.zig").rows,
    @import("golden/darwin.rows.zig").rows,
    @import("golden/plist_bundle.rows.zig").rows,
    @import("golden/objc_strings.rows.zig").rows,
    @import("golden/disasm.rows.zig").rows,
    @import("golden/triage.rows.zig").rows,
};
test "golden: rows table compiles" {
    var n: usize = 0;
    for (all_rows) |r| n += r.len;
    try std.testing.expect(!build_options.update_golden or n >= 0);
}

/// Dotted-path lookup into a JSON value ("info.header.magic").
fn lookup(v: std.json.Value, path: []const u8) ?std.json.Value {
    var cur = v;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |k| {
        cur = switch (cur) {
            .object => |o| o.get(k) orelse return null,
            .array => |a| blk: {
                const i = std.fmt.parseInt(usize, k, 10) catch return null;
                if (i >= a.items.len) return null;
                break :blk a.items[i];
            },
            else => return null,
        };
    }
    return cur;
}

/// Replaces the absolute corpus directory with the repo-relative "tests/corpus" so byte-exact goldens
/// are machine independent (`runRow` appends an absolute fixture path and every command echoes it).
fn portablePaths(arena: std.mem.Allocator, out: []const u8) ![]const u8 {
    const dir = helpers.corpusDir();
    if (std.mem.find(u8, out, dir) == null) return out;
    return std.mem.replaceOwned(u8, arena, out, dir, "tests/corpus");
}

/// Runs one row; failures print the row so it can be identified.
pub fn runRow(gpa: std.mem.Allocator, io: std.Io, row: Row) !void {
    if (row.skip_without_security and !build_options.have_security) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.summaryFixturePath(arena, row.fixture);
    if (std.mem.eql(u8, row.fixture, "bin-ls")) {
        std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch return error.SkipZigTest;
    }
    var argv: std.ArrayList([:0]const u8) = .empty;
    for (row.argv) |a| try argv.append(arena, try arena.dupeSentinel(u8, a, 0));
    try argv.append(arena, path);
    const res = try helpers.runMachre(arena, io, argv.items);
    errdefer {
        std.debug.print("golden row failed: fixture={s} argv=", .{row.fixture});
        for (row.argv) |a| std.debug.print("{s} ", .{a});
        std.debug.print("\n", .{});
    }
    switch (row.compare) {
        .byte_exact => {
            const gf = row.golden_file orelse return error.GoldenFileMissing;
            const gpath = try std.fmt.allocPrint(arena, "{s}/{s}", .{ try helpers.goldenDir(arena), gf });
            const out = try portablePaths(arena, res.out);
            if (build_options.update_golden) {
                var f = try std.Io.Dir.cwd().createFile(io, gpath, .{});
                defer f.close(io);
                var buf: [4096]u8 = undefined;
                var w = f.writer(io, &buf);
                try w.interface.writeAll(out);
                try w.interface.flush();
                return;
            }
            const want = std.Io.Dir.cwd().readFileAlloc(io, gpath, arena, .limited(1 << 26)) catch |e| {
                std.debug.print("cannot read golden file {s}: {t} (run zig build test-golden -Dupdate-golden=true)\n", .{ gpath, e });
                return e;
            };
            try std.testing.expectEqualStrings(want, out);
        },
        .same_lines, .same_line_set => {
            const tc = row.truth_cmd orelse return error.TruthCmdMissing;
            const secs = try truth.load(arena, io, row.fixture);
            const sec = truth.find(secs, tc) orelse {
                std.debug.print("truth section '{s}' not found in {s}.txt\n", .{ tc, row.fixture });
                return error.TruthSectionMissing;
            };
            if (row.compare == .same_lines) try truth.expectSameLines(sec.body, res.out) else try truth.expectSameLineSet(gpa, sec.body, res.out);
        },
        .json_keys => {
            var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
            defer parsed.deinit();
            const root = parsed.value;
            const base: std.json.Value = if (row.top_level) root else lookup(root, "arches.0") orelse {
                std.debug.print("no arches[0] in output\n", .{});
                return error.JsonKeyMissing;
            };
            for (row.json_keys) |k| {
                if (lookup(base, k) == null) {
                    std.debug.print("JSON key '{s}' missing\n", .{k});
                    return error.JsonKeyMissing;
                }
            }
            try std.testing.expectEqual(@as(u8, 0), res.code);
        },
    }
}

test "golden: every row" {
    const gpa = std.testing.allocator;
    // git does not store xattrs, so a fresh clone lacks the fixture's quarantine value. Apply it here:
    // test order across imported files is not guaranteed, so darwin.rows.zig's test may run after this one.
    try helpers.ensureQuarantineXattr(gpa, std.testing.io);
    var failures: usize = 0;
    var skipped: usize = 0;
    for (all_rows) |rows| for (rows) |row| {
        runRow(gpa, std.testing.io, row) catch |e| switch (e) {
            error.SkipZigTest => skipped += 1,
            else => {
                std.debug.print("  -> {t}\n", .{e});
                failures += 1;
            },
        };
    };
    if (failures != 0) {
        std.debug.print("{d} golden rows failed\n", .{failures});
        return error.GoldenRowsFailed;
    }
}
