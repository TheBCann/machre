//! tests/golden/disasm.rows.zig — golden rows and text snapshots for WP8 (`disasm`, `functions`, `xrefs`).
//! Imported by tests/golden_tests.zig.
//!
//! Two layers:
//!  1. `rows` — the `--otool-compat` parity rows (machre text vs the `otool -tV` / `dyld_info
//!     -function_starts` sections of truth/<fixture>.txt, both added to gen/truth.sh by WP8) plus the
//!     §6.3 JSON key inventory for the three commands.
//!  2. `test "golden: disasm text snapshots"` — byte-exact comparison against tests/golden/<fixture>.<cmd>.txt
//!     with the corpus directory normalised to "tests/corpus" so the files are machine-independent.
//!     The `disasm` snapshots pass `--backend=builtin` so the text is identical in Capstone and
//!     non-Capstone builds (DESIGN §13.1 item 3).
const std = @import("std");
const build_options = @import("build_options");
const golden = @import("../golden_tests.zig");
const helpers = golden.helpers;

const otool_tv = "/usr/bin/otool -tV";
const dyld_function_starts = "/usr/bin/dyld_info -function_starts";

/// One `disasm --otool-compat` row: the whole `__TEXT,__text` of a fixture against `otool -tV`.
/// `hello-zig` and `/bin/ls`'s arm64e slice are deliberately absent — they contain SIMD encodings WP7
/// prints in ARM syntax (`movi v0.2d, #…`) where Darwin otool uses the suffix form (`movi.2d v0, #…`);
/// `hello-x86_64` needs Capstone for otool's AT&T text, so it lives in tests/facts/disasm.zig.
fn tvRow(comptime fixture: []const u8) golden.Row {
    return .{
        .fixture = fixture,
        .argv = &.{ "disasm", "--otool-compat" },
        .truth_cmd = otool_tv,
        .compare = .same_lines,
    };
}
fn fsRow(comptime fixture: []const u8) golden.Row {
    return .{
        .fixture = fixture,
        .argv = &.{ "functions", "--otool-compat" },
        .truth_cmd = dyld_function_starts,
        .compare = .same_lines,
    };
}

const disasm_keys: []const []const u8 = &.{
    "disasm.backend",                             "disasm.text_backend",
    "disasm.syntax",                              "disasm.partial",
    "disasm.disagreements",                       "disasm.truncated",
    "disasm.functions.0.name",                    "disasm.functions.0.start",
    "disasm.functions.0.end",                     "disasm.functions.0.source",
    "disasm.functions.0.instructions.0.address",  "disasm.functions.0.instructions.0.size",
    "disasm.functions.0.instructions.0.bytes",    "disasm.functions.0.instructions.0.mnemonic",
    "disasm.functions.0.instructions.0.operands", "disasm.functions.0.instructions.0.kind",
    "disasm.functions.0.instructions.0.comment",  "disasm.functions.0.instructions.0.comment_kind",
    "disasm.functions.0.instructions.0.label",
};
const functions_keys: []const []const u8 = &.{
    "functions.0.name",    "functions.0.start",  "functions.0.end",
    "functions.0.size",    "functions.0.source", "functions.0.name_source",
    "functions.0.section",
};
const xrefs_keys: []const []const u8 = &.{
    "xrefs.0.from", "xrefs.0.from_function", "xrefs.0.to",             "xrefs.0.to_name",
    "xrefs.0.kind", "xrefs.0.via_stub",      "pointer_slots_included",
};

pub const rows: []const golden.Row = &([_]golden.Row{
    tvRow("hello-c"),        tvRow("hello-objc"),     tvRow("legacy-bind"),
    tvRow("libhello.dylib"), tvRow("hello-usedylib"), tvRow("hello-adhoc"),
    tvRow("hello-entitled"), tvRow("hello-unsigned"), tvRow("high-entropy"),
    tvRow("fake-packed"),    tvRow("fake-upx"),       tvRow("hello-quarantined"),
    fsRow("hello-c"),        fsRow("hello-objc"),     fsRow("legacy-bind"),
    fsRow("hello-zig"),      fsRow("libhello.dylib"), fsRow("hello-x86_64"),
} ++ [_]golden.Row{
    .{ .fixture = "hello-c", .argv = &.{ "disasm", "--func", "_main", "--json" }, .compare = .json_keys, .json_keys = disasm_keys },
    .{ .fixture = "hello-objc", .argv = &.{ "disasm", "--func", "_main", "--json" }, .compare = .json_keys, .json_keys = disasm_keys },
    .{ .fixture = "legacy-bind", .argv = &.{ "disasm", "--json" }, .compare = .json_keys, .json_keys = disasm_keys },
    .{ .fixture = "hello-c", .argv = &.{ "functions", "--json" }, .compare = .json_keys, .json_keys = functions_keys },
    .{ .fixture = "hello-objc", .argv = &.{ "functions", "--json" }, .compare = .json_keys, .json_keys = functions_keys },
    .{ .fixture = "hello-c", .argv = &.{ "xrefs", "--json" }, .compare = .json_keys, .json_keys = xrefs_keys },
    .{ .fixture = "legacy-bind", .argv = &.{ "xrefs", "--json" }, .compare = .json_keys, .json_keys = xrefs_keys },
});

// ---------------------------------------------------------------------------------------------
// byte-exact text snapshots
// ---------------------------------------------------------------------------------------------

const Snap = struct { fixture: []const u8, cmd: []const u8, argv: []const []const u8 };
const snapshots: []const Snap = &.{
    .{ .fixture = "hello-c", .cmd = "disasm", .argv = &.{ "disasm", "--func", "_main", "--backend=builtin" } },
    .{ .fixture = "legacy-bind", .cmd = "disasm", .argv = &.{ "disasm", "--func", "_main", "--backend=builtin" } },
    .{ .fixture = "hello-objc", .cmd = "disasm", .argv = &.{ "disasm", "--func", "-[MachreDog bark]", "--backend=builtin" } },
    .{ .fixture = "hello-c", .cmd = "functions", .argv = &.{"functions"} },
    .{ .fixture = "hello-objc", .cmd = "functions", .argv = &.{"functions"} },
    .{ .fixture = "hello-c", .cmd = "xrefs", .argv = &.{"xrefs"} },
};

/// Replaces the absolute corpus path with "tests/corpus" so a snapshot is machine-independent.
fn normalize(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    const dir = helpers.corpusDir();
    const out = try arena.alloc(u8, std.mem.replacementSize(u8, s, dir, "tests/corpus"));
    _ = std.mem.replace(u8, s, dir, "tests/corpus", out);
    return out;
}

fn runSnapshot(gpa: std.mem.Allocator, io: std.Io, s: Snap) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.summaryFixturePath(arena, s.fixture);
    var argv: std.ArrayList([:0]const u8) = .empty;
    for (s.argv) |a| try argv.append(arena, try arena.dupeSentinel(u8, a, 0));
    try argv.append(arena, path);
    const res = try helpers.runMachre(arena, io, argv.items);
    const got = try normalize(arena, res.out);
    const gpath = try std.fmt.allocPrint(arena, "{s}/{s}.{s}.txt", .{ try helpers.goldenDir(arena), s.fixture, s.cmd });
    if (build_options.update_golden) {
        var f = try std.Io.Dir.cwd().createFile(io, gpath, .{});
        defer f.close(io);
        var buf: [4096]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(got);
        try w.interface.flush();
        return;
    }
    const want = std.Io.Dir.cwd().readFileAlloc(io, gpath, arena, .limited(1 << 24)) catch |e| {
        std.debug.print("cannot read snapshot {s}: {t} (regenerate with zig build test-golden -Dupdate-golden=true)\n", .{ gpath, e });
        return e;
    };
    std.testing.expectEqualStrings(want, got) catch |e| {
        std.debug.print("  -> snapshot {s}.{s}.txt\n", .{ s.fixture, s.cmd });
        return e;
    };
}

test "golden: disasm text snapshots" {
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    for (snapshots) |s| runSnapshot(gpa, std.testing.io, s) catch |e| {
        std.debug.print("  -> {t}\n", .{e});
        failures += 1;
    };
    try std.testing.expectEqual(@as(usize, 0), failures);
}
