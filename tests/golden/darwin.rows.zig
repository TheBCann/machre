//! tests/golden/darwin.rows.zig — golden rows contributed by WP-darwin (imported by tests/golden_tests.zig).
//! `quarantine --otool-compat` mirrors `xattr -l`, so every healthy fixture gets a truth-section row.
const std = @import("std");
const golden = @import("../golden_tests.zig");
const helpers = @import("../helpers.zig");

const xattr_l = "/usr/bin/xattr -l";

fn compatRow(comptime fixture: []const u8) golden.Row {
    return .{ .fixture = fixture, .argv = &.{ "quarantine", "--otool-compat" }, .truth_cmd = xattr_l, .compare = .same_lines };
}

pub const rows: []const golden.Row = &.{
    compatRow("hello-c"),
    compatRow("hello-x86_64"),
    compatRow("hello-fat"),
    compatRow("hello-objc"),
    compatRow("libhello.dylib"),
    compatRow("hello-usedylib"),
    compatRow("hello-adhoc"),
    compatRow("hello-entitled"),
    compatRow("hello-unsigned"),
    compatRow("high-entropy"),
    compatRow("fake-packed"),
    compatRow("fake-upx"),
    compatRow("hello-zig"),
    compatRow("legacy-bind"),
    compatRow("hello-quarantined"),
    compatRow("Hello.app"),
    compatRow("bin-ls"),
    .{ .fixture = "hello-quarantined", .argv = &.{"quarantine"}, .golden_file = "hello-quarantined.quarantine.txt", .compare = .byte_exact },
    .{ .fixture = "hello-c", .argv = &.{"quarantine"}, .golden_file = "hello-c.quarantine.txt", .compare = .byte_exact },
    .{
        .fixture = "hello-quarantined",
        .argv = &.{ "quarantine", "--json" },
        .compare = .json_keys,
        .top_level = true,
        .json_keys = &.{
            "xattrs.0",
            "quarantine.raw",
            "quarantine.flags",
            "quarantine.timestamp",
            "quarantine.timestamp_unix",
            "quarantine.agent",
            "quarantine.uuid",
            "quarantine.well_formed",
            "translocated",
            "provenance",
            "file.path",
            "arches.0.arch",
        },
    },
};

// xattrs do not survive a copy of the corpus; re-apply the fixture's quarantine value before the
// rows that depend on it run (tests in an imported file are collected in import order).
test "golden/darwin: the hello-quarantined xattr is present" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    try helpers.ensureQuarantineXattr(gpa, io);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const path = try helpers.fixturePath(arena.allocator(), "hello-quarantined");
    const res = try helpers.runMachre(arena.allocator(), io, &.{ "quarantine", "--otool-compat", path });
    try std.testing.expectEqualStrings(
        "com.apple.quarantine: 0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C\n",
        res.out,
    );
}
