//! tests/golden/objc_strings.rows.zig — golden rows contributed by WP6 (imported by tests/golden_tests.zig).
//! `strings --bare` is diffed against the `strings -n 6 | head -200` truth section of every healthy
//! fixture (DESIGN.md §10.4); the byte-exact rows cover the `entropy`, `strings` and `objc` renderers.
//! Every row passes `--quiet`: the diagnostics footer names whichever parsers are still stubs, which
//! is not part of these commands' output contract.
const golden = @import("../golden_tests.zig");

const strings_truth = "/usr/bin/strings -n 6";

fn bareRow(comptime fixture: []const u8, comptime extra: []const []const u8) golden.Row {
    const argv = [_][]const u8{ "strings", "--bare", "--min=6", "--limit=200", "--quiet" } ++ extra[0..extra.len].*;
    return .{ .fixture = fixture, .argv = &argv, .truth_cmd = strings_truth, .compare = .same_lines };
}

pub const rows: []const golden.Row = &.{
    // --- machre strings --bare == strings(1) on every healthy fixture ---------------------------
    bareRow("hello-c", &.{}),
    bareRow("hello-x86_64", &.{}),
    bareRow("hello-fat", &.{"--all-archs"}), // strings(1) walks every slice of a fat file
    bareRow("hello-objc", &.{}),
    bareRow("libhello.dylib", &.{}),
    bareRow("hello-usedylib", &.{}),
    bareRow("hello-adhoc", &.{}),
    bareRow("hello-entitled", &.{}),
    bareRow("hello-unsigned", &.{}),
    bareRow("high-entropy", &.{}),
    bareRow("fake-packed", &.{}),
    bareRow("fake-upx", &.{}),
    bareRow("hello-zig", &.{}),
    bareRow("legacy-bind", &.{}),
    bareRow("hello-quarantined", &.{}),
    bareRow("Hello.app", &.{}),

    // --- byte-exact renderer snapshots ---------------------------------------------------------
    .{ .fixture = "high-entropy", .argv = &.{ "entropy", "--sections", "--quiet" }, .golden_file = "high-entropy.entropy.txt" },
    .{ .fixture = "fake-upx", .argv = &.{ "entropy", "--quiet" }, .golden_file = "fake-upx.entropy.txt" },
    .{ .fixture = "hello-c", .argv = &.{ "strings", "--min=4", "--quiet" }, .golden_file = "hello-c.strings.txt" },
    // Selectors and stubs resolve through rebases only, so this snapshot needs no bind resolution.
    .{ .fixture = "hello-objc", .argv = &.{ "objc", "--selectors", "--stubs", "--quiet" }, .golden_file = "hello-objc.objc.selectors.txt" },
    // The full listing: the external superclass (`MachreAnimal : NSObject`) and the category on an
    // external class (`NSString(MachreExtras)`) are chained BIND slots, resolved through
    // macho/fixups.FixupTable, so this snapshot also pins that resolution.
    .{ .fixture = "hello-objc", .argv = &.{ "objc", "--quiet" }, .golden_file = "hello-objc.objc.txt" },

    // --- JSON key inventory (DESIGN.md §6.3) ---------------------------------------------------
    .{ .fixture = "hello-objc", .argv = &.{ "objc", "--json" }, .compare = .json_keys, .json_keys = &.{
        "objc.present",                  "objc.image_info.flags.value",   "objc.image_info.is_swift",
        "objc.classes.0.address",        "objc.classes.0.name",           "objc.classes.0.superclass.kind",
        "objc.classes.0.ro_flags.names", "objc.classes.0.methods.0.name", "objc.classes.0.methods.0.imp",
        "objc.classes.0.ivars",          "objc.classes.0.properties",     "objc.classes.0.protocols",
        "objc.categories",               "objc.protocols.0.name",         "objc.selectors.0.selref",
        "objc.selectors.0.name",         "objc.classrefs",                "objc.stubs.0.address",
        "objc.stubs.0.selector",         "objc.truncated",
    } },
    .{ .fixture = "hello-c", .argv = &.{ "objc", "--json" }, .compare = .json_keys, .json_keys = &.{ "objc.present", "objc.classes", "objc.stubs" } },
    .{ .fixture = "hello-objc", .argv = &.{ "strings", "--json", "--min=4" }, .compare = .json_keys, .json_keys = &.{
        "strings.0.address", "strings.0.offset", "strings.0.section", "strings.0.kind",
        "strings.0.class",   "strings.0.text",   "strings.0.length",  "strings.0.cut",
        "strings.0.lossy",   "total",            "lossy_strings",
    } },
    .{ .fixture = "high-entropy", .argv = &.{ "entropy", "--json" }, .compare = .json_keys, .json_keys = &.{
        "entropy.file",               "entropy.segments.0.name",    "entropy.segments.0.offset",
        "entropy.segments.0.size",    "entropy.segments.0.entropy", "entropy.segments.0.file_fraction",
        "entropy.sections.0.segment", "entropy.sections.0.section", "entropy.sections.0.entropy",
        "entropy.tells.0.code",       "entropy.tells.0.detail",     "entropy.tells.0.weight",
    } },
    .{ .fixture = "hello-c", .argv = &.{ "entropy", "--json" }, .compare = .json_keys, .json_keys = &.{ "entropy.file", "entropy.segments.0.name", "entropy.tells" } },
};
