//! tests/golden/plist_bundle.rows.zig — golden rows contributed by WP-plist_bundle (imported by tests/golden_tests.zig).
//!
//! `plist --otool-compat` is diffed against the `plutil -p` truth section (the analyst-output contract of
//! DESIGN.md §10.4); the byte-exact rows pin machre's own text. `Hello.app.bundle.txt` renders the
//! nested-cdhash columns as "unchecked" until WP3's code-signature parser lands — regenerate it with
//! `zig build test-golden -Dupdate-golden=true` after that merge.
const golden = @import("../golden_tests.zig");

pub const rows: []const golden.Row = &.{
    // plutil parity, through the bundle directory and through the plist file itself.
    .{ .fixture = "Hello.app", .argv = &.{ "plist", "--otool-compat" }, .truth_cmd = "/usr/bin/plutil -p", .compare = .same_lines },
    .{ .fixture = "Hello-Info.plist.xml", .argv = &.{ "plist", "--otool-compat" }, .golden_file = "Hello-Info.plist.xml.plist.txt", .compare = .byte_exact },
    // machre's own text.
    .{ .fixture = "Hello.app", .argv = &.{"plist"}, .golden_file = "Hello.app.plist.txt", .compare = .byte_exact },
    .{ .fixture = "Hello.app", .argv = &.{ "bundle", "--no-security", "--quiet" }, .golden_file = "Hello.app.bundle.txt", .compare = .byte_exact },
    .{ .fixture = "Hello.app", .argv = &.{ "bundle", "--no-security", "--quiet", "--files", "--nested" }, .golden_file = "Hello.app.bundle.files.txt", .compare = .byte_exact },
    // JSON key inventory (DESIGN.md §6.3).
    .{
        .fixture = "Hello.app",
        .argv = &.{ "plist", "--json" },
        .compare = .json_keys,
        .top_level = true,
        .json_keys = &.{ "plist.format", "plist.source", "plist.path", "plist.value", "plist.value.CFBundleIdentifier" },
    },
    .{
        .fixture = "Hello-Info.plist.xml",
        .argv = &.{ "plist", "--json" },
        .compare = .json_keys,
        .top_level = true,
        .json_keys = &.{ "plist.format", "plist.value.CFBundleSupportedPlatforms.0" },
    },
    .{
        .fixture = "Hello.app",
        .argv = &.{ "bundle", "--json" },
        .compare = .json_keys,
        .top_level = true,
        .json_keys = &.{
            "bundle.root",                "bundle.kind",                  "bundle.identifier",
            "bundle.executable",          "bundle.executable_path",       "bundle.package_type",
            "bundle.version",             "bundle.short_version",         "bundle.min_system",
            "bundle.ui_element",          "bundle.background_only",       "bundle.ats_arbitrary_loads",
            "bundle.usage_descriptions",  "bundle.url_schemes",           "bundle.principal_class",
            "bundle.info_plist.format",   "bundle.info_plist.path",       "bundle.info_plist.value",
            "bundle.frameworks",          "bundle.helpers",               "bundle.xpc_services",
            "bundle.plugins",             "bundle.dylibs",                "bundle.nested",
            "bundle.nested.0.path",       "bundle.nested.0.sealed_cdhash", "bundle.nested.0.cdhash_match",
            "bundle.nested.0.cdhash_arch", "bundle.nested.0.matched_arch",
            "bundle.nested.0.arches",     "bundle.code_resources.version", "bundle.code_resources.rules",
            "bundle.code_resources.rules2", "bundle.code_resources.files", "bundle.code_resources.nested.0.cdhash",
            "bundle.code_resources.verify.checked", "bundle.code_resources.verify.ok",
            "bundle.stapled_ticket.present", "bundle.provisioning_profile", "bundle.file_count",
            "bundle.total_size",          "bundle.security.available",    "bundle.spctl",
        },
    },
};
