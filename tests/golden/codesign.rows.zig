//! tests/golden/codesign.rows.zig — golden rows contributed by WP3 (imported by tests/golden_tests.zig).
//! `--otool-compat` rows diff machre against the `codesign -dvvv` / `codesign -d -r -` /
//! `codesign -d --entitlements - --xml` truth sections. `tests/truth.zig` drops codesign's
//! locale- and timezone-formatted `Signed Time=`/`Timestamp=` lines (machre prints ISO-8601 UTC), so
//! `/bin/ls` can use the shared comparator too. The byte-exact `codesign` text snapshots
//! (tests/golden/<fixture>.codesign.txt) are compared in tests/facts/codesign.zig instead, because
//! their first line is an absolute path that has to be normalised before comparing.
const golden = @import("../golden_tests.zig");

const codesign_dvvv = "/usr/bin/codesign -dvvv";
const codesign_r = "/usr/bin/codesign -d -r -";
const codesign_xml = "/usr/bin/codesign -d --entitlements - --xml";

const dvvv_argv: []const []const u8 = &.{ "codesign", "--otool-compat", "--no-security" };
const req_argv: []const []const u8 = &.{ "codesign", "--requirements", "--otool-compat", "--no-security" };
const xml_argv: []const []const u8 = &.{ "entitlements", "--xml", "--otool-compat", "--no-security" };

fn dvvvRow(comptime fixture: []const u8) golden.Row {
    return .{ .fixture = fixture, .argv = dvvv_argv, .truth_cmd = codesign_dvvv, .compare = .same_lines };
}
fn reqRow(comptime fixture: []const u8) golden.Row {
    return .{ .fixture = fixture, .argv = req_argv, .truth_cmd = codesign_r, .compare = .same_lines };
}

pub const rows: []const golden.Row = &.{
    // codesign -dvvv --entitlements - parity (every signed fixture; hello-entitled also exercises
    // the [Dict] entitlements dump, hello-fat the universal Format= line).
    dvvvRow("hello-c"),
    dvvvRow("hello-adhoc"),
    dvvvRow("hello-entitled"),
    dvvvRow("fake-upx"),
    dvvvRow("fake-packed"),
    dvvvRow("hello-objc"),
    dvvvRow("hello-zig"),
    dvvvRow("legacy-bind"),
    dvvvRow("libhello.dylib"),
    dvvvRow("hello-usedylib"),
    dvvvRow("high-entropy"),
    dvvvRow("hello-quarantined"),
    dvvvRow("hello-fat"),
    // A bundle: codesign prints `Format=app bundle with ...`, `Info.plist entries=N` and
    // `Sealed Resources version=2 rules=N files=M` (cmd/codesign.zig reads them from bundle.analyze
    // through ctx.bundle_path, which cli.loadImages sets when it promotes a bundle).
    dvvvRow("Hello.app"),
    // /bin/ls: a CMS-signed platform binary, the only fixture with `Signed Time=`.
    dvvvRow("bin-ls"),
    // codesign -d -r - parity (hello-fat excluded: codesign refuses universal files there).
    reqRow("hello-c"),
    reqRow("hello-adhoc"),
    reqRow("hello-entitled"),
    reqRow("fake-upx"),
    reqRow("fake-packed"),
    reqRow("hello-objc"),
    reqRow("hello-zig"),
    reqRow("legacy-bind"),
    reqRow("libhello.dylib"),
    reqRow("hello-usedylib"),
    reqRow("high-entropy"),
    reqRow("hello-quarantined"),
    .{ .fixture = "bin-ls", .argv = &.{ "codesign", "--requirements", "--otool-compat", "--no-security", "--arch", "arm64e" }, .truth_cmd = codesign_r, .compare = .same_lines },
    // codesign -d --entitlements - --xml parity (no entitlements -> no output).
    .{ .fixture = "hello-entitled", .argv = xml_argv, .truth_cmd = codesign_xml, .compare = .same_lines },
    .{ .fixture = "hello-c", .argv = xml_argv, .truth_cmd = codesign_xml, .compare = .same_lines },
    .{ .fixture = "hello-adhoc", .argv = xml_argv, .truth_cmd = codesign_xml, .compare = .same_lines },
    // JSON key inventory (DESIGN.md §6.3).
    .{
        .fixture = "hello-entitled",
        .argv = &.{ "codesign", "--json", "--no-security" },
        .compare = .json_keys,
        .json_keys = &.{
            "codesign.code_signature.present",
            "codesign.code_signature.dataoff",
            "codesign.code_signature.datasize",
            "codesign.code_signature.superblob.magic",
            "codesign.code_signature.superblob.magic_name",
            "codesign.code_signature.superblob.length",
            "codesign.code_signature.superblob.count",
            "codesign.code_signature.superblob.slots.0.type",
            "codesign.code_signature.superblob.slots.0.type_name",
            "codesign.code_signature.superblob.slots.0.offset",
            "codesign.code_signature.superblob.slots.0.magic",
            "codesign.code_signature.superblob.slots.0.length",
            "codesign.code_signature.code_directories.0.slot",
            "codesign.code_signature.code_directories.0.version",
            "codesign.code_signature.code_directories.0.flags.value",
            "codesign.code_signature.code_directories.0.flags.names",
            "codesign.code_signature.code_directories.0.hash_type",
            "codesign.code_signature.code_directories.0.hash_type_name",
            "codesign.code_signature.code_directories.0.hash_size",
            "codesign.code_signature.code_directories.0.page_size",
            "codesign.code_signature.code_directories.0.platform",
            "codesign.code_signature.code_directories.0.n_code_slots",
            "codesign.code_signature.code_directories.0.n_special_slots",
            "codesign.code_signature.code_directories.0.code_limit",
            "codesign.code_signature.code_directories.0.exec_seg.base",
            "codesign.code_signature.code_directories.0.exec_seg.limit",
            "codesign.code_signature.code_directories.0.exec_seg.flags.value",
            "codesign.code_signature.code_directories.0.identifier",
            "codesign.code_signature.code_directories.0.cdhash",
            "codesign.code_signature.code_directories.0.cdhash_full",
            "codesign.code_signature.code_directories.0.special_slots.0.slot",
            "codesign.code_signature.code_directories.0.special_slots.0.name",
            "codesign.code_signature.code_directories.0.special_slots.0.hash",
            "codesign.code_signature.code_directories.0.special_slots.0.bound",
            "codesign.code_signature.code_directories.0.pages.checked",
            "codesign.code_signature.code_directories.0.pages.ok",
            "codesign.code_signature.code_directories.0.pages.mismatches",
            "codesign.code_signature.best_cdhash",
            "codesign.code_signature.designated_requirement.text",
            "codesign.code_signature.designated_requirement.synthesized",
            "codesign.code_signature.entitlements.source",
            "codesign.code_signature.entitlements.keys",
            "codesign.code_signature.entitlements.der",
            "codesign.code_signature.entitlements.disagreement",
            "codesign.code_signature.entitlements.dangerous.0.key",
            "codesign.code_signature.entitlements.dangerous.0.why",
            "codesign.code_signature.entitlements.dangerous.0.weight",
            "codesign.code_signature.offline_trust",
            "codesign.security.available",
            "codesign.verdict.signed",
            "codesign.verdict.valid",
            "codesign.verdict.trust",
            "codesign.verdict.summary",
        },
    },
    .{
        .fixture = "hello-c",
        .argv = &.{ "codesign", "--json", "--no-security" },
        .compare = .json_keys,
        .json_keys = &.{ "codesign.code_signature.code_directories.0.cdhash", "codesign.code_signature.requirements", "codesign.code_signature.cms", "codesign.verdict.summary" },
    },
    .{
        .fixture = "hello-unsigned",
        .argv = &.{ "codesign", "--json", "--no-security" },
        .compare = .json_keys,
        .json_keys = &.{ "codesign.code_signature.present", "codesign.verdict.signed", "codesign.security.available" },
    },
    .{
        .fixture = "hello-entitled",
        .argv = &.{ "entitlements", "--json", "--no-security" },
        .compare = .json_keys,
        .json_keys = &.{ "entitlements.source", "entitlements.keys", "entitlements.der", "entitlements.xml", "entitlements.der_length", "entitlements.disagreement", "entitlements.dangerous.0.key" },
    },
};
