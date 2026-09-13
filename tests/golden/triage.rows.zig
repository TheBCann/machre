//! tests/golden/triage.rows.zig — golden rows and text snapshots for `triage` and `report`. Owned by WP9.
//!
//! Two layers:
//!  1. `rows` — the §6.3 JSON key inventory, run by the WP0 table runner: the `triage` payload (per arch
//!     and merged), the `report` document (every command payload under its own name), and one row per
//!     remaining command so the inventory of docs/json-schema.md is checked end to end.
//!  2. `test "golden: triage text snapshots"` — byte-exact comparison against
//!     tests/golden/<fixture>.triage.txt with the corpus directory normalised to "tests/corpus", so the
//!     files are machine-independent. Regenerate with `zig build test-golden -Dupdate-golden=true`.
//!     Skipped in a `-Dsecurity=false` build, where the trust word comes from the embedded CMS ladder
//!     instead of Security.framework and an extra `sig.not_evaluated` row appears.
const std = @import("std");
const build_options = @import("build_options");
const golden = @import("../golden_tests.zig");
const helpers = golden.helpers;

/// §6.3 `triage` keys, inside `arches[0]`.
const triage_keys: []const []const u8 = &.{
    "triage.score",               "triage.level",                "triage.categories_hit",
    "triage.findings",            "triage.positives",            "triage.corroboration",
    "triage.not_flagged",         "triage.exit_code",            "triage.summary.signed",
    "triage.summary.trust",       "triage.summary.notarized",    "triage.summary.hardened_runtime",
    "triage.summary.quarantined", "triage.summary.packed_hint",  "triage.summary.encrypted",
    "triage.summary.imports",     "triage.summary.exports",      "triage.summary.symbols",
    "triage.summary.dylibs",      "triage.summary.objc_classes", "triage.summary.arch",
};
/// The same payload at the top level (the merged report), plus one finding's full key set.
const merged_keys: []const []const u8 = &.{
    "triage.score",             "triage.level",               "triage.summary.arch",
    "triage.findings.0.id",     "triage.findings.0.category", "triage.findings.0.severity",
    "triage.findings.0.weight", "triage.findings.0.score",    "triage.findings.0.title",
    "triage.findings.0.detail", "triage.findings.0.evidence", "triage.findings.0.corroborates",
};
/// `report` splices every selected command's payload into `arches[i]` under its own name.
const report_arch_keys: []const []const u8 = &.{
    "info.header.magic",       "header.header",       "loadcmds.load_commands", "segments.0.name",
    "symbols.counts",          "dyld",                "imports.imports",        "exports.exports",
    "codesign.code_signature", "entitlements.source", "objc.present",           "strings",
    "entropy.file",            "functions",           "triage.score",
};
/// …and every top-level payload next to `arches`.
const report_top_keys: []const []const u8 = &.{ "triage.score", "triage.level", "quarantine", "translocated", "bundle", "plist", "exit_code" };

fn triageRows(comptime fixture: []const u8) [2]golden.Row {
    return .{
        .{ .fixture = fixture, .argv = &.{ "triage", "--json" }, .compare = .json_keys, .json_keys = triage_keys },
        .{ .fixture = fixture, .argv = &.{ "triage", "--json" }, .compare = .json_keys, .json_keys = merged_keys, .top_level = true },
    };
}

pub const rows: []const golden.Row = &(triageRows("hello-c") ++ triageRows("fake-upx") ++ triageRows("hello-unsigned") ++
    triageRows("high-entropy") ++ triageRows("hello-objc") ++ triageRows("Hello.app") ++ triageRows("hello-fat") ++
    [_]golden.Row{
        // `report` on the fixtures that exercise the different container shapes
        .{ .fixture = "hello-c", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_arch_keys },
        .{ .fixture = "hello-c", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_top_keys, .top_level = true },
        .{ .fixture = "hello-objc", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_arch_keys },
        .{ .fixture = "legacy-bind", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_arch_keys },
        .{ .fixture = "libhello.dylib", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_arch_keys },
        .{ .fixture = "hello-fat", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = report_arch_keys },
        .{ .fixture = "Hello.app", .argv = &.{ "report", "--json" }, .compare = .json_keys, .json_keys = &.{ "bundle.root", "bundle.code_resources", "triage.level" }, .top_level = true },
        // `--only` reaches the two listings the default document leaves out
        .{ .fixture = "hello-c", .argv = &.{ "report", "--json", "--only=disasm,xrefs" }, .compare = .json_keys, .json_keys = &.{ "disasm.backend", "disasm.functions", "xrefs" } },
        .{ .fixture = "hello-c", .argv = &.{ "report", "--json", "--only=version" }, .compare = .json_keys, .json_keys = &.{ "version.machre", "version.zig", "version.capstone.available", "version.security.available", "version.host" }, .top_level = true },
        // the remaining stand-alone commands, so the §6.3 inventory is covered for every command
        .{ .fixture = "hello-c", .argv = &.{ "entropy", "--json", "--sections" }, .compare = .json_keys, .json_keys = &.{ "entropy.file", "entropy.segments.0.name", "entropy.segments.0.entropy", "entropy.segments.0.file_fraction", "entropy.sections", "entropy.tells" } },
        .{ .fixture = "hello-c", .argv = &.{ "strings", "--json" }, .compare = .json_keys, .json_keys = &.{ "strings.0.address", "strings.0.offset", "strings.0.section", "strings.0.kind", "strings.0.class", "strings.0.text", "strings.0.length", "strings.0.cut", "strings.0.lossy", "total", "lossy_strings" } },
        .{ .fixture = "hello-quarantined", .argv = &.{ "quarantine", "--json" }, .compare = .json_keys, .json_keys = &.{ "xattrs", "quarantine.raw", "quarantine.flags", "quarantine.timestamp", "quarantine.timestamp_unix", "quarantine.agent", "quarantine.well_formed", "translocated", "provenance" }, .top_level = true },
        .{ .fixture = "hello-c", .argv = &.{ "version", "--json" }, .compare = .json_keys, .json_keys = &.{ "version.machre", "version.capstone.available", "version.security.available" }, .top_level = true },
    });

// ---------------------------------------------------------------------------------------------
// byte-exact text snapshots
// ---------------------------------------------------------------------------------------------

const Snap = struct { fixture: []const u8, argv: []const []const u8 = &.{"triage"}, suffix: []const u8 = "triage" };

const snapshots: []const Snap = &.{
    .{ .fixture = "hello-c" },
    .{ .fixture = "fake-upx" },
    .{ .fixture = "high-entropy" },
    .{ .fixture = "hello-quarantined" },
    .{ .fixture = "Hello.app" },
    .{ .fixture = "hello-fat", .argv = &.{ "triage", "--all-archs" }, .suffix = "triage.all-archs" },
    .{ .fixture = "fake-upx", .argv = &.{ "triage", "--explain" }, .suffix = "triage.explain" },
};

/// The absolute corpus path becomes "tests/corpus" so a snapshot is machine-independent.
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
    const gpath = try std.fmt.allocPrint(arena, "{s}/{s}.{s}.txt", .{ try helpers.goldenDir(arena), s.fixture, s.suffix });
    if (build_options.update_golden) {
        var f = try std.Io.Dir.cwd().createFile(io, gpath, .{});
        defer f.close(io);
        var buf: [4096]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(got);
        try w.interface.flush();
        return;
    }
    const want = std.Io.Dir.cwd().readFileAlloc(io, gpath, arena, .limited(1 << 22)) catch |e| {
        std.debug.print("cannot read snapshot {s}: {t} (regenerate with zig build test-golden -Dupdate-golden=true)\n", .{ gpath, e });
        return e;
    };
    std.testing.expectEqualStrings(want, got) catch |e| {
        std.debug.print("  -> snapshot {s}.{s}.txt\n", .{ s.fixture, s.suffix });
        return e;
    };
}

test "golden: triage text snapshots" {
    if (!build_options.have_security) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    try helpers.ensureQuarantineXattr(gpa, std.testing.io);
    var failures: usize = 0;
    for (snapshots) |s| runSnapshot(gpa, std.testing.io, s) catch |e| {
        std.debug.print("  -> {t}\n", .{e});
        failures += 1;
    };
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "golden: the §5.5 verdict line and finding rows keep their column layout" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.summaryFixturePath(arena, "fake-upx");
    const res = try helpers.runMachre(arena, std.testing.io, &.{ "triage", "--quiet", path });
    var it = std.mem.splitScalar(u8, res.out, '\n');
    const header = it.next().?;
    try std.testing.expect(std.mem.startsWith(u8, header, "machre triage: "));
    try std.testing.expect(std.mem.endsWith(u8, header, " [arm64]"));
    const level = it.next().?;
    try std.testing.expect(std.mem.startsWith(u8, level, "LEVEL: SUSPICIOUS (score 60, 2 categories)"));
    // the trust word starts at column 54, exactly as DESIGN §5.5 prints it
    const trust_at = std.mem.find(u8, level, "trust: ") orelse return error.NoTrustColumn;
    try std.testing.expectEqual(@as(usize, 54), trust_at);
    // With Security.framework the ladder says the signature is broken; without it the word comes from
    // the embedded CMS ladder (ad hoc) — the score, the level and the columns are the same either way.
    try std.testing.expectEqualStrings(
        if (build_options.have_security) "trust: INVALID SIGNATURE" else "trust: AD HOC",
        level[trust_at..],
    );
    // category 12, "[SEV]" 9, id 18 — the finding rows line up whatever their content
    const first = it.next().?;
    try std.testing.expectEqualStrings("Signing     ", first[0..12]);
    try std.testing.expectEqualStrings("[HIGH]   ", first[12..21]);
    try std.testing.expectEqualStrings("sig.invalid       ", first[21..39]);
    try std.testing.expect(std.mem.startsWith(u8, first[39..], "embedded CodeDirectory does not match the file:"));
    const second = it.next().?;
    try std.testing.expectEqualStrings("Packing     [MEDIUM] pack.names        ", second[0..39]);
    const third = it.next().?;
    try std.testing.expectEqualStrings("Signing     [LOW]    sig.adhoc         ", third[0..39]);
    // The trailing blocks follow the rows; a `-Dsecurity=false` build inserts one more INFO row
    // (`sig.not_evaluated`) before them, so look them up by prefix rather than by line number.
    var corroboration = false;
    var not_flagged = false;
    var rest = std.mem.splitScalar(u8, res.out, '\n');
    while (rest.next()) |line| {
        if (std.mem.startsWith(u8, line, "Corroboration: packing tell (UPX_DATA)")) corroboration = true;
        if (std.mem.startsWith(u8, line, "Not flagged: entropy (max ")) not_flagged = true;
    }
    try std.testing.expect(corroboration and not_flagged);
}

test "golden: every command has a JSON key-inventory row" {
    const machre = @import("machre");
    var missing: usize = 0;
    for (machre.cli.commands) |c| {
        var covered = false;
        for (golden.all_rows) |rows_| for (rows_) |row| {
            if (row.compare != .json_keys or row.argv.len == 0) continue;
            if (std.mem.eql(u8, row.argv[0], c.name)) covered = true;
            for (c.aliases) |al| if (std.mem.eql(u8, row.argv[0], al)) {
                covered = true;
            };
        };
        if (!covered) {
            std.debug.print("no json_keys golden row for command '{s}'\n", .{c.name});
            missing += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), missing);
}
