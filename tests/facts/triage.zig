//! tests/facts/triage.zig — corpus fact tests for WP9 (triage + report).
//!
//! Every assertion runs the real CLI in-process (`helpers.runMachre`) and reads the JSON envelope back,
//! so what is pinned is the analyst-visible contract, not an internal structure. The levels, scores and
//! exit codes are the ones DESIGN.md §4.23 lists as the corpus expectations.
//!
//! Build-configuration independence: the assertions never depend on Security.framework being linked.
//! Without it `sig.not_evaluated` (weight 0) is added and the trust word comes from the embedded CMS
//! ladder, but no score, level, category count or exit code changes — which is itself asserted below.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const build_options = @import("build_options");

const triage = machre.analysis.triage;

/// Runs `machre triage --json [extra] <fixture>` and returns (exit code, the merged triage object).
const Run = struct {
    code: u8,
    root: std.json.Value,
    parsed: std.json.Parsed(std.json.Value),

    fn triageObj(r: Run) std.json.Value {
        return r.root.object.get("triage").?;
    }
    fn arch(r: Run, i: usize) std.json.Value {
        return r.root.object.get("arches").?.array.items[i].object.get("triage").?;
    }
    fn deinit(r: *Run) void {
        r.parsed.deinit();
    }
};

fn runTriage(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, fixture: []const u8, extra: []const []const u8) !Run {
    const path = try helpers.summaryFixturePath(arena, fixture);
    var argv: std.ArrayList([:0]const u8) = .empty;
    try argv.append(arena, try arena.dupeSentinel(u8, "triage", 0));
    try argv.append(arena, try arena.dupeSentinel(u8, "--json", 0));
    for (extra) |e| try argv.append(arena, try arena.dupeSentinel(u8, e, 0));
    try argv.append(arena, path);
    const res = try helpers.runMachre(arena, io, argv.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
    return .{ .code = res.code, .root = parsed.value, .parsed = parsed };
}

fn int(v: std.json.Value, key: []const u8) i64 {
    return v.object.get(key).?.integer;
}
fn str(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}
fn hasFinding(t: std.json.Value, id: []const u8) bool {
    for (t.object.get("findings").?.array.items) |f| {
        if (std.mem.eql(u8, f.object.get("id").?.string, id)) return true;
    }
    return false;
}
fn findingScore(t: std.json.Value, id: []const u8) ?i64 {
    for (t.object.get("findings").?.array.items) |f| {
        if (std.mem.eql(u8, f.object.get("id").?.string, id)) return f.object.get("score").?.integer;
    }
    return null;
}
/// Number of findings whose id starts with `prefix` (e.g. "ent.").
fn countPrefix(t: std.json.Value, prefix: []const u8) usize {
    var n: usize = 0;
    for (t.object.get("findings").?.array.items) |f| {
        if (std.mem.startsWith(u8, f.object.get("id").?.string, prefix)) n += 1;
    }
    return n;
}

test "facts/triage: hello-c is clean — one ad hoc, linker-signed tell and nothing else" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-c", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqual(@as(u8, 0), r.code);
    try std.testing.expectEqualStrings("clean", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 3), int(t, "score"));
    try std.testing.expectEqual(@as(usize, 1), t.object.get("categories_hit").?.array.items.len);
    try std.testing.expectEqualStrings("signature", t.object.get("categories_hit").?.array.items[0].string);
    try std.testing.expectEqual(@as(?i64, 3), findingScore(t, "sig.adhoc"));
    try std.testing.expect(!hasFinding(t, "sig.unsigned") and !hasFinding(t, "sig.invalid"));
    try std.testing.expectEqual(@as(usize, 0), countPrefix(t, "pack."));
    try std.testing.expectEqual(@as(usize, 0), countPrefix(t, "hdr."));
    try std.testing.expectEqual(@as(usize, 0), countPrefix(t, "str."));
    try std.testing.expectEqual(@as(i64, 0), int(t, "exit_code"));
    const s = t.object.get("summary").?;
    try std.testing.expect(s.object.get("signed").?.bool);
    try std.testing.expect(!s.object.get("packed_hint").?.bool);
    try std.testing.expectEqual(@as(i64, 6), int(s, "imports"));
    try std.testing.expectEqual(@as(i64, 12), int(s, "symbols"));
    try std.testing.expectEqualStrings("arm64", str(s, "arch"));
}

test "facts/triage: hello-unsigned is notable (25, one category) and still exits 0" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-unsigned", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqual(@as(u8, 0), r.code); // the C-defect: one tell is never a verdict
    try std.testing.expectEqualStrings("notable", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 25), int(t, "score"));
    try std.testing.expectEqual(@as(usize, 1), t.object.get("categories_hit").?.array.items.len);
    try std.testing.expect(hasFinding(t, "sig.unsigned"));
    try std.testing.expect(!t.object.get("summary").?.object.get("signed").?.bool);
}

test "facts/triage: high-entropy is notable at 28 with two categories" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "high-entropy", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqualStrings("notable", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 28), int(t, "score")); // pack.entropy 25 + sig.adhoc 3
    try std.testing.expectEqual(@as(usize, 2), t.object.get("categories_hit").?.array.items.len);
    try std.testing.expect(hasFinding(t, "pack.entropy"));
    try std.testing.expect(t.object.get("summary").?.object.get("packed_hint").?.bool);
    // two categories and 28 points is still below the suspicious threshold
    try std.testing.expectEqual(@as(u8, 0), r.code);
}

test "facts/triage: fake-packed is notable on its __XHDR segment name" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "fake-packed", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqualStrings("notable", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 28), int(t, "score")); // pack.names 25 + sig.adhoc 3
    try std.testing.expect(hasFinding(t, "pack.names"));
    for (t.object.get("findings").?.array.items) |f| {
        if (std.mem.eql(u8, f.object.get("id").?.string, "pack.names")) {
            try std.testing.expect(std.mem.find(u8, f.object.get("detail").?.string, "__XHDR") != null);
        }
    }
}

test "facts/triage: fake-upx is suspicious at 60 and --fail-on=suspicious exits 20" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var r = try runTriage(std.testing.allocator, a, std.testing.io, "fake-upx", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqualStrings("suspicious", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 60), int(t, "score")); // sig.invalid 35 + pack.names 25
    try std.testing.expectEqual(@as(usize, 2), t.object.get("categories_hit").?.array.items.len);
    try std.testing.expect(hasFinding(t, "sig.invalid") and hasFinding(t, "pack.names"));
    // ad hoc is reported but scores 0: the signature is already known to be broken, and counting it
    // twice would put fake-upx above the score DESIGN §4.23/§5.5 pins.
    try std.testing.expectEqual(@as(?i64, 0), findingScore(t, "sig.adhoc"));
    try std.testing.expectEqual(@as(u8, 0), r.code);
    // the corroboration sentence names the packer marker
    const corr = t.object.get("corroboration").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), corr.len);
    try std.testing.expect(std.mem.find(u8, corr[0].string, "UPX_DATA") != null);
    try std.testing.expect(std.mem.find(u8, corr[0].string, "modified after linking") != null);

    var fail = try runTriage(std.testing.allocator, a, std.testing.io, "fake-upx", &.{"--fail-on=suspicious"});
    defer fail.deinit();
    try std.testing.expectEqual(@as(u8, 20), fail.code);
    try std.testing.expectEqual(@as(i64, 20), int(fail.triageObj(), "exit_code"));
    try std.testing.expectEqual(@as(i64, 20), fail.root.object.get("exit_code").?.integer);

    var clean = try runTriage(std.testing.allocator, a, std.testing.io, "hello-c", &.{"--fail-on=suspicious"});
    defer clean.deinit();
    try std.testing.expectEqual(@as(u8, 0), clean.code);
    var notable = try runTriage(std.testing.allocator, a, std.testing.io, "hello-unsigned", &.{"--fail-on=notable"});
    defer notable.deinit();
    try std.testing.expectEqual(@as(u8, 20), notable.code);
}

test "facts/triage: hello-entitled lists every dangerous entitlement it carries" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-entitled", &.{});
    defer r.deinit();
    const t = r.triageObj();
    // summary.json lists five entitlement keys, three of which are in the dangerous table.
    var s = try helpers.loadSummary(std.testing.allocator, std.testing.io);
    defer s.deinit();
    const f = s.fixtureNamed("hello-entitled").?;
    const cs = helpers.Summary.object(helpers.Summary.slice(f, 0).?, "code_signature").?;
    const keys = try helpers.Summary.strings(arena_state.allocator(), cs, "entitlements_keys");
    var dangerous: usize = 0;
    for (keys) |k| if (machre.codesign.entitlements.isDangerous(k) != null) {
        dangerous += 1;
    };
    try std.testing.expectEqual(@as(usize, 3), dangerous);
    try std.testing.expectEqual(dangerous, countPrefix(t, "ent."));
    try std.testing.expect(hasFinding(t, "ent.get_task_allow"));
    try std.testing.expect(hasFinding(t, "ent.disable_library_validation"));
    try std.testing.expect(hasFinding(t, "ent.allow_jit"));
    try std.testing.expect(!hasFinding(t, "ent.xml_der_mismatch")); // DER and XML agree
    try std.testing.expectEqualStrings("notable", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 40), int(t, "score")); // 12 + 10 + 8 + adhoc 10
}

test "facts/triage: hello-quarantined records the xattr as information, never as score" {
    try helpers.ensureQuarantineXattr(std.testing.allocator, std.testing.io);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-quarantined", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expect(hasFinding(t, "quarantine.present"));
    try std.testing.expectEqual(@as(?i64, 0), findingScore(t, "quarantine.present"));
    try std.testing.expectEqual(@as(i64, 3), int(t, "score")); // unchanged by the xattr
    try std.testing.expectEqualStrings("clean", str(t, "level"));
    // a weight-0 finding must not help a file across the ">= 2 categories" gate
    try std.testing.expectEqual(@as(usize, 1), t.object.get("categories_hit").?.array.items.len);
    try std.testing.expect(t.object.get("summary").?.object.get("quarantined").?.bool);
    for (t.object.get("not_flagged").?.array.items) |n| {
        try std.testing.expect(std.mem.find(u8, n.string, "no quarantine xattr") == null);
    }
}

test "facts/triage: Hello.app is clean — ad hoc only, sealed resources intact" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "Hello.app", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqualStrings("clean", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 10), int(t, "score")); // ad hoc, not linker-signed
    try std.testing.expectEqual(@as(usize, 0), countPrefix(t, "bundle."));
    try std.testing.expect(!hasFinding(t, "bundle.resource_mismatch"));
    try std.testing.expect(!hasFinding(t, "bundle.nested_unsigned"));
}

test "facts/triage: /bin/ls is a clean platform binary (bin-ls)" {
    std.Io.Dir.cwd().access(std.testing.io, "/bin/ls", .{}) catch return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "bin-ls", &.{});
    defer r.deinit();
    const t = r.triageObj();
    try std.testing.expectEqualStrings("clean", str(t, "level"));
    try std.testing.expectEqual(@as(i64, 0), int(t, "score"));
    var platform = false;
    for (t.object.get("positives").?.array.items) |p| {
        if (std.mem.eql(u8, p.object.get("id").?.string, "platform")) platform = true;
    }
    try std.testing.expect(platform);
    try std.testing.expect(!hasFinding(t, "sig.unsigned") and !hasFinding(t, "sig.adhoc"));
}

test "facts/triage: hello-fat reports each slice and the merged verdict" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runTriage(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-fat", &.{});
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 2), r.root.object.get("arches").?.array.items.len);
    const x86 = r.arch(0);
    const arm = r.arch(1);
    try std.testing.expectEqualStrings("x86_64", str(x86.object.get("summary").?, "arch"));
    try std.testing.expectEqualStrings("arm64", str(arm.object.get("summary").?, "arch"));
    try std.testing.expect(hasFinding(x86, "sig.unsigned")); // the x86_64 slice is unsigned
    try std.testing.expect(hasFinding(arm, "sig.adhoc")); // the arm64 slice is signed
    // the arm64 slice's own trust word comes from the embedded ladder, not from the file-wide verdict
    try std.testing.expectEqualStrings("AD HOC", str(arm.object.get("summary").?, "trust"));
    const merged = r.triageObj();
    try std.testing.expectEqual(@as(i64, 28), int(merged, "score")); // 25 + 3, union of both slices
    try std.testing.expectEqualStrings("notable", str(merged, "level"));
    try std.testing.expectEqualStrings("x86_64+arm64", str(merged.object.get("summary").?, "arch"));
}

test "facts/triage: every healthy fixture triages without an error diagnostic" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (helpers.healthy_fixtures) |fixture| {
        var r = try runTriage(std.testing.allocator, a, std.testing.io, fixture, &.{});
        defer r.deinit();
        const t = r.triageObj();
        // a level is always produced, the score is consistent with it, and nothing exits non-zero
        const level = std.meta.stringToEnum(triage.Level, str(t, "level")) orelse return error.UnknownLevel;
        const cats = t.object.get("categories_hit").?.array.items.len;
        try std.testing.expectEqual(level, triage.levelFor(@intCast(int(t, "score")), cats));
        try std.testing.expectEqual(@as(u8, 0), r.code);
        // the ">= 2 categories" gate: one category can never exceed notable on this corpus
        if (cats < 2) try std.testing.expect(@intFromEnum(level) <= @intFromEnum(triage.Level.notable));
        // every finding id is in the rule table and every weight is under the no-single-tell cap
        for (t.object.get("findings").?.array.items) |f| {
            const rule = triage.byId(f.object.get("id").?.string) orelse return error.UnknownRuleId;
            try std.testing.expect(rule.weight < 50);
            try std.testing.expectEqual(@as(i64, rule.weight), f.object.get("weight").?.integer);
            try std.testing.expect(f.object.get("score").?.integer <= @as(i64, rule.weight));
        }
    }
}

test "facts/triage: --no-security changes the trust wording, never the score" {
    if (!build_options.have_security) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for ([_][]const u8{ "hello-c", "fake-upx", "high-entropy", "hello-unsigned" }) |fixture| {
        var with = try runTriage(std.testing.allocator, a, std.testing.io, fixture, &.{});
        defer with.deinit();
        var without = try runTriage(std.testing.allocator, a, std.testing.io, fixture, &.{"--no-security"});
        defer without.deinit();
        try std.testing.expectEqual(int(with.triageObj(), "score"), int(without.triageObj(), "score"));
        try std.testing.expectEqualStrings(str(with.triageObj(), "level"), str(without.triageObj(), "level"));
        try std.testing.expect(hasFinding(without.triageObj(), "sig.not_evaluated"));
        try std.testing.expectEqual(@as(?i64, 0), findingScore(without.triageObj(), "sig.not_evaluated"));
    }
}

// ---------------------------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------------------------

fn runReport(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, fixture: []const u8, extra: []const []const u8) !Run {
    const path = try helpers.summaryFixturePath(arena, fixture);
    var argv: std.ArrayList([:0]const u8) = .empty;
    try argv.append(arena, try arena.dupeSentinel(u8, "report", 0));
    try argv.append(arena, try arena.dupeSentinel(u8, "--json", 0));
    for (extra) |e| try argv.append(arena, try arena.dupeSentinel(u8, e, 0));
    try argv.append(arena, path);
    const res = try helpers.runMachre(arena, io, argv.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
    return .{ .code = res.code, .root = parsed.value, .parsed = parsed };
}

test "facts/report: one envelope carries every command's payload under its own name" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var r = try runReport(std.testing.allocator, arena_state.allocator(), std.testing.io, "hello-c", &.{});
    defer r.deinit();
    try std.testing.expectEqual(@as(u8, 0), r.code);
    const arch0 = r.root.object.get("arches").?.array.items[0].object;
    for ([_][]const u8{ "info", "header", "loadcmds", "segments", "symbols", "dyld", "imports", "exports", "codesign", "entitlements", "objc", "strings", "entropy", "functions", "triage" }) |k| {
        if (arch0.get(k) == null) {
            std.debug.print("report: arches[0].{s} missing\n", .{k});
            return error.ReportPayloadMissing;
        }
    }
    for ([_][]const u8{ "quarantine", "bundle", "plist", "triage" }) |k| {
        try std.testing.expect(r.root.object.get(k) != null);
    }
    // the spliced payloads are the same objects the single commands emit
    try std.testing.expectEqual(@as(i64, 3), r.root.object.get("triage").?.object.get("score").?.integer);
    try std.testing.expectEqualStrings("MH_EXECUTE", arch0.get("info").?.object.get("header").?.object.get("filetype_name").?.string);
}

test "facts/report: --only selects sections, an unknown name is a usage error" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var r = try runReport(std.testing.allocator, a, std.testing.io, "hello-c", &.{"--only=header,triage"});
    defer r.deinit();
    const arch0 = r.root.object.get("arches").?.array.items[0].object;
    try std.testing.expect(arch0.get("header") != null and arch0.get("triage") != null);
    try std.testing.expect(arch0.get("symbols") == null and arch0.get("disasm") == null);

    var with_disasm = try runReport(std.testing.allocator, a, std.testing.io, "hello-c", &.{"--only=disasm,xrefs"});
    defer with_disasm.deinit();
    const d0 = with_disasm.root.object.get("arches").?.array.items[0].object;
    try std.testing.expect(d0.get("disasm") != null and d0.get("xrefs") != null);

    const path = try helpers.summaryFixturePath(a, "hello-c");
    const bad = try helpers.runMachre(a, std.testing.io, &.{ "report", "--json", "--only=nope", path });
    try std.testing.expectEqual(@as(u8, 1), bad.code);
}

/// The sections `report --json` renders by default (docs/json-schema.md, `report`). Spelled out here
/// rather than imported so the test pins the documented contract, not the implementation's own list.
const report_sections: []const []const u8 = &.{
    "info",     "header",       "loadcmds", "segments", "symbols", "dyld",      "imports",    "exports",
    "codesign", "entitlements", "objc",     "strings",  "entropy", "functions", "quarantine", "bundle",
    "plist",    "triage",       "version",
};

test "facts/report: every healthy fixture produces one parseable document with no duplicate keys" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (helpers.healthy_fixtures) |fixture| {
        var r = runReport(std.testing.allocator, a, std.testing.io, fixture, &.{}) catch |e| {
            std.debug.print("report --json {s}: {t}\n", .{ fixture, e });
            return e;
        };
        defer r.deinit();
        try std.testing.expectEqual(@as(u8, 0), r.code);
        try std.testing.expect(r.root.object.get("arches").?.array.items.len >= 1);
        // every default section landed under its own command name, on every slice
        for (r.root.object.get("arches").?.array.items) |arch| {
            for (report_sections) |name| {
                if (arch.object.get(name) != null or r.root.object.get(name) != null) continue;
                std.debug.print("report --json {s}: no '{s}' payload\n", .{ fixture, name });
                return error.ReportPayloadMissing;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// docs/json-schema.md
// ---------------------------------------------------------------------------------------------

/// `<repo>/docs/json-schema.md` — derived from the compiled-in `src/root.zig` path like helpers.corpusDir.
fn schemaDoc(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const root = std.fs.path.dirname(helpers.srcDir()) orelse unreachable;
    const path = try std.fmt.allocPrint(gpa, "{s}/docs/json-schema.md", .{root});
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 22));
}

test "facts/json-schema: the document lists every command and every triage key" {
    const gpa = std.testing.allocator;
    const doc = try schemaDoc(gpa, std.testing.io);
    defer gpa.free(doc);
    // every command has a payload section
    for (machre.cli.commands) |c| {
        var buf: [64]u8 = undefined;
        const needle = try std.fmt.bufPrint(&buf, "### `{s}`", .{c.name});
        if (std.mem.find(u8, doc, needle) == null) {
            std.debug.print("docs/json-schema.md has no section for command '{s}'\n", .{c.name});
            return error.SchemaSectionMissing;
        }
    }
    // every triage rule id is documented, so an analyst can look up what a finding means
    for (triage.rules) |r| {
        if (std.mem.find(u8, doc, r.id) == null) {
            std.debug.print("docs/json-schema.md does not mention rule id '{s}'\n", .{r.id});
            return error.SchemaRuleMissing;
        }
    }
    // every key of the triage payload (§6.3) is named
    for ([_][]const u8{ "categories_hit", "corroborates", "not_flagged", "packed_hint", "objc_classes", "exit_code" }) |k| {
        if (std.mem.find(u8, doc, k) == null) {
            std.debug.print("docs/json-schema.md does not mention '{s}'\n", .{k});
            return error.SchemaKeyMissing;
        }
    }
    // the exit-code table is complete
    inline for (@typeInfo(machre.context.ExitCode).@"enum".field_names) |n| {
        var buf: [8]u8 = undefined;
        const needle = try std.fmt.bufPrint(&buf, "`{d}`", .{@intFromEnum(@field(machre.context.ExitCode, n))});
        try std.testing.expect(std.mem.find(u8, doc, needle) != null);
    }
}
