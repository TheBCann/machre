//! tests/facts/darwin.zig — corpus fact tests for WP-darwin (asserts against truth/summary.json + truth/*.txt sections).
const std = @import("std");
const machre = @import("machre");
const build_options = @import("build_options");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");

const security = machre.darwin.security;
const xattr = machre.darwin.xattr;
const dylib_resolve = machre.darwin.dylib_resolve;
const loadcmds = machre.core.loadcmds;
const Diagnostics = machre.Diagnostics;
const Limits = machre.Limits;

/// `SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures, …)`, exactly the flag set of the
/// zig-api-notes 15.11 oracle run (no revocation, so the matrix is reproducible offline).
const matrix_options: security.Options = .{ .revocation = false, .network = true, .all_archs = true };

fn requireSecurity() !void {
    if (!build_options.have_security) return error.SkipZigTest;
}
fn requirePath(io: std.Io, path: []const u8) !void {
    std.Io.Dir.cwd().access(io, path, .{}) catch return error.SkipZigTest;
}

// ---- xattrs / quarantine -------------------------------------------------------------------

test "facts/darwin: hello-quarantined xattr matches summary.json" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try helpers.ensureQuarantineXattr(gpa, io);

    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const f = summary.fixtureNamed("hello-quarantined").?;
    const want_raw = helpers.Summary.str(f, "quarantine").?;
    const want_names = try helpers.Summary.strings(arena, f, "xattrs");

    var diags = Diagnostics.init(arena, 32);
    const path = try helpers.fixturePath(arena, "hello-quarantined");
    const x = try xattr.read(arena, path, &diags);
    try std.testing.expect(x.available);
    try std.testing.expectEqual(want_names.len, x.names.len);
    for (want_names, x.names) |w, got| try std.testing.expectEqualStrings(w, got);
    const q = x.quarantine orelse return error.NoQuarantineXattr;
    try std.testing.expectEqualStrings(want_raw, q.raw);
    try std.testing.expect(q.well_formed);
    try std.testing.expectEqual(@as(?u16, 0x0083), q.flags);
    try std.testing.expectEqual(@as(?i64, 0x68c3a1b2), q.timestamp);
    try std.testing.expectEqualStrings("Safari", q.agent.?);
    try std.testing.expectEqualStrings("9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C", q.uuid.?);
    try std.testing.expect(!x.is_translocated);
    var buf: [20]u8 = undefined;
    try std.testing.expectEqualStrings("2025-09-12T04:29:38Z", machre.core.sanitize.iso8601(&buf, q.timestamp.?));
}

test "facts/darwin: every fixture's xattr list equals summary.json" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try helpers.ensureQuarantineXattr(gpa, io);
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();

    for (helpers.healthy_fixtures) |name| {
        const f = summary.fixtureNamed(name) orelse continue;
        const want = try helpers.Summary.strings(arena, f, "xattrs");
        var diags = Diagnostics.init(arena, 32);
        const path = try helpers.summaryFixturePath(arena, name);
        const x = try xattr.read(arena, path, &diags);
        std.testing.expectEqual(want.len, x.names.len) catch |e| {
            std.debug.print("xattr count mismatch for {s}\n", .{name});
            return e;
        };
        for (want, x.names) |w, got| try std.testing.expectEqualStrings(w, got);
        const want_q = helpers.Summary.str(f, "quarantine");
        if (want_q) |wq| {
            try std.testing.expectEqualStrings(wq, (x.quarantine orelse return error.NoQuarantineXattr).raw);
        } else try std.testing.expect(x.quarantine == null);
    }
}

test "facts/darwin: quarantine --otool-compat equals the xattr -l truth section" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try helpers.ensureQuarantineXattr(gpa, io);
    for (helpers.healthy_fixtures) |name| {
        const path = try helpers.summaryFixturePath(arena, name);
        const res = try helpers.runMachre(arena, io, &.{ "quarantine", "--otool-compat", path });
        try std.testing.expectEqual(@as(u8, 0), res.code);
        const secs = try truth.load(arena, io, name);
        const sec = truth.find(secs, "/usr/bin/xattr -l") orelse return error.TruthSectionMissing;
        truth.expectSameLines(sec.body, res.out) catch |e| {
            std.debug.print("xattr -l parity failed for {s}\n", .{name});
            return e;
        };
    }
}

// ---- Security.framework trust ladder --------------------------------------------------------

test "facts/darwin: validity agrees with the codesign --verify truth exit for every fixture" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var names: std.ArrayList([]const u8) = .empty;
    for (helpers.healthy_fixtures) |n| try names.append(arena, n);
    try names.append(arena, "Hello.app");
    try names.append(arena, "bin-ls");

    for (names.items) |name| {
        if (std.mem.eql(u8, name, "bin-ls")) requirePath(io, "/bin/ls") catch continue;
        const path = try helpers.summaryFixturePath(arena, name);
        var diags = Diagnostics.init(arena, 64);
        const v = try security.evaluate(arena, path, matrix_options, &diags);
        try std.testing.expect(v.available);
        const secs = try truth.load(arena, io, name);
        const sec = truth.find(secs, "/usr/bin/codesign --verify") orelse return error.TruthSectionMissing;
        const want_valid = sec.exit == 0;
        std.testing.expectEqual(want_valid, v.validity_status == 0) catch |e| {
            std.debug.print("{s}: codesign --verify exit={d} but machre validity={d} ({s})\n", .{ name, sec.exit, v.validity_status, v.validity_status_name });
            return e;
        };
    }
}

const LadderCase = struct {
    fixture: []const u8,
    is_dir: bool = false,
    validity: i32,
    trust: security.Trust,
    /// anchor apple, anchor apple generic, Developer ID, Mac App Store, notarized
    reqs: [5]i32,
};

/// The zig-api-notes 15.11 oracle matrix, reproduced verbatim.
const ladder_cases: []const LadderCase = &.{
    .{ .fixture = "hello-adhoc", .validity = 0, .trust = .adhoc, .reqs = .{ -67050, -67050, -67050, -67050, -67050 } },
    .{ .fixture = "hello-entitled", .validity = 0, .trust = .adhoc, .reqs = .{ -67050, -67050, -67050, -67050, -67050 } },
    .{ .fixture = "Hello.app", .validity = 0, .trust = .adhoc, .reqs = .{ -67050, -67050, -67050, -67050, -67050 } },
    .{ .fixture = "hello-fat", .validity = -67062, .trust = .unsigned, .reqs = .{ -67050, -67050, -67050, -67050, -67050 } },
    .{ .fixture = "hello-x86_64", .validity = -67062, .trust = .unsigned, .reqs = .{ -67062, -67062, -67062, -67062, -67062 } },
    .{ .fixture = "hello-unsigned", .validity = -67062, .trust = .unsigned, .reqs = .{ -67062, -67062, -67062, -67062, -67062 } },
    .{ .fixture = "fake-upx", .validity = -67061, .trust = .invalid, .reqs = .{ -67061, -67061, -67061, -67061, -67061 } },
};

test "facts/darwin: the 15.11 trust-ladder matrix on the corpus" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (ladder_cases) |c| {
        const path = try helpers.summaryFixturePath(arena, c.fixture);
        var diags = Diagnostics.init(arena, 64);
        var opts = matrix_options;
        opts.is_directory = c.is_dir;
        const v = try security.evaluate(arena, path, opts, &diags);
        errdefer std.debug.print("ladder case {s}\n", .{c.fixture});
        try std.testing.expect(v.available);
        try std.testing.expectEqual(c.validity, v.validity_status);
        try std.testing.expectEqualStrings(security.statusName(c.validity), v.validity_status_name);
        try std.testing.expectEqual(c.trust, v.trust);
        const r = v.requirement_results;
        try std.testing.expectEqual(c.reqs[0], r.anchor_apple);
        try std.testing.expectEqual(c.reqs[1], r.apple_generic);
        try std.testing.expectEqual(c.reqs[2], r.developer_id);
        try std.testing.expectEqual(c.reqs[3], r.app_store);
        try std.testing.expectEqual(c.reqs[4], r.notarized);
        try std.testing.expectEqual(c.trust, security.ladder(v.validity_status, r));
        try std.testing.expect(!v.revocation_checked);
    }
}

test "facts/darwin: /bin/ls is a platform binary with the Apple chain" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    try requirePath(io, "/bin/ls");
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);
    const v = try security.evaluate(arena, "/bin/ls", matrix_options, &diags);
    try std.testing.expectEqual(@as(i32, 0), v.validity_status);
    try std.testing.expectEqual(security.Trust.platform, v.trust);
    try std.testing.expectEqual(@as(i32, 0), v.requirement_results.anchor_apple);
    try std.testing.expectEqual(@as(i32, 0), v.requirement_results.apple_generic);
    try std.testing.expectEqual(@as(i32, -67050), v.requirement_results.developer_id);
    try std.testing.expectEqual(@as(i32, -67050), v.requirement_results.app_store);
    // Platform binaries are NOT notarized in requirement terms (zig-api-notes 15.11).
    try std.testing.expectEqual(@as(i32, -67050), v.requirement_results.notarized);
    try std.testing.expectEqualStrings("com.apple.ls", v.identifier.?);
    try std.testing.expectEqualStrings("Mach-O universal (x86_64 arm64e)", v.format.?);
    try std.testing.expectEqual(@as(?u32, 0), v.flags);
    try std.testing.expect(v.platform_identifier != null);
    try std.testing.expect(v.team_id == null);

    // Certificate chain, leaf -> root, from summary.json's `codesign.authority`.
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const cs = helpers.Summary.object(summary.fixtureNamed("bin-ls").?, "codesign").?;
    const want = try helpers.Summary.strings(arena, cs, "authority");
    try std.testing.expectEqual(want.len, v.certificate_chain.len);
    for (want, v.certificate_chain) |w, got| try std.testing.expectEqualStrings(w, got);

    // cdhash and designated requirement against the codesign truth values.
    const want_cdhash = helpers.Summary.str(cs, "cdhash").?;
    var hex: [40]u8 = undefined;
    const got_cdhash = try std.fmt.bufPrint(&hex, "{x}", .{&v.cdhash.?});
    try std.testing.expectEqualStrings(want_cdhash, got_cdhash);
    try std.testing.expect(v.cdhashes.len >= 1);
    try std.testing.expect(v.digest_algorithms.len >= 1);
    const secs = try truth.load(arena, io, "bin-ls");
    const dr = truth.find(secs, "/usr/bin/codesign -d -r -") orelse return error.TruthSectionMissing;
    const want_dr = std.mem.trim(u8, dr.body, " \t\r\n");
    try std.testing.expect(std.mem.endsWith(u8, want_dr, v.designated_requirement.?));
    try std.testing.expect(std.mem.find(u8, v.designated_requirement.?, "identifier \"com.apple.ls\" and anchor apple") != null);
}

test "facts/darwin: Developer ID and App Store rungs (skipped when the apps are absent)" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var checked: usize = 0;

    if (std.Io.Dir.cwd().access(io, "/Applications/Discord.app", .{})) |_| {
        var diags = Diagnostics.init(arena, 64);
        var opts = matrix_options;
        opts.is_directory = true;
        const v = try security.evaluate(arena, "/Applications/Discord.app", opts, &diags);
        try std.testing.expectEqual(@as(i32, 0), v.validity_status);
        try std.testing.expectEqual(security.Trust.developer_id_notarized, v.trust);
        try std.testing.expectEqual(@as(i32, -67050), v.requirement_results.anchor_apple);
        try std.testing.expectEqual(@as(i32, 0), v.requirement_results.apple_generic);
        try std.testing.expectEqual(@as(i32, 0), v.requirement_results.developer_id);
        try std.testing.expectEqual(@as(i32, 0), v.requirement_results.notarized);
        try std.testing.expect(v.team_id != null);
        try std.testing.expect(v.has_stapled_ticket and v.ticket_len > 0);
        try std.testing.expect(v.certificate_chain.len == 3);
        checked += 1;
    } else |_| {}

    if (std.Io.Dir.cwd().access(io, "/Applications/Sketch.app", .{})) |_| {
        var diags = Diagnostics.init(arena, 64);
        var opts = matrix_options;
        opts.is_directory = true;
        const v = try security.evaluate(arena, "/Applications/Sketch.app", opts, &diags);
        try std.testing.expectEqual(@as(i32, 0), v.validity_status);
        try std.testing.expectEqual(security.Trust.app_store, v.trust);
        try std.testing.expectEqual(@as(i32, 0), v.requirement_results.app_store);
        try std.testing.expectEqual(@as(i32, -67050), v.requirement_results.notarized);
        checked += 1;
    } else |_| {}

    if (checked == 0) return error.SkipZigTest;
}

test "facts/darwin: signing information for hello-entitled (entitlements dict, flags, cdhash)" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const cs = helpers.Summary.object(summary.fixtureNamed("hello-entitled").?, "codesign").?;
    const want_keys = try helpers.Summary.strings(arena, cs, "entitlements_keys");
    try std.testing.expectEqual(@as(usize, 5), want_keys.len);

    var diags = Diagnostics.init(arena, 64);
    const path = try helpers.fixturePath(arena, "hello-entitled");
    const v = try security.evaluate(arena, path, matrix_options, &diags);
    try std.testing.expectEqualStrings(helpers.Summary.str(cs, "identifier").?, v.identifier.?);
    try std.testing.expectEqualStrings(helpers.Summary.str(cs, "format").?, v.format.?);
    const want_flags = helpers.Summary.hex(helpers.Summary.object(cs, "flags").?, "hex").?;
    try std.testing.expectEqual(@as(?u32, @intCast(want_flags)), v.flags);
    var hex: [40]u8 = undefined;
    try std.testing.expectEqualStrings(helpers.Summary.str(cs, "cdhash").?, try std.fmt.bufPrint(&hex, "{x}", .{&v.cdhash.?}));

    const ent = v.entitlements orelse return error.NoEntitlements;
    try std.testing.expect(ent == .dict);
    try std.testing.expectEqual(want_keys.len, ent.dict.len);
    for (want_keys) |w| {
        var found = false;
        for (ent.dict) |e| {
            if (std.mem.eql(u8, e.key, w)) found = true;
        }
        std.testing.expect(found) catch |e| {
            std.debug.print("entitlement key {s} missing from kSecCodeInfoEntitlementsDict\n", .{w});
            return e;
        };
    }
    // Ad-hoc objects carry no certificates and no ticket.
    try std.testing.expectEqual(@as(usize, 0), v.certificate_chain.len);
    try std.testing.expect(!v.has_stapled_ticket);
    try std.testing.expect(v.designated_requirement != null);
}

test "facts/darwin: bundle promotion for Hello.app" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);
    const exe = try helpers.fixturePath(arena, "Hello.app/Contents/MacOS/Hello");
    const v = try security.evaluate(arena, exe, matrix_options, &diags);
    try std.testing.expectEqualStrings("app bundle with Mach-O thin (arm64)", v.format.?);
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", v.identifier.?);
    try std.testing.expect(std.mem.endsWith(u8, v.evaluated_path, "Hello.app"));
    try std.testing.expect(std.mem.endsWith(u8, v.main_executable.?, "Hello.app/Contents/MacOS/Hello"));

    // The byte-identical bare file is a plain Mach-O with a file-name identifier.
    const bare = try helpers.fixturePath(arena, "hello-objc");
    const b = try security.evaluate(arena, bare, matrix_options, &diags);
    try std.testing.expectEqualStrings("Mach-O thin (arm64)", b.format.?);
    try std.testing.expectEqualStrings("hello-objc", b.identifier.?);
    try std.testing.expectEqualStrings(bare, b.evaluated_path);
}

// Regression: `urlPath` filled a STACK buffer and handed it to `sanitize.string`, which returns its
// input slice unchanged when clean — so the CFURL path dangled into a dead frame and the first 16
// bytes came back as stale pointer values ("\x87\xe7\x04..gramming/mac-security/..."). The older
// assertions above used `endsWith`, which the corrupted prefix still satisfied; these pin the whole
// string, its bytes, and its run-to-run stability.
test "facts/darwin: bundle paths are whole, printable and stable (no dangling CFURL buffer)" {
    try requireSecurity();
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);

    const exe = try helpers.fixturePath(arena, "Hello.app/Contents/MacOS/Hello");
    const v = try security.evaluate(arena, exe, matrix_options, &diags);

    // Whole-string equality, not a suffix: the executable is echoed back verbatim and the
    // evaluated path is exactly its bundle root.
    try std.testing.expectEqualStrings(exe, v.main_executable.?);
    const root = exe[0 .. exe.len - "/Contents/MacOS/Hello".len];
    try std.testing.expectEqualStrings(root, v.evaluated_path);

    // A dangling slice only shows its damage once another frame reuses that stack region, which is
    // why asserting straight after `evaluate` is not enough — the bytes are still intact. Overwrite
    // the region the way the real CLI does before re-reading the SAME slices.
    std.mem.doNotOptimizeAway(clobberStack(0xA5));
    try std.testing.expectEqualStrings(exe, v.main_executable.?);
    try std.testing.expectEqualStrings(root, v.evaluated_path);

    // Stale memory shows up as control bytes / invalid UTF-8 in an otherwise ASCII path.
    for ([_][]const u8{ v.evaluated_path, v.main_executable.? }) |s| {
        try std.testing.expect(s.len > 0 and s[0] == '/');
        try std.testing.expect(std.unicode.utf8ValidateSlice(s));
        for (s) |c| try std.testing.expect(c >= 0x20 and c != 0x7f);
    }
}

/// Fills a frame at least as large as `urlPath`'s former 4 KiB scratch buffer, so a slice left
/// dangling into that frame reads this pattern instead of the path it used to hold.
fn clobberStack(fill: u8) u64 {
    var scratch: [8192]u8 = undefined;
    @memset(&scratch, fill);
    var sum: u64 = 0;
    for (scratch) |b| sum +%= b;
    return sum;
}

test "facts/darwin: --no-security and -Dsecurity=false report available=false" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const limits = Limits.default;
    var diags = Diagnostics.init(arena, 64);
    const path = try helpers.fixturePath(arena, "hello-c");
    var file = try machre.LoadedFile.load(gpa, arena, io, path, &limits, &diags);
    defer file.deinit(gpa);
    const img = try machre.Image.parse(arena, file.sliceReader(0).?, file.sliceOffset(0).?, 0, &limits, &diags);

    var off = machre.Analysis.init(gpa, arena, io, &file, &img, &limits, &diags, .{ .security = false });
    const v = try off.security();
    try std.testing.expect(!v.available);
    try std.testing.expectEqual(security.Trust.unavailable, v.trust);
    try std.testing.expectEqualStrings(if (build_options.have_security) "--no-security" else "built without Security.framework (-Dsecurity=false)", v.reason.?);
    try std.testing.expectEqualStrings("not evaluated", v.validity_status_name);
    try std.testing.expectEqualStrings("not evaluated", security.trustSentence(v, 0x20002));

    var on = machre.Analysis.init(gpa, arena, io, &file, &img, &limits, &diags, .{ .security = true });
    const w = try on.security();
    try std.testing.expectEqual(build_options.have_security, w.available);
    try std.testing.expectEqual(security.available, build_options.have_security);
    if (build_options.have_security) {
        try std.testing.expectEqual(@as(i32, 0), w.validity_status);
        try std.testing.expectEqual(security.Trust.adhoc, w.trust);
        try std.testing.expectEqualStrings("AD HOC (linker-signed) -- signature proves integrity only, not identity", security.trustSentence(w, 0x20002));
        // --no-network keeps Security but drops revocation.
        var diags2 = Diagnostics.init(arena, 64);
        const nn = try security.evaluate(arena, path, .{ .revocation = true, .network = false }, &diags2);
        try std.testing.expect(!nn.revocation_checked);
        try std.testing.expect(!nn.network_used);
        try std.testing.expectEqual(security.Trust.adhoc, nn.trust);
    }
}

// ---- dylib resolution ------------------------------------------------------------------------

const ImageParts = struct {
    dylibs: []const loadcmds.Dylib,
    rpaths: []const []const u8,
};

/// `file` stays owned (and alive) by the caller: every decoded string points into its bytes.
fn loadParts(arena: std.mem.Allocator, io: std.Io, file: *machre.LoadedFile, diags: *Diagnostics) !ImageParts {
    const limits = Limits.default;
    _ = io;
    const img = try machre.Image.parse(arena, file.sliceReader(0) orelse return error.SkipZigTest, file.sliceOffset(0).?, 0, &limits, diags);
    var dylibs: std.ArrayList(loadcmds.Dylib) = .empty;
    var rpaths: std.ArrayList([]const u8) = .empty;
    var ordinal: u16 = 0;
    for (img.cmds) |c| {
        if (loadcmds.isDylibLoadCmd(c.cmd)) {
            ordinal += 1;
            if (try loadcmds.decodeDylib(arena, c, ordinal, diags)) |d| try dylibs.append(arena, d);
        } else if (c.lc() == .RPATH) {
            if (loadcmds.decodeLcStr(c, 8, diags)) |s| try rpaths.append(arena, s.text);
        }
    }
    return .{ .dylibs = try dylibs.toOwnedSlice(arena), .rpaths = try rpaths.toOwnedSlice(arena) };
}

fn statusOf(res: []const dylib_resolve.Resolution, name: []const u8) ?dylib_resolve.Status {
    for (res) |r| if (std.mem.eql(u8, r.path, name)) return r.status;
    return null;
}

test "facts/darwin: dylib_resolve statuses for hello-usedylib and Hello.app" {
    if (!dylib_resolve.is_macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);

    // Bare hello-usedylib: rpaths @executable_path and @executable_path/../Frameworks; the corpus
    // directory holds libhello.dylib next to it, so @rpath/libhello.dylib resolves on disk.
    const limits = Limits.default;
    const bare = try helpers.fixturePath(arena, "hello-usedylib");
    var bare_file = try machre.LoadedFile.load(gpa, arena, io, bare, &limits, &diags);
    defer bare_file.deinit(gpa);
    const bare_parts = try loadParts(arena, io, &bare_file, &diags);
    try std.testing.expectEqual(@as(usize, 2), bare_parts.rpaths.len);
    try std.testing.expectEqualStrings("@executable_path", bare_parts.rpaths[0]);
    try std.testing.expectEqualStrings("@executable_path/../Frameworks", bare_parts.rpaths[1]);
    const bare_res = try dylib_resolve.resolveAll(arena, io, bare, bare_parts.dylibs, bare_parts.rpaths, &diags);
    try std.testing.expectEqual(@as(usize, 2), bare_res.len);
    try std.testing.expectEqual(dylib_resolve.Status.shared_cache, statusOf(bare_res, "/usr/lib/libSystem.B.dylib").?);
    try std.testing.expectEqual(dylib_resolve.Status.on_disk, statusOf(bare_res, "@rpath/libhello.dylib").?);
    for (bare_res) |r| if (std.mem.eql(u8, r.path, "@rpath/libhello.dylib")) {
        try std.testing.expectEqualStrings("@executable_path", r.via_rpath.?);
        try std.testing.expect(std.mem.endsWith(u8, r.resolved.?, "/libhello.dylib"));
    };

    // Inside Hello.app the same @rpath resolves through @executable_path/../Frameworks.
    const inside = try helpers.fixturePath(arena, "Hello.app/Contents/MacOS/Hello");
    var in_file = try machre.LoadedFile.load(gpa, arena, io, inside, &limits, &diags);
    defer in_file.deinit(gpa);
    const in_parts = try loadParts(arena, io, &in_file, &diags);
    if (in_parts.rpaths.len != 0) {
        const in_res = try dylib_resolve.resolveAll(arena, io, inside, in_parts.dylibs, in_parts.rpaths, &diags);
        if (statusOf(in_res, "@rpath/libhello.dylib")) |st| {
            try std.testing.expectEqual(dylib_resolve.Status.on_disk, st);
            for (in_res) |r| if (std.mem.eql(u8, r.path, "@rpath/libhello.dylib"))
                try std.testing.expect(std.mem.find(u8, r.resolved.?, "Contents/Frameworks") != null);
        }
    }

    // A Homebrew dylib exists as a file and is not in the shared cache.
    const capstone = "/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib";
    if (std.Io.Dir.cwd().access(io, capstone, .{})) |_| {
        const res = try dylib_resolve.resolveAll(arena, io, "/bin/ls", &.{fakeDylib(capstone)}, &.{}, &diags);
        try std.testing.expectEqual(dylib_resolve.Status.on_disk, res[0].status);
        try std.testing.expect(!dylib_resolve.inSharedCache(capstone));
    } else |_| {}
}

fn fakeDylib(name: []const u8) loadcmds.Dylib {
    return .{ .cmd = @intFromEnum(std.macho.LC.LOAD_DYLIB), .name = name, .name_terminated = true, .timestamp = 2, .current_version = 0, .compat_version = 0, .flags = 0, .ordinal = 1, .weak = false, .reexport = false, .upward = false, .delayed_init = false, .use_command = false };
}

test "facts/darwin: every healthy fixture resolves its dylibs without a missing system path" {
    if (!dylib_resolve.is_macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const limits = Limits.default;

    for (helpers.healthy_fixtures) |name| {
        var diags = Diagnostics.init(arena, 64);
        const path = try helpers.summaryFixturePath(arena, name);
        var file = machre.LoadedFile.load(gpa, arena, io, path, &limits, &diags) catch continue;
        defer file.deinit(gpa);
        const parts = loadParts(arena, io, &file, &diags) catch continue;
        const res = try dylib_resolve.resolveAll(arena, io, path, parts.dylibs, parts.rpaths, &diags);
        // summary.json records the LC_LOAD_DYLIB list per slice; the count must line up.
        const sl = helpers.Summary.slice(summary.fixtureNamed(name).?, 0).?;
        const want = helpers.Summary.array(sl, "dylibs") orelse &.{};
        std.testing.expectEqual(want.len, res.len) catch |e| {
            std.debug.print("dylib count mismatch for {s}\n", .{name});
            return e;
        };
        for (res) |r| {
            std.testing.expect(r.status == .on_disk or r.status == .shared_cache) catch |e| {
                std.debug.print("{s}: {s} -> {t}\n", .{ name, r.path, r.status });
                return e;
            };
        }
    }
}
