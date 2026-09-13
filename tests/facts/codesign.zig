//! tests/facts/codesign.zig — corpus fact tests for WP3 (code signing).
//! Asserts against truth/summary.json (`slices[].code_signature`, `codesign{}`) and the
//! `codesign -dvvv --entitlements -` / `codesign -d -r -` / `codesign -d --entitlements - --xml`
//! truth sections, plus the byte-exact `tests/golden/<fixture>.codesign.txt` snapshots
//! (compared here rather than through tests/golden_tests.zig because the first output line is an
//! absolute path, which is normalised to `<corpus>` below so the snapshots stay portable).
const std = @import("std");
const build_options = @import("build_options");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const Summary = helpers.Summary;
const blobs = machre.codesign.blobs;
const hashes = machre.codesign.hashes;
const requirements = machre.codesign.requirements;
const entitlements = machre.codesign.entitlements;
const cms = machre.codesign.cms;
const version = machre.core.version;

/// Every fixture summary.json knows about; the ones without a signature assert `present == false`.
const all_fixtures = [_][]const u8{
    "hello-c",      "hello-x86_64",   "hello-fat",    "hello-objc",  "libhello.dylib", "hello-usedylib", "hello-adhoc",
    "hello-entitled", "hello-unsigned", "high-entropy", "fake-packed", "fake-upx",       "hello-zig",      "legacy-bind",
    "hello-quarantined", "Hello.app",  "bin-ls",
};
/// Fixtures whose `codesign -dvvv` truth section exists and is a real signature.
const signed_fixtures = [_][]const u8{
    "hello-c",   "hello-adhoc", "hello-entitled", "fake-upx",          "fake-packed", "hello-objc", "hello-zig",
    "legacy-bind", "libhello.dylib", "hello-usedylib", "high-entropy", "hello-quarantined", "hello-fat",
};

const Ctx = struct {
    arena: std.mem.Allocator,
    name: []const u8,
    fn fail(c: *const Ctx, comptime what: []const u8, args: anytype) error{FactMismatch} {
        std.debug.print("[{s}] " ++ what ++ "\n", .{c.name} ++ args);
        return error.FactMismatch;
    }
};
fn expectStr(c: *const Ctx, what: []const u8, want: ?[]const u8, got: ?[]const u8) !void {
    const w = want orelse "<null>";
    const g = got orelse "<null>";
    if (!std.mem.eql(u8, w, g)) return c.fail("{s}: expected '{s}', got '{s}'", .{ what, w, g });
}
fn expectInt(c: *const Ctx, what: []const u8, want: ?i64, got: i64) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected {d}, got {d}", .{ what, w, got });
}
fn expectHex(c: *const Ctx, what: []const u8, want: ?u64, got: u64) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected 0x{x}, got 0x{x}", .{ what, w, got });
}

/// One loaded fixture with an Analysis per slice.
const Loaded = struct {
    file: machre.LoadedFile,
    diags: machre.Diagnostics,
    images: []machre.Image,
};
fn load(gpa: std.mem.Allocator, a: std.mem.Allocator, io: std.Io, name: []const u8) !Loaded {
    const path = try helpers.summaryFixturePath(a, name);
    var diags = machre.Diagnostics.init(a, 256);
    var file = machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    errdefer file.deinit(gpa);
    var list: std.ArrayList(machre.Image) = .empty;
    for (0..file.sliceCount()) |i| {
        const r = file.sliceReader(i) orelse continue;
        const img = machre.Image.parse(a, r, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags) catch continue;
        try list.append(a, img);
    }
    return .{ .file = file, .diags = diags, .images = try list.toOwnedSlice(a) };
}

fn checkSignature(c: *const Ctx, a: std.mem.Allocator, an: *machre.Analysis, sl: std.json.Value) !void {
    const want = Summary.object(sl, "code_signature") orelse return c.fail("summary has no code_signature", .{});
    const present = Summary.boolean(want, "present") orelse false;
    const sig = try an.signature();
    if (!present) {
        if (sig != null) return c.fail("expected no signature", .{});
        return;
    }
    const s = sig orelse return c.fail("expected a signature, got none", .{});
    try expectInt(c, "dataoff", Summary.int(want, "dataoff"), s.dataoff);
    try expectInt(c, "datasize", Summary.int(want, "datasize"), s.datasize);
    const sb = Summary.object(want, "superblob") orelse return c.fail("no superblob in summary", .{});
    try expectHex(c, "superblob.magic", Summary.hex(sb, "magic"), s.superblob_magic);
    try expectStr(c, "superblob.magic_name", Summary.str(sb, "magic_name"), version.csMagicName(s.superblob_magic));
    try expectInt(c, "superblob.length", Summary.int(sb, "length"), s.superblob_length);
    try expectInt(c, "superblob.count", Summary.int(sb, "count"), s.count_declared);
    const want_slots = Summary.array(sb, "slots") orelse &.{};
    if (want_slots.len != s.blobs.len) return c.fail("slots: {d} vs {d}", .{ want_slots.len, s.blobs.len });
    for (want_slots, s.blobs) |w, b| {
        try expectInt(c, "slot.type", Summary.int(w, "type"), b.slot);
        try expectInt(c, "slot.offset", Summary.int(w, "offset"), b.offset);
        try expectHex(c, "slot.magic", Summary.hex(w, "magic"), b.magic);
        try expectInt(c, "slot.length", Summary.int(w, "length"), b.length);
        try expectStr(c, "slot.magic_name", Summary.str(w, "magic_name"), version.csMagicName(b.magic));
    }
    const wcd = Summary.object(want, "code_directory") orelse return c.fail("no code_directory in summary", .{});
    const cd = s.cd() orelse return c.fail("no CodeDirectory parsed", .{});
    try expectHex(c, "cd.version", Summary.hex(wcd, "version"), cd.version);
    try expectInt(c, "cd.flags", Summary.int(wcd, "flags"), cd.flags);
    try expectHex(c, "cd.flags_hex", Summary.hex(wcd, "flags_hex"), cd.flags);
    const want_names = try Summary.strings(a, wcd, "flags_names");
    var buf: [32][]const u8 = undefined;
    const got_names = machre.core.fmt.flagNames(cd.flags, version.cs_flags_full, &buf);
    if (want_names.len != got_names.len) return c.fail("cd.flags_names: {d} vs {d}", .{ want_names.len, got_names.len });
    for (want_names, got_names) |w, g| try expectStr(c, "cd.flags_names", w, g);
    try expectStr(c, "cd.hash_type", Summary.str(wcd, "hash_type"), cd.hash_type.name());
    try expectInt(c, "cd.hash_size", Summary.int(wcd, "hash_size"), cd.hash_size);
    try expectInt(c, "cd.page_size", Summary.int(wcd, "page_size"), @intCast(cd.pageSize()));
    try expectInt(c, "cd.platform", Summary.int(wcd, "platform"), cd.platform);
    try expectInt(c, "cd.n_code_slots", Summary.int(wcd, "n_code_slots"), cd.n_code_slots);
    try expectInt(c, "cd.n_special_slots", Summary.int(wcd, "n_special_slots"), cd.n_special_slots);
    try expectInt(c, "cd.code_limit", Summary.int(wcd, "code_limit"), @intCast(cd.code_limit));
    try expectStr(c, "cd.identifier", Summary.str(wcd, "identifier"), cd.identifier);
    try expectStr(c, "cd.team_id", Summary.str(wcd, "team_id") orelse "<null>", cd.team_id orelse "<null>");
    try expectStr(c, "cd.cdhash", Summary.str(wcd, "cdhash"), try std.fmt.allocPrint(a, "{x}", .{@as([]const u8, &cd.cdhash)}));
    try expectStr(c, "cd.cdhash_full", Summary.str(wcd, "cdhash_full"), try std.fmt.allocPrint(a, "{x}", .{cd.cdhash_full}));
    if (cd.exec_seg) |es| {
        try expectInt(c, "cd.exec_seg_base", Summary.int(wcd, "exec_seg_base"), @intCast(es.base));
        try expectInt(c, "cd.exec_seg_limit", Summary.int(wcd, "exec_seg_limit"), @intCast(es.limit));
        try expectHex(c, "cd.exec_seg_flags", Summary.hex(wcd, "exec_seg_flags"), es.flags);
    }
    // sibling blob lengths
    const req_len: ?i64 = Summary.int(want, "requirements_length");
    const got_req: ?i64 = if (s.blob(2)) |b| @intCast(b.length) else null;
    if ((req_len == null) != (got_req == null) or (req_len != null and req_len.? != got_req.?))
        return c.fail("requirements_length: {?d} vs {?d}", .{ req_len, got_req });
    const cms_len: ?i64 = Summary.int(want, "cms_signature_length");
    const got_cms: ?i64 = if (s.blob(0x10000)) |b| @intCast(b.length) else null;
    if ((cms_len == null) != (got_cms == null) or (cms_len != null and cms_len.? != got_cms.?))
        return c.fail("cms_signature_length: {?d} vs {?d}", .{ cms_len, got_cms });
    const der_len: ?i64 = Summary.int(want, "der_entitlements_length");
    const e = try an.entitlements();
    const got_der: ?i64 = if (e.der_len != 0) @intCast(e.der_len) else null;
    if ((der_len == null) != (got_der == null) or (der_len != null and der_len.? != got_der.?))
        return c.fail("der_entitlements_length: {?d} vs {?d}", .{ der_len, got_der });
    const has_der = Summary.boolean(want, "has_der_entitlements") orelse false;
    if (has_der != (s.entitlements_der != null)) return c.fail("has_der_entitlements: {} vs {}", .{ has_der, s.entitlements_der != null });
    if (Summary.array(want, "entitlements_keys")) |wk| {
        const keys = try Summary.strings(a, want, "entitlements_keys");
        if (wk.len != e.keys.len) return c.fail("entitlements_keys: {d} vs {d}", .{ wk.len, e.keys.len });
        for (keys, e.keys) |w, g| try expectStr(c, "entitlements_key", w, g);
    } else if (e.keys.len != 0) return c.fail("entitlements_keys: expected none, got {d}", .{e.keys.len});
}

test "facts/codesign: code_signature facts for every summary.json fixture" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const c: Ctx = .{ .arena = a, .name = name };
        var l = load(gpa, a, io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer l.file.deinit(gpa);
        const fx = summary.fixtureNamed(name) orelse continue;
        const want_slices = Summary.array(fx, "slices") orelse &.{};
        for (l.images, 0..) |*img, i| {
            if (i >= want_slices.len) break;
            var an = machre.Analysis.init(gpa, a, io, &l.file, img, &machre.Limits.default, &l.diags, .{ .security = false });
            defer an.deinit();
            checkSignature(&c, a, &an, want_slices[i]) catch |e| switch (e) {
                error.FactMismatch => failures += 1,
                else => return e,
            };
        }
    }
    if (failures != 0) {
        std.debug.print("{d} code_signature fact mismatches\n", .{failures});
        return error.FactsFailed;
    }
}

test "facts/codesign: page hashes verify for every signed fixture and fake-upx has a mismatch" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    for (signed_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        var l = load(gpa, a, io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer l.file.deinit(gpa);
        for (l.images) |*img| {
            var an = machre.Analysis.init(gpa, a, io, &l.file, img, &machre.Limits.default, &l.diags, .{ .security = false });
            defer an.deinit();
            const sig = try an.signature() orelse continue;
            const cd = sig.cd() orelse continue;
            const v = try an.verification() orelse return error.NoVerification;
            if (!v.hash_type_supported or !v.code_limit_within_slice) {
                std.debug.print("[{s}] hash type/code limit unusable\n", .{name});
                return error.FactsFailed;
            }
            if (v.pages_checked != cd.n_code_slots) {
                std.debug.print("[{s}] checked {d} of {d} pages\n", .{ name, v.pages_checked, cd.n_code_slots });
                return error.FactsFailed;
            }
            if (std.mem.eql(u8, name, "fake-upx")) {
                if (v.mismatches == 0 or v.first_bad_page == null or v.ok()) {
                    std.debug.print("[fake-upx] expected at least one page-hash mismatch\n", .{});
                    return error.FactsFailed;
                }
            } else if (!v.ok()) {
                std.debug.print("[{s}] page hashes: {d}/{d} ok, {d} special mismatches\n", .{ name, v.pages_ok, v.pages_checked, v.special_mismatches });
                return error.FactsFailed;
            }
        }
    }
}

test "facts/codesign: hello-entitled special slots -2/-5/-7 and DER entitlements" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var l = try load(gpa, a, io, "hello-entitled");
    defer l.file.deinit(gpa);
    var an = machre.Analysis.init(gpa, a, io, &l.file, &l.images[0], &machre.Limits.default, &l.diags, .{ .security = false });
    defer an.deinit();
    const sig = (try an.signature()).?;
    const cd = sig.cd().?;
    const v = (try an.verification()).?;
    try std.testing.expectEqual(@as(?bool, true), v.special.requirements);
    try std.testing.expectEqual(@as(?bool, true), v.special.entitlements_xml);
    try std.testing.expectEqual(@as(?bool, true), v.special.entitlements_der);
    try std.testing.expectEqual(@as(u32, 0), v.special_mismatches);
    try std.testing.expect(cd.isSpecialSlotBound(2) and cd.isSpecialSlotBound(5) and cd.isSpecialSlotBound(7));
    try std.testing.expect(!cd.isSpecialSlotBound(1) and !cd.isSpecialSlotBound(3));
    // A flipped byte in the requirements blob must be caught.
    const req = sig.blob(2).?.bytes;
    const copy = try a.dupe(u8, req);
    copy[copy.len - 1] ^= 0xff;
    try std.testing.expectEqual(@as(?bool, false), hashes.verifySpecialSlot(cd, 2, copy));

    const e = try an.entitlements();
    try std.testing.expectEqual(@as(usize, 5), e.keys.len);
    try std.testing.expectEqual(entitlements.EntSource.both, e.source);
    try std.testing.expect(e.isTrue("com.apple.security.cs.allow-jit"));
    try std.testing.expect(e.isTrue("com.apple.security.get-task-allow"));
    try std.testing.expectEqualStrings("MACHRE.hello-entitled", e.get("com.apple.application-identifier").?.string);
    try std.testing.expect(entitlements.isDangerous("com.apple.security.cs.disable-library-validation") != null);
    // The XML side goes through plist/xml (WP5), which is implemented: the two blobs must agree.
    try std.testing.expect(e.xml != null);
    try std.testing.expect(!e.disagreement);
    try std.testing.expect(entitlements.valuesEqual(e.xml.?, e.der.?));
}

test "facts/codesign: bin-ls CMS chain, markers, designated requirement and offline trust" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var l = load(gpa, a, io, "bin-ls") catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
    defer l.file.deinit(gpa);
    if (l.images.len < 2) return error.SkipZigTest;
    for (l.images) |*img| {
        var an = machre.Analysis.init(gpa, a, io, &l.file, img, &machre.Limits.default, &l.diags, .{ .security = false });
        defer an.deinit();
        const c = (try an.cms()).?;
        const names = try c.authorityNames(a);
        try std.testing.expectEqual(@as(usize, 3), names.len);
        try std.testing.expectEqualStrings("Software Signing", names[0]);
        try std.testing.expectEqualStrings("Apple Code Signing Certification Authority", names[1]);
        try std.testing.expectEqualStrings("Apple Root CA", names[2]);
        try std.testing.expect(c.leaf().?.hasMarker(cms.oid_marker_apple_software_signing));
        try std.testing.expect(c.signing_time != null);
        const cd = (try an.signature()).?.cd().?;
        try std.testing.expectEqual(cms.OfflineTrust.platform, cms.offlineTrust(c, cd.flags, cd.platform));
        const rs = (try an.requirements()).?;
        try std.testing.expectEqualStrings("identifier \"com.apple.ls\" and anchor apple", rs.designated().?.text);
    }
}

test "facts/codesign: summary.json codesign{} facts (identifier, cdhash, flags, signature, format)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    var failures: usize = 0;
    for (signed_fixtures ++ [_][]const u8{ "bin-ls", "Hello.app" }) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const c: Ctx = .{ .arena = a, .name = name };
        const fx = summary.fixtureNamed(name) orelse continue;
        const want = Summary.object(fx, "codesign") orelse continue;
        var l = load(gpa, a, io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer l.file.deinit(gpa);
        // codesign reports the slice it would run: the host-preferred one.
        const sel = try machre.core.fat.selectArches(a, l.file.container, null, false, machre.core.arch.Arch.host());
        const idx = if (sel.indices.len != 0) sel.indices[0] else 0;
        var img: ?*machre.Image = null;
        for (l.images) |*im| if (im.index == idx) {
            img = im;
        };
        const image = img orelse continue;
        var an = machre.Analysis.init(gpa, a, io, &l.file, image, &machre.Limits.default, &l.diags, .{ .security = false });
        defer an.deinit();
        const sig = (try an.signature()) orelse {
            failures += 1;
            continue;
        };
        const cd = sig.cd().?;
        checkCodesignFacts(&c, a, fx, want, sig, cd, image, &l.file) catch |e| switch (e) {
            error.FactMismatch => failures += 1,
            else => return e,
        };
    }
    if (failures != 0) return error.FactsFailed;
}

fn checkCodesignFacts(
    c: *const Ctx,
    a: std.mem.Allocator,
    fx: std.json.Value,
    want: std.json.Value,
    sig: *const blobs.Signature,
    cd: *const blobs.CodeDirectory,
    img: *const machre.Image,
    file: *const machre.LoadedFile,
) !void {
    try expectStr(c, "codesign.identifier", Summary.str(want, "identifier"), cd.identifier);
    try expectStr(c, "codesign.cdhash", Summary.str(want, "cdhash"), try std.fmt.allocPrint(a, "{x}", .{@as([]const u8, &cd.cdhash)}));
    const wflags = Summary.object(want, "flags") orelse return c.fail("codesign.flags missing", .{});
    try expectHex(c, "codesign.flags.hex", Summary.hex(wflags, "hex"), cd.flags);
    const names = try machre.output.text.flags(a, cd.flags, version.cs_flags, ",");
    try expectStr(c, "codesign.flags.names", Summary.str(wflags, "names"), if (names.len == 0) "none" else names);
    const wrapper = sig.blob(0x10000);
    const signature: []const u8 = if (wrapper != null and wrapper.?.length > 8)
        try std.fmt.allocPrint(a, "Signature size={d}", .{wrapper.?.length - 8})
    else if (cd.isAdhoc()) "adhoc" else "none";
    try expectStr(c, "codesign.signature", Summary.str(want, "signature"), signature);
    try expectStr(c, "codesign.code_directory_line", Summary.str(want, "code_directory_line"), try std.fmt.allocPrint(a, "{x} size={d} flags=0x{x}({s}) hashes={d}+{d} location=embedded", .{
        cd.version,
        if (sig.blob(cd.slot)) |b| b.length else @as(u32, @intCast(cd.blob.len)),
        cd.flags,
        if (names.len == 0) "none" else names,
        cd.n_code_slots,
        cd.n_special_slots,
    }));
    // The Format= line: bundles are WP5's (`app bundle with ...`), so only plain files are compared.
    if (Summary.get(fx, "bundle") == null) {
        var buf: [32]u8 = undefined;
        const format: []const u8 = switch (file.container) {
            .fat => |f| blk: {
                var out: std.ArrayList(u8) = .empty;
                try out.appendSlice(a, "Mach-O universal (");
                var first = true;
                for (f.arches) |fa| {
                    if (!fa.valid) continue;
                    if (!first) try out.append(a, ' ');
                    var nb: [32]u8 = undefined;
                    try out.appendSlice(a, fa.arch.displayName(&nb));
                    first = false;
                }
                try out.append(a, ')');
                break :blk try out.toOwnedSlice(a);
            },
            else => try std.fmt.allocPrint(a, "Mach-O thin ({s})", .{img.arch.displayName(&buf)}),
        };
        try expectStr(c, "codesign.format", Summary.str(want, "format"), format);
    }
}

// ---------------------------------------------------------------------------------------------
// `codesign` parity: machre --otool-compat vs the truth sections.

/// Lines that cannot match byte for byte: the path (machine-specific) and codesign's locale- and
/// timezone-formatted signing time (machre prints ISO-8601 UTC).
fn skippable(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "Executable=") or std.mem.startsWith(u8, line, "Signed Time=");
}
fn compareLines(name: []const u8, expected: []const u8, actual: []const u8) !void {
    var ei = std.mem.splitScalar(u8, expected, '\n');
    var ai = std.mem.splitScalar(u8, actual, '\n');
    var n: usize = 0;
    while (true) {
        var e: ?[]const u8 = ei.next();
        while (e != null and (skippable(e.?) or (e.?.len == 0 and ei.peek() == null))) e = ei.next();
        var g: ?[]const u8 = ai.next();
        while (g != null and (skippable(g.?) or (g.?.len == 0 and ai.peek() == null))) g = ai.next();
        if (e == null and g == null) return;
        n += 1;
        const es = std.mem.trimEnd(u8, e orelse "<EOF>", " \t\r");
        const gs = std.mem.trimEnd(u8, g orelse "<EOF>", " \t\r");
        if (!std.mem.eql(u8, es, gs)) {
            std.debug.print("[{s}] line {d} differs:\n  codesign: {s}\n  machre:   {s}\n", .{ name, n, es, gs });
            return error.LinesDiffer;
        }
    }
}
fn truthSection(a: std.mem.Allocator, io: std.Io, name: []const u8, prefix: []const u8) !?truth.Section {
    const secs = truth.load(a, io, name) catch return null;
    return truth.find(secs, prefix);
}

test "facts/codesign: codesign --otool-compat equals codesign -dvvv --entitlements - for every signed fixture" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    const names = signed_fixtures ++ [_][]const u8{"bin-ls"};
    for (names) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const path = try helpers.summaryFixturePath(a, name);
        std.Io.Dir.cwd().access(io, path, .{}) catch continue;
        const sec = try truthSection(a, io, name, "/usr/bin/codesign -dvvv") orelse continue;
        const res = try helpers.runMachre(a, io, &.{ "codesign", "--otool-compat", "--no-security", path });
        compareLines(name, sec.body, res.out) catch {
            failures += 1;
        };
    }
    if (failures != 0) return error.CodesignParityFailed;
}

test "facts/codesign: codesign --requirements --otool-compat equals codesign -d -r -" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    // hello-fat is excluded: `codesign -d -r -` refuses universal files ("not signed at all")
    // even though `-dvvv` reports the arm64 slice's CodeDirectory.
    const names = [_][]const u8{
        "hello-c",     "hello-adhoc",      "hello-entitled", "fake-upx",       "fake-packed", "hello-objc",
        "hello-zig",   "legacy-bind",      "libhello.dylib", "hello-usedylib", "high-entropy",
        "hello-quarantined", "bin-ls",
    };
    for (names) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const path = try helpers.summaryFixturePath(a, name);
        std.Io.Dir.cwd().access(io, path, .{}) catch continue;
        const sec = try truthSection(a, io, name, "/usr/bin/codesign -d -r -") orelse continue;
        const res = try helpers.runMachre(a, io, &.{ "codesign", "--requirements", "--otool-compat", "--no-security", path });
        compareLines(name, sec.body, res.out) catch {
            failures += 1;
        };
    }
    if (failures != 0) return error.RequirementsParityFailed;
}

test "facts/codesign: entitlements --xml equals codesign -d --entitlements - --xml" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    for ([_][]const u8{ "hello-entitled", "hello-c", "hello-adhoc", "bin-ls" }) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const path = try helpers.summaryFixturePath(a, name);
        std.Io.Dir.cwd().access(io, path, .{}) catch continue;
        const sec = try truthSection(a, io, name, "/usr/bin/codesign -d --entitlements - --xml") orelse continue;
        const res = try helpers.runMachre(a, io, &.{ "entitlements", "--xml", "--otool-compat", "--no-security", path });
        compareLines(name, sec.body, res.out) catch {
            failures += 1;
        };
    }
    if (failures != 0) return error.EntitlementsXmlParityFailed;
}

// ---------------------------------------------------------------------------------------------
// byte-exact snapshots (tests/golden/<fixture>.codesign.txt, corpus path normalised to `<corpus>`)

fn normalizePaths(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const dir = helpers.corpusDir();
    var rest = s;
    while (std.mem.find(u8, rest, dir)) |i| {
        try out.appendSlice(a, rest[0..i]);
        try out.appendSlice(a, "<corpus>");
        rest = rest[i + dir.len ..];
    }
    try out.appendSlice(a, rest);
    return out.toOwnedSlice(a);
}

fn goldenSnapshot(gpa: std.mem.Allocator, io: std.Io, fixture: []const u8, argv_extra: []const [:0]const u8, file_name: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.summaryFixturePath(a, fixture);
    std.Io.Dir.cwd().access(io, path, .{}) catch return error.SkipZigTest;
    var argv: std.ArrayList([:0]const u8) = .empty;
    try argv.append(a, "codesign");
    try argv.appendSlice(a, argv_extra);
    try argv.append(a, path);
    const res = try helpers.runMachre(a, io, argv.items);
    const got = try normalizePaths(a, res.out);
    const gpath = try std.fmt.allocPrint(a, "{s}/{s}", .{ try helpers.goldenDir(a), file_name });
    if (build_options.update_golden) {
        var f = try std.Io.Dir.cwd().createFile(io, gpath, .{});
        defer f.close(io);
        var buf: [4096]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(got);
        try w.interface.flush();
        return;
    }
    const want = std.Io.Dir.cwd().readFileAlloc(io, gpath, a, .limited(1 << 22)) catch |e| {
        std.debug.print("cannot read {s}: {t} (regenerate with zig build test-corpus -Dupdate-golden=true)\n", .{ gpath, e });
        return e;
    };
    try std.testing.expectEqualStrings(want, got);
}

test "facts/codesign: byte-exact codesign text snapshots" {
    // `--no-security` renders "not evaluated (--no-security)"; a -Dsecurity=false build words that
    // line differently, so the snapshots are only compared in the default configuration.
    if (!build_options.have_security) return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const Row = struct { fixture: []const u8, argv: []const [:0]const u8, file: []const u8 };
    const rows = [_]Row{
        .{ .fixture = "hello-c", .argv = &.{"--no-security"}, .file = "hello-c.codesign.txt" },
        // DESIGN.md §5.4 in full: the same text WITH the Security.framework block (status line, the five
        // requirement probes, the kSecCodeInfo line and the trust ladder). Deterministic for an ad hoc
        // binary -- no certificate chain, so kSecCSEnforceRevocationChecks never touches the network.
        .{ .fixture = "hello-c", .argv = &.{}, .file = "hello-c.codesign.security.txt" },
        .{ .fixture = "hello-adhoc", .argv = &.{"--no-security"}, .file = "hello-adhoc.codesign.txt" },
        .{ .fixture = "hello-entitled", .argv = &.{ "--no-security", "--hashes" }, .file = "hello-entitled.codesign.txt" },
        .{ .fixture = "fake-upx", .argv = &.{"--no-security"}, .file = "fake-upx.codesign.txt" },
        .{ .fixture = "bin-ls", .argv = &.{ "--no-security", "--arch", "arm64e", "--cms" }, .file = "bin-ls.codesign.txt" },
    };
    var failures: usize = 0;
    for (rows) |r| goldenSnapshot(gpa, io, r.fixture, r.argv, r.file) catch |e| switch (e) {
        error.SkipZigTest => {},
        else => {
            std.debug.print("golden snapshot {s} failed: {t}\n", .{ r.file, e });
            failures += 1;
        },
    };
    if (failures != 0) return error.GoldenSnapshotFailed;
}

test "facts/codesign: requirements blob of /bin/ls prints codesign's designated text" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var l = load(gpa, a, io, "bin-ls") catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
    defer l.file.deinit(gpa);
    var an = machre.Analysis.init(gpa, a, io, &l.file, &l.images[l.images.len - 1], &machre.Limits.default, &l.diags, .{ .security = false });
    defer an.deinit();
    const sig = (try an.signature()).?;
    const blob = sig.requirements.?;
    try std.testing.expectEqual(@as(usize, 60), blob.len);
    const set = try requirements.parseSet(a, blob, &machre.Limits.default, &l.diags);
    try std.testing.expectEqual(@as(usize, 1), set.requirements.len);
    const r = set.designated().?;
    try std.testing.expectEqualStrings("identifier \"com.apple.ls\" and anchor apple", r.text);
    // The same text from the bare requirement blob (40 bytes, format-notes 5).
    try std.testing.expectEqualStrings(r.text, try requirements.prettyPrint(a, r.raw, &machre.Limits.default, &l.diags));
    // Ad-hoc fixtures have no designated requirement: codesign synthesises one from the cdhash.
    var l2 = try load(gpa, a, io, "hello-c");
    defer l2.file.deinit(gpa);
    var an2 = machre.Analysis.init(gpa, a, io, &l2.file, &l2.images[0], &machre.Limits.default, &l2.diags, .{ .security = false });
    defer an2.deinit();
    const cd = (try an2.signature()).?.cd().?;
    try std.testing.expectEqualStrings(
        "cdhash H\"f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b\"",
        try requirements.synthesizedDesignated(a, cd.cdhash),
    );
    try std.testing.expect((try an2.requirements()) == null);
}

test "facts/codesign: the JSON payload carries the DESIGN.md §6.3 key set" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.summaryFixturePath(a, "hello-entitled");
    const res = try helpers.runMachre(a, io, &.{ "codesign", "--json", "--no-security", path });
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
    defer parsed.deinit();
    const arch = parsed.value.object.get("arches").?.array.items[0];
    const cs = arch.object.get("codesign").?.object;
    const sigv = cs.get("code_signature").?.object;
    try std.testing.expect(sigv.get("superblob").?.object.get("slots").?.array.items.len == 5);
    const cd0 = sigv.get("code_directories").?.array.items[0].object;
    for ([_][]const u8{ "slot", "version", "flags", "hash_type_name", "hash_size", "page_size", "platform", "n_code_slots", "n_special_slots", "code_limit", "exec_seg", "runtime", "identifier", "team_id", "cdhash", "cdhash_full", "special_slots", "pages" }) |k| {
        if (cd0.get(k) == null) {
            std.debug.print("code_directories[0].{s} missing\n", .{k});
            return error.JsonKeyMissing;
        }
    }
    for ([_][]const u8{ "best_cdhash", "requirements", "designated_requirement", "entitlements", "cms", "offline_trust" }) |k| {
        if (sigv.get(k) == null) {
            std.debug.print("code_signature.{s} missing\n", .{k});
            return error.JsonKeyMissing;
        }
    }
    const ents = sigv.get("entitlements").?.object;
    try std.testing.expectEqual(@as(usize, 5), ents.get("keys").?.array.items.len);
    try std.testing.expect(ents.get("dangerous").?.array.items.len >= 3);
    try std.testing.expectEqualStrings("adhoc", cs.get("verdict").?.object.get("trust").?.string);
    try std.testing.expect(cs.get("security").?.object.get("available").?.bool == false);
}
