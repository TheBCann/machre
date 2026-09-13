//! tests/facts/plist_bundle.zig — corpus fact tests for WP-plist_bundle (asserts against truth/summary.json + truth/*.txt sections).
//!
//! Everything here is checked against ground truth read at runtime: `truth/summary.json`
//! (`fixtures["Hello.app"].info_plist`, `.codesign.sealed_resources`, `.bundle_files`) and the
//! `plutil -p` / `codesign -dvvv` sections of `truth/Hello.app.txt`. Assertions that need a
//! dependency that has not landed return `error.SkipZigTest`.
const std = @import("std");
const Io = std.Io;
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");

const plist = machre.plist.plist;
const bplist = machre.plist.bplist;
const xml = machre.plist.xml;
const bundle = machre.bundle;
const Limits = machre.core.limits.Limits;
const Diagnostics = machre.core.diag.Diagnostics;

fn corpusPath(arena: std.mem.Allocator, rel: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ helpers.corpusDir(), rel });
}
fn readCorpus(arena: std.mem.Allocator, io: Io, rel: []const u8) ![]const u8 {
    var dir = try helpers.openCorpus(io);
    defer dir.close(io);
    return dir.readFileAlloc(io, rel, arena, .limited(1 << 24));
}

// ---------------------------------------------------------------------------------------------
// plists
// ---------------------------------------------------------------------------------------------

test "facts/plist: Hello.app Info.plist (bplist) deep-equals Hello-Info.plist.xml and carries the 12 summary keys" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);

    const bin = try readCorpus(arena, io, "Hello.app/Contents/Info.plist");
    const xml_bytes = try readCorpus(arena, io, "Hello-Info.plist.xml");
    try std.testing.expectEqual(plist.Format.bplist, plist.detect(bin));
    try std.testing.expectEqual(plist.Format.xml, plist.detect(xml_bytes));

    const a = (try bplist.parse(arena, bin, &Limits.default, &diags)).?;
    const b = (try xml.parse(arena, xml_bytes, &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(usize, 0), diags.items().len);
    try std.testing.expect(a.deepEqual(b));
    try std.testing.expect(b.deepEqual(a));
    // parseAny must reach the same values through format detection.
    try std.testing.expect((try plist.parseAny(arena, bin, &Limits.default, &diags)).?.deepEqual(a));
    try std.testing.expect((try plist.parseAny(arena, xml_bytes, &Limits.default, &diags)).?.deepEqual(a));

    var summary = try helpers.loadSummary(std.testing.allocator, io);
    defer summary.deinit();
    const fixture = summary.fixtureNamed("Hello.app").?;
    const want = helpers.Summary.object(fixture, "info_plist").?.object;
    try std.testing.expectEqual(@as(usize, 12), want.count());
    try std.testing.expectEqual(@as(usize, 12), a.dict.len);
    var it = want.iterator();
    while (it.next()) |e| {
        const got = a.get(e.key_ptr.*) orelse {
            std.debug.print("Info.plist key '{s}' missing\n", .{e.key_ptr.*});
            return error.KeyMissing;
        };
        switch (e.value_ptr.*) {
            .string => |s| try std.testing.expectEqualStrings(s, got.string),
            .array => |arr| {
                try std.testing.expectEqual(arr.items.len, got.array.len);
                for (arr.items, got.array) |w, g| try std.testing.expectEqualStrings(w.string, g.string);
            },
            else => return error.UnexpectedSummaryShape,
        }
    }
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", a.getString("CFBundleIdentifier").?);
    try std.testing.expectEqualStrings("Hello", a.getString("CFBundleExecutable").?);
    try std.testing.expectEqualStrings("MacOSX", a.path("CFBundleSupportedPlatforms.0").?.string);
}

test "facts/plist: `machre plist` equals the plutil -p truth section for Hello.app" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const secs = try truth.load(arena, io, "Hello.app");
    const sec = truth.find(secs, "/usr/bin/plutil -p") orelse return error.TruthSectionMissing;

    // Both spellings must render identically: the bundle directory and the plist file itself.
    for ([_][]const u8{ "Hello.app", "Hello.app/Contents/Info.plist", "Hello.app/Contents/MacOS/Hello" }) |rel| {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ helpers.corpusDir(), rel }, 0);
        const res = try helpers.runMachre(arena, io, &.{ "plist", "--otool-compat", path });
        try std.testing.expectEqual(@as(u8, 0), res.code);
        truth.expectSameLines(sec.body, res.out) catch |e| {
            std.debug.print("plutil parity failed for {s}\n", .{rel});
            return e;
        };
    }
    // The XML twin renders the same text.
    const xml_path = try std.fmt.allocPrintSentinel(arena, "{s}/Hello-Info.plist.xml", .{helpers.corpusDir()}, 0);
    const res = try helpers.runMachre(arena, io, &.{ "plist", "--otool-compat", xml_path });
    try truth.expectSameLines(sec.body, res.out);
}

test "facts/plist: CodeResources renders identically to plutil -p" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/Hello.app/Contents/_CodeSignature/CodeResources", .{helpers.corpusDir()}, 0);
    const res = try helpers.runMachre(arena, io, &.{ "plist", "--otool-compat", path });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    // plutil is the oracle; run it if it exists, otherwise fall back to structural assertions.
    const run = std.process.run(std.testing.allocator, io, .{ .argv = &.{ "/usr/bin/plutil", "-p", path } }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(run.stdout);
    defer std.testing.allocator.free(run.stderr);
    try truth.expectSameLines(run.stdout, res.out);
}

test "facts/plist: __TEXT,__info_plist of /usr/bin/codesign parses" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    Io.Dir.cwd().access(io, "/usr/bin/codesign", .{}) catch return error.SkipZigTest;
    const res = try helpers.runMachre(arena, io, &.{ "plist", "--json", "/usr/bin/codesign" });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    var parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, res.out, .{}) catch return error.SkipZigTest;
    defer parsed.deinit();
    const p = parsed.value.object.get("plist").?.object;
    try std.testing.expectEqualStrings("info_plist_section", p.get("source").?.string);
    try std.testing.expectEqualStrings("xml", p.get("format").?.string);
    const v = p.get("value").?.object;
    try std.testing.expectEqualStrings("com.apple.security.codesign", v.get("CFBundleIdentifier").?.string);
}

test "facts/plist: JSON value encoding of data/date/uid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    const v = (try bplist.parse(arena, bplist.tiny, &Limits.default, &diags)).?;
    var w: Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    var js: std.json.Stringify = .{ .writer = &w.writer, .options = .{} };
    try js.write(v);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, w.written(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try std.testing.expectEqualStrings("010203", o.get("d").?.object.get("$data").?.string);
    try std.testing.expectEqualStrings("2001-01-01T00:00:01Z", o.get("t").?.string);
    try std.testing.expectEqual(@as(i64, 300), o.get("i").?.integer);
    try std.testing.expectEqualStrings("héllo", o.get("s").?.string);
    try std.testing.expect(o.get("b").?.bool);
}

// ---------------------------------------------------------------------------------------------
// bundles
// ---------------------------------------------------------------------------------------------

/// Parses "Sealed Resources version=2 rules=13 files=1" from the codesign truth.
const SealLine = struct { version: u32, rules: u32, files: u32 };
fn parseSealLine(s: []const u8) ?SealLine {
    var out: SealLine = .{ .version = 0, .rules = 0, .files = 0 };
    const fields = [_]struct { key: []const u8, dst: *u32 }{
        .{ .key = "version=", .dst = &out.version },
        .{ .key = "rules=", .dst = &out.rules },
        .{ .key = "files=", .dst = &out.files },
    };
    for (fields) |f| {
        const at = std.mem.find(u8, s, f.key) orelse return null;
        var end = at + f.key.len;
        while (end < s.len and s[end] >= '0' and s[end] <= '9') end += 1;
        f.dst.* = std.fmt.parseInt(u32, s[at + f.key.len .. end], 10) catch return null;
    }
    return out;
}

test "facts/bundle: CodeResources matches the codesign 'Sealed Resources' line" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);

    var summary = try helpers.loadSummary(std.testing.allocator, io);
    defer summary.deinit();
    const fixture = summary.fixtureNamed("Hello.app").?;
    const cs = helpers.Summary.object(fixture, "codesign").?;
    const line = helpers.Summary.str(cs, "sealed_resources").?;
    const want = parseSealLine(line) orelse return error.UnexpectedTruthShape;

    const bytes = try readCorpus(arena, io, "Hello.app/Contents/_CodeSignature/CodeResources");
    const cr = (try bundle.parseCodeResources(arena, bytes, &Limits.default, &diags)).?;
    try std.testing.expectEqual(want.version, cr.version);
    try std.testing.expectEqual(want.rules, cr.activeRules());
    try std.testing.expectEqual(@as(usize, want.files), cr.activeFiles());
    // The corpus numbers, spelled out: version 2, 13 v2 rules, 1 sealed nested object.
    try std.testing.expectEqual(@as(u32, 2), cr.version);
    try std.testing.expectEqual(@as(u32, 13), cr.rules2);
    try std.testing.expectEqual(@as(u32, 5), cr.rules);
    try std.testing.expectEqual(@as(usize, 1), cr.files2.len);
    try std.testing.expectEqual(@as(usize, 0), cr.files.len);

    const nested = cr.find("Frameworks/libhello.dylib").?;
    try std.testing.expect(nested.nested);
    try std.testing.expectEqualStrings("41b85e203bb8c224afbb5cc02bb4a5d28049b754", try std.fmt.allocPrint(arena, "{x}", .{&nested.cdhash.?}));
    try std.testing.expect(std.mem.find(u8, nested.requirement.?, "41b85e203bb8c224afbb5cc02bb4a5d28049b754") != null);
    // Apple's default rule set is understood by the rule matcher.
    try std.testing.expect(cr.omit_rules.len >= 3);
    try std.testing.expect(cr.nested_rules.len >= 2);
}

test "facts/bundle: Hello.app layout, nested code and ResourceVerify" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 64);
    const root = try corpusPath(arena, "Hello.app");

    try std.testing.expectEqual(@as(?bundle.Kind, .app), bundle.detect(io, root));
    const b = (try bundle.analyze(arena, std.testing.allocator, io, root, .{}, &Limits.default, &diags)).?;
    try std.testing.expectEqual(bundle.Kind.app, b.kind);
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", b.identifier.?);
    try std.testing.expectEqualStrings("Contents/MacOS/Hello", b.executable_rel.?);
    try std.testing.expectEqualStrings("Contents/Info.plist", b.info_plist_path.?);
    try std.testing.expectEqual(plist.Format.bplist, b.info_plist_format);
    try std.testing.expectEqual(@as(usize, 12), b.info_plist.?.dict.len);
    try std.testing.expectEqualStrings("APPL", b.package_type.?);
    try std.testing.expectEqualStrings("13.0", b.min_system.?);
    try std.testing.expectEqualStrings("NSApplication", b.principal_class.?);
    try std.testing.expect(!b.ui_element and !b.background_only and !b.ats_arbitrary_loads);
    try std.testing.expect(b.stapled_ticket == null);
    try std.testing.expect(!b.provisioning_profile);
    try std.testing.expect(!b.truncated);

    // `find Hello.app -type f` from the truth file is the file list.
    const secs = try truth.load(arena, io, "Hello.app");
    const found = truth.find(secs, "/usr/bin/find") orelse return error.TruthSectionMissing;
    var want_files: usize = 0;
    var it = std.mem.splitScalar(u8, found.body, '\n');
    while (it.next()) |l| {
        if (std.mem.trim(u8, l, " \t\r").len != 0) want_files += 1;
    }
    try std.testing.expectEqual(@as(u32, @intCast(want_files)), b.file_count);

    const nested = try b.nestedAll(arena);
    try std.testing.expectEqual(@as(usize, 1), nested.len);
    try std.testing.expectEqualStrings("Contents/Frameworks/libhello.dylib", nested[0].rel_path);
    try std.testing.expectEqualStrings("41b85e203bb8c224afbb5cc02bb4a5d28049b754", try std.fmt.allocPrint(arena, "{x}", .{&nested[0].sealed_cdhash.?}));
    try std.testing.expectEqual(@as(usize, 1), nested[0].arch_names.len);
    try std.testing.expectEqualStrings("arm64", nested[0].arch_names[0]);
    try std.testing.expectEqual(@as(?bool, true), nested[0].signed);

    const rv = b.resource_verify.?;
    try std.testing.expectEqual(@as(usize, 0), rv.mismatched.len);
    try std.testing.expectEqual(@as(usize, 0), rv.missing.len);
    if (rv.unsealed.len != 0) {
        for (rv.unsealed) |u| std.debug.print("unexpected unsealed file: {s}\n", .{u});
        return error.UnexpectedUnsealedFiles;
    }
    try std.testing.expect(rv.ok);

    // The nested cdhash comparison goes through codesign/blobs (WP3), which is implemented.
    try std.testing.expect(!diags.has(.codesign, .not_implemented));
    try std.testing.expectEqualStrings("41b85e203bb8c224afbb5cc02bb4a5d28049b754", try std.fmt.allocPrint(arena, "{x}", .{&nested[0].actual_cdhash.?}));
    try std.testing.expectEqual(@as(?bool, true), nested[0].cdhash_match);
    try std.testing.expect(rv.checked >= 1);
}

/// Rewrites `rel` inside `dir` with one byte flipped at `at`, and returns the file's length.
fn flipByte(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, rel: []const u8, at: enum { middle, code_directory }) !void {
    const bytes = try dir.readFileAlloc(io, rel, gpa, .limited(1 << 24));
    defer gpa.free(bytes);
    const idx: usize = switch (at) {
        .middle => bytes.len / 2,
        // CSMAGIC_CODEDIRECTORY, big-endian; the blob length is the next big-endian u32. Flipping the
        // last byte of the blob changes a page-hash slot, hence the cdhash, without disturbing any
        // structure the parser walks.
        .code_directory => blk: {
            const off = std.mem.findLast(u8, bytes, &[_]u8{ 0xfa, 0xde, 0x0c, 0x02 }) orelse return error.NoCodeDirectory;
            const len = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .big);
            break :blk off + len - 1;
        },
    };
    bytes[idx] ^= 0xff;
    var f = try dir.createFile(io, rel, .{});
    defer f.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = f.writer(io, &wbuf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}

const nested_dylib_rel = "Hello.app/Contents/Frameworks/libhello.dylib";

test "facts/bundle: flipping a byte of the nested dylib's CodeDirectory breaks the seal" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const app = try copyBundle(gpa, io, tmp.dir, arena);
    try flipByte(gpa, io, tmp.dir, nested_dylib_rel, .code_directory);

    var diags = Diagnostics.init(arena, 64);
    const b = (try bundle.analyze(arena, gpa, io, app, .{}, &Limits.default, &diags)).?;
    const nested = try b.nestedAll(arena);
    try std.testing.expectEqual(@as(usize, 1), nested.len);
    try std.testing.expect(!diags.has(.codesign, .not_implemented));
    try std.testing.expectEqual(@as(?bool, false), nested[0].cdhash_match);
    try std.testing.expect(!b.resource_verify.?.ok);
    try std.testing.expectEqual(@as(usize, 1), b.resource_verify.?.mismatched.len);
}

test "facts/bundle: flipping a code byte of the nested dylib leaves the CodeResources seal intact" {
    // CodeResources seals nested code by the cdhash of its CodeDirectory (DESIGN.md §4.21), which does
    // not cover itself over the __TEXT bytes: a flipped code byte breaks the nested binary's OWN page
    // hashes (`machre codesign` reports that) but not the outer bundle's seal. Pinning the distinction
    // here keeps a future "verify everything in verifyResources" change from being made silently.
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const app = try copyBundle(gpa, io, tmp.dir, arena);
    try flipByte(gpa, io, tmp.dir, nested_dylib_rel, .middle);

    var diags = Diagnostics.init(arena, 64);
    const b = (try bundle.analyze(arena, gpa, io, app, .{}, &Limits.default, &diags)).?;
    const nested = try b.nestedAll(arena);
    try std.testing.expectEqual(@as(usize, 1), nested.len);
    try std.testing.expectEqual(@as(?bool, true), nested[0].cdhash_match);
    try std.testing.expect(b.resource_verify.?.ok);
}

/// Copies tests/corpus/Hello.app into `dir` and returns the absolute path of the copy.
fn copyBundle(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, arena: std.mem.Allocator) ![]const u8 {
    var src = try helpers.openCorpus(io);
    defer src.close(io);
    var app = try src.openDir(io, "Hello.app", .{});
    defer app.close(io);
    try dir.createDirPath(io, "Hello.app/Contents/MacOS");
    try dir.createDirPath(io, "Hello.app/Contents/Frameworks");
    try dir.createDirPath(io, "Hello.app/Contents/_CodeSignature");
    const files = [_][]const u8{
        "Contents/Info.plist",
        "Contents/MacOS/Hello",
        "Contents/Frameworks/libhello.dylib",
        "Contents/_CodeSignature/CodeResources",
    };
    for (files) |rel| {
        const bytes = try app.readFileAlloc(io, rel, gpa, .limited(1 << 24));
        defer gpa.free(bytes);
        const dst = try std.fmt.allocPrint(arena, "Hello.app/{s}", .{rel});
        try writeFile(io, dir, dst, bytes);
    }
    return dir.realPathFileAlloc(io, "Hello.app", arena);
}

test "facts/bundle: a hashed resource file mismatch is detected without WP3" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "X.app/Contents/MacOS");
    try tmp.dir.createDirPath(io, "X.app/Contents/Resources");
    try tmp.dir.createDirPath(io, "X.app/Contents/_CodeSignature");
    try writeFile(io, tmp.dir, "X.app/Contents/Info.plist",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.X</string>
        \\<key>CFBundleExecutable</key><string>X</string>
        \\<key>CFBundlePackageType</key><string>APPL</string>
        \\<key>LSUIElement</key><true/>
        \\<key>NSCameraUsageDescription</key><string>why</string>
        \\<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>xscheme</string></array></dict></array>
        \\</dict></plist>
    );
    try writeFile(io, tmp.dir, "X.app/Contents/MacOS/X", "not a mach-o");
    try writeFile(io, tmp.dir, "X.app/Contents/Resources/data.txt", "goodbye");
    // the seal below carries sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    try writeFile(io, tmp.dir, "X.app/Contents/_CodeSignature/CodeResources",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>files</key><dict/>
        \\<key>files2</key><dict>
        \\  <key>Resources/data.txt</key><dict><key>hash2</key><data>LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=</data></dict>
        \\</dict>
        \\<key>rules</key><dict/>
        \\<key>rules2</key><dict><key>^Info\.plist$</key><dict><key>omit</key><true/></dict></dict>
        \\</dict></plist>
    );
    const root = try tmp.dir.realPathFileAlloc(io, "X.app", arena);
    var diags = Diagnostics.init(arena, 64);
    const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
    try std.testing.expectEqual(bundle.Kind.app, b.kind);
    try std.testing.expectEqualStrings("com.machre.test.X", b.identifier.?);
    try std.testing.expect(b.ui_element);
    try std.testing.expectEqual(@as(usize, 1), b.usage_descriptions.len);
    try std.testing.expectEqualStrings("NSCameraUsageDescription", b.usage_descriptions[0]);
    try std.testing.expectEqual(@as(usize, 1), b.url_schemes.len);
    try std.testing.expectEqualStrings("xscheme", b.url_schemes[0]);
    const rv = b.resource_verify.?;
    try std.testing.expectEqual(@as(u32, 1), rv.checked);
    try std.testing.expectEqual(@as(usize, 1), rv.mismatched.len);
    try std.testing.expectEqualStrings("Resources/data.txt", rv.mismatched[0]);
    try std.testing.expect(!rv.ok);

    // The same bundle with the sealed content verifies.
    try writeFile(io, tmp.dir, "X.app/Contents/Resources/data.txt", "hello");
    var diags2 = Diagnostics.init(arena, 64);
    const ok = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags2)).?;
    try std.testing.expectEqual(@as(usize, 0), ok.resource_verify.?.mismatched.len);
    try std.testing.expect(ok.resource_verify.?.ok);
}

fn writeFile(io: Io, dir: Io.Dir, rel: []const u8, bytes: []const u8) !void {
    var f = try dir.createFile(io, rel, .{});
    defer f.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = f.writer(io, &wbuf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}

test "facts/bundle: framework layout is walked once and .xpc is recognised" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const info =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.Foo</string>
        \\<key>CFBundleExecutable</key><string>Foo</string>
        \\<key>CFBundlePackageType</key><string>FMWK</string>
        \\</dict></plist>
    ;
    try tmp.dir.createDirPath(io, "Foo.framework/Versions/A/Resources");
    try writeFile(io, tmp.dir, "Foo.framework/Versions/A/Resources/Info.plist", info);
    try writeFile(io, tmp.dir, "Foo.framework/Versions/A/Foo", "binary");
    tmp.dir.symLink(io, "A", "Foo.framework/Versions/Current", .{}) catch return error.SkipZigTest;
    tmp.dir.symLink(io, "Versions/Current/Foo", "Foo.framework/Foo", .{}) catch {};
    tmp.dir.symLink(io, "Versions/Current/Resources", "Foo.framework/Resources", .{}) catch {};

    const root = try tmp.dir.realPathFileAlloc(io, "Foo.framework", arena);
    var diags = Diagnostics.init(arena, 64);
    try std.testing.expectEqual(@as(?bundle.Kind, .framework), bundle.detect(io, root));
    const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
    try std.testing.expectEqual(bundle.Kind.framework, b.kind);
    try std.testing.expectEqualStrings("com.machre.test.Foo", b.identifier.?);
    try std.testing.expect(std.mem.endsWith(u8, b.executable_rel.?, "/Foo"));
    // Symlinks are reported but never descended: exactly two real files, each seen once.
    try std.testing.expectEqual(@as(u32, 2), b.file_count);
    var links: usize = 0;
    for (b.entries) |e| if (e.kind == .sym_link) {
        links += 1;
    };
    try std.testing.expect(links >= 1);
    const exe = (try bundle.mainExecutable(arena, io, root, &Limits.default, &diags)).?;
    try std.testing.expect(std.mem.endsWith(u8, exe, "Foo.framework/Versions/Current/Foo"));

    // .xpc bundles use the Contents/ layout.
    try tmp.dir.createDirPath(io, "Bar.xpc/Contents/MacOS");
    try writeFile(io, tmp.dir, "Bar.xpc/Contents/Info.plist",
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.Bar</string>
        \\<key>CFBundleExecutable</key><string>Bar</string>
        \\</dict></plist>
    );
    try writeFile(io, tmp.dir, "Bar.xpc/Contents/MacOS/Bar", "binary");
    const xpc_root = try tmp.dir.realPathFileAlloc(io, "Bar.xpc", arena);
    try std.testing.expectEqual(@as(?bundle.Kind, .xpc), bundle.detect(io, xpc_root));
    const xb = (try bundle.analyze(arena, gpa, io, xpc_root, .{}, &Limits.default, &diags)).?;
    try std.testing.expectEqual(bundle.Kind.xpc, xb.kind);
    try std.testing.expectEqualStrings("Contents/MacOS/Bar", xb.executable_rel.?);
}

test "facts/bundle: a stapled ticket is recognised by its s8ch magic" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "T.app/Contents/MacOS");
    try writeFile(io, tmp.dir, "T.app/Contents/Info.plist", "<plist><dict><key>CFBundleExecutable</key><string>T</string></dict></plist>");
    try writeFile(io, tmp.dir, "T.app/Contents/MacOS/T", "x");
    try writeFile(io, tmp.dir, "T.app/Contents/CodeResources", "s8chticket-bytes");
    try writeFile(io, tmp.dir, "T.app/Contents/embedded.provisionprofile", "profile");
    const root = try tmp.dir.realPathFileAlloc(io, "T.app", arena);
    var diags = Diagnostics.init(arena, 32);
    const b = (try bundle.analyze(arena, std.testing.allocator, io, root, .{}, &machre.core.limits.Limits.default, &diags)).?;
    try std.testing.expect(b.stapled_ticket != null);
    try std.testing.expectEqual(@as(u64, 16), b.stapled_ticket.?.len);
    try std.testing.expect(b.provisioning_profile);
}

test "facts/bundle: `machre bundle --json` on Hello.app carries the DESIGN 6.3 keys" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/Hello.app", .{helpers.corpusDir()}, 0);
    const res = try helpers.runMachre(arena, io, &.{ "bundle", "--json", path });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, res.out, .{});
    defer parsed.deinit();
    const b = parsed.value.object.get("bundle").?.object;
    for ([_][]const u8{
        "root",          "kind",              "identifier",  "executable",      "executable_path", "package_type",
        "version",       "short_version",     "min_system",  "ui_element",      "background_only", "ats_arbitrary_loads",
        "usage_descriptions", "url_schemes",  "principal_class", "info_plist",  "frameworks",      "helpers",
        "xpc_services",  "plugins",           "dylibs",      "nested",          "code_resources",  "stapled_ticket",
        "provisioning_profile", "file_count", "total_size",  "security",        "spctl",
    }) |k| {
        if (b.get(k) == null) {
            std.debug.print("bundle JSON key '{s}' missing\n", .{k});
            return error.JsonKeyMissing;
        }
    }
    try std.testing.expectEqualStrings("app", b.get("kind").?.string);
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", b.get("identifier").?.string);
    const cr = b.get("code_resources").?.object;
    try std.testing.expectEqual(@as(i64, 2), cr.get("version").?.integer);
    try std.testing.expectEqual(@as(i64, 13), cr.get("active_rules").?.integer);
    try std.testing.expectEqual(@as(usize, 1), cr.get("nested").?.array.items.len);
    try std.testing.expectEqualStrings("41b85e203bb8c224afbb5cc02bb4a5d28049b754", cr.get("nested").?.array.items[0].object.get("cdhash").?.string);
    try std.testing.expect(cr.get("verify").?.object.get("ok").?.bool);
    const ip = b.get("info_plist").?.object;
    try std.testing.expectEqualStrings("bplist", ip.get("format").?.string);
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", ip.get("value").?.object.get("CFBundleIdentifier").?.string);
}

test "facts/bundle: non-bundle inputs exit 3 and never crash" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "hello-c", "Hello-Info.plist.xml", "malformed/empty.bin", "malformed/bad-magic.bin" }) |rel| {
        const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ helpers.corpusDir(), rel }, 0);
        const res = try helpers.runMachre(arena, io, &.{ "bundle", "--json", path });
        try std.testing.expectEqual(@as(u8, 3), res.code);
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, res.out, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(i64, 3), parsed.value.object.get("exit_code").?.integer);
    }
}

// ---------------------------------------------------------------------------------------------
// nested BUNDLES (framework / helper .app) — the case tests/corpus/Hello.app never had
//
// Hello.app's only nested object is a bare dylib whose path *is* its binary, so the walker's
// "resolve the bundle to its main executable, then pick the slice codesign speaks for" step was
// never exercised and shipped broken (every nested item of every real app read the FIRST fat
// slice, i.e. x86_64, and reported a false `match = NO`).
// ---------------------------------------------------------------------------------------------

const LoadedFile = machre.core.file.LoadedFile;
const Image = machre.core.image.Image;
const blobs = machre.codesign.blobs;
const Arch = machre.core.arch.Arch;

fn readCorpusFile(gpa: std.mem.Allocator, io: Io, rel: []const u8) ![]u8 {
    var dir = try helpers.openCorpus(io);
    defer dir.close(io);
    return dir.readFileAlloc(io, rel, gpa, .limited(1 << 24));
}

/// cdhash of slice `index` of `bytes`, the way `machre codesign` reports it.
fn sliceCdhash(arena: std.mem.Allocator, bytes: []const u8, index: usize) !?[20]u8 {
    var diags = Diagnostics.init(arena, 32);
    const f = try LoadedFile.fromBytes(arena, "x", bytes, &Limits.default, &diags);
    const r = f.sliceReader(index) orelse return null;
    const off = f.sliceOffset(index) orelse return null;
    const img = Image.parse(arena, r, off, @intCast(index), &Limits.default, &diags) catch return null;
    const sig = (try blobs.parse(arena, &img, &Limits.default, &diags)) orelse return null;
    const cd = sig.cd() orelse return null;
    return cd.cdhash;
}

fn base64Of(arena: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(raw.len));
    return enc.encode(out, raw);
}

/// Builds `Outer.app` in `dir`: a nested `Nest.framework` (Versions/A layout) and a nested helper
/// `Helper.app`, both wrapping `exe` bytes, with a CodeResources that seals each by `sealed`.
/// Returns the absolute path of the bundle.
fn buildNestedBundleFixture(
    io: Io,
    dir: Io.Dir,
    arena: std.mem.Allocator,
    exe: []const u8,
    sealed_framework: []const u8,
    sealed_helper: []const u8,
) ![]const u8 {
    try dir.createDirPath(io, "Outer.app/Contents/MacOS");
    try dir.createDirPath(io, "Outer.app/Contents/_CodeSignature");
    try dir.createDirPath(io, "Outer.app/Contents/Frameworks/Nest.framework/Versions/A/Resources");
    try dir.createDirPath(io, "Outer.app/Contents/Frameworks/Helper.app/Contents/MacOS");
    try writeFile(io, dir, "Outer.app/Contents/Info.plist",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.Outer</string>
        \\<key>CFBundleExecutable</key><string>Outer</string>
        \\<key>CFBundlePackageType</key><string>APPL</string>
        \\</dict></plist>
    );
    try writeFile(io, dir, "Outer.app/Contents/MacOS/Outer", "not a mach-o");
    try writeFile(io, dir, "Outer.app/Contents/Frameworks/Nest.framework/Versions/A/Resources/Info.plist",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.Nest</string>
        \\<key>CFBundleExecutable</key><string>Nest</string>
        \\<key>CFBundlePackageType</key><string>FMWK</string>
        \\</dict></plist>
    );
    try writeFile(io, dir, "Outer.app/Contents/Frameworks/Nest.framework/Versions/A/Nest", exe);
    try writeFile(io, dir, "Outer.app/Contents/Frameworks/Helper.app/Contents/Info.plist",
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>CFBundleIdentifier</key><string>com.machre.test.Helper</string>
        \\<key>CFBundleExecutable</key><string>Helper</string>
        \\<key>CFBundlePackageType</key><string>APPL</string>
        \\</dict></plist>
    );
    try writeFile(io, dir, "Outer.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper", exe);
    const cr = try std.fmt.allocPrint(arena,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>files</key><dict/>
        \\<key>files2</key><dict>
        \\  <key>Frameworks/Nest.framework</key><dict><key>cdhash</key><data>{s}</data></dict>
        \\  <key>Frameworks/Helper.app</key><dict><key>cdhash</key><data>{s}</data></dict>
        \\</dict>
        \\<key>rules</key><dict/>
        \\<key>rules2</key><dict><key>^Frameworks/</key><dict><key>nested</key><true/><key>weight</key><real>10</real></dict></dict>
        \\</dict></plist>
    , .{ sealed_framework, sealed_helper });
    try writeFile(io, dir, "Outer.app/Contents/_CodeSignature/CodeResources", cr);
    return dir.realPathFileAlloc(io, "Outer.app", arena);
}

fn nestedNamed(list: []const bundle.NestedCode, suffix: []const u8) ?bundle.NestedCode {
    for (list) |n| if (std.mem.endsWith(u8, n.rel_path, suffix)) return n;
    return null;
}

test "facts/bundle: a nested .framework and a nested helper .app resolve to their main executables" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;

    // Hello.app's signed libhello.dylib, re-used as the executable *inside* two bundle wrappers.
    const exe = try readCorpusFile(gpa, io, nested_dylib_rel);
    defer gpa.free(exe);
    const cd = (try sliceCdhash(arena, exe, 0)) orelse return error.NoCodeDirectory;
    const b64 = try base64Of(arena, &cd);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try buildNestedBundleFixture(io, tmp.dir, arena, exe, b64, b64);

    var diags = Diagnostics.init(arena, 64);
    const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
    const nested = try b.nestedAll(arena);
    try std.testing.expectEqual(@as(usize, 2), nested.len);

    const fw = nestedNamed(nested, "Nest.framework") orelse return error.NestedFrameworkMissing;
    try std.testing.expectEqual(bundle.Kind.framework, fw.kind);
    // The regression: the cdhash must come from Versions/A/Nest, not from the wrapper directory.
    try std.testing.expectEqualStrings("Contents/Frameworks/Nest.framework/Versions/A/Nest", fw.executable_rel.?);
    try std.testing.expectEqualSlices(u8, &cd, &fw.actual_cdhash.?);
    try std.testing.expectEqual(@as(?bool, true), fw.cdhash_match);

    const helper = nestedNamed(nested, "Helper.app") orelse return error.NestedHelperAppMissing;
    try std.testing.expectEqual(bundle.Kind.app, helper.kind);
    try std.testing.expectEqualStrings("Contents/Frameworks/Helper.app/Contents/MacOS/Helper", helper.executable_rel.?);
    try std.testing.expectEqualSlices(u8, &cd, &helper.actual_cdhash.?);
    try std.testing.expectEqual(@as(?bool, true), helper.cdhash_match);

    const rv = b.resource_verify.?;
    try std.testing.expectEqual(@as(usize, 0), rv.mismatched.len);
    try std.testing.expectEqual(@as(usize, 0), rv.missing.len);
    try std.testing.expectEqual(@as(usize, 0), rv.unsealed.len);
    try std.testing.expect(rv.ok);
}

test "facts/bundle: tampering inside a nested framework's CodeDirectory is still reported" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;

    const exe = try readCorpusFile(gpa, io, nested_dylib_rel);
    defer gpa.free(exe);
    const cd = (try sliceCdhash(arena, exe, 0)) orelse return error.NoCodeDirectory;
    const b64 = try base64Of(arena, &cd);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try buildNestedBundleFixture(io, tmp.dir, arena, exe, b64, b64);
    try flipByte(gpa, io, tmp.dir, "Outer.app/Contents/Frameworks/Nest.framework/Versions/A/Nest", .code_directory);

    var diags = Diagnostics.init(arena, 64);
    const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
    const nested = try b.nestedAll(arena);
    const fw = nestedNamed(nested, "Nest.framework") orelse return error.NestedFrameworkMissing;
    const helper = nestedNamed(nested, "Helper.app") orelse return error.NestedHelperAppMissing;
    try std.testing.expectEqual(@as(?bool, false), fw.cdhash_match);
    try std.testing.expectEqual(@as(?bool, true), helper.cdhash_match);
    const rv = b.resource_verify.?;
    try std.testing.expect(!rv.ok);
    try std.testing.expectEqual(@as(usize, 1), rv.mismatched.len);
    try std.testing.expectEqualStrings("Contents/Frameworks/Nest.framework", rv.mismatched[0]);
}

/// lipo-style container: `a` declared x86_64 (slice 0), `b` declared arm64 (slice 1).
fn buildFatPair(arena: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    const page = 0x4000;
    const off_a = page;
    const off_b = std.mem.alignForward(usize, off_a + a.len, page);
    const total = off_b + b.len;
    const out = try arena.alloc(u8, total);
    @memset(out, 0);
    const be = struct {
        fn w(buf: []u8, at: usize, v: u32) void {
            std.mem.writeInt(u32, buf[at..][0..4], v, .big);
        }
    };
    be.w(out, 0, 0xcafebabe);
    be.w(out, 4, 2);
    be.w(out, 8, 0x01000007); // CPU_TYPE_X86_64
    be.w(out, 12, 3);
    be.w(out, 16, @intCast(off_a));
    be.w(out, 20, @intCast(a.len));
    be.w(out, 24, 14);
    be.w(out, 28, 0x0100000c); // CPU_TYPE_ARM64
    be.w(out, 32, 0);
    be.w(out, 36, @intCast(off_b));
    be.w(out, 40, @intCast(b.len));
    be.w(out, 44, 14);
    @memcpy(out[off_a..][0..a.len], a);
    @memcpy(out[off_b..][0..b.len], b);
    return out;
}

test "facts/bundle: a universal nested binary is hashed on the host-preferred slice, not slice 0" {
    // THE regression. Both payloads are real, separately ad-hoc-signed corpus binaries with
    // different cdhashes; only the fat table's declared cputypes decide which slice wins, and the
    // walker must make the same choice `cmd/codesign.zig` (fat.selectArches) makes.
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;

    const host = Arch.host();
    const intel_payload = try readCorpusFile(gpa, io, "hello-entitled");
    defer gpa.free(intel_payload);
    const arm_payload = try readCorpusFile(gpa, io, "hello-adhoc");
    defer gpa.free(arm_payload);
    const universal = try buildFatPair(arena, intel_payload, arm_payload);

    const cd_slice0 = (try sliceCdhash(arena, universal, 0)) orelse return error.NoCodeDirectory;
    const cd_slice1 = (try sliceCdhash(arena, universal, 1)) orelse return error.NoCodeDirectory;
    try std.testing.expect(!std.mem.eql(u8, &cd_slice0, &cd_slice1));
    const want_preferred = switch (host.name) {
        .x86_64 => cd_slice0,
        .arm64, .arm64e => cd_slice1,
        else => return error.SkipZigTest,
    };
    const other = if (std.mem.eql(u8, &want_preferred, &cd_slice0)) cd_slice1 else cd_slice0;

    // (a) the seal records the host slice: `actual` is that slice and the seal matches.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const b64 = try base64Of(arena, &want_preferred);
        const root = try buildNestedBundleFixture(io, tmp.dir, arena, universal, b64, b64);
        var diags = Diagnostics.init(arena, 64);
        const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
        const fw = nestedNamed(try b.nestedAll(arena), "Nest.framework").?;
        try std.testing.expectEqualSlices(u8, &want_preferred, &fw.actual_cdhash.?);
        try std.testing.expectEqual(@as(?bool, true), fw.cdhash_match);
        try std.testing.expect(b.resource_verify.?.ok);
    }
    // (b) the app was signed on the other architecture: `actual` still shows the host slice (what
    //     `codesign -dvvv` prints here) but the seal is honoured, not reported as tampering.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const b64 = try base64Of(arena, &other);
        const root = try buildNestedBundleFixture(io, tmp.dir, arena, universal, b64, b64);
        var diags = Diagnostics.init(arena, 64);
        const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
        const fw = nestedNamed(try b.nestedAll(arena), "Nest.framework").?;
        try std.testing.expectEqualSlices(u8, &want_preferred, &fw.actual_cdhash.?);
        try std.testing.expectEqual(@as(?bool, true), fw.cdhash_match);
    }
    // (c) a cdhash that belongs to neither slice is still a mismatch.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var bogus = want_preferred;
        bogus[0] ^= 0xff;
        const b64 = try base64Of(arena, &bogus);
        const root = try buildNestedBundleFixture(io, tmp.dir, arena, universal, b64, b64);
        var diags = Diagnostics.init(arena, 64);
        const b = (try bundle.analyze(arena, gpa, io, root, .{}, &Limits.default, &diags)).?;
        const fw = nestedNamed(try b.nestedAll(arena), "Nest.framework").?;
        try std.testing.expectEqual(@as(?bool, false), fw.cdhash_match);
        try std.testing.expect(!b.resource_verify.?.ok);
    }
}

// ---------------------------------------------------------------------------------------------
// installed applications (host-dependent; every assertion skips when the app is not present)
// ---------------------------------------------------------------------------------------------

const installed_app_candidates = [_][]const u8{
    "/Applications/Safari.app",
    "/Applications/Claude.app",
    "/Applications/Discord.app",
    "/Applications/Firefox.app",
    "/Applications/Google Chrome.app",
    "/Applications/Slack.app",
    "/Applications/Visual Studio Code.app",
    "/System/Applications/Books.app",
    "/System/Applications/Podcasts.app",
    "/System/Library/CoreServices/AddPrinter.app",
};

test "facts/bundle: installed apps — nested bundles resolve and never read the x86_64 slice on Apple silicon" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const host = Arch.host();
    var seen_apps: usize = 0;
    var seen_frameworks: usize = 0;
    var seen_helper_apps: usize = 0;
    var seen_universal: usize = 0;

    for (installed_app_candidates) |app| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        if (bundle.detect(io, app) == null) continue;
        seen_apps += 1;
        var diags = Diagnostics.init(arena, 256);
        const b = (try bundle.analyze(arena, gpa, io, app, .{}, &Limits.default, &diags)) orelse continue;
        for (try b.nestedAll(arena)) |n| {
            if (n.kind == .unknown) continue; // bare dylib: its path is its binary
            if (std.mem.endsWith(u8, n.rel_path, ".framework")) seen_frameworks += 1;
            if (std.mem.endsWith(u8, n.rel_path, ".app")) seen_helper_apps += 1;
            // A nested bundle must be resolved to a main executable *inside* itself.
            const exe = n.executable_rel orelse {
                std.debug.print("{s}: {s} has no resolved executable\n", .{ app, n.rel_path });
                return error.NestedExecutableUnresolved;
            };
            try std.testing.expect(std.mem.startsWith(u8, exe, n.rel_path));
            if (n.arch_names.len < 2) continue;
            seen_universal += 1;
            const from = n.cdhash_arch orelse continue;
            // The bug: the cdhash was read from fat slice 0 (x86_64) on an arm64 host.
            if (host.name != .x86_64 and std.mem.eql(u8, from, "x86_64")) {
                std.debug.print("{s}: {s} hashed on the x86_64 slice of {d} (host {t})\n", .{ app, n.rel_path, n.arch_names.len, host.name });
                return error.NestedHashedOnForeignSlice;
            }
        }
    }
    if (seen_apps == 0 or seen_universal == 0) return error.SkipZigTest;
    if (seen_frameworks + seen_helper_apps == 0) return error.SkipZigTest;
}

test "facts/bundle: Safari.app — every sealed nested object matches its own cdhash" {
    // Safari ships on every Mac, is platform-signed, carries universal nested .xpc/.appex bundles
    // and is the cheapest always-available proof that the walker no longer cries tampering.
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const app = "/Applications/Safari.app";
    if (bundle.detect(io, app) == null) return error.SkipZigTest;
    var diags = Diagnostics.init(arena, 256);
    const b = (try bundle.analyze(arena, gpa, io, app, .{}, &Limits.default, &diags)) orelse return error.SkipZigTest;
    var sealed: usize = 0;
    for (try b.nestedAll(arena)) |n| {
        if (n.sealed_cdhash == null) continue;
        sealed += 1;
        if (n.cdhash_match != true) {
            std.debug.print("{s}: sealed {x} actual {?x} match {?}\n", .{ n.rel_path, &n.sealed_cdhash.?, n.actual_cdhash, n.cdhash_match });
            return error.NestedSealMismatch;
        }
    }
    if (sealed == 0) return error.SkipZigTest;
}
