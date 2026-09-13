//! tests/facts/objc_strings.zig — corpus fact tests for WP6 (ObjC metadata, strings, entropy).
//! Ground truth: truth/summary.json (segment entropy, ObjC names from the symbol table) and the
//! `dyld_info -objc` section of truth/<fixture>.txt. Assertions that need a bind-resolved pointer
//! (external superclasses, categories on external classes) go through macho/fixups.FixupTable.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const Summary = helpers.Summary;
const entropy = machre.analysis.entropy;
const objc = machre.objc;
const strings = machre.strings;

const all_fixtures = [_][]const u8{
    "hello-c",     "hello-x86_64",   "hello-fat",         "hello-objc",   "libhello.dylib", "hello-usedylib",
    "hello-adhoc", "hello-entitled", "hello-unsigned",    "high-entropy", "fake-packed",    "fake-upx",
    "hello-zig",   "legacy-bind",    "hello-quarantined", "Hello.app",    "bin-ls",
};
/// The only fixtures whose layout is supposed to look like a packer's (DESIGN.md §12 WP6).
const fixtures_with_tells = [_][]const u8{ "high-entropy", "fake-packed", "fake-upx" };

/// One loaded fixture plus its parsed slices, all owned by `arena`.
const Fixture = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    gpa: std.mem.Allocator,
    file: machre.LoadedFile,
    images: []machre.Image,
    diags: *machre.Diagnostics,

    fn open(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, name: []const u8) !Fixture {
        const path = try helpers.summaryFixturePath(arena, name);
        const diags = try arena.create(machre.Diagnostics);
        diags.* = machre.Diagnostics.init(arena, 256);
        var file = machre.LoadedFile.load(gpa, arena, io, path, &machre.Limits.default, diags) catch |e| switch (e) {
            error.FileNotFound => return error.SkipZigTest,
            else => return e,
        };
        errdefer file.deinit(gpa);
        var list: std.ArrayList(machre.Image) = .empty;
        var i: usize = 0;
        while (i < file.sliceCount()) : (i += 1) {
            const r = file.sliceReader(i) orelse continue;
            const img = try machre.Image.parse(arena, r, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, diags);
            try list.append(arena, img);
        }
        return .{ .arena = arena, .io = io, .gpa = gpa, .file = file, .images = try list.toOwnedSlice(arena), .diags = diags };
    }
    fn deinit(f: *Fixture) void {
        f.file.deinit(f.gpa);
    }
    fn analysis(f: *Fixture, index: usize) machre.Analysis {
        return machre.Analysis.init(f.gpa, f.arena, f.io, &f.file, &f.images[index], &machre.Limits.default, f.diags, .{});
    }
};

// ---------------------------------------------------------------------------------------------
// entropy
// ---------------------------------------------------------------------------------------------

test "facts/objc_strings: per-segment entropy and file_fraction match summary.json for every fixture" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var fx = Fixture.open(gpa, arena, io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer fx.deinit();
        const want_fixture = summary.fixtureNamed(name).?;
        const want_slices = Summary.array(want_fixture, "slices").?;
        for (fx.images, 0..) |*img, i| {
            var an = fx.analysis(i);
            defer an.deinit();
            const rep = try an.entropy();
            const want_segs = Summary.array(want_slices[i], "segments").?;
            if (want_segs.len != rep.segments.len) {
                std.debug.print("[{s}#{d}] segment count {d} != {d}\n", .{ name, i, rep.segments.len, want_segs.len });
                failures += 1;
                continue;
            }
            for (want_segs, rep.segments) |w, got| {
                try std.testing.expectEqualStrings(Summary.str(w, "name").?, got.name);
                const want_entropy = switch (Summary.get(w, "entropy") orelse std.json.Value{ .null = {} }) {
                    .float => |v| v,
                    .integer => |v| @as(f64, @floatFromInt(v)),
                    else => continue, // summary records null for zero-length segments
                };
                if (@abs(want_entropy - got.entropy) > 0.005) {
                    std.debug.print("[{s}#{d}] {s} entropy {d:.4} != {d:.4}\n", .{ name, i, got.name, got.entropy, want_entropy });
                    failures += 1;
                }
                const want_fraction = switch (Summary.get(w, "file_fraction") orelse std.json.Value{ .null = {} }) {
                    .float => |v| v,
                    .integer => |v| @as(f64, @floatFromInt(v)),
                    else => continue,
                };
                if (@abs(want_fraction - got.file_fraction) > 0.001) {
                    std.debug.print("[{s}#{d}] {s} file_fraction {d:.4} != {d:.4}\n", .{ name, i, got.name, got.file_fraction, want_fraction });
                    failures += 1;
                }
            }
            // sections never exceed the slice and are ordered as the image lists them
            for (rep.sections) |sec| try std.testing.expect(sec.file_offset + sec.size <= img.r.len());
        }
        // whole-file entropy is only comparable for thin files (summary hashes the entire file)
        if (fx.images.len == 1 and fx.file.container == .thin) {
            var an = fx.analysis(0);
            defer an.deinit();
            const rep = try an.entropy();
            const want = switch (Summary.get(want_fixture, "file_entropy").?) {
                .float => |v| v,
                .integer => |v| @as(f64, @floatFromInt(v)),
                else => unreachable,
            };
            if (@abs(want - rep.file) > 0.005) {
                std.debug.print("[{s}] file entropy {d:.4} != {d:.4}\n", .{ name, rep.file, want });
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.EntropyFactsFailed;
}

test "facts/objc_strings: packer tells fire for exactly high-entropy, fake-packed and fake-upx" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        var fx = Fixture.open(gpa, arena_state.allocator(), io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer fx.deinit();
        var any = false;
        for (fx.images, 0..) |_, i| {
            var an = fx.analysis(i);
            defer an.deinit();
            const rep = try an.entropy();
            for (rep.tells) |t| {
                try std.testing.expect(t.weight == entropy.tellWeight(t.code));
                try std.testing.expect(t.weight < 50 and t.detail.len > 0);
                any = true;
            }
        }
        var expected = false;
        for (fixtures_with_tells) |n| {
            if (std.mem.eql(u8, n, name)) expected = true;
        }
        if (any != expected) {
            std.debug.print("[{s}] tells present = {}, expected {}\n", .{ name, any, expected });
            return error.TellFactsFailed;
        }
    }
}

test "facts/objc_strings: the packer-name and high-entropy tells name the right segment" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { fixture: []const u8, code: entropy.TellCode, needle: []const u8 };
    const cases = [_]Case{
        .{ .fixture = "high-entropy", .code = .high_entropy_segment, .needle = "__RANDOM" },
        .{ .fixture = "fake-packed", .code = .packer_segment_name, .needle = "__XHDR" },
        .{ .fixture = "fake-upx", .code = .packer_segment_name, .needle = "UPX_DATA" },
    };
    for (cases) |c| {
        var fx = try Fixture.open(gpa, arena, io, c.fixture);
        defer fx.deinit();
        var an = fx.analysis(0);
        defer an.deinit();
        const rep = try an.entropy();
        var found = false;
        for (rep.tells) |t| {
            if (t.code == c.code and std.mem.find(u8, t.detail, c.needle) != null) found = true;
        }
        if (!found) {
            std.debug.print("[{s}] no {t} tell mentioning {s}\n", .{ c.fixture, c.code, c.needle });
            return error.TellFactsFailed;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// strings
// ---------------------------------------------------------------------------------------------

test "facts/objc_strings: hello-c's three cstrings carry the addresses of DESIGN §4.18" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var fx = try Fixture.open(gpa, arena_state.allocator(), io, "hello-c");
    defer fx.deinit();
    var an = fx.analysis(0);
    defer an.deinit();
    const res = try an.strings(.{ .min_len = 4 });
    const Want = struct { addr: u64, text: []const u8 };
    const want = [_]Want{
        .{ .addr = 0x100000668, .text = "hello from machre corpus" },
        .{ .addr = 0x100000681, .text = "%s (%d args)" },
        .{ .addr = 0x10000068e, .text = "exit" },
    };
    for (want) |w| {
        var found = false;
        for (res.strings) |s| {
            if (s.addr != w.addr) continue;
            found = true;
            try std.testing.expectEqualStrings(w.text, s.text);
            try std.testing.expectEqual(strings.Kind.cstring, s.kind);
            try std.testing.expect(!s.lossy and !s.cut);
        }
        if (!found) {
            std.debug.print("hello-c: no string at 0x{x} ({s})\n", .{ w.addr, w.text });
            return error.StringFactsFailed;
        }
    }
    try std.testing.expectEqual(strings.Class.format, strings.classify("%s (%d args)"));
}

test "facts/objc_strings: hello-objc decodes 11 __cfstring entries and 40 selector references" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var fx = try Fixture.open(gpa, arena_state.allocator(), io, "hello-objc");
    defer fx.deinit();
    var an = fx.analysis(0);
    defer an.deinit();
    const fix = try an.fixups();
    const res = try an.strings(.{ .min_len = 1 });
    var cfstrings: usize = 0;
    var methnames: usize = 0;
    for (res.strings) |s| switch (s.kind) {
        .cfstring => cfstrings += 1,
        .objc_methname => methnames += 1,
        else => {},
    };
    try std.testing.expect(fix.source != .none); // ObjC pointers are chained binds (macho/fixups)
    try std.testing.expectEqual(@as(usize, 11), cfstrings);
    try std.testing.expect(methnames > 40);
    var saw_legs = false;
    for (res.strings) |s| {
        if (s.kind == .cfstring and std.mem.eql(u8, s.text, "%@ has %ld legs")) saw_legs = true;
    }
    try std.testing.expect(saw_legs);

    const info = (try an.objc()).?;
    try std.testing.expectEqual(@as(usize, 40), info.selectors.len);
}

test "facts/objc_strings: UTF-16 runs decode where strings(1) sees nothing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The generic scan only follows ASCII-range wide runs; the `__ustring` section decoder handles
    // the full BMP (covered by the "strings: __ustring decodes UTF-16LE (héllo)" module test).
    const utf16 = "w\x00i\x00d\x00e\x00!\x00";
    const res = try strings.extractRaw(arena, utf16, 0, .{ .min_len = 4, .kinds = .initOne(.generic_utf16) }, &machre.Limits.default);
    try std.testing.expectEqual(@as(usize, 1), res.strings.len);
    try std.testing.expectEqualStrings("wide!", res.strings[0].text);
    const ascii = try strings.extractRaw(arena, utf16, 0, .{ .min_len = 4, .kinds = .initOne(.generic_ascii) }, &machre.Limits.default);
    try std.testing.expectEqual(@as(usize, 0), ascii.strings.len);
}

// ---------------------------------------------------------------------------------------------
// ObjC vs the `dyld_info -objc` truth section
// ---------------------------------------------------------------------------------------------

/// One `0xADDR  -[Class selector]` (or address-less protocol) line of `dyld_info -objc`.
const TruthObjc = struct {
    classes: std.ArrayList([]const u8) = .empty,
    categories: std.ArrayList([]const u8) = .empty,
    protocols: std.ArrayList([]const u8) = .empty,
    imps: std.ArrayList(u64) = .empty,
    method_selectors: std.ArrayList([]const u8) = .empty,
    protocol_selectors: std.ArrayList([]const u8) = .empty,

    /// `@interface MachreAnimal : NSObject <MachreGreeter>` / `  0x100001064  -[MachreAnimal sound]`
    fn parse(arena: std.mem.Allocator, body: []const u8) !TruthObjc {
        var t: TruthObjc = .{};
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (std.mem.startsWith(u8, line, "@interface ")) {
                const rest = line["@interface ".len..];
                if (std.mem.findScalar(u8, rest, '(')) |p| {
                    try t.categories.append(arena, try arena.dupe(u8, rest[0..p]));
                } else {
                    const end = std.mem.findScalar(u8, rest, ' ') orelse rest.len;
                    try t.classes.append(arena, try arena.dupe(u8, rest[0..end]));
                }
            } else if (std.mem.startsWith(u8, line, "@protocol ")) {
                const rest = line["@protocol ".len..];
                const end = std.mem.findScalar(u8, rest, ' ') orelse rest.len;
                try t.protocols.append(arena, try arena.dupe(u8, rest[0..end]));
            } else if (std.mem.startsWith(u8, line, "0x")) {
                const sp = std.mem.findScalar(u8, line, ' ') orelse continue;
                const addr = std.fmt.parseInt(u64, line[2..sp], 16) catch continue;
                try t.imps.append(arena, addr);
                if (selectorOf(line[sp..])) |sel| try t.method_selectors.append(arena, try arena.dupe(u8, sel));
            } else if (std.mem.startsWith(u8, line, "-[") or std.mem.startsWith(u8, line, "+[")) {
                if (selectorOf(line)) |sel| try t.protocol_selectors.append(arena, try arena.dupe(u8, sel));
            }
        }
        return t;
    }
    /// "-[MachreAnimal sound]" -> "sound"
    fn selectorOf(s: []const u8) ?[]const u8 {
        const open = std.mem.findScalar(u8, s, '[') orelse return null;
        const close = std.mem.findScalar(u8, s, ']') orelse return null;
        if (close <= open) return null;
        const inner = s[open + 1 .. close];
        const sp = std.mem.findScalar(u8, inner, ' ') orelse return null;
        return inner[sp + 1 ..];
    }
};

fn sortedCopy(arena: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    const out = try arena.dupe([]const u8, items);
    std.mem.sort([]const u8, out, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return out;
}

fn expectSameStringSet(what: []const u8, want: []const []const u8, got: []const []const u8, arena: std.mem.Allocator) !void {
    const a = try sortedCopy(arena, want);
    const b = try sortedCopy(arena, got);
    if (a.len != b.len) {
        std.debug.print("{s}: {d} expected vs {d} parsed\n", .{ what, a.len, b.len });
        for (a) |x| std.debug.print("  want {s}\n", .{x});
        for (b) |x| std.debug.print("  got  {s}\n", .{x});
        return error.ObjcFactsFailed;
    }
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) {
        std.debug.print("{s}: expected '{s}', got '{s}'\n", .{ what, x, y });
        return error.ObjcFactsFailed;
    };
}

fn checkObjcAgainstTruth(gpa: std.mem.Allocator, io: std.Io, fixture: []const u8, truth_name: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sections = try truth.load(arena, io, truth_name);
    const sec = truth.find(sections, "/usr/bin/dyld_info -objc") orelse return error.SkipZigTest;
    const want = try TruthObjc.parse(arena, sec.body);

    var fx = try Fixture.open(gpa, arena, io, fixture);
    defer fx.deinit();
    var an = fx.analysis(0);
    defer an.deinit();
    const fix = try an.fixups();
    const info = (try an.objc()) orelse return error.ObjcFactsFailed;
    if (!info.present or info.classes.len == 0) {
        return error.ObjcFactsFailed;
    }

    // class names (categories are listed separately by dyld_info)
    var got_classes: std.ArrayList([]const u8) = .empty;
    for (info.classes) |c| try got_classes.append(arena, c.name);
    try expectSameStringSet("objc classes", want.classes.items, got_classes.items, arena);

    // protocol names
    var got_protocols: std.ArrayList([]const u8) = .empty;
    for (info.protocols) |p| try got_protocols.append(arena, p.name);
    try expectSameStringSet("objc protocols", want.protocols.items, got_protocols.items, arena);

    // every implementation address dyld_info prints, and the selector at it
    var got_imps: std.ArrayList([]const u8) = .empty;
    var got_selectors: std.ArrayList([]const u8) = .empty;
    for (info.classes) |c| {
        for (c.methods) |m| try appendMethod(arena, &got_imps, &got_selectors, m);
        for (c.class_methods) |m| try appendMethod(arena, &got_imps, &got_selectors, m);
    }
    for (info.categories) |cat| {
        for (cat.instance_methods) |m| try appendMethod(arena, &got_imps, &got_selectors, m);
        for (cat.class_methods) |m| try appendMethod(arena, &got_imps, &got_selectors, m);
    }
    var want_imps: std.ArrayList([]const u8) = .empty;
    for (want.imps.items) |v| try want_imps.append(arena, try std.fmt.allocPrint(arena, "0x{x}", .{v}));
    try expectSameStringSet("objc method addresses", want_imps.items, got_imps.items, arena);
    try expectSameStringSet("objc method selectors", want.method_selectors.items, got_selectors.items, arena);

    // protocol method selectors (dyld_info prints them without an address)
    var got_proto_sels: std.ArrayList([]const u8) = .empty;
    for (info.protocols) |p| {
        for (p.instance_methods) |m| try got_proto_sels.append(arena, m.name);
        for (p.class_methods) |m| try got_proto_sels.append(arena, m.name);
        for (p.optional_instance_methods) |m| try got_proto_sels.append(arena, m.name);
        for (p.optional_class_methods) |m| try got_proto_sels.append(arena, m.name);
    }
    try expectSameStringSet("objc protocol selectors", want.protocol_selectors.items, got_proto_sels.items, arena);

    // Bind-resolved names (external superclass, category on an external class) come from the fixup table.
    try std.testing.expect(fix.source != .none);
    const animal = info.classByName("MachreAnimal").?;
    try std.testing.expect(animal.superclass.kind == .external);
    try std.testing.expectEqualStrings("NSObject", animal.superclass.name.?);
    const dog = info.classByName("MachreDog").?;
    try std.testing.expect(dog.superclass.kind == .local);
    try std.testing.expectEqualStrings("MachreAnimal", dog.superclass.name.?);
    var got_categories: std.ArrayList([]const u8) = .empty;
    for (info.categories) |cat| try got_categories.append(arena, cat.class_name);
    try expectSameStringSet("objc categories", want.categories.items, got_categories.items, arena);
}

fn appendMethod(arena: std.mem.Allocator, imps: *std.ArrayList([]const u8), sels: *std.ArrayList([]const u8), m: objc.Method) !void {
    if (m.imp == 0) return;
    try imps.append(arena, try std.fmt.allocPrint(arena, "0x{x}", .{m.imp}));
    try sels.append(arena, m.name);
}

test "facts/objc_strings: hello-objc classes, protocols and methods equal dyld_info -objc" {
    try checkObjcAgainstTruth(std.testing.allocator, std.testing.io, "hello-objc", "hello-objc");
}

test "facts/objc_strings: Hello.app's executable classes, protocols and methods equal dyld_info -objc" {
    try checkObjcAgainstTruth(std.testing.allocator, std.testing.io, "Hello.app", "Hello.app");
}

test "facts/objc_strings: hello-objc resolves 15 __objc_stubs to selectors" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var fx = try Fixture.open(gpa, arena, io, "hello-objc");
    defer fx.deinit();
    var an = fx.analysis(0);
    defer an.deinit();
    const fix = try an.fixups();
    const info = (try an.objc()).?;
    try std.testing.expect(fix.source != .none);
    try std.testing.expectEqual(@as(usize, 15), info.stubs.len);
    // every stub selector must also be a selector reference in the image
    for (info.stubs) |s| {
        try std.testing.expect(s.selector.len > 0);
        var seen = false;
        for (info.selectors) |sel| {
            if (std.mem.eql(u8, sel.name, s.selector)) seen = true;
        }
        if (!seen) {
            std.debug.print("stub 0x{x} selector '{s}' is not in __objc_selrefs\n", .{ s.addr, s.selector });
            return error.ObjcFactsFailed;
        }
    }
    // stubs are 32 bytes apart (format-notes 12.2)
    var i: usize = 1;
    while (i < info.stubs.len) : (i += 1) try std.testing.expectEqual(@as(u64, 32), info.stubs[i].addr - info.stubs[i - 1].addr);
}

test "facts/objc_strings: parsed class/protocol names agree with summary.json's symbol-derived lists" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var fx = try Fixture.open(gpa, arena, io, "hello-objc");
    defer fx.deinit();
    var an = fx.analysis(0);
    defer an.deinit();
    const fix = try an.fixups();
    const info = (try an.objc()).?;
    try std.testing.expect(fix.source != .none);
    const fixture = summary.fixtureNamed("hello-objc").?;
    const want = try Summary.strings(arena, Summary.slice(fixture, 0).?, "objc_classes");
    for (want) |w| {
        if (info.classByName(w) == null) {
            std.debug.print("summary.json lists class {s}, machre did not find it\n", .{w});
            return error.ObjcFactsFailed;
        }
    }
    const want_protocols = try Summary.strings(arena, Summary.slice(fixture, 0).?, "objc_protocols");
    for (want_protocols) |w| {
        var seen = false;
        for (info.protocols) |p| {
            if (std.mem.eql(u8, p.name, w)) seen = true;
        }
        if (!seen) {
            std.debug.print("summary.json lists protocol {s}, machre did not find it\n", .{w});
            return error.ObjcFactsFailed;
        }
    }
}

test "facts/objc_strings: TextEdit has 19 classes with Document : NSDocument (skipped when absent)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const path = "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit";
    std.Io.Dir.cwd().access(io, path, .{}) catch return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const diags = try arena.create(machre.Diagnostics);
    diags.* = machre.Diagnostics.init(arena, 256);
    var file = try machre.LoadedFile.load(gpa, arena, io, path, &machre.Limits.default, diags);
    defer file.deinit(gpa);
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const r = file.sliceReader(i) orelse continue;
        var img = try machre.Image.parse(arena, r, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, diags);
        if (!objc.hasObjc(&img)) continue;
        var an = machre.Analysis.init(gpa, arena, io, &file, &img, &machre.Limits.default, diags, .{});
        defer an.deinit();
        const fix = try an.fixups();
        const info = (try an.objc()) orelse continue;
        try std.testing.expect(fix.source != .none); // arm64e ObjC pointers are chained binds
        if (info.classes.len == 0) return error.ObjcFactsFailed;
        try std.testing.expectEqual(@as(usize, 19), info.classes.len);
        const doc = info.classByName("Document") orelse return error.ObjcFactsFailed;
        // `Document : NSDocument` is an external bind, resolved through the fixup table.
        try std.testing.expectEqualStrings("NSDocument", doc.superclass.name orelse "");
        return;
    }
    return error.SkipZigTest;
}

// ---------------------------------------------------------------------------------------------
// `machre strings --bare` vs `strings(1)`
// ---------------------------------------------------------------------------------------------

/// The `strings -n 6 | head -200` body of truth/<name>.txt. Read here rather than through
/// tests/truth.zig because that section is the last one in the file and carries no "--- exit="
/// terminator (see core_change_requests); the golden rows cover the same ground once it does.
fn stringsTruthSection(arena: std.mem.Allocator, io: std.Io, name: []const u8) ![]const u8 {
    const path = try std.fmt.allocPrint(arena, "{s}/{s}.txt", .{ helpers.truthDir(), name });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 26));
    const header = "===== /usr/bin/strings -n 6 | head -200 =====\n";
    const at = std.mem.find(u8, bytes, header) orelse return error.SkipZigTest;
    var body = bytes[at + header.len ..];
    if (std.mem.find(u8, body, "\n--- exit=")) |e| body = body[0 .. e + 1];
    return body;
}

test "facts/objc_strings: strings --bare --min=6 --limit=200 equals strings(1) on every healthy fixture" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var failures: usize = 0;
    for (helpers.healthy_fixtures ++ [_][]const u8{"Hello.app"}) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const want = stringsTruthSection(arena, io, name) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        const path = try helpers.summaryFixturePath(arena, name);
        // strings(1) walks every slice of a fat file; machre's text default shows one.
        const argv: []const [:0]const u8 = if (std.mem.eql(u8, name, "hello-fat"))
            &.{ "strings", "--bare", "--min=6", "--limit=200", "--quiet", "--all-archs", path }
        else
            &.{ "strings", "--bare", "--min=6", "--limit=200", "--quiet", path };
        const got = try helpers.runMachre(arena, io, argv);
        if (got.code != 0) {
            std.debug.print("[{s}] strings --bare exited {d}\n", .{ name, got.code });
            failures += 1;
            continue;
        }
        if (!std.mem.eql(u8, want, got.out)) {
            std.debug.print("[{s}] strings --bare differs from strings(1)\n", .{name});
            var wi = std.mem.splitScalar(u8, want, '\n');
            var gi = std.mem.splitScalar(u8, got.out, '\n');
            var line: usize = 1;
            while (true) : (line += 1) {
                const w = wi.next();
                const g = gi.next();
                if (w == null and g == null) break;
                if (w == null or g == null or !std.mem.eql(u8, w.?, g.?)) {
                    std.debug.print("  line {d}: want '{s}' got '{s}'\n", .{ line, w orelse "<eof>", g orelse "<eof>" });
                    break;
                }
            }
            failures += 1;
        }
    }
    if (failures != 0) return error.StringFactsFailed;
}
