//! tests/facts/disasm.zig — corpus fact tests for WP8 (function discovery, stub resolution,
//! annotations, xrefs, engine) asserted against truth/*.txt sections and the DESIGN §12 acceptance list.
//!
//! The `otool -tV` sections these tests read are produced by tests/corpus/gen/truth.sh (WP8 added them).
//! `hello-zig` is the one fixture off the byte-exact list: it uses SIMD families the built-in arm64
//! decoder still has no names for (two-register-misc `rev32`, shift-by-immediate `shl`/`usra`), which
//! print as `.inst 0x…`. That is decoder COVERAGE, not spelling — the Darwin arrangement suffix
//! (`movi.2d v0, #…`), the signed MOV immediates and the x86 immediate rules are covered by the two
//! live-`otool` tests below, which run the real tool over /bin/ls, /bin/date, /bin/cat and plutil.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const build_options = @import("build_options");

const Analysis = machre.analysis.analysis.Analysis;
const functions_mod = machre.disasm.functions;
const symbolize = machre.disasm.symbolize;
const engine_mod = machre.disasm.engine;
const insn_mod = machre.disasm.insn;

const otool_tv = "/usr/bin/otool -tV";

/// Loads one slice of a fixture and hands back an Analysis over it (arena-owned; caller frees `file`).
const Loaded = struct {
    file: machre.LoadedFile,
    img: machre.Image,
    fn deinit(l: *Loaded, gpa: std.mem.Allocator) void {
        l.file.deinit(gpa);
    }
};

fn load(gpa: std.mem.Allocator, a: std.mem.Allocator, io: std.Io, diags: *machre.Diagnostics, path: [:0]const u8, slice: usize) !Loaded {
    var file = try machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, diags);
    errdefer file.deinit(gpa);
    const img = try machre.Image.parse(a, file.sliceReader(slice).?, file.sliceOffset(slice).?, @intCast(slice), &machre.Limits.default, diags);
    return .{ .file = file, .img = img };
}

fn analysisOver(gpa: std.mem.Allocator, a: std.mem.Allocator, io: std.Io, l: *Loaded, diags: *machre.Diagnostics) Analysis {
    return Analysis.init(gpa, a, io, &l.file, &l.img, &machre.Limits.default, diags, .{ .security = false, .resolve_deps = false });
}

// ---------------------------------------------------------------------------------------------
// function discovery
// ---------------------------------------------------------------------------------------------

test "facts/disasm: function discovery covers dyld_info -function_starts and names ObjC IMPs" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 256);

    {
        const path = try helpers.fixturePath(a, "hello-c");
        var l = try load(gpa, a, io, &diags, path, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const t = try an.functions();
        // hello-c is not stripped: the three LC_FUNCTION_STARTS entries are the whole table.
        try std.testing.expectEqual(@as(usize, 3), t.functions.len);
        try std.testing.expectEqual(@as(u64, 0x1000004f8), t.functions[0].start);
        try std.testing.expectEqualStrings("_add_numbers", t.functions[0].name);
        try std.testing.expectEqualStrings("_main", t.byStart(0x100000524).?.name);
        try std.testing.expectEqualStrings("_static_helper", t.byStart(0x10000060c).?.name);
        try std.testing.expectEqual(@as(u64, 0x100000524), t.functions[0].end); // next start
        try std.testing.expect(t.byStart(0x100000524).?.hasSource(.entry)); // LC_MAIN agrees
        try std.testing.expectEqualStrings("_main", t.containing(0x100000588).?.name);
        try std.testing.expect(!t.truncated);
    }
    {
        const path = try helpers.fixturePath(a, "hello-objc");
        var l = try load(gpa, a, io, &diags, path, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const t = try an.functions();
        const starts = (try an.functionStarts()).?;
        var from_starts: usize = 0;
        for (t.functions) |f| if (f.hasSource(.function_starts)) {
            from_starts += 1;
        };
        try std.testing.expectEqual(starts.addrs.len, from_starts);
        for (starts.addrs) |addr| try std.testing.expect(t.byStart(addr) != null);
        // ObjC method IMPs are named "-[Class sel]" / "+[Class sel]".
        try std.testing.expect(t.byName("-[MachreDog bark]") != null);
        try std.testing.expect(t.byName("+[MachreAnimal population]") != null);
        try std.testing.expect(t.byName("-[NSString(MachreExtras) machreShout]") != null);
        // the ObjC message stubs carry local symbols and are discovered too
        try std.testing.expect(t.byName("_objc_msgSend$bark") != null);
    }
}

test "facts/disasm: bin-ls has 50 function starts per slice, all discovered" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 512);
    const path = try helpers.fixturePath(a, "/bin/ls");
    var file = machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags) catch return error.SkipZigTest;
    defer file.deinit(gpa);
    if (file.sliceCount() < 2) return error.SkipZigTest;
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const img = try machre.Image.parse(a, file.sliceReader(i).?, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags);
        var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
        defer an.deinit();
        const starts = (try an.functionStarts()).?;
        try std.testing.expectEqual(@as(usize, 50), starts.addrs.len);
        const t = try an.functions();
        for (starts.addrs) |addr| try std.testing.expect(t.byStart(addr) != null);
        // /bin/ls is stripped: the names are synthesized.
        try std.testing.expect(t.byStart(starts.addrs[0]).?.synthetic());
    }
}

test "facts/disasm: functions --otool-compat equals dyld_info -function_starts" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (helpers.healthy_fixtures) |name| {
        if (std.mem.eql(u8, name, "hello-fat")) continue; // fat: dyld_info prints both slices, see below
        const secs = try truth.load(a, io, name);
        const want = truth.find(secs, "/usr/bin/dyld_info -function_starts") orelse continue;
        const path = try helpers.fixturePath(a, name);
        const got = try helpers.runMachre(a, io, &.{ "functions", "--otool-compat", path });
        truth.expectSameLines(want.body, got.out) catch |e| {
            std.debug.print("  -> functions --otool-compat {s}\n", .{name});
            return e;
        };
    }
}

// ---------------------------------------------------------------------------------------------
// stubs
// ---------------------------------------------------------------------------------------------

test "facts/disasm: hello-c resolves 5 stubs with both algorithms agreeing" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const path = try helpers.fixturePath(a, "hello-c");
    var l = try load(gpa, a, io, &diags, path, 0);
    defer l.deinit(gpa);
    var an = analysisOver(gpa, a, io, &l, &diags);
    defer an.deinit();
    const stubs = try an.stubs();
    try std.testing.expectEqual(@as(usize, 5), stubs.stubs.len);
    try std.testing.expectEqual(@as(u32, 0), stubs.mismatches);
    const want = [_][]const u8{ "___snprintf_chk", "___stack_chk_fail", "_exit", "_puts", "_strcmp" };
    for (want, 0..) |n, i| {
        try std.testing.expectEqualStrings(n, stubs.stubs[i].symbol.?);
        // A named the stub and B confirmed it, so A is recorded as the resolver.
        try std.testing.expectEqual(symbolize.ResolvedBy.indirect_table, stubs.stubs[i].resolved_by);
        try std.testing.expect(!stubs.stubs[i].mismatch);
        try std.testing.expectEqual(@as(u8, 12), stubs.stubs[i].size);
        try std.testing.expectEqual(symbolize.StubKind.arm64_stubs, stubs.stubs[i].kind);
        try std.testing.expect(stubs.stubs[i].slot != null); // algorithm B found the GOT slot
    }
    try std.testing.expectEqual(@as(u64, 0x100000650), stubs.byName("_puts").?.addr);
    try std.testing.expectEqualStrings("_puts", stubs.at(0x100000650).?.symbol.?);
    try std.testing.expect(stubs.at(0x100000651) == null);
    try std.testing.expectEqualStrings("_puts", stubs.covering(0x100000654).?.symbol.?);
}

test "facts/disasm: legacy-bind resolves stubs through __la_symbol_ptr, hello-objc through selrefs" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 128);
    {
        const path = try helpers.fixturePath(a, "legacy-bind");
        var l = try load(gpa, a, io, &diags, path, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const stubs = try an.stubs();
        try std.testing.expect(stubs.stubs.len >= 2);
        try std.testing.expectEqual(@as(u32, 0), stubs.mismatches);
        const qsort = stubs.byName("_qsort") orelse return error.NoQsortStub;
        // The stub loads a __DATA,__la_symbol_ptr slot (the lazy pointer), not a __got slot.
        const slot_sect = l.img.sectionForVm(qsort.slot.?).?;
        try std.testing.expectEqualStrings("__la_symbol_ptr", slot_sect.sectname);
        try std.testing.expect(stubs.byName("_printf") != null);
    }
    {
        const path = try helpers.fixturePath(a, "hello-objc");
        var l = try load(gpa, a, io, &diags, path, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const stubs = try an.stubs();
        var objc_stubs: usize = 0;
        for (stubs.stubs) |s| if (s.kind == .objc_stubs) {
            objc_stubs += 1;
            try std.testing.expect(std.mem.startsWith(u8, s.symbol.?, "_objc_msgSend$"));
            try std.testing.expectEqual(@as(u8, 32), s.size);
        };
        try std.testing.expectEqual(@as(usize, 15), objc_stubs);
        try std.testing.expect(stubs.byName("_objc_msgSend$bark") != null);
        try std.testing.expect(stubs.byName("_objc_msgSend$stringWithFormat:") != null);
    }
}

test "facts/disasm: bin-ls arm64e auth stub 62 is _strcoll" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 512);
    const path = try helpers.fixturePath(a, "/bin/ls");
    var file = machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags) catch return error.SkipZigTest;
    defer file.deinit(gpa);
    var found = false;
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const img = try machre.Image.parse(a, file.sliceReader(i).?, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags);
        const sect = img.sectionByName("__TEXT", "__auth_stubs") orelse continue;
        found = true;
        var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
        defer an.deinit();
        const stubs = try an.stubs();
        try std.testing.expectEqual(@as(u32, 16), sect.reserved2);
        const s = stubs.at(sect.addr + 62 * 16) orelse return error.NoStub62;
        try std.testing.expectEqualStrings("_strcoll", s.symbol.?);
        try std.testing.expectEqual(symbolize.StubKind.arm64e_auth_stubs, s.kind);
        try std.testing.expectEqual(@as(u32, 0), stubs.mismatches);
    }
    if (!found) return error.SkipZigTest;
}

test "facts/disasm: an edited indirect symbol table makes algorithm B disagree (stub_mismatch)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const bytes = try helpers.readFixture(io, gpa, "hello-c");
    defer gpa.free(bytes);
    var diags = machre.Diagnostics.init(a, 64);
    const img0 = try machre.Image.parse(a, machre.Reader.init(bytes, 0), 0, 0, &machre.Limits.default, &diags);
    const syms0 = try machre.macho.symbols.parse(a, &img0, &machre.Limits.default, &diags);
    const dt = syms0.dysymtab.?;
    try std.testing.expect(dt.nindirectsyms >= 1);

    // Point the first indirect entry at a different symbol: algorithm A now names the wrong import
    // while algorithm B still follows the real GOT slot, so the stub must be flagged.
    const orig_index = syms0.indirect[0];
    var replacement: u32 = orig_index;
    for (syms0.indirect) |v| if (v != orig_index and v < syms0.symbols.len) {
        replacement = v;
        break;
    };
    try std.testing.expect(replacement != orig_index);
    std.mem.writeInt(u32, bytes[dt.indirectsymoff..][0..4], replacement, .little);

    var diags2 = machre.Diagnostics.init(a, 64);
    const img = try machre.Image.parse(a, machre.Reader.init(bytes, 0), 0, 0, &machre.Limits.default, &diags2);
    const syms = try machre.macho.symbols.parse(a, &img, &machre.Limits.default, &diags2);
    const chained = try machre.macho.dyld_chained.parse(a, &img, &machre.Limits.default, &diags2);
    const fix = try machre.macho.fixups.build(a, &img, if (chained) |*c| c else null, null, &machre.Limits.default, &diags2);
    const stubs = try symbolize.resolveStubs(a, &img, &syms, &fix, null, &machre.Limits.default, &diags2);
    try std.testing.expect(stubs.mismatches >= 1);
    try std.testing.expect(diags2.has(.symbolize, .stub_mismatch));
    var flagged: usize = 0;
    for (stubs.stubs) |s| if (s.mismatch) {
        flagged += 1;
        // B wins: the name is the one the pointer slot really binds.
        try std.testing.expectEqual(symbolize.ResolvedBy.pointer_slot, s.resolved_by);
    };
    try std.testing.expect(flagged >= 1);
}

// ---------------------------------------------------------------------------------------------
// listings and annotations
// ---------------------------------------------------------------------------------------------

test "facts/disasm: disasm --otool-compat diffs empty against otool -tV" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // hello-zig is excluded: WP7's documented SIMD spelling (see the file header).
    const fixtures = [_][]const u8{
        "hello-c",     "hello-objc",        "legacy-bind",    "libhello.dylib", "hello-usedylib",
        "hello-adhoc", "hello-entitled",    "hello-unsigned", "high-entropy",   "fake-packed",
        "fake-upx",    "hello-quarantined",
    };
    for (fixtures) |name| {
        const secs = try truth.load(a, io, name);
        const want = truth.find(secs, otool_tv) orelse {
            std.debug.print("truth section '{s}' missing from {s}.txt (regenerate with tests/corpus/gen/truth.sh)\n", .{ otool_tv, name });
            return error.TruthSectionMissing;
        };
        const path = try helpers.fixturePath(a, name);
        const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", path });
        truth.expectSameLines(want.body, got.out) catch |e| {
            std.debug.print("  -> disasm --otool-compat {s}\n", .{name});
            return e;
        };
    }
}

test "facts/disasm: the x86_64 listing matches otool when Capstone supplies the text" {
    if (!build_options.have_capstone) return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const secs = try truth.load(a, io, "hello-x86_64");
    const want = truth.find(secs, otool_tv) orelse return error.TruthSectionMissing;
    const path = try helpers.fixturePath(a, "hello-x86_64");
    const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", path });
    try truth.expectSameLines(want.body, got.out);
}

// ---------------------------------------------------------------------------------------------
// live `otool -tV` regression: the corpus fixtures are simple C programs, so an --otool-compat
// listing can be byte-exact on them and still diverge on real system binaries (SIMD arrangements,
// signed immediates, x86 immediate spelling). These tests run the real tool over real binaries.
// ---------------------------------------------------------------------------------------------

/// `otool -tV -arch <arch> <path>`; null when otool, the file or the slice is not there (the tests
/// then skip rather than fail, so the suite still runs on a host without the Xcode tools).
fn otoolListing(gpa: std.mem.Allocator, a: std.mem.Allocator, io: std.Io, arch: []const u8, path: []const u8) !?[]const u8 {
    std.Io.Dir.cwd().access(io, "/usr/bin/otool", .{}) catch return null;
    std.Io.Dir.cwd().access(io, path, .{}) catch return null;
    const res = std.process.run(gpa, io, .{ .argv = &.{ "/usr/bin/otool", "-tV", "-arch", arch, path } }) catch return null;
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    switch (res.term) {
        .exited => |c| if (c != 0) return null,
        else => return null,
    }
    // A slice otool cannot find yields a one-line error on stdout; a real listing has instructions.
    if (std.mem.find(u8, res.stdout, "(__TEXT,__text) section") == null) return null;
    return try a.dupe(u8, res.stdout);
}

const Row = struct { mnemonic: []const u8, text: []const u8 };

/// `<16 hex>\tmnemonic[\toperands]` lines, keyed by address; labels and banners are skipped.
fn listingRows(a: std.mem.Allocator, text: []const u8) !std.AutoHashMapUnmanaged(u64, Row) {
    var out: std.AutoHashMapUnmanaged(u64, Row) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len < 18 or line[16] != '\t') continue;
        const addr = std.fmt.parseInt(u64, line[0..16], 16) catch continue;
        const rest = line[17..];
        const mnem = rest[0 .. std.mem.findScalar(u8, rest, '\t') orelse rest.len];
        try out.put(a, addr, .{ .mnemonic = mnem, .text = rest });
    }
    return out;
}

/// Every `$`/`#` immediate replaced by one sentinel byte, so two lines that differ ONLY in how an
/// immediate is spelled compare equal (`mov x9, #0x88..` vs `mov x9, #-0x77..`).
fn blankImmediates(a: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var k: usize = 0;
    while (k < text.len) {
        const c = text[k];
        if (c != '$' and c != '#') {
            try out.append(a, c);
            k += 1;
            continue;
        }
        var j = k + 1;
        if (j < text.len and text[j] == '-') j += 1;
        if (j + 1 < text.len and text[j] == '0' and (text[j + 1] == 'x' or text[j + 1] == 'X')) j += 2;
        const digits = j;
        while (j < text.len and std.ascii.isHex(text[j])) j += 1;
        if (j == digits) { // a bare '#' (comment marker) is not an immediate
            try out.append(a, c);
            k += 1;
            continue;
        }
        try out.append(a, 1);
        k = j;
    }
    return out.toOwnedSlice(a);
}

/// True for a Darwin vector mnemonic (`movi.2d`, `ld1.h`, `mov.d`) but not for `b.ne` and friends.
fn hasVectorSuffix(mnemonic: []const u8) bool {
    if (std.mem.startsWith(u8, mnemonic, "b.")) return false;
    const dot = std.mem.lastIndexOfScalar(u8, mnemonic, '.') orelse return false;
    if (dot == 0) return false; // `.inst` / `.long` / `.byte`
    const tail = mnemonic[dot + 1 ..];
    if (tail.len == 0) return false;
    for (tail[0 .. tail.len - 1]) |ch| if (!std.ascii.isDigit(ch)) return false;
    return switch (tail[tail.len - 1]) {
        'b', 'h', 's', 'd', 'q' => true,
        else => false,
    };
}

/// Pseudo-mnemonics that mean "this is data / an encoding the decoder does not model": otool and
/// machre legitimately disagree there (machre emits `.long` for the /bin/ls jump tables that otool
/// mis-decodes as instructions, and `.inst` for SIMD encodings the built-in decoder has no name for).
fn isDataPseudo(mnemonic: []const u8) bool {
    return std.mem.eql(u8, mnemonic, ".inst") or std.mem.eql(u8, mnemonic, ".long") or
        std.mem.eql(u8, mnemonic, "db") or std.mem.startsWith(u8, mnemonic, ".byte");
}

/// Counts the three defect classes over the addresses both listings decoded: an immediate spelled
/// differently, a vector arrangement otool hoists onto the mnemonic, and a `## imm = ...` note on
/// one side only. Anything else (Capstone-vs-LLVM spelling, symbolisation) is out of scope here.
fn countSpellingDefects(a: std.mem.Allocator, machre_out: []const u8, otool_out: []const u8, label: []const u8) !usize {
    var mine = try listingRows(a, machre_out);
    var theirs = try listingRows(a, otool_out);
    var bad: usize = 0;
    var it = theirs.iterator();
    while (it.next()) |e| {
        const them = e.value_ptr.*;
        const us = mine.get(e.key_ptr.*) orelse continue;
        if (std.mem.eql(u8, us.text, them.text)) continue;
        if (isDataPseudo(us.mnemonic) or isDataPseudo(them.mnemonic)) continue;
        const kind: ?[]const u8 = blk: {
            if (std.mem.eql(u8, try blankImmediates(a, us.text), try blankImmediates(a, them.text))) break :blk "immediate";
            if (hasVectorSuffix(them.mnemonic) and !std.mem.eql(u8, us.mnemonic, them.mnemonic)) break :blk "vector suffix";
            const ours_note = std.mem.find(u8, us.text, "## imm = ") != null;
            const theirs_note = std.mem.find(u8, them.text, "## imm = ") != null;
            if (ours_note != theirs_note) break :blk "imm note";
            break :blk null;
        };
        if (kind) |k| {
            bad += 1;
            if (bad <= 5)
                std.debug.print("  {s} 0x{x} [{s}]\n    machre: {s}\n    otool : {s}\n", .{ label, e.key_ptr.*, k, us.text, them.text });
        }
    }
    return bad;
}

test "facts/disasm: --otool-compat is byte-exact on the arm64e slices of /bin/ls and /bin/date" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Both carry the encodings the corpus fixtures do not: `movi.2d`/`dup.2d`/`sub.2d` (Darwin's
    // arrangement suffix) and ORR-bitmask MOV immediates otool prints signed.
    const targets = [_][]const u8{ "/bin/ls", "/bin/date" };
    var ran: usize = 0;
    for (targets) |path| {
        const want = (try otoolListing(gpa, a, io, "arm64e", path)) orelse continue;
        const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", "--limit", "0", "--arch", "arm64e", try helpers.fixturePath(a, path) });
        if (got.code != 0) continue;
        ran += 1;
        truth.expectSameLines(want, got.out) catch |e| {
            std.debug.print("  -> disasm --otool-compat --arch arm64e {s}\n", .{path});
            return e;
        };
    }
    if (ran == 0) return error.SkipZigTest;
}

test "facts/disasm: --otool-compat spells SIMD, signed immediates and x86 immediates like otool" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const Target = struct { path: []const u8, arch: [:0]const u8 };
    const targets = [_]Target{
        .{ .path = "/bin/ls", .arch = "arm64e" },
        .{ .path = "/bin/date", .arch = "arm64e" },
        .{ .path = "/bin/cat", .arch = "arm64e" },
        .{ .path = "/usr/bin/plutil", .arch = "arm64e" },
        .{ .path = "/bin/ls", .arch = "x86_64" },
        .{ .path = "/bin/date", .arch = "x86_64" },
        .{ .path = "/bin/cat", .arch = "x86_64" },
        .{ .path = "/usr/bin/plutil", .arch = "x86_64" },
    };
    var ran: usize = 0;
    var bad: usize = 0;
    for (targets) |t| {
        const x86 = std.mem.eql(u8, t.arch, "x86_64");
        // Without Capstone the x86 text is the built-in length decoder's, which is deliberately not
        // otool-compatible (x86len.zig header); the arm64 checks still run.
        if (x86 and !build_options.have_capstone) continue;
        const want = (try otoolListing(gpa, a, io, t.arch, t.path)) orelse continue;
        const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", "--limit", "0", "--arch", t.arch, try helpers.fixturePath(a, t.path) });
        if (got.code != 0) continue;
        ran += 1;
        var lbuf: [64]u8 = undefined;
        bad += try countSpellingDefects(a, got.out, want, try std.fmt.bufPrint(&lbuf, "{s} {s}", .{ t.path, t.arch }));
    }
    if (ran == 0) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "facts/disasm: hello-c _main is the 58-instruction listing of DESIGN 5.4" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const path = try helpers.fixturePath(a, "hello-c");
    var l = try load(gpa, a, io, &diags, path, 0);
    defer l.deinit(gpa);
    var an = analysisOver(gpa, a, io, &l, &diags);
    defer an.deinit();
    var e = try engine_mod.Engine.init(l.img.arch.name, .{ .backend = .builtin_arm64 });
    defer e.deinit();
    const funcs = try an.functions();
    const main = funcs.byName("_main").?;
    const ctx: symbolize.AnnotateCtx = .{
        .img = &l.img,
        .syms = try an.symbols(),
        .index = try an.addressIndex(),
        .fix = try an.fixups(),
        .stubs = try an.stubs(),
        .funcs = funcs,
        .objc = null,
        .strings = null,
    };
    const listing = try engine_mod.disassembleFunction(a, &e, &l.img, main, ctx, &machre.Limits.default, &diags);
    try std.testing.expectEqual(@as(usize, 58), listing.insns.len);
    try std.testing.expectEqual(@as(u64, 0x100000524), listing.start);
    try std.testing.expectEqual(@as(u64, 0x10000060c), listing.end);
    try std.testing.expect(!listing.partial);
    var comments: usize = 0;
    for (listing.comments) |c| if (c != null) {
        comments += 1;
    };
    // 5 adrp pages + 2 GOT symbols + 2 literal pools + 5 stubs + 2 direct calls + 1 pointer follow
    try std.testing.expectEqual(@as(usize, 17), comments);
    // the machre-only one-level pointer follow of DESIGN 5.4
    var found_greeting = false;
    for (listing.insns, 0..) |i, idx| {
        if (i.addr != 0x100000554) continue;
        found_greeting = true;
        try std.testing.expectEqualStrings("_greeting -> 0x100000668 \"hello from machre corpus\"", listing.comments[idx].?);
        try std.testing.expectEqual(symbolize.AnnKind.pointer, symbolize.commentKind(listing.comments[idx].?));
    }
    try std.testing.expect(found_greeting);
    try std.testing.expectEqualStrings("_main", listing.labels[0].?);
}

test "facts/disasm: the x86_64 inline jump table of /bin/ls survives and the decoder resyncs" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch return error.SkipZigTest;
    const got = try helpers.runMachre(a, io, &.{ "disasm", "--arch", "x86_64", "--section=__TEXT,__text", "--all", "--limit", "0", "/bin/ls" });
    if (got.code != 0) return error.SkipZigTest;
    // The 92-entry switch table at 0x1000014b0 is emitted as .long data ...
    try std.testing.expect(std.mem.find(u8, got.out, "\n00000001000014b0\t.long\t") != null);
    try std.testing.expect(std.mem.find(u8, got.out, "\n000000010000161c\t.long\t") != null);
    // ... and real instructions resume exactly at 0x100001620 (otool never resyncs here).
    const resync = std.mem.find(u8, got.out, "\n0000000100001620\t") orelse return error.NoResync;
    try std.testing.expect(std.mem.find(u8, got.out[resync + 1 ..][0..40], ".long") == null);
}

test "facts/disasm: the arm64 inline data table in dyld is marked, and real code around it is not" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    std.Io.Dir.cwd().access(io, "/usr/lib/dyld", .{}) catch return error.SkipZigTest;
    const got = try helpers.runMachre(a, io, &.{ "disasm", "--arch", "arm64e", "--section=__TEXT,__text", "--limit", "0", "/usr/lib/dyld" });
    if (got.code != 0) return error.SkipZigTest;

    // dyld inlines a 16-byte NEON permute table (00 01 .. 0f) at 0x1e20, named by `adr x3, #0x1e20`
    // from two sites and unreachable by fall-through (four `udf` traps precede it).
    try std.testing.expect(std.mem.find(u8, got.out, "\n0000000000001e20\t.long\t0x03020100") != null);
    try std.testing.expect(std.mem.find(u8, got.out, "\n0000000000001e24\t.long\t0x07060504") != null);
    try std.testing.expect(std.mem.find(u8, got.out, "\n0000000000001e2c\t.long\t0x0f0e0d0c") != null);
    // The third word is the point of the whole pass: 0x0b0a0908 is a valid encoding and otool prints
    // it as `add w8, w8, w10, lsl #2`. It is data, and must not be rendered as an instruction.
    try std.testing.expect(std.mem.find(u8, got.out, "\n0000000000001e28\t.long\t0x0b0a0908") != null);

    // Trailing trap padding is NOT swallowed into the run.
    try std.testing.expect(std.mem.find(u8, got.out, "\n0000000000001e30\tudf") != null);

    // Regression guard for a trigger that was tried and removed: dyld contains a SHA-256 routine the
    // built-in decoder cannot name, and an earlier "long run of unnameable words is data" rule
    // mislabelled ~52 words of it. Decoder ignorance is not evidence of data — these must stay code.
    var i: usize = 0;
    var long_words: usize = 0;
    while (std.mem.findPos(u8, got.out, i, "\t.long\t")) |at| : (i = at + 1) long_words += 1;
    // 7 copies of the 4-word table, and nothing else in the whole section.
    try std.testing.expectEqual(@as(usize, 28), long_words);
}

// ---------------------------------------------------------------------------------------------
// xrefs
// ---------------------------------------------------------------------------------------------

test "facts/disasm: xrefs --to=_puts finds the call through the stub" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "hello-c");
    const got = try helpers.runMachre(a, io, &.{ "xrefs", "--to=_puts", path });
    try std.testing.expectEqual(@as(u8, 0), got.code);
    var it = std.mem.splitScalar(u8, got.out, '\n');
    var hit = false;
    while (it.next()) |line| {
        if (std.mem.find(u8, line, "0x100000588") == null) continue;
        try std.testing.expect(std.mem.find(u8, line, "call") != null);
        try std.testing.expect(std.mem.find(u8, line, "(via stub)") != null);
        try std.testing.expect(std.mem.find(u8, line, "_main") != null);
        hit = true;
    }
    try std.testing.expect(hit);
}

test "facts/disasm: legacy-bind reports pointer_slot xrefs for its function-pointer table" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "legacy-bind");
    const with = try helpers.runMachre(a, io, &.{ "xrefs", path });
    try std.testing.expectEqual(@as(u8, 0), with.code);
    var slots: usize = 0;
    var it = std.mem.splitScalar(u8, with.out, '\n');
    while (it.next()) |line| if (std.mem.find(u8, line, "pointer_slot") != null) {
        slots += 1;
    };
    try std.testing.expect(slots >= 4);
    try std.testing.expect(std.mem.find(u8, with.out, "_cmp_int") != null);
    // --no-pointer-slots removes exactly those rows.
    const without = try helpers.runMachre(a, io, &.{ "xrefs", "--no-pointer-slots", path });
    try std.testing.expect(std.mem.find(u8, without.out, "pointer_slot") == null);
}

test "facts/disasm: the xref table is sorted and reachable from both directions" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 128);
    const path = try helpers.fixturePath(a, "hello-c");
    var l = try load(gpa, a, io, &diags, path, 0);
    defer l.deinit(gpa);
    var an = analysisOver(gpa, a, io, &l, &diags);
    defer an.deinit();
    var e = try engine_mod.Engine.init(l.img.arch.name, .{ .backend = .builtin_arm64, .annotate = false });
    defer e.deinit();
    const funcs = try an.functions();
    const ctx: symbolize.AnnotateCtx = .{
        .img = &l.img,
        .syms = try an.symbols(),
        .index = try an.addressIndex(),
        .fix = try an.fixups(),
        .stubs = try an.stubs(),
        .funcs = funcs,
        .objc = null,
        .strings = null,
    };
    var listings: std.ArrayList(insn_mod.Listing) = .empty;
    for (funcs.functions) |*f| try listings.append(a, try engine_mod.disassembleFunction(a, &e, &l.img, f, ctx, &machre.Limits.default, &diags));
    const t = try symbolize.buildXrefs(a, listings.items, ctx, .{}, &machre.Limits.default);
    try std.testing.expect(t.by_to.len == t.by_from.len and t.by_to.len > 0);
    for (t.by_to[1..], 0..) |x, i| try std.testing.expect(t.by_to[i].to <= x.to);
    for (t.by_from[1..], 0..) |x, i| try std.testing.expect(t.by_from[i].from <= x.from);
    // the call to the _puts stub, found by address
    const puts_stub = (try an.stubs()).byName("_puts").?;
    const to_puts = t.to(puts_stub.addr);
    try std.testing.expectEqual(@as(usize, 1), to_puts.len);
    try std.testing.expectEqual(@as(u64, 0x100000588), to_puts[0].from);
    try std.testing.expect(to_puts[0].via_stub);
    try std.testing.expectEqual(symbolize.XrefKind.call, to_puts[0].kind);
    // and the same xref seen from the calling side
    const from_call = t.from(0x100000588);
    try std.testing.expectEqual(@as(usize, 1), from_call.len);
    try std.testing.expectEqual(puts_stub.addr, from_call[0].to);
    // the "%s (%d args)" literal is a string_ref
    var strings: usize = 0;
    for (t.by_to) |x| if (x.kind == .string_ref) {
        strings += 1;
    };
    try std.testing.expect(strings >= 2);
}

// ---------------------------------------------------------------------------------------------
// engine / CLI behaviour
// ---------------------------------------------------------------------------------------------

test "facts/disasm: --backend=capstone without Capstone exits 6, with Capstone agrees on boundaries" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "hello-c");
    const res = try helpers.runMachre(a, io, &.{ "disasm", "--func", "_main", "--backend=capstone", path });
    if (!build_options.have_capstone) {
        try std.testing.expectEqual(@as(u8, 6), res.code);
        return;
    }
    try std.testing.expectEqual(@as(u8, 0), res.code);
    // Capstone text, built-in boundaries: the same 58 addresses as --backend=builtin.
    const builtin = try helpers.runMachre(a, io, &.{ "disasm", "--func", "_main", "--backend=builtin", path });
    var ci = std.mem.splitScalar(u8, res.out, '\n');
    var bi = std.mem.splitScalar(u8, builtin.out, '\n');
    var lines: usize = 0;
    while (ci.next()) |c| {
        const b = bi.next() orelse break;
        if (c.len < 16 or b.len < 16) continue;
        if (!std.ascii.isHex(c[0])) continue;
        try std.testing.expectEqualStrings(b[0..16], c[0..16]); // identical addresses
        lines += 1;
    }
    try std.testing.expectEqual(@as(usize, 58), lines);
}

test "facts/disasm: JSON payload carries the DESIGN 6.3 keys" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "hello-c");
    const res = try helpers.runMachre(a, io, &.{ "disasm", "--func", "_main", "--json", path });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
    defer parsed.deinit();
    const arch0 = parsed.value.object.get("arches").?.array.items[0];
    const d = arch0.object.get("disasm").?.object;
    try std.testing.expect(d.get("backend") != null);
    try std.testing.expect(d.get("text_backend") != null);
    try std.testing.expect(d.get("syntax") != null);
    try std.testing.expect(d.get("partial").?.bool == false);
    try std.testing.expect(d.get("disagreements") != null);
    try std.testing.expect(d.get("truncated") != null);
    const fns = d.get("functions").?.array;
    try std.testing.expectEqual(@as(usize, 1), fns.items.len);
    const f0 = fns.items[0].object;
    try std.testing.expectEqualStrings("_main", f0.get("name").?.string);
    try std.testing.expectEqualStrings("0x100000524", f0.get("start").?.string);
    const ins = f0.get("instructions").?.array;
    try std.testing.expectEqual(@as(usize, 58), ins.items.len);
    const first = ins.items[0].object;
    for ([_][]const u8{ "address", "size", "bytes", "mnemonic", "operands", "kind", "target", "comment", "comment_kind", "label" }) |k|
        try std.testing.expect(first.get(k) != null);
    try std.testing.expectEqualStrings("_main", first.get("label").?.string);
}

test "facts/disasm: functions and xrefs JSON key inventories" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "hello-c");
    {
        const res = try helpers.runMachre(a, io, &.{ "functions", "--json", path });
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer parsed.deinit();
        const arr = parsed.value.object.get("arches").?.array.items[0].object.get("functions").?.array;
        try std.testing.expectEqual(@as(usize, 3), arr.items.len);
        for ([_][]const u8{ "name", "start", "end", "size", "source", "name_source", "section" }) |k|
            try std.testing.expect(arr.items[0].object.get(k) != null);
    }
    {
        const res = try helpers.runMachre(a, io, &.{ "xrefs", "--json", path });
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer parsed.deinit();
        const arch0 = parsed.value.object.get("arches").?.array.items[0].object;
        try std.testing.expect(arch0.get("pointer_slots_included").?.bool);
        const arr = arch0.get("xrefs").?.array;
        try std.testing.expect(arr.items.len > 0);
        for ([_][]const u8{ "from", "from_function", "to", "to_name", "kind", "via_stub" }) |k|
            try std.testing.expect(arr.items[0].object.get(k) != null);
    }
}

// ---------------------------------------------------------------------------------------------
// --otool-compat is a TEXT contract (DESIGN §5.2 / §5.6)
// ---------------------------------------------------------------------------------------------

test "facts/disasm: --otool-compat does not change the JSON payload" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // `--otool-compat` makes machre's RENDERED LINES match an Apple tool. JSON has no Apple tool to
    // diff against, and the flag changes nothing in the JSON of the other twenty-two commands. It used
    // to change `disasm`'s: it forced the built-in arm64 text backend (engine.zig:60) and put the
    // annotator into otool-reproduction mode, so a JSON consumer got different `mnemonic`/`operands`/
    // `kind` values and otool's deliberately-wrong `Objc class ref: bad class ref` instead of the
    // resolved class name. The flag is now dropped at the JSON boundary; `--backend` still works.
    for ([_][]const u8{ "hello-c", "hello-objc", "legacy-bind", "hello-usedylib", "hello-x86_64" }) |name| {
        const path = try helpers.fixturePath(a, name);
        const plain = try helpers.runMachre(a, io, &.{ "disasm", "--all", "--json", path });
        const compat = try helpers.runMachre(a, io, &.{ "disasm", "--all", "--json", "--otool-compat", path });
        try std.testing.expectEqual(plain.code, compat.code);
        std.testing.expectEqualStrings(plain.out, compat.out) catch |e| {
            std.debug.print("  -> disasm --json --otool-compat {s} differs from disasm --json\n", .{name});
            return e;
        };
    }
    // ... and the text channel still switches, which is the whole point of the flag.
    const path = try helpers.fixturePath(a, "hello-objc");
    const t_plain = try helpers.runMachre(a, io, &.{ "disasm", path });
    const t_compat = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", path });
    try std.testing.expect(!std.mem.eql(u8, t_plain.out, t_compat.out));
}

// ---------------------------------------------------------------------------------------------
// one address, several symbols: the label and the branch operand must name the same one
// ---------------------------------------------------------------------------------------------

/// Writes `bytes` into a fresh temp dir and returns the absolute path; caller cleans the dir up.
fn writeTempFixture(arena: std.mem.Allocator, io: std.Io, tmp: *std.testing.TmpDir, name: []const u8, bytes: []const u8) ![:0]const u8 {
    {
        var f = try tmp.dir.createFile(io, name, .{});
        defer f.close(io);
        var wbuf: [8192]u8 = undefined;
        var w = f.writer(io, &wbuf);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
    }
    const real = try tmp.dir.realPathFileAlloc(io, name, arena);
    return arena.dupeSentinel(u8, real, 0);
}

/// `hello-c` with the LOCAL symbol `_static_helper` moved on top of the EXTERNAL `_add_numbers`
/// (0x1000004f8), which `_main` calls. `_static_helper` is nlist index 0 and `_add_numbers` index 2,
/// so the local is seen FIRST — the exact shape that made machre's two name lookups disagree.
fn aliasedHelloC(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const buf = try helpers.readFixture(io, gpa, "hello-c");
    errdefer gpa.free(buf);
    var needle: [8]u8 = undefined;
    var repl: [8]u8 = undefined;
    std.mem.writeInt(u64, &needle, 0x10000060c, .little); // _static_helper's n_value
    std.mem.writeInt(u64, &repl, 0x1000004f8, .little); // _add_numbers' n_value
    const i = std.mem.find(u8, buf, &needle) orelse return error.FixtureLayoutChanged;
    @memcpy(buf[i..][0..8], &repl);
    return buf;
}

test "facts/disasm: at a multi-symbol address the label and the branch operand name one symbol" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 256);

    const bytes = try aliasedHelloC(gpa, io);
    defer gpa.free(bytes);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try writeTempFixture(a, io, &tmp, "aliased-hello-c", bytes);

    // The two lookups machre uses for the same address are `FunctionTable.byStart` (which names the
    // LABEL, from disasm/functions.zig's `noteName`) and `AddressIndex.at` (which names a BRANCH
    // OPERAND under --otool-compat, via symbolize.symbolAt). They must have the same tie-break rule:
    // external wins, else first in symtab order. `noteName` used to test `cur.name[0] != '_'` where it
    // meant the incumbent's externality, so a `_`-prefixed local listed first kept the address here.
    {
        var l = try load(gpa, a, io, &diags, path, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const syms = try an.symbols();
        const index = try an.addressIndex();
        const funcs = try an.functions();
        try std.testing.expectEqualStrings("_add_numbers", index.at(syms, 0x1000004f8).?.name);
        try std.testing.expectEqualStrings("_add_numbers", funcs.byStart(0x1000004f8).?.name);
        // and the rule agrees at every function start of every healthy fixture, not just this one.
        for (funcs.functions) |*f| {
            const s = index.at(syms, f.start) orelse continue;
            if (s.name.len == 0 or f.name_source != .symbol) continue;
            std.testing.expectEqualStrings(s.name, f.name) catch |e| {
                std.debug.print("  -> 0x{x}: label '{s}' vs operand '{s}'\n", .{ f.start, f.name, s.name });
                return e;
            };
        }
    }
    // End to end: the label line and the `bl` line must agree, and agree with otool.
    const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", path });
    try std.testing.expect(std.mem.find(u8, got.out, "\n_add_numbers:\n") != null);
    try std.testing.expect(std.mem.find(u8, got.out, "bl\t_add_numbers\n") != null);
    try std.testing.expect(std.mem.find(u8, got.out, "_static_helper:") == null);

    // The same invariant over the unmodified corpus (no collisions there, so this pins that the two
    // paths stay consistent as the fixtures change).
    for ([_][]const u8{ "hello-c", "hello-objc", "legacy-bind", "libhello.dylib", "hello-usedylib", "hello-zig" }) |name| {
        const p = try helpers.fixturePath(a, name);
        var l = try load(gpa, a, io, &diags, p, 0);
        defer l.deinit(gpa);
        var an = analysisOver(gpa, a, io, &l, &diags);
        defer an.deinit();
        const syms = try an.symbols();
        const index = try an.addressIndex();
        const funcs = try an.functions();
        for (funcs.functions) |*f| {
            const s = index.at(syms, f.start) orelse continue;
            if (s.name.len == 0 or f.name_source != .symbol) continue;
            std.testing.expectEqualStrings(s.name, f.name) catch |e| {
                std.debug.print("  -> {s} 0x{x}: label '{s}' vs operand '{s}'\n", .{ name, f.start, f.name, s.name });
                return e;
            };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// a stale register base must never become a symbol attribution
// ---------------------------------------------------------------------------------------------

/// `hello-usedylib` with the two words at 0x100000524 replaced, so that an `adrp x9` is followed by an
/// instruction that clobbers x9 in a way a single-`?u5` write model misses, and then by the original
/// `ldr x9, [x9, #0x8]`. `pattern` is the second word. The first is always `adrp x9, 4`.
fn staleBaseFixture(gpa: std.mem.Allocator, io: std.Io, second: u32) ![]u8 {
    const buf = try helpers.readFixture(io, gpa, "hello-usedylib");
    errdefer gpa.free(buf);
    // add w8, w0, w8 ; adrp x9, 4  — the 8 bytes at 0x100000524, unique in the file.
    const needle = [_]u8{ 0x08, 0x00, 0x08, 0x0b, 0x29, 0x00, 0x00, 0x90 };
    const i = std.mem.find(u8, buf, &needle) orelse return error.FixtureLayoutChanged;
    std.mem.writeInt(u32, buf[i..][0..4], 0x90000029, .little); // adrp x9, 4
    std.mem.writeInt(u32, buf[i + 4 ..][0..4], second, .little);
    return buf;
}

test "facts/disasm: a clobbered or branched-over adrp base produces no symbol attribution" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // This is the /usr/libexec/relatived:0x100002f40 defect in miniature. There machre printed
    //   ldr x8, [x8, #0x8] ; literal pool symbol address: _CVAFaceTrackingCreate
    // on what is a vtable walk, because the preceding `ldp x21, x8, [x20, #0x20]` reported only x21 as
    // written, so x8 was still believed to hold the `adrp` page from two instructions earlier. A WRONG
    // symbol attribution is worse for an analyst than none, so both shapes must annotate nothing.
    const cases = [_]struct { name: []const u8, word: u32, note: []const u8 }{
        // ldp x10, x9, [x20] — Rt2 is x9. Reported as a write only since `reg_writes`.
        .{ .name = "stale-ldp", .word = 0xa940268a, .note = "LDP Rt2" },
        // ldr x10, [x9, #0x10]! — pre-index writes the BASE x9 back.
        .{ .name = "stale-writeback", .word = 0xf841_0d2a, .note = "writeback base" },
        // b 0x100000540 — control leaves the block; 0x10000052c is not a branch target of this listing,
        // so only the fail-closed rule can drop the page.
        .{ .name = "stale-branch", .word = 0x14000006, .note = "unconditional branch" },
    };
    for (cases) |c| {
        const bytes = try staleBaseFixture(gpa, io, c.word);
        defer gpa.free(bytes);
        const path = try writeTempFixture(a, io, &tmp, c.name, bytes);
        const got = try helpers.runMachre(a, io, &.{ "disasm", "--otool-compat", path });
        // the adrp itself still annotates its page, and the later true positive survives ...
        try std.testing.expect(std.mem.find(u8, got.out, "adrp\tx9, 4 ; 0x100004000") != null);
        try std.testing.expect(std.mem.find(u8, got.out, "literal pool for: \"from use_dylib\"") != null);
        // ... but nothing may be claimed about x9 after it was clobbered or branched over.
        std.testing.expect(std.mem.find(u8, got.out, "ldr\tx9, [x9, #0x8] ; ") == null) catch |e| {
            std.debug.print("  -> {s} ({s}): a stale base still produced an attribution\n", .{ c.name, c.note });
            return e;
        };
    }
}
