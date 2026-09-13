//! tests/golden/core.rows.zig — golden rows and text snapshots for the core commands
//! (`info`/`header`/`loadcmds`/`segments`/`dump`). Owned by WP1; imported by tests/golden_tests.zig.
//!
//! Three layers:
//!  1. `rows` — the `--otool-compat` parity rows (machre text vs the `otool` sections of truth/<fixture>.txt)
//!     and the §6.3 JSON key inventory, both run by the WP0 table runner.
//!  2. `test "golden: core text snapshots"` — byte-exact comparison against tests/golden/<fixture>.<cmd>.txt
//!     with the corpus directory normalised to "tests/corpus" so the files are machine-independent.
//!     `info` also depends on WP2/WP3/WP4; while those are stubs the runner tolerates exactly the lines
//!     they feed (entry symbol, dyld data counts, symbols, signature, security, quarantine, diagnostics)
//!     and compares every other line byte for byte. Once the stubs are gone the whole file must match.
//!  3. `/bin/ls` parity for BOTH slices, diffed against `otool` run as a subprocess (truth/bin-ls.txt only
//!     carries the host slice), plus the per-slice load-command facts of the WP1 acceptance criteria.
const std = @import("std");
const build_options = @import("build_options");
const golden = @import("../golden_tests.zig");
const helpers = golden.helpers;
const truth = golden.truth;

const otool_hv = "/usr/bin/otool -hv";
const otool_hl = "/usr/bin/otool -h -l";

fn compatRows(comptime fixture: []const u8, comptime extra: []const []const u8) [2]golden.Row {
    const h = [_][]const u8{ "header", "--otool-compat" } ++ extra[0..extra.len].*;
    const l = [_][]const u8{ "loadcmds", "--otool-compat" } ++ extra[0..extra.len].*;
    return .{
        .{ .fixture = fixture, .argv = &h, .truth_cmd = otool_hv, .compare = .same_lines },
        .{ .fixture = fixture, .argv = &l, .truth_cmd = otool_hl, .compare = .same_lines },
    };
}

/// §6.3 `info` keys that exist whether or not WP2/WP3/WP4 have landed (absent features are
/// `{"available":false}` objects, absent data is JSON `null`; both keep the key).
const info_keys: []const []const u8 = &.{
    "info.header.magic",         "info.header.magic_name",   "info.header.cputype",   "info.header.cputype_name",
    "info.header.cpusubtype",    "info.header.cpusubtype_low", "info.header.caps",    "info.header.filetype",
    "info.header.filetype_name", "info.header.ncmds",        "info.header.sizeofcmds", "info.header.flags.value",
    "info.header.flags.names",   "info.uuid",                "info.build_version",    "info.version_min",
    "info.source_version",       "info.dylinker",            "info.entry",            "info.dyld.style",
    "info.dyld.pointer_formats", "info.dyld.imports",        "info.dyld.fixups",      "info.dyld.exports",
    "info.dyld.function_starts", "info.dylibs",              "info.id_dylib",         "info.rpaths",
    "info.segments.0.name",      "info.segments.0.vmaddr",   "info.segments.0.vmsize", "info.segments.0.fileoff",
    "info.segments.0.filesize",  "info.segments.0.maxprot",  "info.segments.0.initprot", "info.segments.0.nsects",
    "info.segments.0.flags.names", "info.segments.0.entropy", "info.segments.0.file_fraction",
    "info.symtab",               "info.symbols",             "info.code_signature.present",
    "info.security.available",   "info.encryption",
};
const seg_keys: []const []const u8 = &.{
    "segments.0.name",                    "segments.0.vmaddr",                "segments.0.flags.names",
    "segments.0.entropy",                 "segments.0.file_fraction",         "segments.0.section_count",
    "segments.1.sections.0.index",        "segments.1.sections.0.sectname",   "segments.1.sections.0.segname",
    "segments.1.sections.0.addr",         "segments.1.sections.0.size",       "segments.1.sections.0.offset",
    "segments.1.sections.0.align",        "segments.1.sections.0.reloff",     "segments.1.sections.0.nreloc",
    "segments.1.sections.0.flags.value",  "segments.1.sections.0.flags.type", "segments.1.sections.0.flags.type_name",
    "segments.1.sections.0.flags.attrs",  "segments.1.sections.0.reserved1",  "segments.1.sections.0.reserved2",
    "segments.1.sections.0.reserved3",    "segments.1.sections.0.class",      "segments.1.sections.0.entropy",
    "entropy",
};
const loadcmds_keys: []const []const u8 = &.{
    "loadcmds.ncmds_parsed",        "loadcmds.truncated",           "loadcmds.load_commands.0.index",
    "loadcmds.load_commands.0.cmd", "loadcmds.load_commands.0.cmd_value", "loadcmds.load_commands.0.cmdsize",
    "loadcmds.load_commands.0.offset", "loadcmds.load_commands.0.requires_dyld",
    "loadcmds.load_commands.1.sections.0.sectname",
};
const dump_keys: []const []const u8 = &.{ "dump.segment", "dump.section", "dump.address", "dump.offset", "dump.length", "dump.hex", "dump.ascii" };
const header_keys: []const []const u8 = &.{ "header.header.magic", "header.header.cputype_name", "header.header.is_64", "header.header.endian", "header.fat" };

/// One `--json` key-inventory row per command for `fixture`.
fn jsonRows(comptime fixture: []const u8) [5]golden.Row {
    return .{
        .{ .fixture = fixture, .argv = &.{ "info", "--json" }, .compare = .json_keys, .json_keys = info_keys },
        .{ .fixture = fixture, .argv = &.{ "header", "--json" }, .compare = .json_keys, .json_keys = header_keys },
        .{ .fixture = fixture, .argv = &.{ "loadcmds", "--json" }, .compare = .json_keys, .json_keys = loadcmds_keys },
        .{ .fixture = fixture, .argv = &.{ "segments", "--json", "--entropy" }, .compare = .json_keys, .json_keys = seg_keys },
        .{ .fixture = fixture, .argv = &.{ "dump", "--json", "--section=__TEXT,__text" }, .compare = .json_keys, .json_keys = dump_keys },
    };
}

pub const rows: []const golden.Row = &(compatRows("hello-c", &.{}) ++
    compatRows("hello-x86_64", &.{}) ++
    compatRows("hello-fat", &.{"--all-archs"}) ++
    compatRows("hello-objc", &.{}) ++
    compatRows("libhello.dylib", &.{}) ++
    compatRows("hello-usedylib", &.{}) ++
    compatRows("hello-adhoc", &.{}) ++
    compatRows("hello-entitled", &.{}) ++
    compatRows("hello-unsigned", &.{}) ++
    compatRows("high-entropy", &.{}) ++
    compatRows("fake-packed", &.{}) ++
    compatRows("fake-upx", &.{}) ++
    compatRows("hello-zig", &.{}) ++
    compatRows("legacy-bind", &.{}) ++
    compatRows("hello-quarantined", &.{}) ++
    compatRows("Hello.app", &.{}) ++
    compatRows("bin-ls", &.{ "--arch", "arm64e" }) ++
    jsonRows("hello-c") ++
    jsonRows("hello-objc") ++
    jsonRows("legacy-bind") ++
    jsonRows("libhello.dylib") ++
    jsonRows("hello-fat") ++
    [_]golden.Row{
        .{ .fixture = "hello-c", .argv = &.{ "dump", "--json", "--section=__TEXT,__cstring" }, .compare = .json_keys, .json_keys = dump_keys },
        .{ .fixture = "hello-fat", .argv = &.{ "header", "--json", "--all-archs" }, .compare = .json_keys, .json_keys = &.{ "header.fat.nfat_arch", "header.fat.slices" } },
        .{ .fixture = "libhello.dylib", .argv = &.{ "info", "--json" }, .compare = .json_keys, .json_keys = &.{ "info.id_dylib.path", "info.id_dylib.current_version", "info.rpaths" } },
    });

// ---------------------------------------------------------------------------------------------
// Byte-exact text snapshots
// ---------------------------------------------------------------------------------------------

const Snap = struct {
    fixture: []const u8,
    cmd: []const u8,
    argv: []const []const u8,
    /// `info` reads WP2/WP3/WP4 results; tolerate their lines while those parsers are stubs.
    tolerant: bool = false,
};

/// hello-fat is analysed with `--all-archs` so the snapshot does not depend on the host architecture.
fn snapArgv(comptime cmd: []const u8, comptime fixture: []const u8) []const []const u8 {
    return if (std.mem.eql(u8, fixture, "hello-fat")) &.{ cmd, "--all-archs" } else &.{cmd};
}

fn snapsFor(comptime fixture: []const u8) [4]Snap {
    return .{
        .{ .fixture = fixture, .cmd = "info", .argv = snapArgv("info", fixture), .tolerant = true },
        .{ .fixture = fixture, .cmd = "header", .argv = snapArgv("header", fixture) },
        .{ .fixture = fixture, .cmd = "loadcmds", .argv = snapArgv("loadcmds", fixture) },
        .{ .fixture = fixture, .cmd = "segments", .argv = snapArgv("segments", fixture) },
    };
}

const snapshots: []const Snap = &(snapsFor("hello-c") ++ snapsFor("hello-objc") ++ snapsFor("legacy-bind") ++
    snapsFor("libhello.dylib") ++ snapsFor("hello-fat"));

/// Makes a snapshot machine-independent: the absolute corpus path becomes "tests/corpus", and the
/// `ctime(3)` tail of otool's dylib "time stamp" line (rendered in the local time zone) becomes
/// `<ctime>` — that exact text is still locked by the `--otool-compat` rows against truth/<fixture>.txt.
fn normalize(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    const dir = helpers.corpusDir();
    const repathed = try arena.alloc(u8, std.mem.replacementSize(u8, s, dir, "tests/corpus"));
    _ = std.mem.replace(u8, s, dir, "tests/corpus", repathed);
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, repathed, '\n');
    var first = true;
    while (it.next()) |line| {
        if (!first) try out.append(arena, '\n');
        first = false;
        const tag = "   time stamp ";
        if (std.mem.startsWith(u8, line, tag)) {
            const rest = line[tag.len..];
            const sp = std.mem.findScalar(u8, rest, ' ') orelse rest.len;
            try out.print(arena, "{s}{s} <ctime>", .{ tag, rest[0..sp] });
            continue;
        }
        try out.appendSlice(arena, line);
    }
    return out.items;
}

test "golden: snapshot normaliser hides the local time zone" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualStrings(
        "   time stamp 2 <ctime>\n   time stamp 0 <ctime>\nkeep me\n",
        try normalize(a, "   time stamp 2 Wed Dec 31 19:00:02 1969\n   time stamp 0 Thu Jan  1 00:00:00 1970\nkeep me\n"),
    );
}

/// `  <key padded to 13><value>` -> `key` (empty for continuation/table lines).
fn kvKey(line: []const u8) []const u8 {
    if (line.len < 16 or line[0] != ' ' or line[1] != ' ' or line[2] == ' ') return "";
    return std.mem.trimEnd(u8, line[2..15], " ");
}

/// info lines fed by parsers WP1 does not own.
fn toleratedKey(key: []const u8) bool {
    const keys = [_][]const u8{ "entry", "dyld data", "symbols", "signature", "security", "quarantine", "diagnostics" };
    for (keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

/// Set to false by the comparator's own unit test so expected failures print nothing.
var print_diffs: bool = true;

/// Byte-exact, except that while a dependency is still a stub its own lines are skipped (and the
/// diagnostics block, which then lists the `not_implemented` infos, ends the comparison).
fn expectSnapshot(want: []const u8, got: []const u8, tolerant: bool) !void {
    const stubbed = tolerant and std.mem.find(u8, got, "not implemented") != null;
    var wi = std.mem.splitScalar(u8, want, '\n');
    var gi = std.mem.splitScalar(u8, got, '\n');
    var n: usize = 0;
    while (true) {
        const w = wi.next();
        const g = gi.next();
        if (w == null and g == null) return;
        n += 1;
        if (w == null or g == null) {
            if (print_diffs) std.debug.print("\nsnapshot line {d}: one side ended early\n", .{n});
            return error.SnapshotDiffers;
        }
        if (std.mem.eql(u8, w.?, g.?)) continue;
        const key = kvKey(w.?);
        // The snapshots pin the default configuration; a -Dsecurity=false build renders this one line
        // as "not evaluated (built without Security.framework ...)" and nothing else changes.
        if (!build_options.have_security and std.mem.eql(u8, key, "security")) continue;
        if (stubbed and toleratedKey(key)) {
            if (std.mem.eql(u8, key, "diagnostics")) return; // the stub diagnostics block ends the file
            continue;
        }
        if (print_diffs) std.debug.print("\nsnapshot line {d} differs:\n  want: {s}\n  got:  {s}\n", .{ n, w.?, g.? });
        return error.SnapshotDiffers;
    }
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
    const gpath = try std.fmt.allocPrint(arena, "{s}/{s}.{s}.txt", .{ try helpers.goldenDir(arena), s.fixture, s.cmd });
    if (build_options.update_golden) {
        var f = try std.Io.Dir.cwd().createFile(io, gpath, .{});
        defer f.close(io);
        var buf: [4096]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(got);
        try w.interface.flush();
        return;
    }
    const want = std.Io.Dir.cwd().readFileAlloc(io, gpath, arena, .limited(1 << 24)) catch |e| {
        std.debug.print("cannot read snapshot {s}: {t} (regenerate with zig build test-golden -Dupdate-golden=true)\n", .{ gpath, e });
        return e;
    };
    expectSnapshot(want, got, s.tolerant) catch |e| {
        std.debug.print("  -> snapshot {s}.{s}.txt\n", .{ s.fixture, s.cmd });
        return e;
    };
}

test "golden: core text snapshots" {
    const gpa = std.testing.allocator;
    var failures: usize = 0;
    for (snapshots) |s| runSnapshot(gpa, std.testing.io, s) catch |e| {
        std.debug.print("  -> {t}\n", .{e});
        failures += 1;
    };
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "golden: snapshot comparator tolerates only the stubbed lines" {
    const want =
        \\x: Mach-O 64-bit executable arm64 (thin), 10 bytes
        \\  flags        0x200085 (PIE)
        \\  entry        LC_MAIN entryoff 0x524 -> 0x100000524 (_main)   stacksize 0
        \\  symbols      12 (6 defined, 6 undefined, 0 stabs)   indirect 11
        \\  diagnostics  none
        \\
    ;
    const stub =
        \\x: Mach-O 64-bit executable arm64 (thin), 10 bytes
        \\  flags        0x200085 (PIE)
        \\  entry        LC_MAIN entryoff 0x524 -> 0x100000524   stacksize 0
        \\  symbols      12 declared (LC_SYMTAB ...)   parser not implemented
        \\  diagnostics  1 (0 errors, 0 warnings, 1 info)
        \\    [info] symbols.not_implemented: x
        \\
    ;
    try expectSnapshot(want, stub, true);
    try expectSnapshot(want, want, true);
    print_diffs = false;
    defer print_diffs = true;
    try std.testing.expectError(error.SnapshotDiffers, expectSnapshot(want, stub, false));
    var broken = try std.testing.allocator.dupe(u8, stub);
    defer std.testing.allocator.free(broken);
    broken[std.mem.find(u8, broken, "0x200085").?] = '1'; // a WP1-owned line must still be byte-exact
    try std.testing.expectError(error.SnapshotDiffers, expectSnapshot(want, broken, true));
}

// ---------------------------------------------------------------------------------------------
// /bin/ls: both slices against otool, run as a subprocess (truth/bin-ls.txt has the host slice only)
// ---------------------------------------------------------------------------------------------

fn otool(arena: std.mem.Allocator, io: std.Io, args: []const []const u8) ![]const u8 {
    const res = std.process.run(std.testing.allocator, io, .{ .argv = args }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(res.stderr);
    defer std.testing.allocator.free(res.stdout);
    return arena.dupe(u8, res.stdout);
}

test "golden: header/loadcmds --otool-compat match otool on both /bin/ls slices" {
    const io = std.testing.io;
    std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "arm64e", "x86_64" }) |arch| {
        const arch_z = try arena.dupeSentinel(u8, arch, 0);
        for ([_]struct { cmd: [:0]const u8, otool_flag: []const u8 }{
            .{ .cmd = "header", .otool_flag = "-hv" },
            .{ .cmd = "loadcmds", .otool_flag = "-h" },
        }) |c| {
            const mine = try helpers.runMachre(arena, io, &.{ c.cmd, "--otool-compat", "--arch", arch_z, "/bin/ls" });
            const theirs = if (std.mem.eql(u8, c.cmd, "header"))
                try otool(arena, io, &.{ "/usr/bin/otool", "-arch", arch, c.otool_flag, "/bin/ls" })
            else
                try otool(arena, io, &.{ "/usr/bin/otool", "-arch", arch, "-h", "-l", "/bin/ls" });
            if (theirs.len == 0) return error.SkipZigTest;
            truth.expectSameLines(theirs, mine.out) catch |e| {
                std.debug.print("  -> /bin/ls {s} {s}\n", .{ arch, c.cmd });
                return e;
            };
        }
    }
}

test "golden: /bin/ls per-slice load-command facts (WP1 acceptance)" {
    const io = std.testing.io;
    std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The two slices use different dyld metadata; each must decode on its own.
    // (DESIGN §12/WP1 says the x86_64 slice carries LC_VERSION_MIN_MACOSX; on this macOS the shipped
    //  /bin/ls uses LC_BUILD_VERSION with minos 10.14 on both slices, which is what §10.3 records.
    //  The LC_VERSION_MIN_MACOSX renderer is covered by the synthetic test below instead.)
    const x86 = try helpers.runMachre(arena, io, &.{ "loadcmds", "--otool-compat", "--arch", "x86_64", "/bin/ls" });
    try std.testing.expect(std.mem.find(u8, x86.out, "cmd LC_DYLD_INFO_ONLY") != null);
    try std.testing.expect(std.mem.find(u8, x86.out, "cmd LC_DYLD_CHAINED_FIXUPS") == null);
    try std.testing.expect(std.mem.find(u8, x86.out, "    minos 10.14") != null);
    const arm = try helpers.runMachre(arena, io, &.{ "loadcmds", "--otool-compat", "--arch", "arm64e", "/bin/ls" });
    try std.testing.expect(std.mem.find(u8, arm.out, "cmd LC_DYLD_CHAINED_FIXUPS") != null);
    try std.testing.expect(std.mem.find(u8, arm.out, "cmd LC_DYLD_INFO_ONLY") == null);
    const info = try helpers.runMachre(arena, io, &.{ "info", "--arch", "arm64e", "/bin/ls" });
    try std.testing.expect(std.mem.find(u8, info.out, "  platform     macOS   minos 11.0   sdk ") != null);
    const info86 = try helpers.runMachre(arena, io, &.{ "info", "--arch", "x86_64", "/bin/ls" });
    try std.testing.expect(std.mem.find(u8, info86.out, "  platform     macOS   minos 10.14   sdk ") != null);
    try std.testing.expect(std.mem.find(u8, info86.out, "  dyld data    dyld info (rebase ") != null);
}

// No corpus fixture carries LC_VERSION_MIN_MACOSX, so the decoder is exercised on a 48-byte
// hand-built image and diffed against `otool -h -l` on the same bytes.
test "golden: LC_VERSION_MIN_MACOSX renders exactly like otool" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var img: [48]u8 = @splat(0);
    std.mem.writeInt(u32, img[0..4], 0xfeedfacf, .little); // MH_MAGIC_64
    std.mem.writeInt(u32, img[4..8], 0x0100000c, .little); // CPU_TYPE_ARM64
    std.mem.writeInt(u32, img[12..16], 2, .little); // MH_EXECUTE
    std.mem.writeInt(u32, img[16..20], 1, .little); // ncmds
    std.mem.writeInt(u32, img[20..24], 16, .little); // sizeofcmds
    std.mem.writeInt(u32, img[32..36], 0x24, .little); // LC_VERSION_MIN_MACOSX
    std.mem.writeInt(u32, img[36..40], 16, .little); // cmdsize
    std.mem.writeInt(u32, img[40..44], 0x000a0e00, .little); // 10.14
    std.mem.writeInt(u32, img[44..48], 0x000a0f00, .little); // sdk 10.15
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "vmin.bin", .{});
        defer f.close(io);
        var buf: [64]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&img);
        try w.interface.flush();
    }
    const real = try tmp.dir.realPathFileAlloc(io, "vmin.bin", arena);
    const path: [:0]const u8 = try arena.dupeSentinel(u8, real, 0);
    const mine = try helpers.runMachre(arena, io, &.{ "loadcmds", "--otool-compat", path });
    const theirs = try otool(arena, io, &.{ "/usr/bin/otool", "-h", "-l", real });
    if (theirs.len == 0) return error.SkipZigTest;
    try truth.expectSameLines(theirs, mine.out);
    const info = try helpers.runMachre(arena, io, &.{ "info", path });
    try std.testing.expect(std.mem.find(u8, info.out, "  platform     LC_VERSION_MIN_MACOSX   minos 10.14   sdk 10.15\n") != null);
}

test "golden: hello-zig build tool 5 has no name and prints `tool 5`" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-zig");
    const lc = try helpers.runMachre(arena, io, &.{ "loadcmds", "--otool-compat", path });
    try std.testing.expect(std.mem.find(u8, lc.out, "     tool 5\n") != null);
    const info = try helpers.runMachre(arena, io, &.{ "info", path });
    try std.testing.expect(std.mem.find(u8, info.out, "   tools tool 5 ") != null);
}

test "golden: fat text default names the shown slice" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-fat");
    const res = try helpers.runMachre(arena, io, &.{ "info", path });
    try std.testing.expect(std.mem.startsWith(u8, res.out, "2 architectures, showing "));
    try std.testing.expect(std.mem.find(u8, res.out, " (use --all-archs)\n") != null);
    const all = try helpers.runMachre(arena, io, &.{ "info", "--all-archs", path });
    try std.testing.expect(!std.mem.startsWith(u8, all.out, "2 architectures"));
    try std.testing.expect(std.mem.find(u8, all.out, " (architecture x86_64):\n") != null);
    try std.testing.expect(std.mem.find(u8, all.out, " (architecture arm64):\n") != null);
}

test "golden: dump --section=__TEXT,__cstring shows the three hello-c strings" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-c");
    const res = try helpers.runMachre(arena, io, &.{ "dump", "--section=__TEXT,__cstring", path });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    try std.testing.expect(std.mem.find(u8, res.out, "(__TEXT,__cstring) section, 43 bytes at file offset 1640") != null);
    // The ASCII gutter carries the three C strings across the hexdump rows.
    var ascii: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, res.out, '\n');
    while (it.next()) |line| {
        const bar = std.mem.findScalar(u8, line, '|') orelse continue;
        const end = std.mem.findScalarPos(u8, line, bar + 1, '|') orelse continue;
        try ascii.appendSlice(arena, line[bar + 1 .. end]);
    }
    try std.testing.expectEqualStrings("hello from machre corpus.%s (%d args).exit.", ascii.items);
    const js = try helpers.runMachre(arena, io, &.{ "dump", "--json", "--section=__TEXT,__cstring", path });
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, js.out, .{});
    defer parsed.deinit();
    const d = parsed.value.object.get("arches").?.array.items[0].object.get("dump").?;
    try std.testing.expectEqualStrings("__cstring", d.object.get("section").?.string);
    try std.testing.expectEqual(@as(i64, 43), d.object.get("length").?.integer);
    for ([_][]const u8{ "hello from machre corpus", "%s (%d args)", "exit" }) |s| {
        try std.testing.expect(std.mem.find(u8, d.object.get("ascii").?.string, s) != null);
    }
}

// ---------------------------------------------------------------------------------------------
// Ground truth: the rendered JSON of `segments` against truth/summary.json, for every fixture
// ---------------------------------------------------------------------------------------------

fn jsonHex(v: std.json.Value, key: []const u8) ?u64 {
    const x = switch (v) {
        .object => |o| o.get(key) orelse return null,
        else => return null,
    };
    return switch (x) {
        .string => |s| helpers.Summary.parseHex(s),
        .integer => |i| @bitCast(i),
        else => null,
    };
}
fn jsonInt(v: std.json.Value, key: []const u8) ?i64 {
    const x = switch (v) {
        .object => |o| o.get(key) orelse return null,
        else => return null,
    };
    return switch (x) {
        .integer => |i| i,
        else => null,
    };
}
fn jsonStr(v: std.json.Value, key: []const u8) ?[]const u8 {
    const x = switch (v) {
        .object => |o| o.get(key) orelse return null,
        else => return null,
    };
    return switch (x) {
        .string => |s| s,
        else => null,
    };
}

// `machre segments --json --all-archs` must reproduce every segment/section field of summary.json.
// (WP0's facts/core.zig proves the parser; this proves the renderer does not lose or reshape them.)
test "golden: segments --json equals truth/summary.json for every healthy fixture" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    for (helpers.healthy_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const fx = summary.fixtureNamed(name) orelse return error.FixtureMissingFromSummary;
        const path = try helpers.summaryFixturePath(arena, name);
        const res = try helpers.runMachre(arena, io, &.{ "segments", "--json", "--all-archs", path });
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer parsed.deinit();
        const arches = parsed.value.object.get("arches").?.array.items;
        var slice_i: usize = 0;
        while (helpers.Summary.slice(fx, slice_i)) |sl| : (slice_i += 1) {
            if (slice_i >= arches.len) return error.SliceMissingFromOutput;
            const got_segs = arches[slice_i].object.get("segments").?.array.items;
            const want_segs = helpers.Summary.array(sl, "segments") orelse &.{};
            std.testing.expectEqual(want_segs.len, got_segs.len) catch |e| {
                std.debug.print("  -> {s} slice {d}: segment count\n", .{ name, slice_i });
                return e;
            };
            for (want_segs, got_segs) |ws, gs| {
                try std.testing.expectEqualStrings(helpers.Summary.str(ws, "name").?, jsonStr(gs, "name").?);
                try std.testing.expectEqual(helpers.Summary.hex(ws, "vmaddr").?, jsonHex(gs, "vmaddr").?);
                try std.testing.expectEqual(helpers.Summary.hex(ws, "vmsize").?, jsonHex(gs, "vmsize").?);
                try std.testing.expectEqual(helpers.Summary.int(ws, "fileoff").?, jsonInt(gs, "fileoff").?);
                try std.testing.expectEqual(helpers.Summary.int(ws, "filesize").?, jsonInt(gs, "filesize").?);
                try std.testing.expectEqual(helpers.Summary.int(ws, "maxprot").?, jsonInt(gs, "maxprot").?);
                try std.testing.expectEqual(helpers.Summary.int(ws, "initprot").?, jsonInt(gs, "initprot").?);
                try std.testing.expectEqual(helpers.Summary.int(ws, "nsects").?, jsonInt(gs, "nsects").?);
                try std.testing.expectEqual(helpers.Summary.hex(ws, "flags").?, jsonHex(gs.object.get("flags").?, "value").?);
                const want_sects = helpers.Summary.array(ws, "sections") orelse &.{};
                const got_sects = gs.object.get("sections").?.array.items;
                try std.testing.expectEqual(want_sects.len, got_sects.len);
                for (want_sects, got_sects) |wc, gc| {
                    try std.testing.expectEqualStrings(helpers.Summary.str(wc, "name").?, jsonStr(gc, "sectname").?);
                    try std.testing.expectEqualStrings(helpers.Summary.str(wc, "segname").?, jsonStr(gc, "segname").?);
                    try std.testing.expectEqual(helpers.Summary.hex(wc, "addr").?, jsonHex(gc, "addr").?);
                    try std.testing.expectEqual(helpers.Summary.int(wc, "size").?, jsonInt(gc, "size").?);
                    try std.testing.expectEqual(helpers.Summary.int(wc, "offset").?, jsonInt(gc, "offset").?);
                    try std.testing.expectEqual(helpers.Summary.int(wc, "align").?, jsonInt(gc, "align").?);
                    try std.testing.expectEqual(helpers.Summary.hex(wc, "flags").?, jsonHex(gc.object.get("flags").?, "value").?);
                    try std.testing.expectEqual(helpers.Summary.int(wc, "type").?, jsonInt(gc.object.get("flags").?, "type").?);
                }
            }
        }
        try std.testing.expectEqual(slice_i, arches.len);
    }
}

// `machre info --json` must carry the same header/entry/symtab facts summary.json records.
test "golden: info --json header and entry facts equal truth/summary.json" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    for (helpers.healthy_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const fx = summary.fixtureNamed(name).?;
        const path = try helpers.summaryFixturePath(arena, name);
        const res = try helpers.runMachre(arena, io, &.{ "info", "--json", "--all-archs", path });
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer parsed.deinit();
        const root = parsed.value;
        try std.testing.expectEqualStrings(helpers.Summary.str(fx, "container").?, root.object.get("file").?.object.get("container").?.string);
        try std.testing.expectEqual(helpers.Summary.int(fx, "size").?, root.object.get("file").?.object.get("size").?.integer);
        try std.testing.expectEqualStrings(helpers.Summary.str(fx, "sha256").?, root.object.get("file").?.object.get("sha256").?.string);
        const arches = root.object.get("arches").?.array.items;
        var i: usize = 0;
        while (helpers.Summary.slice(fx, i)) |sl| : (i += 1) {
            const info = arches[i].object.get("info").?;
            const hdr = info.object.get("header").?;
            std.testing.expectEqual(helpers.Summary.hex(sl, "magic").?, jsonHex(hdr, "magic").?) catch |e| {
                std.debug.print("  -> {s} slice {d}: magic\n", .{ name, i });
                return e;
            };
            try std.testing.expectEqual(helpers.Summary.hex(sl, "cputype").?, jsonHex(hdr, "cputype").?);
            try std.testing.expectEqual(helpers.Summary.int(sl, "filetype").?, jsonInt(hdr, "filetype").?);
            try std.testing.expectEqual(helpers.Summary.int(sl, "ncmds").?, jsonInt(hdr, "ncmds").?);
            try std.testing.expectEqual(helpers.Summary.int(sl, "sizeofcmds").?, jsonInt(hdr, "sizeofcmds").?);
            try std.testing.expectEqual(helpers.Summary.hex(sl, "flags").?, jsonHex(hdr.object.get("flags").?, "value").?);
            if (helpers.Summary.object(sl, "entry_point")) |ep| {
                const entry = info.object.get("entry").?;
                try std.testing.expectEqual(helpers.Summary.hex(ep, "entryoff_hex").?, jsonHex(entry, "entryoff").?);
                try std.testing.expectEqual(helpers.Summary.int(ep, "stacksize").?, jsonInt(entry, "stacksize").?);
            }
            if (helpers.Summary.object(sl, "symtab")) |st| {
                const got = info.object.get("symtab").?;
                try std.testing.expectEqual(helpers.Summary.int(st, "nsyms").?, jsonInt(got, "nsyms").?);
                try std.testing.expectEqual(helpers.Summary.int(st, "symoff").?, jsonInt(got, "symoff").?);
                try std.testing.expectEqual(helpers.Summary.int(st, "stroff").?, jsonInt(got, "stroff").?);
                try std.testing.expectEqual(helpers.Summary.int(st, "strsize").?, jsonInt(got, "strsize").?);
            }
        }
        try std.testing.expectEqual(i, arches.len);
    }
}

test "golden: header --fat --otool-compat equals lipo -detailed_info" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "hello-fat", "bin-ls" }) |name| {
        const path = try helpers.summaryFixturePath(arena, name);
        if (std.mem.eql(u8, name, "bin-ls")) std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch continue;
        const mine = try helpers.runMachre(arena, io, &.{ "header", "--fat", "--otool-compat", path });
        const theirs = try otool(arena, io, &.{ "/usr/bin/lipo", "-detailed_info", path });
        if (theirs.len == 0) return error.SkipZigTest;
        truth.expectSameLines(theirs, mine.out) catch |e| {
            std.debug.print("  -> lipo parity for {s}\n", .{name});
            return e;
        };
    }
}

test "golden: dump of a zero-fill section reports memory size and no file bytes" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-zig");
    const res = try helpers.runMachre(arena, io, &.{ "dump", "--section=__DATA,__bss", path });
    try std.testing.expectEqual(@as(u8, 0), res.code);
    try std.testing.expect(std.mem.startsWith(u8, res.out, "(__DATA,__bss) section, 16 bytes in memory, zero-fill (no file bytes)\n"));
    const js = try helpers.runMachre(arena, io, &.{ "dump", "--json", "--section=__DATA,__bss", path });
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, js.out, .{});
    defer parsed.deinit();
    const d = parsed.value.object.get("arches").?.array.items[0].object.get("dump").?;
    try std.testing.expectEqual(true, d.object.get("zerofill").?.bool);
    try std.testing.expectEqual(@as(i64, 0), d.object.get("length").?.integer);
    try std.testing.expectEqual(@as(i64, 16), d.object.get("vm_size").?.integer);
    try std.testing.expectEqualStrings("", d.object.get("hex").?.string);
}

test "golden: dump rejects an unknown section and an unmapped address without trapping" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try helpers.fixturePath(arena, "hello-c");
    // Unresolvable ranges exit 1 with a diagnostic, never a trap.
    for ([_][]const u8{ "--section=__NOPE,__nope", "--section=nocomma", "--addr=notanumber", "--addr=0xdeadbeef", "--offset=99999999", "--offset=0x10+" }) |flag| {
        const z = try arena.dupeSentinel(u8, flag, 0);
        const res = try helpers.runMachre(arena, io, &.{ "dump", z, path });
        std.testing.expectEqual(@as(u8, 1), res.code) catch |e| {
            std.debug.print("  -> dump {s} should exit 1\n", .{flag});
            return e;
        };
    }
    // A length past the end of the mapping is clamped and reported, not refused and never wrapped.
    const clamped = try helpers.runMachre(arena, io, &.{ "dump", "--addr=0x100000668+0xffffffffffffffff", path });
    try std.testing.expectEqual(@as(u8, 0), clamped.code);
    try std.testing.expect(std.mem.find(u8, clamped.out, "[warning] cli.truncated: range clamped to 14744 of 18446744073709551615 requested bytes") != null);
    const clamped_off = try helpers.runMachre(arena, io, &.{ "dump", "--offset=49000+100000", path });
    try std.testing.expectEqual(@as(u8, 0), clamped_off.code);
    try std.testing.expect(std.mem.find(u8, clamped_off.out, "range clamped to 1424 of 100000 requested bytes at the slice end") != null);
}
