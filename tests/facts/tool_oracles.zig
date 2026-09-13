//! tests/facts/tool_oracles.zig — the Apple-tool ground truth that `tests/corpus/gen/truth.sh` captures
//! but that no test used to read: `vtool -show`, `otool -L`, `otool -Iv`, `dyld_info -platform`,
//! `dyld_info -inits` and `objdump --macho --objc-meta-data`.
//!
//! Every test here skips (`error.SkipZigTest`) when the fixture or its truth file is absent, and every
//! comparison is against the CAPTURED section — no Apple tool is executed.
//!
//! Reached from tests/facts/core.zig (the corpus test root imports one file per WP; this file rides
//! along with it rather than inventing a second root).
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");

const loadcmds = machre.core.loadcmds;
const version = machre.core.version;
const fmt = machre.core.fmt;

/// The fixtures gen/truth.sh captures: the healthy corpus plus Hello.app's main executable and /bin/ls.
const all_fixtures = [_][]const u8{
    "hello-c",        "hello-x86_64",   "hello-fat",    "hello-objc",  "libhello.dylib", "hello-usedylib", "hello-adhoc",
    "hello-entitled", "hello-unsigned", "high-entropy", "fake-packed", "fake-upx",       "hello-zig",      "legacy-bind",
    "hello-quarantined", "Hello.app",   "bin-ls",
};

const OracleError = error{OracleMismatch};

/// <mach-o/loader.h>; src/macho/symbols.zig keeps its own private copies.
const indirect_symbol_local: u32 = 0x8000_0000;
const indirect_symbol_abs: u32 = 0x4000_0000;

fn fail(name: []const u8, comptime what: []const u8, args: anytype) OracleError {
    std.debug.print("[{s}] " ++ what ++ "\n", .{name} ++ args);
    return error.OracleMismatch;
}

/// truth.find matches a command PREFIX; objdump's section is keyed by its absolute Xcode path, so its
/// section can only be found by substring.
fn findContaining(secs: []const truth.Section, needle: []const u8) ?truth.Section {
    for (secs) |s| if (std.mem.find(u8, s.cmd, needle) != null) return s;
    return null;
}

// ---------------------------------------------------------------------------------------------
// per-architecture grouping (shared by every tool section below)
// ---------------------------------------------------------------------------------------------

const Group = struct { arch: ?[]const u8, body: []const u8 };

/// A banner is an unindented line ending in ':'. otool spells it `<path> (architecture <arch>):`,
/// dyld_info `<path> [<arch>]:`. When the tool found ONE slice that exactly matches the host cpu it
/// prints a bare `<path>:` banner and analyses only that slice — this is what `otool -L`/`-Iv` do for
/// /bin/ls, whose arm64e slice is an exact host match, while hello-fat (arm64 ALL, not an exact match)
/// gets both banners. A bare banner yields `arch = null` and the caller resolves it by matching.
fn archGroups(arena: std.mem.Allocator, body: []const u8) ![]const Group {
    var out: std.ArrayList(Group) = .empty;
    var arch: ?[]const u8 = null;
    var start: usize = 0;
    var pos: usize = 0;
    var started = false;
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |line| {
        const line_start = pos;
        pos += line.len + 1;
        const t = std.mem.trimEnd(u8, line, " \t\r");
        if (t.len == 0 or t[0] == ' ' or t[0] == '\t' or t[t.len - 1] != ':') continue;
        if (started) try out.append(arena, .{ .arch = arch, .body = body[start..line_start] });
        started = true;
        start = pos;
        arch = bannerArch(t);
    }
    if (started) try out.append(arena, .{ .arch = arch, .body = body[start..] });
    return out.toOwnedSlice(arena);
}

fn bannerArch(t: []const u8) ?[]const u8 {
    const head = t[0 .. t.len - 1];
    if (std.mem.find(u8, head, " (architecture ")) |p| {
        if (head.len > 0 and head[head.len - 1] == ')') return head[p + 15 .. head.len - 1];
    }
    if (head.len > 2 and head[head.len - 1] == ']') {
        if (std.mem.findLast(u8, head, " [")) |p| return head[p + 2 .. head.len - 1];
    }
    return null;
}

fn sliceForArch(file: *const machre.LoadedFile, arch: []const u8) ?usize {
    for (0..file.sliceCount()) |i| {
        const a = file.sliceArch(i) orelse continue;
        if (std.mem.eql(u8, a.name.str(), arch)) return i;
    }
    return null;
}

/// Opens a fixture for the per-slice oracles; null when the fixture is not on disk.
const Opened = struct {
    file: machre.LoadedFile,
    diags: machre.Diagnostics,
    pub fn image(o: *Opened, arena: std.mem.Allocator, i: usize) !machre.Image {
        return machre.Image.parse(arena, o.file.sliceReader(i).?, o.file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &o.diags);
    }
};

fn openFixture(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, name: []const u8) !?Opened {
    const path = try helpers.summaryFixturePath(arena, name);
    var diags = machre.Diagnostics.init(arena, 64);
    const file = machre.LoadedFile.load(gpa, arena, io, path, &machre.Limits.default, &diags) catch |e| switch (e) {
        error.FileNotFound, error.AccessDenied => return null,
        else => return e,
    };
    return .{ .file = file, .diags = diags };
}

/// Loads truth/<name>.txt, or null when it was never captured.
fn sections(arena: std.mem.Allocator, io: std.Io, name: []const u8) !?[]truth.Section {
    return truth.load(arena, io, name) catch |e| switch (e) {
        error.FileNotFound => null,
        else => e,
    };
}

// ---------------------------------------------------------------------------------------------
// 1. `vtool -show` — DESIGN §10.4 "info platform line | vtool -show (values) | same_lines (extracted)"
// ---------------------------------------------------------------------------------------------

/// Canonicalises a tool spelling: upper-cased, and machre's "tool 5" for an unnamed tool id reduced to
/// vtool's bare "5".
fn canonTool(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    const up = try std.ascii.allocUpperString(arena, name);
    if (std.mem.startsWith(u8, up, "TOOL ")) return up[5..];
    return up;
}

/// `vtool -show` group -> canonical lines, in a fixed order (vtool prints the load commands in file
/// order, and hello-zig carries LC_SOURCE_VERSION *before* LC_BUILD_VERSION).
fn vtoolExpected(arena: std.mem.Allocator, name: []const u8, body: []const u8) ![]const u8 {
    var platform: ?[]const u8 = null;
    var minos: ?[]const u8 = null;
    var sdk: ?[]const u8 = null;
    var tools: std.ArrayList([]const u8) = .empty;
    var source: ?[]const u8 = null;
    var cur_cmd: []const u8 = "";
    var pending_tool: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "Load command ")) continue;
        var toks = std.mem.tokenizeAny(u8, line, " \t");
        const key = toks.next() orelse continue;
        const val = toks.rest();
        if (std.mem.eql(u8, key, "cmd")) {
            cur_cmd = val;
            if (!std.mem.eql(u8, val, "LC_BUILD_VERSION") and !std.mem.eql(u8, val, "LC_SOURCE_VERSION"))
                return fail(name, "vtool -show prints {s}, which this oracle does not model yet — extend vtoolExpected/machrePlatform", .{val});
            continue;
        }
        if (std.mem.eql(u8, key, "cmdsize")) continue;
        if (std.mem.eql(u8, key, "platform")) platform = val;
        if (std.mem.eql(u8, key, "minos")) minos = val;
        if (std.mem.eql(u8, key, "sdk")) sdk = val;
        if (std.mem.eql(u8, key, "ntools")) continue;
        if (std.mem.eql(u8, key, "tool")) pending_tool = val;
        if (std.mem.eql(u8, key, "version")) {
            if (std.mem.eql(u8, cur_cmd, "LC_SOURCE_VERSION")) {
                source = val;
            } else {
                const t = pending_tool orelse return fail(name, "vtool 'version' with no preceding 'tool'", .{});
                try tools.append(arena, try std.fmt.allocPrint(arena, "tool={s} version={s}", .{ try canonTool(arena, t), val }));
                pending_tool = null;
            }
        }
    }
    return renderPlatform(arena, name, platform, minos, sdk, tools.items, source);
}

fn renderPlatform(
    arena: std.mem.Allocator,
    name: []const u8,
    platform: ?[]const u8,
    minos: ?[]const u8,
    sdk: ?[]const u8,
    tools: []const []const u8,
    source: ?[]const u8,
) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    if (platform) |p| {
        const up = try std.ascii.allocUpperString(arena, p);
        try w.writer.print("platform={s} minos={s} sdk={s}\n", .{ up, minos orelse "?", sdk orelse "?" });
    }
    for (tools) |t| try w.writer.print("{s}\n", .{t});
    if (source) |s| try w.writer.print("source_version={s}\n", .{s});
    if (platform == null and tools.len == 0 and source == null)
        return fail(name, "no platform/source values extracted", .{});
    return arena.dupe(u8, w.written());
}

/// `machre info` group -> the same canonical lines.
fn machrePlatform(arena: std.mem.Allocator, name: []const u8, body: []const u8) ![]const u8 {
    var platform: ?[]const u8 = null;
    var minos: ?[]const u8 = null;
    var sdk: ?[]const u8 = null;
    var tools: std.ArrayList([]const u8) = .empty;
    var source: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "source ver")) {
            source = std.mem.trim(u8, line["source ver".len..], " \t");
            continue;
        }
        if (!std.mem.startsWith(u8, line, "platform ")) continue;
        var toks = std.mem.tokenizeAny(u8, line, " \t");
        var words: std.ArrayList([]const u8) = .empty;
        while (toks.next()) |t| try words.append(arena, t);
        var i: usize = 0;
        while (i < words.items.len) : (i += 1) {
            const k = words.items[i];
            if (std.mem.eql(u8, k, "platform") and i + 1 < words.items.len) {
                platform = words.items[i + 1];
            } else if (std.mem.eql(u8, k, "minos") and i + 1 < words.items.len) {
                minos = words.items[i + 1];
            } else if (std.mem.eql(u8, k, "sdk") and i + 1 < words.items.len) {
                sdk = words.items[i + 1];
            } else if (std.mem.eql(u8, k, "tools")) {
                // "tools <name words...> <version>"; the corpus only ever carries one tool, and
                // vtoolExpected refuses anything else, so a second tool would surface as a diff.
                const rest = words.items[i + 1 ..];
                if (rest.len < 2) return fail(name, "cannot split 'tools {s}'", .{line});
                const tname = try std.mem.join(arena, " ", rest[0 .. rest.len - 1]);
                try tools.append(arena, try std.fmt.allocPrint(arena, "tool={s} version={s}", .{ try canonTool(arena, tname), rest[rest.len - 1] }));
                break;
            }
        }
    }
    return renderPlatform(arena, name, platform, minos, sdk, tools.items, source);
}

/// Splits `machre info --all-archs` output into one body per slice (a new slice starts at the
/// unindented "<path>: Mach-O ..." header line).
fn machreInfoGroups(arena: std.mem.Allocator, out: []const u8) ![]const []const u8 {
    var groups: std.ArrayList([]const u8) = .empty;
    var start: usize = 0;
    var pos: usize = 0;
    var started = false;
    var it = std.mem.splitScalar(u8, out, '\n');
    while (it.next()) |line| {
        const line_start = pos;
        pos += line.len + 1;
        if (line.len == 0 or line[0] == ' ' or line[0] == '\t') continue;
        if (std.mem.find(u8, line, ": Mach-O ") == null) continue;
        if (started) try groups.append(arena, out[start..line_start]);
        started = true;
        start = line_start;
    }
    if (started) try groups.append(arena, out[start..]);
    return groups.toOwnedSlice(arena);
}

test "facts/tool_oracles: the info platform line matches vtool -show for every captured fixture (DESIGN 10.4)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/vtool -show") orelse continue;
        const path = try helpers.summaryFixturePath(a, name);
        std.Io.Dir.cwd().access(io, path, .{}) catch continue;
        const r = try helpers.runMachre(a, io, &.{ "info", "--all-archs", "--no-security", "-q", path });

        const want_groups = try archGroups(a, sec.body);
        const got_groups = try machreInfoGroups(a, r.out);
        if (want_groups.len != got_groups.len) {
            _ = fail(name, "vtool -show shows {d} slice(s), machre info {d}", .{ want_groups.len, got_groups.len }) catch {};
            failures += 1;
            continue;
        }
        for (want_groups, got_groups) |wg, gg| {
            const want = vtoolExpected(a, name, wg.body) catch {
                failures += 1;
                continue;
            };
            const got = machrePlatform(a, name, gg) catch {
                failures += 1;
                continue;
            };
            truth.expectSameLines(want, got) catch {
                std.debug.print("[{s}] vtool -show vs machre info platform values differ\n", .{name});
                failures += 1;
            };
        }
        checked += 1;
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------------------------
// 2. `otool -L` — the linked-dylib table
// ---------------------------------------------------------------------------------------------

/// otool -L's rows for one slice: the file's OWN LC_ID_DYLIB first (when present), then every dylib
/// load command in file order.
///
/// EXPECTED OFFSET, not a bug: `otool -L` opens with the install name the file declares for ITSELF
/// (LC_ID_DYLIB), which is not a dependency. machre keeps that on its own `id dylib` line and its
/// `dylibs` list holds imports only; the test below asserts exactly that offset.
fn otoolLExpected(arena: std.mem.Allocator, img: *const machre.Image, diags: *machre.Diagnostics) !struct { text: []const u8, imports: usize, has_id: bool } {
    var w: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    var has_id = false;
    if (img.findCmd(.ID_DYLIB)) |c| {
        const d = (try loadcmds.decodeDylib(arena, c, 0, diags)) orelse return error.OracleMismatch;
        has_id = true;
        try w.writer.print("\t{s} (compatibility version {f}, current version {f})\n", .{ d.name, fmt.Version{ .v = d.compat_version }, fmt.Version{ .v = d.current_version } });
    }
    var imports: usize = 0;
    var ordinal: u16 = 0;
    for (img.cmds) |c| {
        if (!loadcmds.isDylibLoadCmd(c.cmd)) continue;
        ordinal += 1;
        const d = (try loadcmds.decodeDylib(arena, c, ordinal, diags)) orelse return error.OracleMismatch;
        imports += 1;
        try w.writer.print("\t{s} (compatibility version {f}, current version {f})\n", .{ d.name, fmt.Version{ .v = d.compat_version }, fmt.Version{ .v = d.current_version } });
    }
    return .{ .text = try arena.dupe(u8, w.written()), .imports = imports, .has_id = has_id };
}

test "facts/tool_oracles: the dylib table matches otool -L (LC_ID_DYLIB is otool's extra first row)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/otool -L") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        for (try archGroups(a, sec.body)) |g| {
            var want_rows: usize = 0;
            var lines = std.mem.splitScalar(u8, g.body, '\n');
            while (lines.next()) |l| if (std.mem.trim(u8, l, " \t\r").len != 0) {
                want_rows += 1;
            };
            var matched = false;
            var last_err: ?[]const u8 = null;
            const candidates: []const usize = if (g.arch) |arch| blk: {
                const i = sliceForArch(&opened.file, arch) orelse {
                    _ = fail(name, "otool -L names architecture {s}, machre has no such slice", .{arch}) catch {};
                    failures += 1;
                    continue;
                };
                break :blk try a.dupe(usize, &.{i});
            } else blk: {
                // Bare banner: otool analysed the single exact host-cpu match. Accept the slice whose
                // table reproduces it (for a thin file that is the only slice).
                const all = try a.alloc(usize, opened.file.sliceCount());
                for (all, 0..) |*s, i| s.* = i;
                break :blk all;
            };
            for (candidates) |i| {
                const img = try opened.image(a, i);
                const got = try otoolLExpected(a, &img, &opened.diags);
                truth.print_diffs = candidates.len == 1;
                defer truth.print_diffs = true;
                truth.expectSameLines(g.body, got.text) catch {
                    last_err = got.text;
                    continue;
                };
                matched = true;
                // The expected offset: otool's row count is machre's import count plus the ID row.
                const extra: usize = if (got.has_id) 1 else 0;
                if (want_rows != got.imports + extra) {
                    _ = fail(name, "otool -L printed {d} rows, machre has {d} imports + {d} id row(s)", .{ want_rows, got.imports, extra }) catch {};
                    failures += 1;
                }
                break;
            }
            if (!matched) {
                _ = fail(name, "otool -L group (arch {s}) matched no slice", .{g.arch orelse "<host>"}) catch {};
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------------------------
// 3. `otool -Iv` — the indirect symbol table behind every stub / pointer section
// ---------------------------------------------------------------------------------------------

/// Reproduces `otool -Iv`'s layout for one slice from machre's parsed model: otool walks the sections
/// in load-command order, prints the ones whose type is S_SYMBOL_STUBS / S_(LAZY|NON_LAZY|LAZY_DYLIB)_
/// SYMBOL_POINTERS, and for entry j prints `sect.addr + j*stride`, the indirect-table value at
/// `reserved1 + j` and the symbol it names. stride is reserved2 for stubs, else the pointer size.
fn otoolIvExpected(arena: std.mem.Allocator, img: *const machre.Image, tbl: *const machre.macho.symbols.SymbolTable) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    const ptr_size: u64 = if (img.hdr.is_64) 8 else 4;
    for (img.sections) |sec| {
        const stride: u64 = switch (sec.sectType()) {
            std.macho.S_SYMBOL_STUBS => if (sec.reserved2 != 0) sec.reserved2 else continue,
            std.macho.S_LAZY_SYMBOL_POINTERS, std.macho.S_NON_LAZY_SYMBOL_POINTERS, 0x10 => ptr_size,
            else => continue,
        };
        const count = sec.size / stride;
        try w.writer.print("Indirect symbols for ({s},{s}) {d} entries\n", .{ sec.segname, sec.sectname, count });
        try w.writer.writeAll("address            index name\n");
        var j: u64 = 0;
        while (j < count) : (j += 1) {
            const addr = sec.addr + j * stride;
            const k: u64 = @as(u64, sec.reserved1) + j;
            if (k >= tbl.indirect.len) {
                try w.writer.print("0x{x:0>16} <past the indirect table>\n", .{addr});
                continue;
            }
            const v = tbl.indirect[@intCast(k)];
            if (v & indirect_symbol_local != 0) {
                try w.writer.print("0x{x:0>16} LOCAL{s}\n", .{ addr, if (v & indirect_symbol_abs != 0) " ABSOLUTE" else "" });
                continue;
            }
            if (v & indirect_symbol_abs != 0) {
                try w.writer.print("0x{x:0>16} ABSOLUTE\n", .{addr});
                continue;
            }
            const sym = tbl.symbolAt(v) orelse {
                try w.writer.print("0x{x:0>16} {d:>5} ?(bad symbol index)\n", .{ addr, v });
                continue;
            };
            try w.writer.print("0x{x:0>16} {d:>5} {s}\n", .{ addr, v, sym.name });
        }
    }
    return arena.dupe(u8, w.written());
}

test "facts/tool_oracles: the stub / pointer tables diff clean against otool -Iv" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/otool -Iv") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        for (try archGroups(a, sec.body)) |g| {
            const candidates: []const usize = if (g.arch) |arch| blk: {
                const i = sliceForArch(&opened.file, arch) orelse {
                    _ = fail(name, "otool -Iv names architecture {s}, machre has no such slice", .{arch}) catch {};
                    failures += 1;
                    continue;
                };
                break :blk try a.dupe(usize, &.{i});
            } else blk: {
                const all = try a.alloc(usize, opened.file.sliceCount());
                for (all, 0..) |*s, i| s.* = i;
                break :blk all;
            };
            var matched = false;
            for (candidates) |i| {
                const img = try opened.image(a, i);
                const tbl = try machre.macho.symbols.parse(a, &img, &machre.Limits.default, &opened.diags);
                const got = try otoolIvExpected(a, &img, &tbl);
                truth.print_diffs = candidates.len == 1;
                defer truth.print_diffs = true;
                truth.expectSameLines(g.body, got) catch continue;
                matched = true;
                break;
            }
            if (!matched) {
                _ = fail(name, "otool -Iv group (arch {s}) matched no slice", .{g.arch orelse "<host>"}) catch {};
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------------------------
// 4. `dyld_info -platform` and `dyld_info -inits`
// ---------------------------------------------------------------------------------------------

/// The `-platform:` sub-block of the combined dyld_info section:
///     -platform:
///         platform     minOS      sdk
///            macOS     26.0      26.5
fn dyldPlatformRow(body: []const u8) ?[3][]const u8 {
    var it = std.mem.splitScalar(u8, body, '\n');
    var in_block = false;
    var saw_header = false;
    while (it.next()) |raw| {
        const t = std.mem.trim(u8, raw, " \t\r");
        if (t.len == 0) continue;
        if (std.mem.startsWith(u8, t, "-")) {
            in_block = std.mem.eql(u8, t, "-platform:");
            saw_header = false;
            continue;
        }
        if (!in_block) continue;
        if (!saw_header) {
            saw_header = true; // "platform     minOS      sdk"
            continue;
        }
        var toks = std.mem.tokenizeAny(u8, t, " \t");
        const p = toks.next() orelse return null;
        const m = toks.next() orelse return null;
        const s = toks.next() orelse return null;
        return .{ p, m, s };
    }
    return null;
}

test "facts/tool_oracles: build version matches dyld_info -platform" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/dyld_info -platform") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        for (try archGroups(a, sec.body)) |g| {
            const arch = g.arch orelse continue;
            const i = sliceForArch(&opened.file, arch) orelse {
                _ = fail(name, "dyld_info names architecture {s}, machre has no such slice", .{arch}) catch {};
                failures += 1;
                continue;
            };
            const row = dyldPlatformRow(g.body) orelse {
                _ = fail(name, "no -platform row in the {s} group", .{arch}) catch {};
                failures += 1;
                continue;
            };
            const img = try opened.image(a, i);
            const cmd = img.findCmd(.BUILD_VERSION) orelse {
                _ = fail(name, "dyld_info shows a platform but machre found no LC_BUILD_VERSION ({s})", .{arch}) catch {};
                failures += 1;
                continue;
            };
            const bv = (try loadcmds.decodeBuildVersion(a, cmd, &machre.Limits.default, &opened.diags)).?;
            const got_platform = version.platformName(bv.platform) orelse "?";
            const got_minos = try std.fmt.allocPrint(a, "{f}", .{fmt.VersionShort{ .v = bv.minos }});
            const got_sdk = try std.fmt.allocPrint(a, "{f}", .{fmt.VersionShort{ .v = bv.sdk }});
            if (!std.mem.eql(u8, row[0], got_platform) or !std.mem.eql(u8, row[1], got_minos) or !std.mem.eql(u8, row[2], got_sdk)) {
                _ = fail(name, "{s}: dyld_info -platform says {s}/{s}/{s}, machre {s}/{s}/{s}", .{ arch, row[0], row[1], row[2], got_platform, got_minos, got_sdk }) catch {};
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

/// True when the slice carries anything dyld would run as an image initializer.
fn hasInitializers(img: *const machre.Image) bool {
    for (img.sections) |sec| switch (sec.class) {
        .mod_init, .init_offsets => if (sec.size != 0) return true,
        else => {},
    };
    return img.findCmd(.ROUTINES) != null or img.findCmd(.ROUTINES_64) != null;
}

test "facts/tool_oracles: dyld_info -inits agrees that no corpus fixture has an initializer" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/dyld_info -inits") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        for (try archGroups(a, sec.body)) |g| {
            const arch = g.arch orelse continue;
            const i = sliceForArch(&opened.file, arch) orelse continue;
            // The body is `    -inits:` plus one line per initializer.
            var rows: usize = 0;
            var lines = std.mem.splitScalar(u8, g.body, '\n');
            while (lines.next()) |l| {
                const t = std.mem.trim(u8, l, " \t\r");
                if (t.len == 0 or std.mem.eql(u8, t, "-inits:")) continue;
                rows += 1;
            }
            const img = try opened.image(a, i);
            const got = hasInitializers(&img);
            if ((rows != 0) != got) {
                _ = fail(name, "{s}: dyld_info -inits lists {d} initializer(s), machre sees has_initializers={}", .{ arch, rows, got }) catch {};
                failures += 1;
            }
            if (rows != 0) {
                // No corpus fixture has one today; when one is added this oracle must grow from a
                // presence check into a per-address diff.
                _ = fail(name, "{s}: -inits is no longer empty — extend this test to diff addresses", .{arch}) catch {};
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

test "facts/tool_oracles: dyld_info -validate_only is clean and machre parses every slice whole" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for (all_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        const sec = truth.find(secs, "/usr/bin/dyld_info -validate_only") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        // dyld_info exits 0 and prints nothing but the per-slice banner when the image validates.
        // It is NOT equivalent to `machre --strict`: fake-upx validates for dyld but machre reports an
        // error-severity diagnostic for its renamed UPX_DATA segment. The comparable claim is the
        // structural one — dyld read every load command, so machre must not have truncated any.
        for (try archGroups(a, sec.body)) |g| {
            var extra: usize = 0;
            var lines = std.mem.splitScalar(u8, g.body, '\n');
            while (lines.next()) |l| if (std.mem.trim(u8, l, " \t\r").len != 0) {
                extra += 1;
            };
            if (extra != 0 or sec.exit != 0) {
                _ = fail(name, "dyld_info -validate_only is no longer clean ({d} line(s), exit {d}) — extend this test", .{ extra, sec.exit }) catch {};
                failures += 1;
                continue;
            }
            const arch = g.arch orelse continue;
            const i = sliceForArch(&opened.file, arch) orelse continue;
            const img = try opened.image(a, i);
            if (img.cmds_truncated or img.ncmds_parsed != img.hdr.ncmds) {
                _ = fail(name, "{s}: dyld validates the image but machre parsed {d}/{d} load commands (truncated={})", .{ arch, img.ncmds_parsed, img.hdr.ncmds, img.cmds_truncated }) catch {};
                failures += 1;
            }
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------------------------
// 5. `objdump --macho --objc-meta-data` — a PARTIAL oracle
// ---------------------------------------------------------------------------------------------
//
// This oracle is WRONG on our own fixture and must not be diffed wholesale. `truth/hello-objc.txt`
// carries 220 `extends past end of file` lines: every `name`/`types`/`imp` row inside an
// `entsize N (relative)` block. Relative method lists store 32-bit deltas from the field's own
// address, and objdump resolves the target address correctly (it prints it) but then bounds-checks it
// against the wrong extent, so it rejects addresses that are plainly inside the image —
// `-[MachreAnimal sound]` is flagged at 0x100001064, which is file offset 0x1064 of a 54 KiB file and
// exactly where `machre objc` reports that method. The test below proves that claim rather than
// asserting it: every flagged address is fed back through `Image.bytesAtVm`, which only answers for
// addresses that are actually backed by bytes in the file.
//
// So: assert the parts objdump gets right (class inventory and geometry, method counts, categories,
// protocols, selector references, image info), and whitelist the relative-method-list defect.

const ObjClass = struct {
    name: []const u8 = "",
    superclass: []const u8 = "",
    instance_start: ?i64 = null,
    instance_size: ?i64 = null,
    methods: ?i64 = null,
    class_methods: ?i64 = null,
};
const ObjCategory = struct { name: []const u8 = "", cls: []const u8 = "", methods: ?i64 = null };

const ObjdumpMeta = struct {
    classes: []const ObjClass,
    categories: []const ObjCategory,
    protocols: []const []const u8,
    selrefs: []const []const u8,
    image_version: ?i64,
    image_flags: []const u8,
    /// Addresses objdump rejected with "extends past end of file".
    flagged: []const u64,
    /// How many of those lines were NOT inside an `entsize N (relative)` block (must be zero — the
    /// defect is confined to relative method lists).
    flagged_outside_relative: usize,
};

fn indentOf(l: []const u8) usize {
    var n: usize = 0;
    while (n < l.len and l[n] == ' ') n += 1;
    return n;
}
/// The symbol an objdump pointer row names, with the ObjC decoration removed:
/// "superclass 0x0 _OBJC_CLASS_$_NSObject" -> "NSObject".
fn objcSymbolName(rest: []const u8) []const u8 {
    var toks = std.mem.tokenizeAny(u8, rest, " \t");
    _ = toks.next(); // the pointer
    const sym = toks.next() orelse return "";
    inline for (.{ "_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "__OBJC_PROTOCOL_$_" }) |p| {
        if (std.mem.startsWith(u8, sym, p)) return sym[p.len..];
    }
    return sym;
}
/// "name 0x100001982 MachreAnimal" -> "MachreAnimal" (the string, which follows the pointer).
fn afterPointer(rest: []const u8) []const u8 {
    var toks = std.mem.tokenizeAny(u8, rest, " \t");
    _ = toks.next();
    return std.mem.trim(u8, toks.rest(), " \t");
}

fn parseObjdump(arena: std.mem.Allocator, body: []const u8) !ObjdumpMeta {
    var classes: std.ArrayList(ObjClass) = .empty;
    var cats: std.ArrayList(ObjCategory) = .empty;
    var protos: std.ArrayList([]const u8) = .empty;
    var selrefs: std.ArrayList([]const u8) = .empty;
    var flagged: std.ArrayList(u64) = .empty;
    var outside: usize = 0;
    var image_version: ?i64 = null;
    var image_flags: []const u8 = "";

    const Sect = enum { none, classlist, catlist, protolist, selrefs, imageinfo };
    var sect: Sect = .none;
    var meta = false;
    var relative = false;
    // Which counter the next "count" line belongs to (objdump prints `entsize`/`count` right after the
    // list pointer it belongs to).
    var pending: ?*?i64 = null;

    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t\r");
        const t = std.mem.trim(u8, line, " \t");
        if (t.len == 0) continue;
        const ind = indentOf(line);

        if (std.mem.startsWith(u8, t, "Contents of ")) {
            sect = if (std.mem.find(u8, t, "__objc_classlist") != null) .classlist else if (std.mem.find(u8, t, "__objc_catlist") != null) .catlist else if (std.mem.find(u8, t, "__objc_protolist") != null) .protolist else if (std.mem.find(u8, t, "__objc_selrefs") != null) .selrefs else if (std.mem.find(u8, t, "__objc_imageinfo") != null) .imageinfo else .none;
            meta = false;
            relative = false;
            pending = null;
            continue;
        }
        if (std.mem.startsWith(u8, t, "entsize")) {
            relative = std.mem.find(u8, t, "(relative)") != null;
            continue;
        }
        if (std.mem.find(u8, t, "extends past end of file") != null) {
            if (!relative) outside += 1;
            if (std.mem.find(u8, t, "(0x")) |p| {
                const tail = t[p + 3 ..];
                const end = std.mem.findScalar(u8, tail, ' ') orelse tail.len;
                if (std.fmt.parseInt(u64, tail[0..end], 16)) |v| try flagged.append(arena, v) else |_| {}
            }
            continue;
        }
        if (std.mem.startsWith(u8, t, "count")) {
            if (pending) |slot| {
                slot.* = std.fmt.parseInt(i64, std.mem.trim(u8, t[5..], " \t"), 10) catch null;
                pending = null;
            }
            continue;
        }

        switch (sect) {
            .classlist => {
                if (ind == 0) {
                    if (std.mem.eql(u8, t, "Meta Class")) {
                        meta = true;
                    } else {
                        try classes.append(arena, .{});
                        meta = false;
                    }
                    relative = false;
                    pending = null;
                    continue;
                }
                if (classes.items.len == 0) continue;
                const c = &classes.items[classes.items.len - 1];
                if (ind == 4 and std.mem.startsWith(u8, t, "superclass ") and !meta) c.superclass = objcSymbolName(t[11..]);
                if (ind != 8) continue;
                if (std.mem.startsWith(u8, t, "name ") and !meta) c.name = afterPointer(t[5..]);
                if (std.mem.startsWith(u8, t, "instanceStart ") and !meta) c.instance_start = std.fmt.parseInt(i64, std.mem.trim(u8, t[14..], " \t"), 10) catch null;
                if (std.mem.startsWith(u8, t, "instanceSize ") and !meta) c.instance_size = std.fmt.parseInt(i64, std.mem.trim(u8, t[13..], " \t"), 10) catch null;
                if (std.mem.startsWith(u8, t, "baseMethods ")) {
                    const slot: *?i64 = if (meta) &c.class_methods else &c.methods;
                    if (std.mem.eql(u8, std.mem.trim(u8, t[12..], " \t"), "0x0")) slot.* = 0 else pending = slot;
                }
            },
            .catlist => {
                if (ind == 0) {
                    try cats.append(arena, .{});
                    relative = false;
                    pending = null;
                    continue;
                }
                if (cats.items.len == 0 or ind != 4) continue;
                const c = &cats.items[cats.items.len - 1];
                if (std.mem.startsWith(u8, t, "name ")) c.name = afterPointer(t[5..]);
                if (std.mem.startsWith(u8, t, "cls ")) c.cls = objcSymbolName(t[4..]);
                if (std.mem.startsWith(u8, t, "instanceMethods ")) {
                    if (std.mem.eql(u8, std.mem.trim(u8, t[16..], " \t"), "0x0")) c.methods = 0 else pending = &c.methods;
                }
            },
            .protolist => {
                if (ind == 0) {
                    try protos.append(arena, "");
                    relative = false;
                    pending = null;
                    continue;
                }
                if (protos.items.len == 0 or ind != 4) continue;
                if (std.mem.startsWith(u8, t, "name ")) protos.items[protos.items.len - 1] = afterPointer(t[5..]);
            },
            .selrefs => {
                if (ind == 0) continue;
                try selrefs.append(arena, afterPointer(t));
            },
            .imageinfo => {
                if (std.mem.startsWith(u8, t, "version ")) image_version = std.fmt.parseInt(i64, std.mem.trim(u8, t[8..], " \t"), 10) catch null;
                if (std.mem.startsWith(u8, t, "flags ")) {
                    var toks = std.mem.tokenizeAny(u8, t[6..], " \t");
                    image_flags = toks.next() orelse "";
                }
            },
            .none => {},
        }
    }
    return .{
        .classes = try classes.toOwnedSlice(arena),
        .categories = try cats.toOwnedSlice(arena),
        .protocols = try protos.toOwnedSlice(arena),
        .selrefs = try selrefs.toOwnedSlice(arena),
        .image_version = image_version,
        .image_flags = image_flags,
        .flagged = try flagged.toOwnedSlice(arena),
        .flagged_outside_relative = outside,
    };
}

fn jsonStr(v: std.json.Value, key: []const u8) []const u8 {
    const x = helpers.Summary.get(v, key) orelse return "";
    return switch (x) {
        .string => |s| s,
        else => "",
    };
}
fn jsonLen(v: std.json.Value, key: []const u8) i64 {
    const a = helpers.Summary.array(v, key) orelse return -1;
    return @intCast(a.len);
}

test "facts/tool_oracles: objdump --objc-meta-data is a partial oracle (relative method lists are objdump's bug)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var checked: usize = 0;
    var failures: usize = 0;
    for ([_][]const u8{ "hello-objc", "Hello.app" }) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const secs = (try sections(a, io, name)) orelse continue;
        // The section is keyed by objdump's absolute Xcode path, so match on the flags.
        const sec = findContaining(secs, "--macho --objc-meta-data") orelse continue;
        var opened = (try openFixture(gpa, a, io, name)) orelse continue;
        defer opened.file.deinit(gpa);
        checked += 1;

        const want = try parseObjdump(a, sec.body);
        const path = try helpers.summaryFixturePath(a, name);
        const r = try helpers.runMachre(a, io, &.{ "objc", "--json", "--no-security", path });
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
        defer parsed.deinit();
        const objc = helpers.Summary.get(parsed.value.object.get("arches").?.array.items[0], "objc").?;

        // ---- the whitelisted defect, verified rather than assumed ----
        if (want.flagged.len == 0) {
            _ = fail(name, "no 'extends past end of file' lines — objdump's relative-method-list defect is gone, re-check this whitelist", .{}) catch {};
            failures += 1;
        }
        if (want.flagged_outside_relative != 0) {
            _ = fail(name, "{d} 'extends past end of file' line(s) outside an `entsize N (relative)` block — the whitelist only covers relative method lists", .{want.flagged_outside_relative}) catch {};
            failures += 1;
        }
        const img = try opened.image(a, 0);
        var not_backed: usize = 0;
        for (want.flagged) |addr| if (img.bytesAtVm(addr, 1) == null) {
            not_backed += 1;
        };
        if (not_backed != 0) {
            _ = fail(name, "{d} of {d} addresses objdump called past-EOF really are unmapped — machre's resolution would be the wrong one", .{ not_backed, want.flagged.len }) catch {};
            failures += 1;
        }

        // ---- the parts objdump gets right ----
        const got_classes = helpers.Summary.array(objc, "classes") orelse &.{};
        if (want.classes.len != got_classes.len) {
            _ = fail(name, "objdump lists {d} classes, machre {d}", .{ want.classes.len, got_classes.len }) catch {};
            failures += 1;
        } else for (want.classes, got_classes) |w, g| {
            const gname = jsonStr(g, "name");
            const gsuper = if (helpers.Summary.get(g, "superclass")) |s| jsonStr(s, "name") else "";
            if (!std.mem.eql(u8, w.name, gname) or !std.mem.eql(u8, w.superclass, gsuper) or
                w.instance_start != helpers.Summary.int(g, "instance_start") or
                w.instance_size != helpers.Summary.int(g, "instance_size") or
                w.methods != jsonLen(g, "methods") or w.class_methods != jsonLen(g, "class_methods"))
            {
                _ = fail(name, "class: objdump {s}:{s} start={?d} size={?d} methods={?d}/{?d}, machre {s}:{s} start={?d} size={?d} methods={d}/{d}", .{
                    w.name,          w.superclass,  w.instance_start,                          w.instance_size,                          w.methods, w.class_methods,
                    gname, gsuper, helpers.Summary.int(g, "instance_start"), helpers.Summary.int(g, "instance_size"), jsonLen(g, "methods"), jsonLen(g, "class_methods"),
                }) catch {};
                failures += 1;
            }
        }

        const got_cats = helpers.Summary.array(objc, "categories") orelse &.{};
        if (want.categories.len != got_cats.len) {
            _ = fail(name, "objdump lists {d} categories, machre {d}", .{ want.categories.len, got_cats.len }) catch {};
            failures += 1;
        } else for (want.categories, got_cats) |w, g| {
            if (!std.mem.eql(u8, w.name, jsonStr(g, "name")) or !std.mem.eql(u8, w.cls, jsonStr(g, "class_name")) or w.methods != jsonLen(g, "instance_methods")) {
                _ = fail(name, "category: objdump {s} on {s} ({?d} methods), machre {s} on {s} ({d})", .{ w.name, w.cls, w.methods, jsonStr(g, "name"), jsonStr(g, "class_name"), jsonLen(g, "instance_methods") }) catch {};
                failures += 1;
            }
        }

        const got_protos = helpers.Summary.array(objc, "protocols") orelse &.{};
        if (want.protocols.len != got_protos.len) {
            _ = fail(name, "objdump lists {d} protocols, machre {d}", .{ want.protocols.len, got_protos.len }) catch {};
            failures += 1;
        } else for (want.protocols, got_protos) |w, g| {
            if (!std.mem.eql(u8, w, jsonStr(g, "name"))) {
                _ = fail(name, "protocol: objdump '{s}', machre '{s}'", .{ w, jsonStr(g, "name") }) catch {};
                failures += 1;
            }
        }

        const got_sels = helpers.Summary.array(objc, "selectors") orelse &.{};
        if (want.selrefs.len != got_sels.len) {
            _ = fail(name, "objdump lists {d} selector refs, machre {d}", .{ want.selrefs.len, got_sels.len }) catch {};
            failures += 1;
        } else for (want.selrefs, got_sels) |w, g| {
            if (!std.mem.eql(u8, w, jsonStr(g, "name"))) {
                _ = fail(name, "selref: objdump '{s}', machre '{s}'", .{ w, jsonStr(g, "name") }) catch {};
                failures += 1;
            }
        }

        const ii = helpers.Summary.get(objc, "image_info") orelse .null;
        const got_flags = if (helpers.Summary.get(ii, "flags")) |f| jsonStr(f, "value") else "";
        if (want.image_version != helpers.Summary.int(ii, "version") or !std.mem.eql(u8, want.image_flags, got_flags)) {
            _ = fail(name, "imageinfo: objdump version={?d} flags={s}, machre version={?d} flags={s}", .{ want.image_version, want.image_flags, helpers.Summary.int(ii, "version"), got_flags }) catch {};
            failures += 1;
        }
    }
    if (failures != 0) return error.OracleMismatch;
    if (checked == 0) return error.SkipZigTest;
}
