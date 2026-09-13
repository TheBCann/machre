//! tests/sanitize_tests.zig — output must be inert.
//!
//! A crafted Mach-O can put ANSI escape sequences, carriage returns, NULs and invalid UTF-8 into any
//! field machre prints (segment/section names, dylib install names, the dylinker path, symbol names,
//! ObjC names, plist keys and values, code-signing identifiers, quarantine agents, bundle paths, and
//! every diagnostic that interpolates one). Raw, those bytes recolour the analyst's terminal, overwrite
//! already-printed lines and can forge a clean-looking verdict.
//!
//! These tests assert the invariant directly on the bytes machre writes: valid UTF-8, and no C0
//! control character other than newline and tab, and no DEL — for every command, in text and in JSON.
//! Fixtures are built in-process by poking equal-length hostile byte patterns into a healthy corpus
//! fixture, so nothing has to be committed and the file layout stays parseable.
const std = @import("std");
const Io = std.Io;
const machre = @import("machre");
const build_options = @import("build_options");
pub const helpers = @import("helpers.zig");

// ---------------------------------------------------------------------------------------------
// the invariant
// ---------------------------------------------------------------------------------------------

/// machre's own layout uses newline and tab (the codesign entitlements tree is tab-indented); nothing
/// else below 0x20, and never DEL, may reach the output, and the whole stream must be valid UTF-8.
pub fn expectInert(out: []const u8, what: []const u8) !void {
    for (out, 0..) |b, i| {
        if (b == 0x7f or (b < 0x20 and b != '\n' and b != '\t')) {
            const lo = if (i > 60) i - 60 else 0;
            std.debug.print("{s}: raw control byte 0x{x:0>2} at offset {d}: '{f}'\n", .{ what, b, i, std.ascii.hexEscape(out[lo..@min(out.len, i + 20)], .lower) });
            return error.ControlByteInOutput;
        }
    }
    if (!std.unicode.utf8ValidateSlice(out)) {
        std.debug.print("{s}: output is not valid UTF-8\n", .{what});
        return error.InvalidUtf8InOutput;
    }
}

/// Every command that takes a path (all but `version`).
fn pathCommands() []const machre.context.Command {
    return machre.cli.commands[0 .. machre.cli.commands.len - 1];
}

const Run = struct { code: u8, out: []u8 };

/// One in-process command run with its stdout captured. `gpa` owns the returned bytes.
fn run(gpa: std.mem.Allocator, io: Io, cmd: []const u8, path: [:0]const u8, as_json: bool, extra: []const [:0]const u8) !Run {
    var outw: Io.Writer.Allocating = .init(gpa);
    errdefer outw.deinit();
    var ebuf: [256]u8 = undefined;
    var errw: Io.Writer.Discarding = .init(&ebuf);
    var argv: [8][:0]const u8 = undefined;
    var n: usize = 0;
    argv[n] = @ptrCast(cmd);
    n += 1;
    argv[n] = "--no-security";
    n += 1;
    argv[n] = "--no-network";
    n += 1;
    if (as_json) {
        argv[n] = "--json";
        n += 1;
    }
    for (extra) |e| {
        argv[n] = e;
        n += 1;
    }
    argv[n] = path;
    n += 1;
    const code = machre.cli.runArgv(gpa, io, argv[0..n], &outw.writer, &errw.writer);
    return .{ .code = code, .out = try outw.toOwnedSlice() };
}

/// Runs every path command over `path` in text and JSON and asserts the invariant on each.
fn expectAllCommandsInert(gpa: std.mem.Allocator, io: Io, path: [:0]const u8, label: []const u8) !void {
    for (pathCommands()) |cmd| {
        for ([_]bool{ false, true }) |as_json| {
            const r = try run(gpa, io, cmd.name, path, as_json, &.{});
            defer gpa.free(r.out);
            var buf: [128]u8 = undefined;
            const what = std.fmt.bufPrint(&buf, "{s}: machre {s}{s}", .{ label, cmd.name, if (as_json) " --json" else "" }) catch label;
            try expectInert(r.out, what);
            if (as_json) {
                var parsed = std.json.parseFromSlice(std.json.Value, gpa, r.out, .{}) catch {
                    std.debug.print("{s}: --json output does not parse\n", .{what});
                    return error.JsonDidNotParse;
                };
                parsed.deinit();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// hostile fixture: equal-length pokes into a healthy binary, so the layout stays parseable
// ---------------------------------------------------------------------------------------------

fn poke(buf: []u8, needle: []const u8, repl: []const u8) !void {
    std.debug.assert(needle.len == repl.len);
    const i = std.mem.find(u8, buf, needle) orelse {
        std.debug.print("fixture no longer contains {f}\n", .{std.ascii.hexEscape(needle, .lower)});
        return error.FixtureStringMissing;
    };
    @memcpy(buf[i..][0..repl.len], repl);
}

/// `hello-usedylib` with ESC/CR/BEL/BS/NUL/invalid-UTF-8 in a segment name, a section name, the
/// dylinker path, both dylib install names and a symbol-table name, AND one `bl` retargeted so the
/// poked symbol is a genuine branch target. Caller owns the bytes.
///
/// The retarget is what makes this fixture able to catch the `--otool-compat` operand-substitution
/// leak: `symbolize` substitutes a symbol name into `Insn.operands` only for a branch whose TARGET
/// carries a symbol, and nothing in stock `hello-usedylib` branches to `_main`, so the hostile name
/// never reached that code path however many commands the test ran.
pub fn hostileBytes(gpa: std.mem.Allocator, io: Io) ![]u8 {
    const buf = try helpers.readFixture(io, gpa, "hello-usedylib");
    errdefer gpa.free(buf);
    // 16-byte segment name: SGR + CR, unterminated-looking, exactly the reported repro.
    try poke(buf, "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "\x1b[31mPWNED\x1b[0m\r\x00");
    // 16-byte section name: BEL, backspace and a lone continuation byte (invalid UTF-8).
    try poke(buf, "__cstring\x00\x00\x00\x00\x00\x00\x00", "c\x07\x08\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    // LC_LOAD_DYLIB / LC_ID_DYLIB install names and the LC_LOAD_DYLINKER path.
    try poke(buf, "/usr/lib/libSystem.B.dylib", "/usr/\x1b[2Jlib\rSystem.B.dylb");
    try poke(buf, "@rpath/libhello.dylib", "@rpath/lib\rhello.dyli");
    try poke(buf, "/usr/lib/dyld", "/usr\x1b[31mdyld");
    // String-table symbol name.
    try poke(buf, "_main", "_m\x1bin");
    // `bl 0x100000550` at 0x100000508 -> `bl _main` (0x1000004e8): imm26 = -8, so 0x97fffff8.
    // Now the hostile symbol name IS a branch target and `--otool-compat` substitutes it as an OPERAND.
    try poke(buf, "\x12\x00\x00\x94", "\xf8\xff\xff\x97");
    return buf;
}

/// `hello-x86_64` with ESC in `_greeting`, whose address is reached by a rip-relative `movq` — the
/// second place a file-derived name enters `Insn.operands` (`symbolize.otoolX86Operands` rewrites
/// `movq 0x…(%rip), %r9` to `movq _greeting(%rip), %r9` under `--otool-compat`). Caller owns the bytes.
pub fn hostileX86Bytes(gpa: std.mem.Allocator, io: Io) ![]u8 {
    const buf = try helpers.readFixture(io, gpa, "hello-x86_64");
    errdefer gpa.free(buf);
    try poke(buf, "_greeting", "_g\x1b[31mPW");
    try poke(buf, "_add_numbers", "_add\x1b[31mPWN"); // also a `callq` target
    return buf;
}

/// Writes `bytes` into a fresh temp dir and returns (dir, absolute path); caller cleans the dir up.
fn writeTemp(arena: std.mem.Allocator, io: Io, tmp: *std.testing.TmpDir, name: []const u8, bytes: []const u8) ![:0]const u8 {
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

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

test "sanitize: crafted names never put control bytes on the terminal or in JSON" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bytes = try hostileBytes(gpa, io);
    defer gpa.free(bytes);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try writeTemp(arena, io, &tmp, "hostile.bin", bytes);

    try expectAllCommandsInert(gpa, io, path, "hostile");

    // The escape must actually have reached a renderer (otherwise the test proves nothing): the
    // segment name is shown escaped, and the lossy tally is reported the way `strings` reports it.
    const seg = try run(gpa, io, "segments", path, false, &.{});
    defer gpa.free(seg.out);
    try std.testing.expect(std.mem.find(u8, seg.out, "\\x1b[31mPWNED\\x1b[0m\\x0d") != null);
    try std.testing.expect(std.mem.find(u8, seg.out, "sanitized") != null);
    try std.testing.expect(std.mem.find(u8, seg.out, "cli.invalid_utf8") != null);

    // Symbol names, dylib paths and the dylinker path are escaped too, not dropped.
    const info = try run(gpa, io, "info", path, false, &.{});
    defer gpa.free(info.out);
    try std.testing.expect(std.mem.find(u8, info.out, "/usr\\x1b[31mdyld") != null);
    try std.testing.expect(std.mem.find(u8, info.out, "@rpath/lib\\x0dhello.dyli") != null);
    const syms = try run(gpa, io, "symbols", path, false, &.{});
    defer gpa.free(syms.out);
    try std.testing.expect(std.mem.find(u8, syms.out, "_m\\x1bin") != null);

    // JSON keeps the originals recoverable: U+FFFD in the string plus `<key>_hex` / `<key>_lossy`.
    const js = try run(gpa, io, "segments", path, true, &.{});
    defer gpa.free(js.out);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, js.out, .{});
    defer parsed.deinit();
    const seg0 = parsed.value.object.get("arches").?.array.items[0].object.get("segments").?.array.items[1].object;
    try std.testing.expect(seg0.get("name_lossy").?.bool);
    try std.testing.expect(std.mem.find(u8, seg0.get("name_hex").?.string, "1b5b33316d") != null);
    try std.testing.expect(parsed.value.object.get("sanitized_strings").?.integer > 0);
}

test "sanitize: otool-compat modes stay inert on a hostile file" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bytes = try hostileBytes(gpa, io);
    defer gpa.free(bytes);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try writeTemp(arena, io, &tmp, "hostile.bin", bytes);
    const x86 = try hostileX86Bytes(gpa, io);
    defer gpa.free(x86);
    const x86_path = try writeTemp(arena, io, &tmp, "hostile-x86.bin", x86);

    // `--otool-compat` is byte-exactness with Apple's tools for healthy input only; on hostile input
    // machre deliberately diverges from otool (which prints the escape raw) and escapes instead.
    //
    // `disasm`/`functions`/`xrefs` are in this list because they are the three commands that render a
    // file-derived symbol name OUTSIDE the label/comment columns that `Sink.safe` covers: under
    // `--otool-compat` the symbolizer substitutes the name into `Insn.operands` (`bl "_name"`,
    // `movq _name(%rip), %r9`) and `functions` prints `dyld_info`'s name column. Both fixtures are
    // built so those substitutions actually fire — see `hostileBytes` / `hostileX86Bytes`.
    const commands = [_][]const u8{ "loadcmds", "symbols", "imports", "dyld", "codesign", "entitlements", "disasm", "functions", "xrefs" };
    for ([_][:0]const u8{ path, x86_path }) |p| {
        for (commands) |cmd| {
            const r = try run(gpa, io, cmd, p, false, &.{"--otool-compat"});
            defer gpa.free(r.out);
            var buf: [64]u8 = undefined;
            try expectInert(r.out, std.fmt.bufPrint(&buf, "otool-compat {s}", .{cmd}) catch cmd);
        }
    }

    // Proof the fixtures reach the operand path at all: without the escaping these lines carry a raw
    // ESC, and `expectInert` above would fire. The escaped spelling is what an analyst must see.
    const arm_dis = try run(gpa, io, "disasm", path, false, &.{"--otool-compat"});
    defer gpa.free(arm_dis.out);
    try std.testing.expect(std.mem.find(u8, arm_dis.out, "bl\t\"_m\\x1bin\"") != null);
    const x86_dis = try run(gpa, io, "disasm", x86_path, false, &.{"--otool-compat"});
    defer gpa.free(x86_dis.out);
    try std.testing.expect(std.mem.find(u8, x86_dis.out, "\"_add\\x1b[31mPWN\"") != null);
    // The rip-relative rewrite (`symbolize.otoolX86Operands`) only runs over Capstone text; the
    // built-in x86 length decoder prints `db` and never reaches an operand substitution at all.
    if (build_options.have_capstone)
        try std.testing.expect(std.mem.find(u8, x86_dis.out, "_g\\x1b[31mPW(%rip)") != null);
    // `functions --otool-compat` prints dyld_info's name column, which is the same file-derived name.
    const fns = try run(gpa, io, "functions", x86_path, false, &.{"--otool-compat"});
    defer gpa.free(fns.out);
    try std.testing.expect(std.mem.find(u8, fns.out, "_add\\x1b[31mPWN") != null);
}

test "sanitize: legitimate non-ASCII UTF-8 in a plist survives unchanged" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0"><dict>
        \\<key>CFBundleName</key><string>Café Münster 日本語 🔒</string>
        \\<key>CFBundleIdentifier</key><string>com.example.café</string>
        \\<key>Evil</key><string>before
    ++ "\x1b[31m" ++
        \\after</string>
        \\</dict></plist>
    ;
    const path = try writeTemp(arena, io, &tmp, "Info.plist", xml);
    const r = try run(gpa, io, "plist", path, false, &.{});
    defer gpa.free(r.out);
    try expectInert(r.out, "plist text");
    // Unicode passes through verbatim; the escape is neutralised. plist/entitlement *values* are the
    // one place machre replaces rather than escapes: `plist.parseAny` sanitises every key and string
    // once, at parse time, with the `.json` policy (DESIGN.md §6.2), so an ESC is already U+FFFD by
    // the time any renderer sees it, and the text renderer escapes whatever is left (`\r`, `\n`, tab).
    try std.testing.expect(std.mem.find(u8, r.out, "Café Münster 日本語 🔒") != null);
    try std.testing.expect(std.mem.find(u8, r.out, "com.example.café") != null);
    try std.testing.expect(std.mem.find(u8, r.out, "\u{FFFD}[31m") != null);

    const j = try run(gpa, io, "plist", path, true, &.{});
    defer gpa.free(j.out);
    try expectInert(j.out, "plist json");
    try std.testing.expect(std.mem.find(u8, j.out, "Café Münster 日本語 🔒") != null);
}

test "sanitize: every command over the malformed corpus emits inert output" {
    const io = std.testing.io;
    const gpa = std.heap.c_allocator; // thousands of runs; leak checking is covered by the robustness matrix
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (helpers.malformed_fixtures) |name| {
        const rel = try std.fmt.allocPrint(arena, "malformed/{s}", .{name});
        const path = try helpers.fixturePath(arena, rel);
        try expectAllCommandsInert(gpa, io, path, name);
    }
}

/// The mutation family that produced the reported artifacts (`<fixture>.offsets.N.bin`,
/// `<fixture>.lc.N.bin`): seeded byte flips, u32 pokes at 4-byte-aligned offsets and truncations.
fn mutate(random: std.Random, orig: []const u8, mutant: []u8) usize {
    @memcpy(mutant, orig);
    var len: usize = orig.len;
    const ops = random.intRangeAtMost(u8, 1, 8);
    var k: u8 = 0;
    while (k < ops) : (k += 1) {
        if (len == 0) break;
        switch (random.uintLessThan(u8, 3)) {
            0 => mutant[random.uintLessThan(usize, len)] ^= random.int(u8),
            1 => {
                if (len < 4) continue;
                const off = random.uintLessThan(usize, len / 4) * 4;
                const vals = [_]u32{ 0, 0xFFFFFFFF, 0x7FFFFFF0, @truncate(orig.len), @truncate(orig.len + 1) };
                std.mem.writeInt(u32, mutant[off..][0..4], vals[random.uintLessThan(usize, vals.len)], .little);
            },
            else => len = random.uintLessThan(usize, len + 1),
        }
    }
    return len;
}

test "sanitize: deterministic mutation sweep never leaks control bytes" {
    const io = std.testing.io;
    const gpa = std.heap.c_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for (helpers.healthy_fixtures) |name| {
        const orig = try helpers.readFixture(io, gpa, name);
        defer gpa.free(orig);
        const mutant = try gpa.alloc(u8, orig.len);
        defer gpa.free(mutant);
        var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0x5A17, name));
        var round: u32 = 0;
        while (round < 12) : (round += 1) {
            const len = mutate(prng.random(), orig, mutant);
            const path = try writeTemp(arena, io, &tmp, "mutant.bin", mutant[0..len]);
            var buf: [96]u8 = undefined;
            const label = std.fmt.bufPrint(&buf, "{s} round {d}", .{ name, round }) catch name;
            try expectAllCommandsInert(gpa, io, path, label);
        }
    }
}

// A hostile FILENAME is the same class of defect as a hostile byte inside the file: argv is
// attacker-influenced whenever the name comes out of an archive, a download, or a sample set.
// `Context.display_path` is the sanitized spelling every renderer prints; `Context.path` stays raw
// because it is what we open. This test pins that split — it fails if any renderer reverts to
// printing `ctx.path`.
test "sanitize: a control-character filename is inert in every command" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A healthy binary under a hostile name: the file content is clean, so anything that leaks
    // can only have come from the path.
    const bytes = try helpers.readFixture(io, gpa, "hello-c");
    defer gpa.free(bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // ESC opens an SGR sequence, CR returns the cursor to column 0 so a later write overprints
    // whatever the analyst already read. Both must come back escaped.
    const path = writeTemp(arena, io, &tmp, "ev\x1b[31mIL\x1b[0m\rbin", bytes) catch |e| switch (e) {
        // Some filesystems reject control bytes in names; the defect is still covered by the
        // in-file fixtures above, so skip rather than fail on such a host.
        error.BadPathName => return error.SkipZigTest,
        else => return e,
    };

    try expectAllCommandsInert(gpa, io, path, "hostile-filename");

    // Non-vacuous: the escape really did reach a renderer, in escaped form.
    const info = try run(gpa, io, "info", path, false, &.{});
    defer gpa.free(info.out);
    try std.testing.expect(std.mem.find(u8, info.out, "ev\\x1b[31mIL\\x1b[0m\\x0dbin") != null);
    try std.testing.expect(std.mem.find(u8, info.out, "\x1b") == null);
    try std.testing.expect(std.mem.find(u8, info.out, "\r") == null);
}
