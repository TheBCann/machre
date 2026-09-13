//! disasm/capstone.zig — Capstone 5 externs behind build_options.have_capstone. Imports: disasm/insn, core/arch, core/sanitize.
//!
//! The ABI facts (struct layout, option numbers, arch/mode constants) are disasm-notes A.2, reproduced
//! by a C `offsetof` probe and pinned by the `comptime` asserts at the bottom of this file. Capstone is
//! used for TEXT ONLY: the engine overlays `mnemonic`/`op_str` on records whose `(address, size)` the
//! built-in decoder already produced, so a Capstone that disagrees can never move an instruction
//! boundary or change a semantic field.
const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");
const ArchName = @import("../core/arch.zig").ArchName;
const sanitize = @import("../core/sanitize.zig");

pub const available: bool = build_options.have_capstone;
pub const OpenError = error{ CapstoneUnavailable, CapstoneOpen, UnsupportedArch };

/// Capstone (arch, mode) for a Mach-O arch, or null when no Capstone backend covers it.
fn archMode(arch: ArchName) ?struct { arch: c_int, mode: c_int } {
    return switch (arch) {
        .arm64, .arm64e, .arm64v8, .arm64_32 => .{ .arch = CS_ARCH_ARM64, .mode = CS_MODE_ARM },
        .x86_64, .x86_64h => .{ .arch = CS_ARCH_X86, .mode = CS_MODE_64 },
        else => null,
    };
}

pub const Handle = struct {
    csh: usize,
    arch: ArchName,
    /// `att` is applied only for x86_64 (CS_OPT_SYNTAX_ATT is invalid on an ARM64 handle).
    pub fn open(arch: ArchName, att: bool) OpenError!Handle {
        if (!available) return error.CapstoneUnavailable;
        const am = archMode(arch) orelse return error.UnsupportedArch;
        var csh: usize = 0;
        if (cs_open(am.arch, am.mode, &csh) != CS_ERR_OK) return error.CapstoneOpen;
        // DETAIL off (we never read cs_detail), SKIPDATA on so an undecodable word still yields a record.
        _ = cs_option(csh, CS_OPT_DETAIL, CS_OPT_OFF);
        _ = cs_option(csh, CS_OPT_SKIPDATA, CS_OPT_ON);
        if (att and am.arch == CS_ARCH_X86) _ = cs_option(csh, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        return .{ .csh = csh, .arch = arch };
    }
    pub fn close(h: *Handle) void {
        if (!available) return;
        if (h.csh == 0) return;
        _ = cs_close(&h.csh);
        h.csh = 0;
    }
};
pub const Text = struct { addr: u64, size: u8, mnemonic: []const u8, operands: []const u8, id: u32 };
/// Decodes `code` (SKIPDATA on, DETAIL off) into arena-owned text records; never fewer than one record per
/// undecodable unit. Used by engine.zig only to overlay text on the built-in decoder's semantic records.
pub fn decodeText(h: *Handle, arena: Allocator, code: []const u8, base: u64, max: u32) Allocator.Error![]Text {
    if (!available) return &.{};
    if (code.len == 0 or h.csh == 0) return &.{};
    var raw: ?[*]CsInsn = null;
    const n = cs_disasm(h.csh, code.ptr, code.len, base, max, &raw);
    const items = raw orelse return &.{};
    defer cs_free(items, n);
    if (n == 0) return &.{};
    const out = try arena.alloc(Text, n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ci = &items[i];
        out[i] = .{
            .addr = ci.address,
            .size = if (ci.size > 255) 255 else @intCast(ci.size),
            // Dupe FIRST, then sanitize: `sanitize.forText` returns its input unchanged when the
            // string is clean, so handing it `&ci.mnemonic` (a field of a stack-local `cs_insn`)
            // would leave the result dangling once this frame dies. The arena copy is the input.
            //
            // Capstone composes these from its own static tables, so on clean input this is a
            // no-op; it is defence in depth against a library bug emitting a control byte, and it
            // keeps the "no file-derived or library-derived bytes reach the terminal raw"
            // invariant true for the one path `cmd/disasm.zig` writes without `sink.safe`.
            .mnemonic = try sanitize.forText(arena, try arena.dupe(u8, std.mem.sliceTo(&ci.mnemonic, 0)), null),
            .operands = try sanitize.forText(arena, try arena.dupe(u8, std.mem.sliceTo(&ci.op_str, 0)), null),
            .id = @intCast(ci.id),
        };
    }
    return out;
}
pub fn version() ?struct { major: u8, minor: u8 } {
    if (!available) return null;
    var major: c_int = 0;
    var minor: c_int = 0;
    _ = cs_version(&major, &minor);
    if (major < 0 or minor < 0) return null;
    return .{ .major = @intCast(@min(major, 255)), .minor = @intCast(@min(minor, 255)) };
}

/// Human-readable backend name for listings and JSON.
pub fn backendLabel() []const u8 {
    return if (available) "capstone" else "capstone (not linked)";
}

const CsInsn = extern struct { id: c_uint, address: u64, size: u16, bytes: [24]u8, mnemonic: [32]u8, op_str: [160]u8, detail: ?*anyopaque };
comptime {
    std.debug.assert(@sizeOf(CsInsn) == 248);
    std.debug.assert(@offsetOf(CsInsn, "detail") == 240);
    std.debug.assert(@offsetOf(CsInsn, "id") == 0);
    std.debug.assert(@offsetOf(CsInsn, "address") == 8);
    std.debug.assert(@offsetOf(CsInsn, "size") == 16);
    std.debug.assert(@offsetOf(CsInsn, "bytes") == 18);
    std.debug.assert(@offsetOf(CsInsn, "mnemonic") == 42);
    std.debug.assert(@offsetOf(CsInsn, "op_str") == 74);
    std.debug.assert(@alignOf(CsInsn) == 8);
}
const CS_ARCH_ARM64: c_int = 1;
const CS_ARCH_X86: c_int = 3;
const CS_MODE_ARM: c_int = 0;
const CS_MODE_64: c_int = 1 << 3;
const CS_OPT_SYNTAX: c_int = 1;
const CS_OPT_DETAIL: c_int = 2;
const CS_OPT_SKIPDATA: c_int = 5;
const CS_OPT_OFF: usize = 0;
const CS_OPT_ON: usize = 3;
const CS_OPT_SYNTAX_ATT: usize = 2;
const CS_ERR_OK: c_int = 0;
extern fn cs_version(major: ?*c_int, minor: ?*c_int) c_uint;
extern fn cs_open(arch: c_int, mode: c_int, handle: *usize) c_int;
extern fn cs_close(handle: *usize) c_int;
extern fn cs_option(handle: usize, opt_type: c_int, value: usize) c_int;
extern fn cs_disasm(handle: usize, code: [*]const u8, code_size: usize, address: u64, count: usize, out: *?[*]CsInsn) usize;
extern fn cs_free(out: [*]CsInsn, count: usize) void;
extern fn cs_strerror(code: c_int) [*:0]const u8;

test "capstone: arch mapping and the unavailable path are total" {
    try std.testing.expect(archMode(.arm64) != null);
    try std.testing.expect(archMode(.arm64e) != null);
    try std.testing.expect(archMode(.x86_64) != null);
    try std.testing.expect(archMode(.x86_64h) != null);
    try std.testing.expect(archMode(.ppc64) == null);
    try std.testing.expect(archMode(.i386) == null);
    if (available) {
        try std.testing.expectError(error.UnsupportedArch, Handle.open(.ppc, false));
    } else {
        // Without the library the unavailable error wins, before any arch check.
        try std.testing.expectError(error.CapstoneUnavailable, Handle.open(.ppc, false));
    }
}

test "capstone: decodes the arm64 and x86 prologue words when linked" {
    if (!available) {
        try std.testing.expectError(error.CapstoneUnavailable, Handle.open(.arm64, false));
        try std.testing.expect(version() == null);
        var dummy: Handle = .{ .csh = 0, .arch = .arm64 };
        try std.testing.expectEqual(@as(usize, 0), (try decodeText(&dummy, std.testing.allocator, "abcd", 0, 0)).len);
        return;
    }
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Handle.open(.arm64e, false);
    defer h.close();
    // add x0, x0, #0x68 ; add x1, x1, #0x68 ; b . ; mov x8, x0
    const code = [_]u8{ 0x00, 0xa0, 0x01, 0x91, 0x21, 0xa0, 0x01, 0x91, 0xe1, 0x0f, 0x00, 0x14, 0xe8, 0x03, 0x00, 0xaa };
    const recs = try decodeText(&h, arena, &code, 0x100000700, 0);
    try std.testing.expectEqual(@as(usize, 4), recs.len);
    try std.testing.expectEqual(@as(u64, 0x100000700), recs[0].addr);
    try std.testing.expectEqualStrings("add", recs[0].mnemonic);
    try std.testing.expectEqual(@as(u8, 4), recs[3].size);

    // A zero word decodes as `udf` — Capstone never stops on padding (disasm-notes E.1).
    const zero = try decodeText(&h, arena, &[_]u8{ 0, 0, 0, 0 }, 0, 0);
    try std.testing.expectEqual(@as(usize, 1), zero.len);

    var hx = try Handle.open(.x86_64, true);
    defer hx.close();
    const xcode = [_]u8{ 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3 };
    const xrecs = try decodeText(&hx, arena, &xcode, 0x100000718, 0);
    try std.testing.expectEqual(@as(usize, 4), xrecs.len);
    try std.testing.expectEqual(@as(u8, 1), xrecs[0].size);
    try std.testing.expectEqual(@as(u8, 3), xrecs[1].size);
    // ATT syntax was requested and IS valid on an x86 handle.
    try std.testing.expectEqualStrings("pushq", xrecs[0].mnemonic);

    const v = version().?;
    try std.testing.expectEqual(@as(u8, 5), v.major);
    try std.testing.expectEqualStrings("capstone", backendLabel());
}

test "capstone: empty input and a closed handle return no records" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var h: Handle = if (available) try Handle.open(.arm64, false) else .{ .csh = 0, .arch = .arm64 };
    defer h.close();
    try std.testing.expectEqual(@as(usize, 0), (try decodeText(&h, arena, &.{}, 0, 0)).len);
    h.close();
    try std.testing.expectEqual(@as(usize, 0), (try decodeText(&h, arena, "\x00\x00\x00\x00", 0, 0)).len);
    h.close(); // idempotent
}
