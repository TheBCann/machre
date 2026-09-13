//! core/loadcmds.zig — bounds-checked load-command walker + typed decoders.
//! Imports: reader, diag, limits, version, macho_extra.
const std = @import("std");
const macho = std.macho;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;
const version = @import("version.zig");
pub const extra = @import("macho_extra.zig");

pub const Header = struct {
    magic: u32,
    is_64: bool,
    endian: std.builtin.Endian, // .little for MH_MAGIC(_64); .big for MH_CIGAM(_64)
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    header_size: u32, // 28 or 32

    pub const ParseError = error{ NotMachO, Truncated };
    /// Validates magic and that the header fits; never reads outside `r`.
    pub fn parse(r: Reader) ParseError!Header {
        const raw = r.u32At(0, .little) orelse return error.Truncated;
        const Kind = struct { is_64: bool, endian: std.builtin.Endian };
        const k: Kind = switch (raw) {
            macho.MH_MAGIC_64 => .{ .is_64 = true, .endian = .little },
            macho.MH_CIGAM_64 => .{ .is_64 = true, .endian = .big },
            macho.MH_MAGIC => .{ .is_64 = false, .endian = .little },
            macho.MH_CIGAM => .{ .is_64 = false, .endian = .big },
            else => return error.NotMachO,
        };
        const is_64 = k.is_64;
        const endian = k.endian;
        const header_size: u32 = if (is_64) 32 else 28;
        if (!r.contains(0, header_size)) return error.Truncated;
        return .{
            .magic = raw,
            .is_64 = is_64,
            .endian = endian,
            .cputype = @bitCast(r.u32At(4, endian).?),
            .cpusubtype = @bitCast(r.u32At(8, endian).?),
            .filetype = r.u32At(12, endian).?,
            .ncmds = r.u32At(16, endian).?,
            .sizeofcmds = r.u32At(20, endian).?,
            .flags = r.u32At(24, endian).?,
            .header_size = header_size,
        };
    }
};

/// A raw, bounds-validated load command: `cmd` may be any value (non-exhaustive std.macho.LC).
pub const LoadCmd = struct {
    index: u32,
    cmd: u32,
    cmdsize: u32,
    /// Offset of the command within the slice; `bytes` is exactly cmdsize long and inside sizeofcmds.
    offset: u32,
    bytes: []const u8,
    endian: std.builtin.Endian,

    pub fn lc(c: LoadCmd) macho.LC {
        return @enumFromInt(c.cmd);
    }
    /// Reader over the command bytes; `base` is the command's offset in the slice.
    pub fn reader(c: LoadCmd) Reader {
        return Reader.init(c.bytes, c.offset);
    }
    pub fn requiresDyld(c: LoadCmd) bool {
        return c.cmd & extra.LC_REQ_DYLD != 0;
    }
    /// "LC_SEGMENT_64" or "LC_?(0x..)".
    pub fn name(c: LoadCmd, buf: *[32]u8) []const u8 {
        return version.lcNameBuf(buf, c.cmd);
    }
};

pub const Walker = struct {
    r: Reader,
    hdr: Header,
    pos: u32,
    index: u32,
    stopped: bool,
    sizeofcmds_clamped: u32,
    ncmds_clamped: u32,

    /// Clamps sizeofcmds to the bytes present and ncmds to `limits.max_load_commands` (diagnostics recorded).
    pub fn init(r: Reader, hdr: Header, limits: *const Limits, diags: *Diagnostics) Walker {
        var sizeofcmds = hdr.sizeofcmds;
        const avail: u64 = r.len() -| hdr.header_size;
        if (sizeofcmds > avail) {
            diags.warn(.loadcmds, .sizeofcmds_invalid, r.base + 20, "sizeofcmds {d} exceeds the {d} bytes after the header; clamped", .{ sizeofcmds, avail });
            sizeofcmds = @intCast(avail);
        }
        var ncmds = hdr.ncmds;
        if (ncmds > limits.max_load_commands) {
            diags.warn(.loadcmds, .count_clamped, r.base + 16, "ncmds {d} clamped to {d}", .{ ncmds, limits.max_load_commands });
            ncmds = limits.max_load_commands;
        }
        return .{ .r = r, .hdr = hdr, .pos = hdr.header_size, .index = 0, .stopped = false, .sizeofcmds_clamped = sizeofcmds, .ncmds_clamped = ncmds };
    }
    /// Null at the end or on the first invalid cmdsize (< 8 / not %8 (4 for 32-bit) / past sizeofcmds:
    /// recorded as `cmdsize_invalid`, `stopped=true`).
    pub fn next(w: *Walker, diags: *Diagnostics) ?LoadCmd {
        if (w.stopped or w.index >= w.ncmds_clamped) return null;
        const end: u64 = @as(u64, w.hdr.header_size) + w.sizeofcmds_clamped;
        if (w.pos >= end) {
            if (!diags.has(.loadcmds, .count_clamped)) {
                diags.warn(.loadcmds, .count_clamped, w.r.base + 16, "ncmds {d} but sizeofcmds holds only {d} load commands", .{ w.hdr.ncmds, w.index });
            }
            w.stopped = true;
            return null;
        }
        const remaining: u64 = end - w.pos;
        const e = w.hdr.endian;
        const cmd = if (remaining >= 8) w.r.u32At(w.pos, e) else null;
        const cmdsize = if (remaining >= 8) w.r.u32At(w.pos + 4, e) else null;
        const alignment: u32 = if (w.hdr.is_64) 8 else 4;
        if (cmd == null or cmdsize == null or cmdsize.? < 8 or cmdsize.? % alignment != 0 or cmdsize.? > remaining) {
            var nb: [32]u8 = undefined;
            const nm = if (cmd) |c| version.lcNameBuf(&nb, c) else "?";
            diags.err(.loadcmds, .cmdsize_invalid, w.r.base + w.pos, "load command {d} ({s}) cmdsize {d} invalid: must be >= 8, a multiple of {d} and end inside sizeofcmds ({d} bytes remain); stopped", .{ w.index, nm, cmdsize orelse 0, alignment, remaining });
            w.stopped = true;
            return null;
        }
        const bytes = w.r.sliceAt(w.pos, cmdsize.?) orelse {
            w.stopped = true;
            return null;
        };
        const out = LoadCmd{ .index = w.index, .cmd = cmd.?, .cmdsize = cmdsize.?, .offset = w.pos, .bytes = bytes, .endian = e };
        w.pos += cmdsize.?;
        w.index += 1;
        return out;
    }
};

pub const Dylib = struct {
    cmd: u32,
    name: []const u8,
    name_terminated: bool,
    timestamp: u32,
    current_version: u32,
    compat_version: u32,
    flags: u32, // dylib_use_command flags (0 for classic encoding)
    ordinal: u16, // 1-based among LOAD/LOAD_WEAK/REEXPORT/UPWARD/LAZY_LOAD
    weak: bool,
    reexport: bool,
    upward: bool,
    delayed_init: bool,
    use_command: bool, // encoded as dylib_use_command (marker 0x1a741800)
};
pub const BuildTool = struct { tool: u32, version: u32 };
pub const BuildVersion = struct { platform: u32, minos: u32, sdk: u32, ntools_declared: u32, tools: []const BuildTool };
pub const VersionMin = struct { cmd: u32, version: u32, sdk: u32 };
pub const Entry = union(enum) {
    main: struct { entryoff: u64, stacksize: u64 },
    unixthread: struct { flavor: u32, count: u32, pc: ?u64 },
    none,
};
pub const EncryptionInfo = struct { cmd: u32, cryptoff: u32, cryptsize: u32, cryptid: u32 };
pub const LinkeditData = struct { dataoff: u32, datasize: u32 };
pub const LcStr = struct { text: []const u8, terminated: bool, offset: u32 };

/// Handles the classic lc_str layout and the dylib_use_command encoding; null when cmdsize is too small.
pub fn decodeDylib(arena: Allocator, c: LoadCmd, ordinal: u16, diags: *Diagnostics) Allocator.Error!?Dylib {
    _ = arena;
    const r = c.reader();
    const e = c.endian;
    if (c.bytes.len < 24) return null;
    const name_off = r.u32At(8, e).?;
    const ts = r.u32At(12, e).?;
    const cur = r.u32At(16, e).?;
    const compat = r.u32At(20, e).?;
    var use_command = false;
    var flags: u32 = 0;
    if (ts == extra.DYLIB_USE_MARKER and c.bytes.len >= 28) {
        use_command = true;
        flags = r.u32At(24, e).?;
    }
    const s = decodeStrAt(c, name_off, diags);
    const cmd = c.cmd;
    return .{
        .cmd = cmd,
        .name = s.text,
        .name_terminated = s.terminated,
        .timestamp = if (use_command) 0 else ts,
        .current_version = cur,
        .compat_version = compat,
        .flags = flags,
        .ordinal = ordinal,
        .weak = cmd == @intFromEnum(macho.LC.LOAD_WEAK_DYLIB) or (flags & extra.DYLIB_USE_WEAK_LINK) != 0,
        .reexport = cmd == @intFromEnum(macho.LC.REEXPORT_DYLIB) or (flags & extra.DYLIB_USE_REEXPORT) != 0,
        .upward = cmd == @intFromEnum(macho.LC.LOAD_UPWARD_DYLIB) or (flags & extra.DYLIB_USE_UPWARD) != 0,
        .delayed_init = (flags & extra.DYLIB_USE_DELAYED_INIT) != 0,
        .use_command = use_command,
    };
}

/// String at command offset `off`, NUL-terminated inside cmdsize (one diagnostic otherwise).
fn decodeStrAt(c: LoadCmd, off: u32, diags: *Diagnostics) LcStr {
    const r = c.reader();
    var nb: [32]u8 = undefined;
    if (off >= c.bytes.len) {
        if (!diags.has(.loadcmds, .string_unterminated))
            diags.warn(.loadcmds, .string_unterminated, c.offset, "{s} at load command {d}: string offset {d} lies outside cmdsize {d}", .{ c.name(&nb), c.index, off, c.cmdsize });
        return .{ .text = "", .terminated = false, .offset = off };
    }
    const s = r.cstrAt(off, c.bytes.len - off).?;
    if (!s.terminated and !diags.has(.loadcmds, .string_unterminated))
        diags.warn(.loadcmds, .string_unterminated, c.offset + off, "{s} at load command {d}: string not NUL-terminated inside cmdsize {d}", .{ c.name(&nb), c.index, c.cmdsize });
    return .{ .text = s.bytes, .terminated = s.terminated, .offset = off };
}

/// RPATH, LOAD_DYLINKER, ID_DYLINKER, DYLD_ENVIRONMENT, SUB_*, TARGET_TRIPLE: string at cmd_start + offset,
/// must be NUL-terminated inside the command (`string_unterminated` otherwise; truncated bytes still returned).
/// `str_off_field` is the offset of the lc_str field inside the command (8 for the plain string commands).
pub fn decodeLcStr(c: LoadCmd, str_off_field: u32, diags: *Diagnostics) ?LcStr {
    const off = c.reader().u32At(str_off_field, c.endian) orelse return null;
    return decodeStrAt(c, off, diags);
}
pub fn decodeBuildVersion(arena: Allocator, c: LoadCmd, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?BuildVersion {
    _ = limits;
    const r = c.reader();
    const e = c.endian;
    if (c.bytes.len < 24) return null;
    const ntools = r.u32At(20, e).?;
    const fit: u32 = @intCast((c.bytes.len - 24) / 8);
    var n = ntools;
    if (n > fit) {
        diags.warn(.loadcmds, .count_clamped, c.offset + 20, "LC_BUILD_VERSION ntools {d} but only {d} fit in cmdsize {d}", .{ ntools, fit, c.cmdsize });
        n = fit;
    }
    const tools = try arena.alloc(BuildTool, n);
    for (tools, 0..) |*t, i| {
        const o: u64 = 24 + @as(u64, i) * 8;
        t.* = .{ .tool = r.u32At(o, e).?, .version = r.u32At(o + 4, e).? };
    }
    return .{ .platform = r.u32At(8, e).?, .minos = r.u32At(12, e).?, .sdk = r.u32At(16, e).?, .ntools_declared = ntools, .tools = tools };
}
pub fn decodeVersionMin(c: LoadCmd) ?VersionMin {
    const r = c.reader();
    if (c.bytes.len < 16) return null;
    return .{ .cmd = c.cmd, .version = r.u32At(8, c.endian).?, .sdk = r.u32At(12, c.endian).? };
}
pub fn decodeUuid(c: LoadCmd) ?[16]u8 {
    const s = c.reader().sliceAt(8, 16) orelse return null;
    var out: [16]u8 = undefined;
    @memcpy(&out, s);
    return out;
}
pub fn decodeSourceVersion(c: LoadCmd) ?u64 {
    return c.reader().u64At(8, c.endian);
}
pub fn decodeEntry(c: LoadCmd, is_64: bool, diags: *Diagnostics) Entry {
    const r = c.reader();
    const e = c.endian;
    if (c.cmd == @intFromEnum(macho.LC.MAIN)) {
        if (c.bytes.len < 24) return .none;
        return .{ .main = .{ .entryoff = r.u64At(8, e).?, .stacksize = r.u64At(16, e).? } };
    }
    if (c.cmd == @intFromEnum(macho.LC.UNIXTHREAD) or c.cmd == @intFromEnum(macho.LC.THREAD)) {
        if (c.bytes.len < 16) return .none;
        const flavor = r.u32At(8, e).?;
        const count = r.u32At(12, e).?;
        var pc: ?u64 = null;
        if (is_64 and flavor == extra.ARM_THREAD_STATE64 and count >= 68) {
            pc = r.u64At(16 + extra.ARM_THREAD_STATE64_PC_OFFSET, e);
        } else if (is_64 and flavor == extra.x86_THREAD_STATE64 and count >= 42) {
            pc = r.u64At(16 + extra.x86_THREAD_STATE64_RIP_OFFSET, e);
        } else {
            diags.info(.loadcmds, .unknown_value, c.offset + 8, "LC_UNIXTHREAD flavor {d} count {d}: entry pc not decoded", .{ flavor, count });
        }
        if (pc == null and !diags.has(.loadcmds, .truncated) and (flavor == extra.ARM_THREAD_STATE64 or flavor == extra.x86_THREAD_STATE64))
            diags.warn(.loadcmds, .truncated, c.offset, "LC_UNIXTHREAD state truncated (count {d})", .{count});
        return .{ .unixthread = .{ .flavor = flavor, .count = count, .pc = pc } };
    }
    return .none;
}
pub fn decodeLinkeditData(c: LoadCmd) ?LinkeditData {
    const r = c.reader();
    if (c.bytes.len < 16) return null;
    return .{ .dataoff = r.u32At(8, c.endian).?, .datasize = r.u32At(12, c.endian).? };
}
pub fn decodeSymtab(c: LoadCmd) ?macho.symtab_command {
    return c.reader().structAt(macho.symtab_command, 0, c.endian);
}
pub fn decodeDysymtab(c: LoadCmd) ?macho.dysymtab_command {
    return c.reader().structAt(macho.dysymtab_command, 0, c.endian);
}
pub fn decodeDyldInfo(c: LoadCmd) ?macho.dyld_info_command {
    return c.reader().structAt(macho.dyld_info_command, 0, c.endian);
}
pub fn decodeEncryptionInfo(c: LoadCmd) ?EncryptionInfo {
    const r = c.reader();
    if (c.bytes.len < 20) return null;
    return .{ .cmd = c.cmd, .cryptoff = r.u32At(8, c.endian).?, .cryptsize = r.u32At(12, c.endian).?, .cryptid = r.u32At(16, c.endian).? };
}
pub fn decodeLinkerOptions(arena: Allocator, c: LoadCmd, diags: *Diagnostics) Allocator.Error![]const []const u8 {
    const r = c.reader();
    if (c.bytes.len < 12) return &.{};
    const count = r.u32At(8, c.endian).?;
    var list: std.ArrayList([]const u8) = .empty;
    var pos: u64 = 12;
    var i: u32 = 0;
    while (i < count and pos < c.bytes.len) : (i += 1) {
        const s = r.cstrAt(pos, c.bytes.len - pos).?;
        if (!s.terminated) {
            if (!diags.has(.loadcmds, .string_unterminated))
                diags.warn(.loadcmds, .string_unterminated, c.offset + pos, "LC_LINKER_OPTION string {d} not NUL-terminated", .{i});
            try list.append(arena, s.bytes);
            break;
        }
        try list.append(arena, s.bytes);
        pos += s.bytes.len + 1;
    }
    if (i < count and !diags.has(.loadcmds, .count_clamped))
        diags.warn(.loadcmds, .count_clamped, c.offset + 8, "LC_LINKER_OPTION count {d} but only {d} strings fit", .{ count, list.items.len });
    return list.toOwnedSlice(arena);
}
pub fn decodeFilesetEntry(c: LoadCmd, diags: *Diagnostics) ?struct { vmaddr: u64, fileoff: u64, entry_id: []const u8 } {
    const r = c.reader();
    if (c.bytes.len < 32) return null;
    const s = decodeLcStr(c, 24, diags) orelse return null;
    return .{ .vmaddr = r.u64At(8, c.endian).?, .fileoff = r.u64At(16, c.endian).?, .entry_id = s.text };
}
pub fn decodeNote(c: LoadCmd) ?struct { data_owner: []const u8, offset: u64, size: u64 } {
    const r = c.reader();
    if (c.bytes.len < 40) return null;
    return .{ .data_owner = r.nameAt(8, 16).?, .offset = r.u64At(24, c.endian).?, .size = r.u64At(32, c.endian).? };
}
/// True for LOAD_DYLIB, LOAD_WEAK_DYLIB, REEXPORT_DYLIB, LOAD_UPWARD_DYLIB, LAZY_LOAD_DYLIB (ordinal-bearing).
pub fn isDylibLoadCmd(cmd: u32) bool {
    return switch (cmd) {
        @intFromEnum(macho.LC.LOAD_DYLIB), @intFromEnum(macho.LC.LOAD_WEAK_DYLIB), @intFromEnum(macho.LC.REEXPORT_DYLIB), @intFromEnum(macho.LC.LOAD_UPWARD_DYLIB), @intFromEnum(macho.LC.LAZY_LOAD_DYLIB) => true,
        else => false,
    };
}

// ---- tests (hand-built bytes; hermetic) ----
fn le32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
fn le64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .little);
}
/// 32-byte header + LC_UUID(24) + LC_MAIN(24) + LC_LOAD_DYLIB(56) = 136 bytes.
fn buildImage(buf: *[136]u8) void {
    @memset(buf, 0);
    le32(buf, 0, macho.MH_MAGIC_64);
    le32(buf, 4, 0x0100000c);
    le32(buf, 12, 2);
    le32(buf, 16, 3);
    le32(buf, 20, 104);
    le32(buf, 24, 0x200085);
    le32(buf, 32, 0x1b);
    le32(buf, 36, 24);
    for (buf[40..56], 0..) |*b, i| b.* = @intCast(i + 1);
    le32(buf, 56, 0x80000028);
    le32(buf, 60, 24);
    le64(buf, 64, 0x524);
    le64(buf, 72, 0);
    le32(buf, 80, 0xc);
    le32(buf, 84, 56);
    le32(buf, 88, 24);
    le32(buf, 92, 2);
    le32(buf, 96, 0x054c0000);
    le32(buf, 100, 0x00010000);
    @memcpy(buf[104..][0.."/usr/lib/libSystem.B.dylib".len], "/usr/lib/libSystem.B.dylib");
}

test "loadcmds: header + walker + decoders on a hand-built image" {
    var buf: [136]u8 = undefined;
    buildImage(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var d = Diagnostics.init(arena.allocator(), 64);
    const r = Reader.init(&buf, 0);
    const hdr = try Header.parse(r);
    try std.testing.expect(hdr.is_64 and hdr.ncmds == 3 and hdr.sizeofcmds == 104 and hdr.cputype == 0x0100000c);
    var w = Walker.init(r, hdr, &Limits.default, &d);
    const c0 = w.next(&d).?;
    try std.testing.expectEqual(macho.LC.UUID, c0.lc());
    try std.testing.expectEqual(@as(u8, 1), decodeUuid(c0).?[0]);
    const c1 = w.next(&d).?;
    try std.testing.expect(c1.requiresDyld());
    try std.testing.expectEqual(@as(u64, 0x524), decodeEntry(c1, true, &d).main.entryoff);
    const c2 = w.next(&d).?;
    try std.testing.expect(isDylibLoadCmd(c2.cmd));
    const dl = (try decodeDylib(arena.allocator(), c2, 1, &d)).?;
    try std.testing.expectEqualStrings("/usr/lib/libSystem.B.dylib", dl.name);
    try std.testing.expect(dl.name_terminated and dl.timestamp == 2 and dl.current_version == 0x054c0000 and !dl.weak);
    try std.testing.expect(w.next(&d) == null);
    try std.testing.expectEqual(@as(usize, 0), d.items().len);
    try std.testing.expect(decodeDysymtab(c0) == null);
    try std.testing.expect(decodeDyldInfo(c0) == null);
    try std.testing.expect(decodeLinkeditData(c0) != null);
}

test "loadcmds: cmdsize 0/4/12/huge stop the walker; sizeofcmds and ncmds clamp" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const bad = [_]u32{ 0, 4, 12, 0xFFFFFFF0 };
    for (bad) |cs| {
        var buf: [136]u8 = undefined;
        buildImage(&buf);
        le32(&buf, 36, cs);
        var d = Diagnostics.init(arena.allocator(), 64);
        const r = Reader.init(&buf, 0);
        var w = Walker.init(r, try Header.parse(r), &Limits.default, &d);
        try std.testing.expect(w.next(&d) == null);
        try std.testing.expect(w.stopped and d.has(.loadcmds, .cmdsize_invalid));
    }
    // sizeofcmds larger than the file: clamped, then all three commands parse.
    {
        var buf: [136]u8 = undefined;
        buildImage(&buf);
        le32(&buf, 20, 0xFFFFFFF0);
        var d = Diagnostics.init(arena.allocator(), 64);
        const r = Reader.init(&buf, 0);
        var w = Walker.init(r, try Header.parse(r), &Limits.default, &d);
        try std.testing.expect(d.has(.loadcmds, .sizeofcmds_invalid));
        var n: u32 = 0;
        while (w.next(&d)) |_| n += 1;
        try std.testing.expectEqual(@as(u32, 3), n);
    }
    // ncmds absurd: clamped to the limit, then bounded by sizeofcmds.
    {
        var buf: [136]u8 = undefined;
        buildImage(&buf);
        le32(&buf, 16, 0xFFFFFFFF);
        var d = Diagnostics.init(arena.allocator(), 64);
        const r = Reader.init(&buf, 0);
        var w = Walker.init(r, try Header.parse(r), &Limits.paranoid, &d);
        try std.testing.expect(d.has(.loadcmds, .count_clamped));
        var n: u32 = 0;
        while (w.next(&d)) |_| n += 1;
        try std.testing.expectEqual(@as(u32, 3), n);
    }
    // every prefix of the image parses without error
    {
        var buf: [136]u8 = undefined;
        buildImage(&buf);
        var len: usize = 0;
        while (len <= buf.len) : (len += 1) {
            var d = Diagnostics.init(arena.allocator(), 64);
            const r = Reader.init(buf[0..len], 0);
            const hdr = Header.parse(r) catch continue;
            var w = Walker.init(r, hdr, &Limits.default, &d);
            while (w.next(&d)) |c| {
                _ = decodeUuid(c);
                _ = decodeEntry(c, true, &d);
                _ = try decodeDylib(arena.allocator(), c, 1, &d);
            }
        }
    }
    // bad magic / truncated header
    try std.testing.expectError(error.NotMachO, Header.parse(Reader.init("\xde\xad\xbe\xef\x00\x00\x00\x00", 0)));
    try std.testing.expectError(error.Truncated, Header.parse(Reader.init("\xcf\xfa\xed\xfe\x0c\x00\x00\x01", 0)));
    try std.testing.expectError(error.Truncated, Header.parse(Reader.init("", 0)));
}
