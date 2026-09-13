//! core/reader.zig — the single bounds-checked view over input bytes.
//! Imports: std only. Verbatim compiling bodies are in DESIGN.md §3.1 (WP0 pastes them here).
const std = @import("std");

/// A read-only window onto a byte buffer. Every accessor is total: it returns `null`
/// (or a typed error for Cursor) instead of ever touching memory outside `bytes`.
/// `base` is the absolute file offset of `bytes[0]`, used only for diagnostics.
pub const Reader = struct {
    bytes: []const u8,
    base: u64 = 0,

    pub const Endian = std.builtin.Endian;

    pub fn init(bytes: []const u8, base: u64) Reader {
        return .{ .bytes = bytes, .base = base };
    }
    pub fn len(r: Reader) usize {
        return r.bytes.len;
    }
    /// True iff [off, off+size) lies inside the window (overflow-safe).
    pub fn contains(r: Reader, off: u64, size: u64) bool {
        const end = std.math.add(u64, off, size) catch return false;
        return end <= r.bytes.len;
    }
    /// Sub-window; null when out of range. `size` may be `null` for "to the end".
    pub fn sub(r: Reader, off: u64, size: ?u64) ?Reader {
        if (off > r.bytes.len) return null;
        const avail: u64 = r.bytes.len - off;
        const n = size orelse avail;
        if (n > avail) return null;
        const o: usize = @intCast(off);
        return .{ .bytes = r.bytes[o..][0..@intCast(n)], .base = r.base + off };
    }
    /// Sub-window clamped to what exists (never null unless `off` itself is past the end).
    /// Returns the window and whether it was truncated.
    pub fn subClamped(r: Reader, off: u64, size: u64) ?struct { r: Reader, truncated: bool } {
        if (off > r.bytes.len) return null;
        const avail: u64 = r.bytes.len - off;
        const n = @min(size, avail);
        const o: usize = @intCast(off);
        return .{ .r = .{ .bytes = r.bytes[o..][0..@intCast(n)], .base = r.base + off }, .truncated = n < size };
    }
    pub fn sliceAt(r: Reader, off: u64, size: u64) ?[]const u8 {
        const s = r.sub(off, size) orelse return null;
        return s.bytes;
    }
    pub fn u8At(r: Reader, off: u64) ?u8 {
        if (off >= r.bytes.len) return null;
        return r.bytes[@intCast(off)];
    }
    pub fn u16At(r: Reader, off: u64, endian: Endian) ?u16 {
        const s = r.sliceAt(off, 2) orelse return null;
        return std.mem.readInt(u16, s[0..2], endian);
    }
    pub fn u32At(r: Reader, off: u64, endian: Endian) ?u32 {
        const s = r.sliceAt(off, 4) orelse return null;
        return std.mem.readInt(u32, s[0..4], endian);
    }
    pub fn u64At(r: Reader, off: u64, endian: Endian) ?u64 {
        const s = r.sliceAt(off, 8) orelse return null;
        return std.mem.readInt(u64, s[0..8], endian);
    }
    /// Alignment-safe extern-struct read (copy out via `bytesToValue`, then byte-swap
    /// all fields when the on-disk endianness differs from the host).
    pub fn structAt(r: Reader, comptime T: type, off: u64, endian: Endian) ?T {
        comptime std.debug.assert(@typeInfo(T) == .@"struct");
        const s = r.sliceAt(off, @sizeOf(T)) orelse return null;
        var v = std.mem.bytesToValue(T, s[0..@sizeOf(T)]);
        if (endian != @import("builtin").cpu.arch.endian()) std.mem.byteSwapAllFields(T, &v);
        return v;
    }
    /// NUL-terminated string at `off`, at most `max` bytes scanned. Returns the bytes
    /// before the NUL; `terminated == false` when no NUL was found within the window/max.
    pub fn cstrAt(r: Reader, off: u64, max: u64) ?struct { bytes: []const u8, terminated: bool } {
        if (off >= r.bytes.len) return null;
        const o: usize = @intCast(off);
        const limit: usize = @intCast(@min(max, r.bytes.len - off));
        const win = r.bytes[o..][0..limit];
        if (std.mem.findScalar(u8, win, 0)) |i| return .{ .bytes = win[0..i], .terminated = true };
        return .{ .bytes = win, .terminated = false };
    }
    /// Fixed-width name field (segname/sectname): up to 16 bytes, stops at first NUL.
    pub fn nameAt(r: Reader, off: u64, width: u8) ?[]const u8 {
        const s = r.sliceAt(off, width) orelse return null;
        return std.mem.sliceTo(s, 0);
    }
    pub fn cursor(r: Reader, off: u64) ?Cursor {
        if (off > r.bytes.len) return null;
        return .{ .r = r, .pos = @intCast(off) };
    }
};

/// Sequential reader for opcode streams / tries / DER. Never panics; every take is checked.
pub const Cursor = struct {
    r: Reader,
    pos: usize,

    pub const Error = error{ Truncated, Overflow };

    pub fn remaining(c: Cursor) usize {
        return c.r.bytes.len - c.pos;
    }
    pub fn atEnd(c: Cursor) bool {
        return c.pos >= c.r.bytes.len;
    }
    pub fn takeU8(c: *Cursor) Error!u8 {
        if (c.pos >= c.r.bytes.len) return error.Truncated;
        defer c.pos += 1;
        return c.r.bytes[c.pos];
    }
    pub fn takeBytes(c: *Cursor, n: usize) Error![]const u8 {
        if (n > c.remaining()) return error.Truncated;
        defer c.pos += n;
        return c.r.bytes[c.pos..][0..n];
    }
    pub fn takeInt(c: *Cursor, comptime T: type, endian: Reader.Endian) Error!T {
        const b = try c.takeBytes(@sizeOf(T));
        return std.mem.readInt(T, b[0..@sizeOf(T)], endian);
    }
    /// ULEB128 into u64; more than 10 bytes or a value that does not fit is `error.Overflow`
    /// (never silently wraps — legacy bind streams encode negative deltas as 10-byte ULEBs,
    /// callers that want wrapping use `takeUlebWrapping`).
    pub fn takeUleb(c: *Cursor) Error!u64 {
        var result: u64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            const bits: u64 = b & 0x7f;
            if (shift >= 64 or (shift > 57 and (bits >> @intCast(64 - @as(u8, shift))) != 0)) return error.Overflow;
            result |= bits << @intCast(shift);
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
        return error.Overflow;
    }
    /// ULEB128 with explicit two's-complement wrap (BIND_OPCODE_ADD_ADDR_ULEB semantics).
    pub fn takeUlebWrapping(c: *Cursor) Error!u64 {
        var result: u64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            if (shift < 64) result |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) return result;
            shift +|= 7;
        }
        return error.Overflow;
    }
    pub fn takeSleb(c: *Cursor) Error!i64 {
        var result: i64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            if (shift < 64) result |= @as(i64, b & 0x7f) << @intCast(shift);
            shift +|= 7;
            if (b & 0x80 == 0) {
                if (shift < 64 and (b & 0x40) != 0) result |= @as(i64, -1) << @intCast(shift);
                return result;
            }
        }
        return error.Overflow;
    }
    /// NUL-terminated string, at most `max` bytes; consumes the NUL.
    pub fn takeCstr(c: *Cursor, max: usize) Error![]const u8 {
        const win = c.r.bytes[c.pos..][0..@min(max, c.remaining())];
        const i = std.mem.findScalar(u8, win, 0) orelse return error.Truncated;
        defer c.pos += i + 1;
        return win[0..i];
    }
    pub fn skip(c: *Cursor, n: usize) Error!void {
        _ = try c.takeBytes(n);
    }
    pub fn seek(c: *Cursor, pos: usize) Error!void {
        if (pos > c.r.bytes.len) return error.Truncated;
        c.pos = pos;
    }
};

test "reader smoke" {
    const r = Reader.init("\xcf\xfa\xed\xfe\x00", 0);
    try std.testing.expectEqual(@as(?u32, 0xfeedfacf), r.u32At(0, .little));
    try std.testing.expect(r.u32At(2, .little) == null);
    try std.testing.expect(!r.contains(std.math.maxInt(u64), 1));
    var c = r.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 0xfdb7d4f), try c.takeUleb());
    const hdr = r.structAt(std.macho.load_command, 0, .little);
    try std.testing.expect(hdr == null);
    try std.testing.expectEqualStrings("", (r.cstrAt(4, 16).?).bytes);
}

test "reader: sleb 9-byte and 10-byte -1, uleb overflow" {
    const r9 = Reader.init(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 0);
    var c9 = r9.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c9.takeSleb());
    const r10 = Reader.init(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 0);
    var c10 = r10.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c10.takeSleb());
    const r1 = Reader.init(&[_]u8{0x7f}, 0);
    var c1 = r1.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c1.takeSleb());
    const big = Reader.init(&[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }, 0);
    var cb = big.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 1 << 63), try cb.takeUleb());
    const over: [10]u8 = @splat(0x80);
    const ro = Reader.init(&over, 0);
    var co = ro.cursor(0).?;
    try std.testing.expectError(error.Overflow, co.takeUleb());
    const wrap = Reader.init(&[_]u8{ 0xf8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }, 0);
    var cw = wrap.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFF78), try cw.takeUlebWrapping());
}
test "reader: every accessor is total at the edges" {
    const r = Reader.init("abcd", 100);
    try std.testing.expect(r.u32At(1, .little) == null);
    try std.testing.expect(r.u64At(0, .little) == null);
    try std.testing.expect(r.sub(4, 0) != null);
    try std.testing.expect(r.sub(5, null) == null);
    try std.testing.expect(r.subClamped(2, 100).?.truncated);
    try std.testing.expect(!r.contains(3, std.math.maxInt(u64)));
    try std.testing.expect(r.cursor(4) != null and r.cursor(5) == null);
    try std.testing.expectEqualStrings("abcd", r.nameAt(0, 4).?);
    try std.testing.expect(!(r.cstrAt(0, 16).?).terminated);
}
