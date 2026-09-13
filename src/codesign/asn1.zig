//! codesign/asn1.zig — BER/DER TLV reader shared by cms.zig and entitlements.zig (indefinite lengths,
//! long forms, OID printing, explicit-stack Walker). Imports: core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;

pub const Class = enum(u2) { universal, application, context, private };
pub const Tlv = struct { class: Class, constructed: bool, tag: u32, indefinite: bool, header_len: usize, content: []const u8, total_len: usize };
pub const Error = error{ Truncated, BadLength, TooDeep, TooMany };

/// Universal tag numbers used by the two callers.
pub const tag_boolean: u32 = 0x01;
pub const tag_integer: u32 = 0x02;
pub const tag_bit_string: u32 = 0x03;
pub const tag_octet_string: u32 = 0x04;
pub const tag_null: u32 = 0x05;
pub const tag_oid: u32 = 0x06;
pub const tag_utf8_string: u32 = 0x0c;
pub const tag_sequence: u32 = 0x10;
pub const tag_set: u32 = 0x11;
pub const tag_printable_string: u32 = 0x13;
pub const tag_ia5_string: u32 = 0x16;
pub const tag_utc_time: u32 = 0x17;
pub const tag_generalized_time: u32 = 0x18;

/// Hard ceiling on nested indefinite-length scanning and on the Walker's stack.
const max_stack_depth: u8 = 64;
/// Steps a single indefinite-length scan may take before giving up.
const max_scan_steps: u32 = 1 << 20;

const Header = struct {
    class: Class,
    constructed: bool,
    tag: u32,
    /// Offset of the first content byte, absolute in `bytes`.
    content_start: usize,
    /// Definite content length; meaningless when `indefinite`.
    length: usize,
    indefinite: bool,
};

/// Tag + length only; never reads content. Every arithmetic step is overflow-checked.
fn readHeader(bytes: []const u8, off: usize) Error!Header {
    if (off >= bytes.len) return error.Truncated;
    var pos = off;
    const id = bytes[pos];
    pos += 1;
    const class: Class = @enumFromInt(@as(u2, @truncate(id >> 6)));
    const constructed = id & 0x20 != 0;
    var tag: u32 = id & 0x1f;
    if (tag == 0x1f) { // high tag number form
        tag = 0;
        var seen: u8 = 0;
        while (true) {
            if (pos >= bytes.len) return error.Truncated;
            const b = bytes[pos];
            pos += 1;
            seen += 1;
            if (seen > 4) return error.BadLength;
            tag = std.math.shlExact(u32, tag, 7) catch return error.BadLength;
            tag |= b & 0x7f;
            if (b & 0x80 == 0) break;
        }
    }
    if (pos >= bytes.len) return error.Truncated;
    const l0 = bytes[pos];
    pos += 1;
    if (l0 == 0x80) return .{ .class = class, .constructed = constructed, .tag = tag, .content_start = pos, .length = 0, .indefinite = true };
    var length: usize = l0;
    if (l0 & 0x80 != 0) {
        const n: usize = l0 & 0x7f;
        if (n == 0 or n > 8) return error.BadLength;
        if (n > bytes.len - pos) return error.Truncated;
        var v: u64 = 0;
        for (bytes[pos..][0..n]) |b| {
            v = std.math.shlExact(u64, v, 8) catch return error.BadLength;
            v |= b;
        }
        pos += n;
        if (v > std.math.maxInt(usize)) return error.BadLength;
        length = @intCast(v);
    }
    if (length > bytes.len - pos) return error.Truncated;
    return .{ .class = class, .constructed = constructed, .tag = tag, .content_start = pos, .length = length, .indefinite = false };
}

/// End offset (just past the `00 00` end-of-contents pair) of an indefinite-length value whose
/// content starts at `start`. Iterative: nesting is tracked with a depth counter, never recursion.
fn scanIndefiniteEnd(bytes: []const u8, start: usize) Error!usize {
    var pos = start;
    var depth: u32 = 1;
    var steps: u32 = 0;
    while (depth > 0) {
        steps += 1;
        if (steps > max_scan_steps) return error.TooMany;
        if (pos >= bytes.len) return error.Truncated;
        if (isEoc(bytes, pos)) {
            pos += 2;
            depth -= 1;
            continue;
        }
        const h = try readHeader(bytes, pos);
        if (h.indefinite) {
            depth += 1;
            if (depth > max_stack_depth) return error.TooDeep;
            pos = h.content_start;
        } else {
            pos = h.content_start + h.length; // both already bounds-checked by readHeader
        }
    }
    return pos;
}

/// Handles 0x80 indefinite (content up to the 00 00 end-of-contents pair) and 0x81..0x84 long forms.
pub fn read(bytes: []const u8, off: usize) Error!Tlv {
    const h = try readHeader(bytes, off);
    const header_len = h.content_start - off;
    if (!h.indefinite) {
        return .{
            .class = h.class,
            .constructed = h.constructed,
            .tag = h.tag,
            .indefinite = false,
            .header_len = header_len,
            .content = bytes[h.content_start..][0..h.length],
            .total_len = header_len + h.length,
        };
    }
    const end = try scanIndefiniteEnd(bytes, h.content_start);
    return .{
        .class = h.class,
        .constructed = h.constructed,
        .tag = h.tag,
        .indefinite = true,
        .header_len = header_len,
        .content = bytes[h.content_start .. end - 2],
        .total_len = end - off,
    };
}

/// Total byte access: `codesign/asn1.zig` may not import `core/reader.zig` (DESIGN.md §4), so this
/// is the module-local equivalent of `Reader.u8At` — the only place that indexes a byte slice.
fn at(buf: []const u8, i: usize) ?u8 {
    if (i >= buf.len) return null;
    return buf[i];
}
/// True when an end-of-contents pair (`00 00`) starts at `pos`.
fn isEoc(buf: []const u8, pos: usize) bool {
    return (at(buf, pos) orelse 1) == 0 and (at(buf, pos + 1) orelse 1) == 0;
}

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(it: *Iterator) Error!?Tlv {
        const buf = it.bytes;
        if (it.pos >= buf.len) return null;
        // A stray end-of-contents pair terminates the sequence.
        if (isEoc(buf, it.pos)) {
            it.pos = buf.len;
            return null;
        }
        const t = try read(buf, it.pos);
        it.pos += @max(t.total_len, 1);
        return t;
    }
};
pub fn children(t: Tlv) Iterator {
    return .{ .bytes = t.content };
}

/// Components of an OID content field, without allocating.
pub const OidIterator = struct {
    content: []const u8,
    pos: usize = 0,
    pending: ?u64 = null,
    pub fn next(it: *OidIterator) ?u64 {
        if (it.pending) |v| {
            it.pending = null;
            return v;
        }
        if (it.pos >= it.content.len) return null;
        const first = it.pos == 0;
        var v: u64 = 0;
        while (it.pos < it.content.len) {
            const b = it.content[it.pos];
            it.pos += 1;
            if (v > (std.math.maxInt(u64) >> 7)) return null; // absurd component: stop
            v = (v << 7) | (b & 0x7f);
            if (b & 0x80 == 0) break;
        }
        if (first) {
            const a: u64 = @min(v / 40, 2);
            it.pending = v - a * 40;
            return a;
        }
        return v;
    }
};

/// "1.2.840.113635.100.6.1.13"
pub fn oidString(arena: Allocator, content: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it: OidIterator = .{ .content = content };
    var first = true;
    while (it.next()) |c| {
        if (!first) try out.append(arena, '.');
        try out.print(arena, "{d}", .{c});
        first = false;
    }
    return out.toOwnedSlice(arena);
}
pub fn oidEquals(content: []const u8, dotted: []const u8) bool {
    var it: OidIterator = .{ .content = content };
    var parts = std.mem.splitScalar(u8, dotted, '.');
    while (parts.next()) |p| {
        const want = std.fmt.parseInt(u64, p, 10) catch return false;
        const got = it.next() orelse return false;
        if (got != want) return false;
    }
    return it.next() == null;
}
pub fn readInteger(content: []const u8) ?i64 {
    if (content.len == 0 or content.len > 8) return null;
    var v: i64 = if (content[0] & 0x80 != 0) -1 else 0;
    for (content) |b| v = (v << 8) | @as(i64, b);
    return v;
}

fn digits2(s: []const u8) ?u32 {
    if (s.len < 2) return null;
    if (!std.ascii.isDigit(s[0]) or !std.ascii.isDigit(s[1])) return null;
    return @as(u32, s[0] - '0') * 10 + (s[1] - '0');
}
/// Days since the Unix epoch for a proleptic-Gregorian y-m-d (Howard Hinnant's days_from_civil).
fn daysFromCivil(y_in: i64, m: u32, d: u32) i64 {
    var y = y_in;
    y -= @intFromBool(m <= 2);
    const era = @divFloor(y, 400);
    const yoe: i64 = y - era * 400;
    const mp: i64 = @intCast((m + 9) % 12);
    const doy: i64 = @divTrunc(153 * mp + 2, 5) + @as(i64, @intCast(d)) - 1;
    const doe: i64 = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}
/// UTCTime (0x17) / GeneralizedTime (0x18) -> unix seconds.
pub fn readTime(t: Tlv) ?i64 {
    const s = t.content;
    var year: i64 = undefined;
    var rest: []const u8 = undefined;
    if (t.tag == tag_utc_time) {
        const yy = digits2(s) orelse return null;
        year = if (yy >= 50) 1900 + @as(i64, yy) else 2000 + @as(i64, yy);
        rest = s[2..];
    } else if (t.tag == tag_generalized_time) {
        if (s.len < 4) return null;
        const hi = digits2(s) orelse return null;
        const lo = digits2(s[2..]) orelse return null;
        year = @as(i64, hi) * 100 + lo;
        rest = s[4..];
    } else return null;
    if (rest.len < 8) return null;
    const month = digits2(rest) orelse return null;
    const day = digits2(rest[2..]) orelse return null;
    const hour = digits2(rest[4..]) orelse return null;
    const minute = digits2(rest[6..]) orelse return null;
    const second: u32 = if (rest.len >= 10) (digits2(rest[8..]) orelse 0) else 0;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60) return null;
    var unix = daysFromCivil(year, month, day) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
    // Trailing "+hhmm"/"-hhmm" offset (Z or nothing means UTC).
    if (std.mem.findScalar(u8, rest, '+') orelse std.mem.findScalar(u8, rest, '-')) |i| {
        if (rest.len >= i + 5) {
            const oh = digits2(rest[i + 1 ..]) orelse 0;
            const om = digits2(rest[i + 3 ..]) orelse 0;
            const off: i64 = @as(i64, oh) * 3600 + @as(i64, om) * 60;
            unix += if (rest[i] == '+') -off else off;
        }
    }
    return unix;
}

pub const Node = struct { depth: u8, tlv: Tlv, offset: usize };
/// Pre-order walk with an explicit stack; depth <= limits.max_asn1_depth, nodes <= limits.max_asn1_nodes.
pub const Walker = struct {
    bytes: []const u8,
    limits: *const Limits,
    stack: [64]Frame = undefined,
    depth: u8 = 0,
    nodes: u32 = 0,
    pub const Frame = struct { end: usize, pos: usize };
    pub fn init(bytes: []const u8, limits: *const Limits) Walker {
        return .{ .bytes = bytes, .limits = limits };
    }
    pub fn next(w: *Walker) Error!?Node {
        if (w.depth == 0) {
            if (w.nodes != 0) return null;
            w.stack[0] = .{ .end = w.bytes.len, .pos = 0 };
            w.depth = 1;
        }
        const cap: u8 = @intCast(@min(@as(u32, max_stack_depth), @max(w.limits.max_asn1_depth, 1)));
        const buf = w.bytes;
        while (w.depth > 0) {
            const top = &w.stack[w.depth - 1];
            const end = @min(top.end, buf.len);
            if (top.pos >= end) {
                w.depth -= 1;
                continue;
            }
            if (isEoc(buf, top.pos)) {
                w.depth -= 1;
                continue;
            }
            const t = try read(buf[0..end], top.pos);
            w.nodes += 1;
            if (w.nodes > w.limits.max_asn1_nodes) return error.TooMany;
            const node: Node = .{ .depth = w.depth - 1, .tlv = t, .offset = top.pos };
            const content_start = top.pos + t.header_len;
            top.pos += @max(t.total_len, 1);
            if (t.constructed and t.content.len != 0) {
                if (w.depth >= cap) return error.TooDeep;
                w.stack[w.depth] = .{ .end = content_start + t.content.len, .pos = content_start };
                w.depth += 1;
            }
            return node;
        }
        return null;
    }
};

test "asn1: definite lengths, long form, nested walk" {
    // SEQUENCE { INTEGER 1, OID 1.2.840.113635.100.6.1.13, UTF8String "hi" }
    const bytes = [_]u8{
        0x30, 0x15, 0x02, 0x01, 0x01, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64,
        0x06, 0x01, 0x0d, 0x0c, 0x02, 'h',  'i',  0x05, 0x00,
    };
    const t = try read(&bytes, 0);
    try std.testing.expect(t.constructed and t.tag == tag_sequence and !t.indefinite);
    try std.testing.expectEqual(@as(usize, 23), t.total_len);
    var it = children(t);
    const a = (try it.next()).?;
    try std.testing.expectEqual(@as(?i64, 1), readInteger(a.content));
    const b = (try it.next()).?;
    try std.testing.expect(oidEquals(b.content, "1.2.840.113635.100.6.1.13"));
    try std.testing.expect(!oidEquals(b.content, "1.2.840.113635.100.6.1"));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("1.2.840.113635.100.6.1.13", try oidString(arena.allocator(), b.content));
    const c = (try it.next()).?;
    try std.testing.expectEqualStrings("hi", c.content);
    _ = (try it.next()).?; // NULL
    try std.testing.expect((try it.next()) == null);

    var w = Walker.init(&bytes, &Limits.default);
    var n: usize = 0;
    while (try w.next()) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 5), n);
}

test "asn1: indefinite lengths (Apple platform CMS shape)" {
    // SEQUENCE(indefinite) { SEQUENCE(indefinite) { INTEGER 1 } }
    const bytes = [_]u8{ 0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const t = try read(&bytes, 0);
    try std.testing.expect(t.indefinite and t.total_len == bytes.len);
    var it = children(t);
    const inner = (try it.next()).?;
    try std.testing.expect(inner.indefinite);
    var it2 = children(inner);
    const i = (try it2.next()).?;
    try std.testing.expectEqual(@as(?i64, 1), readInteger(i.content));
    var w = Walker.init(&bytes, &Limits.default);
    var n: usize = 0;
    while (try w.next()) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 3), n);
}

test "asn1: malformed input is an error, never a trap" {
    try std.testing.expectError(error.Truncated, read(&[_]u8{0x30}, 0));
    try std.testing.expectError(error.Truncated, read(&[_]u8{ 0x30, 0x05, 0x01 }, 0));
    try std.testing.expectError(error.BadLength, read(&[_]u8{ 0x30, 0x8a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, 0));
    try std.testing.expectError(error.Truncated, read(&[_]u8{ 0x30, 0x80, 0x02, 0x01, 0x01 }, 0)); // no EOC
    try std.testing.expectError(error.Truncated, read(&[_]u8{}, 0));
    // Every prefix of a valid encoding either parses or returns an error.
    const good = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x0c, 0x01, 'x' };
    for (0..good.len + 1) |n| {
        const r = read(good[0..n], 0);
        if (r) |t| {
            try std.testing.expect(t.total_len <= n);
        } else |_| {}
    }
    var w = Walker.init(&[_]u8{ 0x30, 0x02, 0x30, 0x00 }, &Limits.paranoid);
    while (try w.next()) |_| {}
}

test "asn1: times" {
    try std.testing.expectEqual(@as(?i64, 0), readTime(.{ .class = .universal, .constructed = false, .tag = tag_utc_time, .indefinite = false, .header_len = 2, .content = "700101000000Z", .total_len = 15 }));
    // 2026-01-16T16:39:18Z
    try std.testing.expectEqual(@as(?i64, 1768581558), readTime(.{ .class = .universal, .constructed = false, .tag = tag_utc_time, .indefinite = false, .header_len = 2, .content = "260116163918Z", .total_len = 15 }));
    try std.testing.expectEqual(@as(?i64, 1768581558), readTime(.{ .class = .universal, .constructed = false, .tag = tag_generalized_time, .indefinite = false, .header_len = 2, .content = "20260116163918Z", .total_len = 17 }));
    try std.testing.expect(readTime(.{ .class = .universal, .constructed = false, .tag = tag_utc_time, .indefinite = false, .header_len = 2, .content = "xx", .total_len = 4 }) == null);
}
