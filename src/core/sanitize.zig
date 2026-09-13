//! core/sanitize.zig — output-safe strings. Imports: std only.
//!
//! Every string that comes out of the input file (segment/section names, dylib paths, symbol names,
//! ObjC names, plist keys/values, code-signing identifiers, quarantine agents, bundle paths, and any
//! diagnostic that interpolates one) is attacker-controlled and must be made inert before it reaches
//! a terminal or a JSON document. Two policies, one classification:
//!
//!   * `.text` — the bytes land on a terminal, so anything that can move the cursor, end the current
//!     line or start an escape sequence is escaped: C0 (NUL/BEL/BS/TAB/LF/CR/ESC/…), DEL, C1
//!     (U+0080–U+009F, which includes CSI U+009B), the bidi/line-separator controls, and every byte
//!     that is not part of a valid UTF-8 sequence. Escapes are `\xNN` for single bytes and `\u{NN}`
//!     for code points, so the analyst can still read what the sample actually contained. Legitimate
//!     non-ASCII UTF-8 (a unicode app name in Info.plist) passes through unchanged.
//!   * `.json` — `std.json.Stringify` already escapes C0 and quotes, so the document itself can never
//!     be broken; what it cannot do is carry invalid UTF-8. Invalid UTF-8, DEL and C0 controls other
//!     than `\t\n\r` become U+FFFD (DESIGN.md §6.2), and `output/json.str` adds `<key>_hex` +
//!     `<key>_lossy` so the original bytes are never lost. `\t\n\r` stay because a plist string may
//!     legitimately contain them and the escape is done by the Stringify layer.
//!
//! Text renderers must therefore never print a `.json`-sanitized string directly (plist and bundle
//! values are sanitized once at parse time with `.json`): run it through `.text` as well.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Policy = enum { text, json };
pub const Sanitized = struct { text: []const u8, lossy: bool };

/// Longest file-derived string rendered into output by `Sink.safe`; longer input is cut.
pub const max_render: u32 = 1 << 20;

/// True when the code point cannot move the cursor, end the line, start an escape sequence or
/// reorder what follows it.
fn okCodepoint(cp: u21) bool {
    if (cp < 0x20 or cp == 0x7f) return false; // C0 + DEL
    if (cp >= 0x80 and cp <= 0x9f) return false; // C1 (0x9b = CSI)
    return switch (cp) {
        0x200b...0x200f => false, // zero width space + LRM/RLM
        0x2028, 0x2029 => false, // line / paragraph separator
        0x202a...0x202e => false, // bidi embedding + override (trojan-source)
        0x2066...0x2069 => false, // bidi isolate
        0xfeff => false, // zero width no-break space
        else => true,
    };
}
fn okByte(b: u8, policy: Policy) bool {
    return switch (policy) {
        .text => b >= 0x20 and b < 0x7f,
        .json => (b >= 0x20 and b < 0x7f) or b == '\t' or b == '\n' or b == '\r',
    };
}
pub fn isClean(s: []const u8, policy: Policy) bool {
    if (policy == .json) {
        if (!std.unicode.utf8ValidateSlice(s)) return false;
        for (s) |b| if ((b < 0x20 or b == 0x7f) and !okByte(b, .json)) return false;
        return true;
    }
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        if (b < 0x80) {
            if (!okByte(b, .text)) return false;
            i += 1;
            continue;
        }
        const n = std.unicode.utf8ByteSequenceLength(b) catch return false;
        if (i + n > s.len) return false;
        const cp = std.unicode.utf8Decode(s[i .. i + n]) catch return false;
        if (!okCodepoint(cp)) return false;
        i += n;
    }
    return true;
}
/// Returns `s` itself (lossy=false) when clean; otherwise an arena copy with invalid UTF-8 / control
/// code points replaced (text: `\xNN` per byte, `\u{NN}` per non-ASCII code point; json: U+FFFD, one
/// per offending byte). Cut at `max` bytes of input.
///
/// LIFETIME CONTRACT: the result may ALIAS `s` rather than being an arena copy, so `s` must outlive
/// the result. Never pass a stack buffer — dupe it into `arena` first. (A stack buffer here produced
/// a use-after-return that disclosed stale pointer bytes through `darwin/security.urlPath`.)
pub fn string(arena: Allocator, s: []const u8, policy: Policy, max: u32) Allocator.Error!Sanitized {
    const in = if (s.len > max) s[0..max] else s;
    if (isClean(in, policy) and in.len == s.len) return .{ .text = s, .lossy = false };
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < in.len) {
        const b = in[i];
        if (b >= 0x80) {
            const n = std.unicode.utf8ByteSequenceLength(b) catch 0;
            if (n != 0 and i + n <= in.len) {
                if (std.unicode.utf8Decode(in[i .. i + n]) catch null) |cp| {
                    if (policy == .json or okCodepoint(cp)) {
                        try out.appendSlice(arena, in[i .. i + n]);
                    } else {
                        try out.print(arena, "\\u{{{x}}}", .{cp});
                    }
                    i += n;
                    continue;
                }
            }
        }
        if (okByte(b, policy)) {
            try out.append(arena, b);
        } else switch (policy) {
            .text => try out.print(arena, "\\x{x:0>2}", .{b}),
            .json => try out.appendSlice(arena, "\u{FFFD}"),
        }
        i += 1;
    }
    return .{ .text = try out.toOwnedSlice(arena), .lossy = true };
}
/// Terminal-safe rendering of one file-derived string; bumps `lossy` when anything was escaped.
pub fn forText(arena: Allocator, s: []const u8, lossy: ?*u32) Allocator.Error![]const u8 {
    const r = try string(arena, s, .text, max_render);
    if (r.lossy) if (lossy) |c| {
        c.* +|= 1;
    };
    return r.text;
}
pub fn hexLower(arena: Allocator, b: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "{x}", .{b});
}
pub fn escapeC(w: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    for (bytes) |b| switch (b) {
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        else => if (b >= 0x20 and b < 0x7f) try w.writeByte(b) else try w.print("\\x{x:0>2}", .{b}),
    };
}
/// "YYYY-MM-DDTHH:MM:SSZ" (std.time.epoch.EpochSeconds; pre-1970 -> epoch).
pub fn iso8601(buf: *[20]u8, unix: i64) []const u8 {
    const secs: u64 = if (unix < 0) 0 else @intCast(unix);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

test "sanitize: json policy never lets invalid UTF-8 reach Stringify as a string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try string(a, "bad\xffutf8\x01ctl", .json, 4096);
    try std.testing.expect(s.lossy);
    try std.testing.expect(std.unicode.utf8ValidateSlice(s.text));
    try std.testing.expectEqualStrings("bad\u{FFFD}utf8\u{FFFD}ctl", s.text);
    const clean = try string(a, "héllo", .json, 4096);
    try std.testing.expect(!clean.lossy);
    const t = try string(a, "a\x01b", .text, 4096);
    try std.testing.expectEqualStrings("a\\x01b", t.text);
    var buf: [20]u8 = undefined;
    try std.testing.expectEqualStrings("2025-09-12T04:29:38Z", iso8601(&buf, 0x68c3a1b2));
}

test "sanitize: text policy neutralises terminal controls and keeps real UTF-8" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The reported defect: a crafted 16-byte segment name carrying SGR + CR.
    const seg = try string(a, "\x1b[31mPWNED\x1b[0m\r", .text, 4096);
    try std.testing.expect(seg.lossy);
    try std.testing.expectEqualStrings("\\x1b[31mPWNED\\x1b[0m\\x0d", seg.text);
    // Unicode app names must still render.
    const uni = try string(a, "Café\u{1F512}日本語", .text, 4096);
    try std.testing.expect(!uni.lossy);
    try std.testing.expectEqualStrings("Café\u{1F512}日本語", uni.text);
    // C1 CSI, DEL, BEL, backspace, NUL, invalid UTF-8, bidi override.
    try std.testing.expectEqualStrings("\\u{9b}", (try string(a, "\u{9b}", .text, 4096)).text);
    try std.testing.expectEqualStrings("\\x7f\\x07\\x08\\x00", (try string(a, "\x7f\x07\x08\x00", .text, 4096)).text);
    try std.testing.expectEqualStrings("a\\xffb", (try string(a, "a\xffb", .text, 4096)).text);
    try std.testing.expectEqualStrings("evil\\u{202e}gpj.exe", (try string(a, "evil\u{202e}gpj.exe", .text, 4096)).text);
    try std.testing.expect(!isClean("a\rb", .text));
    try std.testing.expect(isClean("Café", .text));
    var n: u32 = 0;
    _ = try forText(a, "ok", &n);
    try std.testing.expectEqual(@as(u32, 0), n);
    _ = try forText(a, "no\x1bt ok", &n);
    try std.testing.expectEqual(@as(u32, 1), n);
}
