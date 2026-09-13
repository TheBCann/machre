//! plist/xml.zig — minimal XML plist reader (prologue/DOCTYPE skip, entities, <data> base64, depth cap).
//! Imports: plist/plist, core/reader, core/diag, core/limits.
//!
//! Single pass over the bytes with an explicit container stack: no recursion, every loop bounded by the
//! input length, the element stack bounded by `Limits.max_plist_depth` and the produced values by
//! `Limits.max_plist_objects`. Unknown elements are skipped with one diagnostic.
const std = @import("std");
const Allocator = std.mem.Allocator;
const plist = @import("plist.zig");
const Value = plist.Value;
const Reader = @import("../core/reader.zig").Reader;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

const Tag = struct {
    name: []const u8,
    closing: bool,
    self_closing: bool,
};

const Frame = struct {
    is_dict: bool,
    items: std.ArrayList(Value),
    entries: std.ArrayList(Value.Entry),
    pending_key: ?[]const u8,
};

const Parser = struct {
    arena: Allocator,
    src: []const u8,
    pos: usize = 0,
    limits: *const Limits,
    diags: *Diagnostics,
    stack: std.ArrayList(Frame) = .empty,
    root: ?Value = null,
    values: u32 = 0,

    fn bad(p: *Parser, comptime fmt: []const u8, args: anytype) void {
        if (!p.diags.has(.plist, .plist_malformed)) p.diags.warn(.plist, .plist_malformed, p.pos, fmt, args);
    }
};

/// `null` when nothing plist-shaped was found; otherwise the root value plus diagnostics for anything
/// that did not parse.
pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value {
    var src = bytes;
    if (src.len > limits.max_xml_bytes) {
        diags.warn(.plist, .limit_reached, null, "XML plist {d} bytes cut to max_xml_bytes {d}", .{ src.len, limits.max_xml_bytes });
        src = src[0..limits.max_xml_bytes];
    }
    if (std.mem.startsWith(u8, src, "\xef\xbb\xbf")) src = src[3..];
    var p: Parser = .{ .arena = arena, .src = src, .limits = limits, .diags = diags };
    try run(&p);
    // Close containers that the file never closed.
    while (p.stack.items.len != 0) {
        if (!diags.has(.plist, .truncated)) diags.warn(.plist, .truncated, p.pos, "XML plist ended with {d} unclosed element(s)", .{p.stack.items.len});
        const v = try finishTop(&p);
        try emit(&p, v);
    }
    if (p.root == null) {
        diags.warn(.plist, .plist_malformed, null, "XML plist contains no value element", .{});
        return null;
    }
    return p.root;
}

fn run(p: *Parser) Allocator.Error!void {
    while (true) {
        const t = (try nextTag(p)) orelse return;
        if (t.closing) {
            if (eq(t.name, "plist")) return;
            if (eq(t.name, "dict") or eq(t.name, "array")) {
                if (p.stack.items.len == 0) {
                    p.bad("stray </{s}>", .{t.name});
                    continue;
                }
                const v = try finishTop(p);
                try emit(p, v);
                continue;
            }
            continue; // stray </key>, </string>, ... : the openers consume their own closers
        }
        if (eq(t.name, "plist")) continue;
        if (eq(t.name, "dict") or eq(t.name, "array")) {
            const is_dict = eq(t.name, "dict");
            if (t.self_closing) {
                try emit(p, if (is_dict) Value{ .dict = &.{} } else Value{ .array = &.{} });
                continue;
            }
            if (p.stack.items.len >= p.limits.max_plist_depth) {
                if (!p.diags.has(.plist, .limit_reached)) p.diags.warn(.plist, .limit_reached, p.pos, "XML plist nesting deeper than max_plist_depth {d}", .{p.limits.max_plist_depth});
                try skipElement(p, t.name);
                try emit(p, if (is_dict) Value{ .dict = &.{} } else Value{ .array = &.{} });
                continue;
            }
            try p.stack.append(p.arena, .{ .is_dict = is_dict, .items = .empty, .entries = .empty, .pending_key = null });
            continue;
        }
        if (eq(t.name, "key")) {
            const text = try elementText(p, "key", t.self_closing);
            if (p.stack.items.len == 0 or !p.stack.items[p.stack.items.len - 1].is_dict) {
                p.bad("<key> outside a <dict>", .{});
                continue;
            }
            const top = &p.stack.items[p.stack.items.len - 1];
            if (top.pending_key != null) {
                p.bad("two <key> elements in a row", .{});
                try appendEntry(p, top, .null);
            }
            top.pending_key = try plist.internString(p.arena, text, p.limits, p.diags);
            continue;
        }
        if (eq(t.name, "true") or eq(t.name, "false")) {
            if (!t.self_closing) _ = try elementText(p, t.name, false);
            try emit(p, .{ .bool = eq(t.name, "true") });
            continue;
        }
        if (eq(t.name, "string")) {
            const text = try elementText(p, "string", t.self_closing);
            try emit(p, .{ .string = try plist.internString(p.arena, text, p.limits, p.diags) });
            continue;
        }
        if (eq(t.name, "integer")) {
            const text = try elementText(p, "integer", t.self_closing);
            try emit(p, .{ .integer = parseIntLoose(std.mem.trim(u8, text, " \t\r\n")) });
            continue;
        }
        if (eq(t.name, "real")) {
            const text = try elementText(p, "real", t.self_closing);
            const f = std.fmt.parseFloat(f64, std.mem.trim(u8, text, " \t\r\n")) catch blk: {
                p.bad("<real> is not a number", .{});
                break :blk 0;
            };
            try emit(p, .{ .real = f });
            continue;
        }
        if (eq(t.name, "date")) {
            const text = try elementText(p, "date", t.self_closing);
            try emit(p, .{ .date = parseIso8601(std.mem.trim(u8, text, " \t\r\n")) orelse blk: {
                p.bad("<date> is not ISO-8601", .{});
                break :blk 0;
            } });
            continue;
        }
        if (eq(t.name, "data")) {
            const text = try elementText(p, "data", t.self_closing);
            try emit(p, .{ .data = try decodeBase64(p, text) });
            continue;
        }
        // Unknown element: report once and skip its subtree.
        if (!p.diags.has(.plist, .unknown_value)) p.diags.warn(.plist, .unknown_value, p.pos, "XML plist: unknown element <{s}> skipped", .{t.name});
        if (!t.self_closing) try skipElement(p, t.name);
    }
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Appends a finished value to the container on top of the stack (or makes it the root).
fn emit(p: *Parser, v: Value) Allocator.Error!void {
    p.values += 1;
    if (p.values > p.limits.max_plist_objects) {
        if (!p.diags.has(.plist, .limit_reached)) p.diags.warn(.plist, .limit_reached, p.pos, "XML plist has more than max_plist_objects {d} values", .{p.limits.max_plist_objects});
        return;
    }
    if (p.stack.items.len == 0) {
        if (p.root == null) p.root = v;
        return;
    }
    const top = &p.stack.items[p.stack.items.len - 1];
    if (top.is_dict) {
        if (top.pending_key == null) {
            p.bad("value inside <dict> without a preceding <key>", .{});
            return;
        }
        try appendEntry(p, top, v);
        return;
    }
    try top.items.append(p.arena, v);
}
fn appendEntry(p: *Parser, top: *Frame, v: Value) Allocator.Error!void {
    const k = top.pending_key orelse "";
    top.pending_key = null;
    try top.entries.append(p.arena, .{ .key = k, .value = v });
}

fn finishTop(p: *Parser) Allocator.Error!Value {
    var f = p.stack.pop().?;
    if (f.is_dict) {
        if (f.pending_key != null) {
            p.bad("<dict> ended with a dangling <key>", .{});
            try f.entries.append(p.arena, .{ .key = f.pending_key.?, .value = .null });
        }
        return .{ .dict = try f.entries.toOwnedSlice(p.arena) };
    }
    return .{ .array = try f.items.toOwnedSlice(p.arena) };
}

/// Advances to the next element tag, skipping `<?…?>`, `<!--…-->`, `<!DOCTYPE …>` and character data.
/// Returns null at end of input.
fn nextTag(p: *Parser) Allocator.Error!?Tag {
    while (true) {
        const lt = std.mem.findScalarPos(u8, p.src, p.pos, '<') orelse {
            p.pos = p.src.len;
            return null;
        };
        p.pos = lt + 1;
        if (p.pos >= p.src.len) return null;
        const c = p.src[p.pos];
        if (c == '?') {
            p.pos = skipPast(p, "?>");
            continue;
        }
        if (c == '!') {
            if (std.mem.startsWith(u8, p.src[p.pos..], "!--")) {
                p.pos = skipPast(p, "-->");
                continue;
            }
            p.pos = skipDoctype(p);
            continue;
        }
        var closing = false;
        if (c == '/') {
            closing = true;
            p.pos += 1;
        }
        const name_start = p.pos;
        while (p.pos < p.src.len and isNameByte(p.src[p.pos])) p.pos += 1;
        const name = p.src[name_start..p.pos];
        // Attributes / whitespace up to '>'.
        var self_closing = false;
        while (p.pos < p.src.len and p.src[p.pos] != '>') {
            if (p.src[p.pos] == '/') self_closing = true;
            p.pos += 1;
        }
        if (p.pos < p.src.len) p.pos += 1; // consume '>'
        if (name.len == 0) {
            p.bad("malformed tag", .{});
            continue;
        }
        if (name.len > 64) {
            if (!p.diags.has(.plist, .unknown_value)) p.diags.warn(.plist, .unknown_value, name_start, "XML plist: absurd element name ({d} bytes)", .{name.len});
            continue;
        }
        return .{ .name = name, .closing = closing, .self_closing = self_closing };
    }
}
fn isNameByte(b: u8) bool {
    return (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or (b >= '0' and b <= '9') or b == '_' or b == '-' or b == ':' or b == '.';
}
fn skipPast(p: *Parser, needle: []const u8) usize {
    const at = std.mem.findPos(u8, p.src, p.pos, needle) orelse return p.src.len;
    return at + needle.len;
}
/// `<!DOCTYPE …>` possibly with a `[ … ]` internal subset.
fn skipDoctype(p: *Parser) usize {
    var i = p.pos;
    var in_subset = false;
    while (i < p.src.len) : (i += 1) {
        const b = p.src[i];
        if (b == '[') in_subset = true;
        if (b == ']') in_subset = false;
        if (b == '>' and !in_subset) return i + 1;
    }
    return p.src.len;
}

/// Text between the current position and `</name>`, entity-decoded. `self_closing` -> "".
fn elementText(p: *Parser, name: []const u8, self_closing: bool) Allocator.Error![]const u8 {
    if (self_closing) return "";
    const start = p.pos;
    var close_buf: [72]u8 = undefined;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return "";
    const at = std.mem.findPos(u8, p.src, p.pos, close) orelse {
        if (!p.diags.has(.plist, .truncated)) p.diags.warn(.plist, .truncated, start, "XML plist: <{s}> is never closed", .{name});
        p.pos = p.src.len;
        return decodeEntities(p.arena, p.src[start..]);
    };
    p.pos = at + close.len;
    return decodeEntities(p.arena, p.src[start..at]);
}

/// Skips a whole `<name>…</name>` subtree, counting nested openings; bounded by the input length.
fn skipElement(p: *Parser, name: []const u8) Allocator.Error!void {
    var depth: u32 = 1;
    var guard: u32 = 0;
    while (depth != 0) {
        guard += 1;
        if (guard > p.limits.max_plist_objects) return;
        const t = (try nextTagRaw(p)) orelse return;
        if (!eq(t.name, name)) continue;
        if (t.closing) {
            depth -= 1;
        } else if (!t.self_closing) depth += 1;
    }
}
/// Like `nextTag` but without the name-length diagnostics (used by `skipElement`).
fn nextTagRaw(p: *Parser) Allocator.Error!?Tag {
    const before = p.pos;
    const t = try nextTag(p);
    if (t == null and p.pos == before) p.pos = p.src.len;
    return t;
}

/// Decode `&amp; &lt; &gt; &quot; &apos; &#N; &#xN;` into an arena copy (returns input when no entity).
pub fn decodeEntities(arena: Allocator, text: []const u8) Allocator.Error![]const u8 {
    if (std.mem.findScalar(u8, text, '&') == null) return text;
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, text.len);
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] != '&') {
            try out.append(arena, text[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.findScalarPos(u8, text, i + 1, ';') orelse {
            try out.append(arena, text[i]);
            i += 1;
            continue;
        };
        if (semi - i > 12) {
            try out.append(arena, text[i]);
            i += 1;
            continue;
        }
        const body = text[i + 1 .. semi];
        var handled = true;
        if (eq(body, "amp")) {
            try out.append(arena, '&');
        } else if (eq(body, "lt")) {
            try out.append(arena, '<');
        } else if (eq(body, "gt")) {
            try out.append(arena, '>');
        } else if (eq(body, "quot")) {
            try out.append(arena, '"');
        } else if (eq(body, "apos")) {
            try out.append(arena, '\'');
        } else if (body.len > 1 and body[0] == '#') {
            const hex = body[1] == 'x' or body[1] == 'X';
            const digits = if (hex) body[2..] else body[1..];
            const cp: ?u21 = std.fmt.parseInt(u21, digits, if (hex) 16 else 10) catch null;
            var buf: [4]u8 = undefined;
            const n: usize = if (cp) |x| (std.unicode.utf8Encode(x, &buf) catch 0) else 0;
            if (n == 0) handled = false else try out.appendSlice(arena, buf[0..n]);
        } else handled = false;
        if (!handled) {
            try out.appendSlice(arena, text[i .. semi + 1]);
        }
        i = semi + 1;
    }
    return out.toOwnedSlice(arena);
}

fn decodeBase64(p: *Parser, text: []const u8) Allocator.Error![]const u8 {
    const dec = std.base64.standard.decoderWithIgnore(" \n\t\r");
    const upper = dec.calcSizeUpperBound(text.len);
    if (upper > p.limits.max_string_len * 16) {
        p.diags.warn(.plist, .limit_reached, p.pos, "<data> of {d} bytes is too large", .{upper});
        return "";
    }
    const buf = try p.arena.alloc(u8, upper);
    const n = dec.decode(buf, text) catch {
        p.bad("<data> is not valid base64", .{});
        return "";
    };
    return buf[0..n];
}

fn parseIntLoose(s: []const u8) i64 {
    if (std.fmt.parseInt(i64, s, 0)) |v| return v else |_| {}
    if (std.fmt.parseInt(u64, s, 0)) |v| return @bitCast(v) else |_| {}
    return 0;
}

/// "YYYY-MM-DDTHH:MM:SSZ" -> seconds since 2001-01-01T00:00:00Z (the plist date epoch).
pub fn parseIso8601(s: []const u8) ?f64 {
    if (s.len < 20) return null;
    if (s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(i64, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, s[8..10], 10) catch return null;
    const h = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const se = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or se > 60) return null;
    const days = daysFromCivil(y, mo, d);
    const unix = days * 86400 + h * 3600 + mi * 60 + se;
    return @floatFromInt(unix - plist.cf_epoch_offset);
}
/// Days since 1970-01-01 (Howard Hinnant's civil-from-days inverse; valid for any proleptic Gregorian date).
fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = y_in - @as(i64, if (m <= 2) 1 else 0);
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const doy = @divTrunc(153 * (m + (if (m > 2) @as(i64, -3) else 9)) + 2, 5) + d - 1; // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    \\<plist version="1.0">
    \\<dict>
    \\    <key>s</key><string>a &amp; b &#65; &#x42;</string>
    \\    <key>i</key><integer>300</integer>
    \\    <key>r</key><real>1.5</real>
    \\    <key>t</key><true/>
    \\    <key>f</key><false/>
    \\    <key>d</key><data>
    \\    QbheIDu4wiSvu1zAK7Sl0oBJt1Q=
    \\    </data>
    \\    <key>when</key><date>2001-01-01T00:00:01Z</date>
    \\    <key>arr</key><array><string>x</string><dict/><array/></array>
    \\    <key>nest</key><dict><key>n</key><integer>-1</integer></dict>
    \\</dict>
    \\</plist>
;

test "xml: full sample parses to the expected tree" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 32);
    const v = (try parse(arena, sample, &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(usize, 9), v.dict.len);
    try std.testing.expectEqualStrings("a & b A B", v.getString("s").?);
    try std.testing.expectEqual(@as(?i64, 300), v.getInteger("i"));
    try std.testing.expectEqual(@as(f64, 1.5), v.get("r").?.real);
    try std.testing.expectEqual(@as(?bool, true), v.getBool("t"));
    try std.testing.expectEqual(@as(?bool, false), v.getBool("f"));
    try std.testing.expectEqual(@as(usize, 20), v.get("d").?.data.len);
    try std.testing.expectEqual(@as(u8, 0x41), v.get("d").?.data[0]);
    try std.testing.expectEqual(@as(u8, 0x54), v.get("d").?.data[19]);
    try std.testing.expectEqual(@as(f64, 1.0), v.get("when").?.date);
    try std.testing.expectEqual(@as(usize, 3), v.get("arr").?.array.len);
    try std.testing.expectEqual(@as(usize, 0), v.get("arr").?.array[1].dict.len);
    try std.testing.expectEqual(@as(i64, -1), v.path("nest.n").?.integer);
    try std.testing.expectEqual(@as(usize, 0), diags.items().len);
}

test "xml: every truncation of the sample parses without error" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var i: usize = 0;
    while (i <= sample.len) : (i += 1) {
        var diags = Diagnostics.init(arena, 8);
        _ = try parse(arena, sample[0..i], &Limits.default, &diags);
    }
}

test "xml: entities, unknown elements and dangling keys" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("plain", try decodeEntities(arena, "plain"));
    try std.testing.expectEqualStrings("<a>&\"'", try decodeEntities(arena, "&lt;a&gt;&amp;&quot;&apos;"));
    try std.testing.expectEqualStrings("héllo", try decodeEntities(arena, "h&#233;llo"));
    try std.testing.expectEqualStrings("&nope;x", try decodeEntities(arena, "&nope;x"));
    try std.testing.expectEqualStrings("&broken", try decodeEntities(arena, "&broken"));

    var diags = Diagnostics.init(arena, 32);
    const v = (try parse(arena,
        \\<plist><dict><bogus><key>ignored</key></bogus><key>k</key><string>v</string><key>dangling</key></dict></plist>
    , &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(usize, 2), v.dict.len);
    try std.testing.expectEqualStrings("v", v.getString("k").?);
    try std.testing.expect(v.get("dangling").? == .null);
    try std.testing.expect(diags.has(.plist, .unknown_value));
}

test "xml: date and depth limits" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqual(@as(?f64, 0), parseIso8601("2001-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?f64, -978307200), parseIso8601("1970-01-01T00:00:00Z"));
    // 2025-09-12T04:29:38Z = unix 1757651378 (0x68c3a1b2) = CF 779344178.
    try std.testing.expectEqual(@as(?f64, 779344178), parseIso8601("2025-09-12T04:29:38Z"));
    try std.testing.expect(parseIso8601("nope") == null);
    try std.testing.expect(parseIso8601("2001-13-01T00:00:00Z") == null);

    var lim = Limits.paranoid;
    lim.max_plist_depth = 2;
    var diags = Diagnostics.init(arena, 32);
    const v = (try parse(arena, "<plist><array><array><array><string>x</string></array></array></array></plist>", &lim, &diags)).?;
    try std.testing.expectEqual(@as(usize, 1), v.array.len);
    try std.testing.expectEqual(@as(usize, 0), v.array[0].array[0].array.len);
    try std.testing.expect(diags.has(.plist, .limit_reached));
}

test "xml: garbage never loops and never allocates unboundedly" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 32);
    try std.testing.expect(try parse(arena, "<<<<<<<<", &Limits.paranoid, &diags) == null);
    try std.testing.expect(try parse(arena, "<plist>", &Limits.paranoid, &diags) == null);
    _ = try parse(arena, "<plist><dict><key>a", &Limits.paranoid, &diags);
    _ = try parse(arena, "<!DOCTYPE x [ <!ENTITY y \"z\"> ]><plist><string>ok</string></plist>", &Limits.paranoid, &diags);
    const ok = (try parse(arena, "<!DOCTYPE x [ <!ENTITY y \"z\"> ]><plist><string>ok</string></plist>", &Limits.paranoid, &diags)).?;
    try std.testing.expectEqualStrings("ok", ok.string);
}
