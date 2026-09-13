//! plist/plist.zig — Value model + format detection + parseAny. Imports: core/diag, core/limits, core/sanitize.
//!
//! Invariant maintained by both parsers: every `string` and every `Entry.key` in a parsed `Value` has
//! already gone through `core.sanitize.string(.json)`, so it is valid UTF-8 without C0 controls and can be
//! written to JSON or to a terminal unchanged. `data` keeps the raw bytes.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");
const bplist = @import("bplist.zig");
const xml = @import("xml.zig");

/// Seconds between the Unix epoch and the CoreFoundation epoch (2001-01-01T00:00:00Z).
pub const cf_epoch_offset: i64 = 978307200;
/// Traversal frames used by the non-recursive walkers (`deepEqual`, `jsonStringify`, renderers).
/// Larger than `Limits.max_plist_depth` so a legally deep tree always fits.
pub const max_walk_depth: usize = 128;

pub const Value = union(enum) {
    null,
    bool: bool,
    integer: i64,
    uid: u64,
    real: f64,
    date: f64, // seconds since 2001-01-01T00:00:00Z
    string: []const u8,
    data: []const u8,
    array: []const Value,
    dict: []const Entry, // insertion order preserved

    pub const Entry = struct { key: []const u8, value: Value };

    pub fn get(v: Value, key: []const u8) ?Value {
        switch (v) {
            .dict => |entries| {
                for (entries) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
                return null;
            },
            else => return null,
        }
    }
    pub fn getString(v: Value, key: []const u8) ?[]const u8 {
        const x = v.get(key) orelse return null;
        return switch (x) {
            .string => |s| s,
            else => null,
        };
    }
    pub fn getBool(v: Value, key: []const u8) ?bool {
        const x = v.get(key) orelse return null;
        return switch (x) {
            .bool => |b| b,
            .integer => |i| i != 0,
            else => null,
        };
    }
    pub fn getInteger(v: Value, key: []const u8) ?i64 {
        const x = v.get(key) orelse return null;
        return switch (x) {
            .integer => |i| i,
            .real => |r| if (r >= -9.2e18 and r <= 9.2e18) @intFromFloat(r) else null,
            .uid => |u| if (u <= std.math.maxInt(i64)) @intCast(u) else null,
            else => null,
        };
    }
    /// Dotted-path lookup ("CFBundleURLTypes.0.CFBundleURLSchemes"). A whole-string key match wins first
    /// so keys that themselves contain dots stay reachable.
    pub fn path(v: Value, dotted: []const u8) ?Value {
        if (v.get(dotted)) |direct| return direct;
        var cur = v;
        var it = std.mem.splitScalar(u8, dotted, '.');
        var steps: usize = 0;
        while (it.next()) |seg| {
            steps += 1;
            if (steps > max_walk_depth) return null;
            switch (cur) {
                .dict => cur = cur.get(seg) orelse return null,
                .array => |items| {
                    const i = std.fmt.parseInt(usize, seg, 10) catch return null;
                    if (i >= items.len) return null;
                    cur = items[i];
                },
                else => return null,
            }
        }
        return cur;
    }
    /// Structural equality, ignoring dict key order (a bplist and its XML twin compare equal).
    /// Iterative (frame stack, `max_walk_depth`) with a key-lookup budget, so it terminates on any
    /// input; a tree deeper than `max_walk_depth` compares as unequal rather than recursing.
    pub fn deepEqual(a: Value, b: Value) bool {
        const Frame = struct { a: Value, b: Value, i: usize };
        var stack: [max_walk_depth]Frame = undefined;
        var budget: u32 = 1 << 22;
        if (!sameTag(a, b)) return false;
        if (!isContainer(a)) return scalarEqual(a, b);
        if (containerLen(a) != containerLen(b)) return false;
        stack[0] = .{ .a = a, .b = b, .i = 0 };
        var depth: usize = 1;
        while (depth != 0) {
            const top = &stack[depth - 1];
            if (top.i >= containerLen(top.a)) {
                depth -= 1;
                continue;
            }
            const i = top.i;
            top.i += 1;
            var ca: Value = .null;
            var cb: Value = .null;
            switch (top.a) {
                .dict => |entries| {
                    ca = entries[i].value;
                    const j = findKey(top.b.dict, entries[i].key, &budget) orelse return false;
                    cb = top.b.dict[j].value;
                },
                .array => |items| {
                    ca = items[i];
                    cb = top.b.array[i];
                },
                else => return false,
            }
            if (!sameTag(ca, cb)) return false;
            if (!isContainer(ca)) {
                if (!scalarEqual(ca, cb)) return false;
                continue;
            }
            if (containerLen(ca) != containerLen(cb)) return false;
            if (depth >= max_walk_depth) return false;
            stack[depth] = .{ .a = ca, .b = cb, .i = 0 };
            depth += 1;
        }
        return true;
    }
    /// data -> {"$data":"<hex>"}, date -> ISO string, uid -> {"$uid":n}; strings are already sanitized
    /// (see the module doc comment). Iterative: never recurses on input-shaped data.
    pub fn jsonStringify(v: Value, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        const Frame = struct { v: Value, i: usize };
        var stack: [max_walk_depth]Frame = undefined;
        var depth: usize = 0;
        if (!isContainer(v)) return writeScalar(v, jw);
        try openContainer(v, jw);
        stack[0] = .{ .v = v, .i = 0 };
        depth = 1;
        while (depth != 0) {
            const top = &stack[depth - 1];
            if (top.i >= containerLen(top.v)) {
                try closeContainer(top.v, jw);
                depth -= 1;
                continue;
            }
            const i = top.i;
            top.i += 1;
            if (top.v == .dict) try jw.objectField(top.v.dict[i].key);
            const child = childAt(top.v, i);
            if (!isContainer(child) or depth >= max_walk_depth) {
                if (isContainer(child)) {
                    try jw.write(null); // deeper than the walker supports; never happens for parsed input
                } else {
                    try writeScalar(child, jw);
                }
                continue;
            }
            try openContainer(child, jw);
            stack[depth] = .{ .v = child, .i = 0 };
            depth += 1;
        }
    }
    /// `plutil -p` type word, used by the text renderers.
    pub fn typeName(v: Value) []const u8 {
        return switch (v) {
            .null => "null",
            .bool => "bool",
            .integer => "integer",
            .uid => "uid",
            .real => "real",
            .date => "date",
            .string => "string",
            .data => "data",
            .array => "array",
            .dict => "dict",
        };
    }
};

pub fn isContainer(v: Value) bool {
    return v == .array or v == .dict;
}
pub fn containerLen(v: Value) usize {
    return switch (v) {
        .array => |a| a.len,
        .dict => |d| d.len,
        else => 0,
    };
}
pub fn childAt(v: Value, i: usize) Value {
    return switch (v) {
        .array => |a| a[i],
        .dict => |d| d[i].value,
        else => .null,
    };
}
/// First entry with this key; `budget` bounds the total key comparisons `deepEqual` may perform.
fn findKey(entries: []const Value.Entry, key: []const u8, budget: *u32) ?usize {
    for (entries, 0..) |e, i| {
        if (budget.* == 0) return null;
        budget.* -= 1;
        if (std.mem.eql(u8, e.key, key)) return i;
    }
    return null;
}
fn sameTag(a: Value, b: Value) bool {
    return std.meta.activeTag(a) == std.meta.activeTag(b);
}
fn scalarEqual(a: Value, b: Value) bool {
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .integer => |x| x == b.integer,
        .uid => |x| x == b.uid,
        .real => |x| x == b.real or (std.math.isNan(x) and std.math.isNan(b.real)),
        .date => |x| x == b.date or (std.math.isNan(x) and std.math.isNan(b.date)),
        .string => |x| std.mem.eql(u8, x, b.string),
        .data => |x| std.mem.eql(u8, x, b.data),
        else => false,
    };
}
fn openContainer(v: Value, jw: *std.json.Stringify) std.json.Stringify.Error!void {
    return switch (v) {
        .array => jw.beginArray(),
        .dict => jw.beginObject(),
        else => {},
    };
}
fn closeContainer(v: Value, jw: *std.json.Stringify) std.json.Stringify.Error!void {
    return switch (v) {
        .array => jw.endArray(),
        .dict => jw.endObject(),
        else => {},
    };
}
fn writeScalar(v: Value, jw: *std.json.Stringify) std.json.Stringify.Error!void {
    switch (v) {
        .null => try jw.write(null),
        .bool => |b| try jw.write(b),
        .integer => |i| {
            if (i > (1 << 53) or i < -(1 << 53)) {
                var buf: [24]u8 = undefined;
                try jw.write(std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable);
            } else try jw.write(i);
        },
        .real => |r| {
            if (std.math.isFinite(r)) try jw.write(r) else try jw.write(null);
        },
        .string => |s| try jw.write(s),
        .uid => {
            try jw.beginObject();
            try jw.objectField("$uid");
            try jw.write(v.uid);
            try jw.endObject();
        },
        .data => |d| {
            try jw.beginObject();
            try jw.objectField("$data");
            try jw.beginWriteRaw();
            try jw.writer.writeByte('"');
            try jw.writer.printHex(d, .lower);
            try jw.writer.writeByte('"');
            jw.endWriteRaw();
            try jw.endObject();
        },
        .date => |d| {
            var buf: [20]u8 = undefined;
            const unix: i64 = if (std.math.isFinite(d) and d > -4.0e17 and d < 4.0e17) @as(i64, @intFromFloat(d)) + cf_epoch_offset else 0;
            try jw.write(sanitize.iso8601(&buf, unix));
        },
        else => try jw.write(null),
    }
}

pub const Format = enum { bplist, xml, unknown };

/// "bplist0" prefix vs "<?xml"/"<plist"/"<!DOCTYPE" (leading whitespace/BOM tolerated).
pub fn detect(bytes: []const u8) Format {
    if (std.mem.startsWith(u8, bytes, "bplist0")) return .bplist;
    var s = bytes;
    if (std.mem.startsWith(u8, s, "\xef\xbb\xbf")) s = s[3..];
    s = std.mem.trimStart(u8, s, " \t\r\n");
    if (std.mem.startsWith(u8, s, "bplist0")) return .bplist;
    if (std.mem.startsWith(u8, s, "<?xml")) return .xml;
    if (std.mem.startsWith(u8, s, "<plist")) return .xml;
    if (std.mem.startsWith(u8, s, "<!DOCTYPE")) return .xml;
    if (std.mem.startsWith(u8, s, "<!--")) return .xml;
    if (std.mem.startsWith(u8, s, "<dict") or std.mem.startsWith(u8, s, "<array")) return .xml;
    return .unknown;
}

/// Detects the format and dispatches; `null` means "not a property list" (one `plist_malformed`).
pub fn parseAny(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value {
    return switch (detect(bytes)) {
        .bplist => bplist.parse(arena, bytes, limits, diags),
        .xml => xml.parse(arena, bytes, limits, diags),
        .unknown => {
            if (!diags.has(.plist, .plist_malformed)) diags.warn(.plist, .plist_malformed, 0, "not a property list ({d} bytes; neither bplist00 nor XML)", .{bytes.len});
            return null;
        },
    };
}

/// Arena copy of `s`, sanitized for both JSON and terminals; used by both parsers on every key/string.
pub fn internString(arena: Allocator, s: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const u8 {
    const r = try sanitize.string(arena, s, .json, limits.max_string_len);
    if (r.lossy and !diags.has(.plist, .invalid_utf8)) diags.warn(.plist, .invalid_utf8, null, "plist string contained bytes that are not valid UTF-8; replaced", .{});
    return r.text;
}

test "plist: value accessors, dotted paths and deepEqual" {
    const inner = [_]Value{ .{ .string = "MacOSX" }, .{ .integer = 7 } };
    const sub = [_]Value.Entry{.{ .key = "n", .value = .{ .integer = 3 } }};
    const top = [_]Value.Entry{
        .{ .key = "CFBundleIdentifier", .value = .{ .string = "com.machre.corpus.Hello" } },
        .{ .key = "LSUIElement", .value = .{ .bool = true } },
        .{ .key = "Platforms", .value = .{ .array = &inner } },
        .{ .key = "Sub", .value = .{ .dict = &sub } },
        .{ .key = "dotted.key", .value = .{ .integer = 9 } },
    };
    const v: Value = .{ .dict = &top };
    try std.testing.expectEqualStrings("com.machre.corpus.Hello", v.getString("CFBundleIdentifier").?);
    try std.testing.expectEqual(@as(?bool, true), v.getBool("LSUIElement"));
    try std.testing.expect(v.getString("nope") == null);
    try std.testing.expectEqualStrings("MacOSX", v.path("Platforms.0").?.string);
    try std.testing.expectEqual(@as(i64, 3), v.path("Sub.n").?.integer);
    try std.testing.expectEqual(@as(i64, 9), v.path("dotted.key").?.integer);
    try std.testing.expect(v.path("Platforms.9") == null);
    try std.testing.expect(v.deepEqual(v));
    const other = [_]Value.Entry{.{ .key = "CFBundleIdentifier", .value = .{ .string = "x" } }};
    try std.testing.expect(!v.deepEqual(.{ .dict = &other }));
    try std.testing.expect(!Value.deepEqual(.{ .integer = 1 }, .{ .real = 1.0 }));
    try std.testing.expect(Value.deepEqual(.null, .null));
}

test "plist: detect and jsonStringify shapes" {
    try std.testing.expectEqual(Format.bplist, detect("bplist00\x00"));
    try std.testing.expectEqual(Format.xml, detect("  \n<?xml version=\"1.0\"?>"));
    try std.testing.expectEqual(Format.xml, detect("\xef\xbb\xbf<plist version=\"1.0\">"));
    try std.testing.expectEqual(Format.unknown, detect("\xcf\xfa\xed\xfe"));
    try std.testing.expectEqual(Format.unknown, detect(""));

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var js: std.json.Stringify = .{ .writer = &w, .options = .{} };
    const arr = [_]Value{ .{ .data = &[_]u8{ 0x41, 0xb8 } }, .{ .uid = 4 }, .{ .date = 1.0 }, .{ .real = 1.5 }, .null };
    const entries = [_]Value.Entry{ .{ .key = "a", .value = .{ .array = &arr } }, .{ .key = "b", .value = .{ .bool = false } } };
    try js.write(Value{ .dict = &entries });
    try std.testing.expectEqualStrings(
        "{\"a\":[{\"$data\":\"41b8\"},{\"$uid\":4},\"2001-01-01T00:00:01Z\",1.5,null],\"b\":false}",
        w.buffered(),
    );
}

test "plist: parseAny rejects non-plists with a diagnostic" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    try std.testing.expect(try parseAny(arena, "\x00\x01\x02", &Limits.default, &diags) == null);
    try std.testing.expect(diags.has(.plist, .plist_malformed));
}
