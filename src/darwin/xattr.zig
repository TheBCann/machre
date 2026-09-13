//! darwin/xattr.zig — getxattr/listxattr, com.apple.quarantine parsing, AppTranslocation detection.
//! Externs gated on builtin.os.tag == .macos. Imports: core/diag, core/sanitize.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");

pub const Quarantine = struct { raw: []const u8, flags: ?u16, timestamp: ?i64, agent: ?[]const u8, uuid: ?[]const u8, well_formed: bool };
pub const Xattrs = struct {
    available: bool, // false off-macOS
    names: []const []const u8,
    quarantine: ?Quarantine,
    is_translocated: bool,
    provenance_present: bool, // com.apple.provenance
    pub const empty: Xattrs = .{ .available = false, .names = &.{}, .quarantine = null, .is_translocated = false, .provenance_present = false };
};

/// Caps applied before any allocation (this module may not import core/limits; §4 DAG).
const max_name_list_bytes: usize = 1 << 16;
const max_names: usize = 256;
const max_name_bytes: u32 = 512;
const max_value_bytes: usize = 1 << 16;

pub const quarantine_name: [:0]const u8 = "com.apple.quarantine";
pub const provenance_name: []const u8 = "com.apple.provenance";
pub const translocation_marker: []const u8 = "/AppTranslocation/";

/// listxattr + getxattr; ENOATTR -> null quarantine; other errno -> os_error diagnostic.
pub fn read(arena: Allocator, path_z: [:0]const u8, diags: *Diagnostics) Allocator.Error!Xattrs {
    if (!is_macos) return .empty;
    var out: Xattrs = .{
        .available = true,
        .names = &.{},
        .quarantine = null,
        .is_translocated = isTranslocatedPath(path_z),
        .provenance_present = false,
    };
    const listed = listxattr(path_z.ptr, null, 0, 0);
    if (listed < 0) {
        osError(diags, "listxattr", listed);
        out.available = false;
        return out;
    }
    var want: usize = @intCast(listed);
    if (want > max_name_list_bytes) {
        if (!diags.has(.xattr, .count_clamped))
            diags.warn(.xattr, .count_clamped, null, "xattr name list is {d} bytes; reading only {d}", .{ want, max_name_list_bytes });
        want = max_name_list_bytes;
    }
    if (want != 0) {
        const buf = try arena.alloc(u8, want);
        const got = listxattr(path_z.ptr, buf.ptr, buf.len, 0);
        if (got < 0) {
            osError(diags, "listxattr", got);
            out.available = false;
            return out;
        }
        const n = @min(@as(usize, @intCast(got)), buf.len);
        out.names = try splitNames(arena, buf[0..n], diags);
    }
    for (out.names) |n| {
        if (std.mem.eql(u8, n, provenance_name)) out.provenance_present = true;
    }
    out.quarantine = try readQuarantine(arena, path_z, diags);
    return out;
}

/// NUL-separated name buffer -> sanitized, capped list.
fn splitNames(arena: Allocator, buf: []const u8, diags: *Diagnostics) Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < buf.len) {
        const end = std.mem.findScalarPos(u8, buf, i, 0) orelse buf.len;
        if (end > i) {
            if (list.items.len >= max_names) {
                if (!diags.has(.xattr, .count_clamped))
                    diags.warn(.xattr, .count_clamped, null, "more than {d} extended attributes; list truncated", .{max_names});
                break;
            }
            const s = try sanitize.string(arena, buf[i..end], .json, max_name_bytes);
            try list.append(arena, s.text);
        }
        if (end >= buf.len) break;
        i = end + 1;
    }
    return list.toOwnedSlice(arena);
}

/// getxattr("com.apple.quarantine"); ENOATTR -> null (not an error).
fn readQuarantine(arena: Allocator, path_z: [:0]const u8, diags: *Diagnostics) Allocator.Error!?Quarantine {
    const sized = getxattr(path_z.ptr, quarantine_name.ptr, null, 0, 0, 0);
    if (sized < 0) {
        if (std.posix.errno(sized) != .NOATTR) osError(diags, "getxattr(com.apple.quarantine)", sized);
        return null;
    }
    var want: usize = @intCast(sized);
    if (want == 0) return try parseQuarantine(arena, "");
    if (want > max_value_bytes) {
        if (!diags.has(.xattr, .count_clamped))
            diags.warn(.xattr, .count_clamped, null, "quarantine xattr is {d} bytes; reading only {d}", .{ want, max_value_bytes });
        want = max_value_bytes;
    }
    const buf = try arena.alloc(u8, want);
    const got = getxattr(path_z.ptr, quarantine_name.ptr, buf.ptr, buf.len, 0, 0);
    if (got < 0) {
        osError(diags, "getxattr(com.apple.quarantine)", got);
        return null;
    }
    return try parseQuarantine(arena, buf[0..@min(@as(usize, @intCast(got)), buf.len)]);
}

fn osError(diags: *Diagnostics, comptime what: []const u8, rc: isize) void {
    if (diags.has(.xattr, .os_error)) return;
    diags.warn(.xattr, .os_error, null, what ++ " failed: {t}", .{std.posix.errno(rc)});
}

/// One attribute's value, sanitized for output; null when absent (ENOATTR) or unreadable.
/// Used by `machre quarantine --otool-compat` to mirror `xattr -l`.
pub fn readValue(arena: Allocator, path_z: [:0]const u8, name_z: [:0]const u8, diags: *Diagnostics) Allocator.Error!?[]const u8 {
    if (!is_macos) return null;
    const sized = getxattr(path_z.ptr, name_z.ptr, null, 0, 0, 0);
    if (sized < 0) {
        if (std.posix.errno(sized) != .NOATTR) osError(diags, "getxattr", sized);
        return null;
    }
    var want: usize = @intCast(sized);
    if (want == 0) return "";
    if (want > max_value_bytes) want = max_value_bytes;
    const buf = try arena.alloc(u8, want);
    const got = getxattr(path_z.ptr, name_z.ptr, buf.ptr, buf.len, 0, 0);
    if (got < 0) {
        osError(diags, "getxattr", got);
        return null;
    }
    const n = @min(@as(usize, @intCast(got)), buf.len);
    return (try sanitize.string(arena, buf[0..n], .json, max_value_bytes)).text;
}

/// Pure: "flags;hex-time;agent;uuid".
pub fn parseQuarantine(arena: Allocator, raw: []const u8) Allocator.Error!Quarantine {
    const clean = (try sanitize.string(arena, raw, .json, max_value_bytes)).text;
    var q: Quarantine = .{ .raw = clean, .flags = null, .timestamp = null, .agent = null, .uuid = null, .well_formed = false };
    if (clean.len == 0) return q;
    var it = std.mem.splitScalar(u8, clean, ';');
    const f = it.next() orelse return q;
    const t = it.next() orelse return q;
    const a = it.next() orelse return q;
    const u = it.next() orelse return q;
    if (it.next() != null) return q; // more than four fields: keep `raw`, well_formed = false
    q.flags = std.fmt.parseInt(u16, f, 16) catch null;
    q.timestamp = std.fmt.parseInt(i64, t, 16) catch null;
    if (a.len != 0) q.agent = a;
    if (u.len != 0) q.uuid = u;
    q.well_formed = q.flags != null and q.timestamp != null;
    return q;
}

/// Pure: contains "/AppTranslocation/".
pub fn isTranslocatedPath(path: []const u8) bool {
    return std.mem.find(u8, path, translocation_marker) != null;
}

/// The `file.xattrs` / `file.quarantine` / `file.translocated` trio of the JSON envelope (DESIGN §6.1),
/// shaped for `output/json.envelopeBegin`'s `xattr_json` parameter. Arena-owned.
pub fn envelopeJson(arena: Allocator, x: Xattrs) Allocator.Error!std.json.Value {
    var names: std.json.Array = .init(arena);
    for (x.names) |n| try names.append(.{ .string = n });
    var root: std.json.ObjectMap = .empty;
    try root.put(arena, "xattrs", .{ .array = names });
    if (x.quarantine) |q| {
        var qo: std.json.ObjectMap = .empty;
        try qo.put(arena, "raw", .{ .string = q.raw });
        // §6.2: flag values are lowercase "0x…" strings; times are ISO-8601 with a _unix sibling.
        try qo.put(arena, "flags", if (q.flags) |f| .{ .string = try std.fmt.allocPrint(arena, "0x{x}", .{f}) } else .null);
        if (q.timestamp) |t| {
            var iso: [20]u8 = undefined;
            try qo.put(arena, "timestamp", .{ .string = try arena.dupe(u8, sanitize.iso8601(&iso, t)) });
        } else try qo.put(arena, "timestamp", .null);
        try qo.put(arena, "timestamp_unix", if (q.timestamp) |t| .{ .integer = t } else .null);
        try qo.put(arena, "agent", if (q.agent) |a| .{ .string = a } else .null);
        try qo.put(arena, "uuid", if (q.uuid) |u| .{ .string = u } else .null);
        try qo.put(arena, "well_formed", .{ .bool = q.well_formed });
        try root.put(arena, "quarantine", .{ .object = qo });
    } else try root.put(arena, "quarantine", .null);
    try root.put(arena, "translocated", .{ .bool = x.is_translocated });
    return .{ .object = root };
}
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?[*]u8, size: usize, position: u32, options: c_int) isize;
extern "c" fn listxattr(path: [*:0]const u8, namebuf: ?[*]u8, size: usize, options: c_int) isize;
const XATTR_NOFOLLOW: c_int = 0x0001;

// ---- tests ----

test "xattr: parseQuarantine on the corpus value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try parseQuarantine(arena.allocator(), "0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C");
    try std.testing.expect(q.well_formed);
    try std.testing.expectEqual(@as(?u16, 0x0083), q.flags);
    try std.testing.expectEqual(@as(?i64, 0x68c3a1b2), q.timestamp);
    try std.testing.expectEqualStrings("Safari", q.agent.?);
    try std.testing.expectEqualStrings("9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C", q.uuid.?);
    var buf: [20]u8 = undefined;
    try std.testing.expectEqualStrings("2025-09-12T04:29:38Z", sanitize.iso8601(&buf, q.timestamp.?));
}

test "xattr: parseQuarantine keeps raw for malformed values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_][]const u8{
        "", // empty
        "0083", // one field
        "0083;68c3a1b2;Safari", // three fields
        "0083;68c3a1b2;Safari;uuid;extra", // five fields
        "zzzz;68c3a1b2;Safari;uuid", // bad flags
        "0083;zzzzzzzz;Safari;uuid", // bad time
        "1FFFFF;68c3a1b2;Safari;uuid", // flags overflow u16
    };
    for (cases) |c| {
        const q = try parseQuarantine(a, c);
        try std.testing.expect(!q.well_formed);
        try std.testing.expectEqualStrings(c, q.raw);
    }
    // Empty agent/uuid fields are tolerated but reported as absent.
    const q = try parseQuarantine(a, "0081;6a8dca47;;");
    try std.testing.expect(q.well_formed);
    try std.testing.expect(q.agent == null and q.uuid == null);
}

test "xattr: parseQuarantine sanitizes hostile bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try parseQuarantine(arena.allocator(), "0083;68c3a1b2;Saf\x00ari\xff;u");
    try std.testing.expect(std.mem.find(u8, q.raw, "\x00") == null);
    try std.testing.expect(std.mem.find(u8, q.raw, "\xff") == null);
}

test "xattr: every prefix of a quarantine value parses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const full = "0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C";
    for (0..full.len + 1) |n| {
        const q = try parseQuarantine(arena.allocator(), full[0..n]);
        try std.testing.expect(q.raw.len <= n);
    }
}

test "xattr: isTranslocatedPath" {
    try std.testing.expect(isTranslocatedPath("/private/var/folders/aa/bbb/T/AppTranslocation/UUID/d/X.app/Contents/MacOS/X"));
    try std.testing.expect(!isTranslocatedPath("/Applications/X.app/Contents/MacOS/X"));
    try std.testing.expect(!isTranslocatedPath("AppTranslocation"));
    try std.testing.expect(!isTranslocatedPath(""));
}

test "xattr: splitNames caps and sanitizes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 8);
    const names = try splitNames(a, "com.apple.quarantine\x00com.apple.provenance\x00\x00bad\xffname\x00", &diags);
    try std.testing.expectEqual(@as(usize, 3), names.len);
    try std.testing.expectEqualStrings("com.apple.quarantine", names[0]);
    try std.testing.expectEqualStrings("com.apple.provenance", names[1]);
    try std.testing.expect(std.mem.find(u8, names[2], "\xff") == null);
    // Unterminated final name is still reported.
    const tail = try splitNames(a, "a\x00b", &diags);
    try std.testing.expectEqual(@as(usize, 2), tail.len);
}

test "xattr: envelopeJson shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const q = try parseQuarantine(a, "0083;68c3a1b2;Safari;U");
    const v = try envelopeJson(a, .{ .available = true, .names = &.{"com.apple.quarantine"}, .quarantine = q, .is_translocated = false, .provenance_present = false });
    try std.testing.expectEqual(@as(usize, 1), v.object.get("xattrs").?.array.items.len);
    try std.testing.expectEqualStrings("0x83", v.object.get("quarantine").?.object.get("flags").?.string);
    try std.testing.expectEqualStrings("2025-09-12T04:29:38Z", v.object.get("quarantine").?.object.get("timestamp").?.string);
    try std.testing.expect(!v.object.get("translocated").?.bool);
    const e = try envelopeJson(a, .empty);
    try std.testing.expectEqual(@as(usize, 0), e.object.get("xattrs").?.array.items.len);
    try std.testing.expect(e.object.get("quarantine").? == .null);
}

test "xattr: read on a path that does not exist never traps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 8);
    const x = try read(a, "/nonexistent/machre/xattr/probe", &diags);
    try std.testing.expect(x.quarantine == null);
    try std.testing.expectEqual(@as(usize, 0), x.names.len);
    if (is_macos) try std.testing.expect(!x.available);
}
