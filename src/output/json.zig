//! output/json.zig — JSON conventions helpers every cmd/*.zig uses (so conventions cannot drift).
//! Imports: output/sink, core/diag, core/sanitize, core/file, core/image, core/fat.
const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;
const sink = @import("sink.zig");
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const FlagName = @import("../core/fmt.zig").FlagName;
const fat = @import("../core/fat.zig");

pub const Error = sink.Error;
pub const schema_version: u32 = 1;
/// Longest file-derived string sanitised into JSON (longer input is cut).
pub const max_str: u32 = 1 << 20;

/// Sanitisation tally for the JSON payload path, the counterpart of `Sink.lossy` for text.
/// `str`/`strOpt`/`names` take a `*Stringify` and an arena, never the `Sink` (149 call sites, many
/// behind helpers that have no sink in scope), so the tally lives here instead of being threaded:
/// `cli.dispatch` resets it per run, folds it into the same `cli.invalid_utf8` diagnostic the text
/// renderer raises, and passes the total to `envelopeEnd` as `sanitized_strings`. `threadlocal` so a
/// parallel test runner cannot interleave two runs' counts.
threadlocal var lossy_tally: u32 = 0;
pub fn lossyCount() u32 {
    return lossy_tally;
}
pub fn resetLossyCount() void {
    lossy_tally = 0;
}

pub fn hex(js: *Stringify, key: []const u8, v: u64) Error!void {
    try js.objectField(key);
    try js.write(sink.Hex64{ .v = v });
}
pub fn hexOpt(js: *Stringify, key: []const u8, v: ?u64) Error!void {
    try js.objectField(key);
    if (v) |x| try js.write(sink.Hex64{ .v = x }) else try js.write(null);
}
/// Numbers: anything that fits 2^53 as a JSON number; larger u64 -> hex string.
pub fn int(js: *Stringify, key: []const u8, v: anytype) Error!void {
    try js.objectField(key);
    const T = @TypeOf(v);
    const info = @typeInfo(T);
    switch (info) {
        .int => |ii| {
            const wide: i128 = v;
            if (wide > (1 << 53) or wide < -(1 << 53)) {
                if (ii.signedness == .unsigned) {
                    try js.write(sink.Hex64{ .v = @intCast(v) });
                } else {
                    var buf: [48]u8 = undefined;
                    try js.write(std.fmt.bufPrint(&buf, "{d}", .{v}) catch unreachable);
                }
                return;
            }
            try js.write(v);
        },
        .comptime_int => try js.write(v),
        else => try js.write(v),
    }
}
/// Sanitized string; when sanitisation changed bytes also writes `<key>_hex` with the originals and `<key>_lossy: true`.
pub fn str(js: *Stringify, arena: Allocator, key: []const u8, s: []const u8) Error!void {
    const st = try sink.Str.init(arena, s, max_str);
    try js.objectField(key);
    try js.write(st);
    if (st.lossy) {
        lossy_tally +|= 1;
        try bytesHex(js, try std.fmt.allocPrint(arena, "{s}_hex", .{key}), s);
        try boolean(js, try std.fmt.allocPrint(arena, "{s}_lossy", .{key}), true);
    }
}
pub fn strOpt(js: *Stringify, arena: Allocator, key: []const u8, s: ?[]const u8) Error!void {
    if (s) |v| return str(js, arena, key, v);
    try js.objectField(key);
    try js.write(null);
}
pub fn bytesHex(js: *Stringify, key: []const u8, b: []const u8) Error!void {
    try js.objectField(key);
    try js.write(sink.HexBytes{ .bytes = b });
}
pub fn bytesHexOpt(js: *Stringify, key: []const u8, b: ?[]const u8) Error!void {
    if (b) |v| return bytesHex(js, key, v);
    try js.objectField(key);
    try js.write(null);
}
pub fn uuid(js: *Stringify, key: []const u8, u: [16]u8) Error!void {
    var buf: [40]u8 = undefined;
    const b = u;
    const s = std.fmt.bufPrint(&buf, "{X}-{X}-{X}-{X}-{X}", .{ b[0..4], b[4..6], b[6..8], b[8..10], b[10..16] }) catch unreachable;
    try js.objectField(key);
    try js.write(s);
}
pub fn isoTime(js: *Stringify, key: []const u8, unix: ?i64) Error!void {
    try js.objectField(key);
    if (unix) |t| try js.write(sink.IsoTime{ .secs = t }) else try js.write(null);
}
pub fn boolean(js: *Stringify, key: []const u8, b: bool) Error!void {
    try js.objectField(key);
    try js.write(b);
}
pub fn names(js: *Stringify, arena: Allocator, key: []const u8, list: []const []const u8) Error!void {
    try js.objectField(key);
    try js.beginArray();
    for (list) |n| {
        const st = try sink.Str.init(arena, n, max_str);
        if (st.lossy) lossy_tally +|= 1;
        try js.write(st);
    }
    try js.endArray();
}
/// {"value":"0x200085","names":["NOUNDEFS",...]}
pub fn flags(js: *Stringify, key: []const u8, value: u64, table: []const FlagName) Error!void {
    try js.objectField(key);
    try js.beginObject();
    try hex(js, "value", value);
    try js.objectField("names");
    try js.beginArray();
    for (table) |e| if (value & e.bit != 0) try js.write(e.name);
    try js.endArray();
    try js.endObject();
}
/// {"available": false, "reason": "..."}
pub fn unavailable(js: *Stringify, key: []const u8, reason: []const u8) Error!void {
    try js.objectField(key);
    try js.beginObject();
    try boolean(js, "available", false);
    try js.objectField("reason");
    try js.write(reason);
    try js.endObject();
}
pub fn diagnostics(js: *Stringify, d: *const Diagnostics) Error!void {
    try js.objectField("diagnostics");
    try js.beginArray();
    for (d.items()) |it| {
        try js.beginObject();
        try js.objectField("severity");
        try js.write(@tagName(it.severity));
        try js.objectField("module");
        try js.write(@tagName(it.module));
        try js.objectField("code");
        try js.write(@tagName(it.code));
        try js.objectField("offset");
        if (it.offset) |o| try js.write(o) else try js.write(null);
        // Messages interpolate file-derived names, so they are sanitised like any other file string.
        try str(js, d.arena, "message", it.message);
        try js.endObject();
    }
    try js.endArray();
}
/// Opens one element of "arches": {"arch":"arm64","index":0,"offset_in_file":0,"size":50424,"cputype":"0x100000c","cpusubtype":"0x0","caps":"0x0",
pub fn beginArch(js: *Stringify, img: *const Image) Error!void {
    try js.beginObject();
    var buf: [32]u8 = undefined;
    try js.objectField("arch");
    try js.write(img.arch.displayName(&buf));
    try int(js, "index", img.index);
    try int(js, "offset_in_file", img.slice_offset);
    try int(js, "size", img.r.len());
    try hex(js, "cputype", @as(u32, @bitCast(img.arch.cputype)));
    try hex(js, "cpusubtype", @as(u32, @bitCast(img.arch.cpusubtype)));
    try hex(js, "caps", img.arch.caps);
    try boolean(js, "valid", true);
}
pub fn endArch(js: *Stringify) Error!void {
    try js.endObject();
}
/// {"machre":{"version","schema":1,"command","capstone","security"},"file":{path,size,sha256,mtime,container,fat{...},quarantine,xattrs,translocated},"arches":[
/// `xattr_json`, when non-null, is a `*const std.json.Value` object whose fields replace the default
/// `xattrs: [], quarantine: null, translocated: false` trio (WP4 fills it from darwin/xattr).
pub fn envelopeBegin(js: *Stringify, arena: Allocator, command: []const u8, file: *LoadedFile, xattr_json: ?*const anyopaque) Error!void {
    try js.beginObject();
    try js.objectField("machre");
    try js.beginObject();
    try js.objectField("version");
    try js.write(build_options.version);
    try int(js, "schema", schema_version);
    try js.objectField("command");
    try js.write(command);
    try boolean(js, "capstone", build_options.have_capstone);
    try boolean(js, "security", build_options.have_security);
    try js.endObject();
    try js.objectField("file");
    try js.beginObject();
    try str(js, arena, "path", file.path);
    try int(js, "size", file.size);
    if (file.is_dir or file.bytes.len == 0 and file.size != 0) {
        try js.objectField("sha256");
        try js.write(null);
    } else {
        const d = file.digest();
        try bytesHex(js, "sha256", &d);
    }
    try isoTime(js, "mtime", file.mtime_unix);
    try int(js, "mtime_unix", file.mtime_unix);
    try js.objectField("container");
    try js.write(if (file.is_dir) "bundle" else file.container.containerName());
    try js.objectField("fat");
    switch (file.container) {
        .fat => |f| {
            try js.beginObject();
            try hex(js, "magic", if (f.is_64) std.macho.FAT_MAGIC_64 else std.macho.FAT_MAGIC);
            try int(js, "nfat_arch", f.nfat_arch_declared);
            try js.objectField("arches");
            try js.beginArray();
            for (f.arches) |a| {
                try js.beginObject();
                var buf: [32]u8 = undefined;
                try js.objectField("arch");
                try js.write(a.arch.displayName(&buf));
                try hex(js, "cputype", @as(u32, @bitCast(a.arch.cputype)));
                try hex(js, "cpusubtype", @as(u32, @bitCast(a.arch.cpusubtype)));
                try int(js, "offset", a.offset);
                try int(js, "size", a.size);
                try int(js, "align", a.@"align");
                try boolean(js, "valid", a.valid);
                try js.endObject();
            }
            try js.endArray();
            try js.endObject();
        },
        else => try js.write(null),
    }
    if (xattr_json) |p| {
        const v: *const std.json.Value = @ptrCast(@alignCast(p));
        switch (v.*) {
            .object => |o| {
                var it = o.iterator();
                while (it.next()) |e| {
                    try js.objectField(e.key_ptr.*);
                    try js.write(e.value_ptr.*);
                }
            },
            else => {},
        }
    } else {
        try js.objectField("xattrs");
        try js.beginArray();
        try js.endArray();
        try js.objectField("quarantine");
        try js.write(null);
        try boolean(js, "translocated", false);
    }
    try js.endObject();
    try js.objectField("arches");
    try js.beginArray();
}
/// Closes the "arches" array if it is still open (idempotent); top-level payloads are written after it.
pub fn endArches(js: *Stringify) Error!void {
    if (js.indent_level >= 2) try js.endArray();
}
/// Best-effort close of every open container down to `depth` (used after an internal error so the
/// document is always well-formed).
pub fn closeAll(js: *Stringify, depth: usize) Error!void {
    while (js.indent_level > depth) {
        if (js.next_punctuation == .colon) try js.write(null);
        const is_array = if (@TypeOf(js.nesting_stack) == void) false else std.BitStack.peekWithState(&js.nesting_stack, js.indent_level) == 1;
        if (is_array) try js.endArray() else try js.endObject();
    }
}
/// ],"diagnostics":[...],"diagnostics_dropped":n,"exit_code":n}   (`bundle` is written by the commands that analyse one)
pub fn envelopeEnd(js: *Stringify, d: *const Diagnostics, exit_code: u8, lossy: u32) Error!void {
    try closeAll(js, 1);
    try diagnostics(js, d);
    try int(js, "diagnostics_dropped", d.dropped);
    try int(js, "sanitized_strings", lossy);
    try int(js, "exit_code", exit_code);
    try js.endObject();
}
/// "truncated": true, "total": n  (after a --limit cut)
pub fn truncated(js: *Stringify, total: usize) Error!void {
    try boolean(js, "truncated", true);
    try int(js, "total", total);
}

test "json: helpers and envelope produce parseable JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var s = sink.Sink.init(.json, &w, .{ .pretty_json = false }, a);
    var d = Diagnostics.init(a, 8);
    d.warn(.loadcmds, .cmdsize_invalid, 32, "bad", .{});
    var file: LoadedFile = .{ .path = "x\xff", .path_z = "x\xff", .bytes = "\xcf\xfa\xed\xfe", .size = 4, .mtime_unix = 0, .is_dir = false, .container = .not_macho };
    try envelopeBegin(&s.json, a, "info", &file, null);
    try endArches(&s.json);
    try unavailable(&s.json, "plist", "not implemented");
    try js_extras(&s.json, a);
    try envelopeEnd(&s.json, &d, 3, 2);
    const out = w.buffered();
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 3), root.get("exit_code").?.integer);
    try std.testing.expectEqual(@as(i64, 2), root.get("sanitized_strings").?.integer);
    try std.testing.expectEqualStrings("not_macho", root.get("file").?.object.get("container").?.string);
    try std.testing.expect(root.get("file").?.object.get("path_lossy").?.bool);
    try std.testing.expectEqualStrings("0x8010000000000000", root.get("big").?.string);
    try std.testing.expectEqual(@as(i64, 7), root.get("small").?.integer);
    try std.testing.expectEqualStrings("21C9F585-96F5-3A4C-A516-BBBE1808D26E", root.get("uuid").?.string);
    try std.testing.expectEqual(@as(usize, 1), root.get("diagnostics").?.array.items.len);
    try std.testing.expectEqualStrings("cmdsize_invalid", root.get("diagnostics").?.array.items[0].object.get("code").?.string);
    try std.testing.expectEqual(@as(usize, 4), root.get("flags").?.object.get("names").?.array.items.len);
}
fn js_extras(js: *Stringify, a: Allocator) Error!void {
    try int(js, "big", @as(u64, 0x8010000000000000));
    try int(js, "small", @as(u32, 7));
    try uuid(js, "uuid", .{ 0x21, 0xC9, 0xF5, 0x85, 0x96, 0xF5, 0x3A, 0x4C, 0xA5, 0x16, 0xBB, 0xBE, 0x18, 0x08, 0xD2, 0x6E });
    try flags(js, "flags", 0x200085, &.{ .{ .bit = 1, .name = "NOUNDEFS" }, .{ .bit = 4, .name = "DYLDLINK" }, .{ .bit = 0x80, .name = "TWOLEVEL" }, .{ .bit = 0x200000, .name = "PIE" } });
    try names(js, a, "names", &.{ "a", "b\xff" });
    try strOpt(js, a, "none", null);
    try hexOpt(js, "hnone", null);
    try isoTime(js, "t", 0x68c3a1b2);
    try truncated(js, 12);
}
