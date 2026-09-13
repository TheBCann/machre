//! core/fmt.zig — `{f}` formatter types shared by text and JSON renderers. Imports: std only.
const std = @import("std");
const Io = std.Io;

pub const Addr = struct {
    v: u64,
    pub fn format(a: Addr, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("0x{x}", .{a.v});
    }
};
pub const Addr16 = struct {
    v: u64,
    pub fn format(a: Addr16, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{x:0>16}", .{a.v});
    }
};
pub const Hex = struct {
    bytes: []const u8,
    pub fn format(h: Hex, w: *Io.Writer) Io.Writer.Error!void {
        try w.printHex(h.bytes, .lower);
    }
};
pub const Uuid = struct {
    bytes: [16]u8,
    pub fn format(u: Uuid, w: *Io.Writer) Io.Writer.Error!void {
        const b = u.bytes;
        try w.print("{X}-{X}-{X}-{X}-{X}", .{ b[0..4], b[4..6], b[6..8], b[8..10], b[10..16] });
    }
};
pub const Version = struct {
    v: u32,
    pub fn format(v: Version, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff, v.v & 0xff });
    }
};
pub const VersionShort = struct {
    v: u32,
    pub fn format(v: VersionShort, w: *Io.Writer) Io.Writer.Error!void {
        if (v.v & 0xff == 0) try w.print("{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff }) else try w.print("{d}.{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff, v.v & 0xff });
    }
};
pub const SourceVersion = struct {
    v: u64,
    pub fn format(v: SourceVersion, w: *Io.Writer) Io.Writer.Error!void {
        const a = v.v >> 40;
        const parts = [_]u64{ (v.v >> 30) & 0x3ff, (v.v >> 20) & 0x3ff, (v.v >> 10) & 0x3ff, v.v & 0x3ff };
        var last: usize = 0;
        for (parts, 0..) |p, i| if (p != 0) {
            last = i + 1;
        };
        try w.print("{d}.{d}", .{ a, parts[0] });
        for (parts[1..], 1..) |p, i| if (i < last) try w.print(".{d}", .{p});
    }
};
pub const Iso8601 = struct {
    unix_secs: i64,
    pub fn format(t: Iso8601, w: *Io.Writer) Io.Writer.Error!void {
        var buf: [20]u8 = undefined;
        try w.writeAll(@import("sanitize.zig").iso8601(&buf, t.unix_secs));
    }
};
pub const FlagName = struct { bit: u64, name: []const u8 };
pub const Flags = struct {
    value: u64,
    table: []const FlagName,
    sep: []const u8 = ",",
    pub fn format(f: Flags, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("0x{x} (", .{f.value});
        var rest = f.value;
        var first = true;
        for (f.table) |e| if (f.value & e.bit != 0) {
            if (!first) try w.writeAll(f.sep);
            try w.writeAll(e.name);
            rest &= ~e.bit;
            first = false;
        };
        if (rest != 0) {
            if (!first) try w.writeAll(f.sep);
            try w.print("0x{x}", .{rest});
            first = false;
        }
        if (first) try w.writeAll("none");
        try w.writeAll(")");
    }
};
pub fn flagNames(value: u64, table: []const FlagName, buf: [][]const u8) []const []const u8 {
    var n: usize = 0;
    for (table) |e| if (value & e.bit != 0 and n < buf.len) {
        buf[n] = e.name;
        n += 1;
    };
    return buf[0..n];
}

test "fmt: formatter types match the reference tools' spelling" {
    try std.testing.expectFmt("0x100000524", "{f}", .{Addr{ .v = 0x100000524 }});
    try std.testing.expectFmt("0000000100000524", "{f}", .{Addr16{ .v = 0x100000524 }});
    try std.testing.expectFmt("21C9F585-96F5-3A4C-A516-BBBE1808D26E", "{f}", .{Uuid{ .bytes = .{ 0x21, 0xC9, 0xF5, 0x85, 0x96, 0xF5, 0x3A, 0x4C, 0xA5, 0x16, 0xBB, 0xBE, 0x18, 0x08, 0xD2, 0x6E } }});
    try std.testing.expectFmt("1356.0.0", "{f}", .{Version{ .v = 0x054c0000 }});
    try std.testing.expectFmt("26.5", "{f}", .{VersionShort{ .v = 0x001a0500 }});
    try std.testing.expectFmt("475.0", "{f}", .{SourceVersion{ .v = 0x1db0000000000 }});
    try std.testing.expectFmt("0x20002 (adhoc,linker-signed)", "{f}", .{Flags{ .value = 0x20002, .table = &.{ .{ .bit = 0x2, .name = "adhoc" }, .{ .bit = 0x20000, .name = "linker-signed" } } }});
    try std.testing.expectFmt("0x0 (none)", "{f}", .{Flags{ .value = 0, .table = &.{} }});
    try std.testing.expectFmt("f865cf", "{f}", .{Hex{ .bytes = &.{ 0xf8, 0x65, 0xcf } }});
    try std.testing.expectFmt("2025-09-12T04:29:38Z", "{f}", .{Iso8601{ .unix_secs = 0x68c3a1b2 }});
}
