//! output/text.zig — text helpers: aligned tables, key/value rows, flag joining, hexdump, diagnostics footer.
//! Imports: output/sink, core/diag, core/sanitize, core/fmt.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const FlagName = @import("../core/fmt.zig").FlagName;
const sanitize = @import("../core/sanitize.zig");

pub const Align = enum { left, right };
pub const Col = struct { name: []const u8, @"align": Align = .left, max: u16 = 0 };
pub const Table = struct {
    arena: Allocator,
    columns: []const Col,
    rows: std.ArrayList([]const []const u8) = .empty,
    pub fn init(arena: Allocator, columns: []const Col) Table {
        return .{ .arena = arena, .columns = columns };
    }
    /// Appends a row; the cell strings must outlive the table (arena/static), the slice is copied.
    pub fn row(t: *Table, cells: []const []const u8) Allocator.Error!void {
        try t.rows.append(t.arena, try t.arena.dupe([]const u8, cells));
    }
    /// One format string per cell, one argument tuple element per cell.
    pub fn rowFmt(t: *Table, comptime fmts: []const []const u8, args: anytype) Allocator.Error!void {
        const cells = try t.arena.alloc([]const u8, fmts.len);
        inline for (fmts, 0..) |f, i| {
            const A = @TypeOf(args[i]);
            const ti = @typeInfo(A);
            if (ti == .@"struct" and ti.@"struct".is_tuple) {
                cells[i] = try std.fmt.allocPrint(t.arena, f, args[i]);
            } else {
                cells[i] = try std.fmt.allocPrint(t.arena, f, .{args[i]});
            }
        }
        try t.rows.append(t.arena, cells);
    }
    /// Columns separated by two spaces, last column unpadded, trailing whitespace trimmed.
    /// `limit` > 0 cuts after that many rows and prints "(N more rows)".
    pub fn render(t: *Table, out: *Io.Writer, indent: u8, limit: u32) Io.Writer.Error!void {
        const ncol = t.columns.len;
        var widths_buf: [32]usize = @splat(0);
        const widths = widths_buf[0..@min(ncol, 32)];
        for (t.rows.items) |r| for (r, 0..) |c, i| {
            if (i >= widths.len) break;
            var w = c.len;
            if (t.columns[i].max != 0 and w > t.columns[i].max) w = t.columns[i].max;
            if (w > widths[i]) widths[i] = w;
        };
        const shown = if (limit != 0 and t.rows.items.len > limit) limit else t.rows.items.len;
        for (t.rows.items[0..shown]) |r| {
            var line: std.ArrayList(u8) = .empty;
            defer line.deinit(t.arena);
            line.appendNTimes(t.arena, ' ', indent) catch return error.WriteFailed;
            for (r, 0..) |c0, i| {
                if (i >= widths.len) break;
                var c = c0;
                if (t.columns[i].max != 0 and c.len > t.columns[i].max) c = c[0..t.columns[i].max];
                const last = i + 1 == r.len;
                const pad = widths[i] - c.len;
                if (t.columns[i].@"align" == .right and !last) line.appendNTimes(t.arena, ' ', pad) catch return error.WriteFailed;
                line.appendSlice(t.arena, c) catch return error.WriteFailed;
                if (!last) {
                    if (t.columns[i].@"align" == .left) line.appendNTimes(t.arena, ' ', pad) catch return error.WriteFailed;
                    line.appendSlice(t.arena, "  ") catch return error.WriteFailed;
                }
            }
            try out.writeAll(std.mem.trimEnd(u8, line.items, " "));
            try out.writeByte('\n');
        }
        if (shown < t.rows.items.len) {
            try out.splatByteAll(' ', indent);
            try out.print("({d} more rows, use --limit 0)\n", .{t.rows.items.len - shown});
        }
    }
};
pub fn header(out: *Io.Writer, comptime fmt: []const u8, args: anytype) Io.Writer.Error!void {
    try out.print(fmt, args);
    try out.writeByte('\n');
}
/// "  key          value" — key padded to 13 columns (fixed so goldens diff byte for byte).
pub fn kv(out: *Io.Writer, indent: u8, key: []const u8, comptime fmt: []const u8, args: anytype) Io.Writer.Error!void {
    try out.splatByteAll(' ', indent);
    try out.print("{s:<13}", .{key});
    try out.print(fmt, args);
    try out.writeByte('\n');
}
/// "NOUNDEFS DYLDLINK TWOLEVEL PIE" (+ " 0x..." for unknown bits), joined by `sep`.
pub fn flags(arena: Allocator, value: u64, table: []const FlagName, sep: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var rest = value;
    var first = true;
    for (table) |e| if (value & e.bit != 0) {
        if (!first) try out.appendSlice(arena, sep);
        try out.appendSlice(arena, e.name);
        rest &= ~e.bit;
        first = false;
    };
    if (rest != 0) {
        if (!first) try out.appendSlice(arena, sep);
        try out.print(arena, "0x{x}", .{rest});
    }
    return out.toOwnedSlice(arena);
}
/// xxd-style: "00000000  cf fa ed fe ...  |........|"; `limit` > 0 caps the bytes shown.
pub fn hexdump(out: *Io.Writer, bytes: []const u8, base: u64, limit: u32) Io.Writer.Error!void {
    const n = if (limit != 0 and bytes.len > limit) limit else bytes.len;
    var off: usize = 0;
    while (off < n) : (off += 16) {
        const end = @min(off + 16, n);
        const chunk = bytes[off..end];
        try out.print("{x:0>8}  ", .{base + off});
        for (0..16) |i| {
            if (i < chunk.len) try out.print("{x:0>2} ", .{chunk[i]}) else try out.writeAll("   ");
            if (i == 7) try out.writeByte(' ');
        }
        try out.writeAll(" |");
        for (chunk) |b| try out.writeByte(if (b >= 0x20 and b < 0x7f) b else '.');
        try out.writeAll("|\n");
    }
    if (n < bytes.len) try out.print("({d} more bytes)\n", .{bytes.len - n});
}
/// Footer: "diagnostics  none" or up to 5 lines + "(N more, use --verbose)", followed by the
/// "sanitized" tally when the sample tried to write control characters into the output.
/// Diagnostic messages interpolate file-derived names (segment names, dylib paths, …), so every
/// message is escaped here — the one place all of them pass through.
pub fn diagnostics(out: *Io.Writer, d: *const Diagnostics, verbose: bool, lossy: u32) Io.Writer.Error!void {
    const items = d.items();
    if (items.len == 0 and d.dropped == 0) {
        try kv(out, 2, "diagnostics", "none", .{});
        try sanitizedLine(out, lossy);
        return;
    }
    try kv(out, 2, "diagnostics", "{d} ({d} errors, {d} warnings, {d} info{s})", .{ items.len + d.dropped, d.counts[2], d.counts[1], d.counts[0], if (d.dropped != 0) ", some dropped" else "" });
    const shown = if (verbose) items.len else @min(items.len, 5);
    for (items[0..shown]) |it| {
        try out.print("    [{t}] {t}.{t}", .{ it.severity, it.module, it.code });
        if (it.offset) |o| try out.print(" @0x{x}", .{o});
        const msg = (sanitize.string(d.arena, it.message, .text, sanitize.max_render) catch sanitize.Sanitized{ .text = "(message dropped)", .lossy = true }).text;
        try out.print(": {s}\n", .{msg});
    }
    if (shown < items.len) try out.print("    ({d} more, use --verbose)\n", .{items.len - shown});
    try sanitizedLine(out, lossy);
}
/// Mirrors `strings`' "lossy N strings needed sanitisation" so the analyst is told that output was
/// altered rather than silently trusting what they see.
fn sanitizedLine(out: *Io.Writer, lossy: u32) Io.Writer.Error!void {
    if (lossy == 0) return;
    try kv(out, 2, "sanitized", "{d} file-derived string{s} needed sanitisation (control characters or invalid UTF-8 escaped)", .{ lossy, if (lossy == 1) "" else "s" });
}
pub fn prot(buf: *[3]u8, p: u32) []const u8 {
    buf[0] = if (p & 1 != 0) 'r' else '-';
    buf[1] = if (p & 2 != 0) 'w' else '-';
    buf[2] = if (p & 4 != 0) 'x' else '-';
    return buf[0..3];
}
/// otool-style architecture banner: "<path> (architecture arm64):" when more than one slice is shown.
pub fn archBanner(out: *Io.Writer, path: []const u8, arch_name: []const u8, multi: bool) Io.Writer.Error!void {
    if (multi) try out.print("{s} (architecture {s}):\n", .{ path, arch_name }) else try out.print("{s}:\n", .{path});
}

test "text: table, kv, flags, hexdump, diagnostics footer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var t = Table.init(a, &.{ .{ .name = "name" }, .{ .name = "n", .@"align" = .right }, .{ .name = "x" } });
    try t.row(&.{ "__TEXT", "4", "READ_ONLY" });
    try t.rowFmt(&.{ "{s}", "{d}", "{s}" }, .{ "__DATA", @as(u32, 12), "" });
    try t.render(&w, 2, 0);
    try std.testing.expectEqualStrings("  __TEXT   4  READ_ONLY\n  __DATA  12\n", w.buffered());
    w = .fixed(&buf);
    try kv(&w, 2, "sha256", "{s}", .{"abc"});
    try std.testing.expectEqualStrings("  sha256       abc\n", w.buffered());
    try std.testing.expectEqualStrings("NOUNDEFS PIE 0x1000000", try flags(a, 0x1200001, &.{ .{ .bit = 1, .name = "NOUNDEFS" }, .{ .bit = 0x200000, .name = "PIE" } }, " "));
    w = .fixed(&buf);
    try hexdump(&w, "\xcf\xfa\xed\xfeABC", 0, 0);
    try std.testing.expectEqualStrings("00000000  cf fa ed fe 41 42 43                              |....ABC|\n", w.buffered());
    var d = Diagnostics.init(a, 8);
    w = .fixed(&buf);
    try diagnostics(&w, &d, false, 0);
    try std.testing.expectEqualStrings("  diagnostics  none\n", w.buffered());
    d.warn(.loadcmds, .cmdsize_invalid, 32, "bad", .{});
    w = .fixed(&buf);
    try diagnostics(&w, &d, false, 0);
    try std.testing.expectEqualStrings("  diagnostics  1 (0 errors, 1 warnings, 0 info)\n    [warning] loadcmds.cmdsize_invalid @0x20: bad\n", w.buffered());
    // A diagnostic that interpolated a hostile segment name must not reach the terminal raw.
    var d2 = Diagnostics.init(a, 8);
    d2.warn(.segments, .offset_past_eof, 0, "segment {s} is bad", .{"\x1b[31m\r"});
    w = .fixed(&buf);
    try diagnostics(&w, &d2, false, 3);
    try std.testing.expectEqualStrings(
        "  diagnostics  1 (0 errors, 1 warnings, 0 info)\n    [warning] segments.offset_past_eof @0x0: segment \\x1b[31m\\x0d is bad\n  sanitized    3 file-derived strings needed sanitisation (control characters or invalid UTF-8 escaped)\n",
        w.buffered(),
    );
    var pb: [3]u8 = undefined;
    try std.testing.expectEqualStrings("rw-", prot(&pb, 3));
    w = .fixed(&buf);
    try archBanner(&w, "x", "arm64", true);
    try std.testing.expectEqualStrings("x (architecture arm64):\n", w.buffered());
}
