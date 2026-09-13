//! cmd/segments.zig — segments + sections with prot, flags, type, reserved1/2, entropy. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const version = @import("../core/version.zig");
const Image = @import("../core/image.zig").Image;
const Segment = @import("../core/segments.zig").Segment;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const Sink = @import("../output/sink.zig").Sink;
const entropy_mod = @import("../analysis/entropy.zig");
const loadcmds_cmd = @import("loadcmds.zig");

pub const command: Command = .{
    .name = "segments",
    .summary = "segments + sections with prot, flags, type, reserved1/2, entropy",
    .run = run,
    .flags = &.{"--entropy"},
    .aliases = &.{},
    .needs_macho = true,
};

/// The five padded columns of one segment line (the sixth, flags, is never padded).
const seg_cols = 5;

/// §5.4 spelling: text drops the SG_ prefix, exactly like the MH_ prefix on header flags.
pub const seg_flag_names: []const @import("../core/fmt.zig").FlagName = &.{
    .{ .bit = 0x1, .name = "HIGHVM" },
    .{ .bit = 0x2, .name = "FVMLIB" },
    .{ .bit = 0x4, .name = "NORELOC" },
    .{ .bit = 0x8, .name = "PROTECTED" },
    .{ .bit = 0x10, .name = "READ_ONLY" },
};

/// `  __TEXT        vm 0x100000000+0x4000  file 0+16384      r-x/r-x  4 sects  READ_ONLY`
/// Column widths are shared by every segment of the slice, exactly like the `info` block (§5.4).
pub fn writeSegmentRows(snk: *Sink, img: *const Image, indent: u8, sections: bool) anyerror!void {
    const out = snk.out;
    const arena = snk.arena;
    var rows: std.ArrayList([6][]const u8) = .empty;
    for (img.segments) |seg| try rows.append(arena, try segmentCells(snk, seg));
    var widths: [seg_cols]usize = @splat(0);
    for (rows.items) |r| for (r[0..seg_cols], 0..) |c, i| {
        if (c.len > widths[i]) widths[i] = c.len;
    };
    for (img.segments, rows.items) |seg, r| {
        var line: std.ArrayList(u8) = .empty;
        try line.appendNTimes(arena, ' ', indent);
        for (r, 0..) |c, i| {
            try line.appendSlice(arena, c);
            if (i + 1 == r.len) break;
            if (i < seg_cols) try line.appendNTimes(arena, ' ', widths[i] - c.len);
            try line.appendSlice(arena, "  ");
        }
        try out.writeAll(std.mem.trimEnd(u8, line.items, " "));
        try out.writeByte('\n');
        if (sections) try writeSectionTable(snk, img, seg, indent + 2);
    }
}

fn segmentCells(snk: *Sink, seg: Segment) anyerror![6][]const u8 {
    const arena = snk.arena;
    var ip: [3]u8 = undefined;
    var mp: [3]u8 = undefined;
    var extra = try text.flags(arena, seg.flags, seg_flag_names, ",");
    if (seg.file_range_truncated) extra = try std.fmt.allocPrint(arena, "{s}{s}(filesize clamped to slice)", .{ extra, if (extra.len == 0) "" else "  " });
    return .{
        try snk.safe(seg.name),
        try std.fmt.allocPrint(arena, "vm 0x{x}+0x{x}", .{ seg.vmaddr, seg.vmsize }),
        try std.fmt.allocPrint(arena, "file {d}+{d}", .{ seg.fileoff, seg.filesize }),
        try std.fmt.allocPrint(arena, "{s}/{s}", .{ seg.protString(&ip, .init), seg.protString(&mp, .max) }),
        try std.fmt.allocPrint(arena, "{d} sect{s}", .{ seg.section_count, if (seg.section_count == 1) "" else "s" }),
        extra,
    };
}

fn writeSectionTable(snk: *Sink, img: *const Image, seg: Segment, indent: u8) anyerror!void {
    const out = snk.out;
    const arena = snk.arena;
    if (seg.section_count == 0) return;
    var t = text.Table.init(arena, &.{ .{ .name = "sect" }, .{ .name = "addr" }, .{ .name = "size", .@"align" = .right }, .{ .name = "offset", .@"align" = .right }, .{ .name = "align" }, .{ .name = "type" }, .{ .name = "attrs" }, .{ .name = "class" }, .{ .name = "res1/2" } });
    const end = @min(img.sections.len, @as(usize, seg.first_section) + seg.section_count);
    for (img.sections[seg.first_section..end]) |s| {
        const attrs = try text.flags(arena, s.attrs(), version.s_attr_flags, ",");
        try t.rowFmt(&.{ "{s}", "0x{x}", "0x{x}", "{d}", "2^{d}", "{s}", "{s}", "{t}", "{d}/{d}" }, .{ try snk.safe(s.sectname), s.addr, s.size, s.offset, s.@"align", version.sectionTypeName(s.sectType()) orelse "?", attrs, s.class, .{ s.reserved1, s.reserved2 } });
    }
    try t.render(out, indent, 0);
}

/// `an.entropy()` by value — the report's slices live in `ctx.arena`, but the `Analysis` memo slot it is
/// returned from does not, so the struct is copied out before the facade goes out of scope.
fn entropyValue(ctx: *Context, img: *const Image) anyerror!entropy_mod.EntropyReport {
    var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
    defer an.deinit();
    return (try an.entropy()).*;
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const want_entropy = ctx.args.flag("--entropy");
    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        for (ctx.images) |*img| {
            var report: entropy_mod.EntropyReport = .empty;
            var rep: ?*const entropy_mod.EntropyReport = null;
            if (want_entropy) {
                report = try entropyValue(ctx, img);
                rep = &report;
            }
            try json.beginArch(js, img);
            try js.objectField("segments");
            try js.beginArray();
            for (img.segments) |seg| {
                try js.beginObject();
                try loadcmds_cmd.writeSegmentJson(js, ctx.arena, img, seg, rep);
                try json.int(js, "section_count", seg.section_count);
                try js.endObject();
            }
            try js.endArray();
            if (rep) |r| {
                try js.objectField("entropy");
                try js.beginObject();
                try js.objectField("file");
                try js.write(r.file);
                try js.objectField("segments");
                try js.beginArray();
                for (r.segments) |rg| {
                    try js.beginObject();
                    try json.str(js, ctx.arena, "name", rg.name);
                    try json.int(js, "offset", rg.file_offset);
                    try json.int(js, "size", rg.size);
                    try js.objectField("entropy");
                    try js.write(rg.entropy);
                    try js.objectField("file_fraction");
                    try js.write(rg.file_fraction);
                    try js.endObject();
                }
                try js.endArray();
                try js.endObject();
            } else try json.unavailable(js, "entropy", "not requested (--entropy)");
            try json.endArch(js);
        }
        return 0;
    }
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var buf: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), true);
        try text.header(out, "{s}: {d} segments, {d} sections", .{ ctx.display_path, img.segments.len, img.sections.len });
        try writeSegmentRows(ctx.sink, img, 2, true);
        if (want_entropy) {
            const rep = try entropyValue(ctx, img);
            if (rep.segments.len == 0) {
                try text.kv(out, 2, "entropy", "not implemented", .{});
            } else {
                for (rep.segments) |rg| try out.print("  entropy {s} {d:.3} ({d:.1}% of file)\n", .{ try ctx.sink.safe(rg.name), rg.entropy, rg.file_fraction * 100 });
                for (rep.tells) |tl| try out.print("  tell {t}: {s}\n", .{ tl.code, try ctx.sink.safe(tl.detail) });
            }
        }
    }
    return 0;
}

test "segments: shared column widths and trailing-flag column" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var wbuf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&wbuf);
    var snk = @import("../output/sink.zig").Sink.init(.text, &w, .{}, a);
    const cells = try segmentCells(&snk, .{
        .index = 0,
        .cmd_offset = 0,
        .name = "__DATA_CONST",
        .vmaddr = 0x100004000,
        .vmsize = 0x4000,
        .fileoff = 16384,
        .filesize = 16384,
        .maxprot = 3,
        .initprot = 3,
        .nsects = 1,
        .flags = 0x10,
        .first_section = 0,
        .section_count = 1,
        .file_range_truncated = false,
    });
    try std.testing.expectEqualStrings("__DATA_CONST", cells[0]);
    try std.testing.expectEqualStrings("vm 0x100004000+0x4000", cells[1]);
    try std.testing.expectEqualStrings("file 16384+16384", cells[2]);
    try std.testing.expectEqualStrings("rw-/rw-", cells[3]);
    try std.testing.expectEqualStrings("1 sect", cells[4]);
    try std.testing.expectEqualStrings("READ_ONLY", cells[5]);
}
