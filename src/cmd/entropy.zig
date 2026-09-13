//! cmd/entropy.zig — per-segment/section entropy and packer/encryption tells. Owned by WP6 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;
const entropy = @import("../analysis/entropy.zig");
const Analysis = @import("../analysis/analysis.zig").Analysis;

pub const command: Command = .{
    .name = "entropy",
    .summary = "per-segment/section entropy and packer/encryption tells",
    .run = run,
    .flags = &.{"--sections"},
    .aliases = &.{},
    .needs_macho = true,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const with_sections = ctx.args.flag("--sections");
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
        defer an.deinit();
        const rep = try an.entropy();
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try writeJson(ctx, rep);
            try json.endArch(&ctx.sink.json);
        } else {
            var buf: [32]u8 = undefined;
            if (ctx.images.len > 1) try text.archBanner(ctx.sink.out, ctx.display_path, img.arch.displayName(&buf), true);
            try writeText(ctx, img, rep, with_sections);
        }
    }
    return 0;
}

fn writeText(ctx: *Context, img: *const Image, rep: *const entropy.EntropyReport, with_sections: bool) !void {
    const out = ctx.sink.out;
    try text.kv(out, 2, "file", "{d:.3} bits/byte over {d} bytes", .{ rep.file, img.r.len() });
    try text.kv(out, 2, "segments", "{d}", .{rep.segments.len});
    var tbl = text.Table.init(ctx.arena, &.{
        .{ .name = "name" },
        .{ .name = "file" },
        .{ .name = "entropy", .@"align" = .right },
        .{ .name = "share", .@"align" = .right },
    });
    for (rep.segments) |r| {
        try tbl.rowFmt(&.{ "{s}", "{d}+{d}", "{d:.3}", "{d:.1}%" }, .{
            try ctx.sink.safe(r.name),
            .{ r.file_offset, r.size },
            r.entropy,
            r.file_fraction * 100,
        });
    }
    try tbl.render(out, 4, 0);
    if (with_sections) {
        try text.kv(out, 2, "sections", "{d}", .{rep.sections.len});
        var st = text.Table.init(ctx.arena, &.{
            .{ .name = "name" },
            .{ .name = "file" },
            .{ .name = "entropy", .@"align" = .right },
            .{ .name = "share", .@"align" = .right },
        });
        for (rep.sections) |r| {
            try st.rowFmt(&.{ "{s},{s}", "{d}+{d}", "{d:.3}", "{d:.1}%" }, .{
                .{ try ctx.sink.safe(r.name), try ctx.sink.safeOr(r.sectname, "") },
                .{ r.file_offset, r.size },
                r.entropy,
                r.file_fraction * 100,
            });
        }
        try st.render(out, 4, 0);
    }
    if (rep.tells.len == 0) {
        try text.kv(out, 2, "tells", "none", .{});
        return;
    }
    try text.kv(out, 2, "tells", "{d}", .{rep.tells.len});
    for (rep.tells) |t| try out.print("    [{d:0>2}] {t}  {s}\n", .{ t.weight, t.code, try ctx.sink.safe(t.detail) });
}

fn writeRegions(ctx: *Context, key: []const u8, regions: []const entropy.Region, with_section: bool) !void {
    const js = &ctx.sink.json;
    try js.objectField(key);
    try js.beginArray();
    for (regions) |r| {
        try js.beginObject();
        if (with_section) {
            try json.str(js, ctx.arena, "segment", r.name);
            try json.strOpt(js, ctx.arena, "section", r.sectname);
        } else {
            try json.str(js, ctx.arena, "name", r.name);
        }
        try json.int(js, "offset", r.file_offset);
        try json.int(js, "size", r.size);
        try js.objectField("entropy");
        try js.write(r.entropy);
        try js.objectField("file_fraction");
        try js.write(r.file_fraction);
        try js.endObject();
    }
    try js.endArray();
}

fn writeJson(ctx: *Context, rep: *const entropy.EntropyReport) !void {
    const js = &ctx.sink.json;
    try js.objectField("entropy");
    try js.beginObject();
    try js.objectField("file");
    try js.write(rep.file);
    try writeRegions(ctx, "segments", rep.segments, false);
    try writeRegions(ctx, "sections", rep.sections, true);
    try js.objectField("tells");
    try js.beginArray();
    for (rep.tells) |t| {
        try js.beginObject();
        try js.objectField("code");
        try js.write(@tagName(t.code));
        try json.str(js, ctx.arena, "detail", t.detail);
        try json.int(js, "weight", t.weight);
        try js.endObject();
    }
    try js.endArray();
    try js.endObject();
}
