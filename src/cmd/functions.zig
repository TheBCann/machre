//! cmd/functions.zig — discovered functions with source and size. Owned by WP8 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, disasm/functions, core/*.
//!
//! `--otool-compat` renders the LC_FUNCTION_STARTS table the way `dyld_info -function_starts` does
//! (including its "no function starts info" line), NOT machre's richer discovery: the point of the flag
//! is an empty diff against the Apple tool.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const functions_mod = @import("../disasm/functions.zig");

pub const command: Command = .{
    .name = "functions",
    .summary = "discovered functions with source and size",
    .run = run,
    .flags = &.{"--sort="},
    .aliases = &.{},
    .needs_macho = true,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    if (ctx.sink.isJson()) return runJson(ctx);
    return runText(ctx);
}

fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis {
    return Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
        .security = !ctx.no_security,
        .network = !ctx.no_network,
    });
}

const Sort = enum { addr, name, size };
fn sortOf(ctx: *Context) Sort {
    const v = ctx.args.value("--sort") orelse return .addr;
    return std.meta.stringToEnum(Sort, v) orelse .addr;
}

fn lessByName(_: void, a: functions_mod.Function, b: functions_mod.Function) bool {
    const o = std.mem.order(u8, a.name, b.name);
    if (o != .eq) return o == .lt;
    return a.start < b.start;
}
fn lessBySize(_: void, a: functions_mod.Function, b: functions_mod.Function) bool {
    if (a.size() != b.size()) return a.size() > b.size(); // biggest first
    return a.start < b.start;
}

/// `dyld_info`'s per-slice banner: "<path> [arm64]:".
fn dyldBanner(out: *Io.Writer, path: []const u8, img: *const Image) Io.Writer.Error!void {
    var buf: [32]u8 = undefined;
    try out.print("{s} [{s}]:\n", .{ path, img.arch.displayName(&buf) });
}

/// dyld_info names a start by its symbol, else by "<SEG>,<SECT>[+<decimal offset>]".
fn dyldName(ctx: *Context, an: *Analysis, img: *const Image, addr: u64) anyerror![]const u8 {
    const syms = try an.symbols();
    const index = try an.addressIndex();
    if (index.at(syms, addr)) |s| {
        // File-derived symbol name on its way to a terminal: escaped like every other one.
        if (s.name.len != 0) return ctx.sink.safe(s.name);
    }
    const sect = img.sectionForVm(addr) orelse return "";
    const off = addr - sect.addr;
    if (off == 0) return std.fmt.allocPrint(ctx.arena, "{s},{s}", .{ try ctx.sink.safe(sect.segname), try ctx.sink.safe(sect.sectname) });
    return std.fmt.allocPrint(ctx.arena, "{s},{s}+{d}", .{ try ctx.sink.safe(sect.segname), try ctx.sink.safe(sect.sectname), off });
}

fn runText(ctx: *Context) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        if (ctx.otool_compat) {
            try dyldBanner(out, ctx.display_path, img);
            try out.writeAll("    -function_starts:\n");
            const fs = try an.functionStarts();
            if (fs == null or fs.?.addrs.len == 0) {
                try out.writeAll("        no function starts info\n");
                continue;
            }
            for (fs.?.addrs) |a| try out.print("        0x{X:0>8}  {s}\n", .{ a, try dyldName(ctx, &an, img, a) });
            continue;
        }
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
        const tbl = try an.functions();
        const fns = try ctx.arena.dupe(functions_mod.Function, tbl.functions);
        switch (sortOf(ctx)) {
            .addr => {},
            .name => std.mem.sort(functions_mod.Function, fns, {}, lessByName),
            .size => std.mem.sort(functions_mod.Function, fns, {}, lessBySize),
        }
        try text.header(out, "{s}: {d} function{s}{s}", .{ ctx.display_path, fns.len, if (fns.len == 1) "" else "s", if (tbl.truncated) " (truncated)" else "" });
        var t = text.Table.init(ctx.arena, &.{
            .{ .name = "address" },
            .{ .name = "size", .@"align" = .right },
            .{ .name = "source" },
            .{ .name = "name" },
        });
        for (fns) |f| {
            try t.rowFmt(&.{ "0x{x}", "0x{x}", "{s}", "{s}" }, .{ f.start, f.size(), @tagName(f.source), try ctx.sink.safe(f.name) });
        }
        try t.render(out, 2, ctx.sink.opts.limit);
    }
    return 0;
}

fn runJson(ctx: *Context) anyerror!u8 {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        try json.beginArch(js, img);
        const tbl = try an.functions();
        try js.objectField("functions");
        try js.beginArray();
        var shown: usize = 0;
        for (tbl.functions) |f| {
            if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) break;
            shown += 1;
            try js.beginObject();
            try json.str(js, ctx.arena, "name", f.name);
            try json.hex(js, "start", f.start);
            try json.hex(js, "end", f.end);
            try json.int(js, "size", f.size());
            try js.objectField("source");
            try js.write(@tagName(f.source));
            try js.objectField("name_source");
            try js.write(@tagName(f.name_source));
            try js.objectField("section");
            if (f.section) |s| try js.write(s) else try js.write(null);
            try js.endObject();
        }
        try js.endArray();
        if (shown < tbl.functions.len) try json.truncated(js, tbl.functions.len);
        try json.endArch(js);
    }
    return 0;
}
