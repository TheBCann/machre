//! cmd/imports.zig — imported symbols with dylib attribution + dependency resolution. Owned by WP2 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, macho/*, core/*, darwin/dylib_resolve.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const imports_mod = @import("../macho/imports.zig");

pub const command: Command = .{
    .name = "imports",
    .summary = "imported symbols with dylib attribution + dependency resolution",
    .run = run,
    .flags = &.{ "--resolve", "--by-dylib", "--no-resolve" },
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
        .resolve_deps = !ctx.args.flag("--no-resolve"),
    });
}

/// `dyld_info`'s per-slice banner: "<path> [arm64]:".
fn dyldBanner(out: *Io.Writer, path: []const u8, img: *const Image) Io.Writer.Error!void {
    var buf: [32]u8 = undefined;
    try out.print("{s} [{s}]:\n", .{ path, img.arch.displayName(&buf) });
}

fn runText(ctx: *Context) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    const by_dylib = ctx.args.flag("--by-dylib");
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        const tbl = try an.imports();
        const dl = try an.dylibs();
        if (ctx.otool_compat) {
            try dyldBanner(out, ctx.display_path, img);
            try out.writeAll("    -imports:\n");
            const ordinals = tbl.imports.len != 0 and tbl.imports[0].source == .chained;
            for (tbl.imports, 0..) |e, i| {
                var buf: [32]u8 = undefined;
                const lib = imports_mod.ordinalName(&buf, e.ordinal, dl);
                const weak: []const u8 = if (e.weak) "[weak-import]" else "";
                if (ordinals)
                    try out.print("      0x{X:0>4}  {s} {s} (from {s})\n", .{ i, try ctx.sink.safe(e.symbol), weak, try ctx.sink.safe(lib) })
                else
                    try out.print("      {s} {s} (from {s})\n", .{ try ctx.sink.safe(e.symbol), weak, try ctx.sink.safe(lib) });
            }
            continue;
        }
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
        try text.header(out, "{s}: {d} imports from {d} dylibs ({s})", .{ std.fs.path.basename(ctx.display_path), tbl.imports.len, dl.len, if (tbl.imports.len != 0) @tagName(tbl.imports[0].source) else "none" });
        for (dl) |d| {
            try out.print("  {d:>2}  {s}{s}{s}{s}\n", .{
                d.ordinal,
                try ctx.sink.safe(d.path),
                if (d.weak) " (weak)" else "",
                if (d.reexport) " (re-export)" else "",
                if (d.upward) " (upward)" else "",
            });
        }
        const rp = try an.rpaths();
        for (rp) |p| try text.kv(out, 2, "rpath", "{s}", .{try ctx.sink.safe(p)});
        if (by_dylib) {
            for (dl) |d| {
                var n: u32 = 0;
                for (tbl.imports) |e| if (e.dylib != null and e.dylib.?.ordinal == d.ordinal) {
                    n += 1;
                };
                if (n == 0) continue;
                try out.print("  {s} ({d})\n", .{ try ctx.sink.safe(d.short_name), n });
                for (tbl.imports) |e| if (e.dylib != null and e.dylib.?.ordinal == d.ordinal)
                    try out.print("    {s}{s}{s}\n", .{ try ctx.sink.safe(e.symbol), if (e.weak) " (weak)" else "", if (e.lazy) " (lazy)" else "" });
            }
        } else {
            var t = text.Table.init(ctx.arena, &.{ .{ .name = "symbol" }, .{ .name = "library" }, .{ .name = "ordinal", .@"align" = .right }, .{ .name = "flags" }, .{ .name = "slots", .@"align" = .right }, .{ .name = "first" } });
            for (tbl.imports) |e| {
                var buf: [32]u8 = undefined;
                try t.rowFmt(&.{ "{s}", "{s}", "{d}", "{s}", "{d}", "{s}" }, .{
                    try ctx.sink.safe(e.symbol),
                    try ctx.sink.safe(imports_mod.ordinalName(&buf, e.ordinal, dl)),
                    e.ordinal,
                    if (e.weak and e.lazy) "weak,lazy" else if (e.weak) "weak" else if (e.lazy) "lazy" else "",
                    e.locations,
                    if (e.first_location) |v| try std.fmt.allocPrint(ctx.arena, "0x{x}", .{v}) else "",
                });
            }
            try t.render(out, 2, ctx.sink.opts.limit);
        }
        const res = try an.resolutions();
        for (res) |r| {
            try out.print("  resolve  {s} -> {s} ({s}{s})\n", .{
                try ctx.sink.safe(r.path),
                try ctx.sink.safeOr(r.resolved, "?"),
                @tagName(r.status),
                if (r.via_rpath) |v| try ctx.sink.safe(v) else "",
            });
        }
    }
    return 0;
}

fn runJson(ctx: *Context) anyerror!u8 {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        const tbl = try an.imports();
        const dl = try an.dylibs();
        try json.beginArch(js, img);
        try js.objectField("imports");
        try js.beginObject();
        try js.objectField("imports");
        try js.beginArray();
        for (tbl.imports) |e| {
            try js.beginObject();
            try json.str(js, ctx.arena, "symbol", e.symbol);
            var buf: [32]u8 = undefined;
            try json.str(js, ctx.arena, "library", imports_mod.ordinalName(&buf, e.ordinal, dl));
            try json.int(js, "ordinal", e.ordinal);
            try json.boolean(js, "weak", e.weak);
            try json.boolean(js, "lazy", e.lazy);
            try json.int(js, "locations", e.locations);
            try json.hexOpt(js, "first_location", e.first_location);
            try js.objectField("source");
            try js.write(@tagName(e.source));
            try js.endObject();
        }
        try js.endArray();
        try js.objectField("dylibs");
        try js.beginArray();
        for (dl) |d| {
            try js.beginObject();
            try json.int(js, "ordinal", d.ordinal);
            try json.int(js, "cmd", d.cmd);
            try json.str(js, ctx.arena, "path", d.path);
            try json.str(js, ctx.arena, "short_name", d.short_name);
            try json.int(js, "current_version", d.current_version);
            try json.int(js, "compatibility_version", d.compat_version);
            try json.int(js, "timestamp", d.timestamp);
            try json.boolean(js, "weak", d.weak);
            try json.boolean(js, "reexport", d.reexport);
            try json.boolean(js, "upward", d.upward);
            try json.boolean(js, "delayed_init", d.delayed_init);
            try js.endObject();
        }
        try js.endArray();
        const rp = try an.rpaths();
        try json.names(js, ctx.arena, "rpaths", rp);
        const res = try an.resolutions();
        if (res.len == 0) {
            try json.unavailable(js, "resolution", if (ctx.args.flag("--no-resolve")) "--no-resolve" else "dependency resolution is unavailable in this build");
        } else {
            try js.objectField("resolution");
            try js.beginArray();
            for (res) |r| {
                try js.beginObject();
                try json.str(js, ctx.arena, "path", r.path);
                try js.objectField("status");
                try js.write(@tagName(r.status));
                try json.strOpt(js, ctx.arena, "resolved", r.resolved);
                try json.strOpt(js, ctx.arena, "via_rpath", r.via_rpath);
                try json.boolean(js, "weak", r.weak);
                try js.endObject();
            }
            try js.endArray();
        }
        try js.endObject();
        try json.endArch(js);
    }
    return 0;
}
