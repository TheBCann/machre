//! cmd/exports.zig — export trie / defined external symbols. Owned by WP2 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, macho/*, core/*.
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
const exports_mod = @import("../macho/dyld_exports.zig");

pub const command: Command = .{
    .name = "exports",
    .summary = "export trie / defined external symbols",
    .run = run,
    .flags = &.{"--trie"},
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

/// `dyld_info`'s per-slice banner: "<path> [arm64]:".
fn dyldBanner(out: *Io.Writer, path: []const u8, img: *const Image) Io.Writer.Error!void {
    var buf: [32]u8 = undefined;
    try out.print("{s} [{s}]:\n", .{ path, img.arch.displayName(&buf) });
}

fn runText(ctx: *Context) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        if (ctx.otool_compat) {
            try dyldBanner(out, ctx.display_path, img);
            try out.writeAll("    -exports:\n");
            const trie = try an.exportsTrie();
            if (trie == null or trie.?.exports.len == 0) continue;
            try out.writeAll("        offset      symbol\n");
            for (trie.?.exports) |x| {
                try out.print("        0x{X:0>8}  {s}{s}{s}\n", .{
                    x.offset,
                    x.name,
                    if (x.weak) " [weak-def]" else "",
                    if (x.reexport != null) " [re-export]" else "",
                });
            }
            continue;
        }
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
        const trie = try an.exportsTrie();
        // --trie: the export trie only; without it a trie-less image falls back to defined external symbols.
        if (ctx.args.flag("--trie") and trie == null) {
            try text.header(out, "{s}: no export trie (no LC_DYLD_EXPORTS_TRIE and no LC_DYLD_INFO export_off)", .{std.fs.path.basename(ctx.display_path)});
            continue;
        }
        const tbl = try an.exports();
        const source: []const u8 = if (trie != null) @tagName(trie.?.source) else "nlist";
        try text.header(out, "{s}: {d} exports ({s})", .{ std.fs.path.basename(ctx.display_path), tbl.exports.len, source });
        var t = text.Table.init(ctx.arena, &.{ .{ .name = "address" }, .{ .name = "kind" }, .{ .name = "flags" }, .{ .name = "name" } });
        for (tbl.exports) |x| {
            try t.rowFmt(&.{ "0x{x}", "{s}", "{s}", "{s}" }, .{
                x.address,
                x.kind,
                if (x.weak) "weak-def" else "",
                if (x.reexport_from) |re| try std.fmt.allocPrint(ctx.arena, "{s} (re-export of {s})", .{ try ctx.sink.safe(x.name), try ctx.sink.safe(if (re.len == 0) x.name else re) }) else try ctx.sink.safe(x.name),
            });
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
        try js.objectField("exports");
        try js.beginObject();
        const trie = try an.exportsTrie();
        const dl = try an.dylibs();
        const trie_only = ctx.args.flag("--trie");
        try js.objectField("exports");
        try js.beginArray();
        if (trie) |t| {
            for (t.exports) |x| {
                try js.beginObject();
                try json.str(js, ctx.arena, "name", x.name);
                try json.hex(js, "address", x.address);
                try json.hex(js, "offset", x.offset);
                try js.objectField("kind");
                try js.write(kindName(x.kind));
                try json.boolean(js, "weak", x.weak);
                try js.objectField("reexport");
                if (x.reexport) |re| {
                    try js.beginObject();
                    try json.int(js, "ordinal", re.ordinal);
                    var buf: [32]u8 = undefined;
                    try json.str(js, ctx.arena, "library", imports_mod.ordinalName(&buf, @intCast(re.ordinal), dl));
                    try json.str(js, ctx.arena, "name", if (re.import_name.len == 0) x.name else re.import_name);
                    try js.endObject();
                } else try js.write(null);
                try js.objectField("resolver");
                if (x.stub_resolver) |sr| try js.write(@import("../output/sink.zig").Hex64{ .v = sr.resolver }) else try js.write(null);
                try js.endObject();
            }
        } else if (!trie_only) {
            const tbl = try an.exports();
            for (tbl.exports) |x| {
                try js.beginObject();
                try json.str(js, ctx.arena, "name", x.name);
                try json.hex(js, "address", x.address);
                try json.hex(js, "offset", if (x.address >= img.image_base) x.address - img.image_base else 0);
                try js.objectField("kind");
                try js.write(x.kind);
                try json.boolean(js, "weak", x.weak);
                try js.objectField("reexport");
                try js.write(null);
                try js.objectField("resolver");
                try js.write(null);
                try js.endObject();
            }
        }
        try js.endArray();
        try js.objectField("source");
        try js.write(if (trie) |t| @tagName(t.source) else if (trie_only) "none" else "nlist");
        try js.endObject();
        try json.endArch(js);
    }
    return 0;
}

fn kindName(k: exports_mod.ExportKind) []const u8 {
    return switch (k) {
        .regular => "regular",
        .thread_local => "thread-local",
        .absolute => "absolute",
        _ => "unknown",
    };
}
