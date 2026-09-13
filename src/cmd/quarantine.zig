//! cmd/quarantine.zig — xattrs, parsed com.apple.quarantine, translocation. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const sanitize = @import("../core/sanitize.zig");
const xattr = @import("../darwin/xattr.zig");

pub const command: Command = .{
    .name = "quarantine",
    .summary = "xattrs, parsed com.apple.quarantine, translocation",
    .run = run,
    .flags = &.{},
    .aliases = &.{},
    .needs_macho = false,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    // The xattrs belong to the path the user named, not to the bundle's main executable that
    // cli.loadImages may have swapped in for the Mach-O commands.
    const x = try xattr.read(ctx.arena, ctx.path, ctx.diags);
    if (!x.available and !ctx.diags.has(.xattr, .not_available))
        ctx.diags.info(.xattr, .not_available, null, "extended attributes are not readable on this platform/path", .{});
    if (ctx.sink.isJson()) return renderJson(ctx, x);
    if (ctx.otool_compat) return renderOtoolCompat(ctx, x);
    return renderText(ctx, x);
}

/// Mirrors `xattr -l <path>`: one "name: value" line per attribute, nothing when there are none.
fn renderOtoolCompat(ctx: *Context, x: xattr.Xattrs) anyerror!u8 {
    const out = ctx.sink.out;
    for (x.names) |name| {
        const name_z = try ctx.arena.dupeSentinel(u8, name, 0);
        const value = (try xattr.readValue(ctx.arena, ctx.path, name_z, ctx.diags)) orelse "";
        try out.print("{s}: {s}\n", .{ try ctx.sink.safe(name), try ctx.sink.safe(value) });
    }
    return 0;
}

fn renderText(ctx: *Context, x: xattr.Xattrs) anyerror!u8 {
    const out = ctx.sink.out;
    const base = std.fs.path.basename(ctx.display_path);
    const name = try ctx.sink.safeMax(base, 512);
    if (!x.available) {
        try text.header(out, "{s}: extended attributes not readable", .{name});
    } else {
        try text.header(out, "{s}: {d} extended attribute{s}", .{ name, x.names.len, if (x.names.len == 1) "" else "s" });
    }
    if (x.names.len == 0) {
        try text.kv(out, 2, "xattrs", "none", .{});
    } else {
        const joined = try std.mem.join(ctx.arena, ", ", x.names);
        try text.kv(out, 2, "xattrs", "{s}", .{try ctx.sink.safe(joined)});
    }
    if (x.quarantine) |q| {
        try text.kv(out, 2, "quarantine", "{s}", .{try ctx.sink.safe(q.raw)});
        if (q.flags) |f| try text.kv(out, 2, "flags", "0x{x:0>4}", .{f}) else try text.kv(out, 2, "flags", "unparsed", .{});
        if (q.timestamp) |t| {
            var buf: [20]u8 = undefined;
            try text.kv(out, 2, "timestamp", "{s} (unix {d})", .{ sanitize.iso8601(&buf, t), t });
        } else try text.kv(out, 2, "timestamp", "unparsed", .{});
        try text.kv(out, 2, "agent", "{s}", .{try ctx.sink.safeOr(q.agent, "unknown")});
        try text.kv(out, 2, "uuid", "{s}", .{try ctx.sink.safeOr(q.uuid, "unknown")});
        if (!q.well_formed) try text.kv(out, 2, "note", "value does not match flags;hex-time;agent;uuid", .{});
    } else {
        try text.kv(out, 2, "quarantine", "none", .{});
    }
    try text.kv(out, 2, "translocated", "{s}", .{yesNo(x.is_translocated)});
    try text.kv(out, 2, "provenance", "{s}", .{yesNo(x.provenance_present)});
    return 0;
}

fn yesNo(b: bool) []const u8 {
    return if (b) "yes" else "no";
}

/// Top-level payload (DESIGN §6.3): xattrs[], quarantine{...}|null, translocated, provenance.
fn renderJson(ctx: *Context, x: xattr.Xattrs) anyerror!u8 {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        try json.beginArch(js, img);
        try json.endArch(js);
    }
    try json.endArches(js);
    try json.names(js, ctx.arena, "xattrs", x.names);
    try js.objectField("quarantine");
    if (x.quarantine) |q| {
        try js.beginObject();
        try json.str(js, ctx.arena, "raw", q.raw);
        try json.hexOpt(js, "flags", if (q.flags) |f| @as(u64, f) else null);
        try json.isoTime(js, "timestamp", q.timestamp);
        try js.objectField("timestamp_unix");
        if (q.timestamp) |t| try js.write(t) else try js.write(null);
        try json.strOpt(js, ctx.arena, "agent", q.agent);
        try json.strOpt(js, ctx.arena, "uuid", q.uuid);
        try json.boolean(js, "well_formed", q.well_formed);
        try js.endObject();
    } else try js.write(null);
    try json.boolean(js, "translocated", x.is_translocated);
    try json.boolean(js, "provenance", x.provenance_present);
    return 0;
}
