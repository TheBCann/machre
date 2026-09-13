//! cmd/version.zig — tool version, zig version, capstone/security availability. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const capstone = @import("../disasm/capstone.zig");
const security = @import("../darwin/security.zig");

pub const command: Command = .{
    .name = "version",
    .summary = "tool version, zig version, capstone/security availability",
    .run = run,
    .flags = &.{},
    .aliases = &.{},
    .needs_macho = false,
};

fn hostName() []const u8 {
    return @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag);
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const cs_version = capstone.version();
    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        try json.endArches(js);
        try js.objectField("version");
        try js.beginObject();
        try js.objectField("machre");
        try js.write(build_options.version);
        try js.objectField("zig");
        try js.write(builtin.zig_version_string);
        try js.objectField("capstone");
        try js.beginObject();
        try json.boolean(js, "available", capstone.available);
        try js.objectField("version");
        if (cs_version) |v| {
            var buf: [16]u8 = undefined;
            try js.write(std.fmt.bufPrint(&buf, "{d}.{d}", .{ v.major, v.minor }) catch "?");
        } else try js.write(null);
        try js.endObject();
        try js.objectField("security");
        try js.beginObject();
        try json.boolean(js, "available", security.available);
        try js.endObject();
        try js.objectField("host");
        try js.write(hostName());
        try js.endObject();
        return 0;
    }
    const out = ctx.sink.out;
    try text.header(out, "machre {s}", .{build_options.version});
    try text.kv(out, 2, "zig", "{s}", .{builtin.zig_version_string});
    if (cs_version) |v| {
        try text.kv(out, 2, "capstone", "available ({d}.{d})", .{ v.major, v.minor });
    } else {
        try text.kv(out, 2, "capstone", "{s}", .{if (capstone.available) "available" else "not linked (-Dcapstone=false)"});
    }
    try text.kv(out, 2, "security", "{s}", .{if (security.available) "available" else "not linked (-Dsecurity=false)"});
    try text.kv(out, 2, "host", "{s}", .{hostName()});
    return 0;
}
