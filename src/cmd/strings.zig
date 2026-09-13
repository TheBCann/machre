//! cmd/strings.zig — strings by kind with address/section and classification. Owned by WP6 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const sanitize = @import("../core/sanitize.zig");
const Image = @import("../core/image.zig").Image;
const strings_mod = @import("../strings/strings.zig");
const Analysis = @import("../analysis/analysis.zig").Analysis;

pub const command: Command = .{
    .name = "strings",
    .summary = "strings by kind with address/section and classification",
    .run = run,
    .flags = &.{ "--min=", "--kind=", "--no-generic", "--dedupe", "--bare", "--class=" },
    .aliases = &.{},
    .needs_macho = true,
};

/// Kinds `strings(1)` can see: it walks mapped, non-code sections and never follows a pointer, so
/// `--bare` leaves out the indirect (`__cfstring`) and wide (`__ustring`, UTF-16) kinds by default.
const bare_kinds: std.EnumSet(strings_mod.Kind) = .initMany(&.{ .cstring, .objc_methname, .objc_classname, .objc_methtype, .info_plist, .generic_ascii });

fn kindsFromSpec(spec: []const u8) ?std.EnumSet(strings_mod.Kind) {
    var set: std.EnumSet(strings_mod.Kind) = .empty;
    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |tok0| {
        const tok = std.mem.trim(u8, tok0, " ");
        if (tok.len == 0) continue;
        if (std.mem.eql(u8, tok, "objc")) {
            set.insert(.objc_methname);
            set.insert(.objc_classname);
            set.insert(.objc_methtype);
        } else if (std.mem.eql(u8, tok, "generic")) {
            set.insert(.generic_ascii);
            set.insert(.generic_utf16);
        } else if (std.meta.stringToEnum(strings_mod.Kind, tok)) |k| {
            set.insert(k);
        } else return null;
    }
    return set;
}

fn kindName(k: strings_mod.Kind) []const u8 {
    return @tagName(k);
}

const Params = struct {
    opts: strings_mod.Options,
    bare: bool,
    class_filter: ?strings_mod.Class,
};

fn parseParams(ctx: *Context) !?Params {
    const bare = ctx.args.flag("--bare") or ctx.otool_compat;
    var opts: strings_mod.Options = .{};
    opts.min_len = (ctx.args.valueInt(u32, "--min") catch {
        ctx.diags.err(.cli, .unknown_value, null, "--min: invalid value", .{});
        return null;
    }) orelse ctx.limits.min_string_len;
    if (opts.min_len == 0) opts.min_len = 1;
    opts.generic_scan = !ctx.args.flag("--no-generic");
    opts.dedupe = ctx.args.flag("--dedupe");
    opts.kinds = if (bare) bare_kinds else .full;
    if (ctx.args.value("--kind")) |spec| {
        opts.kinds = kindsFromSpec(spec) orelse {
            ctx.diags.err(.cli, .unknown_value, null, "--kind: unknown kind in '{s}'", .{spec});
            return null;
        };
    }
    var class_filter: ?strings_mod.Class = null;
    if (ctx.args.value("--class")) |spec| {
        class_filter = std.meta.stringToEnum(strings_mod.Class, spec) orelse {
            ctx.diags.err(.cli, .unknown_value, null, "--class: unknown class '{s}'", .{spec});
            return null;
        };
    }
    return .{ .opts = opts, .bare = bare, .class_filter = class_filter };
}

fn keep(p: Params, s: strings_mod.Str) bool {
    if (p.class_filter) |c| return s.class == c;
    return true;
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const p = (try parseParams(ctx)) orelse return 1;
    // `--limit` counts rows over the whole run (like `strings ... | head -n`), not per slice.
    var remaining: u32 = if (ctx.sink.opts.limit == 0) std.math.maxInt(u32) else ctx.sink.opts.limit;
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
        defer an.deinit();
        const res = try an.strings(p.opts);
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try renderJson(ctx, img, p, res, &remaining);
            try json.endArch(&ctx.sink.json);
        } else {
            try renderText(ctx, img, p, res, &remaining);
        }
    }
    return 0;
}

fn sectionName(ctx: *Context, img: *const Image, s: strings_mod.Str) ![]const u8 {
    const idx = s.section orelse return "";
    for (img.sections) |*sec| {
        if (sec.index == idx) return std.fmt.allocPrint(ctx.arena, "{s},{s}", .{ try ctx.sink.safe(sec.segname), try ctx.sink.safe(sec.sectname) });
    }
    return "";
}

fn renderText(ctx: *Context, img: *const Image, p: Params, res: *const strings_mod.StringsResult, remaining: *u32) !void {
    const out = ctx.sink.out;
    if (p.bare) {
        for (res.strings) |s| {
            if (!keep(p, s)) continue;
            // `strings(1)` reports maximal printable runs; a typed entry may contain more than one.
            var i: usize = 0;
            while (i < s.text.len) {
                if (!strings_mod.isPrintable(s.text[i])) {
                    i += 1;
                    continue;
                }
                var n: usize = 0;
                while (i + n < s.text.len and strings_mod.isPrintable(s.text[i + n])) : (n += 1) {}
                if (n >= p.opts.min_len) {
                    if (remaining.* == 0) return;
                    remaining.* -= 1;
                    try out.writeAll(s.text[i..][0..n]);
                    try out.writeByte('\n');
                }
                i += n;
            }
        }
        return;
    }
    var buf: [32]u8 = undefined;
    if (ctx.images.len > 1) try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), true);
    var shown: u32 = 0;
    var total: usize = 0;
    var tbl = text.Table.init(ctx.arena, &.{
        .{ .name = "address" },
        .{ .name = "section" },
        .{ .name = "kind" },
        .{ .name = "class" },
        .{ .name = "text" },
    });
    for (res.strings) |s| {
        if (!keep(p, s)) continue;
        total += 1;
        if (remaining.* == 0) continue;
        remaining.* -= 1;
        shown += 1;
        const shown_text = try ctx.sink.safeMax(s.text, ctx.limits.max_string_len);
        try tbl.rowFmt(&.{ "0x{x}", "{s}", "{s}", "{s}", "{s}" }, .{
            s.addr,
            try sectionName(ctx, img, s),
            kindName(s.kind),
            @tagName(s.class),
            shown_text,
        });
    }
    try text.kv(out, 2, "strings", "{d} shown of {d} (min {d}{s})", .{ shown, total, p.opts.min_len, if (res.truncated) ", limit reached" else "" });
    try tbl.render(out, 4, 0);
    if (shown < total) try out.print("    ({d} more rows, use --limit 0)\n", .{total - shown});
    if (res.lossy_count != 0) try text.kv(out, 2, "lossy", "{d} strings needed sanitisation", .{res.lossy_count});
}

fn renderJson(ctx: *Context, img: *const Image, p: Params, res: *const strings_mod.StringsResult, remaining: *u32) !void {
    const js = &ctx.sink.json;
    var total: usize = 0;
    for (res.strings) |s| {
        if (keep(p, s)) total += 1;
    }
    try js.objectField("strings");
    try js.beginArray();
    var shown: usize = 0;
    for (res.strings) |s| {
        if (!keep(p, s)) continue;
        if (remaining.* == 0) break;
        remaining.* -= 1;
        shown += 1;
        try js.beginObject();
        try json.hex(js, "address", s.addr);
        try json.int(js, "offset", s.file_offset);
        try json.str(js, ctx.arena, "section", try sectionName(ctx, img, s));
        try js.objectField("kind");
        try js.write(kindName(s.kind));
        try js.objectField("class");
        try js.write(@tagName(s.class));
        try json.str(js, ctx.arena, "text", s.text);
        try json.int(js, "length", s.raw_len);
        try json.boolean(js, "cut", s.cut);
        try json.boolean(js, "lossy", s.lossy);
        try js.endObject();
    }
    try js.endArray();
    try json.int(js, "total", total);
    try json.int(js, "lossy_strings", res.lossy_count);
    if (shown < total or res.truncated) try json.truncated(js, total);
}
