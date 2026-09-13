//! cmd/objc.zig — Objective-C classes/methods/ivars/properties, categories, protocols, selectors, imageinfo.
//! Owned by WP6 (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const sanitize = @import("../core/sanitize.zig");
const version = @import("../core/version.zig");
const Image = @import("../core/image.zig").Image;
const objc = @import("../objc/objc.zig");
const Analysis = @import("../analysis/analysis.zig").Analysis;

pub const command: Command = .{
    .name = "objc",
    .summary = "Objective-C classes/methods/ivars/properties, categories, protocols, selectors, imageinfo",
    .run = run,
    .flags = &.{ "--classes", "--categories", "--protocols", "--selectors", "--methods", "--stubs" },
    .aliases = &.{},
    .needs_macho = true,
};

const Show = struct {
    classes: bool,
    categories: bool,
    protocols: bool,
    selectors: bool,
    stubs: bool,
    methods: bool,

    fn parse(ctx: *Context) Show {
        const any = ctx.args.flag("--classes") or ctx.args.flag("--categories") or ctx.args.flag("--protocols") or
            ctx.args.flag("--selectors") or ctx.args.flag("--stubs");
        if (!any) return .{ .classes = true, .categories = true, .protocols = true, .selectors = false, .stubs = false, .methods = true };
        return .{
            .classes = ctx.args.flag("--classes"),
            .categories = ctx.args.flag("--categories"),
            .protocols = ctx.args.flag("--protocols"),
            .selectors = ctx.args.flag("--selectors"),
            .stubs = ctx.args.flag("--stubs"),
            .methods = ctx.args.flag("--methods") or ctx.args.flag("--classes") or ctx.args.flag("--categories") or ctx.args.flag("--protocols"),
        };
    }
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const show = Show.parse(ctx);
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
        defer an.deinit();
        const info = (try an.objc()) orelse &objc.ObjcInfo.empty;
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try writeJson(ctx, info, show);
            try json.endArch(&ctx.sink.json);
        } else {
            var buf: [32]u8 = undefined;
            if (ctx.images.len > 1) try text.archBanner(ctx.sink.out, ctx.display_path, img.arch.displayName(&buf), true);
            try writeText(ctx, info, show);
        }
    }
    return 0;
}

fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    if (s.len == 0) return "?"; // an unresolved bind (external class/protocol) has no name yet
    return ctx.sink.safeMax(s, ctx.limits.max_symbol_name);
}

fn superText(ctx: *Context, sup: objc.SuperRef) ![]const u8 {
    return switch (sup.kind) {
        .local, .external => std.fmt.allocPrint(ctx.arena, " : {s}", .{try clean(ctx, sup.name orelse "")}),
        .unresolved => std.fmt.allocPrint(ctx.arena, " : <0x{x}>", .{sup.address}),
        .none => "",
    };
}

fn protocolsText(ctx: *Context, list: []const []const u8) ![]const u8 {
    if (list.len == 0) return "";
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(ctx.arena, " <");
    for (list, 0..) |p, i| {
        if (i != 0) try out.appendSlice(ctx.arena, ", ");
        try out.appendSlice(ctx.arena, try clean(ctx, p));
    }
    try out.append(ctx.arena, '>');
    return out.toOwnedSlice(ctx.arena);
}

fn writeMethods(ctx: *Context, owner: []const u8, methods: []const objc.Method) !void {
    const out = ctx.sink.out;
    for (methods) |m| {
        if (m.imp != 0) {
            try out.print("      0x{x:0>9}  {c}[{s} {s}]\n", .{ m.imp, @as(u8, if (m.is_class_method) '+' else '-'), owner, try clean(ctx, m.name) });
        } else {
            try out.print("                   {c}[{s} {s}]\n", .{ @as(u8, if (m.is_class_method) '+' else '-'), owner, try clean(ctx, m.name) });
        }
    }
}

fn writeText(ctx: *Context, info: *const objc.ObjcInfo, show: Show) !void {
    const out = ctx.sink.out;
    if (!info.present) {
        try text.kv(out, 2, "objc", "no Objective-C metadata in this slice", .{});
        return;
    }
    try text.kv(out, 2, "objc", "classes {d}  categories {d}  protocols {d}  selectors {d}  classrefs {d}  stubs {d}{s}", .{
        info.classes.len,                            info.categories.len, info.protocols.len, info.selectors.len, info.classrefs.len, info.stubs.len,
        if (info.truncated) "  (truncated)" else "",
    });
    if (info.image_info) |ii| {
        try text.kv(out, 2, "image info", "version {d}  flags 0x{x} ({s}){s}", .{
            ii.version,                        ii.flags, try text.flags(ctx.arena, ii.flags & 0xff, version.objc_image_info_flags, ","),
            if (ii.is_swift) " swift" else "",
        });
        if (ii.is_swift) try text.kv(out, 2, "swift", "unstable {d}  stable {d}.{d}", .{ ii.swift_unstable, ii.swift_stable >> 8, ii.swift_stable & 0xff });
    }
    if (show.classes) {
        for (info.classes) |c| {
            try out.print("    @interface {s}{s}{s}\n", .{ try clean(ctx, c.name), try superText(ctx, c.superclass), try protocolsText(ctx, c.protocols) });
            if (show.methods) {
                try writeMethods(ctx, try clean(ctx, c.name), c.methods);
                try writeMethods(ctx, try clean(ctx, c.name), c.class_methods);
            }
            for (c.ivars) |iv| {
                try out.print("      ivar {s} {s}", .{ try clean(ctx, iv.name), try clean(ctx, iv.type) });
                if (iv.offset) |o| try out.print(" @{d}", .{o});
                try out.print(" size {d}\n", .{iv.size});
            }
            for (c.properties) |pr| try out.print("      property {s} {s}\n", .{ try clean(ctx, pr.name), try clean(ctx, pr.attributes) });
            try out.writeAll("    @end\n");
        }
    }
    if (show.categories) {
        for (info.categories) |cat| {
            try out.print("    @interface {s}({s}){s}\n", .{ try clean(ctx, cat.class_name), try clean(ctx, cat.name), try protocolsText(ctx, cat.protocols) });
            if (show.methods) {
                try writeMethods(ctx, try clean(ctx, cat.class_name), cat.instance_methods);
                try writeMethods(ctx, try clean(ctx, cat.class_name), cat.class_methods);
            }
            try out.writeAll("    @end\n");
        }
    }
    if (show.protocols) {
        for (info.protocols) |p| {
            try out.print("    @protocol {s}{s}\n", .{ try clean(ctx, p.name), try protocolsText(ctx, p.protocols) });
            if (show.methods) {
                try writeMethods(ctx, try clean(ctx, p.name), p.instance_methods);
                try writeMethods(ctx, try clean(ctx, p.name), p.class_methods);
                try writeMethods(ctx, try clean(ctx, p.name), p.optional_instance_methods);
                try writeMethods(ctx, try clean(ctx, p.name), p.optional_class_methods);
            }
            try out.writeAll("    @end\n");
        }
    }
    if (show.selectors) {
        var tbl = text.Table.init(ctx.arena, &.{ .{ .name = "selref" }, .{ .name = "selector" } });
        for (info.selectors) |s| try tbl.rowFmt(&.{ "0x{x}", "{s}" }, .{ s.selref_addr, try clean(ctx, s.name) });
        try tbl.render(ctx.sink.out, 4, ctx.sink.opts.limit);
    }
    if (show.stubs) {
        var tbl = text.Table.init(ctx.arena, &.{ .{ .name = "stub" }, .{ .name = "selector" } });
        for (info.stubs) |s| try tbl.rowFmt(&.{ "0x{x}", "_objc_msgSend${s}" }, .{ s.addr, try clean(ctx, s.selector) });
        try tbl.render(ctx.sink.out, 4, ctx.sink.opts.limit);
    }
}

fn writeMethodsJson(ctx: *Context, key: []const u8, methods: []const objc.Method) !void {
    const js = &ctx.sink.json;
    try js.objectField(key);
    try js.beginArray();
    for (methods) |m| {
        try js.beginObject();
        try json.str(js, ctx.arena, "name", m.name);
        try json.str(js, ctx.arena, "types", m.types);
        try json.hex(js, "imp", m.imp);
        try json.boolean(js, "class_method", m.is_class_method);
        try json.boolean(js, "small", m.small);
        try js.endObject();
    }
    try js.endArray();
}

fn writeNamesJson(ctx: *Context, key: []const u8, names: []const []const u8) !void {
    try json.names(&ctx.sink.json, ctx.arena, key, names);
}

fn writeJson(ctx: *Context, info: *const objc.ObjcInfo, show: Show) !void {
    _ = show;
    const js = &ctx.sink.json;
    try js.objectField("objc");
    try js.beginObject();
    try json.boolean(js, "present", info.present);
    try js.objectField("image_info");
    if (info.image_info) |ii| {
        try js.beginObject();
        try json.int(js, "version", ii.version);
        try json.flags(js, "flags", ii.flags & 0xff, version.objc_image_info_flags);
        try json.int(js, "swift_unstable", ii.swift_unstable);
        try json.int(js, "swift_stable", ii.swift_stable);
        try json.boolean(js, "has_category_class_properties", ii.has_category_class_properties);
        try json.boolean(js, "is_swift", ii.is_swift);
        try js.endObject();
    } else try js.write(null);
    try js.objectField("classes");
    try js.beginArray();
    for (info.classes) |c| {
        try js.beginObject();
        try json.hex(js, "address", c.address);
        try json.str(js, ctx.arena, "name", c.name);
        try js.objectField("superclass");
        try js.beginObject();
        try js.objectField("kind");
        try js.write(@tagName(c.superclass.kind));
        try json.hex(js, "address", c.superclass.address);
        try json.strOpt(js, ctx.arena, "name", c.superclass.name);
        try js.endObject();
        try json.boolean(js, "meta", c.is_meta);
        try json.boolean(js, "swift", c.is_swift);
        try json.flags(js, "ro_flags", c.ro_flags, version.objc_ro_flags);
        try json.int(js, "instance_start", c.instance_start);
        try json.int(js, "instance_size", c.instance_size);
        try writeMethodsJson(ctx, "methods", c.methods);
        try writeMethodsJson(ctx, "class_methods", c.class_methods);
        try js.objectField("ivars");
        try js.beginArray();
        for (c.ivars) |iv| {
            try js.beginObject();
            try json.str(js, ctx.arena, "name", iv.name);
            try json.str(js, ctx.arena, "type", iv.type);
            try js.objectField("offset");
            if (iv.offset) |o| try js.write(o) else try js.write(null);
            try json.int(js, "alignment", iv.alignment);
            try json.int(js, "size", iv.size);
            try js.endObject();
        }
        try js.endArray();
        try js.objectField("properties");
        try js.beginArray();
        for (c.properties) |pr| {
            try js.beginObject();
            try json.str(js, ctx.arena, "name", pr.name);
            try json.str(js, ctx.arena, "attributes", pr.attributes);
            try js.endObject();
        }
        try js.endArray();
        try writeNamesJson(ctx, "protocols", c.protocols);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("categories");
    try js.beginArray();
    for (info.categories) |cat| {
        try js.beginObject();
        try json.hex(js, "address", cat.address);
        try json.str(js, ctx.arena, "name", cat.name);
        try json.str(js, ctx.arena, "class_name", cat.class_name);
        try json.boolean(js, "class_external", cat.class_external);
        try writeMethodsJson(ctx, "instance_methods", cat.instance_methods);
        try writeMethodsJson(ctx, "class_methods", cat.class_methods);
        try writeNamesJson(ctx, "protocols", cat.protocols);
        try js.objectField("properties");
        try js.beginArray();
        for (cat.properties) |pr| {
            try js.beginObject();
            try json.str(js, ctx.arena, "name", pr.name);
            try json.str(js, ctx.arena, "attributes", pr.attributes);
            try js.endObject();
        }
        try js.endArray();
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("protocols");
    try js.beginArray();
    for (info.protocols) |p| {
        try js.beginObject();
        try json.hex(js, "address", p.address);
        try json.str(js, ctx.arena, "name", p.name);
        try writeNamesJson(ctx, "protocols", p.protocols);
        try writeMethodsJson(ctx, "instance_methods", p.instance_methods);
        try writeMethodsJson(ctx, "class_methods", p.class_methods);
        try writeMethodsJson(ctx, "optional_instance_methods", p.optional_instance_methods);
        try writeMethodsJson(ctx, "optional_class_methods", p.optional_class_methods);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("selectors");
    try js.beginArray();
    for (info.selectors) |s| {
        try js.beginObject();
        try json.hex(js, "selref", s.selref_addr);
        try json.str(js, ctx.arena, "name", s.name);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("classrefs");
    try js.beginArray();
    for (info.classrefs) |cr| {
        try js.beginObject();
        try json.hex(js, "ref", cr.ref_addr);
        try json.str(js, ctx.arena, "name", cr.name);
        try json.boolean(js, "external", cr.external);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("stubs");
    try js.beginArray();
    for (info.stubs) |s| {
        try js.beginObject();
        try json.hex(js, "address", s.addr);
        try json.str(js, ctx.arena, "selector", s.selector);
        try js.endObject();
    }
    try js.endArray();
    try json.boolean(js, "truncated", info.truncated);
    try js.endObject();
}
