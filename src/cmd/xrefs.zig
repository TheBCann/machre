//! cmd/xrefs.zig — cross-references to/from an address or symbol, or the whole table.
//! Owned by WP8 (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, disasm/*, core/*.
//!
//! The table is built from a listing of every discovered function plus (unless `--no-pointer-slots`)
//! one `pointer_slot` xref per rebase fixup whose target lands in code — that is what finds
//! function-pointer tables, blocks, ObjC IMPs and `__mod_init_func` entries that no branch reaches.
//! `--to=<symbol>` matches through stubs, so callers of `_puts` are reported against the import.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const ExitCode = context.ExitCode;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const insn_mod = @import("../disasm/insn.zig");
const engine_mod = @import("../disasm/engine.zig");
const symbolize = @import("../disasm/symbolize.zig");
const functions_mod = @import("../disasm/functions.zig");

pub const command: Command = .{
    .name = "xrefs",
    .summary = "cross-references to/from an address or symbol, or the whole table",
    .run = run,
    .flags = &.{ "--to=", "--from=", "--strings", "--no-pointer-slots" },
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

fn annotateCtx(an: *Analysis) anyerror!symbolize.AnnotateCtx {
    return .{
        .img = an.img,
        .syms = try an.symbols(),
        .index = try an.addressIndex(),
        .fix = try an.fixups(),
        .stubs = try an.stubs(),
        .funcs = try an.functions(),
        .objc = try an.objc(),
        .strings = null,
        .otool_compat = false,
    };
}

/// `--to` / `--from` accept a symbol name, a stub name or a number.
const Target = struct { addr: ?u64, name: ?[]const u8 };
fn resolveTarget(an: *Analysis, spec: []const u8) anyerror!Target {
    if (std.fmt.parseInt(u64, spec, 0)) |v| return .{ .addr = v, .name = null } else |_| {}
    const funcs = try an.functions();
    if (funcs.byName(spec)) |f| return .{ .addr = f.start, .name = spec };
    const stubs = try an.stubs();
    if (stubs.byName(spec)) |s| return .{ .addr = s.addr, .name = spec };
    const syms = try an.symbols();
    if (syms.byName(spec)) |s| {
        if (s.n_value != 0) return .{ .addr = s.n_value, .name = spec };
    }
    return .{ .addr = null, .name = spec };
}

fn matchesTo(x: symbolize.Xref, t: Target) bool {
    if (t.addr) |a| if (x.to == a) return true;
    if (t.name) |n| if (x.target_name) |tn| if (std.mem.eql(u8, tn, n)) return true;
    return false;
}

/// Every function's listing, decoded once with annotation off (only semantics feed the xref walk).
fn listingsFor(ctx: *Context, an: *Analysis, img: *const Image) anyerror![]const insn_mod.Listing {
    var e = engine_mod.Engine.init(img.arch.name, .{ .annotate = false }) catch |err| switch (err) {
        error.UnsupportedArch => return &.{},
        error.CapstoneUnavailable, error.CapstoneOpen => return &.{},
        else => return err,
    };
    defer e.deinit();
    const actx = try annotateCtx(an);
    const funcs = try an.functions();
    var out: std.ArrayList(insn_mod.Listing) = .empty;
    var budget: u32 = ctx.limits.max_instructions;
    for (funcs.functions) |*f| {
        if (f.end <= f.start) continue;
        if (budget == 0) break;
        e.opts.max_insns = budget;
        const listing = try engine_mod.disassembleFunction(ctx.arena, &e, img, f, actx, ctx.limits, ctx.diags);
        budget -|= @intCast(@min(listing.insns.len, std.math.maxInt(u32)));
        try out.append(ctx.arena, listing);
    }
    return out.items;
}

fn tableFor(ctx: *Context, an: *Analysis, img: *const Image) anyerror!symbolize.XrefTable {
    const listings = try listingsFor(ctx, an, img);
    const actx = try annotateCtx(an);
    return symbolize.buildXrefs(ctx.arena, listings, actx, .{ .include_pointer_slots = !ctx.args.flag("--no-pointer-slots") }, ctx.limits);
}

/// Rows the flags select, in (to, from) order for `--to` and (from, to) order otherwise.
fn selected(ctx: *Context, an: *Analysis, t: *const symbolize.XrefTable) anyerror![]const symbolize.Xref {
    var out: std.ArrayList(symbolize.Xref) = .empty;
    const only_strings = ctx.args.flag("--strings");
    if (ctx.args.value("--to")) |spec| {
        const target = try resolveTarget(an, spec);
        for (t.by_to) |x| {
            if (!matchesTo(x, target)) continue;
            if (only_strings and x.kind != .string_ref) continue;
            try out.append(ctx.arena, x);
        }
        return out.items;
    }
    if (ctx.args.value("--from")) |spec| {
        const target = try resolveTarget(an, spec);
        const funcs = try an.functions();
        var lo: u64 = 0;
        var hi: u64 = 0;
        if (target.addr) |a| {
            lo = a;
            hi = a + 1;
            if (funcs.byStart(a)) |f| hi = f.end;
        }
        for (t.by_from) |x| {
            if (x.from < lo or x.from >= hi) continue;
            if (only_strings and x.kind != .string_ref) continue;
            try out.append(ctx.arena, x);
        }
        return out.items;
    }
    for (t.by_from) |x| {
        if (only_strings and x.kind != .string_ref) continue;
        try out.append(ctx.arena, x);
    }
    return out.items;
}

fn runText(ctx: *Context) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
        const tbl = try tableFor(ctx, &an, img);
        const rows = try selected(ctx, &an, &tbl);
        const what: []const u8 = if (ctx.args.value("--to")) |s|
            try std.fmt.allocPrint(ctx.arena, "xrefs to {s}", .{s})
        else if (ctx.args.value("--from")) |s|
            try std.fmt.allocPrint(ctx.arena, "xrefs from {s}", .{s})
        else
            "xrefs";
        try text.header(out, "{s}: {d} {s}{s}", .{ ctx.display_path, rows.len, what, if (tbl.truncated) " (truncated)" else "" });
        const funcs = try an.functions();
        var t = text.Table.init(ctx.arena, &.{
            .{ .name = "from" },
            .{ .name = "kind" },
            .{ .name = "function" },
            .{ .name = "target" },
        });
        for (rows) |x| {
            const fname: []const u8 = try ctx.sink.safe(if (x.from_function) |fi| (if (fi < funcs.functions.len) funcs.functions[fi].name else "") else "");
            const target: []const u8 = if (x.target_name) |n|
                try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ try ctx.sink.safe(n), if (x.via_stub) " (via stub)" else "" })
            else
                try std.fmt.allocPrint(ctx.arena, "0x{x}{s}", .{ x.to, if (x.via_stub) " (via stub)" else "" });
            try t.rowFmt(&.{ "0x{x}", "{s}", "{s}", "{s}" }, .{ x.from, @tagName(x.kind), fname, target });
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
        const tbl = try tableFor(ctx, &an, img);
        const rows = try selected(ctx, &an, &tbl);
        const funcs = try an.functions();
        try js.objectField("xrefs");
        try js.beginArray();
        var shown: usize = 0;
        for (rows) |x| {
            if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) break;
            shown += 1;
            try js.beginObject();
            try json.hex(js, "from", x.from);
            try json.strOpt(js, ctx.arena, "from_function", if (x.from_function) |fi|
                (if (fi < funcs.functions.len) funcs.functions[fi].name else null)
            else
                null);
            try json.hex(js, "to", x.to);
            try json.strOpt(js, ctx.arena, "to_name", x.target_name);
            try js.objectField("kind");
            try js.write(@tagName(x.kind));
            try json.boolean(js, "via_stub", x.via_stub);
            try js.endObject();
        }
        try js.endArray();
        if (shown < rows.len) try json.truncated(js, rows.len);
        try json.boolean(js, "pointer_slots_included", !ctx.args.flag("--no-pointer-slots"));
        try json.endArch(js);
    }
    return 0;
}
