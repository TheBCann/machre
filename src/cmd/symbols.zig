//! cmd/symbols.zig — symbol table (nm -m style), stab decoding, library ordinals, indirect table.
//! Owned by WP2 (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, macho/*, core/*.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const version = @import("../core/version.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const symbols_mod = @import("../macho/symbols.zig");
const Symbol = symbols_mod.Symbol;
const SymbolTable = symbols_mod.SymbolTable;
const imports_mod = @import("../macho/imports.zig");

pub const command: Command = .{
    .name = "symbols",
    .summary = "symbol table (nm -m style), stab decoding, library ordinals, indirect table",
    .run = run,
    .flags = &.{ "--defined", "--undefined", "--stabs", "--indirect", "--sort=", "--filter=", "--mode=" },
    .aliases = &.{"nm"},
    .needs_macho = true,
};

const Mode = enum { nm, @"nm-m", @"nm-a", machre };
const Sort = enum { addr, name, index };

const Opts = struct {
    mode: Mode,
    sort: Sort,
    filter: ?[]const u8,
    only_defined: bool,
    only_undefined: bool,
    only_stabs: bool,
    indirect: bool,
};

fn parseOpts(ctx: *Context) !Opts {
    var o: Opts = .{
        .mode = .@"nm-m",
        .sort = .name,
        .filter = ctx.args.value("--filter"),
        .only_defined = ctx.args.flag("--defined"),
        .only_undefined = ctx.args.flag("--undefined"),
        .only_stabs = ctx.args.flag("--stabs"),
        .indirect = ctx.args.flag("--indirect"),
    };
    if (ctx.args.value("--mode")) |m| o.mode = std.meta.stringToEnum(Mode, m) orelse return error.InvalidMode;
    if (o.mode == .machre) o.sort = .index;
    if (ctx.args.value("--sort")) |s| o.sort = std.meta.stringToEnum(Sort, s) orelse return error.InvalidSort;
    return o;
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const o = parseOpts(ctx) catch {
        ctx.diags.err(.cli, .unknown_value, null, "symbols: --mode must be nm|nm-m|nm-a|machre and --sort addr|name|index", .{});
        ctx.exit_code = .usage;
        return @intFromEnum(context.ExitCode.usage);
    };
    if (ctx.sink.isJson()) return runJson(ctx, o);
    return runText(ctx, o);
}

fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis {
    return Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
        .security = !ctx.no_security,
        .network = !ctx.no_network,
    });
}

/// `nm`'s per-slice banner (printed for multi-slice listings, preceded by a blank line).
fn nmBanner(out: *Io.Writer, path: []const u8, img: *const Image) Io.Writer.Error!void {
    var buf: [32]u8 = undefined;
    try out.print("\n{s} (for architecture {s}):\n", .{ path, img.arch.displayName(&buf) });
}

const SortCtx = struct {
    t: *const SymbolTable,
    sort: Sort,
    fn lessThan(c: SortCtx, a: u32, b: u32) bool {
        const sa = c.t.symbols[a];
        const sb = c.t.symbols[b];
        return switch (c.sort) {
            .index => a < b,
            .addr => if (sa.n_value == sb.n_value) a < b else sa.n_value < sb.n_value,
            .name => switch (std.mem.order(u8, sa.name, sb.name)) {
                .lt => true,
                .gt => false,
                .eq => a < b,
            },
        };
    }
};

fn selected(ctx: *Context, o: Opts, s: Symbol, show_stabs: bool) bool {
    _ = ctx;
    if (s.isStab() and !show_stabs and !o.only_stabs) return false;
    if (o.only_stabs and !s.isStab()) return false;
    if (o.only_defined and !(s.kind() == .section or s.kind() == .absolute or s.kind() == .indirect)) return false;
    if (o.only_undefined and !(s.kind() == .undefined or s.kind() == .prebound)) return false;
    if (o.filter) |f| if (std.mem.find(u8, s.name, f) == null) return false;
    return true;
}

fn orderedIndices(ctx: *Context, t: *const SymbolTable, o: Opts, show_stabs: bool) ![]u32 {
    var list: std.ArrayList(u32) = .empty;
    for (t.symbols) |s| if (selected(ctx, o, s, show_stabs)) try list.append(ctx.arena, s.index);
    const items = try list.toOwnedSlice(ctx.arena);
    std.mem.sort(u32, items, SortCtx{ .t = t, .sort = o.sort }, SortCtx.lessThan);
    return items;
}

// ---------------------------------------------------------------- text ----

fn runText(ctx: *Context, o: Opts) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        const t = try an.symbols();
        const dl = try an.dylibs();
        const show_stabs = o.mode == .@"nm-a" or o.only_stabs;
        if (multi) {
            if (o.mode == .machre) {
                var nb: [32]u8 = undefined;
                try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
            } else try nmBanner(out, ctx.display_path, img);
        }
        if (o.mode == .machre and !ctx.otool_compat) {
            try text.header(out, "{s}: {d} symbols ({d} defined, {d} undefined, {d} stabs, {d} external, {d} local)", .{
                std.fs.path.basename(ctx.display_path), t.symbols.len, t.counts.defined, t.counts.undefined, t.counts.stabs, t.counts.external, t.counts.local,
            });
        }
        const idx = try orderedIndices(ctx, t, o, show_stabs);
        switch (o.mode) {
            .nm, .@"nm-a" => for (idx) |i| try nmLine(ctx, img, out, t, t.symbols[i]),
            .@"nm-m" => for (idx) |i| try nmMLine(ctx, img, out, t, dl, t.symbols[i]),
            .machre => try machreTable(ctx, img, out, t, dl, idx),
        }
        // --otool-compat suppresses every machre-only block so the text diffs clean against nm(1).
        if (o.indirect and !ctx.otool_compat) try indirectTable(ctx, img, out, t);
    }
    return 0;
}

fn nmLine(ctx: *Context, img: *const Image, out: *Io.Writer, t: *const SymbolTable, s: Symbol) !void {
    _ = t;
    const name = try ctx.sink.safeMax(s.name, ctx.limits.max_symbol_name);
    if (s.isStab()) {
        try out.print("{x:0>16} - {x:0>2} {x:0>4} {s:>5} {s}\n", .{ s.n_value, s.n_sect, s.n_desc, version.stabName(s.n_type) orelse "??", name });
        return;
    }
    if (s.kind() == .undefined or s.kind() == .prebound) {
        if (s.n_value == 0) {
            try out.splatByteAll(' ', 16);
        } else try out.print("{x:0>16}", .{s.n_value});
    } else try out.print("{x:0>16}", .{s.n_value});
    try out.print(" {c} {s}\n", .{ s.nmLetter(img), name });
}

fn nmMLine(ctx: *Context, img: *const Image, out: *Io.Writer, t: *const SymbolTable, dl: []const imports_mod.DylibRef, s: Symbol) !void {
    _ = t;
    const name = try ctx.sink.safeMax(s.name, ctx.limits.max_symbol_name);
    if (s.isStab()) {
        try out.print("{x:0>16} - {x:0>2} {x:0>4} {s:>5} {s}\n", .{ s.n_value, s.n_sect, s.n_desc, version.stabName(s.n_type) orelse "??", name });
        return;
    }
    const undef = s.kind() == .undefined or s.kind() == .prebound;
    if (undef and s.n_value == 0) try out.splatByteAll(' ', 16) else try out.print("{x:0>16}", .{s.n_value});
    var lb: [40]u8 = undefined;
    try out.print(" {s} ", .{try ctx.sink.safe(s.nmLocation(img, &lb))});
    if (s.referencedDynamically()) try out.writeAll("[referenced dynamically] ");
    const ext = s.n_type & 0x01 != 0;
    if (s.isPrivateExternal()) {
        try out.writeAll(if (ext) "private external" else "non-external (was a private external)");
    } else if (ext) {
        try out.writeAll(if (s.isWeakRef() or s.isWeakDef()) "weak external" else "external");
    } else try out.writeAll("non-external");
    try out.print(" {s}", .{name});
    if (undef and (img.hdr.flags & std.macho.MH_TWOLEVEL) != 0) {
        const ord = s.libraryOrdinal();
        if (ord != 0) {
            if (ord == 0xff) {
                try out.writeAll(" (from executable)");
            } else if (ord == 0xfe) {
                try out.writeAll(" (dynamically looked up)");
            } else if (ord <= dl.len) {
                try out.print(" (from {s})", .{try ctx.sink.safe(nmShortName(dl[ord - 1].path))});
            } else {
                try out.print(" (from bad library ordinal {d})", .{ord});
            }
        }
    }
    try out.writeByte('\n');
}

fn machreTable(ctx: *Context, img: *const Image, out: *Io.Writer, t: *const SymbolTable, dl: []const imports_mod.DylibRef, idx: []const u32) !void {
    var tb = text.Table.init(ctx.arena, &.{
        .{ .name = "#", .@"align" = .right },
        .{ .name = "value" },
        .{ .name = "nm" },
        .{ .name = "type" },
        .{ .name = "sect" },
        .{ .name = "desc" },
        .{ .name = "library" },
        .{ .name = "name" },
    });
    for (idx) |i| {
        const s = t.symbols[i];
        var lb: [40]u8 = undefined;
        var ob: [32]u8 = undefined;
        const undef = s.kind() == .undefined or s.kind() == .prebound;
        const lib: []const u8 = if (undef) try ctx.sink.safe(imports_mod.ordinalName(&ob, ordinalOf(s), dl)) else "";
        try tb.rowFmt(&.{ "{d}", "0x{x}", "{c}", "{s}", "{s}", "0x{x:0>4}", "{s}", "{s}" }, .{
            s.index,
            s.n_value,
            s.nmLetter(img),
            if (s.isStab()) (version.stabName(s.n_type) orelse "stab") else @tagName(s.kind()),
            try ctx.sink.safe(s.nmLocation(img, &lb)),
            s.n_desc,
            lib,
            try ctx.sink.safeMax(s.name, ctx.limits.max_symbol_name),
        });
    }
    try tb.render(out, 2, ctx.sink.opts.limit);
}

/// `nm -m`'s spelling of a dylib: basename cut at the first '.' ("/usr/lib/libncurses.5.4.dylib" -> "libncurses").
fn nmShortName(path: []const u8) []const u8 {
    var name = path;
    if (std.mem.findScalarLast(u8, name, '/')) |i| name = name[i + 1 ..];
    if (std.mem.findScalar(u8, name, '.')) |i| name = name[0..i];
    return name;
}

/// nlist GET_LIBRARY_ORDINAL: 0xff EXECUTABLE_ORDINAL, 0xfe DYNAMIC_LOOKUP_ORDINAL; 1..0xfd are real.
fn ordinalOf(s: Symbol) i32 {
    return switch (s.libraryOrdinal()) {
        0xff => -1,
        0xfe => -2,
        else => |v| v,
    };
}

fn indirectTable(ctx: *Context, img: *const Image, out: *Io.Writer, t: *const SymbolTable) !void {
    try text.kv(out, 2, "indirect", "{d} entries (declared {d})", .{ t.indirect.len, t.nindirect_declared });
    var tb = text.Table.init(ctx.arena, &.{ .{ .name = "#", .@"align" = .right }, .{ .name = "section" }, .{ .name = "symbol index", .@"align" = .right }, .{ .name = "symbol" } });
    for (t.indirect, 0..) |raw, i| {
        const sect = sectionForIndirect(img, @intCast(i));
        const name: []const u8 = try ctx.sink.safeMax(if (t.indirectAt(@intCast(i))) |si| (if (t.symbolAt(si)) |s| s.name else "") else if (raw & 0x8000_0000 != 0) "LOCAL" else if (raw & 0x4000_0000 != 0) "ABS" else "", ctx.limits.max_symbol_name);
        try tb.rowFmt(&.{ "{d}", "{s}", "{d}", "{s}" }, .{
            i,
            if (sect) |s| try std.fmt.allocPrint(ctx.arena, "{s},{s}", .{ try ctx.sink.safe(s.segname), try ctx.sink.safe(s.sectname) }) else "",
            raw,
            name,
        });
    }
    try tb.render(out, 4, ctx.sink.opts.limit);
}

fn sectionForIndirect(img: *const Image, i: u32) ?*const @import("../core/image.zig").Section {
    for (img.sections) |*s| {
        const entsize = s.entrySize() orelse continue;
        if (entsize == 0) continue;
        if (!s.isSymbolStubs() and s.class != .la_symbol_ptr and s.class != .nl_symbol_ptr and s.class != .got and s.class != .auth_got) continue;
        const n: u64 = s.size / entsize;
        if (i >= s.reserved1 and i - s.reserved1 < n) return s;
    }
    return null;
}

// ---------------------------------------------------------------- json ----

fn runJson(ctx: *Context, o: Opts) anyerror!u8 {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        const t = try an.symbols();
        const dl = try an.dylibs();
        try json.beginArch(js, img);
        try js.objectField("symbols");
        try js.beginObject();
        try js.objectField("symtab");
        if (t.symtab) |st| {
            try js.beginObject();
            try json.int(js, "symoff", st.symoff);
            try json.int(js, "nsyms", st.nsyms);
            try json.int(js, "stroff", st.stroff);
            try json.int(js, "strsize", st.strsize);
            try js.endObject();
        } else try js.write(null);
        try js.objectField("dysymtab");
        if (t.dysymtab) |d| {
            try js.beginObject();
            try json.int(js, "ilocalsym", d.ilocalsym);
            try json.int(js, "nlocalsym", d.nlocalsym);
            try json.int(js, "iextdefsym", d.iextdefsym);
            try json.int(js, "nextdefsym", d.nextdefsym);
            try json.int(js, "iundefsym", d.iundefsym);
            try json.int(js, "nundefsym", d.nundefsym);
            try json.int(js, "tocoff", d.tocoff);
            try json.int(js, "ntoc", d.ntoc);
            try json.int(js, "modtaboff", d.modtaboff);
            try json.int(js, "nmodtab", d.nmodtab);
            try json.int(js, "extrefsymoff", d.extrefsymoff);
            try json.int(js, "nextrefsyms", d.nextrefsyms);
            try json.int(js, "indirectsymoff", d.indirectsymoff);
            try json.int(js, "nindirectsyms", d.nindirectsyms);
            try json.int(js, "extreloff", d.extreloff);
            try json.int(js, "nextrel", d.nextrel);
            try json.int(js, "locreloff", d.locreloff);
            try json.int(js, "nlocrel", d.nlocrel);
            try js.endObject();
        } else try js.write(null);
        try js.objectField("counts");
        try js.beginObject();
        try json.int(js, "defined", t.counts.defined);
        try json.int(js, "undefined", t.counts.undefined);
        try json.int(js, "stabs", t.counts.stabs);
        try json.int(js, "external", t.counts.external);
        try json.int(js, "local", t.counts.local);
        try js.endObject();
        const idx = try orderedIndices(ctx, t, o, true);
        try js.objectField("symbols");
        try js.beginArray();
        var shown: u32 = 0;
        for (idx) |i| {
            if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) break;
            shown += 1;
            const s = t.symbols[i];
            try js.beginObject();
            try json.int(js, "index", s.index);
            try json.str(js, ctx.arena, "name", s.name);
            try js.objectField("nm");
            var letter = [_]u8{s.nmLetter(img)};
            try js.write(@as([]const u8, &letter));
            try js.objectField("type");
            try js.write(@tagName(s.kind()));
            try json.hex(js, "type_raw", s.n_type);
            try json.int(js, "sect", s.n_sect);
            try json.hex(js, "desc", s.n_desc);
            try json.hex(js, "value", s.n_value);
            try json.boolean(js, "external", s.isExternal());
            try json.boolean(js, "private_external", s.isPrivateExternal());
            try json.boolean(js, "weak_ref", s.isWeakRef());
            try json.boolean(js, "weak_def", s.isWeakDef());
            try json.int(js, "library_ordinal", s.libraryOrdinal());
            var ob: [32]u8 = undefined;
            const undef = s.kind() == .undefined or s.kind() == .prebound;
            try json.strOpt(js, ctx.arena, "library", if (undef) imports_mod.ordinalName(&ob, ordinalOf(s), dl) else null);
            try json.strOpt(js, ctx.arena, "stab", if (s.isStab()) (version.stabName(s.n_type) orelse "unknown") else null);
            try js.endObject();
        }
        try js.endArray();
        if (ctx.sink.opts.limit != 0 and idx.len > shown) try json.truncated(js, idx.len);
        try js.objectField("indirect");
        try js.beginArray();
        for (t.indirect, 0..) |raw, i| {
            try js.beginObject();
            try json.int(js, "index", i);
            try json.int(js, "symbol_index", raw);
            const si = t.indirectAt(@intCast(i));
            try json.strOpt(js, ctx.arena, "symbol", if (si) |v| (if (t.symbolAt(v)) |s| s.name else null) else null);
            const sect = sectionForIndirect(img, @intCast(i));
            try json.strOpt(js, ctx.arena, "section", if (sect) |s| try std.fmt.allocPrint(ctx.arena, "{s},{s}", .{ s.segname, s.sectname }) else null);
            try js.endObject();
        }
        try js.endArray();
        try json.int(js, "lossy_strings", t.lossy_names);
        try js.endObject();
        try json.endArch(js);
    }
    return 0;
}
