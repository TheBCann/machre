//! cmd/dyld.zig — chained fixups / legacy opcode streams, function starts, data-in-code. Owned by WP2 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, macho/*, core/*.
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
const fixups_mod = @import("../macho/fixups.zig");
const dyld_chained = @import("../macho/dyld_chained.zig");
const dyld_legacy = @import("../macho/dyld_legacy.zig");
const imports_mod = @import("../macho/imports.zig");
const symbols_mod = @import("../macho/symbols.zig");

pub const command: Command = .{
    .name = "dyld",
    .summary = "chained fixups / legacy opcode streams, function starts, data-in-code",
    .run = run,
    .flags = &.{ "--fixups", "--chains", "--opcodes", "--function-starts", "--data-in-code", "--raw" },
    .aliases = &.{"fixups"},
    .needs_macho = true,
};

const Want = struct {
    fixups: bool,
    chains: bool,
    opcodes: bool,
    function_starts: bool,
    data_in_code: bool,
    raw: bool,

    fn from(ctx: *Context) Want {
        var w: Want = .{
            .fixups = ctx.args.flag("--fixups"),
            .chains = ctx.args.flag("--chains"),
            .opcodes = ctx.args.flag("--opcodes"),
            .function_starts = ctx.args.flag("--function-starts"),
            .data_in_code = ctx.args.flag("--data-in-code"),
            .raw = ctx.args.flag("--raw"),
        };
        if (!w.fixups and !w.chains and !w.opcodes and !w.function_starts and !w.data_in_code) {
            w.fixups = true;
            w.chains = true;
            w.function_starts = true;
            w.data_in_code = true;
        }
        return w;
    }
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const want = Want.from(ctx);
    if (ctx.sink.isJson()) return runJson(ctx, want);
    return runText(ctx, want);
}

// ---------------------------------------------------------------- text ----

fn runText(ctx: *Context, want: Want) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        if (ctx.otool_compat) {
            if (want.chains) try compatChains(ctx, img, &an, out);
            if (want.fixups) try compatFixups(ctx, img, &an, out);
            if (want.function_starts) try compatFunctionStarts(ctx, img, &an, out);
            continue;
        }
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true);
        const fix = try an.fixups();
        try text.header(out, "{s}: dyld data ({s})", .{ std.fs.path.basename(ctx.display_path), @tagName(fix.source) });
        if (want.chains) try textChains(ctx, &an, out);
        if (want.fixups) try textFixups(ctx, img, &an, out);
        if (want.opcodes) try textOpcodes(ctx, img, &an, out);
        if (want.function_starts) try textFunctionStarts(ctx, img, &an, out);
        if (want.data_in_code) try textDataInCode(ctx, &an, out);
        if (want.raw) try textRaw(ctx, img, &an, out);
    }
    return 0;
}

/// `dyld_info`'s per-slice banner: "<path> [arm64]:".
fn dyldBanner(out: *Io.Writer, path: []const u8, img: *const Image) Io.Writer.Error!void {
    var buf: [32]u8 = undefined;
    try out.print("{s} [{s}]:\n", .{ path, img.arch.displayName(&buf) });
}

fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis {
    return Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
        .security = !ctx.no_security,
        .network = !ctx.no_network,
    });
}

fn compatChains(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    try dyldBanner(out, ctx.display_path, img);
    try out.writeAll("    -fixup_chains:\n");
    const ch = (try an.chained()) orelse return;
    const h = ch.header;
    try headerRow(out, "fixups_version:", "0x{X:0>8}", .{h.fixups_version});
    try headerRow(out, "starts_offset:", "0x{X:0>8}", .{h.starts_offset});
    try headerRow(out, "imports_offset:", "0x{X:0>8}", .{h.imports_offset});
    try headerRow(out, "symbols_offset:", "0x{X:0>8}", .{h.symbols_offset});
    try headerRow(out, "imports_count:", "{d}", .{h.imports_count});
    if (version.importFormatName(h.imports_format)) |n|
        try headerRow(out, "imports_format:", "{d} ({s})", .{ h.imports_format, n })
    else
        try headerRow(out, "imports_format:", "{d}", .{h.imports_format});
    try headerRow(out, "symbols_format:", "{d}", .{h.symbols_format});
    for (ch.starts) |s| {
        try out.print("        seg[{d}]:\n", .{s.seg_index});
        try segRow(out, "page_size:", "0x{X:0>4}", .{s.page_size});
        const pf: dyld_chained.PointerFormat = @enumFromInt(s.pointer_format);
        const pname = version.pointerFormatName(s.pointer_format) orelse "?";
        try segRow(out, "pointer_format:", "{d} ({s}){s}", .{ s.pointer_format, pname, pf.describe() });
        try segRow(out, "segment_offset:", "0x{X:0>8}", .{s.segment_offset});
        try segRow(out, "max_pointer:", "0x{X:0>8}", .{s.max_valid_pointer});
        try out.print("          pages:{d:>10}\n", .{s.page_count});
        for (s.page_starts, 0..) |ps, i| try out.print("             start[{d:>2}]:  0x{X:0>4}\n", .{ i, ps });
    }
}

fn headerRow(out: *Io.Writer, label: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try out.print("      {s:<18}", .{label});
    try out.print(fmt, args);
    try out.writeByte('\n');
}
fn segRow(out: *Io.Writer, label: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try out.print("          {s:<17}", .{label});
    try out.print(fmt, args);
    try out.writeByte('\n');
}

fn compatFixups(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    try dyldBanner(out, ctx.display_path, img);
    try out.writeAll("    -fixups:\n");
    const fix = try an.fixups();
    if (fix.fixups.len == 0) return;
    const dl = try an.dylibs();
    try out.writeAll("        segment         section          address             type   target\n");
    for (fix.fixups) |f| try fixupRow(ctx, img, out, dl, f);
}

fn fixupRow(ctx: *Context, img: *const Image, out: *Io.Writer, dl: []const imports_mod.DylibRef, f: fixups_mod.Fixup) !void {
    var segname: []const u8 = "";
    var sectname: []const u8 = "";
    if (f.section) |si| {
        if (si >= 1 and si <= img.sections.len) {
            const s = img.sections[si - 1];
            segname = s.segname;
            sectname = s.sectname;
        }
    } else if (img.segmentForVm(f.vmaddr)) |seg| segname = seg.name;
    const kind = typeName(f);
    const target = try targetText(ctx, dl, f);
    try out.print("        {s:<16}{s:<17}0x{X:0>8}{s:>15}  {s}\n", .{ try ctx.sink.safe(segname), try ctx.sink.safe(sectname), f.vmaddr, kind, target });
}

fn typeName(f: fixups_mod.Fixup) []const u8 {
    return switch (f.kind) {
        .rebase => if (f.auth != null) "auth-rebase" else "rebase",
        .bind => if (f.auth != null) "auth-bind" else "bind",
        .lazy_bind => "lazy-bind",
        .weak_bind => "weak-bind",
    };
}

fn targetText(ctx: *Context, dl: []const imports_mod.DylibRef, f: fixups_mod.Fixup) ![]const u8 {
    if (f.kind == .rebase) return std.fmt.allocPrint(ctx.arena, "0x{X:0>8}", .{f.target});
    var buf: [32]u8 = undefined;
    const lib = imports_mod.ordinalName(&buf, f.lib_ordinal, dl);
    const weak = if (f.weak_import) " [weak-import]" else "";
    if (f.auth) |a| {
        return std.fmt.allocPrint(ctx.arena, "{s}/{s}{s} (div=0x{x:0>4} ad={d} key={s})", .{ try ctx.sink.safe(lib), try ctx.sink.safe(f.symbol), weak, a.diversity, @intFromBool(a.addr_div), keyName(a.key) });
    }
    return std.fmt.allocPrint(ctx.arena, "{s}/{s}{s}", .{ try ctx.sink.safe(lib), try ctx.sink.safe(f.symbol), weak });
}

fn keyName(k: u2) []const u8 {
    return switch (k) {
        0 => "IA",
        1 => "IB",
        2 => "DA",
        3 => "DB",
    };
}

fn compatFunctionStarts(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    try dyldBanner(out, ctx.display_path, img);
    try out.writeAll("    -function_starts:\n");
    const fs = (try an.functionStarts()) orelse {
        try out.writeAll("        no function starts info\n");
        return;
    };
    if (fs.addrs.len == 0) {
        try out.writeAll("        no function starts info\n");
        return;
    }
    const syms = try an.symbols();
    const ix = try an.addressIndex();
    for (fs.addrs) |a| {
        const label = try startLabel(ctx, img, syms, ix, a);
        try out.print("        0x{X:0>8}  {s}\n", .{ a, label });
    }
}

fn startLabel(ctx: *Context, img: *const Image, syms: *const symbols_mod.SymbolTable, ix: *const symbols_mod.AddressIndex, addr: u64) ![]const u8 {
    if (ix.at(syms, addr)) |s| if (s.name.len != 0) return ctx.sink.safe(s.name);
    const sect = img.sectionForVm(addr) orelse return "";
    const delta = addr - sect.addr;
    if (delta == 0) return std.fmt.allocPrint(ctx.arena, "{s},{s}", .{ try ctx.sink.safe(sect.segname), try ctx.sink.safe(sect.sectname) });
    return std.fmt.allocPrint(ctx.arena, "{s},{s}+{d}", .{ try ctx.sink.safe(sect.segname), try ctx.sink.safe(sect.sectname), delta });
}

fn textChains(ctx: *Context, an: *Analysis, out: *Io.Writer) !void {
    const ch = (try an.chained()) orelse {
        try text.kv(out, 2, "chains", "no LC_DYLD_CHAINED_FIXUPS", .{});
        return;
    };
    const h = ch.header;
    try text.kv(out, 2, "chains", "version {d}  imports {d} (format {d} {s})  symbols {s}", .{
        h.fixups_version,
        h.imports_count,
        h.imports_format,
        version.importFormatName(h.imports_format) orelse "?",
        if (ch.symbols_compressed) "zlib" else "uncompressed",
    });
    for (ch.starts) |s| {
        const pname = version.pointerFormatName(s.pointer_format) orelse "?";
        try out.print("    seg[{d}]  page_size 0x{x}  format {d} ({s})  segment_offset 0x{x}  pages {d}\n", .{ s.seg_index, s.page_size, s.pointer_format, pname, s.segment_offset, s.page_count });
    }
    var t = text.Table.init(ctx.arena, &.{ .{ .name = "#", .@"align" = .right }, .{ .name = "ordinal", .@"align" = .right }, .{ .name = "weak" }, .{ .name = "addend", .@"align" = .right }, .{ .name = "name" } });
    for (ch.imports, 0..) |imp, i| {
        try t.rowFmt(&.{ "{d}", "{d}", "{s}", "{d}", "{s}" }, .{ i, imp.lib_ordinal, if (imp.weak) "weak" else "", imp.addend, try ctx.sink.safe(imp.name) });
    }
    try t.render(out, 4, ctx.sink.opts.limit);
}

fn textFixups(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    const fix = try an.fixups();
    const dl = try an.dylibs();
    try text.kv(out, 2, "fixups", "{d} ({d} rebases, {d} binds, {d} auth, {d} lazy, {d} weak)", .{
        fix.fixups.len, fix.counts.rebases, fix.counts.binds, fix.counts.auth_binds, fix.counts.lazy, fix.counts.weak,
    });
    var t = text.Table.init(ctx.arena, &.{ .{ .name = "address" }, .{ .name = "segment" }, .{ .name = "section" }, .{ .name = "type" }, .{ .name = "target" } });
    for (fix.fixups) |f| {
        var segname: []const u8 = "";
        var sectname: []const u8 = "";
        if (f.section) |si| if (si >= 1 and si <= img.sections.len) {
            segname = img.sections[si - 1].segname;
            sectname = img.sections[si - 1].sectname;
        };
        try t.rowFmt(&.{ "0x{x}", "{s}", "{s}", "{s}", "{s}" }, .{ f.vmaddr, try ctx.sink.safe(segname), try ctx.sink.safe(sectname), typeName(f), try targetText(ctx, dl, f) });
    }
    try t.render(out, 4, ctx.sink.opts.limit);
}

fn textOpcodes(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    const lg = (try an.legacy()) orelse {
        try text.kv(out, 2, "opcodes", "no LC_DYLD_INFO", .{});
        return;
    };
    try dumpStream(ctx, img, out, "rebase", lg.cmd.rebase_off, lg.cmd.rebase_size, .rebase);
    try dumpStream(ctx, img, out, "bind", lg.cmd.bind_off, lg.cmd.bind_size, .bind);
    try dumpStream(ctx, img, out, "weak bind", lg.cmd.weak_bind_off, lg.cmd.weak_bind_size, .bind);
    try dumpStream(ctx, img, out, "lazy bind", lg.cmd.lazy_bind_off, lg.cmd.lazy_bind_size, .bind);
}

fn dumpStream(ctx: *Context, img: *const Image, out: *Io.Writer, what: []const u8, off: u32, size: u32, kind: enum { rebase, bind }) !void {
    if (size == 0) return;
    const sub = img.r.subClamped(off, size) orelse return;
    try text.kv(out, 2, "opcodes", "{s} stream at {d} ({d} bytes)", .{ what, off, size });
    const ops = switch (kind) {
        .rebase => try dyld_legacy.trace(ctx.arena, sub.r.bytes, .rebase, ctx.limits),
        .bind => try dyld_legacy.trace(ctx.arena, sub.r.bytes, .bind, ctx.limits),
    };
    var shown: u32 = 0;
    for (ops) |op| {
        if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) {
            try out.print("    ({d} more opcodes, use --limit 0)\n", .{ops.len - shown});
            break;
        }
        try out.print("    0x{x:0>6}  {s}\n", .{ op.offset, try ctx.sink.safe(op.text) });
        shown += 1;
    }
}

fn textFunctionStarts(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    const fs = (try an.functionStarts()) orelse {
        try text.kv(out, 2, "func starts", "none", .{});
        return;
    };
    try text.kv(out, 2, "func starts", "{d} (dataoff {d}, datasize {d})", .{ fs.addrs.len, fs.dataoff, fs.datasize });
    const syms = try an.symbols();
    const ix = try an.addressIndex();
    var shown: u32 = 0;
    for (fs.addrs) |a| {
        if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) {
            try out.print("    ({d} more rows, use --limit 0)\n", .{fs.addrs.len - shown});
            break;
        }
        try out.print("    0x{x}  {s}\n", .{ a, try startLabel(ctx, img, syms, ix, a) });
        shown += 1;
    }
}

/// `--raw`: hexdump of the on-disk payloads the parsers read.
fn textRaw(ctx: *Context, img: *const Image, an: *Analysis, out: *Io.Writer) !void {
    const limit = if (ctx.sink.opts.limit == 0) 0 else ctx.sink.opts.limit * 16;
    if (img.findCmd(.DYLD_CHAINED_FIXUPS)) |c| {
        const cr = c.reader();
        const off = cr.u32At(8, c.endian) orelse 0;
        const size = cr.u32At(12, c.endian) orelse 0;
        if (img.r.subClamped(off, size)) |sub| {
            try text.kv(out, 2, "raw", "LC_DYLD_CHAINED_FIXUPS dataoff {d} datasize {d}", .{ off, size });
            try text.hexdump(out, sub.r.bytes, img.slice_offset + off, limit);
        }
    }
    if (try an.legacy()) |lg| {
        const streams = [_]struct { name: []const u8, off: u32, size: u32 }{
            .{ .name = "rebase", .off = lg.cmd.rebase_off, .size = lg.cmd.rebase_size },
            .{ .name = "bind", .off = lg.cmd.bind_off, .size = lg.cmd.bind_size },
            .{ .name = "weak bind", .off = lg.cmd.weak_bind_off, .size = lg.cmd.weak_bind_size },
            .{ .name = "lazy bind", .off = lg.cmd.lazy_bind_off, .size = lg.cmd.lazy_bind_size },
            .{ .name = "export", .off = lg.cmd.export_off, .size = lg.cmd.export_size },
        };
        for (streams) |st| {
            if (st.size == 0) continue;
            const sub = img.r.subClamped(st.off, st.size) orelse continue;
            try text.kv(out, 2, "raw", "{s} stream at {d} ({d} bytes)", .{ st.name, st.off, st.size });
            try text.hexdump(out, sub.r.bytes, img.slice_offset + st.off, limit);
        }
    }
}

fn textDataInCode(ctx: *Context, an: *Analysis, out: *Io.Writer) !void {
    const dic = (try an.dataInCode()) orelse {
        try text.kv(out, 2, "data in code", "none", .{});
        return;
    };
    try text.kv(out, 2, "data in code", "{d} entries (dataoff {d}, datasize {d})", .{ dic.entries.len, dic.dataoff, dic.datasize });
    for (dic.entries) |x| {
        try out.print("    offset 0x{x}  length {d}  kind {d} ({s})\n", .{ x.offset, x.length, x.kind, version.diceKindName(x.kind) orelse "?" });
    }
    _ = ctx;
}

// ---------------------------------------------------------------- json ----

fn runJson(ctx: *Context, want: Want) anyerror!u8 {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        try json.beginArch(js, img);
        try js.objectField("dyld");
        try js.beginObject();
        const fix = try an.fixups();
        try js.objectField("source");
        try js.write(@tagName(fix.source));
        if (want.chains or want.fixups) try jsonChained(ctx, img, &an, js);
        if (want.chains or want.fixups or want.opcodes) try jsonLegacy(ctx, &an, js);
        try jsonExportsTrie(&an, js);
        if (want.function_starts) try jsonFunctionStarts(&an, js);
        if (want.data_in_code) try jsonDataInCode(ctx, &an, js);
        try js.endObject();
        try json.endArch(js);
    }
    return 0;
}

fn jsonChained(ctx: *Context, img: *const Image, an: *Analysis, js: *std.json.Stringify) !void {
    try js.objectField("chained_fixups");
    const ch = (try an.chained()) orelse {
        try js.write(null);
        return;
    };
    const dl = try an.dylibs();
    try js.beginObject();
    try js.objectField("header");
    try js.beginObject();
    try json.int(js, "fixups_version", ch.header.fixups_version);
    try json.int(js, "starts_offset", ch.header.starts_offset);
    try json.int(js, "imports_offset", ch.header.imports_offset);
    try json.int(js, "symbols_offset", ch.header.symbols_offset);
    try json.int(js, "imports_count", ch.header.imports_count);
    try json.int(js, "imports_format", ch.header.imports_format);
    try json.int(js, "symbols_format", ch.header.symbols_format);
    try js.endObject();
    try js.objectField("imports");
    try js.beginArray();
    for (ch.imports, 0..) |imp, i| {
        try js.beginObject();
        try json.int(js, "index", i);
        try json.int(js, "lib_ordinal", imp.lib_ordinal);
        var buf: [32]u8 = undefined;
        try json.str(js, ctx.arena, "library", imports_mod.ordinalName(&buf, imp.lib_ordinal, dl));
        try json.boolean(js, "weak", imp.weak);
        try json.str(js, ctx.arena, "name", imp.name);
        try json.int(js, "addend", imp.addend);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("starts");
    try js.beginArray();
    for (ch.starts) |s| {
        try js.beginObject();
        try json.int(js, "seg_index", s.seg_index);
        try json.strOpt(js, ctx.arena, "segment", if (s.seg_index < img.segments.len) img.segments[s.seg_index].name else null);
        try json.int(js, "page_size", s.page_size);
        try json.int(js, "pointer_format", s.pointer_format);
        try json.strOpt(js, ctx.arena, "pointer_format_name", version.pointerFormatName(s.pointer_format));
        try json.hex(js, "segment_offset", s.segment_offset);
        try json.int(js, "page_count", s.page_count);
        try js.objectField("page_starts");
        try js.beginArray();
        for (s.page_starts) |p| try js.write(sinkHex(p));
        try js.endArray();
        try js.endObject();
    }
    try js.endArray();
    try jsonFixupArray(ctx, img, an, js);
    try js.endObject();
}

fn sinkHex(v: u16) @import("../output/sink.zig").Hex64 {
    return .{ .v = v };
}

fn jsonFixupArray(ctx: *Context, img: *const Image, an: *Analysis, js: *std.json.Stringify) !void {
    const fix = try an.fixups();
    const dl = try an.dylibs();
    try js.objectField("fixups");
    try js.beginArray();
    var shown: u32 = 0;
    for (fix.fixups) |f| {
        if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) break;
        shown += 1;
        try js.beginObject();
        try json.hex(js, "address", f.vmaddr);
        var segname: ?[]const u8 = null;
        var sectname: ?[]const u8 = null;
        if (f.section) |si| if (si >= 1 and si <= img.sections.len) {
            segname = img.sections[si - 1].segname;
            sectname = img.sections[si - 1].sectname;
        };
        try json.strOpt(js, ctx.arena, "segment", segname);
        try json.strOpt(js, ctx.arena, "section", sectname);
        try js.objectField("kind");
        try js.write(typeName(f));
        try json.hex(js, "target", f.target);
        try json.str(js, ctx.arena, "symbol", f.symbol);
        var buf: [32]u8 = undefined;
        try json.str(js, ctx.arena, "library", if (f.kind == .rebase) "" else imports_mod.ordinalName(&buf, f.lib_ordinal, dl));
        try json.int(js, "addend", f.addend);
        try js.objectField("auth");
        if (f.auth) |a| {
            try js.beginObject();
            try js.objectField("key");
            try js.write(keyName(a.key));
            try json.int(js, "diversity", a.diversity);
            try json.boolean(js, "addr_div", a.addr_div);
            try js.endObject();
        } else try js.write(null);
        try json.hexOpt(js, "raw", f.raw);
        try js.endObject();
    }
    try js.endArray();
    if (ctx.sink.opts.limit != 0 and fix.fixups.len > shown) try json.truncated(js, fix.fixups.len);
}

fn jsonLegacy(ctx: *Context, an: *Analysis, js: *std.json.Stringify) !void {
    try js.objectField("dyld_info");
    const lg = (try an.legacy()) orelse {
        try js.write(null);
        return;
    };
    const dl = try an.dylibs();
    try js.beginObject();
    try js.objectField("cmd");
    try js.beginObject();
    try json.int(js, "rebase_off", lg.cmd.rebase_off);
    try json.int(js, "rebase_size", lg.cmd.rebase_size);
    try json.int(js, "bind_off", lg.cmd.bind_off);
    try json.int(js, "bind_size", lg.cmd.bind_size);
    try json.int(js, "weak_bind_off", lg.cmd.weak_bind_off);
    try json.int(js, "weak_bind_size", lg.cmd.weak_bind_size);
    try json.int(js, "lazy_bind_off", lg.cmd.lazy_bind_off);
    try json.int(js, "lazy_bind_size", lg.cmd.lazy_bind_size);
    try json.int(js, "export_off", lg.cmd.export_off);
    try json.int(js, "export_size", lg.cmd.export_size);
    try js.endObject();
    try js.objectField("rebases");
    try js.beginArray();
    for (lg.rebases) |r| {
        try js.beginObject();
        try json.int(js, "segment_index", r.seg_index);
        try json.hex(js, "segment_offset", r.seg_offset);
        try json.hexOpt(js, "address", r.vmaddr);
        try json.int(js, "type", r.type);
        try json.int(js, "stream_offset", r.stream_offset);
        try js.endObject();
    }
    try js.endArray();
    inline for (.{ .{ "binds", dyld_legacy.BindKind.bind }, .{ "weak_binds", dyld_legacy.BindKind.weak }, .{ "lazy_binds", dyld_legacy.BindKind.lazy } }) |pair| {
        try js.objectField(pair[0]);
        try js.beginArray();
        for (lg.binds) |b| {
            if (b.kind != pair[1]) continue;
            try js.beginObject();
            try json.int(js, "segment_index", b.seg_index);
            try json.hex(js, "segment_offset", b.seg_offset);
            try json.hexOpt(js, "address", b.vmaddr);
            try json.str(js, ctx.arena, "symbol", b.symbol);
            try json.int(js, "library_ordinal", b.lib_ordinal);
            var buf: [32]u8 = undefined;
            try json.str(js, ctx.arena, "library", imports_mod.ordinalName(&buf, b.lib_ordinal, dl));
            try json.int(js, "addend", b.addend);
            try json.int(js, "type", b.type);
            try json.boolean(js, "weak_import", b.weakImport());
            try json.int(js, "stream_offset", b.stream_offset);
            try js.endObject();
        }
        try js.endArray();
    }
    try js.objectField("threaded");
    if (lg.threaded) |t| {
        try js.beginObject();
        try json.int(js, "ordinal_table_size", t.ordinal_table_size);
        try json.int(js, "applies", t.applies);
        try js.endObject();
    } else try js.write(null);
    try js.endObject();
}

fn jsonExportsTrie(an: *Analysis, js: *std.json.Stringify) !void {
    try js.objectField("exports_trie");
    const t = (try an.exportsTrie()) orelse {
        try js.write(null);
        return;
    };
    try js.beginObject();
    try json.int(js, "dataoff", t.dataoff);
    try json.int(js, "datasize", t.datasize);
    try json.int(js, "count", t.exports.len);
    try js.endObject();
}

fn jsonFunctionStarts(an: *Analysis, js: *std.json.Stringify) !void {
    try js.objectField("function_starts");
    const fs = (try an.functionStarts()) orelse {
        try js.write(null);
        return;
    };
    try js.beginObject();
    try json.int(js, "dataoff", fs.dataoff);
    try json.int(js, "datasize", fs.datasize);
    try js.objectField("addresses");
    try js.beginArray();
    for (fs.addrs) |a| try js.write(@import("../output/sink.zig").Hex64{ .v = a });
    try js.endArray();
    try js.endObject();
}

fn jsonDataInCode(ctx: *Context, an: *Analysis, js: *std.json.Stringify) !void {
    try js.objectField("data_in_code");
    const dic = (try an.dataInCode()) orelse {
        try js.write(null);
        return;
    };
    try js.beginObject();
    try json.int(js, "dataoff", dic.dataoff);
    try json.int(js, "datasize", dic.datasize);
    try js.objectField("entries");
    try js.beginArray();
    for (dic.entries) |x| {
        try js.beginObject();
        try json.int(js, "offset", x.offset);
        try json.int(js, "length", x.length);
        try json.int(js, "kind", x.kind);
        try json.strOpt(js, ctx.arena, "kind_name", version.diceKindName(x.kind));
        try js.endObject();
    }
    try js.endArray();
    try js.endObject();
}
