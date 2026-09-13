//! cmd/info.zig — one-screen summary: container, header, platform, entry, dylibs, segments, symbol counts, signature summary, quarantine. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const macho = std.macho;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const fmt = @import("../core/fmt.zig");
const sanitize = @import("../core/sanitize.zig");
const version = @import("../core/version.zig");
const loadcmds = @import("../core/loadcmds.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const header_cmd = @import("header.zig");
const loadcmds_cmd = @import("loadcmds.zig");
const segments_cmd = @import("segments.zig");

pub const command: Command = .{
    .name = "info",
    .summary = "one-screen summary: container, header, platform, entry, dylibs, segments, symbol counts, signature summary, quarantine",
    .run = run,
    .flags = &.{"--no-hash"},
    .aliases = &.{},
    .needs_macho = true,
};

/// Everything `info` shows that comes straight from the load commands.
const Facts = struct {
    uuid: ?[16]u8 = null,
    build: ?loadcmds.BuildVersion = null,
    version_min: ?loadcmds.VersionMin = null,
    source_version: ?u64 = null,
    dylinker: ?[]const u8 = null,
    entry: loadcmds.Entry = .none,
    dylibs: []const loadcmds.Dylib = &.{},
    id_dylib: ?loadcmds.Dylib = null,
    rpaths: []const []const u8 = &.{},
    encryption: ?loadcmds.EncryptionInfo = null,
    chained: ?loadcmds.LinkeditData = null,
    exports_trie: ?loadcmds.LinkeditData = null,
    function_starts: ?loadcmds.LinkeditData = null,
    data_in_code: ?loadcmds.LinkeditData = null,
    code_signature: ?loadcmds.LinkeditData = null,
    dyld_info: ?macho.dyld_info_command = null,
    symtab: ?macho.symtab_command = null,
    dysymtab: ?macho.dysymtab_command = null,
};

fn collect(ctx: *Context, img: *const Image) !Facts {
    var f: Facts = .{};
    var dylibs: std.ArrayList(loadcmds.Dylib) = .empty;
    var rpaths: std.ArrayList([]const u8) = .empty;
    var ordinal: u16 = 0;
    for (img.cmds) |c| {
        switch (c.lc()) {
            .UUID => f.uuid = loadcmds.decodeUuid(c),
            .BUILD_VERSION => f.build = try loadcmds.decodeBuildVersion(ctx.arena, c, ctx.limits, ctx.diags),
            .VERSION_MIN_MACOSX, .VERSION_MIN_IPHONEOS, .VERSION_MIN_TVOS, .VERSION_MIN_WATCHOS => f.version_min = loadcmds.decodeVersionMin(c),
            .SOURCE_VERSION => f.source_version = loadcmds.decodeSourceVersion(c),
            .LOAD_DYLINKER => if (loadcmds.decodeLcStr(c, 8, ctx.diags)) |s| {
                f.dylinker = s.text;
            },
            .MAIN, .UNIXTHREAD => if (f.entry == .none) {
                f.entry = loadcmds.decodeEntry(c, img.hdr.is_64, ctx.diags);
            },
            .ID_DYLIB => f.id_dylib = try loadcmds.decodeDylib(ctx.arena, c, 0, ctx.diags),
            .RPATH => if (loadcmds.decodeLcStr(c, 8, ctx.diags)) |s| {
                if (rpaths.items.len < ctx.limits.max_rpaths) try rpaths.append(ctx.arena, s.text);
            },
            .ENCRYPTION_INFO, .ENCRYPTION_INFO_64 => f.encryption = loadcmds.decodeEncryptionInfo(c),
            .DYLD_CHAINED_FIXUPS => f.chained = loadcmds.decodeLinkeditData(c),
            .DYLD_EXPORTS_TRIE => f.exports_trie = loadcmds.decodeLinkeditData(c),
            .FUNCTION_STARTS => f.function_starts = loadcmds.decodeLinkeditData(c),
            .DATA_IN_CODE => f.data_in_code = loadcmds.decodeLinkeditData(c),
            .CODE_SIGNATURE => f.code_signature = loadcmds.decodeLinkeditData(c),
            .DYLD_INFO, .DYLD_INFO_ONLY => f.dyld_info = loadcmds.decodeDyldInfo(c),
            .SYMTAB => f.symtab = loadcmds.decodeSymtab(c),
            .DYSYMTAB => f.dysymtab = loadcmds.decodeDysymtab(c),
            else => {},
        }
        if (loadcmds.isDylibLoadCmd(c.cmd)) {
            if (ordinal < ctx.limits.max_dylibs) {
                ordinal += 1;
                if (try loadcmds.decodeDylib(ctx.arena, c, ordinal, ctx.diags)) |d| try dylibs.append(ctx.arena, d);
            } else if (!ctx.diags.has(.loadcmds, .limit_reached)) {
                ctx.diags.warn(.loadcmds, .limit_reached, c.offset, "more than {d} dylib load commands; the rest are ignored", .{ctx.limits.max_dylibs});
            }
        }
    }
    f.dylibs = try dylibs.toOwnedSlice(ctx.arena);
    f.rpaths = try rpaths.toOwnedSlice(ctx.arena);
    return f;
}

/// `file(1)`-style description: "Mach-O 64-bit executable arm64".
fn fileDescription(buf: []u8, img: *const Image) []const u8 {
    const kind: []const u8 = switch (img.hdr.filetype) {
        1 => "object",
        2 => "executable",
        3 => "fixed virtual memory shared library",
        4 => "core",
        5 => "preload executable",
        6 => "dynamically linked shared library",
        7 => "dynamic linker",
        8 => "bundle",
        9 => "dynamically linked shared library stub",
        10 => "dSYM companion file",
        11 => "kext bundle",
        12 => "fileset",
        else => "unknown filetype",
    };
    var ab: [32]u8 = undefined;
    return std.fmt.bufPrint(buf, "Mach-O {s}{s} {s}", .{ if (img.hdr.is_64) "64-bit " else "", kind, img.arch.displayName(&ab) }) catch "Mach-O";
}

fn writeText(ctx: *Context, img: *const Image, f: Facts, an: *Analysis) !void {
    const out = ctx.sink.out;
    const file = ctx.file.?;
    var desc_buf: [96]u8 = undefined;
    switch (file.container) {
        .fat => try out.print("{s}: {s} (fat slice {d} of {d} at offset {d}), {d} bytes\n", .{ ctx.display_path, fileDescription(&desc_buf, img), img.index + 1, file.sliceCount(), img.slice_offset, img.r.len() }),
        else => try out.print("{s}: {s} (thin), {d} bytes\n", .{ ctx.display_path, fileDescription(&desc_buf, img), img.r.len() }),
    }
    if (!ctx.args.flag("--no-hash")) {
        const d = file.digest();
        try text.kv(out, 2, "sha256", "{x}", .{@as([]const u8, &d)});
    }
    const hdr = img.hdr;
    const sub: u32 = @bitCast(hdr.cpusubtype);
    try text.kv(out, 2, "magic", "0x{x} {s}   cputype 0x{x} ({s})   cpusubtype 0x{x} ({s})   caps 0x{x:0>2}", .{
        hdr.magic,                       version.magicName(hdr.magic) orelse "?",
        @as(u32, @bitCast(hdr.cputype)), version.cpuTypeName(hdr.cputype) orelse "unknown",
        sub & 0x00ff_ffff,               subtypeWord(img),
        sub >> 24,
    });
    try text.kv(out, 2, "filetype", "{d} {s}   ncmds {d}   sizeofcmds {d}", .{ hdr.filetype, version.filetypeName(hdr.filetype) orelse "?", hdr.ncmds, hdr.sizeofcmds });
    try text.kv(out, 2, "flags", "{f}", .{fmt.Flags{ .value = hdr.flags, .table = version.mh_flags }});
    if (f.uuid) |u| try text.kv(out, 2, "uuid", "{f}", .{fmt.Uuid{ .bytes = u }});
    if (f.build) |bv| {
        try out.print("  {s:<13}{s}   minos {f}   sdk {f}", .{ "platform", version.platformName(bv.platform) orelse "unknown", fmt.VersionShort{ .v = bv.minos }, fmt.VersionShort{ .v = bv.sdk } });
        if (bv.tools.len > 0) {
            try out.writeAll("   tools");
            for (bv.tools) |t| {
                if (version.toolName(t.tool)) |n| try out.print(" {s} {f}", .{ n, fmt.VersionShort{ .v = t.version } }) else try out.print(" tool {d} {f}", .{ t.tool, fmt.VersionShort{ .v = t.version } });
            }
        }
        try out.writeByte('\n');
    } else if (f.version_min) |vm| {
        var nb: [32]u8 = undefined;
        try text.kv(out, 2, "platform", "{s}   minos {f}   sdk {f}", .{ version.lcNameBuf(&nb, vm.cmd), fmt.VersionShort{ .v = vm.version }, fmt.VersionShort{ .v = vm.sdk } });
    }
    if (f.source_version) |sv| try text.kv(out, 2, "source ver", "{f}", .{fmt.SourceVersion{ .v = sv }});
    if (f.dylinker) |dl| try text.kv(out, 2, "dylinker", "{s}", .{try ctx.sink.safe(dl)});
    if (f.id_dylib) |id| try text.kv(out, 2, "id dylib", "{s} (compatibility version {f}, current version {f})", .{ try ctx.sink.safe(id.name), fmt.Version{ .v = id.compat_version }, fmt.Version{ .v = id.current_version } });
    switch (f.entry) {
        .main => |m| {
            const vm = std.math.add(u64, img.image_base, m.entryoff) catch img.image_base;
            const name = try entrySymbol(ctx, an, vm);
            if (name) |n| {
                try text.kv(out, 2, "entry", "LC_MAIN entryoff 0x{x} -> 0x{x} ({s})   stacksize {d}", .{ m.entryoff, vm, n, m.stacksize });
            } else try text.kv(out, 2, "entry", "LC_MAIN entryoff 0x{x} -> 0x{x}   stacksize {d}", .{ m.entryoff, vm, m.stacksize });
        },
        .unixthread => |t| {
            if (t.pc) |pc| {
                const name = try entrySymbol(ctx, an, pc);
                if (name) |n| {
                    try text.kv(out, 2, "entry", "LC_UNIXTHREAD pc 0x{x} ({s})", .{ pc, n });
                } else try text.kv(out, 2, "entry", "LC_UNIXTHREAD pc 0x{x}", .{pc});
            } else try text.kv(out, 2, "entry", "LC_UNIXTHREAD flavor {d} (pc not decoded)", .{t.flavor});
        },
        .none => {},
    }
    // dyld data line (§5.4): parsed counts when the parser is available, declared byte sizes otherwise.
    {
        try out.print("  {s:<13}", .{"dyld data"});
        var first = true;
        if (f.chained) |ld| {
            const ch = try an.chained();
            if (ch) |c| {
                try out.writeAll("chained fixups (");
                if (c.pointerFormat()) |pf| try out.print("format {d} {s}, ", .{ @intFromEnum(pf), version.pointerFormatName(@intFromEnum(pf)) orelse "?" });
                try out.print("{d} imports, {d} fixups)", .{ c.imports.len, c.fixups.len });
            } else try out.print("chained fixups ({d} bytes)", .{ld.datasize});
            first = false;
        }
        if (f.dyld_info) |di| {
            if (!first) try out.writeAll("   ");
            try out.print("dyld info (rebase {d}, bind {d}, weak {d}, lazy {d}, export {d} bytes)", .{ di.rebase_size, di.bind_size, di.weak_bind_size, di.lazy_bind_size, di.export_size });
            first = false;
        }
        if (f.exports_trie) |ld| {
            if (!first) try out.writeAll("   ");
            if (try an.exportsTrie()) |t| try out.print("exports trie ({d})", .{t.exports.len}) else try out.print("exports trie ({d} bytes)", .{ld.datasize});
            first = false;
        }
        if (f.function_starts) |ld| {
            if (!first) try out.writeAll("   ");
            if (try an.functionStarts()) |fs| try out.print("function starts ({d})", .{fs.addrs.len}) else try out.print("function starts ({d} bytes)", .{ld.datasize});
            first = false;
        }
        if (first) try out.writeAll("none");
        try out.writeByte('\n');
    }
    if (f.encryption) |ei| try text.kv(out, 2, "encryption", "cryptoff {d} cryptsize {d} cryptid {d}{s}", .{ ei.cryptoff, ei.cryptsize, ei.cryptid, if (ei.cryptid != 0) " (ENCRYPTED)" else "" });
    try text.kv(out, 2, "dylibs", "{d}", .{f.dylibs.len});
    for (f.dylibs) |d| {
        try out.print("    {d}  {s} (compatibility version {f}, current version {f}){s}{s}{s}\n", .{ d.ordinal, try ctx.sink.safe(d.name), fmt.Version{ .v = d.compat_version }, fmt.Version{ .v = d.current_version }, if (d.weak) " weak" else "", if (d.reexport) " reexport" else "", if (d.upward) " upward" else "" });
    }
    if (f.rpaths.len > 0) {
        try text.kv(out, 2, "rpaths", "{d}", .{f.rpaths.len});
        for (f.rpaths) |p| try out.print("    {s}\n", .{try ctx.sink.safe(p)});
    }
    try text.kv(out, 2, "segments", "{d}", .{img.segments.len});
    try segments_cmd.writeSegmentRows(ctx.sink, img, 4, false);
    // WP2/WP3/WP4 payloads through the facade (stubs report "not implemented").
    const syms = try an.symbols();
    if (syms.present) {
        try text.kv(out, 2, "symbols", "{d} ({d} defined, {d} undefined, {d} stabs)   indirect {d}", .{ syms.symbols.len, syms.counts.defined, syms.counts.undefined, syms.counts.stabs, syms.indirect.len });
    } else if (f.symtab) |st| {
        try text.kv(out, 2, "symbols", "{d} declared (LC_SYMTAB symoff {d} stroff {d} strsize {d}){s}", .{ st.nsyms, st.symoff, st.stroff, st.strsize, if (ctx.diags.has(.symbols, .not_implemented)) "   parser not implemented" else "" });
    } else try text.kv(out, 2, "symbols", "none (no LC_SYMTAB)", .{});
    if (f.code_signature) |cs| {
        if (try an.signature()) |sig| {
            if (sig.cd()) |cd| {
                const ident = try ctx.sink.safeMax(cd.identifier, ctx.limits.max_string_len);
                try out.print("  {s:<13}{s}   identifier \"{s}\"   cdhash {x}", .{ "signature", try signingFlagText(ctx.arena, cd.flags), ident, &cd.cdhash });
                if (try an.verification()) |v| {
                    if (v.pages_checked == 0) {
                        try out.writeAll("   pages not verified");
                    } else if (v.mismatches == 0) {
                        try out.print("   pages {d}/{d} ok", .{ v.pages_ok, v.pages_checked });
                    } else try out.print("   pages {d}/{d}, {d} mismatch{s}", .{ v.pages_ok, v.pages_checked, v.mismatches, if (v.mismatches == 1) "" else "es" });
                }
                try out.writeByte('\n');
            } else try text.kv(out, 2, "signature", "present (no CodeDirectory)", .{});
        } else try text.kv(out, 2, "signature", "present (LC_CODE_SIGNATURE dataoff {d} datasize {d}){s}", .{ cs.dataoff, cs.datasize, if (ctx.diags.has(.codesign, .not_implemented)) "   parser not implemented" else "" });
    } else try text.kv(out, 2, "signature", "none (no LC_CODE_SIGNATURE)", .{});
    const verdict = try an.security();
    if (verdict.available) {
        try text.kv(out, 2, "security", "{s} ({s})   trust: {s}   notarized: {s}", .{
            validityWord(verdict.validity_status, verdict.trust),
            verdict.validity_status_name,
            trustText(verdict.trust),
            if (verdict.requirement_results.notarized == 0) "yes" else "no",
        });
    } else try text.kv(out, 2, "security", "not evaluated ({s})", .{verdict.reason orelse "unavailable"});
    const xa = try an.xattrs();
    if (xa.available) {
        if (xa.quarantine) |q| {
            try text.kv(out, 2, "quarantine", "{s}{s}", .{ try ctx.sink.safeMax(q.raw, ctx.limits.max_string_len), if (xa.is_translocated) "   (translocated)" else "" });
        } else try text.kv(out, 2, "quarantine", "none", .{});
    } else try text.kv(out, 2, "quarantine", "not checked{s}", .{if (ctx.diags.has(.xattr, .not_implemented)) " (not implemented)" else ""});
}

/// `an.addressIndex()` lookup for the entry address; null while `macho/symbols` is a stub.
fn entrySymbol(ctx: *Context, an: *Analysis, vm: u64) !?[]const u8 {
    const syms = try an.symbols();
    if (!syms.present or syms.symbols.len == 0) return null;
    const ix = try an.addressIndex();
    const sym = ix.at(syms, vm) orelse return null;
    if (sym.name.len == 0) return null;
    return try ctx.sink.safeMax(sym.name, ctx.limits.max_string_len);
}

/// CS flag names in the §5.4 spelling: "ad hoc, linker-signed" (codesign's `adhoc` with a space).
fn signingFlagText(arena: std.mem.Allocator, flags: u32) ![]const u8 {
    if (flags == 0) return "signed";
    const joined = try text.flags(arena, flags, version.cs_flags, ", ");
    if (std.mem.startsWith(u8, joined, "adhoc")) return std.fmt.allocPrint(arena, "ad hoc{s}", .{joined["adhoc".len..]});
    return joined;
}

/// "valid" / "unsigned" / "revoked" / "invalid" — an unsigned file is not an invalid one.
fn validityWord(status: i32, trust: anytype) []const u8 {
    if (status == 0) return "valid";
    return switch (trust) {
        .unsigned => "unsigned",
        .revoked => "revoked",
        else => "invalid",
    };
}

/// Trust ladder rung in the §5.4 spelling (never `@tagName`, which would print `developer_id_notarized`).
fn trustText(t: anytype) []const u8 {
    return switch (t) {
        .platform => "platform",
        .app_store => "Mac App Store",
        .developer_id_notarized => "Developer ID, notarized",
        .developer_id => "Developer ID",
        .other_certificate => "other certificate",
        .adhoc => "ad hoc",
        .unsigned => "unsigned",
        .invalid => "invalid",
        .revoked => "revoked",
        .unavailable => "not evaluated",
    };
}

fn subtypeWord(img: *const Image) []const u8 {
    return switch (img.arch.name) {
        .x86_64, .arm64, .i386, .ppc, .ppc64 => "ALL",
        .x86_64h => "H",
        .arm64v8 => "V8",
        .arm64e => "E",
        .arm64_32 => "V8",
        else => "?",
    };
}

fn writeJson(ctx: *Context, img: *const Image, f: Facts, an: *Analysis) !void {
    const js = &ctx.sink.json;
    const a = ctx.arena;
    try js.objectField("info");
    try js.beginObject();
    try header_cmd.writeHeaderJson(js, img);
    if (f.uuid) |u| try json.uuid(js, "uuid", u) else {
        try js.objectField("uuid");
        try js.write(null);
    }
    try js.objectField("build_version");
    if (f.build) |bv| {
        try js.beginObject();
        try json.int(js, "platform", bv.platform);
        try js.objectField("platform_name");
        if (version.platformName(bv.platform)) |n| try js.write(n) else try js.write(null);
        try js.objectField("minos");
        try js.print("\"{f}\"", .{fmt.VersionShort{ .v = bv.minos }});
        try js.objectField("sdk");
        try js.print("\"{f}\"", .{fmt.VersionShort{ .v = bv.sdk }});
        try js.objectField("tools");
        try js.beginArray();
        for (bv.tools) |t| {
            try js.beginObject();
            try json.int(js, "tool", t.tool);
            try js.objectField("name");
            if (version.toolName(t.tool)) |n| try js.write(n) else try js.write(null);
            try js.objectField("version");
            try js.print("\"{f}\"", .{fmt.VersionShort{ .v = t.version }});
            try js.endObject();
        }
        try js.endArray();
        try js.endObject();
    } else try js.write(null);
    try js.objectField("version_min");
    if (f.version_min) |vm| {
        var nb: [32]u8 = undefined;
        try js.beginObject();
        try js.objectField("cmd");
        try js.write(version.lcNameBuf(&nb, vm.cmd));
        try js.objectField("version");
        try js.print("\"{f}\"", .{fmt.VersionShort{ .v = vm.version }});
        try js.objectField("sdk");
        try js.print("\"{f}\"", .{fmt.VersionShort{ .v = vm.sdk }});
        try js.endObject();
    } else try js.write(null);
    try js.objectField("source_version");
    if (f.source_version) |sv| try js.print("\"{f}\"", .{fmt.SourceVersion{ .v = sv }}) else try js.write(null);
    try json.strOpt(js, a, "dylinker", f.dylinker);
    try js.objectField("entry");
    switch (f.entry) {
        .main => |m| {
            try js.beginObject();
            try js.objectField("kind");
            try js.write("main");
            try json.hex(js, "entryoff", m.entryoff);
            try json.hex(js, "address", std.math.add(u64, img.image_base, m.entryoff) catch img.image_base);
            try json.int(js, "stacksize", m.stacksize);
            try json.strOpt(js, a, "symbol", try entrySymbol(ctx, an, std.math.add(u64, img.image_base, m.entryoff) catch img.image_base));
            try js.endObject();
        },
        .unixthread => |t| {
            try js.beginObject();
            try js.objectField("kind");
            try js.write("unixthread");
            try json.int(js, "flavor", t.flavor);
            try json.hexOpt(js, "address", t.pc);
            try json.strOpt(js, a, "symbol", if (t.pc) |pc| try entrySymbol(ctx, an, pc) else null);
            try js.endObject();
        },
        .none => try js.write(null),
    }
    try js.objectField("dyld");
    try js.beginObject();
    try js.objectField("style");
    try js.write(@tagName(img.dyldStyle()));
    try js.objectField("pointer_formats");
    try js.beginArray();
    if (try an.chained()) |ch| if (ch.pointerFormat()) |pf| try js.write(version.pointerFormatName(@intFromEnum(pf)) orelse "unknown");
    try js.endArray();
    try js.objectField("imports");
    if (try an.chained()) |ch| try js.write(ch.imports.len) else try js.write(null);
    try js.objectField("fixups");
    if (try an.chained()) |ch| try js.write(ch.fixups.len) else try js.write(null);
    try js.objectField("exports");
    if (try an.exportsTrie()) |t| try js.write(t.exports.len) else try js.write(null);
    try js.objectField("function_starts");
    if (try an.functionStarts()) |fs| try js.write(fs.addrs.len) else try js.write(null);
    try js.objectField("chained_fixups_cmd");
    if (f.chained) |ld| {
        try js.beginObject();
        try json.int(js, "dataoff", ld.dataoff);
        try json.int(js, "datasize", ld.datasize);
        try js.endObject();
    } else try js.write(null);
    try js.objectField("exports_trie_cmd");
    if (f.exports_trie) |ld| {
        try js.beginObject();
        try json.int(js, "dataoff", ld.dataoff);
        try json.int(js, "datasize", ld.datasize);
        try js.endObject();
    } else try js.write(null);
    try js.endObject();
    try js.objectField("dylibs");
    try js.beginArray();
    for (f.dylibs) |d| try writeDylibJson(js, a, d);
    try js.endArray();
    try js.objectField("id_dylib");
    if (f.id_dylib) |d| try writeDylibJson(js, a, d) else try js.write(null);
    try json.names(js, a, "rpaths", f.rpaths);
    try js.objectField("segments");
    try js.beginArray();
    for (img.segments) |seg| {
        try js.beginObject();
        try loadcmds_cmd.writeSegmentJson(js, a, img, seg, null);
        try js.endObject();
    }
    try js.endArray();
    const syms = try an.symbols();
    if (syms.present) {
        try js.objectField("symbols");
        try js.beginObject();
        try json.int(js, "total", syms.symbols.len);
        try json.int(js, "defined", syms.counts.defined);
        try json.int(js, "undefined", syms.counts.undefined);
        try json.int(js, "stabs", syms.counts.stabs);
        try json.int(js, "external", syms.counts.external);
        try json.int(js, "local", syms.counts.local);
        try json.int(js, "indirect", syms.indirect.len);
        try js.endObject();
    } else try json.unavailable(js, "symbols", if (f.symtab == null) "no LC_SYMTAB" else "not implemented");
    try js.objectField("symtab");
    if (f.symtab) |st| {
        try js.beginObject();
        try json.int(js, "symoff", st.symoff);
        try json.int(js, "nsyms", st.nsyms);
        try json.int(js, "stroff", st.stroff);
        try json.int(js, "strsize", st.strsize);
        try js.endObject();
    } else try js.write(null);
    if (try an.signature()) |sig| {
        try js.objectField("code_signature");
        try js.beginObject();
        try json.boolean(js, "present", true);
        if (sig.cd()) |cd| {
            try json.flags(js, "flags", cd.flags, version.cs_flags);
            try json.str(js, a, "identifier", cd.identifier);
            try json.strOpt(js, a, "team_id", cd.team_id);
            try json.bytesHex(js, "cdhash", &cd.cdhash);
            try json.int(js, "hash_type", @intFromEnum(cd.hash_type));
        } else {
            try js.objectField("flags");
            try js.write(null);
            try js.objectField("identifier");
            try js.write(null);
            try js.objectField("team_id");
            try js.write(null);
            try js.objectField("cdhash");
            try js.write(null);
            try js.objectField("hash_type");
            try js.write(null);
        }
        if (try an.verification()) |v| {
            try json.int(js, "pages_ok", v.pages_ok);
            try json.int(js, "pages_total", v.pages_checked);
            try json.int(js, "page_mismatches", v.mismatches);
        } else {
            try js.objectField("pages_ok");
            try js.write(null);
            try js.objectField("pages_total");
            try js.write(null);
            try js.objectField("page_mismatches");
            try js.write(null);
        }
        try js.endObject();
    } else if (f.code_signature) |cs| {
        try js.objectField("code_signature");
        try js.beginObject();
        try json.boolean(js, "present", true);
        try json.int(js, "dataoff", cs.dataoff);
        try json.int(js, "datasize", cs.datasize);
        try json.boolean(js, "available", false);
        try js.objectField("reason");
        try js.write("not implemented");
        try js.endObject();
    } else {
        try js.objectField("code_signature");
        try js.beginObject();
        try json.boolean(js, "present", false);
        try js.endObject();
    }
    const verdict = try an.security();
    if (verdict.available) {
        try js.objectField("security");
        try js.beginObject();
        try json.boolean(js, "available", true);
        try js.objectField("trust");
        try js.write(@tagName(verdict.trust));
        try json.int(js, "status", verdict.validity_status);
        try js.objectField("status_name");
        try js.write(verdict.validity_status_name);
        try json.boolean(js, "notarized", verdict.requirement_results.notarized == 0);
        try js.endObject();
    } else try json.unavailable(js, "security", verdict.reason orelse "unavailable");
    try js.objectField("encryption");
    if (f.encryption) |ei| {
        try js.beginObject();
        try json.int(js, "cryptoff", ei.cryptoff);
        try json.int(js, "cryptsize", ei.cryptsize);
        try json.int(js, "cryptid", ei.cryptid);
        try js.endObject();
    } else try js.write(null);
    try js.endObject();
}

fn writeDylibJson(js: *std.json.Stringify, a: std.mem.Allocator, d: loadcmds.Dylib) !void {
    var nb: [32]u8 = undefined;
    try js.beginObject();
    try json.int(js, "ordinal", d.ordinal);
    try js.objectField("cmd");
    try js.write(version.lcNameBuf(&nb, d.cmd));
    try json.str(js, a, "path", d.name);
    try json.str(js, a, "short_name", version.dylibShortName(d.name));
    try js.objectField("current_version");
    try js.print("\"{f}\"", .{fmt.Version{ .v = d.current_version }});
    try js.objectField("compatibility_version");
    try js.print("\"{f}\"", .{fmt.Version{ .v = d.compat_version }});
    try json.int(js, "timestamp", d.timestamp);
    try json.boolean(js, "weak", d.weak);
    try json.boolean(js, "reexport", d.reexport);
    try json.boolean(js, "upward", d.upward);
    try json.boolean(js, "delayed_init", d.delayed_init);
    try js.endObject();
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        const f = try collect(ctx, img);
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
        defer an.deinit();
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try writeJson(ctx, img, f, &an);
            try json.endArch(&ctx.sink.json);
        } else {
            var buf: [32]u8 = undefined;
            if (multi) try text.archBanner(ctx.sink.out, ctx.display_path, img.arch.displayName(&buf), true);
            try writeText(ctx, img, f, &an);
        }
    }
    return 0;
}

test "info: §5.4 signature and trust spellings" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualStrings("ad hoc, linker-signed", try signingFlagText(a, 0x20002));
    try std.testing.expectEqualStrings("ad hoc", try signingFlagText(a, 0x2));
    try std.testing.expectEqualStrings("runtime", try signingFlagText(a, 0x10000));
    try std.testing.expectEqualStrings("signed", try signingFlagText(a, 0));
    const Trust = @import("../darwin/security.zig").Trust;
    try std.testing.expectEqualStrings("ad hoc", trustText(Trust.adhoc));
    try std.testing.expectEqualStrings("Developer ID, notarized", trustText(Trust.developer_id_notarized));
    try std.testing.expectEqualStrings("platform", trustText(Trust.platform));
    try std.testing.expectEqualStrings("unsigned", trustText(Trust.unsigned));
    try std.testing.expectEqualStrings("valid", validityWord(0, Trust.adhoc));
    try std.testing.expectEqualStrings("unsigned", validityWord(-67062, Trust.unsigned));
    try std.testing.expectEqualStrings("revoked", validityWord(-66992, Trust.revoked));
    try std.testing.expectEqualStrings("invalid", validityWord(-67061, Trust.invalid));
    // Every rung must have a spelling (a new Trust member would fail to compile here).
    inline for (@typeInfo(Trust).@"enum".field_names) |n| try std.testing.expect(trustText(@field(Trust, n)).len > 0);
}

test "info: file(1)-style description per filetype" {
    var buf: [96]u8 = undefined;
    var img: Image = undefined;
    img.hdr = .{ .magic = std.macho.MH_MAGIC_64, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = 2, .ncmds = 0, .sizeofcmds = 0, .flags = 0, .header_size = 32 };
    img.arch = @import("../core/arch.zig").Arch.fromCpu(0x0100000c, 0);
    try std.testing.expectEqualStrings("Mach-O 64-bit executable arm64", fileDescription(&buf, &img));
    img.hdr.filetype = 6;
    try std.testing.expectEqualStrings("Mach-O 64-bit dynamically linked shared library arm64", fileDescription(&buf, &img));
    img.hdr.filetype = 99;
    try std.testing.expectEqualStrings("Mach-O 64-bit unknown filetype arm64", fileDescription(&buf, &img));
    img.hdr.is_64 = false;
    img.hdr.filetype = 1;
    try std.testing.expectEqualStrings("Mach-O object arm64", fileDescription(&buf, &img));
}
