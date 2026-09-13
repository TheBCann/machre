//! cmd/loadcmds.zig — every load command decoded, otool -l layout, unknown commands hex-dumped. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const macho = std.macho;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const fmt = @import("../core/fmt.zig");
const version = @import("../core/version.zig");
const loadcmds = @import("../core/loadcmds.zig");
const LoadCmd = loadcmds.LoadCmd;
const Image = @import("../core/image.zig").Image;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const entropy_mod = @import("../analysis/entropy.zig");
const Sink = @import("../output/sink.zig").Sink;
const header_cmd = @import("header.zig");

pub const command: Command = .{
    .name = "loadcmds",
    .summary = "every load command decoded, otool -l layout, unknown commands hex-dumped",
    .run = run,
    .flags = &.{"--raw"},
    .aliases = &.{"headers"},
    .needs_macho = true,
};

const past_eof = " (past end of file)";

/// otool's dylib time stamp: `ctime()` in the local time zone when libc is linked, UTC otherwise.
fn writeCtime(out: *Io.Writer, ts: u32) Io.Writer.Error!void {
    if (builtin.link_libc and builtin.os.tag == .macos) {
        var buf: [32]u8 = undefined;
        const t: c_long = ts;
        if (ctime_r(&t, &buf)) |p| {
            const s = std.mem.sliceTo(p, 0);
            try out.writeAll(std.mem.trimEnd(u8, s, "\n"));
            return;
        }
    }
    const es = std.time.epoch.EpochSeconds{ .secs = ts };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    const days = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    try out.print("{s} {s} {d:>2} {d:0>2}:{d:0>2}:{d:0>2} {d}", .{ days[(ts / 86400) % 7], months[md.month.numeric() - 1], @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), yd.year });
}
extern "c" fn ctime_r(clock: *const c_long, buf: [*]u8) ?[*:0]u8;

fn pastEof(out: *Io.Writer, off: u64, size: u64, object_size: u64) Io.Writer.Error!void {
    const end = std.math.add(u64, off, size) catch std.math.maxInt(u64);
    if (end > object_size) try out.writeAll(past_eof);
    try out.writeByte('\n');
}

/// One load command in `otool -l` layout.
pub fn writeCmdText(snk: *Sink, img: *const Image, c: LoadCmd, nsyms: u32, raw: bool, diags: *Diagnostics) anyerror!void {
    const out = snk.out;
    const osz = img.r.len();
    var nb: [32]u8 = undefined;
    const r = c.reader();
    const e = c.endian;
    switch (c.lc()) {
        .SEGMENT_64, .SEGMENT => {
            const is_64 = c.lc() == .SEGMENT_64;
            const seg_size: u32 = if (is_64) 72 else 56;
            const sect_size: u32 = if (is_64) 80 else 68;
            try out.print("      cmd {s}\n  cmdsize {d}", .{ c.name(&nb), c.cmdsize });
            const nsects: u64 = if (c.bytes.len >= seg_size) (if (is_64) r.u32At(64, e).? else r.u32At(48, e).?) else 0;
            const expect = std.math.add(u64, seg_size, std.math.mul(u64, nsects, sect_size) catch std.math.maxInt(u64)) catch std.math.maxInt(u64);
            if (c.cmdsize != expect) try out.writeAll(" Incorrect size");
            try out.writeByte('\n');
            if (c.bytes.len < seg_size) return;
            try out.print("  segname {s}\n", .{try snk.safe(r.nameAt(8, 16).?)});
            if (is_64) {
                try out.print("   vmaddr 0x{x:0>16}\n   vmsize 0x{x:0>16}\n", .{ r.u64At(24, e).?, r.u64At(32, e).? });
                const fileoff = r.u64At(40, e).?;
                const filesize = r.u64At(48, e).?;
                try out.print("  fileoff {d}", .{fileoff});
                if (fileoff > osz) try out.writeAll(past_eof);
                try out.print("\n filesize {d}", .{filesize});
                try pastEof(out, fileoff, filesize, osz);
                try out.print("  maxprot 0x{x:0>8}\n initprot 0x{x:0>8}\n   nsects {d}\n    flags 0x{x}\n", .{ r.u32At(56, e).?, r.u32At(60, e).?, nsects, r.u32At(68, e).? });
            } else {
                try out.print("   vmaddr 0x{x:0>8}\n   vmsize 0x{x:0>8}\n", .{ r.u32At(24, e).?, r.u32At(28, e).? });
                const fileoff = r.u32At(32, e).?;
                const filesize = r.u32At(36, e).?;
                try out.print("  fileoff {d}", .{fileoff});
                if (fileoff > osz) try out.writeAll(past_eof);
                try out.print("\n filesize {d}", .{filesize});
                try pastEof(out, fileoff, filesize, osz);
                try out.print("  maxprot 0x{x:0>8}\n initprot 0x{x:0>8}\n   nsects {d}\n    flags 0x{x}\n", .{ r.u32At(40, e).?, r.u32At(44, e).?, nsects, r.u32At(52, e).? });
            }
            const fit: u64 = (c.bytes.len - seg_size) / sect_size;
            const n = @min(nsects, fit);
            var i: u64 = 0;
            while (i < n) : (i += 1) {
                const o = seg_size + i * sect_size;
                try out.writeAll("Section\n");
                try out.print("  sectname {s}\n   segname {s}\n", .{ try snk.safe(r.nameAt(o, 16).?), try snk.safe(r.nameAt(o + 16, 16).?) });
                var addr: u64 = undefined;
                var size: u64 = undefined;
                var fo: u64 = undefined;
                var flags: u32 = undefined;
                var res1: u32 = undefined;
                var res2: u32 = undefined;
                if (is_64) {
                    addr = r.u64At(o + 32, e).?;
                    size = r.u64At(o + 40, e).?;
                    try out.print("      addr 0x{x:0>16}\n      size 0x{x:0>16}", .{ addr, size });
                    fo = r.u32At(o + 48, e).?;
                    try pastEof(out, fo, size, osz);
                    try out.print("    offset {d}", .{fo});
                    if (fo > osz) try out.writeAll(past_eof);
                    const al = r.u32At(o + 52, e).?;
                    try out.print("\n     align 2^{d} ({d})\n    reloff {d}\n    nreloc {d}\n", .{ al, @as(u64, 1) << @intCast(@min(al, 63)), r.u32At(o + 56, e).?, r.u32At(o + 60, e).? });
                    flags = r.u32At(o + 64, e).?;
                    res1 = r.u32At(o + 68, e).?;
                    res2 = r.u32At(o + 72, e).?;
                } else {
                    addr = r.u32At(o + 32, e).?;
                    size = r.u32At(o + 36, e).?;
                    try out.print("      addr 0x{x:0>8}\n      size 0x{x:0>8}", .{ addr, size });
                    fo = r.u32At(o + 40, e).?;
                    try pastEof(out, fo, size, osz);
                    try out.print("    offset {d}", .{fo});
                    if (fo > osz) try out.writeAll(past_eof);
                    const al = r.u32At(o + 44, e).?;
                    try out.print("\n     align 2^{d} ({d})\n    reloff {d}\n    nreloc {d}\n", .{ al, @as(u64, 1) << @intCast(@min(al, 63)), r.u32At(o + 48, e).?, r.u32At(o + 52, e).? });
                    flags = r.u32At(o + 56, e).?;
                    res1 = r.u32At(o + 60, e).?;
                    res2 = r.u32At(o + 64, e).?;
                }
                try out.print("     flags 0x{x:0>8}\n", .{flags});
                const st: u8 = @truncate(flags & 0xff);
                switch (st) {
                    macho.S_SYMBOL_STUBS => try out.print(" reserved1 {d} (index into indirect symbol table)\n reserved2 {d} (size of stubs)\n", .{ res1, res2 }),
                    macho.S_LAZY_SYMBOL_POINTERS, macho.S_NON_LAZY_SYMBOL_POINTERS, 0x10, 0x14 => try out.print(" reserved1 {d} (index into indirect symbol table)\n reserved2 {d}\n", .{ res1, res2 }),
                    else => try out.print(" reserved1 {d}\n reserved2 {d}\n", .{ res1, res2 }),
                }
            }
        },
        .SYMTAB => {
            try out.print("     cmd LC_SYMTAB\n cmdsize {d}{s}\n", .{ c.cmdsize, if (c.cmdsize != 24) " Incorrect size" else "" });
            const st = loadcmds.decodeSymtab(c) orelse return;
            try out.print("  symoff {d}", .{st.symoff});
            if (st.symoff > osz) try out.writeAll(past_eof);
            try out.print("\n   nsyms {d}", .{st.nsyms});
            try pastEof(out, st.symoff, std.math.mul(u64, st.nsyms, if (img.hdr.is_64) 16 else 12) catch std.math.maxInt(u64), osz);
            try out.print("  stroff {d}", .{st.stroff});
            if (st.stroff > osz) try out.writeAll(past_eof);
            try out.print("\n strsize {d}", .{st.strsize});
            try pastEof(out, st.stroff, st.strsize, osz);
        },
        .DYSYMTAB => {
            try out.print("            cmd LC_DYSYMTAB\n        cmdsize {d}{s}\n", .{ c.cmdsize, if (c.cmdsize != 80) " Incorrect size" else "" });
            const d = loadcmds.decodeDysymtab(c) orelse return;
            const runs = [_]struct { i: u32, n: u32, il: []const u8, nl: []const u8 }{
                .{ .i = d.ilocalsym, .n = d.nlocalsym, .il = "      ilocalsym ", .nl = "      nlocalsym " },
                .{ .i = d.iextdefsym, .n = d.nextdefsym, .il = "     iextdefsym ", .nl = "     nextdefsym " },
                .{ .i = d.iundefsym, .n = d.nundefsym, .il = "      iundefsym ", .nl = "      nundefsym " },
            };
            for (runs) |ru| {
                try out.print("{s}{d}", .{ ru.il, ru.i });
                if (ru.i > nsyms) try out.writeAll(" (greater than the number of symbols)");
                try out.print("\n{s}{d}", .{ ru.nl, ru.n });
                const end = std.math.add(u64, ru.i, ru.n) catch std.math.maxInt(u64);
                if (end > nsyms) try out.writeAll(" (past the end of the symbol table)");
                try out.writeByte('\n');
            }
            const tabs = [_]struct { off: u32, n: u32, esz: u64, ol: []const u8, nl: []const u8 }{
                .{ .off = d.tocoff, .n = d.ntoc, .esz = 8, .ol = "         tocoff ", .nl = "           ntoc " },
                .{ .off = d.modtaboff, .n = d.nmodtab, .esz = if (img.hdr.is_64) 56 else 52, .ol = "      modtaboff ", .nl = "        nmodtab " },
                .{ .off = d.extrefsymoff, .n = d.nextrefsyms, .esz = 4, .ol = "   extrefsymoff ", .nl = "    nextrefsyms " },
                .{ .off = d.indirectsymoff, .n = d.nindirectsyms, .esz = 4, .ol = " indirectsymoff ", .nl = "  nindirectsyms " },
                .{ .off = d.extreloff, .n = d.nextrel, .esz = 8, .ol = "      extreloff ", .nl = "        nextrel " },
                .{ .off = d.locreloff, .n = d.nlocrel, .esz = 8, .ol = "      locreloff ", .nl = "        nlocrel " },
            };
            for (tabs) |t| {
                try out.print("{s}{d}", .{ t.ol, t.off });
                if (t.off > osz) try out.writeAll(past_eof);
                try out.print("\n{s}{d}", .{ t.nl, t.n });
                try pastEof(out, t.off, std.math.mul(u64, t.n, t.esz) catch std.math.maxInt(u64), osz);
            }
        },
        .LOAD_DYLIB, .ID_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB, .LOAD_UPWARD_DYLIB, .LAZY_LOAD_DYLIB => {
            try out.print("          cmd {s}\n      cmdsize {d}\n", .{ c.name(&nb), c.cmdsize });
            const dl = (try loadcmds.decodeDylib(undefined, c, 0, diags)) orelse return;
            const name_off = r.u32At(8, e).?;
            if (name_off >= c.cmdsize) try out.print("         name ?(bad offset {d})\n", .{name_off}) else try out.print("         name {s} (offset {d})\n", .{ try snk.safe(dl.name), name_off });
            if (dl.use_command) {
                try out.print("   time stamp use_command (flags 0x{x})\n", .{dl.flags});
            } else {
                try out.print("   time stamp {d} ", .{dl.timestamp});
                try writeCtime(out, dl.timestamp);
                try out.writeByte('\n');
            }
            try out.print("      current version {f}\ncompatibility version {f}\n", .{ fmt.Version{ .v = dl.current_version }, fmt.Version{ .v = dl.compat_version } });
        },
        .LOAD_DYLINKER, .ID_DYLINKER, .DYLD_ENVIRONMENT => {
            try out.print("          cmd {s}\n      cmdsize {d}\n", .{ c.name(&nb), c.cmdsize });
            try writeLcStr(snk, c, "         name ", diags);
        },
        .RPATH => {
            try out.print("          cmd LC_RPATH\n      cmdsize {d}\n", .{c.cmdsize});
            try writeLcStr(snk, c, "         path ", diags);
        },
        .SUB_FRAMEWORK => {
            try out.print("      cmd LC_SUB_FRAMEWORK\n  cmdsize {d}\n", .{c.cmdsize});
            try writeLcStr(snk, c, " umbrella ", diags);
        },
        .SUB_UMBRELLA => {
            try out.print("          cmd LC_SUB_UMBRELLA\n      cmdsize {d}\n", .{c.cmdsize});
            try writeLcStr(snk, c, " sub_umbrella ", diags);
        },
        .SUB_LIBRARY => {
            try out.print("         cmd LC_SUB_LIBRARY\n     cmdsize {d}\n", .{c.cmdsize});
            try writeLcStr(snk, c, " sub_library ", diags);
        },
        .SUB_CLIENT => {
            try out.print("      cmd LC_SUB_CLIENT\n  cmdsize {d}\n", .{c.cmdsize});
            try writeLcStr(snk, c, "   client ", diags);
        },
        .UUID => {
            try out.print("     cmd LC_UUID\n cmdsize {d}{s}\n", .{ c.cmdsize, if (c.cmdsize != 24) " Incorrect size" else "" });
            if (loadcmds.decodeUuid(c)) |u| try out.print("    uuid {f}\n", .{fmt.Uuid{ .bytes = u }});
        },
        .BUILD_VERSION => {
            try out.print("      cmd LC_BUILD_VERSION\n  cmdsize {d}", .{c.cmdsize});
            const bv = (try loadcmds.decodeBuildVersion(std.heap.page_allocator, c, undefined, diags)) orelse {
                try out.writeAll(" Incorrect size\n");
                return;
            };
            defer std.heap.page_allocator.free(bv.tools);
            if (c.cmdsize != 24 + bv.ntools_declared * 8) try out.writeAll(" Incorrect size");
            try out.print("\n platform {d}\n    minos {f}\n      sdk ", .{ bv.platform, fmt.VersionShort{ .v = bv.minos } });
            if (bv.sdk == 0) try out.writeAll("n/a\n") else try out.print("{f}\n", .{fmt.VersionShort{ .v = bv.sdk }});
            try out.print("   ntools {d}\n", .{bv.ntools_declared});
            for (bv.tools) |t| try out.print("     tool {d}\n  version {f}\n", .{ t.tool, fmt.VersionShort{ .v = t.version } });
        },
        .VERSION_MIN_MACOSX, .VERSION_MIN_IPHONEOS, .VERSION_MIN_TVOS, .VERSION_MIN_WATCHOS => {
            try out.print("      cmd {s}\n  cmdsize {d}{s}\n", .{ c.name(&nb), c.cmdsize, if (c.cmdsize != 16) " Incorrect size" else "" });
            const vm = loadcmds.decodeVersionMin(c) orelse return;
            try out.print("  version {f}\n      sdk ", .{fmt.VersionShort{ .v = vm.version }});
            if (vm.sdk == 0) try out.writeAll("n/a\n") else try out.print("{f}\n", .{fmt.VersionShort{ .v = vm.sdk }});
        },
        .SOURCE_VERSION => {
            try out.print("      cmd LC_SOURCE_VERSION\n  cmdsize {d}{s}\n", .{ c.cmdsize, if (c.cmdsize != 16) " Incorrect size" else "" });
            if (loadcmds.decodeSourceVersion(c)) |v| try out.print("  version {f}\n", .{fmt.SourceVersion{ .v = v }});
        },
        .MAIN => {
            try out.print("       cmd LC_MAIN\n   cmdsize {d}{s}\n", .{ c.cmdsize, if (c.cmdsize != 24) " Incorrect size" else "" });
            switch (loadcmds.decodeEntry(c, img.hdr.is_64, diags)) {
                .main => |m| try out.print("  entryoff {d}\n stacksize {d}\n", .{ m.entryoff, m.stacksize }),
                else => {},
            }
        },
        .UNIXTHREAD, .THREAD => {
            try out.print("        cmd {s}\n    cmdsize {d}\n", .{ c.name(&nb), c.cmdsize });
            switch (loadcmds.decodeEntry(c, img.hdr.is_64, diags)) {
                .unixthread => |t| {
                    try out.print("     flavor {d}\n      count {d}\n", .{ t.flavor, t.count });
                    if (t.pc) |pc| try out.print("         pc 0x{x:0>16}\n", .{pc});
                },
                else => {},
            }
        },
        .CODE_SIGNATURE, .SEGMENT_SPLIT_INFO, .FUNCTION_STARTS, .DATA_IN_CODE, .DYLIB_CODE_SIGN_DRS, .LINKER_OPTIMIZATION_HINT, .DYLD_EXPORTS_TRIE, .DYLD_CHAINED_FIXUPS => {
            try out.print("      cmd {s}\n  cmdsize {d}{s}\n", .{ c.name(&nb), c.cmdsize, if (c.cmdsize != 16) " Incorrect size" else "" });
            const ld = loadcmds.decodeLinkeditData(c) orelse return;
            try out.print("  dataoff {d}", .{ld.dataoff});
            if (ld.dataoff > osz) try out.writeAll(past_eof);
            try out.print("\n datasize {d}", .{ld.datasize});
            try pastEof(out, ld.dataoff, ld.datasize, osz);
        },
        .DYLD_INFO, .DYLD_INFO_ONLY => {
            try out.print("            cmd {s}\n        cmdsize {d}{s}\n", .{ c.name(&nb), c.cmdsize, if (c.cmdsize != 48) " Incorrect size" else "" });
            const di = loadcmds.decodeDyldInfo(c) orelse return;
            const parts = [_]struct { off: u32, size: u32, ol: []const u8, sl: []const u8 }{
                .{ .off = di.rebase_off, .size = di.rebase_size, .ol = "     rebase_off ", .sl = "    rebase_size " },
                .{ .off = di.bind_off, .size = di.bind_size, .ol = "       bind_off ", .sl = "      bind_size " },
                .{ .off = di.weak_bind_off, .size = di.weak_bind_size, .ol = "  weak_bind_off ", .sl = " weak_bind_size " },
                .{ .off = di.lazy_bind_off, .size = di.lazy_bind_size, .ol = "  lazy_bind_off ", .sl = " lazy_bind_size " },
                .{ .off = di.export_off, .size = di.export_size, .ol = "     export_off ", .sl = "    export_size " },
            };
            for (parts) |p| {
                try out.print("{s}{d}", .{ p.ol, p.off });
                if (p.off > osz) try out.writeAll(past_eof);
                try out.print("\n{s}{d}", .{ p.sl, p.size });
                try pastEof(out, p.off, p.size, osz);
            }
        },
        .ENCRYPTION_INFO, .ENCRYPTION_INFO_64 => {
            try out.print("          cmd {s}\n      cmdsize {d}\n", .{ c.name(&nb), c.cmdsize });
            const ei = loadcmds.decodeEncryptionInfo(c) orelse return;
            try out.print("     cryptoff {d}\n    cryptsize {d}\n      cryptid {d}\n", .{ ei.cryptoff, ei.cryptsize, ei.cryptid });
            if (c.lc() == .ENCRYPTION_INFO_64 and c.bytes.len >= 24) try out.print("          pad {d}\n", .{r.u32At(20, e).?});
        },
        .LINKER_OPTION => {
            try out.print("     cmd LC_LINKER_OPTION\n cmdsize {d}\n", .{c.cmdsize});
            const count = r.u32At(8, e) orelse return;
            try out.print("   count {d}\n", .{count});
            const strs = try loadcmds.decodeLinkerOptions(std.heap.page_allocator, c, diags);
            defer std.heap.page_allocator.free(strs);
            for (strs, 1..) |s, i| try out.print("  string #{d} {s}\n", .{ i, try snk.safe(s) });
        },
        .NOTE => {
            try out.print("       cmd LC_NOTE\n   cmdsize {d}\n", .{c.cmdsize});
            const n = loadcmds.decodeNote(c) orelse return;
            try out.print("data_owner {s}\n    offset {d}\n      size {d}\n", .{ try snk.safe(n.data_owner), n.offset, n.size });
        },
        .ROUTINES_64, .ROUTINES => {
            try out.print("          cmd {s}\n      cmdsize {d}\n", .{ c.name(&nb), c.cmdsize });
            if (c.lc() == .ROUTINES_64) {
                if (c.bytes.len >= 24) try out.print(" init_address 0x{x:0>16}\n  init_module {d}\n", .{ r.u64At(8, e).?, r.u64At(16, e).? });
            } else if (c.bytes.len >= 16) try out.print(" init_address 0x{x:0>8}\n  init_module {d}\n", .{ r.u32At(8, e).?, r.u32At(12, e).? });
        },
        .PREBIND_CKSUM => {
            try out.print("     cmd LC_PREBIND_CKSUM\n cmdsize {d}\n", .{c.cmdsize});
            if (r.u32At(8, e)) |ck| try out.print("   cksum {d}\n", .{ck});
        },
        .TWOLEVEL_HINTS => {
            try out.print("     cmd LC_TWOLEVEL_HINTS\n cmdsize {d}\n", .{c.cmdsize});
            if (c.bytes.len >= 16) try out.print("  offset {d}\n  nhints {d}\n", .{ r.u32At(8, e).?, r.u32At(12, e).? });
        },
        else => {
            if (c.cmd == loadcmds.extra.LC_FILESET_ENTRY) {
                try out.print("      cmd LC_FILESET_ENTRY\n  cmdsize {d}\n", .{c.cmdsize});
                if (loadcmds.decodeFilesetEntry(c, diags)) |fe| try out.print("   vmaddr 0x{x:0>16}\n  fileoff {d}\n entry_id {s}\n", .{ fe.vmaddr, fe.fileoff, try snk.safe(fe.entry_id) });
            } else if (c.cmd == loadcmds.extra.LC_TARGET_TRIPLE) {
                try out.print("      cmd LC_TARGET_TRIPLE\n  cmdsize {d}\n", .{c.cmdsize});
                try writeLcStr(snk, c, "   triple ", diags);
            } else if (version.lcName(c.cmd)) |n| {
                try out.print("      cmd {s}\n  cmdsize {d}\n", .{ n, c.cmdsize });
                try text.hexdump(out, c.bytes, c.offset, 0);
            } else {
                try out.print("     cmd ?(0x{x:0>8}) Unknown load command\n cmdsize {d}\n", .{ c.cmd, c.cmdsize });
                try text.hexdump(out, c.bytes, c.offset, 0);
            }
        },
    }
    if (raw) try text.hexdump(out, c.bytes, c.offset, 0);
}

fn writeLcStr(snk: *Sink, c: LoadCmd, label: []const u8, diags: *Diagnostics) anyerror!void {
    const out = snk.out;
    const off = c.reader().u32At(8, c.endian) orelse return;
    if (off >= c.cmdsize) {
        try out.print("{s}?(bad offset {d})\n", .{ label, off });
        return;
    }
    const s = loadcmds.decodeLcStr(c, 8, diags) orelse return;
    try out.print("{s}{s} (offset {d})\n", .{ label, try snk.safe(s.text), off });
}

/// JSON object for one load command (typed fields per LC).
pub fn writeCmdJson(js: *std.json.Stringify, arena: std.mem.Allocator, img: *const Image, c: LoadCmd, raw: bool, diags: *Diagnostics) anyerror!void {
    var nb: [32]u8 = undefined;
    const r = c.reader();
    const e = c.endian;
    try js.beginObject();
    try json.int(js, "index", c.index);
    try js.objectField("cmd");
    try js.write(c.name(&nb));
    try json.hex(js, "cmd_value", c.cmd);
    try json.int(js, "cmdsize", c.cmdsize);
    try json.int(js, "offset", c.offset);
    try json.boolean(js, "requires_dyld", c.requiresDyld());
    switch (c.lc()) {
        .SEGMENT_64, .SEGMENT => {
            for (img.segments) |seg| if (seg.cmd_offset == c.offset) {
                try writeSegmentJson(js, arena, img, seg, null);
                break;
            };
        },
        .SYMTAB => if (loadcmds.decodeSymtab(c)) |st| {
            try json.int(js, "symoff", st.symoff);
            try json.int(js, "nsyms", st.nsyms);
            try json.int(js, "stroff", st.stroff);
            try json.int(js, "strsize", st.strsize);
        },
        .DYSYMTAB => if (loadcmds.decodeDysymtab(c)) |d| {
            inline for (.{ "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel" }) |f| {
                try json.int(js, f, @field(d, f));
            }
        },
        .LOAD_DYLIB, .ID_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB, .LOAD_UPWARD_DYLIB, .LAZY_LOAD_DYLIB => if (try loadcmds.decodeDylib(arena, c, 0, diags)) |dl| {
            try json.str(js, arena, "name", dl.name);
            try json.int(js, "timestamp", dl.timestamp);
            try js.objectField("current_version");
            try js.print("\"{f}\"", .{fmt.Version{ .v = dl.current_version }});
            try js.objectField("compatibility_version");
            try js.print("\"{f}\"", .{fmt.Version{ .v = dl.compat_version }});
            try json.boolean(js, "weak", dl.weak);
            try json.boolean(js, "reexport", dl.reexport);
            try json.boolean(js, "upward", dl.upward);
            try json.boolean(js, "delayed_init", dl.delayed_init);
            try json.boolean(js, "use_command", dl.use_command);
        },
        .LOAD_DYLINKER, .ID_DYLINKER, .DYLD_ENVIRONMENT, .RPATH, .SUB_FRAMEWORK, .SUB_UMBRELLA, .SUB_LIBRARY, .SUB_CLIENT => if (loadcmds.decodeLcStr(c, 8, diags)) |s| {
            try json.str(js, arena, "string", s.text);
            try json.boolean(js, "terminated", s.terminated);
        },
        .UUID => if (loadcmds.decodeUuid(c)) |u| try json.uuid(js, "uuid", u),
        .BUILD_VERSION => if (try loadcmds.decodeBuildVersion(arena, c, undefined, diags)) |bv| {
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
        },
        .VERSION_MIN_MACOSX, .VERSION_MIN_IPHONEOS, .VERSION_MIN_TVOS, .VERSION_MIN_WATCHOS => if (loadcmds.decodeVersionMin(c)) |vm| {
            try js.objectField("version");
            try js.print("\"{f}\"", .{fmt.VersionShort{ .v = vm.version }});
            try js.objectField("sdk");
            try js.print("\"{f}\"", .{fmt.VersionShort{ .v = vm.sdk }});
        },
        .SOURCE_VERSION => if (loadcmds.decodeSourceVersion(c)) |v| {
            try js.objectField("version");
            try js.print("\"{f}\"", .{fmt.SourceVersion{ .v = v }});
        },
        .MAIN => switch (loadcmds.decodeEntry(c, img.hdr.is_64, diags)) {
            .main => |m| {
                try json.hex(js, "entryoff", m.entryoff);
                try json.int(js, "stacksize", m.stacksize);
            },
            else => {},
        },
        .UNIXTHREAD, .THREAD => switch (loadcmds.decodeEntry(c, img.hdr.is_64, diags)) {
            .unixthread => |t| {
                try json.int(js, "flavor", t.flavor);
                try json.int(js, "count", t.count);
                try json.hexOpt(js, "pc", t.pc);
            },
            else => {},
        },
        .CODE_SIGNATURE, .SEGMENT_SPLIT_INFO, .FUNCTION_STARTS, .DATA_IN_CODE, .DYLIB_CODE_SIGN_DRS, .LINKER_OPTIMIZATION_HINT, .DYLD_EXPORTS_TRIE, .DYLD_CHAINED_FIXUPS => if (loadcmds.decodeLinkeditData(c)) |ld| {
            try json.int(js, "dataoff", ld.dataoff);
            try json.int(js, "datasize", ld.datasize);
        },
        .DYLD_INFO, .DYLD_INFO_ONLY => if (loadcmds.decodeDyldInfo(c)) |di| {
            inline for (.{ "rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off", "weak_bind_size", "lazy_bind_off", "lazy_bind_size", "export_off", "export_size" }) |f| {
                try json.int(js, f, @field(di, f));
            }
        },
        .ENCRYPTION_INFO, .ENCRYPTION_INFO_64 => if (loadcmds.decodeEncryptionInfo(c)) |ei| {
            try json.int(js, "cryptoff", ei.cryptoff);
            try json.int(js, "cryptsize", ei.cryptsize);
            try json.int(js, "cryptid", ei.cryptid);
        },
        .LINKER_OPTION => {
            const strs = try loadcmds.decodeLinkerOptions(arena, c, diags);
            try json.names(js, arena, "strings", strs);
        },
        .NOTE => if (loadcmds.decodeNote(c)) |n| {
            try json.str(js, arena, "data_owner", n.data_owner);
            try json.int(js, "offset", n.offset);
            try json.int(js, "size", n.size);
        },
        else => {
            if (c.cmd == loadcmds.extra.LC_FILESET_ENTRY) {
                if (loadcmds.decodeFilesetEntry(c, diags)) |fe| {
                    try json.hex(js, "vmaddr", fe.vmaddr);
                    try json.int(js, "fileoff", fe.fileoff);
                    try json.str(js, arena, "entry_id", fe.entry_id);
                }
            } else if (c.cmd == loadcmds.extra.LC_TARGET_TRIPLE) {
                if (loadcmds.decodeLcStr(c, 8, diags)) |s| try json.str(js, arena, "triple", s.text);
            } else {
                try json.bytesHex(js, "raw_hex", c.bytes);
            }
        },
    }
    if (raw and c.lc() != .SEGMENT_64 and c.lc() != .SEGMENT) try json.bytesHex(js, "raw_hex", c.bytes);
    _ = r;
    _ = e;
    try js.endObject();
}

/// The entropy report's region for one segment (`sectname == null`) or section, or null when not computed.
pub fn entropyRegion(rep: ?*const entropy_mod.EntropyReport, segname: []const u8, sectname: ?[]const u8) ?entropy_mod.Region {
    const r = rep orelse return null;
    const list = if (sectname == null) r.segments else r.sections;
    for (list) |reg| {
        if (!std.mem.eql(u8, reg.name, segname)) continue;
        if (sectname) |sn| {
            const rs = reg.sectname orelse continue;
            if (!std.mem.eql(u8, rs, sn)) continue;
        } else if (reg.sectname != null) continue;
        return reg;
    }
    return null;
}

/// Segment fields (+ sections[]) inside a load-command or `segments` JSON object. `ent` fills the
/// `entropy`/`file_fraction` members of §6.3; they are `null` when no entropy report was requested.
pub fn writeSegmentJson(js: *std.json.Stringify, arena: std.mem.Allocator, img: *const Image, seg: @import("../core/segments.zig").Segment, ent: ?*const entropy_mod.EntropyReport) anyerror!void {
    try json.str(js, arena, "name", seg.name);
    try json.hex(js, "vmaddr", seg.vmaddr);
    try json.hex(js, "vmsize", seg.vmsize);
    try json.int(js, "fileoff", seg.fileoff);
    try json.int(js, "filesize", seg.filesize);
    try json.int(js, "maxprot", seg.maxprot);
    try json.int(js, "initprot", seg.initprot);
    try json.int(js, "nsects", seg.nsects);
    try json.flags(js, "flags", seg.flags, version.sg_flags);
    try json.boolean(js, "file_range_truncated", seg.file_range_truncated);
    if (entropyRegion(ent, seg.name, null)) |reg| {
        try js.objectField("entropy");
        try js.write(reg.entropy);
        try js.objectField("file_fraction");
        try js.write(reg.file_fraction);
    } else {
        try js.objectField("entropy");
        try js.write(null);
        try js.objectField("file_fraction");
        try js.write(null);
    }
    try js.objectField("sections");
    try js.beginArray();
    const end = @min(img.sections.len, @as(usize, seg.first_section) + seg.section_count);
    for (img.sections[seg.first_section..end]) |s| {
        try js.beginObject();
        try json.int(js, "index", s.index);
        try json.str(js, arena, "sectname", s.sectname);
        try json.str(js, arena, "segname", s.segname);
        try json.hex(js, "addr", s.addr);
        try json.int(js, "size", s.size);
        try json.int(js, "offset", s.offset);
        try json.int(js, "align", s.@"align");
        try json.int(js, "reloff", s.reloff);
        try json.int(js, "nreloc", s.nreloc);
        try js.objectField("flags");
        try js.beginObject();
        try json.hex(js, "value", s.flags);
        try json.int(js, "type", s.sectType());
        try js.objectField("type_name");
        if (version.sectionTypeName(s.sectType())) |n| try js.write(n) else try js.write(null);
        try js.objectField("attrs");
        try js.beginArray();
        for (version.s_attr_flags) |f| if (s.flags & f.bit != 0) try js.write(f.name);
        try js.endArray();
        try js.endObject();
        try json.int(js, "reserved1", s.reserved1);
        try json.int(js, "reserved2", s.reserved2);
        try json.int(js, "reserved3", s.reserved3);
        try js.objectField("class");
        try js.write(@tagName(s.class));
        try js.objectField("entropy");
        if (entropyRegion(ent, s.segname, s.sectname)) |reg| try js.write(reg.entropy) else try js.write(null);
        try js.endObject();
    }
    try js.endArray();
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const raw = ctx.args.flag("--raw");
    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        for (ctx.images) |*img| {
            try json.beginArch(js, img);
            try js.objectField("loadcmds");
            try js.beginObject();
            try json.int(js, "ncmds_parsed", img.ncmds_parsed);
            try json.boolean(js, "truncated", img.cmds_truncated);
            try js.objectField("load_commands");
            try js.beginArray();
            for (img.cmds) |c| try writeCmdJson(js, ctx.arena, img, c, raw, ctx.diags);
            try js.endArray();
            try js.endObject();
            try json.endArch(js);
        }
        return 0;
    }
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var buf: [32]u8 = undefined;
        try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), multi);
        try out.writeAll("Mach header\n");
        try out.writeAll(header_cmd.column_header ++ "\n");
        try header_cmd.writeRawRow(out, img.hdr);
        var nsyms: u32 = 0;
        if (img.findCmd(.SYMTAB)) |sc| if (loadcmds.decodeSymtab(sc)) |st| {
            nsyms = st.nsyms;
        };
        for (img.cmds) |c| {
            try out.print("Load command {d}\n", .{c.index});
            try writeCmdText(ctx.sink, img, c, nsyms, raw, ctx.diags);
        }
        if (img.cmds_truncated and !ctx.otool_compat) try out.print("(load commands truncated after {d} of {d}; see diagnostics)\n", .{ img.ncmds_parsed, img.hdr.ncmds });
    }
    return 0;
}

test "loadcmds: entropy region lookup separates segments from sections" {
    const rep: entropy_mod.EntropyReport = .{
        .file = 6.0,
        .segments = &.{.{ .name = "__TEXT", .sectname = null, .file_offset = 0, .size = 16384, .entropy = 5.5, .file_fraction = 0.3 }},
        .sections = &.{.{ .name = "__TEXT", .sectname = "__text", .file_offset = 1272, .size = 308, .entropy = 6.25, .file_fraction = 0.006 }},
        .tells = &.{},
    };
    try std.testing.expectEqual(@as(f64, 5.5), entropyRegion(&rep, "__TEXT", null).?.entropy);
    try std.testing.expectEqual(@as(f64, 6.25), entropyRegion(&rep, "__TEXT", "__text").?.entropy);
    try std.testing.expect(entropyRegion(&rep, "__TEXT", "__cstring") == null);
    try std.testing.expect(entropyRegion(&rep, "__DATA", null) == null);
    try std.testing.expect(entropyRegion(null, "__TEXT", null) == null);
}

test "loadcmds: past-end-of-file annotation is overflow-safe" {
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try pastEof(&w, 0, 100, 200);
    try std.testing.expectEqualStrings("\n", w.buffered());
    w = .fixed(&buf);
    try pastEof(&w, 150, 100, 200);
    try std.testing.expectEqualStrings(past_eof ++ "\n", w.buffered());
    w = .fixed(&buf);
    try pastEof(&w, std.math.maxInt(u64), std.math.maxInt(u64), 200);
    try std.testing.expectEqualStrings(past_eof ++ "\n", w.buffered());
}
