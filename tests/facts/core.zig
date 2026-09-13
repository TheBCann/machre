//! tests/facts/core.zig — corpus fact tests for WP-core (asserts against truth/summary.json + truth/*.txt sections).
//! WP0: header / load-command / segment / section / dylib / uuid / build_version / entry / symtab facts for every
//! summary.json fixture (17 incl. bin-ls and Hello.app's main executable). WP1 adds entropy/file_fraction.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const Summary = helpers.Summary;
const fmt = machre.core.fmt;
const version = machre.core.version;
const loadcmds = machre.core.loadcmds;

const Ctx = struct {
    arena: std.mem.Allocator,
    diags: *machre.Diagnostics,
    name: []const u8,
    fn fail(c: *const Ctx, comptime what: []const u8, args: anytype) error{FactMismatch} {
        std.debug.print("[{s}] " ++ what ++ "\n", .{c.name} ++ args);
        return error.FactMismatch;
    }
};

fn expectStr(c: *const Ctx, what: []const u8, want: ?[]const u8, got: ?[]const u8) !void {
    const w = want orelse "<null>";
    const g = got orelse "<null>";
    if (!std.mem.eql(u8, w, g)) return c.fail("{s}: expected '{s}', got '{s}'", .{ what, w, g });
}
fn expectInt(c: *const Ctx, what: []const u8, want: ?i64, got: i64) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected {d}, got {d}", .{ what, w, got });
}
fn expectHex(c: *const Ctx, what: []const u8, want: ?u64, got: u64) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected 0x{x}, got 0x{x}", .{ what, w, got });
}
fn fmtStr(arena: std.mem.Allocator, comptime f: []const u8, args: anytype) ![]const u8 {
    return std.fmt.allocPrint(arena, f, args);
}
/// A.B.C.D.E as summary.json spells LC_SOURCE_VERSION.
fn sourceVersion5(arena: std.mem.Allocator, v: u64) ![]const u8 {
    return fmtStr(arena, "{d}.{d}.{d}.{d}.{d}", .{ v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff });
}

fn checkSlice(c: *const Ctx, img: *const machre.Image, sl: std.json.Value) !void {
    const a = c.arena;
    const hdr = img.hdr;
    try expectHex(c, "magic", Summary.hex(sl, "magic"), hdr.magic);
    try expectInt(c, "cputype", Summary.int(sl, "cputype"), hdr.cputype);
    try expectStr(c, "cputype_name", Summary.str(sl, "cputype_name"), img.arch.name.str());
    try expectInt(c, "cpusubtype", Summary.int(sl, "cpusubtype"), hdr.cpusubtype);
    try expectHex(c, "cpusubtype_caps", Summary.hex(sl, "cpusubtype_caps"), img.arch.caps);
    try expectInt(c, "cpusubtype_low", Summary.int(sl, "cpusubtype_low"), img.arch.subtypeLow());
    try expectInt(c, "filetype", Summary.int(sl, "filetype"), hdr.filetype);
    try expectStr(c, "filetype_name", Summary.str(sl, "filetype_name"), version.filetypeName(hdr.filetype));
    try expectInt(c, "ncmds", Summary.int(sl, "ncmds"), hdr.ncmds);
    try expectInt(c, "sizeofcmds", Summary.int(sl, "sizeofcmds"), hdr.sizeofcmds);
    try expectHex(c, "flags", Summary.hex(sl, "flags"), hdr.flags);
    try expectInt(c, "offset_in_file", Summary.int(sl, "offset_in_file"), @intCast(img.slice_offset));
    try expectInt(c, "size", Summary.int(sl, "size"), @intCast(img.r.len()));
    // flag names in summary.json spelling
    const want_flags = try Summary.strings(a, sl, "flags_names");
    var buf: [40][]const u8 = undefined;
    const got_flags = fmt.flagNames(hdr.flags, version.mh_flags_full, &buf);
    if (want_flags.len != got_flags.len) return c.fail("flags_names: {d} vs {d}", .{ want_flags.len, got_flags.len });
    for (want_flags, got_flags) |w, g| try expectStr(c, "flags_names", w, g);
    // load command order
    const want_lcs = try Summary.strings(a, sl, "load_commands");
    if (want_lcs.len != img.cmds.len) return c.fail("load_commands: {d} vs {d} (truncated={})", .{ want_lcs.len, img.cmds.len, img.cmds_truncated });
    for (want_lcs, img.cmds) |w, cmd| try expectStr(c, "load_commands", w, version.lcName(cmd.cmd));
    if (img.cmds_truncated) return c.fail("load commands truncated", .{});
    // segments + sections
    const want_segs = Summary.array(sl, "segments") orelse &.{};
    if (want_segs.len != img.segments.len) return c.fail("segments: {d} vs {d}", .{ want_segs.len, img.segments.len });
    for (want_segs, img.segments) |ws, seg| {
        try expectStr(c, "segment.name", Summary.str(ws, "name"), seg.name);
        try expectHex(c, "segment.vmaddr", Summary.hex(ws, "vmaddr"), seg.vmaddr);
        try expectHex(c, "segment.vmsize", Summary.hex(ws, "vmsize"), seg.vmsize);
        try expectInt(c, "segment.fileoff", Summary.int(ws, "fileoff"), @intCast(seg.fileoff));
        try expectInt(c, "segment.filesize", Summary.int(ws, "filesize"), @intCast(seg.filesize));
        try expectInt(c, "segment.maxprot", Summary.int(ws, "maxprot"), seg.maxprot);
        try expectInt(c, "segment.initprot", Summary.int(ws, "initprot"), seg.initprot);
        try expectInt(c, "segment.nsects", Summary.int(ws, "nsects"), seg.nsects);
        try expectHex(c, "segment.flags", Summary.hex(ws, "flags"), seg.flags);
        const want_sects = Summary.array(ws, "sections") orelse &.{};
        if (want_sects.len != seg.section_count) return c.fail("{s} sections: {d} vs {d}", .{ seg.name, want_sects.len, seg.section_count });
        for (want_sects, img.sections[seg.first_section .. seg.first_section + seg.section_count]) |wsec, sec| {
            try expectStr(c, "section.name", Summary.str(wsec, "name"), sec.sectname);
            try expectStr(c, "section.segname", Summary.str(wsec, "segname"), sec.segname);
            try expectHex(c, "section.addr", Summary.hex(wsec, "addr"), sec.addr);
            try expectInt(c, "section.size", Summary.int(wsec, "size"), @intCast(sec.size));
            try expectInt(c, "section.offset", Summary.int(wsec, "offset"), sec.offset);
            try expectInt(c, "section.align", Summary.int(wsec, "align"), sec.@"align");
            try expectHex(c, "section.flags", Summary.hex(wsec, "flags"), sec.flags);
            try expectInt(c, "section.type", Summary.int(wsec, "type"), sec.sectType());
            if (sec.segment != seg.index) return c.fail("section.segment index", .{});
        }
    }
    // dylibs / id_dylib / rpaths / dylinker / uuid / build_version / version_min / source_version / entry / symtab / dysymtab / linkedit data
    const want_dylibs = Summary.array(sl, "dylibs") orelse &.{};
    var dl_i: usize = 0;
    var ordinal: u16 = 0;
    var rp_i: usize = 0;
    const want_rpaths = try Summary.strings(a, sl, "rpaths");
    var saw_uuid = false;
    var saw_build = false;
    var saw_vmin = false;
    var saw_srcver = false;
    var saw_entry = false;
    var saw_symtab = false;
    var saw_dysymtab = false;
    var saw_fs = false;
    var saw_dic = false;
    var saw_dylinker = false;
    var saw_id = false;
    for (img.cmds) |cmd| {
        if (loadcmds.isDylibLoadCmd(cmd.cmd)) {
            ordinal += 1;
            const d = (try loadcmds.decodeDylib(a, cmd, ordinal, c.diags)) orelse return c.fail("dylib decode", .{});
            if (dl_i >= want_dylibs.len) return c.fail("more dylibs than summary", .{});
            const wd = want_dylibs[dl_i];
            dl_i += 1;
            try expectStr(c, "dylib.cmd", Summary.str(wd, "cmd"), version.lcName(cmd.cmd));
            try expectStr(c, "dylib.path", Summary.str(wd, "path"), d.name);
            try expectInt(c, "dylib.timestamp", Summary.int(wd, "timestamp"), d.timestamp);
            try expectStr(c, "dylib.current_version", Summary.str(wd, "current_version"), try fmtStr(a, "{f}", .{fmt.Version{ .v = d.current_version }}));
            try expectStr(c, "dylib.compatibility_version", Summary.str(wd, "compatibility_version"), try fmtStr(a, "{f}", .{fmt.Version{ .v = d.compat_version }}));
            if (!d.name_terminated) return c.fail("dylib name unterminated", .{});
        }
        switch (cmd.lc()) {
            .ID_DYLIB => {
                saw_id = true;
                const d = (try loadcmds.decodeDylib(a, cmd, 0, c.diags)) orelse return c.fail("id_dylib decode", .{});
                const wd = Summary.object(sl, "id_dylib") orelse return c.fail("id_dylib missing in summary", .{});
                try expectStr(c, "id_dylib.path", Summary.str(wd, "path"), d.name);
                try expectStr(c, "id_dylib.current_version", Summary.str(wd, "current_version"), try fmtStr(a, "{f}", .{fmt.Version{ .v = d.current_version }}));
                try expectInt(c, "id_dylib.timestamp", Summary.int(wd, "timestamp"), d.timestamp);
            },
            .RPATH => {
                const s = loadcmds.decodeLcStr(cmd, 8, c.diags) orelse return c.fail("rpath decode", .{});
                if (rp_i >= want_rpaths.len) return c.fail("more rpaths than summary", .{});
                try expectStr(c, "rpath", want_rpaths[rp_i], s.text);
                rp_i += 1;
            },
            .LOAD_DYLINKER => {
                saw_dylinker = true;
                const s = loadcmds.decodeLcStr(cmd, 8, c.diags) orelse return c.fail("dylinker decode", .{});
                try expectStr(c, "dylinker", Summary.str(sl, "dylinker"), s.text);
            },
            .UUID => {
                saw_uuid = true;
                const u = loadcmds.decodeUuid(cmd) orelse return c.fail("uuid decode", .{});
                try expectStr(c, "uuid", Summary.str(sl, "uuid"), try fmtStr(a, "{f}", .{fmt.Uuid{ .bytes = u }}));
            },
            .BUILD_VERSION => {
                saw_build = true;
                const bv = (try loadcmds.decodeBuildVersion(a, cmd, &machre.Limits.default, c.diags)) orelse return c.fail("build_version decode", .{});
                const wb = Summary.object(sl, "build_version") orelse return c.fail("build_version missing in summary", .{});
                try expectInt(c, "build_version.platform", Summary.int(wb, "platform"), bv.platform);
                try expectStr(c, "build_version.platform_name", Summary.str(wb, "platform_name"), version.platformName(bv.platform));
                try expectStr(c, "build_version.minos", Summary.str(wb, "minos"), try fmtStr(a, "{f}", .{fmt.VersionShort{ .v = bv.minos }}));
                try expectStr(c, "build_version.sdk", Summary.str(wb, "sdk"), try fmtStr(a, "{f}", .{fmt.VersionShort{ .v = bv.sdk }}));
                const wt = Summary.array(wb, "tools") orelse &.{};
                if (wt.len != bv.tools.len or bv.ntools_declared != bv.tools.len) return c.fail("build_version.tools count", .{});
                for (wt, bv.tools) |w, t| {
                    const wname = Summary.str(w, "tool") orelse "";
                    if (version.toolName(t.tool)) |n| {
                        try expectStr(c, "tool", wname, n);
                    } else if (!std.mem.startsWith(u8, wname, "zig(5")) return c.fail("unknown tool id {d} spelled '{s}'", .{ t.tool, wname });
                    try expectStr(c, "tool.version", Summary.str(w, "version"), try fmtStr(a, "{f}", .{fmt.Version{ .v = t.version }}));
                }
            },
            .VERSION_MIN_MACOSX, .VERSION_MIN_IPHONEOS, .VERSION_MIN_TVOS, .VERSION_MIN_WATCHOS => saw_vmin = true,
            .SOURCE_VERSION => {
                saw_srcver = true;
                const sv = loadcmds.decodeSourceVersion(cmd) orelse return c.fail("source_version decode", .{});
                try expectStr(c, "source_version", Summary.str(sl, "source_version"), try sourceVersion5(a, sv));
            },
            .MAIN => {
                saw_entry = true;
                const e = loadcmds.decodeEntry(cmd, img.hdr.is_64, c.diags);
                const we = Summary.object(sl, "entry_point") orelse return c.fail("entry_point missing in summary", .{});
                try expectInt(c, "entry_point.entryoff", Summary.int(we, "entryoff"), @intCast(e.main.entryoff));
                try expectInt(c, "entry_point.stacksize", Summary.int(we, "stacksize"), @intCast(e.main.stacksize));
                try expectHex(c, "entry_point.entryoff_hex", Summary.hex(we, "entryoff_hex"), e.main.entryoff);
                if (img.entryVm() != img.image_base + e.main.entryoff) return c.fail("entryVm", .{});
            },
            .SYMTAB => {
                saw_symtab = true;
                const st = loadcmds.decodeSymtab(cmd) orelse return c.fail("symtab decode", .{});
                const ws = Summary.object(sl, "symtab") orelse return c.fail("symtab missing in summary", .{});
                try expectInt(c, "symtab.symoff", Summary.int(ws, "symoff"), st.symoff);
                try expectInt(c, "symtab.nsyms", Summary.int(ws, "nsyms"), st.nsyms);
                try expectInt(c, "symtab.stroff", Summary.int(ws, "stroff"), st.stroff);
                try expectInt(c, "symtab.strsize", Summary.int(ws, "strsize"), st.strsize);
            },
            .DYSYMTAB => {
                saw_dysymtab = true;
                const dt = loadcmds.decodeDysymtab(cmd) orelse return c.fail("dysymtab decode", .{});
                const wd = Summary.object(sl, "dysymtab") orelse return c.fail("dysymtab missing in summary", .{});
                inline for (.{ "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel" }) |f| {
                    try expectInt(c, "dysymtab." ++ f, Summary.int(wd, f), @field(dt, f));
                }
            },
            .FUNCTION_STARTS, .DATA_IN_CODE => {
                const ld = loadcmds.decodeLinkeditData(cmd) orelse return c.fail("linkedit_data decode", .{});
                const key = if (cmd.lc() == .FUNCTION_STARTS) "function_starts" else "data_in_code";
                if (cmd.lc() == .FUNCTION_STARTS) saw_fs = true else saw_dic = true;
                const wl = Summary.object(sl, key) orelse return c.fail("{s} missing in summary", .{key});
                try expectInt(c, "dataoff", Summary.int(wl, "dataoff"), ld.dataoff);
                try expectInt(c, "datasize", Summary.int(wl, "datasize"), ld.datasize);
            },
            .DYLD_INFO, .DYLD_INFO_ONLY => {
                const di = loadcmds.decodeDyldInfo(cmd) orelse return c.fail("dyld_info decode", .{});
                const wd = Summary.object(sl, "dyld_info") orelse return c.fail("dyld_info missing in summary", .{});
                inline for (.{ "rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off", "weak_bind_size", "lazy_bind_off", "lazy_bind_size", "export_off", "export_size" }) |f| {
                    try expectInt(c, "dyld_info." ++ f, Summary.int(wd, f), @field(di, f));
                }
                if (img.dyldStyle() != .legacy) return c.fail("dyldStyle should be legacy", .{});
            },
            .DYLD_CHAINED_FIXUPS => if (img.dyldStyle() != .chained) return c.fail("dyldStyle should be chained", .{}),
            else => {},
        }
    }
    if (dl_i != want_dylibs.len) return c.fail("dylibs: {d} vs {d}", .{ dl_i, want_dylibs.len });
    if (rp_i != want_rpaths.len) return c.fail("rpaths: {d} vs {d}", .{ rp_i, want_rpaths.len });
    if (saw_uuid != (Summary.str(sl, "uuid") != null)) return c.fail("uuid presence", .{});
    if (saw_build != (Summary.object(sl, "build_version") != null)) return c.fail("build_version presence", .{});
    if (saw_vmin != (Summary.get(sl, "version_min") != null)) return c.fail("version_min presence", .{});
    if (saw_srcver != (Summary.str(sl, "source_version") != null)) return c.fail("source_version presence", .{});
    if (saw_entry != (Summary.object(sl, "entry_point") != null)) return c.fail("entry_point presence", .{});
    if (saw_dylinker != (Summary.str(sl, "dylinker") != null)) return c.fail("dylinker presence", .{});
    if (saw_id != (Summary.object(sl, "id_dylib") != null)) return c.fail("id_dylib presence", .{});
    if (!saw_symtab or !saw_dysymtab or !saw_fs or !saw_dic) return c.fail("symtab/dysymtab/function_starts/data_in_code missing", .{});
    if (Summary.boolean(sl, "has_chained_fixups").? != (img.findCmd(.DYLD_CHAINED_FIXUPS) != null)) return c.fail("has_chained_fixups", .{});
    if (Summary.boolean(sl, "has_dyld_info").? != (img.findCmd(.DYLD_INFO_ONLY) != null or img.findCmd(.DYLD_INFO) != null)) return c.fail("has_dyld_info", .{});
    // translation sanity: every section address maps back to its file offset
    for (img.sections) |s| if (!s.isZerofill() and s.size > 0) {
        const off = img.vmToOff(s.addr) orelse return c.fail("vmToOff({s})", .{s.sectname});
        if (off != s.offset) return c.fail("vmToOff({s}) = {d}, want {d}", .{ s.sectname, off, s.offset });
        if (img.offToVm(off) != s.addr) return c.fail("offToVm({s})", .{s.sectname});
        if (img.sectionForVm(s.addr) == null) return c.fail("sectionForVm({s})", .{s.sectname});
    };
    if (img.text_seg == null or img.linkedit_seg == null) return c.fail("__TEXT/__LINKEDIT not found", .{});
}

fn checkFixture(gpa: std.mem.Allocator, io: std.Io, summary: *const Summary, name: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const c: Ctx = .{ .arena = a, .diags = &diags, .name = name };
    const fx = summary.fixtureNamed(name) orelse return c.fail("fixture missing in summary", .{});
    const path = try helpers.summaryFixturePath(a, name);
    var file = machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer file.deinit(gpa);
    try expectInt(&c, "size", Summary.int(fx, "size"), @intCast(file.size));
    const digest = file.digest();
    try expectStr(&c, "sha256", Summary.str(fx, "sha256"), try fmtStr(a, "{x}", .{@as([]const u8, &digest)}));
    try expectStr(&c, "container", Summary.str(fx, "container"), file.container.containerName());
    const want_fat = Summary.array(fx, "fat_arches") orelse &.{};
    switch (file.container) {
        .fat => |f| {
            if (want_fat.len != f.arches.len) return c.fail("fat_arches: {d} vs {d}", .{ want_fat.len, f.arches.len });
            for (want_fat, f.arches) |w, fa| {
                try expectInt(&c, "fat.cputype", Summary.int(w, "cputype"), fa.arch.cputype);
                try expectStr(&c, "fat.cputype_name", Summary.str(w, "cputype_name"), version.cpuTypeName(fa.arch.cputype));
                try expectHex(&c, "fat.cpusubtype", Summary.hex(w, "cpusubtype"), @as(u32, @bitCast(fa.arch.cpusubtype)));
                try expectInt(&c, "fat.offset", Summary.int(w, "offset"), @intCast(fa.offset));
                try expectInt(&c, "fat.size", Summary.int(w, "size"), @intCast(fa.size));
                try expectInt(&c, "fat.align", Summary.int(w, "align"), fa.@"align");
                if (!fa.valid) return c.fail("fat arch invalid", .{});
            }
        },
        else => if (want_fat.len != 0) return c.fail("expected a fat container", .{}),
    }
    const want_slices = Summary.array(fx, "slices") orelse &.{};
    if (want_slices.len != file.sliceCount()) return c.fail("slices: {d} vs {d}", .{ want_slices.len, file.sliceCount() });
    for (want_slices, 0..) |sl, i| {
        const r = file.sliceReader(i) orelse return c.fail("sliceReader({d})", .{i});
        const img = try machre.Image.parse(a, r, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags);
        try checkSlice(&c, &img, sl);
    }
    if (diags.hasErrors()) {
        for (diags.items()) |d| std.debug.print("  diag {t}.{t}: {s}\n", .{ d.module, d.code, d.message });
        return c.fail("unexpected error diagnostics", .{});
    }
}

test "facts/core: header, load commands, segments, sections, dylibs and linkedit facts for every summary.json fixture" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const names = [_][]const u8{ "hello-c", "hello-x86_64", "hello-fat", "hello-objc", "libhello.dylib", "hello-usedylib", "hello-adhoc", "hello-entitled", "hello-unsigned", "high-entropy", "fake-packed", "fake-upx", "hello-zig", "legacy-bind", "hello-quarantined", "Hello.app", "bin-ls" };
    var failures: usize = 0;
    for (names) |n| checkFixture(gpa, io, &summary, n) catch |e| switch (e) {
        error.SkipZigTest => {},
        else => failures += 1,
    };
    if (failures != 0) return error.FactsFailed;
}

test "facts/core: text-mode arch selection on hello-fat prefers the host and --arch selects" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try helpers.fixturePath(a, "hello-fat");
    const r = try helpers.runMachre(a, io, &.{ "info", path });
    try std.testing.expectEqual(@as(u8, 0), r.code);
    try std.testing.expect(std.mem.startsWith(u8, r.out, "2 architectures, showing arm64 (use --all-archs)\n"));
    const x = try helpers.runMachre(a, io, &.{ "info", "--arch", "x86_64", path });
    try std.testing.expect(std.mem.find(u8, x.out, "x86_64 (fat slice 1 of 2 at offset 4096)") != null);
    const all = try helpers.runMachre(a, io, &.{ "header", "--all-archs", path });
    try std.testing.expect(std.mem.find(u8, all.out, "(architecture x86_64):") != null and std.mem.find(u8, all.out, "(architecture arm64):") != null);
}

test {
    // tests/facts/tool_oracles.zig holds the Apple-tool oracles gen/truth.sh captures that had no
    // reader (vtool -show, otool -L, otool -Iv, dyld_info -platform/-inits, objdump --objc-meta-data);
    // it rides along with this file instead of adding a second corpus-test root.
    _ = @import("tool_oracles.zig");
}
