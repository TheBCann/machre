//! core/image.zig — one parsed Mach-O slice. Imports: reader, loadcmds, segments, arch, diag, limits.
const std = @import("std");
const macho = std.macho;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const loadcmds = @import("loadcmds.zig");
const segments = @import("segments.zig");
const Arch = @import("arch.zig").Arch;
const Limits = @import("limits.zig").Limits;
const diag = @import("diag.zig");
const Diagnostics = diag.Diagnostics;

pub const Header = loadcmds.Header;
pub const LoadCmd = loadcmds.LoadCmd;
pub const Segment = segments.Segment;
pub const Section = segments.Section;

pub const Image = struct {
    /// Whole slice (thin file or fat member). All `offset` fields below are relative to this.
    r: Reader,
    /// Absolute file offset of this slice (0 for thin). JSON: "offset_in_file".
    slice_offset: u64,
    index: u32, // slice index (0 for thin)
    arch: Arch,
    hdr: Header,
    cmds: []const LoadCmd, // file order, every one validated
    segments: []const Segment, // load-command order, including __PAGEZERO
    sections: []const Section, // flat, file order; Section.index is 1-based like n_sect
    /// vmaddr of __TEXT (0x100000000 executables, 0 dylibs) or of the first segment with fileoff 0.
    image_base: u64,
    text_seg: ?u16,
    linkedit_seg: ?u16,
    /// True when the walker stopped early (bad cmdsize etc.); the parsed prefix is still usable.
    cmds_truncated: bool,
    ncmds_parsed: u32,

    pub const ParseError = error{ NotMachO, Truncated } || Allocator.Error;

    /// Validates magic, header, every load command and every segment/section against `r.len()` and `limits`;
    /// structural problems become diagnostics. Only "not even a header" is a hard error.
    pub fn parse(arena: Allocator, r: Reader, slice_offset: u64, index: u32, limits: *const Limits, diags: *Diagnostics) ParseError!Image {
        const hdr = try Header.parse(r);
        var img: Image = .{
            .r = r,
            .slice_offset = slice_offset,
            .index = index,
            .arch = Arch.fromCpu(hdr.cputype, hdr.cpusubtype),
            .hdr = hdr,
            .cmds = &.{},
            .segments = &.{},
            .sections = &.{},
            .image_base = 0,
            .text_seg = null,
            .linkedit_seg = null,
            .cmds_truncated = false,
            .ncmds_parsed = 0,
        };
        var cmds: std.ArrayList(LoadCmd) = .empty;
        var segs: std.ArrayList(Segment) = .empty;
        var sects: std.ArrayList(Section) = .empty;
        var w = loadcmds.Walker.init(r, hdr, limits, diags);
        while (w.next(diags)) |c| {
            try cmds.append(arena, c);
            const is_seg64 = c.cmd == @intFromEnum(macho.LC.SEGMENT_64);
            const is_seg32 = c.cmd == @intFromEnum(macho.LC.SEGMENT);
            if (is_seg64 or is_seg32) {
                if (segs.items.len < std.math.maxInt(u16)) {
                    try parseSegment(arena, &img, c, is_seg64, &segs, &sects, limits, diags);
                } else if (!diags.has(.segments, .limit_reached)) {
                    diags.warn(.segments, .limit_reached, c.offset, "more than 65535 segments; the rest are ignored", .{});
                }
            } else {
                checkLinkeditRanges(&img, c, diags);
            }
        }
        img.cmds_truncated = w.stopped;
        img.ncmds_parsed = w.index;
        img.cmds = try cmds.toOwnedSlice(arena);
        img.segments = try segs.toOwnedSlice(arena);
        img.sections = try sects.toOwnedSlice(arena);
        for (img.segments, 0..) |s, i| {
            if (std.mem.eql(u8, s.name, "__TEXT") and img.text_seg == null) img.text_seg = @intCast(i);
            if (std.mem.eql(u8, s.name, "__LINKEDIT") and img.linkedit_seg == null) img.linkedit_seg = @intCast(i);
        }
        if (img.text_seg) |t| {
            img.image_base = img.segments[t].vmaddr;
        } else for (img.segments) |s| {
            if (s.fileoff == 0 and s.filesize != 0) {
                img.image_base = s.vmaddr;
                break;
            }
        }
        if (hdr.endian == .big and !diags.has(.header, .version_unsupported))
            diags.warn(.header, .version_unsupported, slice_offset, "big-endian (MH_CIGAM) image: header and load commands decoded, payload parsers skipped", .{});
        return img;
    }

    fn parseSegment(arena: Allocator, img: *Image, c: LoadCmd, is_64: bool, segs: *std.ArrayList(Segment), sects: *std.ArrayList(Section), limits: *const Limits, diags: *Diagnostics) Allocator.Error!void {
        const cr = c.reader();
        const e = c.endian;
        const seg_size: u32 = if (is_64) 72 else 56;
        const sect_size: u32 = if (is_64) 80 else 68;
        if (c.bytes.len < seg_size) {
            diags.err(.segments, .cmdsize_invalid, c.offset, "segment load command {d} cmdsize {d} smaller than {d}", .{ c.index, c.cmdsize, seg_size });
            return;
        }
        var seg: Segment = undefined;
        seg.index = @intCast(segs.items.len);
        seg.name = try arena.dupe(u8, cr.nameAt(8, 16).?);
        seg.cmd_offset = c.offset;
        if (is_64) {
            seg.vmaddr = cr.u64At(24, e).?;
            seg.vmsize = cr.u64At(32, e).?;
            seg.fileoff = cr.u64At(40, e).?;
            seg.filesize = cr.u64At(48, e).?;
            seg.maxprot = cr.u32At(56, e).?;
            seg.initprot = cr.u32At(60, e).?;
            seg.nsects = cr.u32At(64, e).?;
            seg.flags = cr.u32At(68, e).?;
        } else {
            seg.vmaddr = cr.u32At(24, e).?;
            seg.vmsize = cr.u32At(28, e).?;
            seg.fileoff = cr.u32At(32, e).?;
            seg.filesize = cr.u32At(36, e).?;
            seg.maxprot = cr.u32At(40, e).?;
            seg.initprot = cr.u32At(44, e).?;
            seg.nsects = cr.u32At(48, e).?;
            seg.flags = cr.u32At(52, e).?;
        }
        seg.file_range_truncated = false;
        if (!img.r.contains(seg.fileoff, seg.filesize)) {
            if (!diags.has(.segments, .offset_past_eof))
                diags.warn(.segments, .offset_past_eof, c.offset + 40, "segment {s} fileoff {d} + filesize {d} exceeds the {d}-byte slice; clamped", .{ seg.name, seg.fileoff, seg.filesize, img.r.len() });
            seg.file_range_truncated = true;
            seg.filesize = if (seg.fileoff < img.r.len()) img.r.len() - seg.fileoff else 0;
        }
        // sections: 72 + 80*nsects must fit inside cmdsize
        const fit: u64 = (c.bytes.len - seg_size) / sect_size;
        var n: u64 = seg.nsects;
        if (n > fit) {
            diags.err(.segments, .nsects_invalid, c.offset + 64, "segment {s} nsects {d} but cmdsize {d} holds only {d} sections; clamped", .{ seg.name, seg.nsects, c.cmdsize, fit });
            n = fit;
        }
        const room: u64 = limits.max_sections -| sects.items.len;
        if (n > room) {
            if (!diags.has(.segments, .count_clamped))
                diags.warn(.segments, .count_clamped, c.offset + 64, "sections clamped to limits.max_sections {d}", .{limits.max_sections});
            n = room;
        }
        seg.first_section = @intCast(sects.items.len);
        seg.section_count = @intCast(n);
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const o: u64 = seg_size + i * sect_size;
            var s: Section = undefined;
            s.index = @intCast(sects.items.len + 1);
            s.segment = seg.index;
            s.sectname = try arena.dupe(u8, cr.nameAt(o, 16).?);
            s.segname = try arena.dupe(u8, cr.nameAt(o + 16, 16).?);
            if (is_64) {
                s.addr = cr.u64At(o + 32, e).?;
                s.size = cr.u64At(o + 40, e).?;
                s.offset = cr.u32At(o + 48, e).?;
                s.@"align" = cr.u32At(o + 52, e).?;
                s.reloff = cr.u32At(o + 56, e).?;
                s.nreloc = cr.u32At(o + 60, e).?;
                s.flags = cr.u32At(o + 64, e).?;
                s.reserved1 = cr.u32At(o + 68, e).?;
                s.reserved2 = cr.u32At(o + 72, e).?;
                s.reserved3 = cr.u32At(o + 76, e).?;
            } else {
                s.addr = cr.u32At(o + 32, e).?;
                s.size = cr.u32At(o + 36, e).?;
                s.offset = cr.u32At(o + 40, e).?;
                s.@"align" = cr.u32At(o + 44, e).?;
                s.reloff = cr.u32At(o + 48, e).?;
                s.nreloc = cr.u32At(o + 52, e).?;
                s.flags = cr.u32At(o + 56, e).?;
                s.reserved1 = cr.u32At(o + 60, e).?;
                s.reserved2 = cr.u32At(o + 64, e).?;
                s.reserved3 = 0;
            }
            s.class = segments.classify(s.segname, s.sectname, s.flags);
            if (!s.isZerofill() and !img.r.contains(s.offset, s.size)) {
                if (!diags.has(.segments, .offset_past_eof))
                    diags.warn(.segments, .offset_past_eof, c.offset + o + 48, "section {s},{s} offset {d} + size {d} exceeds the {d}-byte slice", .{ s.segname, s.sectname, s.offset, s.size, img.r.len() });
            }
            try sects.append(arena, s);
        }
        try segs.append(arena, seg);
    }

    /// Validates the file ranges named by LC_SYMTAB/LC_DYSYMTAB/LC_DYLD_INFO/linkedit_data commands.
    fn checkLinkeditRanges(img: *Image, c: LoadCmd, diags: *Diagnostics) void {
        const lc = c.lc();
        var ranges: [12]struct { off: u64, size: u64, what: []const u8 } = undefined;
        var n: usize = 0;
        switch (lc) {
            .SYMTAB => if (loadcmds.decodeSymtab(c)) |st| {
                ranges[0] = .{ .off = st.symoff, .size = std.math.mul(u64, st.nsyms, if (img.hdr.is_64) 16 else 12) catch std.math.maxInt(u64), .what = "symbol table" };
                ranges[1] = .{ .off = st.stroff, .size = st.strsize, .what = "string table" };
                n = 2;
            },
            .DYSYMTAB => if (loadcmds.decodeDysymtab(c)) |dt| {
                ranges[0] = .{ .off = dt.tocoff, .size = std.math.mul(u64, dt.ntoc, 8) catch std.math.maxInt(u64), .what = "table of contents" };
                ranges[1] = .{ .off = dt.modtaboff, .size = std.math.mul(u64, dt.nmodtab, if (img.hdr.is_64) 56 else 52) catch std.math.maxInt(u64), .what = "module table" };
                ranges[2] = .{ .off = dt.extrefsymoff, .size = std.math.mul(u64, dt.nextrefsyms, 4) catch std.math.maxInt(u64), .what = "external reference table" };
                ranges[3] = .{ .off = dt.indirectsymoff, .size = std.math.mul(u64, dt.nindirectsyms, 4) catch std.math.maxInt(u64), .what = "indirect symbol table" };
                ranges[4] = .{ .off = dt.extreloff, .size = std.math.mul(u64, dt.nextrel, 8) catch std.math.maxInt(u64), .what = "external relocations" };
                ranges[5] = .{ .off = dt.locreloff, .size = std.math.mul(u64, dt.nlocrel, 8) catch std.math.maxInt(u64), .what = "local relocations" };
                n = 6;
            },
            .DYLD_INFO, .DYLD_INFO_ONLY => if (loadcmds.decodeDyldInfo(c)) |di| {
                ranges[0] = .{ .off = di.rebase_off, .size = di.rebase_size, .what = "rebase info" };
                ranges[1] = .{ .off = di.bind_off, .size = di.bind_size, .what = "bind info" };
                ranges[2] = .{ .off = di.weak_bind_off, .size = di.weak_bind_size, .what = "weak bind info" };
                ranges[3] = .{ .off = di.lazy_bind_off, .size = di.lazy_bind_size, .what = "lazy bind info" };
                ranges[4] = .{ .off = di.export_off, .size = di.export_size, .what = "export info" };
                n = 5;
            },
            .CODE_SIGNATURE, .SEGMENT_SPLIT_INFO, .FUNCTION_STARTS, .DATA_IN_CODE, .DYLIB_CODE_SIGN_DRS, .LINKER_OPTIMIZATION_HINT, .DYLD_EXPORTS_TRIE, .DYLD_CHAINED_FIXUPS => if (loadcmds.decodeLinkeditData(c)) |ld| {
                ranges[0] = .{ .off = ld.dataoff, .size = ld.datasize, .what = "linkedit data" };
                n = 1;
            },
            else => {},
        }
        for (ranges[0..n]) |rg| {
            if (rg.size == 0) continue;
            if (!img.r.contains(rg.off, rg.size)) {
                if (!diags.has(.loadcmds, .offset_past_eof)) {
                    var nb: [32]u8 = undefined;
                    diags.warn(.loadcmds, .offset_past_eof, c.offset, "{s}: {s} at offset {d} size {d} exceeds the {d}-byte slice", .{ c.name(&nb), rg.what, rg.off, rg.size, img.r.len() });
                }
                // `continue`, not `return`: an LC_DYSYMTAB carries six ranges, and returning on the
                // first bad one left the other five unchecked -- the analyst saw a single diagnostic
                // with no sign that the rest were also out of bounds. The `diags.has` guard above
                // still prevents a flood.
                continue;
            }
        }
    }

    // ---- address translation (all total) ----
    pub fn vmToOff(img: *const Image, vmaddr: u64) ?u64 {
        const s = img.segmentForVm(vmaddr) orelse return null;
        const delta = vmaddr - s.vmaddr;
        if (delta >= s.filesize) return null;
        return s.fileoff + delta;
    }
    pub fn offToVm(img: *const Image, off: u64) ?u64 {
        for (img.segments) |*s| {
            if (s.filesize == 0) continue;
            if (off >= s.fileoff and off - s.fileoff < s.filesize) return s.vmaddr + (off - s.fileoff);
        }
        return null;
    }
    pub fn segmentForVm(img: *const Image, vmaddr: u64) ?*const Segment {
        for (img.segments) |*s| if (s.vmsize != 0 and s.containsVm(vmaddr)) return s;
        return null;
    }
    pub fn sectionForVm(img: *const Image, vmaddr: u64) ?*const Section {
        for (img.sections) |*s| if (s.containsVm(vmaddr)) return s;
        return null;
    }
    pub fn sectionByName(img: *const Image, segname: []const u8, sectname: []const u8) ?*const Section {
        for (img.sections) |*s| if (std.mem.eql(u8, s.segname, segname) and std.mem.eql(u8, s.sectname, sectname)) return s;
        return null;
    }
    pub fn sectionByClass(img: *const Image, class: segments.SectionClass) ?*const Section {
        for (img.sections) |*s| if (s.class == class) return s;
        return null;
    }
    pub fn segmentByName(img: *const Image, segname: []const u8) ?*const Segment {
        for (img.segments) |*s| if (std.mem.eql(u8, s.name, segname)) return s;
        return null;
    }
    pub const VmBytes = struct { bytes: []const u8, truncated: bool };
    /// Bytes backing a vm range; clamps at the segment filesize and slice end. Null when start is unmapped.
    pub fn bytesAtVm(img: *const Image, vmaddr: u64, size: u64) ?VmBytes {
        const s = img.segmentForVm(vmaddr) orelse return null;
        const delta = vmaddr - s.vmaddr;
        if (delta >= s.filesize) return .{ .bytes = &.{}, .truncated = size != 0 };
        const avail = s.filesize - delta;
        const want = @min(size, avail);
        const sub = img.r.subClamped(s.fileoff + delta, want) orelse return null;
        return .{ .bytes = sub.r.bytes, .truncated = sub.truncated or want < size };
    }
    pub fn cstrAtVm(img: *const Image, vmaddr: u64, max: u32) ?[]const u8 {
        const off = img.vmToOff(vmaddr) orelse return null;
        const s = img.r.cstrAt(off, max) orelse return null;
        return s.bytes;
    }
    pub fn u64AtVm(img: *const Image, vmaddr: u64) ?u64 {
        const off = img.vmToOff(vmaddr) orelse return null;
        return img.r.u64At(off, img.hdr.endian);
    }
    pub fn u32AtVm(img: *const Image, vmaddr: u64) ?u32 {
        const off = img.vmToOff(vmaddr) orelse return null;
        return img.r.u32At(off, img.hdr.endian);
    }
    /// Section bytes as a Reader (null if offset/size fall outside the slice; zero-fill -> empty).
    pub fn sectionReader(img: *const Image, sect: *const Section) ?Reader {
        if (sect.isZerofill()) return Reader.init(&.{}, sect.offset);
        const sub = img.r.subClamped(sect.offset, sect.size) orelse return null;
        return sub.r;
    }
    /// (dataoff, datasize) of a linkedit_data_command: must lie inside the slice; a diagnostic when
    /// it also falls outside __LINKEDIT (tolerated). Clamped at the slice end.
    pub fn linkeditReader(img: *const Image, dataoff: u64, datasize: u64, diags: *Diagnostics, who: diag.Module) ?Reader {
        if (dataoff >= img.r.len()) {
            if (!diags.has(who, .offset_past_eof))
                diags.err(who, .offset_past_eof, dataoff, "linkedit data at offset {d} lies past the {d}-byte slice", .{ dataoff, img.r.len() });
            return null;
        }
        const sub = img.r.subClamped(dataoff, datasize).?;
        if (sub.truncated and !diags.has(who, .truncated))
            diags.warn(who, .truncated, dataoff, "linkedit data at offset {d} size {d} clamped to the slice end", .{ dataoff, datasize });
        if (img.linkedit_seg) |li| {
            const le = img.segments[li];
            const inside = dataoff >= le.fileoff and (dataoff - le.fileoff) < le.filesize;
            if (!inside and !diags.has(who, .unaligned))
                diags.info(who, .unaligned, dataoff, "linkedit data at offset {d} lies outside __LINKEDIT", .{dataoff});
        }
        return sub.r;
    }
    pub fn findCmd(img: *const Image, cmd: macho.LC) ?LoadCmd {
        for (img.cmds) |c| if (c.cmd == @intFromEnum(cmd)) return c;
        return null;
    }
    pub fn cmdIterator(img: *const Image, cmd: ?macho.LC) CmdIterator {
        return .{ .img = img, .want = cmd };
    }
    pub const CmdIterator = struct {
        img: *const Image,
        want: ?macho.LC,
        i: usize = 0,
        pub fn next(it: *CmdIterator) ?LoadCmd {
            while (it.i < it.img.cmds.len) {
                const c = it.img.cmds[it.i];
                it.i += 1;
                if (it.want == null or c.cmd == @intFromEnum(it.want.?)) return c;
            }
            return null;
        }
    };
    /// Entry vmaddr from LC_MAIN (image_base + entryoff) or LC_UNIXTHREAD pc.
    pub fn entryVm(img: *const Image) ?u64 {
        for (img.cmds) |c| {
            if (c.cmd == @intFromEnum(macho.LC.MAIN)) {
                const r = c.reader();
                const entryoff = r.u64At(8, c.endian) orelse return null;
                return std.math.add(u64, img.image_base, entryoff) catch null;
            }
            if (c.cmd == @intFromEnum(macho.LC.UNIXTHREAD)) {
                var sink = diag.Diagnostics.init(std.heap.page_allocator, 0);
                const e = loadcmds.decodeEntry(c, img.hdr.is_64, &sink);
                return switch (e) {
                    .unixthread => |t| t.pc,
                    else => null,
                };
            }
        }
        return null;
    }
    pub fn dyldStyle(img: *const Image) DyldStyle {
        if (img.findCmd(.DYLD_CHAINED_FIXUPS) != null) return .chained;
        if (img.findCmd(.DYLD_INFO_ONLY) != null or img.findCmd(.DYLD_INFO) != null) return .legacy;
        return .none;
    }
    pub const DyldStyle = enum { chained, legacy, none };
};

// ---- tests ----
fn le32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
fn le64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .little);
}
/// header(32) + LC_SEGMENT_64 __TEXT with one __text section (152) + LC_MAIN(24) = 208 bytes, then 48 bytes of "file".
fn buildImage(buf: *[256]u8) void {
    @memset(buf, 0);
    le32(buf, 0, macho.MH_MAGIC_64);
    le32(buf, 4, 0x0100000c);
    le32(buf, 12, 2);
    le32(buf, 16, 2);
    le32(buf, 20, 176);
    le32(buf, 24, 0x200085);
    le32(buf, 32, 0x19);
    le32(buf, 36, 152);
    @memcpy(buf[40..][0..6], "__TEXT");
    le64(buf, 56, 0x100000000);
    le64(buf, 64, 0x100);
    le64(buf, 72, 0);
    le64(buf, 80, 256);
    le32(buf, 88, 5);
    le32(buf, 92, 5);
    le32(buf, 96, 1);
    le32(buf, 100, 0);
    @memcpy(buf[104..][0..6], "__text");
    @memcpy(buf[120..][0..6], "__TEXT");
    le64(buf, 136, 0x1000000d0);
    le64(buf, 144, 0x30);
    le32(buf, 152, 208);
    le32(buf, 156, 2);
    le32(buf, 168, 0x80000400);
    le32(buf, 184, 0x80000028);
    le32(buf, 188, 24);
    le64(buf, 192, 0xd0);
    @memcpy(buf[208..][0..5], "hello");
}

test "image: parse, translation and section readers on a hand-built slice" {
    var buf: [256]u8 = undefined;
    buildImage(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var d = Diagnostics.init(a, 32);
    const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 2), img.cmds.len);
    try std.testing.expectEqual(@as(usize, 1), img.segments.len);
    try std.testing.expectEqual(@as(usize, 1), img.sections.len);
    try std.testing.expectEqual(@as(u64, 0x100000000), img.image_base);
    try std.testing.expectEqual(@as(?u16, 0), img.text_seg);
    try std.testing.expectEqualStrings("__text", img.sections[0].sectname);
    try std.testing.expectEqual(segments.SectionClass.text, img.sections[0].class);
    try std.testing.expectEqual(@as(?u64, 208), img.vmToOff(0x1000000d0));
    try std.testing.expectEqual(@as(?u64, 0x1000000d0), img.offToVm(208));
    try std.testing.expect(img.vmToOff(0x200000000) == null);
    try std.testing.expectEqualStrings("hello", img.cstrAtVm(0x1000000d0, 16).?);
    try std.testing.expectEqual(@as(?u64, 0x1000000d0), img.entryVm());
    try std.testing.expectEqual(Image.DyldStyle.none, img.dyldStyle());
    try std.testing.expect(img.sectionByName("__TEXT", "__text") != null and img.sectionByClass(.stubs) == null);
    const sr = img.sectionReader(&img.sections[0]).?;
    try std.testing.expectEqual(@as(usize, 0x30), sr.len());
    const vb = img.bytesAtVm(0x1000000d0, 1000).?;
    try std.testing.expect(vb.truncated and vb.bytes.len == 48);
    try std.testing.expect(img.findCmd(.MAIN) != null and img.findCmd(.SYMTAB) == null);
    var it = img.cmdIterator(null);
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(usize, 0), d.items().len);
}

test "image: nsects/section offset/segment range diagnostics and every-prefix parse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    {
        var buf: [256]u8 = undefined;
        buildImage(&buf);
        le32(&buf, 96, 0xFFFFFFFF);
        var d = Diagnostics.init(a, 32);
        const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
        try std.testing.expect(d.has(.segments, .nsects_invalid));
        try std.testing.expectEqual(@as(u16, 1), img.segments[0].section_count);
    }
    {
        var buf: [256]u8 = undefined;
        buildImage(&buf);
        le32(&buf, 152, 0x7FFFFFF0);
        var d = Diagnostics.init(a, 32);
        const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
        try std.testing.expect(d.has(.segments, .offset_past_eof));
        try std.testing.expect(img.sectionReader(&img.sections[0]) == null);
    }
    {
        var buf: [256]u8 = undefined;
        buildImage(&buf);
        le64(&buf, 80, 0x7FFFFFF0);
        var d = Diagnostics.init(a, 32);
        const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
        try std.testing.expect(img.segments[0].file_range_truncated and img.segments[0].filesize == 256);
    }
    {
        var buf: [256]u8 = undefined;
        buildImage(&buf);
        var len: usize = 0;
        while (len <= buf.len) : (len += 1) {
            var d = Diagnostics.init(a, 32);
            const img = Image.parse(a, Reader.init(buf[0..len], 0), 0, 0, &Limits.paranoid, &d) catch |e| switch (e) {
                error.NotMachO, error.Truncated => continue,
                else => return e,
            };
            _ = img.entryVm();
            _ = img.dyldStyle();
            _ = img.vmToOff(0x1000000d0);
        }
    }
}
