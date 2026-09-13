//! core/segments.zig — normalized Segment/Section + classification. Imports: std only.
const std = @import("std");
const macho = std.macho;

pub const Segment = struct {
    index: u16,
    name: []const u8, // arena dupe of the NUL-trimmed 16-byte field (may be 16 chars, may be empty)
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32, // declared
    flags: u32,
    cmd_offset: u32,
    first_section: u16, // into Image.sections
    section_count: u16, // actually parsed (<= nsects)
    /// filesize clamped to the slice; true when clamped.
    file_range_truncated: bool,

    pub const Which = enum { init, max };
    /// "r-x" style protection string.
    pub fn protString(s: Segment, buf: *[3]u8, which: Which) []const u8 {
        const p = if (which == .init) s.initprot else s.maxprot;
        buf[0] = if (p & 1 != 0) 'r' else '-';
        buf[1] = if (p & 2 != 0) 'w' else '-';
        buf[2] = if (p & 4 != 0) 'x' else '-';
        return buf[0..3];
    }
    /// SG_PROTECTED_VERSION_1 (encrypted segment).
    pub fn isProtected(s: Segment) bool {
        return s.flags & macho.SG_PROTECTED_VERSION_1 != 0;
    }
    pub fn containsVm(s: Segment, vmaddr: u64) bool {
        return vmaddr >= s.vmaddr and vmaddr - s.vmaddr < s.vmsize;
    }
};

pub const SectionClass = enum {
    text,
    stubs,
    auth_stubs,
    objc_stubs,
    stub_helper,
    cstring,
    ustring,
    cfstring,
    const_data,
    got,
    auth_got,
    la_symbol_ptr,
    nl_symbol_ptr,
    data,
    bss,
    common,
    unwind,
    eh_frame,
    info_plist,
    objc_methname,
    objc_classname,
    objc_methtype,
    objc_methlist,
    objc_classlist,
    objc_nlclslist,
    objc_catlist,
    objc_nlcatlist,
    objc_protolist,
    objc_imageinfo,
    objc_selrefs,
    objc_classrefs,
    objc_superrefs,
    objc_const,
    objc_data,
    objc_ivar,
    mod_init,
    mod_term,
    init_offsets,
    thread_local,
    other,
};

pub const Section = struct {
    index: u16, // 1-based (n_sect)
    segment: u16,
    sectname: []const u8,
    segname: []const u8,
    addr: u64,
    size: u64,
    offset: u32,
    @"align": u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
    class: SectionClass,

    pub fn sectType(s: Section) u8 {
        return @truncate(s.flags & macho.SECTION_TYPE);
    }
    pub fn attrs(s: Section) u32 {
        return s.flags & 0xffffff00;
    }
    pub fn isZerofill(s: Section) bool {
        return switch (s.sectType()) {
            macho.S_ZEROFILL, macho.S_GB_ZEROFILL, macho.S_THREAD_LOCAL_ZEROFILL => true,
            else => false,
        };
    }
    /// S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS
    pub fn isCode(s: Section) bool {
        return s.flags & (macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS) != 0;
    }
    pub fn isSymbolStubs(s: Section) bool {
        return s.sectType() == macho.S_SYMBOL_STUBS;
    }
    pub fn containsVm(s: Section, vmaddr: u64) bool {
        return vmaddr >= s.addr and vmaddr - s.addr < s.size;
    }
    /// Entry size for stub/pointer sections: reserved2 for S_SYMBOL_STUBS, 32 for __objc_stubs,
    /// 8 for pointer sections, null otherwise.
    pub fn entrySize(s: Section) ?u32 {
        if (s.isSymbolStubs()) return if (s.reserved2 != 0) s.reserved2 else null;
        if (s.class == .objc_stubs) return 32;
        return switch (s.sectType()) {
            macho.S_NON_LAZY_SYMBOL_POINTERS, macho.S_LAZY_SYMBOL_POINTERS, 0x10, 0x14 => 8,
            else => switch (s.class) {
                .got, .auth_got, .la_symbol_ptr, .nl_symbol_ptr, .objc_selrefs, .objc_classrefs, .objc_superrefs, .objc_classlist, .objc_nlclslist, .objc_catlist, .objc_nlcatlist, .objc_protolist, .mod_init, .mod_term => 8,
                else => null,
            },
        };
    }
};

const eql = std.mem.eql;

/// Section class from (segname, sectname, flags): the section type wins, then well-known names.
pub fn classify(segname: []const u8, sectname: []const u8, flags: u32) SectionClass {
    _ = segname;
    const t: u8 = @truncate(flags & macho.SECTION_TYPE);
    switch (t) {
        macho.S_CSTRING_LITERALS => {
            if (eql(u8, sectname, "__objc_methname")) return .objc_methname;
            if (eql(u8, sectname, "__objc_classname")) return .objc_classname;
            if (eql(u8, sectname, "__objc_methtype")) return .objc_methtype;
            if (eql(u8, sectname, "__info_plist")) return .info_plist;
            return .cstring;
        },
        macho.S_SYMBOL_STUBS => return if (eql(u8, sectname, "__auth_stubs")) .auth_stubs else .stubs,
        macho.S_NON_LAZY_SYMBOL_POINTERS => {
            if (eql(u8, sectname, "__auth_got")) return .auth_got;
            if (eql(u8, sectname, "__got")) return .got;
            return .nl_symbol_ptr;
        },
        macho.S_LAZY_SYMBOL_POINTERS, 0x10 => return .la_symbol_ptr,
        macho.S_ZEROFILL, macho.S_GB_ZEROFILL => return if (eql(u8, sectname, "__common")) .common else .bss,
        macho.S_MOD_INIT_FUNC_POINTERS => return .mod_init,
        macho.S_MOD_TERM_FUNC_POINTERS => return .mod_term,
        macho.S_INIT_FUNC_OFFSETS => return .init_offsets,
        0x11, 0x12, 0x13, 0x14, 0x15 => return .thread_local,
        else => {},
    }
    const names = [_]struct { n: []const u8, c: SectionClass }{
        .{ .n = "__text", .c = .text },
        .{ .n = "__objc_stubs", .c = .objc_stubs },
        .{ .n = "__stub_helper", .c = .stub_helper },
        .{ .n = "__cstring", .c = .cstring },
        .{ .n = "__ustring", .c = .ustring },
        .{ .n = "__cfstring", .c = .cfstring },
        .{ .n = "__const", .c = .const_data },
        .{ .n = "__data", .c = .data },
        .{ .n = "__unwind_info", .c = .unwind },
        .{ .n = "__eh_frame", .c = .eh_frame },
        .{ .n = "__info_plist", .c = .info_plist },
        .{ .n = "__objc_methname", .c = .objc_methname },
        .{ .n = "__objc_classname", .c = .objc_classname },
        .{ .n = "__objc_methtype", .c = .objc_methtype },
        .{ .n = "__objc_methlist", .c = .objc_methlist },
        .{ .n = "__objc_classlist", .c = .objc_classlist },
        .{ .n = "__objc_nlclslist", .c = .objc_nlclslist },
        .{ .n = "__objc_catlist", .c = .objc_catlist },
        .{ .n = "__objc_nlcatlist", .c = .objc_nlcatlist },
        .{ .n = "__objc_protolist", .c = .objc_protolist },
        .{ .n = "__objc_imageinfo", .c = .objc_imageinfo },
        .{ .n = "__objc_selrefs", .c = .objc_selrefs },
        .{ .n = "__objc_classrefs", .c = .objc_classrefs },
        .{ .n = "__objc_superrefs", .c = .objc_superrefs },
        .{ .n = "__objc_const", .c = .objc_const },
        .{ .n = "__objc_data", .c = .objc_data },
        .{ .n = "__objc_ivar", .c = .objc_ivar },
        .{ .n = "__auth_got", .c = .auth_got },
        .{ .n = "__got", .c = .got },
        .{ .n = "__la_symbol_ptr", .c = .la_symbol_ptr },
        .{ .n = "__nl_symbol_ptr", .c = .nl_symbol_ptr },
        .{ .n = "__bss", .c = .bss },
        .{ .n = "__common", .c = .common },
        .{ .n = "__mod_init_func", .c = .mod_init },
        .{ .n = "__mod_term_func", .c = .mod_term },
        .{ .n = "__init_offsets", .c = .init_offsets },
    };
    for (names) |e| if (eql(u8, sectname, e.n)) return e.c;
    if (flags & macho.S_ATTR_PURE_INSTRUCTIONS != 0) return .text;
    return .other;
}

test "segments: classify and accessors" {
    try std.testing.expectEqual(SectionClass.text, classify("__TEXT", "__text", 0x80000400));
    try std.testing.expectEqual(SectionClass.stubs, classify("__TEXT", "__stubs", 0x80000408));
    try std.testing.expectEqual(SectionClass.auth_stubs, classify("__TEXT", "__auth_stubs", 0x80000408));
    try std.testing.expectEqual(SectionClass.cstring, classify("__TEXT", "__cstring", 0x2));
    try std.testing.expectEqual(SectionClass.objc_methname, classify("__TEXT", "__objc_methname", 0x2));
    try std.testing.expectEqual(SectionClass.got, classify("__DATA_CONST", "__got", 0x6));
    try std.testing.expectEqual(SectionClass.auth_got, classify("__DATA_CONST", "__auth_got", 0x6));
    try std.testing.expectEqual(SectionClass.la_symbol_ptr, classify("__DATA", "__la_symbol_ptr", 0x7));
    try std.testing.expectEqual(SectionClass.bss, classify("__DATA", "__bss", 0x1));
    try std.testing.expectEqual(SectionClass.common, classify("__DATA", "__common", 0x1));
    try std.testing.expectEqual(SectionClass.thread_local, classify("__DATA", "__thread_vars", 0x13));
    try std.testing.expectEqual(SectionClass.objc_stubs, classify("__TEXT", "__objc_stubs", 0x80000400));
    try std.testing.expectEqual(SectionClass.other, classify("__XHDR", "__xhdr", 0));
    const s = Section{ .index = 2, .segment = 1, .sectname = "__stubs", .segname = "__TEXT", .addr = 0x10000062c, .size = 0x3c, .offset = 1580, .@"align" = 2, .reloff = 0, .nreloc = 0, .flags = 0x80000408, .reserved1 = 0, .reserved2 = 12, .reserved3 = 0, .class = .stubs };
    try std.testing.expectEqual(@as(u8, 8), s.sectType());
    try std.testing.expect(s.isCode() and s.isSymbolStubs() and !s.isZerofill());
    try std.testing.expectEqual(@as(?u32, 12), s.entrySize());
    try std.testing.expect(s.containsVm(0x10000062c) and !s.containsVm(0x100000668));
    var buf: [3]u8 = undefined;
    const seg = Segment{ .index = 1, .name = "__TEXT", .vmaddr = 0x100000000, .vmsize = 0x4000, .fileoff = 0, .filesize = 16384, .maxprot = 5, .initprot = 5, .nsects = 4, .flags = 0, .cmd_offset = 104, .first_section = 0, .section_count = 4, .file_range_truncated = false };
    try std.testing.expectEqualStrings("r-x", seg.protString(&buf, .init));
    try std.testing.expect(seg.containsVm(0x100003fff) and !seg.containsVm(0x100004000));
}
