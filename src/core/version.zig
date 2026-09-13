//! core/version.zig — name tables for every Mach-O / code-signing enum. Imports: std, core/fmt.
//! Pure data; spellings follow the reference tool named on each table.
const std = @import("std");
const fmt = @import("fmt.zig");
pub const FlagName = fmt.FlagName;

const LC_REQ_DYLD: u32 = 0x80000000;

const Named = struct { v: u32, name: []const u8 };

fn lookup(table: []const Named, v: u32) ?[]const u8 {
    for (table) |e| if (e.v == v) return e.name;
    return null;
}

const lc_names = [_]Named{
    .{ .v = 0x1, .name = "LC_SEGMENT" },
    .{ .v = 0x2, .name = "LC_SYMTAB" },
    .{ .v = 0x3, .name = "LC_SYMSEG" },
    .{ .v = 0x4, .name = "LC_THREAD" },
    .{ .v = 0x5, .name = "LC_UNIXTHREAD" },
    .{ .v = 0x6, .name = "LC_LOADFVMLIB" },
    .{ .v = 0x7, .name = "LC_IDFVMLIB" },
    .{ .v = 0x8, .name = "LC_IDENT" },
    .{ .v = 0x9, .name = "LC_FVMFILE" },
    .{ .v = 0xa, .name = "LC_PREPAGE" },
    .{ .v = 0xb, .name = "LC_DYSYMTAB" },
    .{ .v = 0xc, .name = "LC_LOAD_DYLIB" },
    .{ .v = 0xd, .name = "LC_ID_DYLIB" },
    .{ .v = 0xe, .name = "LC_LOAD_DYLINKER" },
    .{ .v = 0xf, .name = "LC_ID_DYLINKER" },
    .{ .v = 0x10, .name = "LC_PREBOUND_DYLIB" },
    .{ .v = 0x11, .name = "LC_ROUTINES" },
    .{ .v = 0x12, .name = "LC_SUB_FRAMEWORK" },
    .{ .v = 0x13, .name = "LC_SUB_UMBRELLA" },
    .{ .v = 0x14, .name = "LC_SUB_CLIENT" },
    .{ .v = 0x15, .name = "LC_SUB_LIBRARY" },
    .{ .v = 0x16, .name = "LC_TWOLEVEL_HINTS" },
    .{ .v = 0x17, .name = "LC_PREBIND_CKSUM" },
    .{ .v = 0x18 | LC_REQ_DYLD, .name = "LC_LOAD_WEAK_DYLIB" },
    .{ .v = 0x19, .name = "LC_SEGMENT_64" },
    .{ .v = 0x1a, .name = "LC_ROUTINES_64" },
    .{ .v = 0x1b, .name = "LC_UUID" },
    .{ .v = 0x1c | LC_REQ_DYLD, .name = "LC_RPATH" },
    .{ .v = 0x1d, .name = "LC_CODE_SIGNATURE" },
    .{ .v = 0x1e, .name = "LC_SEGMENT_SPLIT_INFO" },
    .{ .v = 0x1f | LC_REQ_DYLD, .name = "LC_REEXPORT_DYLIB" },
    .{ .v = 0x20, .name = "LC_LAZY_LOAD_DYLIB" },
    .{ .v = 0x21, .name = "LC_ENCRYPTION_INFO" },
    .{ .v = 0x22, .name = "LC_DYLD_INFO" },
    .{ .v = 0x22 | LC_REQ_DYLD, .name = "LC_DYLD_INFO_ONLY" },
    .{ .v = 0x23 | LC_REQ_DYLD, .name = "LC_LOAD_UPWARD_DYLIB" },
    .{ .v = 0x24, .name = "LC_VERSION_MIN_MACOSX" },
    .{ .v = 0x25, .name = "LC_VERSION_MIN_IPHONEOS" },
    .{ .v = 0x26, .name = "LC_FUNCTION_STARTS" },
    .{ .v = 0x27, .name = "LC_DYLD_ENVIRONMENT" },
    .{ .v = 0x28 | LC_REQ_DYLD, .name = "LC_MAIN" },
    .{ .v = 0x29, .name = "LC_DATA_IN_CODE" },
    .{ .v = 0x2a, .name = "LC_SOURCE_VERSION" },
    .{ .v = 0x2b, .name = "LC_DYLIB_CODE_SIGN_DRS" },
    .{ .v = 0x2c, .name = "LC_ENCRYPTION_INFO_64" },
    .{ .v = 0x2d, .name = "LC_LINKER_OPTION" },
    .{ .v = 0x2e, .name = "LC_LINKER_OPTIMIZATION_HINT" },
    .{ .v = 0x2f, .name = "LC_VERSION_MIN_TVOS" },
    .{ .v = 0x30, .name = "LC_VERSION_MIN_WATCHOS" },
    .{ .v = 0x31, .name = "LC_NOTE" },
    .{ .v = 0x32, .name = "LC_BUILD_VERSION" },
    .{ .v = 0x33 | LC_REQ_DYLD, .name = "LC_DYLD_EXPORTS_TRIE" },
    .{ .v = 0x34 | LC_REQ_DYLD, .name = "LC_DYLD_CHAINED_FIXUPS" },
    .{ .v = 0x35 | LC_REQ_DYLD, .name = "LC_FILESET_ENTRY" },
    .{ .v = 0x36, .name = "LC_ATOM_INFO" },
    .{ .v = 0x37, .name = "LC_FUNCTION_VARIANTS" },
    .{ .v = 0x38, .name = "LC_FUNCTION_VARIANT_FIXUPS" },
    .{ .v = 0x39, .name = "LC_TARGET_TRIPLE" },
    .{ .v = 0x3a, .name = "LC_LAZY_LOAD_DYLIB_INFO" },
};

/// "LC_SEGMENT_64" ...; null for unknown values (callers print "LC_?(0x..)").
pub fn lcName(cmd: u32) ?[]const u8 {
    return lookup(&lc_names, cmd);
}
/// Always yields a name: "LC_SEGMENT_64" or "LC_?(0x39)".
pub fn lcNameBuf(buf: *[32]u8, cmd: u32) []const u8 {
    if (lcName(cmd)) |n| return n;
    return std.fmt.bufPrint(buf, "LC_?(0x{x})", .{cmd}) catch "LC_?";
}

const filetype_names = [_]Named{
    .{ .v = 0x1, .name = "MH_OBJECT" },      .{ .v = 0x2, .name = "MH_EXECUTE" },     .{ .v = 0x3, .name = "MH_FVMLIB" },
    .{ .v = 0x4, .name = "MH_CORE" },        .{ .v = 0x5, .name = "MH_PRELOAD" },     .{ .v = 0x6, .name = "MH_DYLIB" },
    .{ .v = 0x7, .name = "MH_DYLINKER" },    .{ .v = 0x8, .name = "MH_BUNDLE" },      .{ .v = 0x9, .name = "MH_DYLIB_STUB" },
    .{ .v = 0xa, .name = "MH_DSYM" },        .{ .v = 0xb, .name = "MH_KEXT_BUNDLE" }, .{ .v = 0xc, .name = "MH_FILESET" },
    .{ .v = 0xd, .name = "MH_GPU_EXECUTE" }, .{ .v = 0xe, .name = "MH_GPU_DYLIB" },
};
pub fn filetypeName(ft: u32) ?[]const u8 {
    return lookup(&filetype_names, ft);
}

const platform_names = [_]Named{
    .{ .v = 0, .name = "unknown" },              .{ .v = 0xffffffff, .name = "any" },
    .{ .v = 1, .name = "macOS" },                .{ .v = 2, .name = "iOS" },
    .{ .v = 3, .name = "tvOS" },                 .{ .v = 4, .name = "watchOS" },
    .{ .v = 5, .name = "bridgeOS" },             .{ .v = 6, .name = "macCatalyst" },
    .{ .v = 7, .name = "iOSSimulator" },         .{ .v = 8, .name = "tvOSSimulator" },
    .{ .v = 9, .name = "watchOSSimulator" },     .{ .v = 10, .name = "driverKit" },
    .{ .v = 11, .name = "visionOS" },            .{ .v = 12, .name = "visionOSSimulator" },
    .{ .v = 13, .name = "firmware" },            .{ .v = 14, .name = "sepOS" },
    .{ .v = 15, .name = "macOSExclaveCore" },    .{ .v = 16, .name = "macOSExclaveKit" },
    .{ .v = 17, .name = "iOSExclaveCore" },      .{ .v = 18, .name = "iOSExclaveKit" },
    .{ .v = 19, .name = "tvOSExclaveCore" },     .{ .v = 20, .name = "tvOSExclaveKit" },
    .{ .v = 21, .name = "watchOSExclaveCore" },  .{ .v = 22, .name = "watchOSExclaveKit" },
    .{ .v = 23, .name = "visionOSExclaveCore" }, .{ .v = 24, .name = "visionOSExclaveKit" },
};
pub fn platformName(p: u32) ?[]const u8 {
    return lookup(&platform_names, p);
}

const tool_names = [_]Named{
    .{ .v = 1, .name = "clang" },          .{ .v = 2, .name = "swift" },              .{ .v = 3, .name = "ld" },
    .{ .v = 4, .name = "lld" },            .{ .v = 1024, .name = "metal" },           .{ .v = 1025, .name = "airlld" },
    .{ .v = 1026, .name = "airnt" },       .{ .v = 1027, .name = "airnt_plugin" },    .{ .v = 1028, .name = "airpack" },
    .{ .v = 1031, .name = "gpuarchiver" }, .{ .v = 1032, .name = "metal_framework" },
};
pub fn toolName(t: u32) ?[]const u8 {
    return lookup(&tool_names, t);
}

pub fn cpuTypeName(cputype: i32) ?[]const u8 {
    return switch (cputype) {
        -1 => "any",
        7 => "x86",
        12 => "arm",
        18 => "powerpc",
        0x01000007 => "x86_64",
        0x0100000c => "arm64",
        0x0200000c => "arm64_32",
        0x01000012 => "powerpc64",
        else => null,
    };
}

const section_type_names = [_][]const u8{
    "S_REGULAR",                             "S_ZEROFILL",                   "S_CSTRING_LITERALS",
    "S_4BYTE_LITERALS",                      "S_8BYTE_LITERALS",             "S_LITERAL_POINTERS",
    "S_NON_LAZY_SYMBOL_POINTERS",            "S_LAZY_SYMBOL_POINTERS",       "S_SYMBOL_STUBS",
    "S_MOD_INIT_FUNC_POINTERS",              "S_MOD_TERM_FUNC_POINTERS",     "S_COALESCED",
    "S_GB_ZEROFILL",                         "S_INTERPOSING",                "S_16BYTE_LITERALS",
    "S_DTRACE_DOF",                          "S_LAZY_DYLIB_SYMBOL_POINTERS", "S_THREAD_LOCAL_REGULAR",
    "S_THREAD_LOCAL_ZEROFILL",               "S_THREAD_LOCAL_VARIABLES",     "S_THREAD_LOCAL_VARIABLE_POINTERS",
    "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS", "S_INIT_FUNC_OFFSETS",
};
pub fn sectionTypeName(t: u8) ?[]const u8 {
    if (t < section_type_names.len) return section_type_names[t];
    return null;
}

const stab_names = [_]Named{
    .{ .v = 0x20, .name = "GSYM" },    .{ .v = 0x22, .name = "FNAME" },  .{ .v = 0x24, .name = "FUN" },   .{ .v = 0x26, .name = "STSYM" },
    .{ .v = 0x28, .name = "LCSYM" },   .{ .v = 0x2e, .name = "BNSYM" },  .{ .v = 0x30, .name = "PC" },    .{ .v = 0x32, .name = "AST" },
    .{ .v = 0x3c, .name = "OPT" },     .{ .v = 0x40, .name = "RSYM" },   .{ .v = 0x44, .name = "SLINE" }, .{ .v = 0x4e, .name = "ENSYM" },
    .{ .v = 0x60, .name = "SSYM" },    .{ .v = 0x64, .name = "SO" },     .{ .v = 0x66, .name = "OSO" },   .{ .v = 0x68, .name = "LIB" },
    .{ .v = 0x80, .name = "LSYM" },    .{ .v = 0x82, .name = "BINCL" },  .{ .v = 0x84, .name = "SOL" },   .{ .v = 0x86, .name = "PARAMS" },
    .{ .v = 0x88, .name = "VERSION" }, .{ .v = 0x8a, .name = "OLEVEL" }, .{ .v = 0xa0, .name = "PSYM" },  .{ .v = 0xa2, .name = "EINCL" },
    .{ .v = 0xa4, .name = "ENTRY" },   .{ .v = 0xc0, .name = "LBRAC" },  .{ .v = 0xc2, .name = "EXCL" },  .{ .v = 0xe0, .name = "RBRAC" },
    .{ .v = 0xe2, .name = "BCOMM" },   .{ .v = 0xe4, .name = "ECOMM" },  .{ .v = 0xe8, .name = "ECOML" }, .{ .v = 0xfe, .name = "LENG" },
};
/// nm -a spelling without the N_ prefix ("FUN", "SO", ...).
pub fn stabName(n_type: u8) ?[]const u8 {
    return lookup(&stab_names, n_type);
}

const pointer_format_names = [_][]const u8{
    "DYLD_CHAINED_PTR_ARM64E",              "DYLD_CHAINED_PTR_64",                  "DYLD_CHAINED_PTR_32",
    "DYLD_CHAINED_PTR_32_CACHE",            "DYLD_CHAINED_PTR_32_FIRMWARE",         "DYLD_CHAINED_PTR_64_OFFSET",
    "DYLD_CHAINED_PTR_ARM64E_KERNEL",       "DYLD_CHAINED_PTR_64_KERNEL_CACHE",     "DYLD_CHAINED_PTR_ARM64E_USERLAND",
    "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",     "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE", "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
    "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE", "DYLD_CHAINED_PTR_ARM64E_SEGMENTED",
};
pub fn pointerFormatName(pf: u16) ?[]const u8 {
    if (pf >= 1 and pf <= pointer_format_names.len) return pointer_format_names[pf - 1];
    return null;
}
pub fn importFormatName(f: u32) ?[]const u8 {
    return switch (f) {
        1 => "DYLD_CHAINED_IMPORT",
        2 => "DYLD_CHAINED_IMPORT_ADDEND",
        3 => "DYLD_CHAINED_IMPORT_ADDEND64",
        else => null,
    };
}
pub fn diceKindName(kind: u16) ?[]const u8 {
    return switch (kind) {
        1 => "DICE_KIND_DATA",
        2 => "DICE_KIND_JUMP_TABLE8",
        3 => "DICE_KIND_JUMP_TABLE16",
        4 => "DICE_KIND_JUMP_TABLE32",
        5 => "DICE_KIND_ABS_JUMP_TABLE32",
        else => null,
    };
}
pub fn csSlotName(slot: u32) ?[]const u8 {
    return switch (slot) {
        0 => "CSSLOT_CODEDIRECTORY",
        1 => "CSSLOT_INFOSLOT",
        2 => "CSSLOT_REQUIREMENTS",
        3 => "CSSLOT_RESOURCEDIR",
        4 => "CSSLOT_APPLICATION",
        5 => "CSSLOT_ENTITLEMENTS",
        7 => "CSSLOT_DER_ENTITLEMENTS",
        8 => "CSSLOT_LAUNCH_CONSTRAINT_SELF",
        9 => "CSSLOT_LAUNCH_CONSTRAINT_PARENT",
        10 => "CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE",
        11 => "CSSLOT_LIBRARY_CONSTRAINT",
        0x1000 => "CSSLOT_ALTERNATE_CODEDIRECTORIES",
        0x1001 => "CSSLOT_ALTERNATE_CODEDIRECTORIES+1",
        0x1002 => "CSSLOT_ALTERNATE_CODEDIRECTORIES+2",
        0x1003 => "CSSLOT_ALTERNATE_CODEDIRECTORIES+3",
        0x1004 => "CSSLOT_ALTERNATE_CODEDIRECTORIES+4",
        0x10000 => "CSSLOT_SIGNATURESLOT",
        0x10001 => "CSSLOT_IDENTIFICATIONSLOT",
        0x10002 => "CSSLOT_TICKETSLOT",
        else => null,
    };
}
pub fn csMagicName(magic: u32) ?[]const u8 {
    return switch (magic) {
        0xfade0c00 => "CSMAGIC_REQUIREMENT",
        0xfade0c01 => "CSMAGIC_REQUIREMENTS",
        0xfade0c02 => "CSMAGIC_CODEDIRECTORY",
        0xfade0cc0 => "CSMAGIC_EMBEDDED_SIGNATURE",
        0xfade0b02 => "CSMAGIC_EMBEDDED_SIGNATURE_OLD",
        0xfade0cc1 => "CSMAGIC_DETACHED_SIGNATURE",
        0xfade7171 => "CSMAGIC_EMBEDDED_ENTITLEMENTS",
        0xfade7172 => "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS",
        0xfade0b01 => "CSMAGIC_BLOBWRAPPER",
        0xfade8181 => "CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT",
        else => null,
    };
}
/// Special (negative) CodeDirectory slot names, 1-based (`-n` in codesign terms).
pub fn csSpecialSlotName(index: u32) ?[]const u8 {
    return switch (index) {
        1 => "Info.plist",
        2 => "Requirements",
        3 => "Resource Directory",
        4 => "Application Specific",
        5 => "Entitlements",
        6 => "Rep Specific",
        7 => "DER Entitlements",
        8 => "Launch Constraint (self)",
        9 => "Launch Constraint (parent)",
        10 => "Launch Constraint (responsible)",
        11 => "Library Constraint",
        else => null,
    };
}
/// codesign spelling: "sha1", "sha256", "sha256_truncated", "sha384".
pub fn csHashTypeName(t: u8) ?[]const u8 {
    return switch (t) {
        1 => "sha1",
        2 => "sha256",
        3 => "sha256_truncated",
        4 => "sha384",
        else => null,
    };
}
pub fn magicName(magic: u32) ?[]const u8 {
    return switch (magic) {
        0xfeedface => "MH_MAGIC",
        0xcefaedfe => "MH_CIGAM",
        0xfeedfacf => "MH_MAGIC_64",
        0xcffaedfe => "MH_CIGAM_64",
        0xcafebabe => "FAT_MAGIC",
        0xbebafeca => "FAT_CIGAM",
        0xcafebabf => "FAT_MAGIC_64",
        0xbfbafeca => "FAT_CIGAM_64",
        else => null,
    };
}
/// dyld_info-style short name: "/usr/lib/libSystem.B.dylib" -> "libSystem", ".../Foundation.framework/Versions/C/Foundation" -> "Foundation".
pub fn dylibShortName(path: []const u8) []const u8 {
    var name = path;
    if (std.mem.findScalarLast(u8, name, '/')) |i| name = name[i + 1 ..];
    if (std.mem.endsWith(u8, name, ".dylib")) {
        name = name[0 .. name.len - ".dylib".len];
        if (std.mem.findScalarLast(u8, name, '.')) |i| name = name[0..i];
    }
    return name;
}

/// Flag tables (bit, name) in the spelling of the reference tool named in the comment.
pub const mh_flags: []const FlagName = &.{ // otool -hv spelling: NOUNDEFS DYLDLINK TWOLEVEL PIE ...
    .{ .bit = 0x1, .name = "NOUNDEFS" },
    .{ .bit = 0x2, .name = "INCRLINK" },
    .{ .bit = 0x4, .name = "DYLDLINK" },
    .{ .bit = 0x8, .name = "BINDATLOAD" },
    .{ .bit = 0x10, .name = "PREBOUND" },
    .{ .bit = 0x20, .name = "SPLIT_SEGS" },
    .{ .bit = 0x40, .name = "LAZY_INIT" },
    .{ .bit = 0x80, .name = "TWOLEVEL" },
    .{ .bit = 0x100, .name = "FORCE_FLAT" },
    .{ .bit = 0x200, .name = "NOMULTIDEFS" },
    .{ .bit = 0x400, .name = "NOFIXPREBINDING" },
    .{ .bit = 0x800, .name = "PREBINDABLE" },
    .{ .bit = 0x1000, .name = "ALLMODSBOUND" },
    .{ .bit = 0x2000, .name = "SUBSECTIONS_VIA_SYMBOLS" },
    .{ .bit = 0x4000, .name = "CANONICAL" },
    .{ .bit = 0x8000, .name = "WEAK_DEFINES" },
    .{ .bit = 0x10000, .name = "BINDS_TO_WEAK" },
    .{ .bit = 0x20000, .name = "ALLOW_STACK_EXECUTION" },
    .{ .bit = 0x40000, .name = "ROOT_SAFE" },
    .{ .bit = 0x80000, .name = "SETUID_SAFE" },
    .{ .bit = 0x100000, .name = "NO_REEXPORTED_DYLIBS" },
    .{ .bit = 0x200000, .name = "PIE" },
    .{ .bit = 0x400000, .name = "DEAD_STRIPPABLE_DYLIB" },
    .{ .bit = 0x800000, .name = "MH_HAS_TLV_DESCRIPTORS" },
    .{ .bit = 0x1000000, .name = "MH_NO_HEAP_EXECUTION" },
    .{ .bit = 0x2000000, .name = "APP_EXTENSION_SAFE" },
    .{ .bit = 0x4000000, .name = "NLIST_OUTOFSYNC_WITH_DYLDINFO" },
    .{ .bit = 0x8000000, .name = "SIM_SUPPORT" },
    .{ .bit = 0x80000000, .name = "DYLIB_IN_CACHE" },
};
pub const mh_flags_full: []const FlagName = &.{ // summary.json spelling: MH_NOUNDEFS ...
    .{ .bit = 0x1, .name = "MH_NOUNDEFS" },
    .{ .bit = 0x2, .name = "MH_INCRLINK" },
    .{ .bit = 0x4, .name = "MH_DYLDLINK" },
    .{ .bit = 0x8, .name = "MH_BINDATLOAD" },
    .{ .bit = 0x10, .name = "MH_PREBOUND" },
    .{ .bit = 0x20, .name = "MH_SPLIT_SEGS" },
    .{ .bit = 0x40, .name = "MH_LAZY_INIT" },
    .{ .bit = 0x80, .name = "MH_TWOLEVEL" },
    .{ .bit = 0x100, .name = "MH_FORCE_FLAT" },
    .{ .bit = 0x200, .name = "MH_NOMULTIDEFS" },
    .{ .bit = 0x400, .name = "MH_NOFIXPREBINDING" },
    .{ .bit = 0x800, .name = "MH_PREBINDABLE" },
    .{ .bit = 0x1000, .name = "MH_ALLMODSBOUND" },
    .{ .bit = 0x2000, .name = "MH_SUBSECTIONS_VIA_SYMBOLS" },
    .{ .bit = 0x4000, .name = "MH_CANONICAL" },
    .{ .bit = 0x8000, .name = "MH_WEAK_DEFINES" },
    .{ .bit = 0x10000, .name = "MH_BINDS_TO_WEAK" },
    .{ .bit = 0x20000, .name = "MH_ALLOW_STACK_EXECUTION" },
    .{ .bit = 0x40000, .name = "MH_ROOT_SAFE" },
    .{ .bit = 0x80000, .name = "MH_SETUID_SAFE" },
    .{ .bit = 0x100000, .name = "MH_NO_REEXPORTED_DYLIBS" },
    .{ .bit = 0x200000, .name = "MH_PIE" },
    .{ .bit = 0x400000, .name = "MH_DEAD_STRIPPABLE_DYLIB" },
    .{ .bit = 0x800000, .name = "MH_HAS_TLV_DESCRIPTORS" },
    .{ .bit = 0x1000000, .name = "MH_NO_HEAP_EXECUTION" },
    .{ .bit = 0x2000000, .name = "MH_APP_EXTENSION_SAFE" },
    .{ .bit = 0x4000000, .name = "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO" },
    .{ .bit = 0x8000000, .name = "MH_SIM_SUPPORT" },
    .{ .bit = 0x10000000, .name = "MH_IMPLICIT_PAGEZERO" },
    .{ .bit = 0x80000000, .name = "MH_DYLIB_IN_CACHE" },
};
pub const sg_flags: []const FlagName = &.{ // SG_HIGHVM ... SG_READ_ONLY
    .{ .bit = 0x1, .name = "SG_HIGHVM" },
    .{ .bit = 0x2, .name = "SG_FVMLIB" },
    .{ .bit = 0x4, .name = "SG_NORELOC" },
    .{ .bit = 0x8, .name = "SG_PROTECTED_VERSION_1" },
    .{ .bit = 0x10, .name = "SG_READ_ONLY" },
};
pub const s_attr_flags: []const FlagName = &.{ // S_ATTR_PURE_INSTRUCTIONS ...
    .{ .bit = 0x80000000, .name = "S_ATTR_PURE_INSTRUCTIONS" },
    .{ .bit = 0x40000000, .name = "S_ATTR_NO_TOC" },
    .{ .bit = 0x20000000, .name = "S_ATTR_STRIP_STATIC_SYMS" },
    .{ .bit = 0x10000000, .name = "S_ATTR_NO_DEAD_STRIP" },
    .{ .bit = 0x08000000, .name = "S_ATTR_LIVE_SUPPORT" },
    .{ .bit = 0x04000000, .name = "S_ATTR_SELF_MODIFYING_CODE" },
    .{ .bit = 0x02000000, .name = "S_ATTR_DEBUG" },
    .{ .bit = 0x00000400, .name = "S_ATTR_SOME_INSTRUCTIONS" },
    .{ .bit = 0x00000200, .name = "S_ATTR_EXT_RELOC" },
    .{ .bit = 0x00000100, .name = "S_ATTR_LOC_RELOC" },
};
pub const cs_flags: []const FlagName = &.{ // codesign spelling: adhoc linker-signed runtime ... (CD flags)
    .{ .bit = 0x1, .name = "valid" },
    .{ .bit = 0x2, .name = "adhoc" },
    .{ .bit = 0x4, .name = "get-task-allow" },
    .{ .bit = 0x8, .name = "installer" },
    .{ .bit = 0x10, .name = "forced-lv" },
    .{ .bit = 0x20, .name = "invalid-allowed" },
    .{ .bit = 0x100, .name = "hard" },
    .{ .bit = 0x200, .name = "kill" },
    .{ .bit = 0x400, .name = "check-expiration" },
    .{ .bit = 0x800, .name = "restrict" },
    .{ .bit = 0x1000, .name = "enforcement" },
    .{ .bit = 0x2000, .name = "library-validation" },
    .{ .bit = 0x4000, .name = "entitlements-validated" },
    .{ .bit = 0x8000, .name = "nvram-unrestricted" },
    .{ .bit = 0x10000, .name = "runtime" },
    .{ .bit = 0x20000, .name = "linker-signed" },
};
pub const cs_flags_full: []const FlagName = &.{ // summary.json spelling: CS_ADHOC CS_LINKER_SIGNED ...
    .{ .bit = 0x1, .name = "CS_VALID" },
    .{ .bit = 0x2, .name = "CS_ADHOC" },
    .{ .bit = 0x4, .name = "CS_GET_TASK_ALLOW" },
    .{ .bit = 0x8, .name = "CS_INSTALLER" },
    .{ .bit = 0x10, .name = "CS_FORCED_LV" },
    .{ .bit = 0x20, .name = "CS_INVALID_ALLOWED" },
    .{ .bit = 0x100, .name = "CS_HARD" },
    .{ .bit = 0x200, .name = "CS_KILL" },
    .{ .bit = 0x400, .name = "CS_CHECK_EXPIRATION" },
    .{ .bit = 0x800, .name = "CS_RESTRICT" },
    .{ .bit = 0x1000, .name = "CS_ENFORCEMENT" },
    .{ .bit = 0x2000, .name = "CS_REQUIRE_LV" },
    .{ .bit = 0x4000, .name = "CS_ENTITLEMENTS_VALIDATED" },
    .{ .bit = 0x8000, .name = "CS_NVRAM_UNRESTRICTED" },
    .{ .bit = 0x10000, .name = "CS_RUNTIME" },
    .{ .bit = 0x20000, .name = "CS_LINKER_SIGNED" },
};
pub const exec_seg_flags: []const FlagName = &.{ // main-binary allow-unsigned debugger jit skip-lv can-load-cdhash can-exec-cdhash
    .{ .bit = 0x1, .name = "main-binary" },
    .{ .bit = 0x10, .name = "allow-unsigned" },
    .{ .bit = 0x20, .name = "debugger" },
    .{ .bit = 0x40, .name = "jit" },
    .{ .bit = 0x80, .name = "skip-lv" },
    .{ .bit = 0x100, .name = "can-load-cdhash" },
    .{ .bit = 0x200, .name = "can-exec-cdhash" },
};
pub const n_desc_flags: []const FlagName = &.{ // REFERENCED_DYNAMICALLY N_WEAK_REF N_WEAK_DEF ...
    .{ .bit = 0x0008, .name = "N_ARM_THUMB_DEF" },
    .{ .bit = 0x0010, .name = "REFERENCED_DYNAMICALLY" },
    .{ .bit = 0x0020, .name = "N_NO_DEAD_STRIP" },
    .{ .bit = 0x0040, .name = "N_WEAK_REF" },
    .{ .bit = 0x0080, .name = "N_WEAK_DEF" },
    .{ .bit = 0x0100, .name = "N_SYMBOL_RESOLVER" },
    .{ .bit = 0x0200, .name = "N_ALT_ENTRY" },
    .{ .bit = 0x0400, .name = "N_COLD_FUNC" },
};
pub const export_flags: []const FlagName = &.{ // WEAK_DEFINITION REEXPORT STUB_AND_RESOLVER STATIC_RESOLVER
    .{ .bit = 0x04, .name = "WEAK_DEFINITION" },
    .{ .bit = 0x08, .name = "REEXPORT" },
    .{ .bit = 0x10, .name = "STUB_AND_RESOLVER" },
    .{ .bit = 0x20, .name = "STATIC_RESOLVER" },
};
pub const objc_ro_flags: []const FlagName = &.{ // RO_META RO_ROOT ... RO_IS_ARC
    .{ .bit = 1 << 0, .name = "RO_META" },
    .{ .bit = 1 << 1, .name = "RO_ROOT" },
    .{ .bit = 1 << 2, .name = "RO_HAS_CXX_STRUCTORS" },
    .{ .bit = 1 << 4, .name = "RO_HIDDEN" },
    .{ .bit = 1 << 5, .name = "RO_EXCEPTION" },
    .{ .bit = 1 << 6, .name = "RO_HAS_SWIFT_INITIALIZER" },
    .{ .bit = 1 << 7, .name = "RO_IS_ARC" },
    .{ .bit = 1 << 8, .name = "RO_HAS_CXX_DTOR_ONLY" },
    .{ .bit = 1 << 9, .name = "RO_HAS_WEAK_WITHOUT_ARC" },
    .{ .bit = 1 << 10, .name = "RO_FORBIDS_ASSOCIATED_OBJECTS" },
    .{ .bit = 1 << 29, .name = "RO_FROM_BUNDLE" },
    .{ .bit = 1 << 30, .name = "RO_FUTURE" },
    .{ .bit = 1 << 31, .name = "RO_REALIZED" },
};
pub const objc_image_info_flags: []const FlagName = &.{
    .{ .bit = 1 << 0, .name = "IS_REPLACEMENT" },
    .{ .bit = 1 << 1, .name = "SUPPORTS_GC" },
    .{ .bit = 1 << 2, .name = "REQUIRES_GC" },
    .{ .bit = 1 << 3, .name = "OPTIMIZED_BY_DYLD" },
    .{ .bit = 1 << 4, .name = "CORRECTED_SYNTHESIZE" },
    .{ .bit = 1 << 5, .name = "IS_SIMULATED" },
    .{ .bit = 1 << 6, .name = "HAS_CATEGORY_CLASS_PROPERTIES" },
    .{ .bit = 1 << 7, .name = "OPTIMIZED_BY_DYLD_CLOSURE" },
};

test "version: name tables" {
    try std.testing.expectEqualStrings("LC_SEGMENT_64", lcName(0x19).?);
    try std.testing.expectEqualStrings("LC_MAIN", lcName(0x80000028).?);
    try std.testing.expect(lcName(0x99) == null);
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("LC_?(0x99)", lcNameBuf(&buf, 0x99));
    try std.testing.expectEqualStrings("MH_EXECUTE", filetypeName(2).?);
    try std.testing.expectEqualStrings("macOS", platformName(1).?);
    try std.testing.expectEqualStrings("ld", toolName(3).?);
    try std.testing.expect(toolName(5) == null);
    try std.testing.expectEqualStrings("S_SYMBOL_STUBS", sectionTypeName(8).?);
    try std.testing.expect(sectionTypeName(0x17) == null);
    try std.testing.expectEqualStrings("DYLD_CHAINED_PTR_64_OFFSET", pointerFormatName(6).?);
    try std.testing.expectEqualStrings("libSystem", dylibShortName("/usr/lib/libSystem.B.dylib"));
    try std.testing.expectEqualStrings("libncurses.5", dylibShortName("/usr/lib/libncurses.5.4.dylib"));
    try std.testing.expectEqualStrings("Foundation", dylibShortName("/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"));
    try std.testing.expectEqualStrings("libhello", dylibShortName("@rpath/libhello.dylib"));
    try std.testing.expectEqualStrings("FUN", stabName(0x24).?);
    try std.testing.expectEqualStrings("MH_MAGIC_64", magicName(0xfeedfacf).?);
    try std.testing.expectFmt("0x200085 (NOUNDEFS,DYLDLINK,TWOLEVEL,PIE)", "{f}", .{fmt.Flags{ .value = 0x200085, .table = mh_flags }});
}
