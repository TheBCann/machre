//! core/macho_extra.zig — declarations std.macho lacks (all `extern struct`, little-endian on disk,
//! offsets from docs/format-notes.md). Data only; no logic. Imports: std only.
const std = @import("std");

pub const fat_arch_64 = extern struct { cputype: i32, cpusubtype: i32, offset: u64, size: u64, @"align": u32, reserved: u32 };
pub const encryption_info_command = extern struct { cmd: u32, cmdsize: u32, cryptoff: u32, cryptsize: u32, cryptid: u32 };
pub const encryption_info_command_64 = extern struct { cmd: u32, cmdsize: u32, cryptoff: u32, cryptsize: u32, cryptid: u32, pad: u32 };
pub const dylib_use_command = extern struct { cmd: u32, cmdsize: u32, nameoff: u32, marker: u32, current_version: u32, compat_version: u32, flags: u32 };
pub const DYLIB_USE_MARKER: u32 = 0x1a741800;
pub const DYLIB_USE_WEAK_LINK: u32 = 0x01;
pub const DYLIB_USE_REEXPORT: u32 = 0x02;
pub const DYLIB_USE_UPWARD: u32 = 0x04;
pub const DYLIB_USE_DELAYED_INIT: u32 = 0x08;
pub const thread_command = extern struct { cmd: u32, cmdsize: u32 }; // then { flavor: u32, count: u32, state[count] } repeated
pub const x86_THREAD_STATE64: u32 = 4; // count 42; rip at state byte offset 128
pub const ARM_THREAD_STATE64: u32 = 6; // count 68; pc at state byte offset 256
pub const x86_THREAD_STATE64_RIP_OFFSET: u32 = 128;
pub const ARM_THREAD_STATE64_PC_OFFSET: u32 = 256;
pub const fileset_entry_command = extern struct { cmd: u32, cmdsize: u32, vmaddr: u64, fileoff: u64, entry_id: u32, reserved: u32 };
pub const note_command = extern struct { cmd: u32, cmdsize: u32, data_owner: [16]u8, offset: u64, size: u64 };
pub const routines_command_64 = extern struct { cmd: u32, cmdsize: u32, init_address: u64, init_module: u64, reserved1: u64, reserved2: u64, reserved3: u64, reserved4: u64, reserved5: u64, reserved6: u64 };
pub const linker_option_command = extern struct { cmd: u32, cmdsize: u32, count: u32 };
pub const lc_str_command = extern struct { cmd: u32, cmdsize: u32, str_offset: u32 }; // rpath, dylinker, sub_*, target_triple, dyld_environment
pub const prebound_dylib_command = extern struct { cmd: u32, cmdsize: u32, name: u32, nmodules: u32, linked_modules: u32 };
pub const twolevel_hints_command = extern struct { cmd: u32, cmdsize: u32, offset: u32, nhints: u32 };
pub const prebind_cksum_command = extern struct { cmd: u32, cmdsize: u32, cksum: u32 };

pub const LC_REQ_DYLD: u32 = 0x80000000;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
pub const LC_ATOM_INFO: u32 = 0x36;
pub const LC_FUNCTION_VARIANTS: u32 = 0x37;
pub const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
pub const LC_TARGET_TRIPLE: u32 = 0x39;
pub const LC_LAZY_LOAD_DYLIB_INFO: u32 = 0x3a;
pub const MH_FILESET: u32 = 0xc;
pub const MH_GPU_EXECUTE: u32 = 0xd;
pub const MH_GPU_DYLIB: u32 = 0xe;
pub const CPU_SUBTYPE_MASK: u32 = 0xff000000;
pub const CPU_SUBTYPE_LIB64: u32 = 0x80000000;
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x80000000;
pub const CPU_SUBTYPE_ARM64_PTR_AUTH_MASK: u32 = 0x0f000000;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
pub const CPU_SUBTYPE_ARM64_32_V8: u32 = 1;
pub const CPU_TYPE_ARM64_32: i32 = 0x0200000c;

// cs_blobs.h: CodeDirectory flags not in std.macho
pub const CS_VALID: u32 = 0x1;
pub const CS_GET_TASK_ALLOW: u32 = 0x4;
pub const CS_INSTALLER: u32 = 0x8;
pub const CS_FORCED_LV: u32 = 0x10;
pub const CS_INVALID_ALLOWED: u32 = 0x20;
pub const CS_HARD: u32 = 0x100;
pub const CS_KILL: u32 = 0x200;
pub const CS_CHECK_EXPIRATION: u32 = 0x400;
pub const CS_RESTRICT: u32 = 0x800;
pub const CS_ENFORCEMENT: u32 = 0x1000;
pub const CS_REQUIRE_LV: u32 = 0x2000;
pub const CS_ENTITLEMENTS_VALIDATED: u32 = 0x4000;
pub const CS_NVRAM_UNRESTRICTED: u32 = 0x8000;
pub const CS_RUNTIME: u32 = 0x10000;
pub const CS_LINKER_SIGNED: u32 = 0x20000;
pub const CS_SUPPORTSSCATTER: u32 = 0x20100;
pub const CS_SUPPORTSTEAMID: u32 = 0x20200;
pub const CS_SUPPORTSCODELIMIT64: u32 = 0x20300;
pub const CS_SUPPORTSEXECSEG: u32 = 0x20400;
pub const CS_SUPPORTSRUNTIME: u32 = 0x20500;
pub const CS_SUPPORTSLINKAGE: u32 = 0x20600;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_RESOURCEDIR: u32 = 3;
pub const CSSLOT_APPLICATION: u32 = 4;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
pub const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 8;
pub const CSSLOT_LAUNCH_CONSTRAINT_PARENT: u32 = 9;
pub const CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: u32 = 10;
pub const CSSLOT_LIBRARY_CONSTRAINT: u32 = 11;
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
pub const CSSLOT_IDENTIFICATIONSLOT: u32 = 0x10001;
pub const CSSLOT_TICKETSLOT: u32 = 0x10002;
pub const CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: u32 = 0xfade8181;
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
pub const CS_EXECSEG_ALLOW_UNSIGNED: u64 = 0x10;
pub const CS_EXECSEG_DEBUGGER: u64 = 0x20;
pub const CS_EXECSEG_JIT: u64 = 0x40;
pub const CS_EXECSEG_SKIP_LV: u64 = 0x80;
pub const CS_EXECSEG_CAN_LOAD_CDHASH: u64 = 0x100;
pub const CS_EXECSEG_CAN_EXEC_CDHASH: u64 = 0x200;

// fixup-chains.h
pub const dyld_chained_fixups_header = extern struct { fixups_version: u32, starts_offset: u32, imports_offset: u32, symbols_offset: u32, imports_count: u32, imports_format: u32, symbols_format: u32 };
pub const dyld_chained_starts_in_segment_header = extern struct { size: u32, page_size: u16, pointer_format: u16, segment_offset: u64, max_valid_pointer: u32, page_count: u16 }; // page_start[] follows at +22
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;
pub const BIND_SPECIAL_DYLIB_SELF: i32 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i32 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i32 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i32 = -3;

// objc-runtime-new.h field offsets (64-bit)
pub const objc = struct {
    pub const class_isa: u32 = 0;
    pub const class_superclass: u32 = 8;
    pub const class_cache: u32 = 16;
    pub const class_vtable: u32 = 24;
    pub const class_data: u32 = 32;
    pub const class_size: u32 = 40;
    pub const FAST_DATA_MASK: u64 = 0x00007ffffffffff8;
    pub const FAST_IS_SWIFT_LEGACY: u64 = 1;
    pub const FAST_IS_SWIFT_STABLE: u64 = 2;
    pub const PTR_MASK: u64 = 0x00007fffffffffff; // strip PAC / high8 before use
    pub const ro_flags: u32 = 0;
    pub const ro_instance_start: u32 = 4;
    pub const ro_instance_size: u32 = 8;
    pub const ro_ivar_layout: u32 = 16;
    pub const ro_name: u32 = 24;
    pub const ro_base_methods: u32 = 32;
    pub const ro_base_protocols: u32 = 40;
    pub const ro_ivars: u32 = 48;
    pub const ro_weak_ivar_layout: u32 = 56;
    pub const ro_base_properties: u32 = 64;
    pub const ro_size: u32 = 72;
    pub const RO_META: u32 = 1 << 0;
    pub const RO_ROOT: u32 = 1 << 1;
    pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;
    pub const RO_HIDDEN: u32 = 1 << 4;
    pub const RO_EXCEPTION: u32 = 1 << 5;
    pub const RO_HAS_SWIFT_INITIALIZER: u32 = 1 << 6;
    pub const RO_IS_ARC: u32 = 1 << 7;
    pub const RO_HAS_CXX_DTOR_ONLY: u32 = 1 << 8;
    pub const RO_HAS_WEAK_WITHOUT_ARC: u32 = 1 << 9;
    pub const RO_FORBIDS_ASSOCIATED_OBJECTS: u32 = 1 << 10;
    pub const RO_FROM_BUNDLE: u32 = 1 << 29;
    pub const RO_FUTURE: u32 = 1 << 30;
    pub const RO_REALIZED: u32 = 1 << 31;
    pub const method_list_entsize_mask: u32 = 0x0000fffc;
    pub const method_list_small_flag: u32 = 0x80000000;
    pub const method_list_uniqued_flag: u32 = 0x40000000;
    pub const method_large_size: u32 = 24;
    pub const method_small_size: u32 = 12;
    pub const ivar_entry_size: u32 = 32;
    pub const property_entry_size: u32 = 16;
    pub const cfstring_size: u32 = 32;
    pub const cfstring_flags_utf8: u64 = 0x7c8;
    pub const cfstring_flags_utf16: u64 = 0x7d0;
    pub const objc_stub_size: u32 = 32;
    pub const image_info_has_category_class_properties: u32 = 1 << 6;
};

comptime {
    std.debug.assert(@sizeOf(fat_arch_64) == 32);
    std.debug.assert(@sizeOf(encryption_info_command_64) == 24);
    std.debug.assert(@sizeOf(dylib_use_command) == 28);
    std.debug.assert(@sizeOf(dyld_chained_fixups_header) == 28);
    std.debug.assert(@sizeOf(note_command) == 40);
    std.debug.assert(@sizeOf(routines_command_64) == 72);
}
