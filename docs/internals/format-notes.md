# machre format notes (macOS Mach-O / dyld / code signing / ObjC / plist)

Verified 2026-09-11 on macOS 26.3 (arm64), SDK 26.5 at `$(xcrun --show-sdk-path)`.
Every struct below was cross-checked against the SDK header text (quoted field lists) and
`sizeof`/`offsetof` from a compiled C probe (`probe_layout.c`, `probe_x86state.c`); every
algorithm was implemented in a probe (`probe_*.py`) and its output compared with Apple's
tools (`otool`, `nm`, `dyld_info`, `codesign`, `vtool`, `objdump`, `plutil`) on real binaries.
Section 9 lists concrete expected values for tests. Section 10 lists what Zig's `std.macho`
lacks. Probe sources live in the scratchpad `format-notes/` directory (paths in section 11).

Conventions: offsets are byte offsets from the start of the struct; sizes in bytes; all
Mach-O structures are **little-endian on disk for x86_64/arm64** (the only live targets);
`fat_*` and every code-signing blob are **big-endian**. "LE u32 at +N" means read 4 bytes
little-endian at offset N.

---

## 1. Fat / universal binaries (`<mach-o/fat.h>`, `<mach/machine.h>`)

Header text (fat.h):
```
#define FAT_MAGIC     0xcafebabe
#define FAT_CIGAM     0xbebafeca   /* NXSwapLong(FAT_MAGIC) */
struct fat_header { uint32_t magic; uint32_t nfat_arch; };
struct fat_arch   { int32_t cputype; int32_t cpusubtype; uint32_t offset; uint32_t size; uint32_t align; };
#define FAT_MAGIC_64  0xcafebabf
#define FAT_CIGAM_64  0xbfbafeca
struct fat_arch_64 { int32_t cputype; int32_t cpusubtype; uint64_t offset; uint64_t size; uint32_t align; uint32_t reserved; };
```

| struct | size | fields (offset:type) |
|---|---|---|
| `fat_header` | 8 | magic @0:u32, nfat_arch @4:u32 |
| `fat_arch` | 20 | cputype @0:i32, cpusubtype @4:i32, offset @8:u32, size @12:u32, align @16:u32 (power of 2) |
| `fat_arch_64` | 32 | cputype @0, cpusubtype @4, offset @8:u64, size @16:u64, align @24:u32, reserved @28:u32 |

**Big-endian rule:** all fat fields are big-endian. If the first 4 bytes read as a *little-endian*
u32 equal `FAT_CIGAM` (0xbebafeca) the file is fat with `FAT_MAGIC`; reading them as big-endian
u32 gives 0xcafebabe directly. `fat_arch` array starts at offset 8; slice `i` is at
`8 + i*20` (or `8 + i*32` for `FAT_MAGIC_64`). Each slice is a complete thin Mach-O at
`offset`, normally aligned to `1<<align` (0xe = 16 KiB on this system).

Verified bytes, `/bin/ls`:
```
00000000: cafe babe 0000 0002 | 0100 0007 0000 0003 0000 4000 0000 bbf0 0000 000e | 0100 000c 8000 0002 0001 0000 0001 5c00 0000 000e
           magic     nfat=2    | x86_64  sub=3   off=16384  size=48112 align=14   | arm64   sub=0x80000002 off=65536 size=89088 align=14
```
`lipo -detailed_info` reports the second slice as `arm64e`, `capabilities PTR_AUTH_VERSION USERSPACE 0`.

CPU constants (machine.h, verified by C probe):
```
CPU_ARCH_MASK 0xff000000  CPU_ARCH_ABI64 0x01000000  CPU_ARCH_ABI64_32 0x02000000
CPU_TYPE_X86 7   CPU_TYPE_X86_64 0x01000007   CPU_TYPE_ARM 12   CPU_TYPE_ARM64 0x0100000c
CPU_TYPE_ARM64_32 0x0200000c   CPU_TYPE_POWERPC 18   CPU_TYPE_POWERPC64 0x01000012   CPU_TYPE_ANY -1
CPU_SUBTYPE_MASK 0xff000000   CPU_SUBTYPE_LIB64 0x80000000   CPU_SUBTYPE_PTRAUTH_ABI 0x80000000
CPU_SUBTYPE_ARM64_PTR_AUTH_MASK 0x0f000000   version = (sub & 0x0f000000) >> 24
CPU_SUBTYPE_X86_64_ALL 3   CPU_SUBTYPE_X86_64_H 8 (Haswell)   CPU_SUBTYPE_I386_ALL 3
CPU_SUBTYPE_ARM64_ALL 0   CPU_SUBTYPE_ARM64_V8 1   CPU_SUBTYPE_ARM64E 2   CPU_SUBTYPE_ARM64_32_V8 1
CPU_SUBTYPE_ARM_V7 9  ARM_V7S 11  ARM_V7K 12  ARM_V8 13  (32-bit arm, historical)
```
**Gotcha:** arm64e slices carry `cpusubtype = 0x80000002` in both `fat_arch` and `mach_header`
(PTRAUTH_ABI bit + version 0). Always compare `cpusubtype & 0x00ffffff` and report
`caps = cpusubtype >> 24` (otool prints `caps 0x80`). `CPU_SUBTYPE_LIB64` is the same bit,
used on x86_64 for 64-bit-library capability in old binaries.

Arch naming: `(cputype, sub & 0xffffff)` → x86_64: (0x01000007, 3) "x86_64", (…, 8) "x86_64h";
arm64: (0x0100000c, 0) "arm64", (…, 1) "arm64v8", (…, 2) "arm64e"; arm64_32: (0x0200000c, 1) "arm64_32".

---

## 2. Mach-O header and load commands (`<mach-o/loader.h>`)

### 2.1 mach_header / mach_header_64
```
struct mach_header    { uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags; };            /* 28 bytes */
struct mach_header_64 { uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags; uint32_t reserved; }; /* 32 bytes */
MH_MAGIC 0xfeedface  MH_CIGAM 0xcefaedfe  MH_MAGIC_64 0xfeedfacf  MH_CIGAM_64 0xcffaedfe
```
Offsets (64): magic@0 cputype@4 cpusubtype@8 filetype@12 ncmds@16 sizeofcmds@20 flags@24 reserved@28.
On disk (LE) `MH_MAGIC_64` appears as bytes `cf fa ed fe`. Load commands begin at offset 32
(28 for 32-bit) and occupy `sizeofcmds` bytes; each begins `{uint32_t cmd; uint32_t cmdsize;}`;
64-bit `cmdsize` must be a multiple of 8 and every command must lie inside `sizeofcmds`.

Verified: `enumerateProcess` header bytes `cffa edfe 0c00 0001 0000 0000 0200 0000 1100 0000 2004 0000 8500 2000 0000 0000`
= arm64, sub 0, MH_EXECUTE, ncmds 17, sizeofcmds 1056, flags 0x00200085.

Filetypes: `MH_OBJECT 1, MH_EXECUTE 2, MH_FVMLIB 3, MH_CORE 4, MH_PRELOAD 5, MH_DYLIB 6, MH_DYLINKER 7,
MH_BUNDLE 8, MH_DYLIB_STUB 9, MH_DSYM 0xa, MH_KEXT_BUNDLE 0xb, MH_FILESET 0xc, MH_GPU_EXECUTE 0xd, MH_GPU_DYLIB 0xe`.

Flags: `MH_NOUNDEFS 0x1, MH_INCRLINK 0x2, MH_DYLDLINK 0x4, MH_BINDATLOAD 0x8, MH_PREBOUND 0x10, MH_SPLIT_SEGS 0x20,
MH_LAZY_INIT 0x40, MH_TWOLEVEL 0x80, MH_FORCE_FLAT 0x100, MH_NOMULTIDEFS 0x200, MH_NOFIXPREBINDING 0x400,
MH_PREBINDABLE 0x800, MH_ALLMODSBOUND 0x1000, MH_SUBSECTIONS_VIA_SYMBOLS 0x2000, MH_CANONICAL 0x4000,
MH_WEAK_DEFINES 0x8000, MH_BINDS_TO_WEAK 0x10000, MH_ALLOW_STACK_EXECUTION 0x20000, MH_ROOT_SAFE 0x40000,
MH_SETUID_SAFE 0x80000, MH_NO_REEXPORTED_DYLIBS 0x100000, MH_PIE 0x200000, MH_DEAD_STRIPPABLE_DYLIB 0x400000,
MH_HAS_TLV_DESCRIPTORS 0x800000, MH_NO_HEAP_EXECUTION 0x1000000, MH_APP_EXTENSION_SAFE 0x02000000,
MH_NLIST_OUTOFSYNC_WITH_DYLDINFO 0x04000000, MH_SIM_SUPPORT 0x08000000, MH_IMPLICIT_PAGEZERO 0x10000000,
MH_DYLIB_IN_CACHE 0x80000000`. Typical executable: 0x00200085 = NOUNDEFS|DYLDLINK|TWOLEVEL|PIE.

### 2.2 All LC_* values
`LC_REQ_DYLD = 0x80000000` is OR'd into commands dyld must understand (a loader that does not
recognise such a command must refuse the file). Parsers should switch on `cmd & ~LC_REQ_DYLD`
but remember the bit.

| value | name | payload struct |
|---|---|---|
| 0x1 | LC_SEGMENT | segment_command (+ section[]) |
| 0x2 | LC_SYMTAB | symtab_command |
| 0x3 | LC_SYMSEG | symseg_command (obsolete) |
| 0x4 | LC_THREAD | thread_command |
| 0x5 | LC_UNIXTHREAD | thread_command (+stack) |
| 0x6 | LC_LOADFVMLIB | fvmlib_command |
| 0x7 | LC_IDFVMLIB | fvmlib_command |
| 0x8 | LC_IDENT | ident_command (obsolete) |
| 0x9 | LC_FVMFILE | fvmfile_command |
| 0xa | LC_PREPAGE | (internal) |
| 0xb | LC_DYSYMTAB | dysymtab_command |
| 0xc | LC_LOAD_DYLIB | dylib_command |
| 0xd | LC_ID_DYLIB | dylib_command |
| 0xe | LC_LOAD_DYLINKER | dylinker_command |
| 0xf | LC_ID_DYLINKER | dylinker_command |
| 0x10 | LC_PREBOUND_DYLIB | prebound_dylib_command |
| 0x11 | LC_ROUTINES | routines_command |
| 0x12 | LC_SUB_FRAMEWORK | sub_framework_command |
| 0x13 | LC_SUB_UMBRELLA | sub_umbrella_command |
| 0x14 | LC_SUB_CLIENT | sub_client_command |
| 0x15 | LC_SUB_LIBRARY | sub_library_command |
| 0x16 | LC_TWOLEVEL_HINTS | twolevel_hints_command |
| 0x17 | LC_PREBIND_CKSUM | prebind_cksum_command |
| 0x80000018 | LC_LOAD_WEAK_DYLIB | dylib_command |
| 0x19 | LC_SEGMENT_64 | segment_command_64 (+ section_64[]) |
| 0x1a | LC_ROUTINES_64 | routines_command_64 |
| 0x1b | LC_UUID | uuid_command |
| 0x8000001c | LC_RPATH | rpath_command |
| 0x1d | LC_CODE_SIGNATURE | linkedit_data_command |
| 0x1e | LC_SEGMENT_SPLIT_INFO | linkedit_data_command |
| 0x8000001f | LC_REEXPORT_DYLIB | dylib_command |
| 0x20 | LC_LAZY_LOAD_DYLIB | dylib_command |
| 0x21 | LC_ENCRYPTION_INFO | encryption_info_command |
| 0x22 | LC_DYLD_INFO | dyld_info_command |
| 0x80000022 | LC_DYLD_INFO_ONLY | dyld_info_command |
| 0x80000023 | LC_LOAD_UPWARD_DYLIB | dylib_command |
| 0x24 | LC_VERSION_MIN_MACOSX | version_min_command |
| 0x25 | LC_VERSION_MIN_IPHONEOS | version_min_command |
| 0x26 | LC_FUNCTION_STARTS | linkedit_data_command |
| 0x27 | LC_DYLD_ENVIRONMENT | dylinker_command (string `NAME=value`) |
| 0x80000028 | LC_MAIN | entry_point_command |
| 0x29 | LC_DATA_IN_CODE | linkedit_data_command |
| 0x2a | LC_SOURCE_VERSION | source_version_command |
| 0x2b | LC_DYLIB_CODE_SIGN_DRS | linkedit_data_command |
| 0x2c | LC_ENCRYPTION_INFO_64 | encryption_info_command_64 |
| 0x2d | LC_LINKER_OPTION | linker_option_command (MH_OBJECT only) |
| 0x2e | LC_LINKER_OPTIMIZATION_HINT | linkedit_data_command (MH_OBJECT) |
| 0x2f | LC_VERSION_MIN_TVOS | version_min_command |
| 0x30 | LC_VERSION_MIN_WATCHOS | version_min_command |
| 0x31 | LC_NOTE | note_command |
| 0x32 | LC_BUILD_VERSION | build_version_command (+ build_tool_version[]) |
| 0x80000033 | LC_DYLD_EXPORTS_TRIE | linkedit_data_command (payload = trie) |
| 0x80000034 | LC_DYLD_CHAINED_FIXUPS | linkedit_data_command (payload = dyld_chained_fixups_header) |
| 0x80000035 | LC_FILESET_ENTRY | fileset_entry_command |
| 0x36 | LC_ATOM_INFO | linkedit_data_command |
| 0x37 | LC_FUNCTION_VARIANTS | linkedit_data_command |
| 0x38 | LC_FUNCTION_VARIANT_FIXUPS | linkedit_data_command |
| 0x39 | LC_TARGET_TRIPLE | target_triple_command (lc_str triple, e.g. "arm64e-apple-macosx15.0.0") |
| 0x3a | LC_LAZY_LOAD_DYLIB_INFO | linkedit_data_command |

`union lc_str { uint32_t offset; }` (64-bit): the string lives at `cmd_start + offset`, NUL
terminated, padded to the 8-byte `cmdsize` (otool prints `(offset 24)` for dylib names,
`(offset 12)` for dylinker/rpath).

### 2.3 segment_command_64 / section_64
```
struct segment_command_64 { uint32_t cmd; uint32_t cmdsize; char segname[16]; uint64_t vmaddr; uint64_t vmsize;
    uint64_t fileoff; uint64_t filesize; int32_t maxprot; int32_t initprot; uint32_t nsects; uint32_t flags; };  /* 72 */
struct section_64 { char sectname[16]; char segname[16]; uint64_t addr; uint64_t size; uint32_t offset; uint32_t align;
    uint32_t reloff; uint32_t nreloc; uint32_t flags; uint32_t reserved1; uint32_t reserved2; uint32_t reserved3; }; /* 80 */
```
Offsets: seg: segname@8 vmaddr@24 vmsize@32 fileoff@40 filesize@48 maxprot@56 initprot@60 nsects@64 flags@68;
`cmdsize = 72 + 80*nsects`, sections follow immediately. sect: sectname@0 segname@16 addr@32 size@40
offset@48 align@52 (log2) reloff@56 nreloc@60 flags@64 reserved1@68 reserved2@72 reserved3@76.
32-bit variants: segment_command 56 bytes, section 68 bytes (u32 addr/size, no reserved3).
Names are NUL-padded, not necessarily NUL-terminated (`__unwind_info` is 13 chars; a 16-char
name has no terminator). VM prot: 1 = r, 2 = w, 4 = x.

Segment flags: `SG_HIGHVM 0x1, SG_FVMLIB 0x2, SG_NORELOC 0x4, SG_PROTECTED_VERSION_1 0x8 (encrypted),
SG_READ_ONLY 0x10` (`__DATA_CONST` has 0x10 in every modern binary).

Section flags = type (low 8 bits, `SECTION_TYPE 0xff`) | attributes (`SECTION_ATTRIBUTES 0xffffff00`):
```
S_REGULAR 0x0  S_ZEROFILL 0x1  S_CSTRING_LITERALS 0x2  S_4BYTE_LITERALS 0x3  S_8BYTE_LITERALS 0x4  S_LITERAL_POINTERS 0x5
S_NON_LAZY_SYMBOL_POINTERS 0x6  S_LAZY_SYMBOL_POINTERS 0x7  S_SYMBOL_STUBS 0x8  S_MOD_INIT_FUNC_POINTERS 0x9
S_MOD_TERM_FUNC_POINTERS 0xa  S_COALESCED 0xb  S_GB_ZEROFILL 0xc  S_INTERPOSING 0xd  S_16BYTE_LITERALS 0xe
S_DTRACE_DOF 0xf  S_LAZY_DYLIB_SYMBOL_POINTERS 0x10  S_THREAD_LOCAL_REGULAR 0x11  S_THREAD_LOCAL_ZEROFILL 0x12
S_THREAD_LOCAL_VARIABLES 0x13  S_THREAD_LOCAL_VARIABLE_POINTERS 0x14  S_THREAD_LOCAL_INIT_FUNCTION_POINTERS 0x15
S_INIT_FUNC_OFFSETS 0x16
S_ATTR_PURE_INSTRUCTIONS 0x80000000  S_ATTR_NO_TOC 0x40000000  S_ATTR_STRIP_STATIC_SYMS 0x20000000
S_ATTR_NO_DEAD_STRIP 0x10000000  S_ATTR_LIVE_SUPPORT 0x08000000  S_ATTR_SELF_MODIFYING_CODE 0x04000000
S_ATTR_DEBUG 0x02000000  S_ATTR_SOME_INSTRUCTIONS 0x00000400  S_ATTR_EXT_RELOC 0x00000200  S_ATTR_LOC_RELOC 0x00000100
```
Typical: `__text` 0x80000400, `__stubs`/`__auth_stubs` 0x80000408, `__cstring` 0x2, `__got`/`__auth_got` 0x6,
`__la_symbol_ptr` 0x7, `__bss`/`__common` 0x1 (offset field 0: no file bytes).

**reserved1/reserved2 semantics (header comment, verified):** for `S_SYMBOL_STUBS`,
`S_LAZY_SYMBOL_POINTERS`, `S_NON_LAZY_SYMBOL_POINTERS`, `S_LAZY_DYLIB_SYMBOL_POINTERS`,
`S_THREAD_LOCAL_VARIABLE_POINTERS`: `reserved1` = index of this section's first entry in the
indirect symbol table; `reserved2` = byte size of one stub (stubs only; 16 on arm64e
`__auth_stubs`, 12 on arm64 `__stubs`, 6 on x86_64). Entry count = `size / entry_size` where
entry_size = `reserved2` for stubs and the pointer size (8 on 64-bit; the header's "4 bytes"
is 32-bit era) for pointer sections. Otherwise reserved1/2/3 are 0.
Verified: `enumerateProcess` `__stubs` size 0x9c/12 = 13 entries at reserved1 0, `__got` 0x88/8 = 17
entries at reserved1 13; 13+17 = 30 = `nindirectsyms`. `/bin/ls` `__auth_got` reserved1 84, `__got` 168.

Well-known segment/section names (loader.h): `__PAGEZERO`, `__TEXT`(`__text`, `__stubs`, `__auth_stubs`,
`__const`, `__cstring`, `__unwind_info`, `__eh_frame`, `__info_plist`, `__objc_methlist`, `__objc_methname`,
`__objc_classname`, `__objc_methtype`, `__objc_stubs`), `__DATA_CONST` (`__got`, `__auth_got`, `__const`,
`__cfstring`, `__objc_classlist`, `__objc_catlist`, `__objc_protolist`, `__objc_imageinfo`, `__objc_superrefs`),
`__DATA` (`__data`, `__bss`, `__common`, `__la_symbol_ptr`, `__objc_selrefs`, `__objc_classrefs`, `__objc_data`,
`__objc_const`, `__objc_ivar`), `__LINKEDIT`. Packer tells: `__XHDR`, `UPX_DATA`, `upxTEXT`, `__MPRESS__`.

### 2.4 dylib commands
```
struct dylib { union lc_str name; uint32_t timestamp; uint32_t current_version; uint32_t compatibility_version; };
struct dylib_command { uint32_t cmd; uint32_t cmdsize; struct dylib dylib; };   /* 24 + string */
```
Offsets: name.offset@8, timestamp@12, current_version@16, compatibility_version@20; name at
`cmd + name.offset` (normally 24). Used by `LC_ID_DYLIB` (the dylib's own install name, e.g.
`/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib`, `@rpath/Electron Framework.framework/Electron Framework`),
`LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB` (missing lib tolerated), `LC_REEXPORT_DYLIB` (symbols
re-exported through this image — proxying tell), `LC_LOAD_UPWARD_DYLIB` (circular dependency),
`LC_LAZY_LOAD_DYLIB` (obsolete).
**Version encoding:** `X.Y.Z` = `(v >> 16) . ((v >> 8) & 0xff) . (v & 0xff)`; e.g. libSystem current
1356.0.0 = 0x054c0000, compatibility 1.0.0 = 0x00010000. Timestamp is usually 2 (or 0/1).
**Library ordinals:** the n-th dylib load command (counting LOAD, LOAD_WEAK, REEXPORT, UPWARD,
LAZY_LOAD in load-command order, 1-based) is ordinal n. `/bin/ls`: 1 libutil, 2 libncurses.5.4, 3 libSystem.B.

Alternate encoding (macOS 15+, header text):
```
struct dylib_use_command { uint32_t cmd; uint32_t cmdsize; uint32_t nameoff /*==28*/; uint32_t marker /*==DYLIB_USE_MARKER*/;
    uint32_t current_version; uint32_t compat_version; uint32_t flags; };   /* 28 */
DYLIB_USE_WEAK_LINK 0x01  DYLIB_USE_REEXPORT 0x02  DYLIB_USE_UPWARD 0x04  DYLIB_USE_DELAYED_INIT 0x08  DYLIB_USE_MARKER 0x1a741800
```
Detection: cmd is LC_LOAD_DYLIB/LC_LOAD_WEAK_DYLIB and the u32 at +12 (the `timestamp` slot) ==
0x1a741800; then name is at +28 and flags at +24. Not present in the local corpus.

### 2.5 Other string commands
- `rpath_command {cmd, cmdsize, lc_str path}` (12 + string): `@executable_path/../Frameworks`,
  `@loader_path/Libraries` (verified in Claude.app, Electron Framework).
- `dylinker_command {cmd, cmdsize, lc_str name}` (12): `LC_LOAD_DYLINKER` name `/usr/lib/dyld`
  (offset 12, cmdsize 32); `LC_ID_DYLINKER` in dyld itself; `LC_DYLD_ENVIRONMENT` string `DYLD_x=y`.
- `sub_framework_command {umbrella}`, `sub_client_command {client}`, `sub_umbrella_command {sub_umbrella}`,
  `sub_library_command {sub_library}`: all `{cmd, cmdsize, lc_str}` 12 + string (umbrella-framework
  linkage metadata; none present in local corpus).
- `linker_option_command {cmd, cmdsize, uint32_t count}` (12) followed by `count` NUL-terminated
  UTF-8 strings (MH_OBJECT only).
- `target_triple_command {cmd, cmdsize, lc_str triple}` (12).
- `fileset_entry_command {cmd, cmdsize, uint64_t vmaddr @8, uint64_t fileoff @16, lc_str entry_id @24, uint32_t reserved @28}` (32 + string; kernel collections / MH_FILESET).

### 2.6 symtab / dysymtab
```
struct symtab_command { cmd; cmdsize; uint32_t symoff @8; uint32_t nsyms @12; uint32_t stroff @16; uint32_t strsize @20; }  /* 24 */
struct dysymtab_command { cmd; cmdsize; ilocalsym @8; nlocalsym @12; iextdefsym @16; nextdefsym @20; iundefsym @24; nundefsym @28;
    tocoff @32; ntoc @36; modtaboff @40; nmodtab @44; extrefsymoff @48; nextrefsyms @52; indirectsymoff @56; nindirectsyms @60;
    extreloff @64; nextrel @68; locreloff @72; nlocrel @76; }  /* 80, all uint32_t */
INDIRECT_SYMBOL_LOCAL 0x80000000   INDIRECT_SYMBOL_ABS 0x40000000
```
Symbol table = `nsyms` × `nlist_64` (16 bytes) at `symoff`; string table at `stroff`, `strsize`
bytes; index 0 of the string table is conventionally a space/empty string. The dysymtab groups
the symbol table into three contiguous runs: local (`ilocalsym..`), externally defined,
undefined — `/bin/ls`: 1 local, 1 extdef (`__mh_execute_header`), 90 undef = 92;
`enumerateProcess`: 13 local (all stabs), 3 extdef, 17 undef = 33.
**Indirect symbol table:** `nindirectsyms` × u32 at `indirectsymoff`; each value is an index into
the symbol table (or `INDIRECT_SYMBOL_LOCAL`/`ABS`, possibly OR'd together); sections reference
it via `reserved1` (see 2.3). `enumerateProcess` table: `11 14 15 16 17 18 1a 1b 1c 1d 1e 1f 20 | 10 11 … 20`
(13 stub entries, then 17 `__got` entries = undefined symbols 16..32).
`tocoff/modtaboff/extrefsymoff/extreloff/locreloff` are 0 in all modern binaries.

### 2.7 dyld_info_command (legacy, LC_DYLD_INFO(_ONLY))
```
struct dyld_info_command { cmd; cmdsize /*48*/; rebase_off @8; rebase_size @12; bind_off @16; bind_size @20;
    weak_bind_off @24; weak_bind_size @28; lazy_bind_off @32; lazy_bind_size @36; export_off @40; export_size @44; }
```
Payloads are byte streams (no endianness). See 4.3 / 4.2. Still emitted for deployment
targets < macOS 12 (Alacritty x86_64: rebase 5512 B, bind 728, lazy 8664, export 77928;
Burp `JavaApplicationStub` arm64 minOS 11.0: rebase 80, bind 1040, lazy 1408, export 568).

### 2.8 linkedit_data_command
```
struct linkedit_data_command { cmd; cmdsize /*16*/; uint32_t dataoff @8; uint32_t datasize @12; }
```
`dataoff` is a **file offset within this slice** (add the fat slice offset), inside `__LINKEDIT`.
Used by LC_CODE_SIGNATURE (superblob, 5), LC_FUNCTION_STARTS (4.4), LC_DATA_IN_CODE (array of
`data_in_code_entry {uint32_t offset /*from mach_header*/; uint16_t length; uint16_t kind;}`,
kinds `DICE_KIND_DATA 1, JUMP_TABLE8 2, JUMP_TABLE16 3, JUMP_TABLE32 4, ABS_JUMP_TABLE32 5`),
LC_DYLD_CHAINED_FIXUPS (4.1), LC_DYLD_EXPORTS_TRIE (4.2), LC_SEGMENT_SPLIT_INFO (shared-cache
split-seg info; present in `/usr/lib/dyld`), LC_DYLIB_CODE_SIGN_DRS (designated requirements of
linked dylibs, old), LC_LINKER_OPTIMIZATION_HINT (MH_OBJECT), LC_ATOM_INFO, LC_FUNCTION_VARIANTS,
LC_FUNCTION_VARIANT_FIXUPS, LC_LAZY_LOAD_DYLIB_INFO. `datasize` 0 is legal (`LC_DATA_IN_CODE` 0 in both test binaries).

### 2.9 uuid / version_min / build_version / source_version
```
struct uuid_command { cmd; cmdsize /*24*/; uint8_t uuid[16] @8; }          -> print as 8-4-4-4-12 uppercase hex, e.g. 322CB148-C401-3EA0-A023-4B21A104D42F
struct version_min_command { cmd; cmdsize /*16*/; uint32_t version @8; uint32_t sdk @12; }   /* X.Y.Z = nibbles xxxx.yy.zz */
struct build_version_command { cmd; cmdsize; uint32_t platform @8; uint32_t minos @12; uint32_t sdk @16; uint32_t ntools @20; } /* 24 + ntools*8 */
struct build_tool_version { uint32_t tool; uint32_t version; }
struct source_version_command { cmd; cmdsize /*16*/; uint64_t version @8; }  /* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
```
Version `X.Y.Z` = `v>>16 . (v>>8)&0xff . v&0xff`: `/bin/ls` minos 0x000b0000 = 11.0, sdk 0x001a0300 = 26.3.
Source version: `A = v >> 40; B = (v >> 30) & 0x3ff; C = (v >> 20) & 0x3ff; D = (v >> 10) & 0x3ff; E = v & 0x3ff`
(verified: `/bin/ls` raw 0x1db0000000000 → 475.0.0.0.0, printed "475.0").
Platforms: `UNKNOWN 0, ANY 0xffffffff, MACOS 1, IOS 2, TVOS 3, WATCHOS 4, BRIDGEOS 5, MACCATALYST 6,
IOSSIMULATOR 7, TVOSSIMULATOR 8, WATCHOSSIMULATOR 9, DRIVERKIT 10, VISIONOS 11, VISIONOSSIMULATOR 12,
FIRMWARE 13, SEPOS 14, MACOS_EXCLAVECORE 15, MACOS_EXCLAVEKIT 16, IOS_EXCLAVECORE 17, IOS_EXCLAVEKIT 18,
TVOS_EXCLAVECORE 19, TVOS_EXCLAVEKIT 20, WATCHOS_EXCLAVECORE 21, WATCHOS_EXCLAVEKIT 22,
VISIONOS_EXCLAVECORE 23, VISIONOS_EXCLAVEKIT 24`.
Tools: `CLANG 1, SWIFT 2, LD 3, LLD 4, METAL 1024, AIRLLD 1025, AIRNT 1026, AIRNT_PLUGIN 1027, AIRPACK 1028,
GPUARCHIVER 1031, METAL_FRAMEWORK 1032` (Zig's std.macho adds an unofficial `ZIG = 5`).
`vtool -show` prints e.g. `platform MACOS minos 11.0 sdk 26.3 ntools 1 tool LD version 1230.4`.
Older binaries carry `LC_VERSION_MIN_MACOSX` instead (Alacritty x86_64: version 10.12 sdk 15.5).

### 2.10 Entry point: LC_MAIN and LC_UNIXTHREAD
```
struct entry_point_command { cmd /*LC_MAIN*/; cmdsize /*24*/; uint64_t entryoff @8 /* file (__TEXT) offset of main() */; uint64_t stacksize @16; }
```
Entry vmaddr = `__TEXT.vmaddr + entryoff` (`__TEXT.fileoff` is 0). Verified: `enumerateProcess`
entryoff 1292 = 0x50c → 0x10000050c = `_main` per `nm`; `/bin/ls` entryoff 0x960 → 0x100000960.

Old binaries (and `/usr/lib/dyld` today) use `LC_UNIXTHREAD`:
```
struct thread_command { cmd /*LC_THREAD|LC_UNIXTHREAD*/; cmdsize; /* then repeated: uint32_t flavor; uint32_t count; uint32_t state[count]; */ }
```
- x86_64: flavor `x86_THREAD_STATE64 = 4`, count `x86_THREAD_STATE64_COUNT = 42` (168 bytes);
  state layout (all u64): rax@0 rbx@8 rcx@16 rdx@24 rdi@32 rsi@40 rbp@48 rsp@56 r8@64 r9@72 r10@80 r11@88
  r12@96 r13@104 r14@112 r15@120 **rip@128** rflags@136 cs@144 fs@152 gs@160. Total cmdsize 184.
  Entry = rip (dyld x86_64: 0x4e50).
- arm64: flavor `ARM_THREAD_STATE64 = 6`, count `ARM_THREAD_STATE64_COUNT = 68` (272 bytes):
  x[29] u64 @0..224, fp@232, lr@240, sp@248, **pc@256**, cpsr u32@264, flags u32@268. cmdsize 288.
  Entry = pc (dyld arm64e: 0x49c0). (Other flavors: `x86_THREAD_STATE32 1`, `ARM_THREAD_STATE 1`,
  `ARM_THREAD_STATE32 9`; state offsets from `<mach/i386/_structs.h>`, `<mach/arm/_structs.h>`.)
The state value is an absolute vmaddr in old binaries (unslid); for LC_UNIXTHREAD in a PIE the
loader adds the slide.

### 2.11 Remaining structs
```
struct encryption_info_command    { cmd; cmdsize /*20*/; uint32_t cryptoff @8; uint32_t cryptsize @12; uint32_t cryptid @16; }
struct encryption_info_command_64 { cmd; cmdsize /*24*/; cryptoff @8; cryptsize @12; cryptid @16; uint32_t pad @20; }   /* cryptid != 0 => range is encrypted (FairPlay) */
struct note_command { cmd; cmdsize /*40*/; char data_owner[16] @8; uint64_t offset @24; uint64_t size @32; }
struct routines_command_64 { cmd; cmdsize /*72*/; uint64_t init_address @8; uint64_t init_module @16; uint64_t reserved1..6 @24..64; }
struct prebind_cksum_command { cmd; cmdsize /*12*/; uint32_t cksum @8; }
struct twolevel_hints_command { cmd; cmdsize /*16*/; uint32_t offset @8; uint32_t nhints @12; }
struct twolevel_hint { uint32_t isub_image:8, itoc:24; }      /* 4 bytes; bitfield: isub_image = v & 0xff, itoc = v >> 8 */
struct prebound_dylib_command { cmd; cmdsize; lc_str name @8; uint32_t nmodules @12; lc_str linked_modules @16; } /* 20 */
```

---

## 3. Symbols (`<mach-o/nlist.h>`, `<mach-o/stab.h>`)

```
struct nlist_64 { union { uint32_t n_strx; } n_un; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };  /* 16: n_strx@0 n_type@4 n_sect@5 n_desc@6 n_value@8 */
struct nlist    { union { uint32_t n_strx; } n_un; uint8_t n_type; uint8_t n_sect; int16_t n_desc; uint32_t n_value; };   /* 12 */
N_STAB 0xe0  N_PEXT 0x10  N_TYPE 0x0e  N_EXT 0x01
N_UNDF 0x0  N_ABS 0x2  N_SECT 0xe  N_PBUD 0xc  N_INDR 0xa      (values of n_type & N_TYPE)
NO_SECT 0  MAX_SECT 255
```
Decode: if `n_type & N_STAB` ≠ 0 the entry is a debugging stab (whole `n_type` byte is the stab
code below); else `type = n_type & N_TYPE`, `ext = n_type & N_EXT`, `pext = n_type & N_PEXT`.
`n_sect` is the 1-based section number (order of sections across all segments) for N_SECT.
`n_value`: address for N_SECT/N_ABS; for N_UNDF with N_EXT and non-zero value = common symbol
size; for N_INDR = string-table index of the aliased symbol name. `n_strx` 0 = no name.

n_desc (undefined symbols): low 3 bits `REFERENCE_TYPE 0x7` = `REFERENCE_FLAG_UNDEFINED_NON_LAZY 0,
UNDEFINED_LAZY 1, DEFINED 2, PRIVATE_DEFINED 3, PRIVATE_UNDEFINED_NON_LAZY 4, PRIVATE_UNDEFINED_LAZY 5`;
`REFERENCED_DYNAMICALLY 0x0010`; `N_NO_DEAD_STRIP 0x0020` (= `N_DESC_DISCARDED` for MH_OBJECT);
`N_WEAK_REF 0x0040`; `N_WEAK_DEF 0x0080` (= `N_REF_TO_WEAK` on undefined); `N_ARM_THUMB_DEF 0x0008`;
`N_SYMBOL_RESOLVER 0x0100`; `N_ALT_ENTRY 0x0200`; `N_COLD_FUNC 0x0400`.
**Library ordinal** (two-level namespace, undefined symbols): `GET_LIBRARY_ORDINAL(n_desc) = (n_desc >> 8) & 0xff`;
`SELF_LIBRARY_ORDINAL 0x0`, `MAX_LIBRARY_ORDINAL 0xfd`, `DYNAMIC_LOOKUP_ORDINAL 0xfe`, `EXECUTABLE_ORDINAL 0xff`.
`GET_COMM_ALIGN(n_desc) = (n_desc >> 8) & 0x0f` for common symbols in .o files.

Verified `nm -x` (value, n_type, n_sect, n_desc, n_strx): `enumerateProcess`
`0000000000000000 01 00 0100 0000002b ___chkstk_darwin` → N_UNDF|N_EXT, ordinal 1 (libSystem);
`0000000100000000 0f 01 0010 00000002 __mh_execute_header` → N_SECT|N_EXT, sect 1, REFERENCED_DYNAMICALLY;
`000000010000050c 0f 01 0000 00000025 _main`. `/bin/ls`: `… 01 00 0300 … __DefaultRuneLocale` → ordinal 3 = libSystem.

Stabs (stab.h): `N_GSYM 0x20, N_FNAME 0x22, N_FUN 0x24, N_STSYM 0x26, N_LCSYM 0x28, N_BNSYM 0x2e, N_AST 0x32,
N_OPT 0x3c, N_RSYM 0x40, N_SLINE 0x44, N_ENSYM 0x4e, N_SSYM 0x60, N_SO 0x64, N_OSO 0x66, N_LIB 0x68, N_LSYM 0x80,
N_BINCL 0x82, N_SOL 0x84, N_PARAMS 0x86, N_VERSION 0x88, N_OLEVEL 0x8A, N_PSYM 0xa0, N_EINCL 0xa2, N_ENTRY 0xa4,
N_LBRAC 0xc0, N_EXCL 0xc2, N_RBRAC 0xe0, N_BCOMM 0xe2, N_ECOMM 0xe4, N_ECOML 0xe8, N_LENG 0xfe, N_PC 0x30`.
`enumerateProcess` (built locally, not stripped) has 13 stabs: `N_SO` (dir), `N_SO` (file), `N_OSO`
(object path, n_value = mtime 0x6aa17aaf, n_desc 1), `N_BNSYM/N_FUN/N_FUN(size)/N_ENSYM` per function,
closing `N_SO`. Raw first entry: `01000000 64 01 0000 0000000000000000` = n_strx 1 (the empty string: the string table starts `20 00`, so index 0 is " " and index 1 is ""), n_type 0x64 N_SO, n_sect 1, n_desc 0, n_value 0; the second N_SO (n_strx 0x10d) names the directory, the third the source file, and N_OSO's n_value is the .o mtime.

---

## 4. dyld data

### 4.1 Chained fixups (`<mach-o/fixup-chains.h>`, `__MACH_O_FIXUP_CHAINS__ 7`)

Payload of `LC_DYLD_CHAINED_FIXUPS` at `dataoff` (all little-endian, offsets relative to the
payload start = "chain_data"):
```
struct dyld_chained_fixups_header { uint32_t fixups_version /*0*/; uint32_t starts_offset; uint32_t imports_offset;
    uint32_t symbols_offset; uint32_t imports_count; uint32_t imports_format /*DYLD_CHAINED_IMPORT*/; uint32_t symbols_format /*0 uncompressed, 1 zlib*/; }  /* 28 */
struct dyld_chained_starts_in_image { uint32_t seg_count; uint32_t seg_info_offset[seg_count]; }  /* offsets relative to THIS struct; 0 = segment has no fixups */
struct dyld_chained_starts_in_segment { uint32_t size @0; uint16_t page_size @4 /*0x1000|0x4000*/; uint16_t pointer_format @6;
    uint64_t segment_offset @8 /* vmaddr - image base (mach_header vmaddr) */; uint32_t max_valid_pointer @16 /*32-bit only*/;
    uint16_t page_count @20; uint16_t page_start[page_count] @22; /* uint16_t chain_starts[] may follow for MULTI */ }
DYLD_CHAINED_PTR_START_NONE 0xFFFF   DYLD_CHAINED_PTR_START_MULTI 0x8000 (in page_start[])   DYLD_CHAINED_PTR_START_LAST 0x8000 (in chain_starts[])
imports_format: DYLD_CHAINED_IMPORT 1, DYLD_CHAINED_IMPORT_ADDEND 2, DYLD_CHAINED_IMPORT_ADDEND64 3
struct dyld_chained_import          { uint32_t lib_ordinal:8, weak_import:1, name_offset:23; }               /* 4 */
struct dyld_chained_import_addend   { uint32_t lib_ordinal:8, weak_import:1, name_offset:23; int32_t addend; } /* 8 */
struct dyld_chained_import_addend64 { uint64_t lib_ordinal:16, weak_import:1, reserved:15, name_offset:32; uint64_t addend; } /* 16 */
```
Bitfields are LSB-first: for format 1/2 `lib_ordinal = v & 0xff`, `weak = (v >> 8) & 1`,
`name_offset = v >> 9`; name = NUL string at `chain_data + symbols_offset + name_offset`.
**lib_ordinal semantics:** 8-bit two's complement-ish: 0x00..0xF0 = ordinals 0..240,
0xF1..0xFF = -15..-1 (16-bit: 0xFFF1..0xFFFF). `0` = `BIND_SPECIAL_DYLIB_SELF`, `-1` = main
executable, `-2` = flat namespace lookup, `-3` = weak lookup; positive n = n-th dylib load
command (2.4). `symbols_format 1` means the string pool is zlib-compressed (not seen in corpus).

pointer_format values and per-format facts:
| fmt | name | stride | `next` bits | rebase target | notes |
|---|---|---|---|---|---|
| 1 | ARM64E | 8 | 11 | unauth: vmaddr (43-bit + high8); auth: runtime offset (+base) | arm64e executables/dylibs (macOS 11-12 era, `/bin/ls`) |
| 2 | 64 | 4 | 12 | vmaddr (36-bit + high8) | x86_64/arm64 dylibs (Electron Framework) |
| 3 | 32 | 4 | 5 | vmaddr (26-bit) | 32-bit; values > `max_valid_pointer` are non-pointers (bias `(64MB+max)/2`) |
| 4 | 32_CACHE | 4 | 2 | 30-bit | shared cache |
| 5 | 32_FIRMWARE | 4 | 6 | 26-bit | firmware |
| 6 | 64_OFFSET | 4 | 12 | vm offset (+base) | arm64/x86_64 executables (`enumerateProcess`) |
| 7 | ARM64E_KERNEL (=ARM64E_OFFSET) | 4 | 11 | vm offset | kernel/KC |
| 8 | 64_KERNEL_CACHE | 4 | 12 | cache-level relative | KC |
| 9 | ARM64E_USERLAND | 8 | 11 | vm offset | 16-bit bind ordinal |
| 10 | ARM64E_FIRMWARE | 4 | 11 | vmaddr | |
| 11 | X86_64_KERNEL_CACHE | 1 | 12 | | |
| 12 | ARM64E_USERLAND24 | 8 | 11 | vm offset | 24-bit bind ordinal; current arm64e userland (TextEdit) |
| 13 | ARM64E_SHARED_CACHE | 8 | 11 | | |
| 14 | ARM64E_SEGMENTED | 4 | 12 | segIndex/segOffset | |

Pointer encodings (u64 read LE at the fixup location; bit 63 = MSB):
```
64/64_OFFSET rebase : target:36 @0, high8:8 @36, reserved:7 @44, next:12 @51, bind:1 @63 (==0)
64 bind             : ordinal:24 @0, addend:8 @24, reserved:19 @32, next:12 @51, bind:1 @63 (==1)
arm64e rebase       : target:43 @0, high8:8 @43, next:11 @51, bind:1 @62 (==0), auth:1 @63 (==0)
arm64e bind         : ordinal:16 @0, zero:16 @16, addend:19 @32 (signed, +/-256K), next:11 @51, bind=1, auth=0
arm64e auth_rebase  : target:32 @0 (runtimeOffset), diversity:16 @32, addrDiv:1 @48, key:2 @49, next:11 @51, bind=0, auth=1
arm64e auth_bind    : ordinal:16 @0, zero:16 @16, diversity:16 @32, addrDiv:1 @48, key:2 @49, next:11 @51, bind=1, auth=1
arm64e bind24       : ordinal:24 @0, zero:8 @24, addend:19 @32, next:11 @51, bind=1, auth=0        (USERLAND24)
arm64e auth_bind24  : ordinal:24 @0, zero:8 @24, diversity:16 @32, addrDiv:1 @48, key:2 @49, next:11 @51, bind=1, auth=1
32 rebase           : target:26 @0, next:5 @26, bind:1 @31 (==0)      32 bind: ordinal:20 @0, addend:6 @20, next:5 @26, bind:1 @31
32_cache rebase     : target:30, next:2          32_firmware rebase: target:26, next:6
64_kernel_cache     : target:30, cacheLevel:2, diversity:16, addrDiv:1, key:2, next:12, isAuth:1
arm64e_segmented    : (u32) targetSegOffset:28, targetSegIndex:4 ; (u32) padding:19, next:12, auth:1   [auth variant: diversity:16, addrDiv:1, key:2, next:12, auth:1]
arm64e_shared_cache : runtimeOffset:34, high8:8, unused:10, next:11, auth:1  [auth: runtimeOffset:34, diversity:16, addrDiv:1, keyIsData:1, next:11, auth:1]
key: 0 IA, 1 IB, 2 DA, 3 DB
```

**Walk algorithm (verified against `dyld_info -fixups` for formats 1, 2, 6, 12 with exact counts:
`/bin/ls` 23 rebases + 90 binds; `enumerateProcess` 0 + 17; TextEdit arm64e 2259 + 559; Electron
Framework arm64 573785 + 7978; targets spot-checked equal):**
1. `H = file[dataoff .. dataoff+datasize]`; parse header; `imports[i]` from `imports_offset`.
2. `starts = H + starts_offset`; `seg_count`; for each `i` with `seg_info_offset[i] != 0`:
   `S = starts + seg_info_offset[i]`; the segment is **load command segment index i** (counting
   every LC_SEGMENT_64 including `__PAGEZERO`); assert `segments[i].vmaddr - image_base == segment_offset`
   where `image_base` = `__TEXT.vmaddr` (0x100000000 for executables, 0 for dylibs).
3. For page `p` in `0..page_count`: `ps = page_start[p]`; skip if 0xFFFF. If `ps & 0x8000` (MULTI):
   `idx = ps & 0x7fff` indexes `chain_starts[]` (u16 array after `page_start[page_count]`), walk
   each start until one with `DYLD_CHAINED_PTR_START_LAST` (0x8000) set (mask it off) — only 32-bit
   formats use this; not present in corpus.
4. `off = p*page_size + ps`; loop: file offset `fo = slice_base + seg.fileoff + off`, vmaddr
   `va = seg.vmaddr + off`; `raw = LE u64 at fo` (u32 for 32-bit formats); decode per format; the
   fixup **location** is `va`; `next = 0` ends the chain, else `off += next * stride`.
5. Rebase target value: fmt 2 → `target | high8<<56`; fmt 6/9/12 (and arm64e auth rebases for
   all arm64e formats) → `image_base + target` (auth: no high8); fmt 1/10 unauth → `target | high8<<56`
   (already a vmaddr). Bind → `imports[ordinal]` gives (lib_ordinal, weak, name, addend); the
   pointer's own addend (`addend` field, absent in auth variants) adds to the import addend.
6. Symbol display like `dyld_info`: `<libshortname>/<symbol>`; `auth-bind … (div=0x0000 ad=1 key=IA)`.

Worked examples: `enumerateProcess` `__got` slot 0 raw `0x8010000000000000`: bit63=1 → bind,
`next = (raw>>51)&0xfff = 2` → next fixup at +8, ordinal 0 → `___chkstk_darwin` (libSystem);
last slot raw `0x8000000000000010`: next 0, ordinal 16. `/bin/ls` `__auth_got` raw
`0xC009000000000000`: auth=1 bind=1, next=1 (×8), key=(>>49)&3=0 IA, addrDiv=(>>48)&1=1, div=0,
ordinal 0 → `libutil/_humanize_number`. `/bin/ls` `__const` raw `0x0048000100004A03`: rebase,
next=9 (×8 = 72 → 0x82D0+0x48 = 0x8318 ✓), target=0x100004A03 (43-bit vmaddr), high8=0.
TextEdit (fmt 12) `__objc_classlist[0]` raw `0x0008000000030740`: rebase, next=1, target
0x30740 → 0x100030740 = `_OBJC_CLASS_$_Document`. Electron (fmt 2) `__objc_classlist[0]` raw
`0x001000000A4B1718`: next=2 (×4 = 8), target 0xA4B1718 (vmaddr; dylib base 0).

Header dump for `enumerateProcess` (376 bytes at file 32768): `00000000 20000000 50000000 94000000 11000000 01000000 00000000 |
04000000 00000000 00000000 18000000 00000000 | 18000000 0040 0600 0040000000000000 00000000 0100 0000 | 01020000 01240000 …`
= version 0, starts 0x20, imports 0x50, symbols 0x94, 17 imports, format 1, symbols uncompressed;
seg_count 4, seg_info_offset {0,0,0x18,0}; starts_in_segment size 0x18, page 0x4000, fmt 6,
segment_offset 0x4000, max_valid 0, page_count 1, page_start[0]=0; import[0] = 0x00000201 →
lib 1, weak 0, name_offset 1 (`___chkstk_darwin` at 0x95).

### 4.2 Export trie (LC_DYLD_EXPORTS_TRIE, or dyld_info_command.export_off)
Header comment (loader.h) summarised and verified: stream of nodes; node = `uleb128 terminal_size`,
then if non-zero the terminal info: `uleb128 flags`, then
- default: `uleb128 offset` (address of symbol relative to the mach_header vmaddr);
- `EXPORT_SYMBOL_FLAGS_REEXPORT 0x08`: `uleb128 library_ordinal`, then NUL-terminated import
  name (empty = same name) — the symbol is re-exported from that dylib;
- `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER 0x10`: `uleb128 stub_offset`, `uleb128 resolver_offset`;
then (at node_start + 1 + terminal_size, i.e. after the terminal bytes) `uint8 child_count`, and
per child: NUL-terminated edge label, `uleb128 child_node_offset` (relative to trie start).
Symbol name = concatenation of edge labels along the path. Flags: `KIND_MASK 0x03` (`REGULAR 0,
THREAD_LOCAL 1, ABSOLUTE 2`), `WEAK_DEFINITION 0x04`, `REEXPORT 0x08`, `STUB_AND_RESOLVER 0x10`,
`STATIC_RESOLVER 0x20`. The trie may be padded with zeros to 8 bytes.

Worked example, `enumerateProcess` (72 bytes at file 33144):
```
@0x00: 00 01 5f 00 17      node0: terminal size 0; 1 child; label "_" -> child node @0x17
@0x05: 00 00 00 00         unused bytes (ld64 leaves them; never referenced)
@0x09: 02 00 00 | 00       terminal size 2: flags 0, offset 0  ; 0 children   => "__mh_execute_header" @ 0x0
@0x0d: 03 00 e0 08 | 00   terminal 3: flags 0, offset uleb(e0 08)=0x460 ; 0 children => "_getAuditToken"
@0x12: 03 00 8c 0a | 00   flags 0, offset uleb(8c 0a)=0x50c ; 0 children => "_main"
@0x17: 00 03  "_mh_execute_header\0" 09  "getAuditToken\0" 0d  "main\0" 12   ; then 6 zero pad bytes
```
`dyld_info -exports` agrees: `0x00000000 __mh_execute_header, 0x00000460 _getAuditToken, 0x0000050C _main`.
Probe counts match dyld_info: Burp stub 25, libcapstone 20, Electron Framework arm64 11158
(8485 regular + 2673 `WEAK_DEFINITION`, shown as `[weak-def]`), `/bin/ls` 1.

### 4.3 Legacy rebase / bind / lazy-bind / weak-bind opcode streams
Rebase (`REBASE_OPCODE_MASK 0xF0`, `REBASE_IMMEDIATE_MASK 0x0F`): state = (type, seg_index, seg_offset).
```
0x00 DONE                          0x10 SET_TYPE_IMM(type=imm)              (REBASE_TYPE_POINTER 1, TEXT_ABSOLUTE32 2, TEXT_PCREL32 3)
0x20 SET_SEGMENT_AND_OFFSET_ULEB   seg=imm, offset=uleb
0x30 ADD_ADDR_ULEB                 offset += uleb
0x40 ADD_ADDR_IMM_SCALED           offset += imm * 8
0x50 DO_REBASE_IMM_TIMES           imm times: emit(seg,offset); offset += 8
0x60 DO_REBASE_ULEB_TIMES          uleb times: emit; offset += 8
0x70 DO_REBASE_ADD_ADDR_ULEB       emit; offset += 8 + uleb
0x80 DO_REBASE_ULEB_TIMES_SKIPPING_ULEB   count=uleb, skip=uleb: count times { emit; offset += 8 + skip }
```
Bind (`BIND_OPCODE_MASK 0xF0`, `BIND_IMMEDIATE_MASK 0x0F`): state = (lib_ordinal, symbol, flags, type, addend, seg, offset).
```
0x00 DONE     0x10 SET_DYLIB_ORDINAL_IMM(imm)     0x20 SET_DYLIB_ORDINAL_ULEB(uleb)
0x30 SET_DYLIB_SPECIAL_IMM: imm==0 -> 0 (self); else sign-extend low nibble: 0xF -> -1 (MAIN_EXECUTABLE), 0xE -> -2 (FLAT_LOOKUP), 0xD -> -3 (WEAK_LOOKUP)
0x40 SET_SYMBOL_TRAILING_FLAGS_IMM: flags=imm (BIND_SYMBOL_FLAGS_WEAK_IMPORT 0x1, NON_WEAK_DEFINITION 0x8), then NUL-terminated name
0x50 SET_TYPE_IMM(type)  (BIND_TYPE_POINTER 1, TEXT_ABSOLUTE32 2, TEXT_PCREL32 3)
0x60 SET_ADDEND_SLEB(sleb128)
0x70 SET_SEGMENT_AND_OFFSET_ULEB(seg=imm, offset=uleb)
0x80 ADD_ADDR_ULEB(offset += uleb, wrapping mod 2^64 — negative deltas are encoded as 10-byte ulebs, e.g. 0xFFFFFFFFFFFFFF78)
0x90 DO_BIND: emit; offset += 8
0xA0 DO_BIND_ADD_ADDR_ULEB: emit; offset += 8 + uleb
0xB0 DO_BIND_ADD_ADDR_IMM_SCALED: emit; offset += 8 + imm*8
0xC0 DO_BIND_ULEB_TIMES_SKIPPING_ULEB: count, skip: count times { emit; offset += 8 + skip }
0xD0 THREADED (arm64e pre-chained-fixups): sub-opcode imm: 0x00 SET_BIND_ORDINAL_TABLE_SIZE_ULEB, 0x01 APPLY
```
The **lazy bind** stream contains `DONE` (0x00) after every entry — keep parsing until the
stream end (verified: 66 lazy entries in Burp stub). Weak bind stream is sorted by symbol name.
Verified counts (Burp `JavaApplicationStub`): rebase 463, bind 235, lazy 66 = `dyld_info -fixups`.
Sample rebase bytes `11 22 50 53 43 70 18 52 42 …` decode: SET_TYPE_IMM(1); SET_SEGMENT_AND_OFFSET_ULEB(2, 0x50);
DO_REBASE_IMM_TIMES(3); ADD_ADDR_IMM_SCALED(3→0x18); DO_REBASE_ADD_ADDR_ULEB(0x18); DO_REBASE_IMM_TIMES(2);
ADD_ADDR_IMM_SCALED(2→0x10) … `80 c5 01 18` = DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(197, 24).
Sample bind bytes `13 40 "__NSConcreteGlobalBlock\0" 51 72 90 01 90` = ordinal 3 (libSystem), symbol,
type 1, seg 2 offset 0x90, DO_BIND → `__DATA_CONST+0x90` = 0x100010090. Lazy: `73 00 15 40 "_CFArrayGetCount\0" 90 00`.
Legacy-format files have `__la_symbol_ptr` (S_LAZY_SYMBOL_POINTERS) + `__stub_helper`; ObjC
class pointers for external classes are **zero in the file** (bound at load), so an ObjC
walker must consult bind info to name `superclass`/`isa` targets.

### 4.4 LC_FUNCTION_STARTS
Stream of `uleb128` deltas; first delta is relative to `__TEXT.vmaddr`, each subsequent delta
relative to the previous function; a zero delta terminates (padding follows). Verified:
`enumerateProcess` bytes `e0 08 ac 01 00` → 0x100000460 (`_getAuditToken`), +0xac → 0x10000050c
(`_main`); `/bin/ls` 80 bytes → 50 functions, first `0x100000700, 0x10000070C, 0x10000071C, 0x100000780,
0x100000790, 0x1000007F4`, last `0x100004280` (= `dyld_info -function_starts`).

---

## 5. Code signing (`Kernel.framework/Headers/kern/cs_blobs.h`; not in `/usr/include`)

Located at `$SDK/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/kern/cs_blobs.h`.
**All blob fields are big-endian.** Signature data is at `LC_CODE_SIGNATURE.dataoff` (per slice).

Magics:
```
CSMAGIC_REQUIREMENT 0xfade0c00   CSMAGIC_REQUIREMENTS 0xfade0c01   CSMAGIC_CODEDIRECTORY 0xfade0c02
CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0   CSMAGIC_EMBEDDED_SIGNATURE_OLD 0xfade0b02   CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1
CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171   CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172
CSMAGIC_BLOBWRAPPER 0xfade0b01 (CMS signature)   CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT 0xfade8181
```
Structures:
```
typedef struct __BlobIndex { uint32_t type; uint32_t offset; } CS_BlobIndex;                      /* 8; offset relative to SuperBlob start */
typedef struct __SC_SuperBlob { uint32_t magic; uint32_t length; uint32_t count; CS_BlobIndex index[]; } CS_SuperBlob; /* 12 + 8*count */
typedef struct __SC_GenericBlob { uint32_t magic; uint32_t length; char data[]; } CS_GenericBlob;   /* 8 + payload; length includes header */
typedef struct __SC_Scatter { uint32_t count; uint32_t base; uint64_t targetOffset; uint64_t spare; } SC_Scatter; /* 24 */
```
Slots (`CS_BlobIndex.type`): `CSSLOT_CODEDIRECTORY 0, INFOSLOT 1, REQUIREMENTS 2, RESOURCEDIR 3, APPLICATION 4,
ENTITLEMENTS 5, DER_ENTITLEMENTS 7, LAUNCH_CONSTRAINT_SELF 8, LAUNCH_CONSTRAINT_PARENT 9,
LAUNCH_CONSTRAINT_RESPONSIBLE 10, LIBRARY_CONSTRAINT 11, ALTERNATE_CODEDIRECTORIES 0x1000 (+0..4, max 5),
SIGNATURESLOT 0x10000 (CMS), IDENTIFICATIONSLOT 0x10001, TICKETSLOT 0x10002`.
The same numbers (1..11) are the **special hash slot** indices in the CodeDirectory (negative
indices, see below); slot 6 is unused in modern signatures (hash all zero).

CodeDirectory (offsets verified by probe; `end_*` markers show where each version stops):
```
typedef struct __CodeDirectory {
  uint32_t magic @0;  uint32_t length @4;  uint32_t version @8;  uint32_t flags @12;
  uint32_t hashOffset @16;      /* offset (from CD start) of hash slot 0 */
  uint32_t identOffset @20;     /* NUL-terminated identifier */
  uint32_t nSpecialSlots @24;   /* hashes at hashOffset - n*hashSize, n = 1..nSpecialSlots */
  uint32_t nCodeSlots @28;      /* code page hashes at hashOffset + k*hashSize */
  uint32_t codeLimit @32;       /* bytes of the file covered = offset of the signature blob */
  uint8_t hashSize @36; uint8_t hashType @37; uint8_t platform @38; uint8_t pageSize @39 /* log2; 0 => single page */; uint32_t spare2 @40;
  /* end_earliest = 44 */
  uint32_t scatterOffset @44;                         /* version >= 0x20100 CS_SUPPORTSSCATTER   (end 48) */
  uint32_t teamOffset @48;                            /* version >= 0x20200 CS_SUPPORTSTEAMID    (end 52) */
  uint32_t spare3 @52; uint64_t codeLimit64 @56;      /* version >= 0x20300 CS_SUPPORTSCODELIMIT64 (end 64) */
  uint64_t execSegBase @64; uint64_t execSegLimit @72; uint64_t execSegFlags @80;  /* >= 0x20400 CS_SUPPORTSEXECSEG (end 88) */
  uint32_t runtime @88; uint32_t preEncryptOffset @92;                              /* >= 0x20500 CS_SUPPORTSRUNTIME (end 96) */
  uint8_t linkageHashType @96; uint8_t linkageApplicationType @97; uint16_t linkageApplicationSubType @98;
  uint32_t linkageOffset @100; uint32_t linkageSize @104;                           /* >= 0x20600 CS_SUPPORTSLINKAGE (end 108) */
} CS_CodeDirectory;   /* sizeof = 112 (4 trailing pad) */
```
Only read fields whose version threshold ≤ `version`; the header is followed by the
identifier, team ID, hashes at the given offsets (not necessarily in that order).
`hashType`: `CS_HASHTYPE_SHA1 1 (20), SHA256 2 (32), SHA256_TRUNCATED 3 (20), SHA384 4 (48)`;
`CS_CDHASH_LEN 20`, `CS_HASH_MAX_SIZE 48`. `runtime` is a version nibble-encoded like minos
(Claude: 0x1a0500 = 26.5.0 → codesign "Runtime Version=26.5.0"). `platform` non-zero =
Apple platform binary (26 on this OS). `execSegFlags`: `CS_EXECSEG_MAIN_BINARY 0x1, ALLOW_UNSIGNED 0x10,
DEBUGGER 0x20, JIT 0x40, SKIP_LV 0x80, CAN_LOAD_CDHASH 0x100, CAN_EXEC_CDHASH 0x200`.

CD `flags` (CS_* from cs_blobs.h; also used by `csops`):
```
CS_VALID 0x1  CS_ADHOC 0x2  CS_GET_TASK_ALLOW 0x4  CS_INSTALLER 0x8  CS_FORCED_LV 0x10  CS_INVALID_ALLOWED 0x20
CS_HARD 0x100  CS_KILL 0x200  CS_CHECK_EXPIRATION 0x400  CS_RESTRICT 0x800  CS_ENFORCEMENT 0x1000  CS_REQUIRE_LV 0x2000
CS_ENTITLEMENTS_VALIDATED 0x4000  CS_NVRAM_UNRESTRICTED 0x8000  CS_RUNTIME 0x10000  CS_LINKER_SIGNED 0x20000
CS_ALLOWED_MACHO = ADHOC|HARD|KILL|CHECK_EXPIRATION|RESTRICT|ENFORCEMENT|REQUIRE_LV|RUNTIME|LINKER_SIGNED
CS_EXEC_SET_HARD 0x100000  CS_EXEC_SET_KILL 0x200000  CS_EXEC_SET_ENFORCEMENT 0x400000  CS_EXEC_INHERIT_SIP 0x800000
CS_KILLED 0x1000000  CS_NO_UNTRUSTED_HELPERS/CS_DYLD_PLATFORM 0x2000000  CS_PLATFORM_BINARY 0x4000000  CS_PLATFORM_PATH 0x8000000
CS_DEBUGGED 0x10000000  CS_SIGNED 0x20000000  CS_DEV_CODE 0x40000000  CS_DATAVAULT_CONTROLLER 0x80000000
```
codesign prints e.g. `flags=0x20002(adhoc,linker-signed)`, `flags=0x10000(runtime)`, `flags=0x0(none)`.

**cdhash:** `hash = hashType(entire CodeDirectory blob, from its magic through length bytes)`;
the displayed CDHash is the first 20 bytes (`CS_CDHASH_LEN`) of that digest. Verified for
`/bin/ls` (4f35b316…7621, full …8e9f08), `enumerateProcess` (973fb442…aad7), Claude (ff2a59b4…eb69),
Burp stub (8a941bc9…8bf3), TextEdit (979142b9…687c) = `codesign -dvvv` `CDHash=` / `CandidateCDHashFull`.
**Code slot k** = `hashType(file[k*2^pageSize .. min((k+1)*2^pageSize, codeLimit)))` (last page short) —
verified for all 9 slots of `enumerateProcess`. **Special slots**: `-1` Info.plist, `-2` = hash of
the requirements blob (verified), `-3` `_CodeSignature/CodeResources`, `-4` application specific,
`-5` = hash of the XML entitlements blob (whole blob incl. 8-byte header; verified), `-6` unused,
`-7` = hash of the DER entitlements blob (verified). An all-zero special slot means "not bound"
(`/bin/ls` slot -1: `Info.plist=not bound`).

Verified layouts: `/bin/ls` superblob `fade0cc0 length 5287 count 3: (0 → 0x24 CD len 741 v0x20400
flags 0 hashOffset 0xa5 identOffset 0x58 nSpecial 2 nCode 18 codeLimit 70240 hashSize 32 hashType 2
platform 26 pageSize 12 execSegBase 0 execSegLimit 0x8000 execSegFlags 1 ident "com.apple.ls")
(2 → 0x309 requirements len 60) (0x10000 → 0x345 CMS len 4450)`; `codesign` reports
`Signature size=4442` (= blob length − 8). `enumerateProcess` (ad hoc, linker signed): superblob
length 413, count 1 (CD only, len 393, flags 0x20002, nSpecial 0, nCode 9, no requirements: codesign
synthesises `designated => cdhash H"973f…"`). Developer ID apps (Claude/Discord/Burp): 5 blobs
(CD v0x20500, requirements, XML entitlements, DER entitlements, CMS), `teamOffset` → team ID string.

**Requirements** (`CSMAGIC_REQUIREMENTS`): `{magic, length, count}` then `count` × `{uint32 type, uint32 offset}`
(offset relative to the requirements blob); type `1 host, 2 guest, 3 designated, 4 library, 5 plugin`.
Each target is a `CSMAGIC_REQUIREMENT` blob `{magic, length, uint32 kind /*1 = exprForm*/}` followed
by a prefix-notation expression of big-endian u32 opcodes (`ExprOp`, from Security's
`requirement.h` — not shipped in any SDK on this machine; the numbering was **verified by decoding
real blobs to the exact `codesign -d -r-` text**):
```
0 opFalse "never"    1 opTrue "always"   2 opIdent [string] -> identifier "x"   3 opAppleAnchor -> anchor apple
4 opAnchorHash [cert index; data] -> certificate <slot> = H"hex"   5 opInfoKeyValue [key; value] (legacy) -> info[key] = "value"
6 opAnd [expr; expr]   7 opOr [expr; expr]   8 opCDHash [data] -> cdhash H"hex"   9 opNot [expr] -> !expr
10 opInfoKeyField [key; match] -> info[key] <match>   11 opCertField [cert index; field name; match] -> certificate <slot>[subject.OU] <match>
12 opTrustedCert [cert index] -> certificate <slot> trusted   13 opTrustedCerts -> anchor trusted
14 opCertGeneric [cert index; OID data; match] -> certificate <slot>[field.1.2.840.113635.100.6.2.6] <match>
15 opAppleGenericAnchor -> anchor apple generic   16 opEntitlementField [key; match] -> entitlement[key] <match>
17 opCertPolicy [cert index; OID; match] -> certificate <slot>[policy.OID] <match>   18 opNamedAnchor [string] -> anchor apple <name>
19 opNamedCode [string] -> (name)   20 opPlatform [int32] -> platform = N   21 opNotarized -> notarized
22 opCertFieldDate [cert index; field; match] -> certificate <slot>[timestamp.OID] <match>   23 opLegacyDevID -> legacy
flags in the high byte: opFlagMask 0xFF000000, opGenericFalse 0x80000000, opGenericSkip 0x40000000 (mask off before switching)
```
Operand encodings: **data/string** = `uint32 length` + bytes, padded to a multiple of 4;
**cert index** = int32: 0 = `leaf`, -1 = `root`/`anchor`, n ≥ 1 = `certificate n` (from leaf);
**match** = `uint32 MatchOperation` (`0 exists ⇒ "/* exists */"`, `1 equal "="`, `2 contains "~"`,
`3 beginsWith`, `4 endsWith`, `5 lessThan "<"`, `6 greaterThan ">"`, `7 lessEqual`, `8 greaterEqual`,
`9 on`, `10 before`, `11 after`, `12 onOrBefore`, `13 onOrAfter`, `14 absent`) followed by a data
operand except for 0/14; OID data is DER OID content bytes (e.g. `2a 86 48 86 f7 63 64 06 02 06` =
1.2.840.113635.100.6.2.6). codesign quotes a string value only if it is not a plain
identifier (`= Q6L2SF6YDW` unquoted, `= "53Q6R32WPB"` quoted because it starts with a digit).
Verified decodes: `/bin/ls` 40-byte requirement `fade0c00 00000028 00000001 | 00000006 00000002 0000000c "com.apple.ls" 00000003`
→ `identifier "com.apple.ls" and anchor apple`; Burp stub 16-byte `… 00000001` → `always`; Claude
(172 B): `opAnd(opIdent, opAnd(opAppleGenericAnchor, opAnd(opCertGeneric(1, 1.2.840.113635.100.6.2.6, exists),
opAnd(opCertGeneric(0, 1.2.840.113635.100.6.1.13, exists), opCertField(0, "subject.OU", equal, "Q6L2SF6YDW")))))`
→ `identifier "com.anthropic.claudefordesktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */
and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = Q6L2SF6YDW`
(codesign prints nested `and` chains flat, parenthesises `or`: Cursor's DR ends `(certificate leaf[subject.OU] = VDXQ22DGB9 or … = DCNK4UB866)`).

**Entitlements:** slot 5 blob `0xfade7171`: payload is the XML plist text (starts `<?xml`);
slot 7 blob `0xfade7172`: DER, grammar (verified against `codesign -d --entitlements :-`):
```
Entitlements ::= [APPLICATION 16] (tag 0x70) SEQUENCE-like { INTEGER version (1), [CONTEXT 16] (tag 0xb0) SET OF Entry }
Entry ::= SEQUENCE (0x30) { UTF8String (0x0c) key, Value }
Value ::= BOOLEAN (0x01: ff/00) | INTEGER (0x02) | UTF8String (0x0c) | OCTET STRING (0x04, data) | SEQUENCE (0x30, array of Value) | [CONTEXT 16] (0xb0, nested dictionary of Entry) | (dates as UTCTime 0x17 / GeneralizedTime 0x18 — not seen)
```
Example (Burp): `70 81 df 02 01 01 b0 81 d9 30 24 0c 1f "com.apple.security.cs.allow-jit" 01 01 ff …`.
DER lengths: `< 0x80` one byte; `0x81 n`, `0x82 n n`; keys are sorted. Launch constraints
(`0xfade8181`, slots 8-11) use the same DER dictionary style (not present in corpus).

**CMS blob (slot 0x10000, `CSMAGIC_BLOBWRAPPER`):** payload is a CMS `SignedData` in
**BER with indefinite lengths** for Apple-signed binaries (`30 80 06 09 2a864886f70d010702 a0 80 30 80 02 01 01 31 0f …`;
Developer ID signatures use definite lengths `30 82 21 dd …`). An ASN.1 walker must therefore
handle length byte `0x80` (indefinite; content ends at the `00 00` end-of-contents pair) as
well as `0x8n` long forms. Structure: `ContentInfo SEQUENCE { OID 1.2.840.113549.1.7.2 (signedData),
[0] EXPLICIT SignedData SEQUENCE { INTEGER version, SET digestAlgorithms, SEQUENCE encapContentInfo (OID 1.2.840.113549.1.7.1 data, no content),
[0] IMPLICIT certificates SET OF Certificate, SET signerInfos } }`. Strategy that works (verified: produces
`Software Signing / Apple Code Signing Certification Authority / Apple Root CA` for `/bin/ls` and
`Developer ID Application: Anthropic PBC (Q6L2SF6YDW) / Developer ID Certification Authority / Apple Root CA` for Claude):
recursively walk every constructed TLV (tags 0x30, 0x31, 0xa0, 0xa3); a definite-length
`SEQUENCE` whose three children are `SEQUENCE, SEQUENCE, BIT STRING` is an X.509 `Certificate`;
its first child (`TBSCertificate`) has children `[0] version (optional, tag 0xa0), INTEGER serial,
SEQUENCE signatureAlgorithm, SEQUENCE issuer, SEQUENCE validity, SEQUENCE subject, …`; `Name` =
`SEQUENCE OF SET OF SEQUENCE { OID type, value }` with `2.5.4.3 CN (55 04 03)`, `2.5.4.11 OU (55 04 0b)`,
`2.5.4.10 O (55 04 0a)`, `2.5.4.6 C (55 04 06)`, `0.9.2342.19200300.100.1.1 UID` (Developer ID leaf:
`UID=<team>, CN=Developer ID Application: <org> (<team>), OU=<team>, O=<org>, C=US`). Values are
PrintableString (0x13) or UTF8String (0x0c). The leaf is the certificate whose issuer ≠ subject
and which is not an issuer of another cert; codesign's `Authority=` lines are the chain from leaf
to root. Signing time: `signingTime` (OID 1.2.840.113549.1.9.5) inside signerInfo signed
attributes; notarisation timestamp = RFC3161 token in unsigned attributes (not implemented in probe).

Trust ladder for display (from Wardle): platform (`anchor apple`, CD.platform ≠ 0) > Developer ID
(`anchor apple generic` + OID 1.2.840.113635.100.6.1.13 leaf) > App Store (…6.1.9) > ad hoc
(`CS_ADHOC`, no CMS blob) > unsigned (no LC_CODE_SIGNATURE). `CS_LINKER_SIGNED` (0x20000) marks
ld's automatic ad-hoc signature.

---

## 6. Objective-C runtime metadata (64-bit, objc4 "new" ABI)

Layouts below come from objc4 `objc-runtime-new.h` (not shipped in the SDK; only `objc/runtime.h`
public API is) and were **verified field-by-field against `xcrun objdump --macho --objc-meta-data`
and `dyld_info -objc`** on TextEdit (arm64e, fmt 12 chains), Electron Framework (arm64, fmt 2),
Hopper (x86_64, LC_DYLD_INFO_ONLY). All pointers are 8 bytes.

```
objc_class (in __objc_data, 40 bytes):  isa @0 | superclass @8 | cache.buckets @16 | cache.mask/occupied @24 ("vtable" in objdump) | data (bits) @32
  class_ro_t* = data & FAST_DATA_MASK (0x00007ffffffffff8); low bits FAST_IS_SWIFT_LEGACY 1, FAST_IS_SWIFT_STABLE 2, FAST_HAS_DEFAULT_RR 4
class_ro_t (in __objc_const, 72 bytes): uint32 flags @0 | uint32 instanceStart @4 | uint32 instanceSize @8 | uint32 reserved @12 |
  ivarLayout @16 | name @24 (char*) | baseMethods @32 (method_list_t*) | baseProtocols @40 | ivars @48 (ivar_list_t*) | weakIvarLayout @56 | baseProperties @64
  RO flags: RO_META 1<<0, RO_ROOT 1<<1, RO_HAS_CXX_STRUCTORS 1<<2, RO_HIDDEN 1<<4, RO_EXCEPTION 1<<5, RO_HAS_SWIFT_INITIALIZER 1<<6,
            RO_IS_ARC 1<<7, RO_HAS_CXX_DTOR_ONLY 1<<8, RO_HAS_WEAK_WITHOUT_ARC 1<<9, RO_FORBIDS_ASSOCIATED_OBJECTS 1<<10, RO_FROM_BUNDLE 1<<29, RO_FUTURE 1<<30, RO_REALIZED 1<<31
  (Electron: flags 0x94 = HAS_CXX_STRUCTORS|HIDDEN|IS_ARC; Hopper 0x194 adds HAS_CXX_DTOR_ONLY; metaclass flags have RO_META)
method_list_t: uint32 entsizeAndFlags @0 | uint32 count @4 | entries @8
  entsize = entsizeAndFlags & ~0xffff0003 ; smallMethodListFlag 0x80000000 ; (0x40000000 = uniqued selectors flag)
  method_t large (entsize 24): SEL name @0 (pointer to selector string) | const char* types @8 | IMP imp @16     (Hopper x86_64, minOS 12.4)
  method_t small (entsize 12, flag 0x80000000): int32 nameOffset @0 | int32 typesOffset @4 | int32 impOffset @8, each relative to ITS OWN field address;
     nameOffset points at a selector-reference slot (an 8-byte pointer in __objc_selrefs whose target is the string); types points at the string; imp at code (may be negative)
     (all modern arm64/x86_64 binaries with deployment >= macOS 11: TextEdit, Electron, Burp; lists live in __TEXT,__objc_methlist)
ivar_list_t: uint32 entsize (32) @0 | uint32 count @4 ; ivar_t: int32* offset @0 | char* name @8 | char* type @16 | uint32 alignment @24 (log2, 0xffffffff = default) | uint32 size @28
property_list_t: uint32 entsize (16) | uint32 count ; property_t: char* name @0 | char* attributes @8 (e.g. "TB,VusesDefaultHyphenation")
protocol_list_t: uintptr_t count @0 | protocol_t* list[count]
protocol_t: isa @0 | mangledName @8 | protocols @16 | instanceMethods @24 | classMethods @32 | optionalInstanceMethods @40 | optionalClassMethods @48 |
  instanceProperties @56 | uint32 size @64 | uint32 flags @68 | extendedMethodTypes @72 | demangledName @80 | classProperties @88  (read only up to `size`)
category_t: name @0 | cls @8 | instanceMethods @16 | classMethods @24 | protocols @32 | instanceProperties @40 | classProperties @48 (if image has HAS_CATEGORY_CLASS_PROPERTIES)
objc_image_info (__objc_imageinfo, 8 bytes): uint32 version (0) | uint32 flags
  flags: IsReplacement 1<<0, SupportsGC 1<<1, RequiresGC 1<<2, OptimizedByDyld 1<<3, CorrectedSynthesize 1<<4, IsSimulated 1<<5,
         HasCategoryClassProperties 1<<6, OptimizedByDyldClosure 1<<7, Swift unstable version = (flags >> 8) & 0xff (7 = "Swift 5 or later" per objdump),
         Swift stable ABI version = flags >> 16 (objc4 comment: "2 byte Swift stable ABI version number"; observed 0x0602 / 0x0603, which reads as major.minor 6.2 / 6.3 — interpretation, not verified against a toolchain)
  verified raw values: TextEdit 0x06020750 (objdump: "OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES Swift 5 or later"), Aviary 0x06030740, Burp 0x40 (no Swift), Electron 0x40
```
Sections (segment varies: `__DATA_CONST` in modern binaries, `__DATA` in older):
`__objc_classlist` (array of `objc_class*`, count = size/8; TextEdit 19 classes), `__objc_nlclslist`
(+load classes), `__objc_catlist` (`category_t*`; TextEdit 1), `__objc_nlcatlist`, `__objc_protolist`
(`protocol_t*`; TextEdit 7), `__objc_selrefs` (SEL slots → strings in `__objc_methname`), `__objc_classrefs`
/ `__objc_superrefs` (class pointer slots; external classes are binds), `__objc_imageinfo`, `__objc_const`
(class_ro_t, lists), `__objc_data` (objc_class), `__objc_ivar` (ivar offset u32 variables),
`__TEXT,__objc_methname` / `__objc_classname` / `__objc_methtype` (C strings), `__TEXT,__objc_methlist`
(relative method lists), `__TEXT,__objc_stubs` (arm64 `objc_msgSend` stubs). Class name = `class_ro_t.name`;
metaclass = `isa` of the class (its `class_ro_t.flags` has RO_META); superclass of a locally defined
class is a rebase (pointer into `__objc_data`) or a bind (external, e.g. `_OBJC_CLASS_$_NSDocument`).

**Pointers under chained fixups:** every pointer-sized slot in these sections is a chain entry,
so read it through the chained-fixup decoder: rebase → target vmaddr (per 4.1 rules; for fmt 12
add `image_base`), bind → external symbol name (e.g. superclass `_OBJC_CLASS_$_NSObject`), and
`isa`/`data` may carry auth bits on arm64e. `objdump` shows the un-decoded value (`superclass 0x0
_OBJC_CLASS_$_NSDocument` for binds). Raw TextEdit `__objc_classlist` bytes: `40 07 03 00 00 00 08 00`
→ 0x100030740 = `_OBJC_CLASS_$_Document` (see 4.1). Under legacy LC_DYLD_INFO the slots hold
plain unslid vmaddrs (rebases) or zeros (binds). Also strip PAC/high bits: mask targets with
`& 0x0000_7fff_ffff_ffff` before use, and `data & FAST_DATA_MASK`.

Expected values for tests (`/System/Applications/TextEdit.app/Contents/MacOS/TextEdit`, arm64e slice):
19 classes — first 12 in `__objc_classlist` order: `Document, IsLightAppearanceValueTransformer, Controller,
ScalingScrollView, MultiplePageView, Preferences, EncodingsWindowController, EncodingPopUpButtonCell,
EncodingManager, OpenSaveAccessoryOwner, DocumentController, DocumentWindowController`; 1 category
`NSTextView(TextEditAdditions)` (1 instance method); 7 protocols (`NSObject, NSApplicationDelegate,
NSWindowRestoration, NSLayoutManagerDelegate, NSTextDelegate, NSTextViewDelegate, …`); `Document`
superclass `NSDocument`, 79 instance methods (first `-[Document makeWindowControllers]` imp 0x1000022C0),
26 ivars (first `setUpPrintInfoDefaults` offset-var 0x100030674 value 8, type `B`), 2 properties;
section sizes: classlist 0x98, catlist 0x8, protolist 0x38, selrefs 0x1be0, superrefs 0x68,
methname 0x5ad9, classname 0x255, methtype 0x182d. Electron Framework (arm64): 132 classes, first
`MacLockMonitor : NSObject` with 10 methods (`init, dealloc, addEmitter:, removeEmitter:, onScreenLocked:,
onScreenUnlocked:, onUserDidBecomeActive:, onUserDidResignActive:, .cxx_destruct, .cxx_construct`).
`/Applications/Discord.app/Contents/MacOS/Discord` itself has **no** ObjC sections (Electron shell);
neither do Alacritty (Rust), Cursor, Claude main executables.

---

## 7. Binary property lists (`bplist00`) and `__TEXT,__info_plist`

Layout (CoreFoundation `CFBinaryPList.c`; verified with a controlled file and
`~/Library/Preferences/.GlobalPreferences.plist` / `com.apple.dock.plist` against `plutil -p`):
```
header  : "bplist00" (8 bytes; "bplist0?" other minor versions exist)
objects : object table, each object = marker byte (hi nibble = type, lo nibble = count/size) + payload
trailer : last 32 bytes, big-endian: uint8 unused[5]; uint8 sortVersion; uint8 offsetIntSize; uint8 objectRefSize;
          uint64 numObjects; uint64 topObject; uint64 offsetTableOffset
offset table: numObjects entries of offsetIntSize bytes (big-endian), at offsetTableOffset; entry i = file offset of object i
```
Object markers (`m`, `hi = m >> 4`, `lo = m & 0xf`; when `lo == 0xf` the count follows as an
int object: marker `0x1n` then `2^n` bytes big-endian):
```
0x00 null   0x08 false   0x09 true   0x0f fill
0x1n int    : 2^n bytes big-endian (n=0..3; n=3 8-byte is signed; n=4 16-byte); negative ints always 8 bytes
0x2n real   : 2^n bytes IEEE big-endian (0x22 float, 0x23 double)
0x33 date   : 8-byte double, seconds since 2001-01-01T00:00:00Z (CFAbsoluteTime)
0x4c data   : lo/count bytes
0x5c string : ASCII, count chars       0x6c string : UTF-16BE, count code units      0x7x: unused in bplist00 (reject)
0x8n uid    : n+1 bytes (NSKeyedArchiver)
0xac array  : count refs      0xcc set : count refs      0xdc dict : count key refs then count value refs
refs are objectRefSize-byte big-endian indices into the offset table
```
Worked example (`tiny.bplist`, 146 bytes): `62706c6973743030 | d8 01..08 09 0a 0b 0c 0d 0e 11 12 | 51 74 (“t”) … | 33 3ff0000000000000 (date 2001-01-01T00:00:01Z)
| 65 0068 00e9 006c 006c 006f ("héllo" UTF-16) | 43 010203 (data) | 11 012c (300) | 23 3ff8000000000000 (1.5) | a2 0f 10 (array)
| 10 01 (1) | 13 ffffffffffffffff (-1) | 52 6869 ("hi") | 09 (true) | offset table 08 19 1b 1d 1f 21 23 25 27 29 32 3d 41 44 4d 50 52 5b 5e
| trailer 0000000000 00 01 01 0000000000000013 0000000000000000 000000000000005f` → offsetIntSize 1, refSize 1,
19 objects, top 0, table at 0x5f. `.GlobalPreferences.plist`: `bplist00 df 10 26 …` (dict of 38, count as int8),
trailer offsetIntSize 2, refSize 1, 97 objects, top 0, table at 1629 — probe key count 38 = plutil.
Info.plist files in this corpus (Discord, TextEdit, Alacritty, Safari) are XML; Apple/3rd-party
apps may use either, so detect by the first 8 bytes (`bplist00` vs `<?xml`/`<plist`). XML plist
keys of interest: `CFBundleExecutable`, `CFBundleIdentifier`, `CFBundleShortVersionString`,
`CFBundleVersion`, `LSMinimumSystemVersion`, `NSAppTransportSecurity`, `LSUIElement`.

**`__TEXT,__info_plist`:** command-line tools embed their Info.plist as an XML text section
(no bplist seen). Verified `/usr/bin/codesign` arm64e: `sectname __info_plist segname __TEXT addr 0x10001e215
size 0x1f8 offset 123413`, contents begin `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist … <dict>\n\t<key>CFBundleDevelo…`.
Also present in `/usr/libexec/xpcproxy`, `/usr/bin/ssh`, `/usr/libexec/sshd-keygen-wrapper`, `/usr/bin/osascript`, `/usr/libexec/trustd`.
The CD special slot -1 hashes this plist when bound.

---

## 8. Quarantine xattr and app translocation

`com.apple.quarantine` value (verified with `xattr -p`): `flags;timestamp;agent;uuid`, four
`;`-separated ASCII fields:
- `flags`: 4 hex digits, e.g. `0081` (PDF downloaded by Firefox), `01c1` / `03c1` (downloaded .app
  bundles that have been opened and approved). Bit meanings are not in any public header on this
  machine; observed only. Treat non-empty value = quarantined; `0x0040`-style approval bits are
  unverified.
- `timestamp`: hex seconds since the Unix epoch (`0x69aa7f48` → `date -r` = Fri Mar 6 02:16:24 EST 2026).
- `agent`: application name that created the file (`Firefox`, `Safari`, `Chrome`, `curl` absent → no xattr).
- `uuid`: `LSQuarantineEventIdentifier` keying `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`
  (SQLite; on this machine the file exists (20 KB) but has no tables, so the lookup could not be verified;
  historically table `LSQuarantineEvent` with `LSQuarantineDataURLString`, `LSQuarantineOriginURLString`).
`LSQuarantine.h` keys (kLSQuarantineAgentNameKey, AgentBundleIdentifierKey, TimeStampKey, TypeKey
(`kLSQuarantineTypeWebDownload`, `OtherDownload`, `EmailAttachment`, `InstantMessageAttachment`,
`CalendarEventAttachment`, `OtherAttachment`), DataURLKey, OriginURLKey) describe the same record.
Read with `xattr -p com.apple.quarantine <path>` or `getxattr(2)`; `xattr -l` lists all.
Examples: `/Applications/Alacritty.app => 01c1;69aa7f48;Firefox;DC0FB98F-9143-4CEE-A5F3-D77C06CB27EF`,
`~/Downloads/….pdf => 0081;6a8dca47;Firefox;714D7932-…`.

**App translocation:** Gatekeeper runs a quarantined app that was not moved by the user from a
read-only randomized mount `/private/var/folders/<xx>/<yyyyyy…>/T/AppTranslocation/<UUID>/d/<Name>.app`;
detect by `strstr(path, "/AppTranslocation/")` in the executable path / `proc_pidpath`. No
translocated app was running and `…/T/AppTranslocation` was empty on this machine (dir pattern
from Apple docs; not observed live).

---

## 9. Ground truth for tests

### 9.1 `/bin/ls` (universal; use the arm64e slice at file offset 65536 unless noted)
- `file`: `Mach-O universal binary with 2 architectures: [x86_64 …] [arm64e …]`.
- fat: magic 0xcafebabe, nfat_arch 2; slice0 x86_64 (cputype 0x01000007, sub 3, offset 16384, size 48112, align 14);
  slice1 arm64e (0x0100000c, sub 0x80000002, offset 65536, size 89088, align 14).
- arm64e mach_header_64: magic 0xfeedfacf, filetype 2, ncmds 20, sizeofcmds 1712, flags 0x00200085;
  x86_64: ncmds 18, sizeofcmds 1736, flags 0x00200085, cpusubtype 3.
- arm64e load commands in order: LC_SEGMENT_64 ×5 (`__PAGEZERO` vm 0/0x100000000; `__TEXT` 0x100000000/0x8000
  file 0/32768 prot 5/5 5 sects; `__DATA_CONST` 0x100008000/0x4000 file 32768/16384 flags 0x10 3 sects;
  `__DATA` 0x10000c000/0x4000 file 49152 3 sects; `__LINKEDIT` 0x100010000/0x8000 file 65536/23552 prot 1/1),
  LC_DYLD_CHAINED_FIXUPS (65536, 1424), LC_DYLD_EXPORTS_TRIE (66960, 32), LC_SYMTAB (symoff 67072, nsyms 92, stroff 69240, strsize 1000),
  LC_DYSYMTAB (ilocal 0/1, iextdef 1/1, iundef 2/90, indirectsymoff 68544, nindirect 174), LC_LOAD_DYLINKER `/usr/lib/dyld`,
  LC_UUID `322CB148-C401-3EA0-A023-4B21A104D42F`, LC_BUILD_VERSION (platform 1, minos 11.0, sdk 26.3, ntools 1: LD 1230.4),
  LC_SOURCE_VERSION 475.0 (raw 0x1db0000000000), LC_MAIN (entryoff 2400 = 0x960, stacksize 0),
  LC_LOAD_DYLIB ×3 (`/usr/lib/libutil.dylib` 1.0.0/1.0.0; `/usr/lib/libncurses.5.4.dylib` 5.4.0/5.4.0; `/usr/lib/libSystem.B.dylib` 1356.0.0/1.0.0; timestamps 2),
  LC_FUNCTION_STARTS (66992, 80), LC_DATA_IN_CODE (67072, 0), LC_CODE_SIGNATURE (70240, 18848).
- Sections (arm64e): `__TEXT`: `__text` 0x100000700 size 0x3bac off 1792 flags 0x80000400; `__auth_stubs` 0x1000042ac 0x540 off 17068
  flags 0x80000408 res1 0 res2 16; `__const` 0x1000047f0 0x105; `__cstring` 0x1000048f5 0x503 flags 0x2; `__unwind_info` 0x100004df8 0xd0.
  `__DATA_CONST`: `__auth_got` 0x100008000 0x2a0 flags 0x6 res1 84; `__got` 0x1000082a0 0x30 flags 0x6 res1 168; `__const` 0x1000082d0 0x268.
  `__DATA`: `__data` 0x10000c000 0x20; `__common` 0x10000c020 0xb0 flags 0x1 off 0; `__bss` 0x10000c0d0 0x158 flags 0x1.
- `nm -arch arm64e`: 91 lines; first `U __DefaultRuneLocale, U ___assert_rtn, U ___error, U ___maskrune, U ___stack_chk_fail`; last `U _write`;
  `nm -m`: `(undefined) external __DefaultRuneLocale (from libSystem)`.
- `dyld_info -platform`: macOS 11.0 / sdk 26.3. `-exports`: 1 (`0x00000000 __mh_execute_header`). `-imports`: 90, first
  `_humanize_number (from libutil), _tgetent, _tgetstr, _tgoto, _tputs (from libncurses.5), ___assert_rtn (from libSystem)`.
  `-fixups`: 113 lines = 84 auth-bind + 6 bind + 23 rebase; first `__DATA_CONST __auth_got 0x100008000 auth-bind libutil/_humanize_number (div=0x0000 ad=1 key=IA)`;
  first bind `__got 0x1000082A0 libSystem/__DefaultRuneLocale`; first rebase `__const 0x1000082D0 → 0x100004A03`; last `__DATA __data 0x10000C008 rebase 0x10000C004`.
  `-fixup_chains`: imports 90 (format 1), symbols_format 0, seg[2] fmt 1 page 0x4000 seg_off 0x8000 start[0]=0; seg[3] seg_off 0xC000 start[0]=0x8.
  `-function_starts`: 50 entries (see 4.4).
- `codesign -dvvv --arch arm64e`: Identifier `com.apple.ls`; `CodeDirectory v=20400 size=741 flags=0x0(none) hashes=18+2`; Platform identifier 26;
  Hash type sha256 size 32; `CDHash=4f35b3163233a684d47f496a1e050f518de37621`; Signature size 4442; Authority `Software Signing`,
  `Apple Code Signing Certification Authority`, `Apple Root CA`; TeamIdentifier not set; `Info.plist=not bound`; requirements count 1 size 60;
  `codesign -d -r-`: `designated => identifier "com.apple.ls" and anchor apple`. Entitlements: none.
- `vtool -show`: `LC_BUILD_VERSION platform MACOS minos 11.0 sdk 26.3 ntools 1 tool LD version 1230.4`; `LC_SOURCE_VERSION version 475.0`.

### 9.2 `enumerateProcess` (thin arm64, 35 KB, ad hoc linker-signed, with stabs)
- header: cputype 0x0100000c sub 0, filetype 2, ncmds 17, sizeofcmds 1056, flags 0x00200085.
- LCs: `__PAGEZERO`; `__TEXT` 0x100000000/0x4000 (4 sects: `__text` 0x100000460 size 0x334 off 1120; `__stubs` 0x100000794 0x9c off 1940 res2 12;
  `__cstring` 0x100000830 0xa9; `__unwind_info` 0x1000008dc 0x60); `__DATA_CONST` 0x100004000/0x4000 file 16384 flags 0x10 (`__got` 0x100004000 0x88 flags 6 res1 13);
  `__LINKEDIT` 0x100008000/0x4000 file 32768/1936; LC_DYLD_CHAINED_FIXUPS (32768, 376); LC_DYLD_EXPORTS_TRIE (33144, 72);
  LC_SYMTAB (33224, 33 syms, stroff 33872, strsize 408); LC_DYSYMTAB (local 0/13, extdef 13/3, undef 16/17, indirectsymoff 33752, n 30);
  LC_LOAD_DYLINKER; LC_UUID `C8099B17-4814-386C-8413-D40CDA19A541`; LC_BUILD_VERSION (macOS, minos 26.0, sdk 26.5, LD 1267.0);
  LC_SOURCE_VERSION 0.0; LC_MAIN entryoff 1292 (0x50c); LC_LOAD_DYLIB libSystem.B 1356.0.0/1.0.0; LC_FUNCTION_STARTS (33216, 8);
  LC_DATA_IN_CODE (33224, 0); LC_CODE_SIGNATURE (34288, 416).
- `nm`: 20 lines: 17 `U` (`___chkstk_darwin, ___stack_chk_fail, ___stack_chk_guard, ___stderrp, _bzero, _calloc, _fprintf, _free,
  _mach_port_deallocate, _mach_task_self_, _printf, _proc_listallpids, _proc_pidpath, _strstr, _sysctlbyname, _task_info, _task_name_for_pid`),
  `0000000100000000 T __mh_execute_header`, `0000000100000460 T _getAuditToken`, `000000010000050c T _main`. `nm -a` adds 13 stabs.
- `dyld_info`: platform macOS 26.0/26.5; exports 3 (`0x0 __mh_execute_header, 0x460 _getAuditToken, 0x50C _main`); imports 17 (all libSystem, order as above);
  fixups 17 binds in `__DATA_CONST __got` 0x100004000..0x100004080, no rebases; chain header (starts 0x20, imports 0x50, symbols 0x94, 17, fmt 1, 0);
  seg[2] fmt 6, page 0x4000, seg_off 0x4000, 1 page, start 0; raw first pointer 0x8010000000000000, last 0x8000000000000010; function starts 2.
- `codesign -dvvv`: Identifier `enumerateProcess`; `CodeDirectory v=20400 size=393 flags=0x20002(adhoc,linker-signed) hashes=9+0`;
  `CDHash=973fb442b089ddd2e62c39dd642e246c6872aad7`; `Signature=adhoc`; TeamIdentifier not set; `Internal requirements=none`;
  `-r-`: `# designated => cdhash H"973fb442b089ddd2e62c39dd642e246c6872aad7"`; superblob length 413, count 1; code slot 0 = sha256 of first 4096 bytes
  = `55e1139936e7549b2f9347395d4243eaeb5fd56525d4e73c2f439b00b079e810`. `vtool`: platform MACOS minos 26.0 sdk 26.5 LD 1267.0.

### 9.3 Other corpus expectations
- `/Applications/Claude.app/Contents/MacOS/Claude` (universal x86_64+arm64, Developer ID, hardened runtime): arm64 CD v0x20500 size 458
  flags 0x10000 hashes 3+7 pageSize 2^14, team `Q6L2SF6YDW`, `CDHash=ff2a59b49054875423c564c9f75c0dce03e8eb69`, runtime 26.5.0, requirements 192 B,
  entitlements 14 keys incl. `com.apple.security.cs.allow-jit`, `keychain-access-groups` (5 strings); LC_RPATH `@executable_path/../Frameworks`.
- `/Applications/Discord.app/Contents/MacOS/Discord`: identifier `com.hnc.Discord`, team `53Q6R32WPB`, CD v0x20500 flags 0x10000, no ObjC sections;
  its `Frameworks/Electron Framework.framework/Versions/A/Electron Framework` (arm64): MH_DYLIB, LC_ID_DYLIB `@rpath/Electron Framework.framework/Electron Framework`
  (0.0.0/0.0.0), LC_RPATH `@loader_path/Libraries`, 66 LC_LOAD_DYLIB + 2 LC_LOAD_WEAK_DYLIB (QuickLookThumbnailing, ScreenCaptureKit),
  chained fixups fmt 2 (imports 5037, 573785 rebases, 7978 binds), exports 11158 (2673 weak), 132 ObjC classes.
- `/Applications/Burp Suite.app/Contents/MacOS/JavaApplicationStub` (thin arm64, minOS 11.0, LC_DYLD_INFO_ONLY): rebase 463 / bind 235 / lazy 66,
  exports 25, designated requirement `always`, CD v0x20400 flags 0x10000 hashes 27+7, team `N82YM748DZ`, 4 DER entitlements.
- `/Applications/Alacritty.app/Contents/MacOS/alacritty`: x86_64 slice has LC_VERSION_MIN_MACOSX 10.12 / sdk 15.5 and LC_DYLD_INFO_ONLY; ad hoc signed
  (`designated => cdhash H"…" or cdhash H"…"`), no ObjC method lists.
- `/opt/homebrew/opt/capstone/lib/libcapstone.dylib` (thin arm64 MH_DYLIB): LC_ID_DYLIB `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib` 5.0.8/5.0.0,
  exports 20 (`_cs_close 0xefc, _cs_disasm 0x1290, _cs_disasm_iter 0x1a90, _cs_errno 0xda8 …`), chained fixups.
- `/usr/lib/dyld` (on disk): MH_DYLINKER (7), LC_UNIXTHREAD arm64e pc 0x49c0 / x86_64 rip 0x4e50, LC_SEGMENT_SPLIT_INFO present.
- `/System/Applications/TextEdit.app/Contents/MacOS/TextEdit`: see section 6; CD v0x20400 hashes 97+7 platform 26, `CDHash=979142b9eb7fed28f3485f5bdc07dc4b86a6687c`,
  DR `identifier "com.apple.TextEdit" and anchor apple`, chained fixups fmt 12.
- Safari: `/Applications/Safari.app/Contents/MacOS/Safari` is a stub; the real executable is
  `/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari` (codesign reports that path).

---

## 10. Zig `std.macho` (0.17.0-dev.1154) coverage vs. this document
Present: mach_header(_64), fat_header, fat_arch, load_command, uuid/version_min/source_version/build_version/
build_tool_version/entry_point/symtab/dysymtab/linkedit_data/dyld_info/dylinker/dylib(_command)/rpath/
segment_command(_64)/section(_64)/nlist(_64)/data_in_code_entry, unwind structs; `LC` enum (non-exhaustive,
ends at `DYLD_CHAINED_FIXUPS = 0x34|LC_REQ_DYLD`); MH_*, SG_*, S_*, N_*, REBASE_/BIND_/EXPORT_ constants,
INDIRECT_SYMBOL_*, CPU types, TOOL enum with extra `ZIG = 5`.
**Missing (define locally):** `fat_arch_64`, `dylib_use_command`, `thread_command` + thread states,
`routines_command(_64)`, `sub_*_command`, `prebound_dylib_command`, `twolevel_hints_command`/`twolevel_hint`,
`prebind_cksum_command`, `encryption_info_command(_64)`, `note_command`, `fileset_entry_command`,
`linker_option_command`, `target_triple_command`, `LC_FILESET_ENTRY 0x35|REQ`, `LC_ATOM_INFO 0x36`,
`LC_FUNCTION_VARIANTS 0x37`, `LC_FUNCTION_VARIANT_FIXUPS 0x38`, `LC_TARGET_TRIPLE 0x39`, `LC_LAZY_LOAD_DYLIB_INFO 0x3a`,
every `dyld_chained_*` struct and `DYLD_CHAINED_PTR_*` constant, all cs_blobs.h types, all ObjC layouts,
bplist. Bitfield structs must be decoded with shifts/masks (Zig packed structs are viable but the
bit order is LSB-first as listed in 4.1).

## 11. Probe files (scratchpad `…/9135d7a5-…/scratchpad/format-notes/`)
- `probe_layout.c` — sizeof/offsetof of every loader.h, fat.h, nlist.h, fixup-chains.h, cs_blobs.h, arm64 thread-state struct (compiled with `xcrun clang`).
- `probe_x86state.c` — x86_64 thread state (`-arch x86_64`, `_Static_assert`s + run under Rosetta).
- `probe_codesign.py` — superblob/CodeDirectory/cdhash/requirements pretty-printer/DER entitlements/CMS certificate names.
- `probe_chains.py` — chained fixup walker (formats 1, 2, 6, 12) with dyld_info-style output.
- `probe_exports.py` — export trie walker. `probe_funcstarts.py` — LC_FUNCTION_STARTS. `probe_opcodes.py` — legacy rebase/bind/lazy streams.
- `probe_bplist.py` — bplist00 parser. `tiny.plist`/`tiny.bplist` — controlled plist sample. `gt/` — saved tool outputs (`ls_arm64e_l.txt`, `enum_l.txt`, `ls_fixups.txt`, `burp_opcodes.txt`, …).

---

## 12. Completeness-critic additions (verified 2026-09-11)

Probe sources: scratchpad `critic/` (`cfstr.c`, `cspac.c`, `src/sec.zig`, `walk.zig`); Apple-tool outputs quoted inline.

### 12.1 `__DATA_CONST,__cfstring`: constant CFString layout (strings extractor)
32 bytes per entry, verified with `CFSTR("plain ascii")` / `CFSTR("héllo unicode")` (`cfstr.c`) and hello-objc (`otool -s __DATA_CONST __cfstring`):
```
struct __CFConstantString { void *isa @0; uint64_t flags @8; const void *data @16; uint64_t length @24; }
isa    : chained-fixup BIND slot -> ___CFConstantStringClassReference (hello-objc raw 0x80200000_0000000e: bind=1, next=4 (x4 B = 16 -> the data slot), import ordinal 14)
flags  : 0x7c8 = 8-bit string: data -> NUL-terminated bytes in __TEXT,__cstring, length = byte count
         0x7d0 = UTF-16 string: data -> __TEXT,__ustring (UTF-16LE), length = code units
data   : chained-fixup REBASE slot (fmt 6: image_base + target; raw 0x00200000_0000190c -> 0x10000190c)
length : plain u64
```
Section align 2^3; entry count = size / 32 (hello-objc 0x160 → 11). Under legacy `LC_DYLD_INFO` the `isa` slot is 0 (bound at load) and `data` holds the unslid vmaddr. `__TEXT,__ustring` bytes look like `68 00 e9 00 6c 00 …`; `strings(1)` never shows them, so a strings pass must scan `__ustring` (and generic UTF-16LE runs) separately.

### 12.2 `__TEXT,__objc_stubs` stride
hello-objc: size 0x1e0, align 2^5 → 15 stubs of **32 bytes** (`-objc_stubs_fast`, ld-1267 default) serving 40 `__objc_selrefs`; stub count = distinct selectors sent through `objc_msgSend`. `reserved2` is 0 (section type S_REGULAR), so the stride comes from the alignment/disassembly, not from `reserved2`. (`-objc_stubs_small` produces a different size; not built here.)

### 12.3 Dual CodeDirectories (SHA-1 + SHA-256)
9 of the `/Applications/*.app` main executables (Sketch, Termius, Jump Desktop, MKPlayer, Swift Playground, CleanMyMac_5_MAS, Authenticator, App for Google Authenticator, iNet Network Scanner — Mac App Store signatures) carry slot 0 = CodeDirectory `hashType 1` (SHA-1) **and** slot `0x1000` (`CSSLOT_ALTERNATE_CODEDIRECTORIES`) = CodeDirectory `hashType 2` (SHA-256), both v0x20400/v0x20500, plus requirements (2), entitlements (5, 7) and CMS (0x10000). `codesign -dvvv` prints `Hash choices=sha1,sha256`, `CandidateCDHash sha1=3e777e81…` / `sha256=417d4058…`, and **`CDHash=` is the SHA-256 one**; `kSecCodeInfoUnique` is the same SHA-256 cdhash and `kSecCodeInfoCdHashes` lists both. Rule: enumerate slot 0 and 0x1000..0x1004, hash each CD with its own `hashType`, and present the strongest as *the* CDHash; each CD has its own special-slot hashes. Developer ID / ad-hoc / platform signatures here have a single SHA-256 CD.

### 12.4 Notarization artifacts
- Stapled ticket = `<App>.app/Contents/CodeResources` at the bundle root (**not** `_CodeSignature/CodeResources`): Discord 2304 B, Claude 2.7 KB; bytes begin `73 38 63 68` ("s8ch") `01 00 00 00 f0 05 00 00 b8 02 00 00` then BER `30 82 05 ec …`; absent for Alacritty. `kSecCodeInfoStapledNotarizationTicket` returns exactly these bytes (needs `kSecCSContentInformation`). A bare Mach-O could carry a ticket in superblob slot `CSSLOT_TICKETSLOT 0x10002` (none seen on this machine).
- `xcrun stapler validate <path>`: exit 0 with a ticket ("The validate action worked!"), **exit 65** without ("does not have a ticket stapled to it"), 65 for `/bin/ls` too.
- `codesign --verify -R='notarized' <path>`: exit 0 for Discord.app/Claude.app; exit 3 "code failed to satisfy specified code requirement(s)" for Alacritty.app, `/bin/ls`, hello-adhoc. `codesign --verify -R='anchor apple' /bin/ls` → 0.
- `spctl -a -vv -t exec <bundle>` (stderr): `accepted` + `source=Notarized Developer ID` + `origin=Developer ID Application: … (TEAM)`, exit 0; ad-hoc bundles `rejected`, exit 3; bare Mach-Os are always rejected ("does not seem to be an app", `errSecCSNotAppLike -67002`).
- Requirement language (`notarized`, opcode 21) via Security.framework: platform binaries and Mac App Store apps do **not** satisfy `notarized`; Developer ID apps with a ticket do (see zig-api-notes 15.11 for the full matrix).

### 12.5 `_CodeSignature/CodeResources` schema (XML plist, "Sealed Resources version=2")
Verified on corpus `Hello.app` (rules=13, files=1) and `Discord.app` (15 v1 / 24 v2 entries):
```
dict {
  files  : dict path -> <data> SHA-1 (20 B)  |  dict { hash: <data> SHA-1, optional: bool }                     (version-1 seal kept for old OSes)
  files2 : dict path -> dict { hash2: <data> SHA-256 (32 B) [, optional: true] }                                   (resource file)
                       | dict { cdhash: <data> 20 B, requirement: string }                                        (nested code: frameworks, helper apps, dylibs, XPC services; no file hash — verify by the nested code's own CD cdhash + DR)
                       | dict { symlink: string target }                                                           (symlink; none in these two bundles)
  rules  : dict regex -> true | dict { weight: real, omit: bool, optional: bool }                                 (v1; paths relative to Contents/)
  rules2 : dict regex -> true | dict { weight: real, omit, optional, nested: bool }                               (v2; `nested` marks code-bearing dirs)
}
```
Default `rules2` include `^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/` (nested, weight 10), `^[^/]+$` (nested), `^Info\.plist$` and `^PkgInfo$` (omit, weight 20), `^(.*/)?\.DS_Store$` (omit), `.*\.dSYM($|/)`, `^Resources/.*\.lproj/` (optional), `^embedded\.provisionprofile$`, `^version\.plist$`. `<data>` payloads are base64 wrapped with tab/newline whitespace. Examples: `Frameworks/libhello.dylib → cdhash 41b85e203bb8c224afbb5cc02bb4a5d28049b754, requirement 'cdhash H"41b8…b754"'`; Discord `Frameworks/Electron Framework.framework → cdhash d5576e6a…, requirement 'identifier "com.github.Electron.framework" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "53Q6R32WPB"'`; `Resources/app.asar → hash2 81b176f0…`. CD special slot -3 hashes this file; `Info.plist` is covered by slot -1 instead (hence `omit`).

### 12.6 Bundle layouts (verified on Discord.app, its nested bundles, and corpus Hello.app)
- App: `X.app/Contents/{Info.plist, PkgInfo ("APPL????"), MacOS/<CFBundleExecutable>, Frameworks/, Resources/, PlugIns/, XPCServices/, Helpers/, Library/LoginItems/, _CodeSignature/CodeResources, CodeResources (stapled ticket), embedded.provisionprofile}`. `Frameworks/` may hold nested apps (`Discord Helper (GPU).app`: `CFBundlePackageType APPL`, `LSUIElement true`, own `_CodeSignature`).
- Framework: `X.framework/Versions/A/{X (MH_DYLIB), Resources/Info.plist (CFBundlePackageType FMWK), _CodeSignature/, Frameworks/, Helpers/, Libraries/}` with top-level symlinks `X -> Versions/Current/X`, `Resources -> Versions/Current/Resources`, `Versions/Current -> A`. **No `Contents/`**; the Info.plist is `Versions/A/Resources/Info.plist`.
- Detection: directory containing `Contents/Info.plist` (app / bundle / `.xpc`) or `Versions/*/Resources/Info.plist` (framework); main executable = `Contents/MacOS/` + `CFBundleExecutable`. Keys worth reporting: `CFBundleIdentifier`, `CFBundleExecutable`, `CFBundlePackageType` (`APPL`, `FMWK`, `BNDL`, `XPC!`), `CFBundleShortVersionString`, `LSMinimumSystemVersion`, `LSUIElement`, `LSBackgroundOnly`, `NSAppleEventsUsageDescription`, `NSPrincipalClass`.
- Walking must not descend symlinked directories twice (`Versions/Current`); Zig's `Io.Dir.Walker` reports them as `sym_link` and does not descend (zig-api-notes 15.7).

### 12.7 Security.framework's view of a file inside a bundle
`SecStaticCodeCreateWithPath` on `Contents/MacOS/<exe>` of any bundle (app, helper app, framework `Versions/A/X`) evaluates the **bundle** (Format `app bundle with …` / `bundle with …`, identifier = `CFBundleIdentifier`, bundle DR, stapled ticket visible, `kSecCodeInfoMainExecutable` = the path). The same bytes outside a bundle (`hello-objc` vs `Hello.app/Contents/MacOS/Hello`) are `Mach-O thin (arm64)` with identifier `hello-objc`. Report the embedded signature parsed from `LC_CODE_SIGNATURE` *and* the Security verdict, and name the object Security evaluated.

### 12.8 dyld shared-cache residency
`_dyld_shared_cache_contains_path()` (`<mach-o/dyld.h>:128`, macOS 11+) is true for every system dylib/framework path with no on-disk file (`/usr/lib/libSystem.B.dylib`, `/usr/lib/libutil.dylib`, `/usr/lib/libncurses.5.4.dylib`, `/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation`) and false for `/opt/homebrew/...` and nonexistent paths. Dependency resolution: `@rpath/` → each `LC_RPATH` (expanding `@executable_path`/`@loader_path`) → on disk; absolute → on disk **or** in the shared cache; otherwise "missing" (a real tell only for non-system paths).

### 12.9 Still unverified (kept from earlier sections)
Quarantine-flag bit meanings (no header on this machine; only `0081`/`0083` unopened vs `01c1`/`03c1` approved observed); `LSQuarantineEventsV2` table lookup; app-translocation path observed live; `-objc_stubs_small` stride; launch-constraint DER (`0xfade8181`) and `CSSLOT_TICKETSLOT` contents; 32-bit (`MH_MAGIC`, `section` 68 B) and big-endian (`MH_CIGAM`) files — none exist in the corpus, so parse their headers for reporting only.
