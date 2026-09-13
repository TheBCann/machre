# machre test corpus — notes

Location: `tests/corpus/` (fixtures at the root, `malformed/` for robustness cases, `truth/` for
Apple-tool ground truth, `gen/` for the generators). Everything below was built and verified on
macOS 26.3 (25D125), Xcode 26.6 / Apple clang 21.0.0 (clang-2100.1.1.101), ld-1267, SDK 26.5,
Zig 0.17.0-dev.1154+ba5420896, on 2026-09-11. `truth/TOOLS.txt` records the exact toolchain.

All fixtures are built from sources in `gen/src/` that we wrote, so they can be redistributed.
The only stored random input is `gen/src/random.bin` (64 KiB from `/dev/urandom`, generated once).

## Regenerating

```sh
bash tests/corpus/gen/build.sh   # rebuild every fixture (idempotent, byte-for-byte reproducible)
bash tests/corpus/gen/truth.sh   # re-capture Apple-tool output + regenerate truth/summary.json
```

`build.sh` uses `/usr/bin/clang` (Apple clang; NOT the Homebrew llvm `clang` that is first on
PATH here — it targets the same triple but is a different linker/driver), `lipo`, `codesign`,
`plutil`, `xattr`, `python3`, and the Zig nightly at `$ZIG` (default
`/Users/bcann/.zig-versions/nightly/zig`). Intermediates go to a `mktemp -d` dir that is removed
on exit. Two consecutive runs were verified to produce identical SHA-256 for all 52 files
(see "Reproducibility" below for the flag that makes this true).

`truth.sh` writes one `truth/<name>.txt` per healthy fixture (plus `/bin/ls` as `bin-ls.txt`)
containing, in `===== cmd =====` sections with exit codes: `file`, `stat`, `shasum`, `otool -hv`,
`otool -h -l`, `otool -L`, `nm -m`, `nm -a`, `dyld_info` (`-platform -uuid -segments
-linked_dylibs -load_commands`, `-fixup_chains`, `-fixups`, `-exports`, `-imports`, `-objc`,
`-inits`, `-function_starts`, `-validate_only`), `vtool -show`, `codesign -dvvv --entitlements -`,
`codesign -d --entitlements - --xml`, `codesign -d -r -`, `codesign --verify --strict`,
`spctl -a -vv -t exec`, `xattr -l`, and for the app also `plutil -p`/`plutil -lint`, `find`,
`codesign -dvvv` on the embedded dylib; `objdump --macho --objc-meta-data` when an
`__objc_classlist` section exists; `strings -n 6 | head -200`. It also writes
`truth/malformed-tool-reactions.txt` (how otool / dyld_info / file / codesign react to each
malformed fixture) and `truth/TOOLS.txt`.

## summary.json (the machine oracle)

`truth/summary.json` is produced by `gen/summary.py`, an *independent* pure-Python Mach-O and
code-signature parser. For each fixture it records: size, sha256, `file` output, container
(thin/fat), fat arches (cputype/subtype/offset/size/align), and per slice: magic, cputype,
cpusubtype (+caps byte), filetype, ncmds, sizeofcmds, MH_ flags (values verified against
`mach-o/loader.h`), load-command names in order, segments (name, vmaddr, vmsize, fileoff,
filesize, prots, flags, Shannon entropy, fraction of file) with their sections (name, addr, size,
offset, align, flags, type), dylibs (cmd, path, timestamp, versions), `LC_ID_DYLIB`, rpaths,
dylinker, UUID, `LC_BUILD_VERSION` (platform, minos, sdk, tools), `LC_SOURCE_VERSION`, `LC_MAIN`
(entryoff, stacksize), `LC_SYMTAB`/`LC_DYSYMTAB` fields, symbol counts from an nlist scan
(defined / undefined / stabs / external / local), first-20 defined and undefined names, `LC_DYLD_INFO`
offsets, chained-fixups header + per-segment starts (page size, pointer format), exports trie,
function starts, data-in-code, the full code-signature SuperBlob slot table, the CodeDirectory
(version, flags + names, hash type, page size, code/special slot counts, code limit, exec-seg
fields, identifier, team id, cdhash + full sha256), entitlement keys (from the XML blob), DER
entitlement presence/length, CMS blob length, ObjC class / category / protocol names from the
symbol table, plus `dyld_info`-scraped exports / imports (with source dylib) / ObjC classes and
`nm -m`-scraped undefined-with-dylib lists. Per file it also records `codesign -dvvv` facts
(identifier, team id, cdhash, flags, signature kind, format, authority chain, verify result,
entitlement keys via `--xml`), the `spctl -a -vv -t exec` verdict, xattrs and the quarantine
string, and for the app the parsed `Info.plist`, its format, and the file list.

The parser cross-checks itself: ncmds/sizeofcmds against `otool -h`, and identifier, cdhash and
CS flags against `codesign -dvvv` (a mismatch aborts generation). All 13 signed thin fixtures
pass (`"cross_check"` key present). Hex fields are lowercase `0x` strings, offsets/sizes decimal.

## Fixture inventory

| fixture | bytes | what it is | exercises |
|---|---:|---|---|
| `hello-c` | 50424 | C, arm64 thin, `-O0 -g0`, linker ad-hoc signed | baseline header/segments/chained fixups/exports trie/linker signature |
| `hello-x86_64` | 13008 | same source, `-arch x86_64` | x86_64 cputype 0x1000007/subtype 3, 4 KiB pages, **no** `LC_CODE_SIGNATURE` |
| `hello-fat` | 83192 | `lipo -create` of the two above | `FAT_MAGIC` 0xcafebabe, 2 arches at offsets 4096/32768, per-slice signing state differs |
| `hello-objc` | 54440 | ObjC: 2 classes, properties, protocol, 2 categories, ARC, Foundation | all `__objc_*` sections incl. `__objc_catlist`, objc stubs, 4 dylibs, 19 imports |
| `libhello.dylib` | 50016 | `-dynamiclib`, 3 functions + 1 global | `MH_DYLIB`, `LC_ID_DYLIB @rpath/…`, `LC_RPATH`, versions 1.2.3 / 1.0.0, no `LC_MAIN`/dylinker |
| `hello-usedylib` | 33600 | links `libhello.dylib` | `LC_LOAD_DYLIB @rpath/libhello.dylib`, two `LC_RPATH`s, imports from a non-system dylib |
| `hello-adhoc` | 68256 | `hello-c` re-signed with `codesign -s -` | `CS_ADHOC` only (0x2), requirements blob, empty CMS wrapper, `__LINKEDIT` growth |
| `hello-entitled` | 69200 | ad-hoc + entitlements plist | `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171) **and** DER (0xfade7172), 7 special slots |
| `hello-unsigned` | 49880 | `codesign --remove-signature` | no `LC_CODE_SIGNATURE`, ncmds 17, `__LINKEDIT` shrunk to 728 bytes |
| `high-entropy` | 99536 | 64 KiB urandom in `__RANDOM,__blob` | per-segment entropy 7.997 over 65.8 % of the file (packer heuristic must fire) |
| `fake-packed` | 50024 | custom `__XHDR` segment with 2 sections | name-based packer detection (`__XHDR`), non-standard segment ordering |
| `fake-upx` | 50424 | `hello-c` with `__DATA_CONST` renamed `UPX_DATA` (byte patch) | name-based packer detection (`UPX_DATA`); signature valid-looking but page hashes stale |
| `hello-zig` | 165448 | `zig build-exe -O ReleaseSmall` | non-ld64 Mach-O: `LC_DYLD_INFO_ONLY`, unusual LC order, tool id 5, 428 symbols |
| `legacy-bind` | 50424 | C with function-pointer table, `-Wl,-no_fixup_chains` | `LC_DYLD_INFO_ONLY` rebase/bind/lazy-bind/export opcode streams, `__stub_helper`, `__la_symbol_ptr` |
| `hello-quarantined` | 50424 | `hello-c` + `com.apple.quarantine` xattr | quarantine parsing (see caveat: xattrs do not survive git) |
| `Hello.app/` | — | bundle: `Contents/{Info.plist (binary), MacOS/Hello, Frameworks/libhello.dylib, _CodeSignature/CodeResources}` | bundle discovery, binary plist, nested signing, `CodeResources`, Gatekeeper verdict |
| `Hello-Info.plist.xml` | 929 | XML twin of the bundle's binary plist | plist format detection (`bplist00` vs XML) |
| `malformed/*.bin` (16) | — | byte-patched copies (see below) | parser robustness |

External reference used in the truth set but not copied: `/bin/ls` (Apple platform binary,
universal x86_64 + arm64e, `truth/bin-ls.txt`, `summary.json["fixtures"]["bin-ls"]`).

## Per-fixture details and what we learned

### hello-c (arm64) and hello-x86_64, hello-fat

Built with `clang -arch arm64 -O0 -g0 -fno-omit-frame-pointer -Wl,-reproducible`.

* Load commands, in order (ncmds 18, sizeofcmds 1208): `LC_SEGMENT_64` ×5 (`__PAGEZERO`,
  `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`), `LC_DYLD_CHAINED_FIXUPS`,
  `LC_DYLD_EXPORTS_TRIE`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_LOAD_DYLINKER`, `LC_UUID`,
  `LC_BUILD_VERSION`, `LC_SOURCE_VERSION`, `LC_MAIN`, `LC_LOAD_DYLIB`, `LC_FUNCTION_STARTS`,
  `LC_DATA_IN_CODE`, `LC_CODE_SIGNATURE`. Header flags 0x200085 = `MH_NOUNDEFS | MH_DYLDLINK |
  MH_TWOLEVEL | MH_PIE`.
* **This SDK's clang/ld emits chained fixups by default** (`LC_DYLD_CHAINED_FIXUPS` +
  `LC_DYLD_EXPORTS_TRIE`, no `LC_DYLD_INFO`). Pointer format is 6
  (`DYLD_CHAINED_PTR_64_OFFSET`) for both arm64 and x86_64; page size 16384 on arm64, 4096 on
  x86_64; starts exist for segment indices 2 (`__DATA_CONST`) and 3 (`__DATA`). imports_format 1
  (`DYLD_CHAINED_IMPORT`), 6 imports, all from `libSystem`.
* `LC_BUILD_VERSION`: platform 1 (macOS), minos 26.0 (the default deployment target = the host),
  sdk 26.5, one tool entry: ld 1267.0. `LC_SOURCE_VERSION` is 0.
* `LC_MAIN` entryoff 1316 (0x524), stacksize 0. Segments are 16 KiB aligned; `__LINKEDIT` at
  fileoff 49152, filesize 1272.
* Symbols: 12 nlist entries, 6 defined (`__mh_execute_header`, `_add_numbers`, `_global_counter`,
  `_greeting`, `_main`, `_static_helper`), 6 undefined; `LC_DYSYMTAB` nlocalsym+nextdefsym = 6,
  nundefsym = 6 — the nlist scan and dysymtab agree. Exports trie has 5 entries (the static is
  not exported).
* **The linker signs arm64 output ad hoc, but not x86_64.** `hello-c` has
  `LC_CODE_SIGNATURE` with a bare CodeDirectory (SuperBlob 0xfade0cc0, count 1, only slot 0),
  CD version 0x20400, flags 0x20002 = `CS_ADHOC | CS_LINKER_SIGNED`, sha256 hashes, **page size
  4096** (log2 = 12) so 13 code slots for code_limit 49888, 0 special slots, execSegFlags 0x1
  (`CS_EXECSEG_MAIN_BINARY`), identifier = the output file name ("hello-c"), no team id.
  `hello-x86_64` has no `LC_CODE_SIGNATURE` at all (ncmds 17) and `codesign -dv` says "code
  object is not signed at all".
* `hello-fat`: `FAT_MAGIC` 0xcafebabe (big-endian), nfat_arch 2, x86_64 slice at offset 4096
  (align 2^12), arm64 slice at offset 32768 (align 2^14). Because one slice is signed and the
  other is not, `codesign -dvvv hello-fat` happily reports the arm64 slice's signature
  ("Format=Mach-O universal (x86_64 arm64)", flags 0x20002) while `codesign --verify hello-fat`
  fails with "code object is not signed at all" and `codesign -dvvv --arch x86_64` reports
  unsigned. A tool must therefore evaluate signing per slice, never per file.
* cdhash = SHA-256 over the whole CodeDirectory blob truncated to 20 bytes; our parser's value
  matches `codesign`'s `CDHash=` for every signed fixture.

### hello-objc

`clang -fobjc-arc -framework Foundation`. Classes `MachreAnimal : NSObject <MachreGreeter>`
and `MachreDog : MachreAnimal`, properties (`name`, `legs`, `tricks`), protocol `MachreGreeter`
(with an `@optional` method), categories `MachreAnimal (Sounds)` and `NSString (MachreExtras)`.

* ncmds 21; dylibs: Foundation, `/usr/lib/libobjc.A.dylib`, libSystem, CoreFoundation (the
  linker added CoreFoundation itself). 19 imports: `_objc_msgSend`, `_objc_storeStrong`,
  `_objc_msgSendSuper2`, `_objc_release`, `_objc_retain`, `_OBJC_CLASS_$_NSString`, ….
* Sections: `__TEXT`: `__text __stubs __objc_stubs __objc_methlist __objc_methname __cstring
  __objc_classname __objc_methtype __unwind_info`; `__DATA_CONST`: `__got __cfstring
  __objc_classlist __objc_catlist __objc_protolist __objc_imageinfo __objc_superrefs
  __objc_arraydata __objc_arrayobj`; `__DATA`: `__objc_const __objc_selrefs __objc_ivar
  __objc_data __data __bss`. Note the modern `__objc_stubs` (objc_msgSend stubs) and
  `__objc_methlist` in `__TEXT` — relative method lists.
* **Surprise: ld64 merges categories into their class when both live in the same image.**
  The first build had only `MachreAnimal (Sounds)`; the output had no `__objc_catlist`, no
  category symbols, and `dyld_info -objc` listed `-[MachreAnimal sound]` inside the class. Adding
  a category on an external class (`NSString`) produced a real `__objc_catlist` with one entry
  and the symbols `__OBJC_$_CATEGORY_NSString_$_MachreExtras` /
  `__OBJC_$_CATEGORY_INSTANCE_METHODS_NSString_$_MachreExtras`. `-Wl,-no_objc_category_merging`
  disables the merge (verified in a scratch build: `Foo(Bar)` then appears as a category).
  A category count derived from `__objc_catlist` therefore under-reports the source.
* Class names come from the symbol table (`_OBJC_CLASS_$_MachreAnimal`, `_OBJC_CLASS_$_MachreDog`,
  plus `_OBJC_METACLASS_$_*`), protocols from `__OBJC_PROTOCOL_$_MachreGreeter` and
  `__OBJC_PROTOCOL_$_NSObject` (the NSObject protocol is copied into the image), and
  `dyld_info -objc` / `objdump --macho --objc-meta-data` both list them; those outputs are in
  `truth/hello-objc.txt`.

### libhello.dylib and hello-usedylib

`clang -dynamiclib -install_name @rpath/libhello.dylib -compatibility_version 1.0
-current_version 1.2.3 -Wl,-rpath,@loader_path/../Frameworks`.

* filetype `MH_DYLIB` (6); flags include `MH_NO_REEXPORTED_DYLIBS` (0x100000) and **not**
  `MH_PIE`; no `__PAGEZERO`, no `LC_LOAD_DYLINKER`, no `LC_MAIN`; `LC_ID_DYLIB` path
  `@rpath/libhello.dylib`, timestamp 1, current 1.2.3, compat 1.0.0; one `LC_RPATH`
  `@loader_path/../Frameworks`; exports `_hello_add _hello_global _hello_mul _hello_print`
  (4, all in the trie); linker ad-hoc signed like executables (flags 0x20002).
* `hello-usedylib`: `LC_LOAD_DYLIB @rpath/libhello.dylib (1.2.3 / 1.0.0)` before libSystem,
  `LC_RPATH @executable_path` and `@executable_path/../Frameworks`, imports
  `_hello_add _hello_mul _hello_global _hello_print (from libhello)` — the only fixture with
  imports from a non-system dylib. `otool -L` shows libSystem current version 1356.0.0.

### hello-adhoc, hello-entitled, hello-unsigned

* `codesign -s - -f -i com.machre.corpus.hello-adhoc` replaces the linker signature. Result:
  SuperBlob with 3 slots: CodeDirectory (310 bytes), Requirements (`CSSLOT_REQUIREMENTS`,
  magic 0xfade0c01, 12 bytes = an empty requirement set), and `CSSLOT_SIGNATURESLOT` (65536,
  magic 0xfade0b01 BlobWrapper, 8 bytes = empty CMS). CD flags 0x2 (`CS_ADHOC` only —
  `CS_LINKER_SIGNED` is gone), **page size 16384** (codesign uses 16 KiB pages, ld uses 4 KiB),
  so 4 code slots + 2 special slots (slot −2 = sha256 of the requirements blob; slot −1 Info.plist
  = zero).
* **Identifier suffix gotcha:** without `-i`, `codesign -s -` on a bare executable produced
  `Identifier=hello-adhoc-55554944854e63c916cf4837922faa4fc6ae6045` (name + "-" + a hash), so
  build.sh always passes explicit `-i`.
* **Re-signing grows the file:** `__LINKEDIT` went from filesize 1272 to 19104 (vmsize 0x4000 →
  0x8000) and the file from 50424 to 68256 bytes; `LC_CODE_SIGNATURE` datasize 536 → 18368
  (codesign reserves/pads generously). Any "size of signature" heuristic must expect this.
* `hello-entitled` adds `--entitlements gen/src/entitlements.plist` (keys
  `com.apple.application-identifier`, `com.apple.security.cs.allow-jit`,
  `com.apple.security.cs.disable-library-validation`, `com.apple.security.get-task-allow`,
  `com.apple.security.network.client`). **Ad-hoc signing does emit both entitlement blobs**:
  slot 5 `CSMAGIC_EMBEDDED_ENTITLEMENTS` 0xfade7171 (514 bytes, body is the XML plist verbatim)
  and slot 7 `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` 0xfade7172 (249 bytes, body starts
  `70 81 ee 02 01 01 b0 81 e8 30 39 0c 20 …` = APPLICATION[16] { INTEGER 1, [0] SET OF SEQUENCE
  { UTF8String key, value } }). The CD has nSpecialSlots 7; slots −2, −5, −7 hold the sha256 of
  the requirements, XML-entitlements and DER-entitlements blobs respectively (verified), −1/−3/−4/−6
  are zero. `codesign -d --entitlements - --xml` prints the XML after an `Executable=` line on
  stderr.
* `hello-unsigned`: `codesign --remove-signature` drops `LC_CODE_SIGNATURE` (ncmds 17), trims
  `__LINKEDIT` to 728 bytes, file 49880 bytes; `codesign -dv` → "code object is not signed at
  all" (exit 1); `spctl` → rejected.

### high-entropy and the packer-name fixtures

* `high-entropy`: `__attribute__((section("__RANDOM,__blob")))` on a 65536-byte array generated
  from `gen/src/random.bin`. The linker creates a separate `__RANDOM` segment (vmaddr 0x100008000,
  vmsize 0x10000, fileoff 32768, filesize 65536, prot rw-) with one section `__blob`
  (type 0, align 2^0). Measured Shannon entropy: `__RANDOM` 7.997 bits/byte over 65.8 % of the
  file; `__TEXT` 0.394, `__LINKEDIT` 6.68; whole file 6.276. For comparison `hello-c`'s `__TEXT`
  is 0.54 (it is mostly zero padding to 16 KiB) and `hello-zig`'s `__TEXT` is 6.33 (dense code).
  A "segment entropy > 7.0 covering > 20 % of the file" rule fires only on `high-entropy`; note
  that padded tiny `__TEXT` segments have *very low* entropy, so thresholds must be applied per
  segment on file bytes, not on the whole file.
* `fake-packed`: `__attribute__((section("__XHDR,__xhdr")))` and `("__XHDR,__text2")` give a
  `__XHDR` segment (rw-, 2 sections) placed *between* `__DATA_CONST` and `__LINKEDIT`, and no
  `__DATA` segment at all — segment order/presence is not fixed. The linker still signed it and
  it runs.
* `fake-upx`: `gen/malform.py` renames `__DATA_CONST` (segment_command_64.segname and every
  section_64.segname under it) to `UPX_DATA`. It is structurally valid — `otool`/`dyld_info`
  parse it, `codesign -dvvv` still prints the (now stale) CodeDirectory, and `codesign --verify`
  reports "invalid signature (code or signature have been modified)". The kernel would refuse to
  run it. Use it for name-based packer detection and for "signature present but invalid" logic.
  (The prompt suggested a `UPX_DATA`/`upxTEXT` byte patch was unsafe; it is fine for a static
  fixture — only execution is affected.)

### hello-zig

`zig build-exe gen/src/hello.zig -O ReleaseSmall` (Debug was 2.1 MB; ReleaseSmall 165 KB with
symbols; `-fstrip` did not shrink ReleaseSmall further). Zig uses its own linker, and the output
is quite different from ld64's:

* Load-command order: 5 segments, `LC_DYLD_INFO_ONLY`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`,
  `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_SOURCE_VERSION`,
  `LC_BUILD_VERSION`, `LC_UUID`, `LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE` (17). **No chained
  fixups and no exports trie** — it uses the legacy `LC_DYLD_INFO_ONLY` opcode streams
  (rebase 40 B, bind 56 B, lazy-bind 1776 B, export 72 B) with `__stub_helper`,
  `__la_symbol_ptr` and a `dyld_stub_binder` import.
* `LC_BUILD_VERSION`: minos 26.3 (the *host* version, not the SDK's 26.0 default), sdk 26.5,
  ntools 1 with **tool id 5**, version 0.0 — 5 is not defined in this SDK's `loader.h`
  (`TOOL_CLANG`=1, `SWIFT`=2, `LD`=3, `LLD`=4, then 1024+ for Metal); it is zig's private value.
  Parsers must tolerate unknown tool ids.
* Header flags 0xb00085 add `MH_HAS_TLV_DESCRIPTORS` and `MH_NO_REEXPORTED_DYLIBS` (sections
  `__thread_vars`/`__thread_bss` exist). `LC_MAIN` stacksize is 16 MiB (0x1000000), entryoff
  0x768. 428 symbols (325 defined, 103 undefined, 0 stabs); exports only `_main`,
  `__mh_execute_header`, `___dso_handle`.
* Zig's linker **does** ad-hoc sign: CD flags 0x20002 (`CS_ADHOC | CS_LINKER_SIGNED`), 11 code
  slots at 16 KiB pages, identifier "hello-zig". Its `LC_UUID` is deterministic across rebuilds
  even without any flag.
* `dyld_info -fixups` on this binary prints binds in `__thread_vars` to `___divti3`, which looks
  wrong but is what Apple's tool says; treat `truth/hello-zig.txt` as tool output, not gospel.

### legacy-bind

`clang -Wl,-no_fixup_chains` (also `-mmacosx-version-min=10.15` produces the same layout).
Verified: `LC_DYLD_INFO_ONLY` present, `LC_DYLD_CHAINED_FIXUPS`/`LC_DYLD_EXPORTS_TRIE` absent;
build.sh asserts this. Offsets: rebase 49152/8, bind 49160/120, weak 0/0, lazy 49280/72, export
49352/72. The function-pointer table in `__DATA,__data` produces 4 non-lazy binds
(`_puts _printf _malloc _free`) plus `___stack_chk_guard` in `__got`; the calls produce lazy
binds through `__stub_helper`/`__la_symbol_ptr`; 9 undefined symbols including
`dyld_stub_binder`. `dyld_info -imports` prints these **without** the leading ordinal column that
chained-fixup binaries get (the summary regex handles both).

### Hello.app

`Contents/MacOS/Hello` is a byte-identical copy of `hello-objc`; `Contents/Frameworks/libhello.dylib`
a copy of the dylib; `Contents/Info.plist` is `gen/src/Info.plist` converted with
`plutil -convert binary1` (`file` says "Apple binary property list"; `bplist00` header);
`Hello-Info.plist.xml` at the corpus root is the XML original. Signed inner→outer
(`codesign -s - Frameworks/libhello.dylib`, then `codesign -s - Hello.app`; `--deep` is
deprecated), which creates `Contents/_CodeSignature/CodeResources` (sealed resources
version 2, 13 rules, 1 file). `codesign -dvvv Hello.app` reports Identifier
`com.machre.corpus.Hello` (taken from `CFBundleIdentifier`), `Format=app bundle with Mach-O thin
(arm64)`, flags 0x2, "Info.plist entries=12", 3 special slots (−1 Info.plist hash, −2
requirements, −3 resource directory), and `--verify --strict` passes ("valid on disk",
"satisfies its Designated Requirement"). Gatekeeper: `spctl -a -vv -t exec Hello.app` → rejected
(exit 3), as for every ad-hoc fixture; no notarization ticket exists anywhere in the corpus.
The signed main executable inside the bundle is *not* identical to `hello-objc` any more (its
signature was replaced), see the different cdhash in `summary.json`.

### hello-quarantined

`xattr -w com.apple.quarantine "0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C"`.
Value format: `<flags hex>;<unix time hex>;<agent name>;<UUID>` — flags 0x0083 =
kLSQuarantineTypeWebDownload-style download not yet approved by Gatekeeper, timestamp
0x68c3a1b2 (= 2025-09-12 04:29:38 UTC), agent name, and a UUID that keys into the
`LSQuarantineEvent` table in `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
`xattr -l` prints it; `summary.json` stores it under `"quarantine"`. **Caveat:** extended
attributes are not tracked by git and are dropped by many copy paths, so `build.sh` re-applies
it on every run and a test should call `xattr` (or re-apply) rather than assume the checkout has
it.

### /bin/ls (system reference, not copied)

Universal x86_64 + arm64e (cpusubtype 0x80000002: `CPU_SUBTYPE_ARM64E` with the
`CPU_SUBTYPE_PTRAUTH_ABI` high bit, caps byte 0x80). **The two slices use different fixup
formats:** x86_64 uses `LC_DYLD_INFO_ONLY` (minos 10.14), arm64e uses `LC_DYLD_CHAINED_FIXUPS`
with pointer format 1 (`DYLD_CHAINED_PTR_ARM64E`) (minos 11.0). Both are sdk 26.3, ld 1230.4.
Signature: identifier `com.apple.ls`, flags 0x0, CD platform byte 26, a real CMS blob (4450
bytes) with Authority chain "Software Signing / Apple Code Signing Certification Authority / Apple
Root CA", no team id. `spctl -a -t exec /bin/ls` says "rejected (the code is valid but does not
seem to be an app)" — `spctl -t exec` on a non-bundle Mach-O is *not* a usable notarization
check; use `SecStaticCodeCheckValidity` with requirements, or `codesign --verify -R=...`, and
`spctl` only for bundles/installers.

### malformed/ (robustness)

Generated by `gen/malform.py` from `hello-c`, `hello-fat` and `legacy-bind` by locating the
structure with a tiny parser and patching bytes; `malformed/MANIFEST.txt` lists each.

| file | patch | otool | dyld_info -validate_only |
|---|---|---|---|
| `truncated-header.bin` | first 20 bytes of hello-c | `-h` prints zeros past EOF (sizeofcmds 0); `-l` "is a truncated object file" | "non-mach-o in fat file" then "file not found" |
| `bogus-ncmds.bin` | ncmds = 0xFFFFFFFF | prints the header, walks 18 LCs | "malformed load command (19 of -1) … off end of load commands" |
| `cmdsize-zero.bin` | LC[0].cmdsize = 0 | ok | "size (0x0) too small" |
| `cmdsize-huge.bin` | LC[0].cmdsize = 0xFFFFFFF0 | "load command 0 extends past end of load commands" | "size (0xFFFFFFF0) is too large" |
| `fat-1000-arches.bin` | nfat_arch = 1000 | otool-classic fatal "slice size too large, exceeds file size" | **segfault (exit 139)**; `file` says "compiled Java class data, version 1000.0" |
| `fat-arch-offset-past-eof.bin` | fat_arch[0].offset = 0x7FFFFFF0 | same fatal error | **segfault (exit 139)** |
| `sizeofcmds-too-big.bin` | sizeofcmds = 0xFFFFFFF0 | prints it, parses fine | silent (exit 0) |
| `section-offset-past-eof.bin` | `__TEXT,__text` offset = 0x7FFFFFF0 | parses fine | silent (exit 0) |
| `nsects-huge.bin` | `__TEXT` nsects = 0xFFFFFFFF | ok | "LC_SEGMENT_64 size does not match number of sections" |
| `symtab-stroff-past-eof.bin` | stroff = strsize = 0x7FFFFFF0 | ok | "'symbol table strings' extends beyond end of segment" |
| `symtab-nsyms-huge.bin` | nsyms = 0x0FFFFFFF | ok | "symbol count from symbol table and dynamic symbol table differ" |
| `chained-fixups-absurd.bin` | header offsets 0x7FFFFFF0, imports_count 0xFFFFFFFF | ok | "starts_offset exceeds LC_DYLD_CHAINED_FIXUPS size" |
| `chained-starts-segcount-huge.bin` | starts_in_image.seg_count = 0xFFFFFFFF | ok | "seg_count exceeds number of segments" |
| `dyldinfo-bind-past-eof.bin` | bind_off = bind_size = 0x7FFFFFF0 (legacy-bind) | ok | "'bind opcodes' extends beyond end of segment" |
| `bad-magic.bin` | magic = de ad be ef | "is not an object file" | "non-mach-o" |
| `empty.bin` | 0 bytes | "is not an object file" | "non-mach-o" |

Lessons: Apple's own `dyld_info` crashes on two of these, `otool -h` reads past EOF on the
truncated header, and neither tool objects to a section offset or sizeofcmds beyond EOF — so a
machre parser must bound every offset/size against the slice length itself (and against
`sizeofcmds`), must cap `ncmds`/`nsects`/`nsyms` loops by remaining bytes, and must treat a
`cmdsize` of 0 (or < 8) as fatal to avoid an infinite loop. The exact messages are in
`truth/malformed-tool-reactions.txt`.

## Cross-cutting surprises (things the implementer must know)

1. **Chained fixups are the default** for this clang/ld regardless of deployment target ≥ 11;
   `-Wl,-no_fixup_chains` (or a pre-11 `-mmacosx-version-min`) reverts to `LC_DYLD_INFO_ONLY`.
   Zig's linker never emits chained fixups. `/bin/ls` mixes both formats in one fat file.
2. **ld ad-hoc-signs arm64 output (`CS_LINKER_SIGNED`, 0x20002) but not x86_64 output.**
   Linker signatures have exactly one blob (the CodeDirectory), 4 KiB pages, no requirements,
   no CMS wrapper; `codesign -s -` signatures have 16 KiB pages, a requirements blob and an
   empty BlobWrapper, and flags 0x2.
3. **ld-1267 emits a random LC_UUID on every link** (the man page still says content-hash) —
   two identical links differed only in the 16 UUID bytes and, consequently, the linker
   CodeDirectory hashes. `-Wl,-reproducible` restores the content-hash (version-3, `xxxx-3xxx`)
   UUID and makes output byte-identical; build.sh uses it. `codesign -s -` is deterministic.
4. **Ad-hoc `codesign` with `--entitlements` writes both the XML (0xfade7171) and DER
   (0xfade7172) entitlement blobs**; the DER blob's hash sits in special slot −7 and the XML's in
   −5, so nSpecialSlots jumps from 2 to 7.
5. **The `codesign` identifier of a bare executable is `<filename>` for linker signatures and
   `<filename>-<hash>` for `codesign -s -` unless `-i` is given**; for bundles it is
   `CFBundleIdentifier`.
6. **ld64 merges same-image ObjC categories into the class** — `__objc_catlist` only lists
   categories on classes from other images (or everything with `-Wl,-no_objc_category_merging`).
7. **Modern ObjC layout**: `__objc_stubs` and `__objc_methlist` live in `__TEXT`;
   `__objc_classlist/catlist/protolist/imageinfo/superrefs` in `__DATA_CONST`; `__objc_const/
   selrefs/ivar/data` in `__DATA`.
8. **Segment order and presence vary**: `fake-packed` has `__XHDR` before `__LINKEDIT` and no
   `__DATA`; the dylib has no `__PAGEZERO`; zig places `LC_FUNCTION_STARTS` before `LC_SYMTAB`.
   Never assume `__TEXT` is LC[1] or that `__LINKEDIT` is last-but-one.
9. **Entropy heuristics**: tiny `-O0` binaries have near-zero `__TEXT` entropy because of page
   padding; `__LINKEDIT` is naturally ~5–6.7; only genuinely random data reaches ≈ 8.0.
10. **`dyld_info` output format differs by fixup style** (`-imports` has an ordinal column only
    for chained-fixup binaries), and `-validate_only` is not a safe oracle for fat malformations.
11. **`spctl -a -t exec` rejects every non-bundle executable**, even Apple's `/bin/ls`
    ("does not seem to be an app"); every fixture here is ad hoc and therefore also rejected; no
    fixture is notarized (there is no Developer ID on this machine).
12. **Homebrew `clang` shadows Apple `clang` on this PATH** (`/opt/homebrew/opt/llvm/bin/clang`,
    LLVM 22.1.5). build.sh pins `/usr/bin/clang` so the ld64/ld-prime behaviour above applies.
13. The `_CodeSignature/CodeResources` plist, the binary `Info.plist`, and the XML plist twin give
    three plist flavours to parse (`bplist00`, XML, and the resource-rules XML).
14. `file` misidentifies a fat header with a large nfat_arch as a Java class file (shared
    0xCAFEBABE magic) — machre should require nfat_arch to be small (< ~20) and every
    fat_arch to fit in the file before calling something universal.

## Ground-truth file index

```
tests/corpus/truth/
  hello-c.txt hello-x86_64.txt hello-fat.txt hello-objc.txt libhello.dylib.txt
  hello-usedylib.txt hello-adhoc.txt hello-entitled.txt hello-unsigned.txt
  high-entropy.txt fake-packed.txt fake-upx.txt hello-zig.txt legacy-bind.txt
  hello-quarantined.txt Hello.app.txt bin-ls.txt
  malformed-tool-reactions.txt TOOLS.txt summary.json
```

---

## Completeness-critic verification (2026-09-11 19:45)

### Idempotency re-checked
`bash gen/build.sh` run twice back-to-back (≈2 s each, exit 0): SHA-256 of all 37 fixture files under `tests/corpus/`
(everything except `gen/` and `truth/`) identical before run 1, after run 1 and after run 2; the
`com.apple.quarantine` value on `hello-quarantined` re-applied byte-identically; every `sha256` recorded in
`truth/summary.json` still matches the file on disk (0 mismatches). Evidence: scratchpad
`critic/sha-before.txt`, `sha-run1.txt`, `sha-run2.txt`, `build-run1.log`, `build-run2.log`.

### `truth/summary.json` key schema (what tests can assert against)
Top level: `_generated_by`, `_host`, `_note`, `fixtures{ name → … }` with names `hello-c hello-x86_64 hello-fat
hello-objc libhello.dylib hello-usedylib hello-adhoc hello-entitled hello-unsigned high-entropy fake-packed fake-upx
hello-zig legacy-bind hello-quarantined Hello.app bin-ls`. Per fixture (210 leaf keys):
```
name path bundle size sha256 file file_entropy container fat_arches[] quarantine xattrs cross_check
codesign{ authority[] cdhash code_directory_line entitlements_keys[] exit flags{hex names[]} format hash_type identifier info_plist runtime_version sealed_resources signature signed team_id timestamp verify_exit verify_output }
spctl{ assessment exit raw source }
slices[]{ offset_in_file size magic cputype cputype_hex cputype_name cpusubtype cpusubtype_hex cpusubtype_caps cpusubtype_low filetype filetype_name ncmds sizeofcmds flags flags_names[] load_commands[]
  segments[]{ name vmaddr vmsize fileoff filesize maxprot initprot nsects flags entropy file_fraction sections[]{ name segname addr size offset align flags type } }
  dylibs[]{ cmd path timestamp current_version compatibility_version } id_dylib rpaths[] dylinker uuid
  build_version{ platform platform_name minos sdk tools[]{ tool version } } version_min source_version
  entry_point{ entryoff entryoff_hex stacksize } symtab{ symoff nsyms stroff strsize }
  dysymtab{ ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc modtaboff nmodtab extrefsymoff nextrefsyms indirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel }
  symbols{ total defined undefined stabs external local } defined_symbols_first20[] undefined_symbols_first20[]
  dyld_info has_dyld_info has_chained_fixups has_exports_trie
  chained_fixups{ dataoff datasize fixups_version starts_offset imports_offset symbols_offset imports_count imports_format symbols_format seg_count starts[]{ seg_index page_size pointer_format segment_offset page_count } }
  exports_trie{ dataoff datasize } exports_count exports_first20[] imports_count imports_first20[]{ symbol dylib }
  nm_undefined_count nm_undefined_first20[]{ symbol dylib } function_starts{ dataoff datasize } data_in_code{ dataoff datasize }
  code_signature{ present dataoff datasize superblob{ magic magic_name length count slots[]{ type type_name offset magic magic_name length } }
    code_directory{ version flags flags_hex flags_names[] hash_type hash_size page_size n_code_slots n_special_slots code_limit exec_seg_base exec_seg_limit exec_seg_flags platform identifier team_id cdhash cdhash_full }
    requirements_length entitlements_keys[] has_der_entitlements der_entitlements_length cms_signature_length }
  objc_classes[] objc_categories[] objc_protocols[] objc_classes_dyld_info[] }
```
Hex fields are lowercase `0x…` strings; offsets/sizes/counts are integers; `bundle` is null except for `Hello.app`; `bin-ls` has two slices.

### How `std.macho.LoadCommandIterator` reacts to `malformed/` (Zig probe; details in zig-api-notes 15.2)
| fixture | std iterator | implementer must add |
|---|---|---|
| truncated-header.bin, empty.bin | cannot read the header | length check before parsing |
| bad-magic.bin | iterates all 18 commands | magic check |
| bogus-ncmds.bin | 18 commands then `error.InvalidMachO` | nothing (bounded by sizeofcmds) |
| cmdsize-zero.bin | returns the same empty command 18× and ends **without error** | `cmdsize >= 8` and `cmdsize % 8 == 0` |
| cmdsize-huge.bin | `error.InvalidMachO` on the first `next()` | nothing |
| sizeofcmds-too-big.bin | `init` → `error.InvalidMachO` | nothing |
| nsects-huge.bin | iterates; `getSections()` yields a 4 294 967 295-element slice | `72 + 80*nsects <= cmdsize` before `getSections()` |
| section-offset-past-eof, symtab-*, chained-*, dyldinfo-bind-past-eof | iterate normally | bound every offset/size against the slice |

### Security.framework verdicts on the corpus (Zig probe `critic`)
`SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures, NULL)`: hello-adhoc, hello-entitled, Hello.app → **0**
(valid ad hoc — 0 is not "trusted"); hello-fat → -67062 `errSecCSUnsigned` (its x86_64 slice is unsigned; without
`kSecCSCheckAllArchitectures` only the native slice is checked); hello-x86_64, hello-unsigned → -67062; fake-upx →
-67061 `errSecCSSignatureFailed` (matches `codesign --verify`). Every requirement string (`anchor apple`, `anchor apple
generic`, Developer ID, App Store, `notarized`) fails with -67050 `errSecCSReqFailed` on every fixture.
`SecCodeCopySigningInformation`: `kSecCodeInfoCertificates` absent, `kSecCodeInfoFlags` 0x2 (codesign-signed) or 0x20002
(linker-signed, fake-upx), designated requirement `cdhash H"…"`, `kSecCodeInfoEntitlementsDict` of hello-entitled = the 5
keys of `gen/src/entitlements.plist` (`com.apple.application-identifier` = `MACHRE.hello-entitled`, four booleans true).
`Hello.app/Contents/MacOS/Hello` evaluates as the bundle (`app bundle with Mach-O thin (arm64)`, identifier
`com.machre.corpus.Hello`) while the byte-identical `hello-objc` is `Mach-O thin (arm64)` / `hello-objc`.
`spctl -a -vv -t exec Hello.app` → exit 3 "rejected"; `xcrun stapler validate` → exit 65 on every fixture (no ticket).
