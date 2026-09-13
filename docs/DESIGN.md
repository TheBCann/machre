# machre — Binding design (synthesis of design-B with grafts from A and C)

Target toolchain: Zig `0.17.0-dev.1154+ba5420896`, macOS 26.3 arm64, SDK 26.5, Capstone 5.0.8 (optional).
This is the single binding design for implementation. It follows design-B (robustness-first, the judges'
winner) and merges the ideas the judges asked for from A (library-first) and C (analyst-output-first). Every
judge-reported defect is resolved in §13.2 (fixed, or explicitly rejected with a reason).

**Verification record.** Everything in §3, §4 and §11 exists as compiled code:

* `skeleton-reference/` (copied from `scratchpad/design-skeleton/`) contains `build.zig` verbatim (§11) and
  every `src/**/*.zig` / `tests/**/*.zig` file with every `pub` type and `pub fn` signature of §3/§4, bodies
  stubbed `@panic("todo")`. `src/root.zig` references every declaration recursively at comptime, so plain
  `zig build` semantically checks every signature (proven: an injected type error in the never-called
  `cmd/version.zig` fails `zig build`). Verified on this nightly: `zig build`, `zig build test --summary all`
  (14/14 steps, 26/26 tests), `-Dcapstone=false`, `-Dsecurity=false -Dcapstone=false` (links only libSystem),
  `-Dcapstone=true` (static libcapstone; Security + CoreFoundation propagate from the lib module),
  `-Doptimize=ReleaseSafe`, `--release`, `--release=fast` (still `-OReleaseSafe`), `-Dtarget=x86_64-linux`.
* `skeleton-reference/contract/` holds the verbatim bodies quoted in §3 (Reader/Cursor, Limits +
  BudgetAllocator, Diagnostics, sanitize, Sink + JSON wrapper types, fmt types, Arch) with tests:
  `zig test contract/all.zig` passes in Debug and `-OReleaseSafe` (10/10), including the judges' SLEB
  9/10-byte `-1` cases, ULEB overflow, the wrapping ULEB, invalid-UTF-8 never reaching `std.json.Stringify`
  as a string, and `std.json.Stringify.value` over a struct of `Str`/`Hex64`/`HexBytes`/`IsoTime`.
* Every std API named below was checked with `zfn` on the installed nightly (line numbers cited where they
  matter): `Build/Step/Options.createModule` :436, `addOptionPath` :424, `Build.standardOptimizeOption`
  :1320-1349, `mem/Allocator.VTable` fields :32/:51/:72/:84, `enums.EnumSet.full` :284 (no `initFull`),
  `testing.fuzz` :1227 with `Smith` (`value/index/eos/bytes/slice` at Smith.zig:199-288), `Io/Writer.Discarding`,
  `json/Stringify.beginWriteRaw` :258 / `endWriteRaw` :267, `Random.DefaultPrng` (Xoshiro256),
  `bit_set.DynamicBitSetUnmanaged` :676, `meta.stringToEnum` :19, `Io/File.isTty` :241.
  `std.testing.refAllDeclsRecursive` does NOT exist on this nightly (only non-recursive, test-only
  `refAllDecls` :1213); `root.zig` carries its own recursive version.

---

## 1. Design thesis

A triage tool that can be crashed by the sample it is triaging is worse than no tool. The kernel therefore
optimises for a provable "no crash, no UB, bounded memory, bounded time" guarantee on hostile input (malware,
fuzzed files, the 16 `tests/corpus/malformed/*` fixtures on which Apple's own `dyld_info` segfaults), and
layers features on top of that kernel without weakening it:

1. **One reader, no raw indexing.** Every byte is read through `core.Reader`/`Cursor` (§3.1) whose every
   accessor is total (`?T` / `error{Truncated,Overflow}`); every offset+size is computed with `std.math.add`,
   every count is clamped to `min(declared, Limits cap, bytes available / entry size)`.
2. **Limits are a value.** `core.Limits` (§3.2, passed as `*const Limits`) carries every cap with `.default` and
   `.paranoid` presets; `--paranoid` and every fuzzer use the tiny preset so pathological loops terminate at once.
   The per-analysis arena is wrapped in `BudgetAllocator` so a parser bomb cannot exceed `max_arena_bytes`.
3. **Malformed structure is data.** Parsers append `Diagnostics` (§3.3, enum module + enum code) and continue;
   the only propagating errors are `Allocator.Error` and I/O errors. A partial report is always produced; one
   diagnostic per (module, code) per structure (`Diagnostics.has`) stops floods.
4. **No recursion on input-shaped data.** Export trie, bplist, XML, ASN.1 (CMS + DER entitlements),
   requirement expressions, ObjC protocol lists and bundle walks all use explicit stacks with depth caps.
5. **Memoising facade.** `Analysis` (§4.24, from A/C) parses each data source at most once per slice and only
   when a command asks: `machre info` on a 100 MB image never parses symbols, chains or ObjC. Getters propagate
   `Allocator.Error` (OOM is exit 70, never silently "empty").
6. **Analyst output is a contract.** Each command owns its text and JSON renderers (`cmd/<name>.zig`), JSON
   goes through wrapper types that can never emit number arrays or >2^53 numbers (§3.7), absent features are
   `{"available":false,"reason":...}`, sanitised strings carry `<key>_hex` siblings, and `--otool-compat`
   makes text diff empty against `otool -hv/-l/-tV`, `nm -m/-a`, `dyld_info -fixups/-exports/-imports/
   -function_starts`, `codesign -dvvv/-r-`, `plutil -p`, `strings -n` — those diffs ARE the golden tests (§10).
7. **Never a single tell.** Triage (§4.26) is a weighted rule table with a comptime assert that no weight
   reaches 50, a `>= 2 categories` gate for `suspicious` and above, positives that subtract, KnockKnock-style
   text with "Corroboration:" and "Not flagged:" lines, and `exit_code` echoed in the JSON envelope.
8. **Shipped build is ReleaseSafe** (`zig build --release`, `-Doptimize=ReleaseSafe` also accepted): anything
   the type system cannot express traps loudly; the robustness suite (malformed matrix × every command,
   deterministic 256-mutation sweep per fixture, Smith fuzzers) is the evidence that no trap is reachable.
9. **Parallel implementation by file ownership.** After WP0, every file has exactly one owner; each WP owns its
   `cmd/<name>.zig` and its own `tests/facts|fuzz|golden/<wp>.zig`; nobody edits a shared file (§12).

---

## 2. Repository layout

Owner column = the work package that implements the file (§12). WP0 creates every file from
`skeleton-reference/` (all signatures final) and fully implements the ones marked WP0.

```
machre/
  build.zig                              WP0   §11 (verbatim from skeleton-reference)
  build.zig.zon                          WP0   .{ .name = .machre, .version = "0.1.0", .fingerprint = 0xee7caf0ceabb3411, .minimum_zig_version = "0.17.0-dev.1154", .paths = .{ "build.zig", "build.zig.zon", "src", "tests", "README.md", "docs" } }
  README.md                              WP0   build/run/test, subcommand table, exit codes, JSON conventions
  docs/DESIGN.md                         —     this file
  docs/json-schema.md                    WP9   normative per-command JSON key inventory (§6), checked by golden tests
  docs/{zig-api-notes,format-notes,corpus-notes,disasm-notes}.md   (existing research)
  skeleton-reference/                    —     compile-checked contract (seed for WP0)
  src/
    main.zig                             WP0   `pub fn main(init: std.process.Init) u8 { return machre.cli.run(init); }` + std_options
    root.zig                             WP0   library root: namespaced re-exports, refAllDeclsRecursive comptime gate, `test { refAllDecls }`
    core/                                       === kernel: depends only on std ===
      reader.zig                         WP0   Reader (bounds-checked view), Cursor (LEB128, cstr)         — bodies verbatim §3.1
      limits.zig                         WP0   Limits (.default/.paranoid), BudgetAllocator                 — bodies verbatim §3.2
      diag.zig                           WP0   Severity, Module, Code, Diag, Diagnostics                   — bodies verbatim §3.3
      arch.zig                           WP0   CpuType, ArchName (enum, stringToEnum), Arch.fromCpu/host    — bodies verbatim §3.4
      sanitize.zig                       WP0   Policy/Sanitized string(), isClean, hexLower, escapeC, iso8601 — bodies verbatim §3.5
      fmt.zig                            WP0   {f} types: Addr, Addr16, Hex, Uuid, Version, VersionShort, SourceVersion, Iso8601, Flags — verbatim §3.6
      version.zig                        WP0   every name table (LC, MH flags, filetypes, platforms, tools, section types, CS flags/slots/magics, stabs, pointer formats, dylibShortName)
      macho_extra.zig                    WP0   declarations std.macho lacks (data only; verbatim in skeleton; comptime size asserts)
      loadcmds.zig                       WP0   Header.parse, LoadCmd, Walker, Dylib/BuildVersion/Entry decoders
      segments.zig                       WP0   Segment, Section, SectionClass, classify
      fat.zig                            WP0   FatArch, Container, parse, selectArches
      file.zig                           WP0   LoadedFile (gpa-owned bytes, sha256, slices)
      image.zig                          WP0   Image (one slice): parse, vm<->file translation, section/linkedit readers
    macho/
      symbols.zig                        WP2   nlist/strtab/dysymtab/indirect, AddressIndex
      dyld_chained.zig                   WP2   LC_DYLD_CHAINED_FIXUPS header/starts/imports/chain walk, decodePointer
      dyld_exports.zig                   WP2   export trie (iterative)
      dyld_legacy.zig                    WP2   LC_DYLD_INFO(_ONLY) rebase/bind/weak/lazy/THREADED streams
      function_starts.zig                WP2   LC_FUNCTION_STARTS + LC_DATA_IN_CODE
      fixups.zig                         WP2   FixupTable (unified), Slot resolution
      imports.zig                        WP2   DylibRef/ImportTable/ExportTable with dylib attribution
    codesign/
      asn1.zig                           WP3   BER/DER TLV (indefinite lengths), OIDs, times, explicit-stack Walker
      blobs.zig                          WP3   SuperBlob, CodeDirectory (all versions), cdhash, dual CDs
      hashes.zig                         WP3   page-hash + special-slot verification
      requirements.zig                   WP3   requirement set + two-pass pretty-printer, synthesized DR
      entitlements.zig                   WP3   XML + DER entitlements, dangerous-key table
      cms.zig                            WP3   CMS certificates/chain/marker OIDs/signing time, offline ladder
    darwin/
      security.zig                       WP4   Security.framework externs (§8) + trust ladder (gated by build_options.have_security)
      xattr.zig                          WP4   getxattr/listxattr, quarantine parse, translocation
      dylib_resolve.zig                  WP4   @rpath/@executable_path/@loader_path + shared-cache oracle
    objc/objc.zig                        WP6   classes/categories/protocols/selectors/stubs/imageinfo
    strings/strings.zig                  WP6   sectioned strings + classifier
    analysis/
      entropy.zig                        WP6   Shannon entropy + packer/encryption tells
      analysis.zig                       WP0   memoising Analysis facade (implemented by WP0 over the stubs)
      triage.zig                         WP9   rule table, scoring, KnockKnock text/JSON
    plist/{plist,bplist,xml}.zig         WP5   Value model, bplist00, XML plist
    bundle/bundle.zig                    WP5   bundle discovery, Info.plist, nested code, CodeResources verification (portable)
    disasm/
      insn.zig                           WP7   Insn/Kind/Listing record
      capstone.zig                       WP7   Capstone 5 externs (§8), text decode
      arm64.zig                          WP7   built-in arm64 decoder
      x86len.zig                         WP7   built-in x86_64 length decoder
      functions.zig                      WP8   function discovery
      symbolize.zig                      WP8   stubs (A/B algorithms), annotations, xrefs
      engine.zig                         WP8   decode loop; built-in semantics + Capstone text overlay
    output/
      sink.zig                           WP0   Sink, Str/Hex64/HexBytes/IsoTime                            — bodies verbatim §3.7
      json.zig                           WP0   JSON convention helpers, envelope
      text.zig                           WP0   Table, kv, flags, hexdump, diagnostics footer, arch banner
    cli/
      args.zig                           WP0   flag parser
      context.zig                        WP0   Context, Command, ExitCode (leaf: no cmd<->cli cycle)
      cli.zig                            WP0   command table, run/runArgv, loadImages, analysisFor, usage
    cmd/                                        one file per subcommand; owner = the module's WP
      info.zig header.zig loadcmds.zig segments.zig dump.zig                 WP1
      symbols.zig dyld.zig imports.zig exports.zig                           WP2
      codesign.zig entitlements.zig                                          WP3
      quarantine.zig                                                         WP4
      plist.zig bundle.zig                                                   WP5
      objc.zig strings.zig entropy.zig                                       WP6
      disasm.zig functions.zig xrefs.zig                                     WP8
      triage.zig report.zig                                                  WP9
      version.zig                                                            WP0
  tests/
    corpus/                              (existing) fixtures, malformed/, truth/, gen/
    helpers.zig                          WP0   corpusDir/truthDir/srcDir, fixture loading, Summary accessors, runMachre, ensureQuarantineXattr
    truth.zig                            WP0   "===== cmd =====" section extraction + line comparators
    corpus_tests.zig                     WP0   root: imports tests/facts/*.zig
    golden_tests.zig                     WP0   root: Row type + table runner; imports tests/golden/*.rows.zig
    robustness_tests.zig                 WP0   root: malformed × command matrix, mutation sweep driver, budget tests; imports tests/fuzz/*.zig
    deps_tests.zig                       WP0   import-policy check (allowed-edge table from §4)
    facts/{core,dyld,codesign,darwin,plist_bundle,objc_strings,decoders,disasm,triage}.zig     owner = matching WP (core: WP0+WP1)
    fuzz/{core,dyld,codesign,darwin,plist_bundle,objc_strings,decoders,disasm,triage}.zig      owner = matching WP
    golden/{core,dyld,codesign,darwin,plist_bundle,objc_strings,disasm,triage}.rows.zig        owner = matching WP
    golden/<fixture>.<command>[.<variant>].txt                                                 owner = the WP that added the row
```
---

## 3. Core data model

Everything in §3.1–§3.7 is quoted verbatim from `skeleton-reference/contract/*.zig`, which passes `zig test`
in Debug and `-OReleaseSafe` on this nightly (the tests are included). §3.8–§3.11 are the exact compiled
signatures from `skeleton-reference/src/core/*.zig` (bodies elided). Conventions used everywhere:

* `arena: std.mem.Allocator` = the per-analysis budgeted arena (§7); results are arena-owned slices, no
  `deinit` on result types. `gpa` appears only in `cli/`, `core/file.zig` (input bytes), `bundle.zig`
  (nested files) and `disasm/capstone.zig`.
* `limits: *const Limits`, `diags: *Diagnostics` on every parser; parsers return `Allocator.Error!T`
  (or `Allocator.Error!?T` when the underlying load command may be absent: `null` = absent).
* `img: *const Image` is one Mach-O slice; `io: std.Io` only where the OS is touched.

### 3.1 `core/reader.zig` — the single bounds-checked view (verbatim, compiled)

```zig
const std = @import("std");

/// A read-only window onto a byte buffer. Every accessor is total: it returns `null`
/// (or a typed error for Cursor) instead of ever touching memory outside `bytes`.
/// `base` is the absolute file offset of `bytes[0]`, used only for diagnostics.
pub const Reader = struct {
    bytes: []const u8,
    base: u64 = 0,

    pub const Endian = std.builtin.Endian;

    pub fn init(bytes: []const u8, base: u64) Reader {
        return .{ .bytes = bytes, .base = base };
    }
    pub fn len(r: Reader) usize {
        return r.bytes.len;
    }
    /// True iff [off, off+size) lies inside the window (overflow-safe).
    pub fn contains(r: Reader, off: u64, size: u64) bool {
        const end = std.math.add(u64, off, size) catch return false;
        return end <= r.bytes.len;
    }
    /// Sub-window; null when out of range. `size` may be `null` for "to the end".
    pub fn sub(r: Reader, off: u64, size: ?u64) ?Reader {
        if (off > r.bytes.len) return null;
        const avail: u64 = r.bytes.len - off;
        const n = size orelse avail;
        if (n > avail) return null;
        const o: usize = @intCast(off);
        return .{ .bytes = r.bytes[o..][0..@intCast(n)], .base = r.base + off };
    }
    /// Sub-window clamped to what exists (never null unless `off` itself is past the end).
    /// Returns the window and whether it was truncated.
    pub fn subClamped(r: Reader, off: u64, size: u64) ?struct { r: Reader, truncated: bool } {
        if (off > r.bytes.len) return null;
        const avail: u64 = r.bytes.len - off;
        const n = @min(size, avail);
        const o: usize = @intCast(off);
        return .{ .r = .{ .bytes = r.bytes[o..][0..@intCast(n)], .base = r.base + off }, .truncated = n < size };
    }
    pub fn sliceAt(r: Reader, off: u64, size: u64) ?[]const u8 {
        const s = r.sub(off, size) orelse return null;
        return s.bytes;
    }
    pub fn u8At(r: Reader, off: u64) ?u8 {
        if (off >= r.bytes.len) return null;
        return r.bytes[@intCast(off)];
    }
    pub fn u16At(r: Reader, off: u64, endian: Endian) ?u16 {
        const s = r.sliceAt(off, 2) orelse return null;
        return std.mem.readInt(u16, s[0..2], endian);
    }
    pub fn u32At(r: Reader, off: u64, endian: Endian) ?u32 {
        const s = r.sliceAt(off, 4) orelse return null;
        return std.mem.readInt(u32, s[0..4], endian);
    }
    pub fn u64At(r: Reader, off: u64, endian: Endian) ?u64 {
        const s = r.sliceAt(off, 8) orelse return null;
        return std.mem.readInt(u64, s[0..8], endian);
    }
    /// Alignment-safe extern-struct read (copy out via `bytesToValue`, then byte-swap
    /// all fields when the on-disk endianness differs from the host).
    pub fn structAt(r: Reader, comptime T: type, off: u64, endian: Endian) ?T {
        comptime std.debug.assert(@typeInfo(T) == .@"struct");
        const s = r.sliceAt(off, @sizeOf(T)) orelse return null;
        var v = std.mem.bytesToValue(T, s[0..@sizeOf(T)]);
        if (endian != @import("builtin").cpu.arch.endian()) std.mem.byteSwapAllFields(T, &v);
        return v;
    }
    /// NUL-terminated string at `off`, at most `max` bytes scanned. Returns the bytes
    /// before the NUL; `terminated == false` when no NUL was found within the window/max.
    pub fn cstrAt(r: Reader, off: u64, max: u64) ?struct { bytes: []const u8, terminated: bool } {
        if (off >= r.bytes.len) return null;
        const o: usize = @intCast(off);
        const limit: usize = @intCast(@min(max, r.bytes.len - off));
        const win = r.bytes[o..][0..limit];
        if (std.mem.findScalar(u8, win, 0)) |i| return .{ .bytes = win[0..i], .terminated = true };
        return .{ .bytes = win, .terminated = false };
    }
    /// Fixed-width name field (segname/sectname): up to 16 bytes, stops at first NUL.
    pub fn nameAt(r: Reader, off: u64, width: u8) ?[]const u8 {
        const s = r.sliceAt(off, width) orelse return null;
        return std.mem.sliceTo(s, 0);
    }
    pub fn cursor(r: Reader, off: u64) ?Cursor {
        if (off > r.bytes.len) return null;
        return .{ .r = r, .pos = @intCast(off) };
    }
};

/// Sequential reader for opcode streams / tries / DER. Never panics; every take is checked.
pub const Cursor = struct {
    r: Reader,
    pos: usize,

    pub const Error = error{ Truncated, Overflow };

    pub fn remaining(c: Cursor) usize {
        return c.r.bytes.len - c.pos;
    }
    pub fn atEnd(c: Cursor) bool {
        return c.pos >= c.r.bytes.len;
    }
    pub fn takeU8(c: *Cursor) Error!u8 {
        if (c.pos >= c.r.bytes.len) return error.Truncated;
        defer c.pos += 1;
        return c.r.bytes[c.pos];
    }
    pub fn takeBytes(c: *Cursor, n: usize) Error![]const u8 {
        if (n > c.remaining()) return error.Truncated;
        defer c.pos += n;
        return c.r.bytes[c.pos..][0..n];
    }
    pub fn takeInt(c: *Cursor, comptime T: type, endian: Reader.Endian) Error!T {
        const b = try c.takeBytes(@sizeOf(T));
        return std.mem.readInt(T, b[0..@sizeOf(T)], endian);
    }
    /// ULEB128 into u64; more than 10 bytes or a value that does not fit is `error.Overflow`
    /// (never silently wraps — legacy bind streams encode negative deltas as 10-byte ULEBs,
    /// callers that want wrapping use `takeUlebWrapping`).
    pub fn takeUleb(c: *Cursor) Error!u64 {
        var result: u64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            const bits: u64 = b & 0x7f;
            if (shift >= 64 or (shift > 57 and (bits >> @intCast(64 - @as(u8, shift))) != 0)) return error.Overflow;
            result |= bits << @intCast(shift);
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
        return error.Overflow;
    }
    /// ULEB128 with explicit two's-complement wrap (BIND_OPCODE_ADD_ADDR_ULEB semantics).
    pub fn takeUlebWrapping(c: *Cursor) Error!u64 {
        var result: u64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            if (shift < 64) result |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) return result;
            shift +|= 7;
        }
        return error.Overflow;
    }
    pub fn takeSleb(c: *Cursor) Error!i64 {
        var result: i64 = 0;
        var shift: u7 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const b = try c.takeU8();
            if (shift < 64) result |= @as(i64, b & 0x7f) << @intCast(shift);
            shift +|= 7;
            if (b & 0x80 == 0) {
                if (shift < 64 and (b & 0x40) != 0) result |= @as(i64, -1) << @intCast(shift);
                return result;
            }
        }
        return error.Overflow;
    }
    /// NUL-terminated string, at most `max` bytes; consumes the NUL.
    pub fn takeCstr(c: *Cursor, max: usize) Error![]const u8 {
        const win = c.r.bytes[c.pos..][0..@min(max, c.remaining())];
        const i = std.mem.findScalar(u8, win, 0) orelse return error.Truncated;
        defer c.pos += i + 1;
        return win[0..i];
    }
    pub fn skip(c: *Cursor, n: usize) Error!void {
        _ = try c.takeBytes(n);
    }
    pub fn seek(c: *Cursor, pos: usize) Error!void {
        if (pos > c.r.bytes.len) return error.Truncated;
        c.pos = pos;
    }
};

test "reader smoke" {
    const r = Reader.init("\xcf\xfa\xed\xfe\x00", 0);
    try std.testing.expectEqual(@as(?u32, 0xfeedfacf), r.u32At(0, .little));
    try std.testing.expect(r.u32At(2, .little) == null);
    try std.testing.expect(!r.contains(std.math.maxInt(u64), 1));
    var c = r.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 0xfdb7d4f), try c.takeUleb());
    const hdr = r.structAt(std.macho.load_command, 0, .little);
    try std.testing.expect(hdr == null);
    try std.testing.expectEqualStrings("", (r.cstrAt(4, 16).?).bytes);
}

test "reader: sleb 9-byte and 10-byte -1, uleb overflow" {
    const r9 = Reader.init(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 0);
    var c9 = r9.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c9.takeSleb());
    const r10 = Reader.init(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 0);
    var c10 = r10.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c10.takeSleb());
    const r1 = Reader.init(&[_]u8{0x7f}, 0);
    var c1 = r1.cursor(0).?;
    try std.testing.expectEqual(@as(i64, -1), try c1.takeSleb());
    const big = Reader.init(&[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }, 0);
    var cb = big.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 1 << 63), try cb.takeUleb());
    const over: [10]u8 = @splat(0x80);
    const ro = Reader.init(&over, 0);
    var co = ro.cursor(0).?;
    try std.testing.expectError(error.Overflow, co.takeUleb());
    const wrap = Reader.init(&[_]u8{ 0xf8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }, 0);
    var cw = wrap.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFF78), try cw.takeUlebWrapping());
}
test "reader: every accessor is total at the edges" {
    const r = Reader.init("abcd", 100);
    try std.testing.expect(r.u32At(1, .little) == null);
    try std.testing.expect(r.u64At(0, .little) == null);
    try std.testing.expect(r.sub(4, 0) != null);
    try std.testing.expect(r.sub(5, null) == null);
    try std.testing.expect(r.subClamped(2, 100).?.truncated);
    try std.testing.expect(!r.contains(3, std.math.maxInt(u64)));
    try std.testing.expect(r.cursor(4) != null and r.cursor(5) == null);
    try std.testing.expectEqualStrings("abcd", r.nameAt(0, 4).?);
    try std.testing.expect(!(r.cstrAt(0, 16).?).terminated);
}
```

Error set: `Cursor.Error = error{ Truncated, Overflow }`. `takeUleb` refuses to wrap (10-byte ULEBs that do
not fit are `Overflow`); `takeUlebWrapping` implements `BIND_OPCODE_ADD_ADDR_ULEB` two's-complement deltas;
`takeSleb` sign-extends without a shift overflow for 9- and 10-byte encodings (the judges' C-defect).

### 3.2 `core/limits.zig` — every cap in one place + `BudgetAllocator` (verbatim, compiled)

```zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Limits = struct {
    max_file_size: u64 = 1 << 31,
    max_fat_arches: u32 = 32,
    max_load_commands: u32 = 4096,
    max_sizeofcmds: u32 = 1 << 20,
    max_sections: u32 = 4096,
    max_symbols: u32 = 1 << 22,
    max_strtab: u32 = 1 << 28,
    max_indirect_symbols: u32 = 1 << 22,
    max_symbol_name: u32 = 4096,
    max_dylibs: u32 = 1024,
    max_rpaths: u32 = 256,
    max_fixups: u32 = 1 << 22,
    max_chain_steps_per_page: u32 = 1 << 16,
    max_imports: u32 = 1 << 20,
    max_exports: u32 = 1 << 20,
    max_trie_nodes: u32 = 1 << 20,
    max_trie_depth: u32 = 512,
    max_opcode_bytes: u32 = 1 << 26,
    max_function_starts: u32 = 1 << 20,
    max_data_in_code: u32 = 1 << 20,
    max_superblob_slots: u32 = 64,
    max_blob_len: u32 = 1 << 24,
    max_code_slots: u32 = 1 << 20,
    max_special_slots: u32 = 16,
    max_requirement_ops: u32 = 4096,
    max_requirement_depth: u32 = 64,
    max_der_depth: u32 = 32,
    max_der_nodes: u32 = 1 << 16,
    max_asn1_depth: u32 = 32,
    max_asn1_nodes: u32 = 1 << 16,
    max_cms_certs: u32 = 32,
    max_entitlement_keys: u32 = 4096,
    max_objc_classes: u32 = 1 << 16,
    max_objc_methods_per_list: u32 = 1 << 14,
    max_objc_total_methods: u32 = 1 << 20,
    max_objc_protocol_depth: u32 = 16,
    max_strings: u32 = 1 << 20,
    max_string_len: u32 = 1 << 16,
    min_string_len: u32 = 4,
    max_plist_objects: u32 = 1 << 20,
    max_plist_depth: u32 = 64,
    max_plist_bytes: u32 = 1 << 26,
    max_xml_bytes: u32 = 1 << 26,
    max_bundle_entries: u32 = 1 << 16,
    max_bundle_depth: u32 = 16,
    max_nested_code: u32 = 1024,
    max_disasm_bytes: u32 = 1 << 26,
    max_instructions: u32 = 1 << 22,
    max_functions: u32 = 1 << 20,
    max_xrefs: u32 = 1 << 22,
    max_diagnostics: u32 = 512,
    max_arena_bytes: u64 = 1 << 31,

    pub const default: Limits = .{};
    /// Tiny caps so pathological loops terminate instantly (fuzzers, --paranoid).
    pub const paranoid: Limits = .{
        .max_file_size = 1 << 24,
        .max_load_commands = 256,
        .max_sections = 256,
        .max_symbols = 1 << 12,
        .max_fixups = 1 << 12,
        .max_imports = 1 << 12,
        .max_exports = 1 << 12,
        .max_trie_nodes = 1 << 10,
        .max_code_slots = 1 << 12,
        .max_objc_classes = 1 << 10,
        .max_strings = 1 << 12,
        .max_plist_objects = 1 << 12,
        .max_instructions = 1 << 12,
        .max_functions = 1 << 12,
        .max_xrefs = 1 << 12,
        .max_arena_bytes = 1 << 26,
    };
};

/// std.mem.Allocator wrapper that fails with OutOfMemory once `used` would exceed `budget`.
pub const BudgetAllocator = struct {
    child: Allocator,
    budget: u64,
    used: u64 = 0,
    peak: u64 = 0,
    failures: u32 = 0,

    pub fn init(child: Allocator, budget: u64) BudgetAllocator {
        return .{ .child = child, .budget = budget };
    }
    pub fn allocator(b: *BudgetAllocator) Allocator {
        return .{ .ptr = b, .vtable = &vtable };
    }
    pub fn remaining(b: *const BudgetAllocator) u64 {
        return b.budget -| b.used;
    }
    fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (n > b.remaining()) {
            b.failures += 1;
            return null;
        }
        const p = b.child.rawAlloc(n, alignment, ret_addr) orelse {
            b.failures += 1;
            return null;
        };
        b.used += n;
        b.peak = @max(b.peak, b.used);
        return p;
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > b.remaining()) {
            b.failures += 1;
            return false;
        }
        if (!b.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        b.used = b.used - memory.len + new_len;
        b.peak = @max(b.peak, b.used);
        return true;
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > b.remaining()) {
            b.failures += 1;
            return null;
        }
        const p = b.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        b.used = b.used - memory.len + new_len;
        b.peak = @max(b.peak, b.used);
        return p;
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        b.child.rawFree(memory, alignment, ret_addr);
        b.used -|= memory.len;
    }
    pub const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
};

test "limits: budget allocator enforces the cap and tracks usage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var budget = BudgetAllocator.init(arena.allocator(), 1024);
    const a = budget.allocator();
    const first = try a.alloc(u8, 600);
    try std.testing.expectEqual(@as(u64, 600), budget.used);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 600));
    try std.testing.expectEqual(@as(u32, 1), budget.failures);
    const second = try a.alloc(u8, 400);
    try std.testing.expectEqual(@as(u64, 1000), budget.peak);
    a.free(second);
    a.free(first);
    try std.testing.expect(budget.used <= 1000);
    try std.testing.expect(Limits.default.max_symbols > Limits.paranoid.max_symbols);
}
```

`Limits` is passed as `*const Limits` everywhere (`&Limits.default`, `&Limits.paranoid`, or a CLI-built value).
`BudgetAllocator` uses the verified `std.mem.Allocator.VTable` shape (`alloc/resize/remap/free`,
mem/Allocator.zig:32-84) and wraps the per-analysis `ArenaAllocator`; `--verbose` prints `peak`/`failures`.

### 3.3 `core/diag.zig` — problems are data (verbatim, compiled)

```zig
//! core/diag.zig — problems are data. Imports: std only.
const std = @import("std");

pub const Severity = enum(u8) { info, warning, @"error" };

pub const Module = enum {
    file, fat, header, loadcmds, segments, symbols, chained, exports, legacy, function_starts, fixups, imports,
    codesign, requirements, entitlements, cms, security, xattr, dylib_resolve, objc, strings, entropy, plist,
    bundle, disasm, functions, symbolize, analysis, triage, cli,
};

/// Stable machine-readable codes (JSON emits the tag name). Add, never renumber/rename.
pub const Code = enum {
    truncated,
    bad_magic,
    count_clamped,
    cmdsize_invalid,
    sizeofcmds_invalid,
    nsects_invalid,
    offset_past_eof,
    overlap,
    unaligned,
    unknown_value,
    string_unterminated,
    invalid_utf8,
    ordinal_out_of_range,
    chain_broken,
    trie_malformed,
    opcode_malformed,
    blob_malformed,
    hash_mismatch,
    version_unsupported,
    der_malformed,
    plist_malformed,
    limit_reached,
    not_available,
    not_implemented,
    os_error,
    backend_disagree,
    stub_mismatch,
    heuristic,
};

pub const Diag = struct {
    severity: Severity,
    module: Module,
    code: Code,
    /// Absolute file offset where the problem was observed, when meaningful.
    offset: ?u64,
    /// Arena-owned, already sanitized (printable ASCII only).
    message: []const u8,
};

pub const Diagnostics = struct {
    arena: std.mem.Allocator,
    list: std.ArrayList(Diag) = .empty,
    dropped: u32 = 0,
    max: u32,
    counts: [3]u32 = .{ 0, 0, 0 },

    pub fn init(arena: std.mem.Allocator, max: u32) Diagnostics {
        return .{ .arena = arena, .max = max };
    }
    /// Never fails visibly: on OOM the diagnostic is counted in `dropped`.
    pub fn add(d: *Diagnostics, severity: Severity, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.counts[@intFromEnum(severity)] += 1;
        if (d.list.items.len >= d.max) {
            d.dropped += 1;
            return;
        }
        const msg = std.fmt.allocPrint(d.arena, fmt, args) catch {
            d.dropped += 1;
            return;
        };
        d.list.append(d.arena, .{ .severity = severity, .module = module, .code = code, .offset = offset, .message = msg }) catch {
            d.dropped += 1;
        };
    }
    pub fn warn(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.warning, module, code, offset, fmt, args);
    }
    pub fn err(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.@"error", module, code, offset, fmt, args);
    }
    pub fn info(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.info, module, code, offset, fmt, args);
    }
    /// True when a diagnostic with this (module, code) was already recorded.
    pub fn has(d: *const Diagnostics, module: Module, code: Code) bool {
        for (d.list.items) |it| if (it.module == module and it.code == code) return true;
        return false;
    }
    pub fn hasErrors(d: *const Diagnostics) bool {
        return d.counts[@intFromEnum(Severity.@"error")] != 0;
    }
    pub fn items(d: *const Diagnostics) []const Diag {
        return d.list.items;
    }
};

test "diag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var d = Diagnostics.init(arena.allocator(), 2);
    d.warn(.loadcmds, .cmdsize_invalid, 32, "cmdsize {d}", .{@as(u32, 0)});
    d.err(.symbols, .truncated, null, "x", .{});
    d.err(.symbols, .truncated, null, "y", .{});
    try std.testing.expectEqual(@as(usize, 2), d.items().len);
    try std.testing.expectEqual(@as(u32, 1), d.dropped);
    try std.testing.expect(d.hasErrors());
}
```

Rules: `Code` and `Module` are enums (JSON emits tag names; add, never rename). `Diagnostics.add` never fails
visibly (OOM or `max` reached -> `dropped += 1`). Parsers emit **one diagnostic per (module, code) per
structure** using `has()` before adding repeat instances (e.g. one `truncated` for "N symbol names past
strsize", not N). `message` is sanitised text (§3.5 `.text` policy) built with `std.fmt.allocPrint`.

### 3.4 `core/arch.zig` (verbatim, compiled)

```zig
const std = @import("std");
const builtin = @import("builtin");

pub const CpuType = enum(i32) {
    any = -1,
    x86 = 7,
    arm = 12,
    powerpc = 18,
    x86_64 = 0x01000007,
    arm64 = 0x0100000c,
    arm64_32 = 0x0200000c,
    powerpc64 = 0x01000012,
    _,
};

pub const ArchName = enum {
    x86_64, x86_64h, i386, arm64, arm64v8, arm64e, arm64_32, armv7, armv7s, armv7k, armv8, ppc, ppc64, unknown,
    pub fn parse(s: []const u8) ?ArchName {
        return std.meta.stringToEnum(ArchName, s);
    }
    pub fn str(n: ArchName) []const u8 {
        return @tagName(n);
    }
};
pub const Arch = struct {
    cputype: i32,
    cpusubtype: i32,
    name: ArchName,
    ptr_size: u8,
    is_64: bool,
    is_arm64e: bool,
    ptrauth_version: u8,
    caps: u8,

    pub fn fromCpu(cputype: i32, cpusubtype: i32) Arch {
        const sub: u32 = @bitCast(cpusubtype);
        const low = sub & 0x00ff_ffff;
        const caps: u8 = @truncate(sub >> 24);
        const name: ArchName = switch (cputype) {
            0x01000007 => if (low == 8) .x86_64h else .x86_64,
            7 => .i386,
            0x0100000c => switch (low) {
                1 => .arm64v8,
                2 => .arm64e,
                else => .arm64,
            },
            0x0200000c => .arm64_32,
            12 => switch (low) {
                9 => .armv7,
                11 => .armv7s,
                12 => .armv7k,
                13 => .armv8,
                else => .unknown,
            },
            18 => .ppc,
            0x01000012 => .ppc64,
            else => .unknown,
        };
        const is_64 = (cputype & 0x01000000) != 0;
        return .{
            .cputype = cputype,
            .cpusubtype = cpusubtype,
            .name = name,
            .ptr_size = if (is_64) 8 else 4,
            .is_64 = is_64,
            .is_arm64e = name == .arm64e,
            .ptrauth_version = @truncate((sub & 0x0f000000) >> 24),
            .caps = caps,
        };
    }
    pub fn subtypeLow(a: Arch) u32 {
        return @as(u32, @bitCast(a.cpusubtype)) & 0x00ff_ffff;
    }
    pub fn matches(a: Arch, wanted: ArchName) bool {
        return a.name == wanted;
    }
    pub fn host() Arch {
        return switch (builtin.cpu.arch) {
            .aarch64 => fromCpu(0x0100000c, 0),
            .x86_64 => fromCpu(0x01000007, 3),
            else => fromCpu(0, 0),
        };
    }
    pub fn preferenceRank(a: Arch, host_arch: Arch) u8 {
        if (a.name == host_arch.name) return 0;
        if (a.cputype == host_arch.cputype) return 1;
        return 2;
    }
    /// "arm64e" or "unknown(0x1000012/0x0)" for unrecognised pairs.
    pub fn displayName(a: Arch, buf: *[32]u8) []const u8 {
        if (a.name != .unknown) return @tagName(a.name);
        return std.fmt.bufPrint(buf, "unknown(0x{x}/0x{x})", .{ @as(u32, @bitCast(a.cputype)), @as(u32, @bitCast(a.cpusubtype)) }) catch "unknown";
    }
};

test "arch: /bin/ls slices and --arch parsing" {
    const e = Arch.fromCpu(0x0100000c, @bitCast(@as(u32, 0x80000002)));
    try std.testing.expectEqual(ArchName.arm64e, e.name);
    try std.testing.expectEqual(@as(u8, 0x80), e.caps);
    try std.testing.expectEqual(@as(u32, 2), e.subtypeLow());
    try std.testing.expect(e.is_arm64e and e.is_64 and e.ptr_size == 8);
    try std.testing.expectEqual(ArchName.x86_64, Arch.fromCpu(0x01000007, 3).name);
    try std.testing.expectEqual(ArchName.x86_64h, Arch.fromCpu(0x01000007, 8).name);
    try std.testing.expectEqual(ArchName.arm64e, ArchName.parse("arm64e").?);
    try std.testing.expect(ArchName.parse("mips") == null);
    try std.testing.expectEqual(@as(u8, 1), e.preferenceRank(Arch.fromCpu(0x0100000c, 0)));
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("arm64e", e.displayName(&buf));
    try std.testing.expectEqualStrings("unknown(0x1000013/0x0)", Arch.fromCpu(0x01000013, 0).displayName(&buf));
}
```

`ArchName` is the `--arch` vocabulary (`std.meta.stringToEnum`); `Arch.preferenceRank` implements the
text-mode default-slice policy (§5): exact host name (arm64 on this machine) > same cputype (arm64e) > first valid.

### 3.5 `core/sanitize.zig` (verbatim, compiled)

Output must be inert: every string that comes out of the input file is attacker-controlled, so a crafted
segment name or symbol name must not be able to recolour the terminal, overwrite an already-printed line
or forge a verdict. `.text` escapes C0, DEL, C1 (including CSI U+009B), the bidi/line-separator controls
and invalid UTF-8 as `\xNN` / `\u{NN}` while passing legitimate non-ASCII UTF-8 through unchanged;
`.json` replaces invalid UTF-8 and C0/DEL (except `\t\n\r`, which `std.json.Stringify` escapes itself)
with U+FFFD and `output/json.str` adds the `<key>_hex` / `<key>_lossy` siblings. Renderers reach it through
`Sink.safe` / `Sink.safeMax`, which also bump the per-run tally reported as `sanitized_strings`.

```zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Policy = enum { text, json };
pub const Sanitized = struct { text: []const u8, lossy: bool };

/// Longest file-derived string rendered into output by `Sink.safe`; longer input is cut.
pub const max_render: u32 = 1 << 20;

/// True when the code point cannot move the cursor, end the line, start an escape sequence or
/// reorder what follows it.
fn okCodepoint(cp: u21) bool {
    if (cp < 0x20 or cp == 0x7f) return false; // C0 + DEL
    if (cp >= 0x80 and cp <= 0x9f) return false; // C1 (0x9b = CSI)
    return switch (cp) {
        0x200b...0x200f => false, // zero width space + LRM/RLM
        0x2028, 0x2029 => false, // line / paragraph separator
        0x202a...0x202e => false, // bidi embedding + override (trojan-source)
        0x2066...0x2069 => false, // bidi isolate
        0xfeff => false, // zero width no-break space
        else => true,
    };
}
fn okByte(b: u8, policy: Policy) bool {
    return switch (policy) {
        .text => b >= 0x20 and b < 0x7f,
        .json => (b >= 0x20 and b < 0x7f) or b == '\t' or b == '\n' or b == '\r',
    };
}
pub fn isClean(s: []const u8, policy: Policy) bool {
    if (policy == .json) {
        if (!std.unicode.utf8ValidateSlice(s)) return false;
        for (s) |b| if ((b < 0x20 or b == 0x7f) and !okByte(b, .json)) return false;
        return true;
    }
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        if (b < 0x80) {
            if (!okByte(b, .text)) return false;
            i += 1;
            continue;
        }
        const n = std.unicode.utf8ByteSequenceLength(b) catch return false;
        if (i + n > s.len) return false;
        const cp = std.unicode.utf8Decode(s[i .. i + n]) catch return false;
        if (!okCodepoint(cp)) return false;
        i += n;
    }
    return true;
}
/// Returns `s` itself (lossy=false) when clean; otherwise an arena copy with invalid UTF-8 / control
/// code points replaced (text: `\xNN` per byte, `\u{NN}` per non-ASCII code point; json: U+FFFD, one
/// per offending byte). Cut at `max` bytes of input.
pub fn string(arena: Allocator, s: []const u8, policy: Policy, max: u32) Allocator.Error!Sanitized {
    const in = if (s.len > max) s[0..max] else s;
    if (isClean(in, policy) and in.len == s.len) return .{ .text = s, .lossy = false };
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < in.len) {
        const b = in[i];
        if (b >= 0x80) {
            const n = std.unicode.utf8ByteSequenceLength(b) catch 0;
            if (n != 0 and i + n <= in.len) {
                if (std.unicode.utf8Decode(in[i .. i + n]) catch null) |cp| {
                    if (policy == .json or okCodepoint(cp)) {
                        try out.appendSlice(arena, in[i .. i + n]);
                    } else {
                        try out.print(arena, "\\u{{{x}}}", .{cp});
                    }
                    i += n;
                    continue;
                }
            }
        }
        if (okByte(b, policy)) {
            try out.append(arena, b);
        } else switch (policy) {
            .text => try out.print(arena, "\\x{x:0>2}", .{b}),
            .json => try out.appendSlice(arena, "\u{FFFD}"),
        }
        i += 1;
    }
    return .{ .text = try out.toOwnedSlice(arena), .lossy = true };
}
/// Terminal-safe rendering of one file-derived string; bumps `lossy` when anything was escaped.
pub fn forText(arena: Allocator, s: []const u8, lossy: ?*u32) Allocator.Error![]const u8 {
    const r = try string(arena, s, .text, max_render);
    if (r.lossy) if (lossy) |c| {
        c.* +|= 1;
    };
    return r.text;
}
pub fn hexLower(arena: Allocator, b: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "{x}", .{b});
}
pub fn escapeC(w: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    for (bytes) |b| switch (b) {
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        else => if (b >= 0x20 and b < 0x7f) try w.writeByte(b) else try w.print("\\x{x:0>2}", .{b}),
    };
}
/// "YYYY-MM-DDTHH:MM:SSZ" (std.time.epoch.EpochSeconds; pre-1970 -> epoch).
pub fn iso8601(buf: *[20]u8, unix: i64) []const u8 {
    const secs: u64 = if (unix < 0) 0 else @intCast(unix);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

test "sanitize: json policy never lets invalid UTF-8 reach Stringify as a string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try string(a, "bad\xffutf8\x01ctl", .json, 4096);
    try std.testing.expect(s.lossy);
    try std.testing.expect(std.unicode.utf8ValidateSlice(s.text));
    try std.testing.expectEqualStrings("bad\u{FFFD}utf8\u{FFFD}ctl", s.text);
    const clean = try string(a, "héllo", .json, 4096);
    try std.testing.expect(!clean.lossy);
    const t = try string(a, "a\x01b", .text, 4096);
    try std.testing.expectEqualStrings("a\\x01b", t.text);
    var buf: [20]u8 = undefined;
    try std.testing.expectEqualStrings("2025-09-12T04:29:38Z", iso8601(&buf, 0x68c3a1b2));
}

test "sanitize: text policy neutralises terminal controls and keeps real UTF-8" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The reported defect: a crafted 16-byte segment name carrying SGR + CR.
    const seg = try string(a, "\x1b[31mPWNED\x1b[0m\r", .text, 4096);
    try std.testing.expect(seg.lossy);
    try std.testing.expectEqualStrings("\\x1b[31mPWNED\\x1b[0m\\x0d", seg.text);
    // Unicode app names must still render.
    const uni = try string(a, "Café\u{1F512}日本語", .text, 4096);
    try std.testing.expect(!uni.lossy);
    try std.testing.expectEqualStrings("Café\u{1F512}日本語", uni.text);
    // C1 CSI, DEL, BEL, backspace, NUL, invalid UTF-8, bidi override.
    try std.testing.expectEqualStrings("\\u{9b}", (try string(a, "\u{9b}", .text, 4096)).text);
    try std.testing.expectEqualStrings("\\x7f\\x07\\x08\\x00", (try string(a, "\x7f\x07\x08\x00", .text, 4096)).text);
    try std.testing.expectEqualStrings("a\\xffb", (try string(a, "a\xffb", .text, 4096)).text);
    try std.testing.expectEqualStrings("evil\\u{202e}gpj.exe", (try string(a, "evil\u{202e}gpj.exe", .text, 4096)).text);
    try std.testing.expect(!isClean("a\rb", .text));
    try std.testing.expect(isClean("Café", .text));
    var n: u32 = 0;
    _ = try forText(a, "ok", &n);
    try std.testing.expectEqual(@as(u32, 0), n);
    _ = try forText(a, "no\x1bt ok", &n);
    try std.testing.expectEqual(@as(u32, 1), n);
}
```

### 3.6 `core/fmt.zig` — `{f}` formatter types shared by text and JSON (verbatim, compiled)

```zig
const std = @import("std");
const Io = std.Io;

pub const Addr = struct {
    v: u64,
    pub fn format(a: Addr, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("0x{x}", .{a.v});
    }
};
pub const Addr16 = struct {
    v: u64,
    pub fn format(a: Addr16, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{x:0>16}", .{a.v});
    }
};
pub const Hex = struct {
    bytes: []const u8,
    pub fn format(h: Hex, w: *Io.Writer) Io.Writer.Error!void {
        try w.printHex(h.bytes, .lower);
    }
};
pub const Uuid = struct {
    bytes: [16]u8,
    pub fn format(u: Uuid, w: *Io.Writer) Io.Writer.Error!void {
        const b = u.bytes;
        try w.print("{X}-{X}-{X}-{X}-{X}", .{ b[0..4], b[4..6], b[6..8], b[8..10], b[10..16] });
    }
};
pub const Version = struct {
    v: u32,
    pub fn format(v: Version, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff, v.v & 0xff });
    }
};
pub const VersionShort = struct {
    v: u32,
    pub fn format(v: VersionShort, w: *Io.Writer) Io.Writer.Error!void {
        if (v.v & 0xff == 0) try w.print("{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff }) else try w.print("{d}.{d}.{d}", .{ v.v >> 16, (v.v >> 8) & 0xff, v.v & 0xff });
    }
};
pub const SourceVersion = struct {
    v: u64,
    pub fn format(v: SourceVersion, w: *Io.Writer) Io.Writer.Error!void {
        const a = v.v >> 40;
        const parts = [_]u64{ (v.v >> 30) & 0x3ff, (v.v >> 20) & 0x3ff, (v.v >> 10) & 0x3ff, v.v & 0x3ff };
        var last: usize = 0;
        for (parts, 0..) |p, i| if (p != 0) {
            last = i + 1;
        };
        try w.print("{d}.{d}", .{ a, parts[0] });
        for (parts[1..], 1..) |p, i| if (i < last) try w.print(".{d}", .{p});
    }
};
pub const Iso8601 = struct {
    unix_secs: i64,
    pub fn format(t: Iso8601, w: *Io.Writer) Io.Writer.Error!void {
        var buf: [20]u8 = undefined;
        try w.writeAll(@import("sanitize.zig").iso8601(&buf, t.unix_secs));
    }
};
pub const FlagName = struct { bit: u64, name: []const u8 };
pub const Flags = struct {
    value: u64,
    table: []const FlagName,
    sep: []const u8 = ",",
    pub fn format(f: Flags, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("0x{x} (", .{f.value});
        var rest = f.value;
        var first = true;
        for (f.table) |e| if (f.value & e.bit != 0) {
            if (!first) try w.writeAll(f.sep);
            try w.writeAll(e.name);
            rest &= ~e.bit;
            first = false;
        };
        if (rest != 0) {
            if (!first) try w.writeAll(f.sep);
            try w.print("0x{x}", .{rest});
            first = false;
        }
        if (first) try w.writeAll("none");
        try w.writeAll(")");
    }
};
pub fn flagNames(value: u64, table: []const FlagName, buf: [][]const u8) []const []const u8 {
    var n: usize = 0;
    for (table) |e| if (value & e.bit != 0 and n < buf.len) {
        buf[n] = e.name;
        n += 1;
    };
    return buf[0..n];
}

test "fmt: formatter types match the reference tools' spelling" {
    try std.testing.expectFmt("0x100000524", "{f}", .{Addr{ .v = 0x100000524 }});
    try std.testing.expectFmt("0000000100000524", "{f}", .{Addr16{ .v = 0x100000524 }});
    try std.testing.expectFmt("21C9F585-96F5-3A4C-A516-BBBE1808D26E", "{f}", .{Uuid{ .bytes = .{ 0x21, 0xC9, 0xF5, 0x85, 0x96, 0xF5, 0x3A, 0x4C, 0xA5, 0x16, 0xBB, 0xBE, 0x18, 0x08, 0xD2, 0x6E } }});
    try std.testing.expectFmt("1356.0.0", "{f}", .{Version{ .v = 0x054c0000 }});
    try std.testing.expectFmt("26.5", "{f}", .{VersionShort{ .v = 0x001a0500 }});
    try std.testing.expectFmt("475.0", "{f}", .{SourceVersion{ .v = 0x1db0000000000 }});
    try std.testing.expectFmt("0x20002 (adhoc,linker-signed)", "{f}", .{Flags{ .value = 0x20002, .table = &.{ .{ .bit = 0x2, .name = "adhoc" }, .{ .bit = 0x20000, .name = "linker-signed" } } }});
    try std.testing.expectFmt("0x0 (none)", "{f}", .{Flags{ .value = 0, .table = &.{} }});
    try std.testing.expectFmt("f865cf", "{f}", .{Hex{ .bytes = &.{ 0xf8, 0x65, 0xcf } }});
    try std.testing.expectFmt("2025-09-12T04:29:38Z", "{f}", .{Iso8601{ .unix_secs = 0x68c3a1b2 }});
}
```

### 3.7 `output/sink.zig` — the output abstraction + JSON wrapper types (verbatim, compiled)

```zig
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const sanitize = @import("../core/sanitize.zig");

pub const Mode = enum { text, json };
pub const Options = struct { verbose: u8 = 0, color: bool = false, limit: u32 = 0, pretty_json: bool = true, otool_compat: bool = false, quiet: bool = false };

pub const Sink = struct {
    mode: Mode,
    out: *Io.Writer,
    json: std.json.Stringify,
    opts: Options,
    arena: Allocator,
    /// How many file-derived strings needed escaping on their way out (reported by `cli.zig` as a
    /// `cli.invalid_utf8` diagnostic so the analyst knows the sample tried to write control bytes).
    lossy: u32 = 0,

    pub fn init(mode: Mode, out: *Io.Writer, opts: Options, arena: Allocator) Sink {
        return .{
            .mode = mode,
            .out = out,
            .json = .{ .writer = out, .options = .{ .whitespace = if (opts.pretty_json) .indent_2 else .minified } },
            .opts = opts,
            .arena = arena,
        };
    }
    pub fn isJson(s: *const Sink) bool {
        return s.mode == .json;
    }
    pub fn flush(s: *Sink) Io.Writer.Error!void {
        return s.out.flush();
    }
    /// The one way a file-derived string becomes text output: control characters, C1/bidi code points
    /// and invalid UTF-8 are escaped (`core/sanitize.zig`), legitimate UTF-8 is preserved, and the
    /// per-run lossy counter is bumped. Returns `bytes` itself when nothing had to change.
    pub fn safe(s: *Sink, bytes: []const u8) Allocator.Error![]const u8 {
        return sanitize.forText(s.arena, bytes, &s.lossy);
    }
    /// `safe` with an explicit input cap (the caller's `Limits` value).
    pub fn safeMax(s: *Sink, bytes: []const u8, max: u32) Allocator.Error![]const u8 {
        const r = try sanitize.string(s.arena, bytes, .text, max);
        if (r.lossy) s.lossy +|= 1;
        return r.text;
    }
    /// `safe` for an optional string; `null` renders as `fallback`.
    pub fn safeOr(s: *Sink, bytes: ?[]const u8, fallback: []const u8) Allocator.Error![]const u8 {
        return if (bytes) |b| s.safe(b) else fallback;
    }
};
pub const Error = Io.Writer.Error || Allocator.Error;

/// Pre-sanitized string: `jsonStringify` never allocates and never yields a number array.
pub const Str = struct {
    text: []const u8,
    lossy: bool,
    pub fn init(arena: Allocator, bytes: []const u8, max: u32) Allocator.Error!Str {
        const s = try sanitize.string(arena, bytes, .json, max);
        return .{ .text = s.text, .lossy = s.lossy };
    }
    pub fn jsonStringify(self: Str, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        return jw.write(self.text);
    }
};
pub const Hex64 = struct {
    v: u64,
    pub fn jsonStringify(self: Hex64, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        var buf: [20]u8 = undefined;
        return jw.write(std.fmt.bufPrint(&buf, "0x{x}", .{self.v}) catch unreachable);
    }
};
pub const HexBytes = struct {
    bytes: []const u8,
    pub fn jsonStringify(self: HexBytes, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginWriteRaw();
        try jw.writer.writeByte('"');
        try jw.writer.printHex(self.bytes, .lower);
        try jw.writer.writeByte('"');
        jw.endWriteRaw();
    }
};
pub const IsoTime = struct {
    secs: i64,
    pub fn jsonStringify(self: IsoTime, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        var buf: [20]u8 = undefined;
        return jw.write(sanitize.iso8601(&buf, self.secs));
    }
};

test "sink: wrapper types serialize as strings via std.json.Stringify.value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var s = Sink.init(.json, &w, .{ .pretty_json = false }, a);
    const Rec = struct { name: Str, raw: Hex64, digest: HexBytes, when: IsoTime, small: u32 };
    const rec: Rec = .{
        .name = try Str.init(a, "bad\xffname", 4096),
        .raw = .{ .v = 0x8010000000000000 },
        .digest = .{ .bytes = &[_]u8{ 0xf8, 0x65, 0xcf } },
        .when = .{ .secs = 0x68c3a1b2 },
        .small = 7,
    };
    try std.json.Stringify.value(rec, .{}, s.out);
    try std.testing.expectEqualStrings(
        "{\"name\":\"bad\u{FFFD}name\",\"raw\":\"0x8010000000000000\",\"digest\":\"f865cf\",\"when\":\"2025-09-12T04:29:38Z\",\"small\":7}",
        w.buffered(),
    );
    try std.testing.expect(rec.name.lossy);
    try s.json.beginObject();
    try s.json.objectField("k");
    try s.json.write(@as(u32, 1));
    try s.json.endObject();
}
```

`Str` is built **before** stringification (`Str.init(arena, bytes, max)`), so `jsonStringify` never allocates and
a name of any length is sanitised in full (the judges' 512-byte-FBA defect is gone); `lossy` tells the JSON
helper (§4.28 `json.str`) to also emit `<key>_hex` (original bytes) and `<key>_lossy: true`.
`Hex64` keeps raw pointers/addends out of the >2^53 trap; `HexBytes` uses the verified
`beginWriteRaw`/`printHex`/`endWriteRaw`.

### 3.8 `core/loadcmds.zig` — header + bounds-checked load-command walker (signatures)

```zig
//! core/loadcmds.zig — bounds-checked load-command walker + typed decoders.
//! Imports: reader, diag, limits, version, macho_extra.
const std = @import("std");
const macho = std.macho;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;
pub const extra = @import("macho_extra.zig");

pub const Header = struct {
    magic: u32,
    is_64: bool,
    endian: std.builtin.Endian, // .little for MH_MAGIC(_64); .big for MH_CIGAM(_64)
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    header_size: u32, // 28 or 32

    pub const ParseError = error{ NotMachO, Truncated };
    /// Validates magic and that the header fits; never reads outside `r`.
    pub fn parse(r: Reader) ParseError!Header;
};

/// A raw, bounds-validated load command: `cmd` may be any value (non-exhaustive std.macho.LC).
pub const LoadCmd = struct {
    index: u32,
    cmd: u32,
    cmdsize: u32,
    /// Offset of the command within the slice; `bytes` is exactly cmdsize long and inside sizeofcmds.
    offset: u32,
    bytes: []const u8,
    endian: std.builtin.Endian,

    pub fn lc(c: LoadCmd) macho.LC;
    pub fn reader(c: LoadCmd) Reader;
    pub fn requiresDyld(c: LoadCmd) bool;
};

pub const Walker = struct {
    r: Reader,
    hdr: Header,
    pos: u32,
    index: u32,
    stopped: bool,
    sizeofcmds_clamped: u32,
    ncmds_clamped: u32,

    /// Clamps sizeofcmds to the bytes present and ncmds to `limits.max_load_commands` (diagnostics recorded).
    pub fn init(r: Reader, hdr: Header, limits: *const Limits, diags: *Diagnostics) Walker;
    /// Null at the end or on the first invalid cmdsize (< 8 / not %8 (4 for 32-bit) / past sizeofcmds:
    /// recorded as `cmdsize_invalid`, `stopped=true`).
    pub fn next(w: *Walker, diags: *Diagnostics) ?LoadCmd;
};

pub const Dylib = struct {
    cmd: u32,
    name: []const u8,
    name_terminated: bool,
    timestamp: u32,
    current_version: u32,
    compat_version: u32,
    flags: u32, // dylib_use_command flags (0 for classic encoding)
    ordinal: u16, // 1-based among LOAD/LOAD_WEAK/REEXPORT/UPWARD/LAZY_LOAD
    weak: bool,
    reexport: bool,
    upward: bool,
    delayed_init: bool,
    use_command: bool, // encoded as dylib_use_command (marker 0x1a741800)
};
pub const BuildTool = struct { tool: u32, version: u32 };
pub const BuildVersion = struct { platform: u32, minos: u32, sdk: u32, ntools_declared: u32, tools: []const BuildTool };
pub const VersionMin = struct { cmd: u32, version: u32, sdk: u32 };
pub const Entry = union(enum) {
    main: struct { entryoff: u64, stacksize: u64 },
    unixthread: struct { flavor: u32, count: u32, pc: ?u64 },
    none,
};
pub const EncryptionInfo = struct { cmd: u32, cryptoff: u32, cryptsize: u32, cryptid: u32 };
pub const LinkeditData = struct { dataoff: u32, datasize: u32 };
pub const LcStr = struct { text: []const u8, terminated: bool, offset: u32 };

/// Handles the classic lc_str layout and the dylib_use_command encoding; null when cmdsize is too small.
pub fn decodeDylib(arena: Allocator, c: LoadCmd, ordinal: u16, diags: *Diagnostics) Allocator.Error!?Dylib;
/// RPATH, LOAD_DYLINKER, ID_DYLINKER, DYLD_ENVIRONMENT, SUB_*, TARGET_TRIPLE: string at cmd_start + offset,
/// must be NUL-terminated inside the command (`string_unterminated` otherwise; truncated bytes still returned).
pub fn decodeLcStr(c: LoadCmd, str_off_field: u32, diags: *Diagnostics) ?LcStr;
pub fn decodeBuildVersion(arena: Allocator, c: LoadCmd, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?BuildVersion;
pub fn decodeVersionMin(c: LoadCmd) ?VersionMin;
pub fn decodeUuid(c: LoadCmd) ?[16]u8;
pub fn decodeSourceVersion(c: LoadCmd) ?u64;
pub fn decodeEntry(c: LoadCmd, is_64: bool, diags: *Diagnostics) Entry;
pub fn decodeLinkeditData(c: LoadCmd) ?LinkeditData;
pub fn decodeSymtab(c: LoadCmd) ?macho.symtab_command;
pub fn decodeDysymtab(c: LoadCmd) ?macho.dysymtab_command;
pub fn decodeDyldInfo(c: LoadCmd) ?macho.dyld_info_command;
pub fn decodeEncryptionInfo(c: LoadCmd) ?EncryptionInfo;
pub fn decodeLinkerOptions(arena: Allocator, c: LoadCmd, diags: *Diagnostics) Allocator.Error![]const []const u8;
pub fn decodeFilesetEntry(c: LoadCmd, diags: *Diagnostics) ?struct { vmaddr: u64, fileoff: u64, entry_id: []const u8 };
pub fn decodeNote(c: LoadCmd) ?struct { data_owner: []const u8, offset: u64, size: u64 };
/// True for LOAD_DYLIB, LOAD_WEAK_DYLIB, REEXPORT_DYLIB, LOAD_UPWARD_DYLIB, LAZY_LOAD_DYLIB (ordinal-bearing).
pub fn isDylibLoadCmd(cmd: u32) bool;
```

`Header` and `LoadCmd` live here (not in image.zig) so `image -> loadcmds` is the only edge between them.
`Walker.next` rules (zig-api-notes 15.2 / corpus-notes): `cmdsize < 8` (4 for 32-bit) or `cmdsize % 8 != 0`
or `pos + cmdsize > sizeofcmds` -> `cmdsize_invalid` + stop; `hdr_size + sizeofcmds > r.len()` ->
`sizeofcmds_invalid` + clamp; `ncmds > limits.max_load_commands` -> `count_clamped`. Every decoder checks
`c.bytes.len >= @sizeOf(T)` and every `lc_str.offset` against `cmdsize`.

### 3.9 `core/segments.zig` (signatures)

```zig
//! core/segments.zig — normalized Segment/Section + classification. Imports: std only.
const std = @import("std");

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
    pub fn protString(s: Segment, buf: *[3]u8, which: Which) []const u8;
    pub fn isProtected(s: Segment) bool;
    pub fn containsVm(s: Segment, vmaddr: u64) bool;
};

pub const SectionClass = enum {
    text, stubs, auth_stubs, objc_stubs, stub_helper, cstring, ustring, cfstring, const_data,
    got, auth_got, la_symbol_ptr, nl_symbol_ptr, data, bss, common, unwind, eh_frame, info_plist,
    objc_methname, objc_classname, objc_methtype, objc_methlist, objc_classlist, objc_nlclslist, objc_catlist,
    objc_nlcatlist, objc_protolist, objc_imageinfo, objc_selrefs, objc_classrefs, objc_superrefs, objc_const,
    objc_data, objc_ivar, mod_init, mod_term, init_offsets, thread_local, other,
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

    pub fn sectType(s: Section) u8;
    pub fn attrs(s: Section) u32;
    pub fn isZerofill(s: Section) bool;
    /// S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS
    pub fn isCode(s: Section) bool;
    pub fn isSymbolStubs(s: Section) bool;
    pub fn containsVm(s: Section, vmaddr: u64) bool;
    /// Entry size for stub/pointer sections: reserved2 for S_SYMBOL_STUBS, 32 for __objc_stubs,
    /// 8 for pointer sections, null otherwise.
    pub fn entrySize(s: Section) ?u32;
};

pub fn classify(segname: []const u8, sectname: []const u8, flags: u32) SectionClass;
```

### 3.10 `core/fat.zig` and `core/file.zig` (signatures)

```zig
//! core/fat.zig — fat/universal container detection and slice selection.
//! Imports: reader, arch, diag, limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const arch_mod = @import("arch.zig");
const Arch = arch_mod.Arch;
const ArchName = arch_mod.ArchName;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;

pub const FatArch = struct {
    arch: Arch,
    offset: u64,
    size: u64,
    @"align": u32, // log2
    /// false when the slice range is outside the file, overlaps another, or its magic is not Mach-O.
    valid: bool,
};

pub const Fat = struct { is_64: bool, nfat_arch_declared: u32, arches: []const FatArch };

pub const Container = union(enum) {
    /// One Mach-O at file offset 0.
    thin: Arch,
    /// FAT_MAGIC / FAT_MAGIC_64 header; `arches` clamped to limits.max_fat_arches.
    fat: Fat,
    /// Neither: still analysable for xattr/plist/bundle/entropy/strings.
    not_macho,

    pub fn sliceCount(c: Container) usize;
    pub fn containerName(c: Container) []const u8;
};

/// Magic read big-endian; `nfat_arch > max_fat_arches` -> clamp + count_clamped; per arch:
/// offset+size <= r.len() else valid=false + offset_past_eof; pairwise overlap -> overlap;
/// slice magic must be MH_*; FAT_MAGIC_64 uses 32-byte entries.
pub fn parse(arena: Allocator, r: Reader, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Container;

pub const SelectReason = enum { thin, all, requested, host, first };
pub const Selection = struct { indices: []const u32, reason: SelectReason };
pub const SelectError = error{ ArchNotFound, NoValidArch } || Allocator.Error;

/// Applies --arch / --all-archs: `wanted` wins (ArchNotFound if absent); `all` = every valid slice;
/// otherwise the best `Arch.preferenceRank` against `host`, falling back to the first valid slice.
pub fn selectArches(arena: Allocator, c: Container, wanted: ?ArchName, all: bool, host: Arch) SelectError!Selection;

//! core/file.zig — the loaded input file. Imports: reader, fat, arch, limits, diag.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const fat = @import("fat.zig");
const Arch = @import("arch.zig").Arch;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;

pub const LoadedFile = struct {
    path: []const u8, // arena-owned
    path_z: [:0]const u8, // arena-owned NUL-terminated copy for C APIs
    /// Whole file. Owned by `gpa` (freed by `deinit`), NOT by the analysis arena, so a large input can
    /// be released before the arena is torn down (bundles: per nested code object).
    bytes: []const u8,
    size: u64,
    mtime_unix: i64,
    is_dir: bool, // true for bundles/directories (bytes is empty; container = .not_macho)
    container: fat.Container,
    sha256: ?[32]u8 = null,

    pub const LoadError = error{ FileNotFound, AccessDenied, TooLarge, Unexpected } || Allocator.Error;

    /// Stats the path, reads at most `limits.max_file_size` bytes (`Io.Dir.readFileAlloc(.., .limited64(..))`;
    /// larger -> error.TooLarge), classifies the container via fat.parse. Directories -> is_dir=true.
    pub fn load(gpa: Allocator, arena: Allocator, io: Io, path: []const u8, limits: *const Limits, diags: *Diagnostics) LoadError!LoadedFile;
    /// Same classification over caller-provided bytes (tests, fuzzers, nested code already in memory).
    pub fn fromBytes(arena: Allocator, path: []const u8, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!LoadedFile;
    /// Frees `bytes` when they were allocated by `load` (no-op for `fromBytes`).
    pub fn deinit(f: *LoadedFile, gpa: Allocator) void;
    pub fn reader(f: *const LoadedFile) Reader;
    /// Slice reader for Mach-O `index` (0 for thin; only valid fat arches count).
    pub fn sliceReader(f: *const LoadedFile, index: usize) ?Reader;
    pub fn sliceOffset(f: *const LoadedFile, index: usize) ?u64;
    pub fn sliceArch(f: *const LoadedFile, index: usize) ?Arch;
    pub fn sliceCount(f: *const LoadedFile) usize;
    /// Memoized SHA-256 of the whole file.
    pub fn digest(f: *LoadedFile) [32]u8;
};
```

`LoadedFile.bytes` are **gpa-owned** (not arena-owned) so a 2 GiB input — or each nested code object inside a
bundle — can be released with `deinit(gpa)` right after its output is flushed, before the analysis arena is
torn down (judges' B-defect). Results that slice into `bytes` (symbol names, section bytes) are only valid
while the file is loaded; the CLI order is flush -> `file.deinit` -> arena deinit.

### 3.11 `core/image.zig` — one Mach-O slice (signatures)

```zig
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
    pub fn parse(arena: Allocator, r: Reader, slice_offset: u64, index: u32, limits: *const Limits, diags: *Diagnostics) ParseError!Image;
    // ---- address translation (all total) ----
    pub fn vmToOff(img: *const Image, vmaddr: u64) ?u64;
    pub fn offToVm(img: *const Image, off: u64) ?u64;
    pub fn segmentForVm(img: *const Image, vmaddr: u64) ?*const Segment;
    pub fn sectionForVm(img: *const Image, vmaddr: u64) ?*const Section;
    pub fn sectionByName(img: *const Image, segname: []const u8, sectname: []const u8) ?*const Section;
    pub fn sectionByClass(img: *const Image, class: segments.SectionClass) ?*const Section;
    pub fn segmentByName(img: *const Image, segname: []const u8) ?*const Segment;
    pub const VmBytes = struct { bytes: []const u8, truncated: bool };
    /// Bytes backing a vm range; clamps at the segment filesize and slice end. Null when start is unmapped.
    pub fn bytesAtVm(img: *const Image, vmaddr: u64, size: u64) ?VmBytes;
    pub fn cstrAtVm(img: *const Image, vmaddr: u64, max: u32) ?[]const u8;
    pub fn u64AtVm(img: *const Image, vmaddr: u64) ?u64;
    pub fn u32AtVm(img: *const Image, vmaddr: u64) ?u32;
    /// Section bytes as a Reader (null if offset/size fall outside the slice; zero-fill -> empty).
    pub fn sectionReader(img: *const Image, sect: *const Section) ?Reader;
    /// (dataoff, datasize) of a linkedit_data_command: must lie inside the slice; a diagnostic when
    /// it also falls outside __LINKEDIT (tolerated). Clamped at the slice end.
    pub fn linkeditReader(img: *const Image, dataoff: u64, datasize: u64, diags: *Diagnostics, who: diag.Module) ?Reader;
    pub fn findCmd(img: *const Image, cmd: macho.LC) ?LoadCmd;
    pub fn cmdIterator(img: *const Image, cmd: ?macho.LC) CmdIterator;
    pub const CmdIterator = struct {
        img: *const Image,
        want: ?macho.LC,
        i: usize = 0,
        pub fn next(it: *CmdIterator) ?LoadCmd;
    };
    pub fn entryVm(img: *const Image) ?u64;
    pub fn dyldStyle(img: *const Image) DyldStyle;
    pub const DyldStyle = enum { chained, legacy, none };
};
```

Parse rules: magic in {MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM} else `error.NotMachO`; header must fit
else `error.Truncated` (the only hard errors: `truncated-header.bin`, `empty.bin`, `bad-magic.bin`);
`72 + 80*nsects > cmdsize` (56+68 for 32-bit) -> `nsects_invalid`, sections clamped to `(cmdsize-72)/80`
(`nsects-huge.bin` -> `__TEXT` keeps 4 sections); section `offset+size > r.len()` for non-zerofill ->
`offset_past_eof` warning and `sectionReader` returns the clamped part; segment `fileoff+filesize > r.len()`
-> clamp + `file_range_truncated`; `MH_CIGAM*` images: header decoded, commands walked with `endian = .big`,
everything else skipped with `version_unsupported`. `image_base` = vmaddr of `__TEXT` (0x100000000 for
executables, 0 for dylibs). `dyldStyle()` = chained if `LC_DYLD_CHAINED_FIXUPS`, legacy if `LC_DYLD_INFO(_ONLY)`.
---

## 4. Module APIs

Every listing below is the compiled signature set of the named `skeleton-reference/src/...` file (bodies
elided). The **Imports** line of each file header is the complete list of allowed `@import` edges; the union
of these lines is the `allowed` table of `tests/deps_tests.zig`, which greps `src/**/*.zig` and fails on any
other edge. `std`, `builtin` and `build_options` are always allowed. The graph is acyclic; `cmd/*` import
`cli/context.zig` (a leaf) and never `cli/cli.zig`, which is what removes the cmd<->cli cycle of design-B.

Dependency table (edges point at dependencies):

```
core/{reader,limits,diag,arch,sanitize,macho_extra,segments,fmt} -> (std only)
core/version -> fmt
core/loadcmds -> reader, diag, limits, version, macho_extra
core/fat -> reader, arch, diag, limits
core/file -> reader, fat, arch, limits, diag
core/image -> reader, loadcmds, segments, arch, diag, limits
macho/symbols -> image, reader, diag, limits, sanitize, version
macho/dyld_chained -> image, reader, diag, limits, macho_extra
macho/dyld_exports -> image, reader, diag, limits
macho/dyld_legacy -> image, reader, diag, limits
macho/function_starts -> image, reader, diag, limits
macho/fixups -> image, diag, limits, dyld_chained, dyld_legacy
macho/imports -> image, loadcmds, diag, limits, version, symbols, fixups, dyld_exports
codesign/asn1 -> limits
codesign/blobs -> image, reader, diag, limits, version, macho_extra
codesign/hashes -> image, diag, limits, blobs
codesign/requirements -> reader, diag, limits, sanitize
codesign/entitlements -> diag, limits, blobs, asn1, plist/plist, plist/xml
codesign/cms -> diag, limits, sanitize, asn1
darwin/security -> diag, sanitize, plist/plist
darwin/xattr -> diag, sanitize
darwin/dylib_resolve -> loadcmds, diag
objc/objc -> image, reader, diag, limits, sanitize, macho_extra, fixups, symbols
strings/strings -> image, reader, limits, diag, sanitize, macho_extra, fixups
analysis/entropy -> image, loadcmds
plist/plist -> diag, limits, sanitize
plist/bplist -> plist, reader, diag, limits
plist/xml -> plist, reader, diag, limits
bundle/bundle -> file, fat, image, reader, diag, limits, sanitize, plist/plist, plist/bplist, plist/xml, codesign/blobs, codesign/hashes
disasm/insn -> arch
disasm/capstone -> insn, arch
disasm/arm64 -> insn
disasm/x86len -> insn
disasm/functions -> image, limits, diag, symbols, function_starts, dyld_exports, objc, insn
disasm/symbolize -> image, limits, diag, sanitize, symbols, fixups, objc, strings, insn, functions
disasm/engine -> insn, capstone, arm64, x86len, functions, symbolize, image, arch, limits, diag
analysis/analysis -> file, image, limits, diag, every macho/*, codesign/*, darwin/*, objc, strings, entropy, disasm/{functions,symbolize,engine}
analysis/triage -> analysis, bundle, output/sink, output/json, output/text, limits, diag, (types of every module)
output/sink -> sanitize
output/json -> sink, diag, sanitize, file, image, fat, fmt
output/text -> sink, diag, sanitize, fmt
cli/args -> (std only)
cli/context -> limits, diag, file, image, arch, output/sink, cli/args
cli/cli -> args, context, output/*, core/*, analysis/analysis, cmd/*
cmd/<name> -> cli/context, output/*, analysis/analysis, analysis/triage (triage/report only), bundle (bundle/triage/report), plist/* (plist), darwin/* (quarantine/bundle/codesign/triage), the modules it renders
main -> root (machre), build_options
```

### 4.1 `macho/symbols.zig`

**Imports:** core/image, core/reader, core/diag, core/limits, core/sanitize, core/version.
**Rules:** `symoff + 16*nsyms` through `Reader.subClamped` (`symtab-nsyms-huge.bin` -> clamp + `count_clamped`);
`stroff/strsize` clamped (`symtab-stroff-past-eof.bin` -> empty strtab, every name "" and ONE `truncated`
diagnostic); `n_strx >= strsize` -> "" ; names cut at `max_symbol_name`; 32-bit `nlist` (12 B) for MH_MAGIC;
`n_type` read as a raw `u8` (std's packed union via `@bitCast`); `n_desc` as `u16` (`libraryOrdinal = n_desc >> 8`,
zig-api-notes 15.3). `counts` follow summary.json semantics (`defined` = N_SECT/N_ABS/N_INDR non-stab,
`external` = N_EXT, `local` = !N_EXT non-stab). `nmLetter` reproduces `nm(1)` letters using section classes.
**Verified oracle:** hello-c 12 total / 6 defined / 6 undefined / 0 stabs / 11 external / 1 local; hello-zig
428/325/103/0; `/bin/ls` arm64e `__DefaultRuneLocale` n_type 0x01 n_desc 0x0300 ordinal 3.

```zig
//! macho/symbols.zig — nlist table, string table, dysymtab ranges, indirect symbol table.
//! Imports: core/image, core/reader, core/diag, core/limits, core/sanitize, core/version.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const SymbolKind = enum { undefined, absolute, section, prebound, indirect, stab };

pub const Symbol = struct {
    index: u32,
    name: []const u8, // slice into the string table (never past strsize); "" when n_strx >= strsize (+ one diag)
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,

    pub fn isStab(s: Symbol) bool;
    pub fn isExternal(s: Symbol) bool;
    pub fn isPrivateExternal(s: Symbol) bool;
    pub fn kind(s: Symbol) SymbolKind;
    pub fn libraryOrdinal(s: Symbol) u8;
    pub fn isWeakRef(s: Symbol) bool;
    pub fn isWeakDef(s: Symbol) bool;
    pub fn referencedDynamically(s: Symbol) bool;
    /// nm letter: U T t D d S s A a I i C - (nm(1) semantics; needs section classes for T/D/S)
    pub fn nmLetter(s: Symbol, img: *const Image) u8;
};

pub const Counts = struct { defined: u32 = 0, undefined: u32 = 0, stabs: u32 = 0, external: u32 = 0, local: u32 = 0 };

pub const SymbolTable = struct {
    present: bool, // false when there is no LC_SYMTAB (result is `empty`)
    symbols: []const Symbol, // <= min(nsyms, limits.max_symbols, bytes available / entry size)
    nsyms_declared: u32,
    strtab: []const u8, // clamped view; may be shorter than strsize
    strsize_declared: u32,
    indirect: []const u32, // clamped
    nindirect_declared: u32,
    symtab: ?std.macho.symtab_command,
    dysymtab: ?std.macho.dysymtab_command,
    counts: Counts,
    truncated: bool,
    lossy_names: u32, // names that needed sanitisation

    pub const empty: SymbolTable = .{
        .present = false, .symbols = &.{}, .nsyms_declared = 0, .strtab = "", .strsize_declared = 0,
        .indirect = &.{}, .nindirect_declared = 0, .symtab = null, .dysymtab = null, .counts = .{},
        .truncated = false, .lossy_names = 0,
    };
    pub fn byName(t: *const SymbolTable, name: []const u8) ?*const Symbol;
    /// INDIRECT_SYMBOL_LOCAL / ABS (possibly OR'd) -> null; out of range -> null.
    pub fn indirectAt(t: *const SymbolTable, i: u32) ?u32;
    pub fn symbolAt(t: *const SymbolTable, i: u32) ?*const Symbol;
};

pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!SymbolTable;

/// Sorted-by-address index (symbol indices) of defined N_SECT/N_ABS non-stab symbols.
pub const AddressIndex = struct {
    order: []const u32,
    pub fn build(arena: Allocator, t: *const SymbolTable) Allocator.Error!AddressIndex;
    /// Exact match at `vmaddr` (external preferred over local).
    pub fn at(ix: *const AddressIndex, t: *const SymbolTable, vmaddr: u64) ?*const Symbol;
    /// Nearest symbol at or below `vmaddr` -> (symbol, delta).
    pub fn nearest(ix: *const AddressIndex, t: *const SymbolTable, vmaddr: u64) ?struct { sym: *const Symbol, delta: u64 };
};
```

### 4.2 `macho/dyld_chained.zig`

**Imports:** core/image, core/reader, core/diag, core/limits, core/macho_extra.
**Walk rules** (format-notes 4.1): `starts_offset/imports_offset/symbols_offset < payload.len` else `truncated`
+ empty result (`chained-fixups-absurd.bin`); `imports_count` clamped by `(payload.len - imports_offset) /
entry_size` and `max_imports`; `seg_count` clamped by `min(img.segments.len, (payload.len - starts_offset - 4)/4)`
(`chained-starts-segcount-huge.bin` -> `count_clamped`); per page the chain walk is bounded by `page_size/stride`
and `max_chain_steps_per_page` and must stay inside the page (`chain_broken`); `page_start & 0x8000` (MULTI)
walks `chain_starts[]` until `DYLD_CHAINED_PTR_START_LAST`; `symbols_format == 1` -> `std.compress.flate.Decompress`
(`.zlib`, `allocRemaining(arena, .limited(max_strtab))`). Rebase targets: fmt 2/1/10 = `target | high8<<56`;
fmt 6/9/12 and every arm64e auth rebase = `image_base + target`. Binds carry `import_index`; `addend` = import
addend + pointer addend. `decodePointer` is the format switch alone (used by symbolize/objc on single slots).
**Verified oracle:** hello-c header `{0,32,104,128,6,1,0}`, starts seg 2/3 page 16384 fmt 6, 6 binds
(`___snprintf_chk … _strcmp`) + 1 rebase `0x100008008 -> 0x100000668`; `/bin/ls` arm64e 23 rebases + 90 binds
(84 auth); TextEdit fmt 12 2259/559; Electron fmt 2 573785/7978.

```zig
//! macho/dyld_chained.zig — LC_DYLD_CHAINED_FIXUPS. Imports: core/image, core/reader, core/diag, core/limits, core/macho_extra.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const PointerFormat = enum(u16) {
    arm64e = 1, @"64" = 2, @"32" = 3, @"32_cache" = 4, @"32_firmware" = 5, @"64_offset" = 6, arm64e_kernel = 7,
    @"64_kernel_cache" = 8, arm64e_userland = 9, arm64e_firmware = 10, x86_64_kernel_cache = 11,
    arm64e_userland24 = 12, arm64e_shared_cache = 13, arm64e_segmented = 14, _,

    pub fn stride(f: PointerFormat) ?u8;
    pub fn is32(f: PointerFormat) bool;
};
pub const ImportFormat = enum(u32) { import = 1, import_addend = 2, import_addend64 = 3, _ };

pub const Import = struct { lib_ordinal: i32, weak: bool, name: []const u8, addend: i64, name_offset: u32 };
pub const SegmentStarts = struct {
    seg_index: u32, size: u32, page_size: u16, pointer_format: u16, segment_offset: u64,
    max_valid_pointer: u32, page_count: u16, page_starts: []const u16, // clamped
    chain_starts: []const u16, // MULTI (32-bit formats) only
};
pub const Header = struct { fixups_version: u32, starts_offset: u32, imports_offset: u32, symbols_offset: u32, imports_count: u32, imports_format: u32, symbols_format: u32 };

pub const Auth = struct { key: u2, diversity: u16, addr_div: bool };

pub const Fixup = struct {
    vmaddr: u64,
    file_offset: u64,
    seg_index: u16,
    raw: u64,
    kind: Kind,

    pub const Kind = union(enum) {
        rebase: struct { target: u64, auth: ?Auth, high8: u8 },
        bind: struct { import_index: u32, addend: i64, auth: ?Auth },
    };
};

pub const ChainedFixups = struct {
    header: Header,
    imports: []const Import,
    imports_declared: u32,
    symbols_compressed: bool,
    starts: []const SegmentStarts,
    seg_count_declared: u32,
    fixups: []const Fixup, // in walk order (segment, page, chain)
    truncated: bool,

    pub const empty: ChainedFixups = .{
        .header = .{ .fixups_version = 0, .starts_offset = 0, .imports_offset = 0, .symbols_offset = 0, .imports_count = 0, .imports_format = 0, .symbols_format = 0 },
        .imports = &.{}, .imports_declared = 0, .symbols_compressed = false, .starts = &.{}, .seg_count_declared = 0,
        .fixups = &.{}, .truncated = false,
    };
    /// "<bad ordinal N>" when out of range.
    pub fn importName(c: *const ChainedFixups, i: u32) []const u8;
    pub fn pointerFormat(c: *const ChainedFixups) ?PointerFormat;
};

/// Null when no LC_DYLD_CHAINED_FIXUPS. Walk rules in DESIGN.md §4.6 (format-notes 4.1).
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?ChainedFixups;
/// Decode one raw pointer without walking (symbolize/objc read slots directly). Null for unknown formats.
pub fn decodePointer(raw: u64, format: PointerFormat, image_base: u64) ?Fixup.Kind;
/// `next` field of a raw pointer in `format` (0 = end of chain).
pub fn nextOf(raw: u64, format: PointerFormat) ?u16;
```

### 4.3 `macho/dyld_exports.zig`

**Imports:** core/image, core/reader, core/diag, core/limits.
**Rules:** iterative DFS with an explicit `std.ArrayList(struct { node_off: u32, prefix_len: u32 })` stack and a
`std.DynamicBitSetUnmanaged` of visited node offsets (cycle guard); child offsets `< trie.len`; `max_trie_nodes`,
`max_trie_depth`; the accumulated name buffer is capped at `max_symbol_name`; a node's terminal bytes must end
inside the trie (`trie_malformed`). REEXPORT nodes carry the ordinal + import name; STUB_AND_RESOLVER both offsets.
**Verified oracle:** hello-c 5, libhello 4 (`_hello_add _hello_global _hello_mul _hello_print`), enumerateProcess 3,
`/bin/ls` 1, Electron 11158 (2673 weak).

```zig
//! macho/dyld_exports.zig — export trie (LC_DYLD_EXPORTS_TRIE or dyld_info.export_off), iterative walker.
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const ExportKind = enum(u2) { regular = 0, thread_local = 1, absolute = 2, _ };
pub const Reexport = struct { ordinal: u32, import_name: []const u8 };
pub const StubResolver = struct { stub: u64, resolver: u64 };
pub const Export = struct {
    name: []const u8,
    flags: u64,
    address: u64, // image_base + offset (0 for reexports)
    offset: u64,
    kind: ExportKind,
    weak: bool,
    reexport: ?Reexport,
    stub_resolver: ?StubResolver,
};
pub const ExportTrie = struct {
    source: enum { exports_trie, dyld_info },
    dataoff: u32,
    datasize: u32,
    exports: []const Export, // trie (DFS) order
    nodes_visited: u32,
    truncated: bool,
    pub const empty: ExportTrie = .{ .source = .exports_trie, .dataoff = 0, .datasize = 0, .exports = &.{}, .nodes_visited = 0, .truncated = false };
    pub fn byName(t: *const ExportTrie, name: []const u8) ?*const Export;
};
/// Null when neither LC_DYLD_EXPORTS_TRIE nor dyld_info export_off exists.
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?ExportTrie;
/// Walk an arbitrary trie payload (tests, nested).
pub fn parseBytes(arena: Allocator, trie: []const u8, image_base: u64, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ExportTrie;
```

### 4.4 `macho/dyld_legacy.zig`

**Imports:** core/image, core/reader, core/diag, core/limits.
**Rules:** each stream is a `Cursor` over `Image.linkeditReader(off, size)` (`dyldinfo-bind-past-eof.bin` ->
`truncated`, stream skipped); opcode loop bounded by stream length, `max_opcode_bytes` and `max_fixups`
(`DO_REBASE_ULEB_TIMES` count of 2^40 is clamped, not iterated); `seg_index >= segments.len` ->
`ordinal_out_of_range`, entry kept with `vmaddr = null`; `ADD_ADDR_ULEB` uses `takeUlebWrapping`;
`SET_ADDEND_SLEB` uses `takeSleb`; lazy stream continues past every `DONE`; `THREADED` sub-opcodes recorded in
`threaded` (ordinal table size capped). `stream_offset` of lazy entries is what `__stub_helper` pushes.
**Verified oracle:** legacy-bind 4 non-lazy binds `_puts _printf _malloc _free` + `___stack_chk_guard`, lazy
binds for the calls, `dyld_stub_binder` import; hello-zig rebase 40 B / bind 56 B / lazy 1776 B / export 72 B;
Burp stub 463/235/66.

```zig
//! macho/dyld_legacy.zig — LC_DYLD_INFO(_ONLY) rebase/bind/weak/lazy opcode streams (incl. THREADED).
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Rebase = struct { seg_index: u8, seg_offset: u64, vmaddr: ?u64, type: u8, stream_offset: u32 };
pub const BindKind = enum { bind, weak, lazy };
pub const Bind = struct {
    seg_index: u8, seg_offset: u64, vmaddr: ?u64, lib_ordinal: i32, symbol: []const u8, flags: u8, type: u8,
    addend: i64, kind: BindKind,
    /// Offset of this entry's first opcode in its stream (lazy: what __stub_helper's `pushq $off` refers to).
    stream_offset: u32,
};
pub const Threaded = struct { ordinal_table_size: u64, applies: u32 };
pub const DyldInfo = struct {
    cmd: std.macho.dyld_info_command,
    rebases: []const Rebase,
    binds: []const Bind, // all three kinds, stream order (bind, weak, lazy)
    threaded: ?Threaded,
    truncated: bool,
    counts: struct { rebase: u32, bind: u32, weak: u32, lazy: u32 },
    pub const empty: DyldInfo = .{
        .cmd = .{ .cmd = .DYLD_INFO, .cmdsize = 48, .rebase_off = 0, .rebase_size = 0, .bind_off = 0, .bind_size = 0, .weak_bind_off = 0, .weak_bind_size = 0, .lazy_bind_off = 0, .lazy_bind_size = 0, .export_off = 0, .export_size = 0 },
        .rebases = &.{}, .binds = &.{}, .threaded = null, .truncated = false, .counts = .{ .rebase = 0, .bind = 0, .weak = 0, .lazy = 0 },
    };
};
/// Null when no LC_DYLD_INFO(_ONLY).
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?DyldInfo;
pub const OpTrace = struct { offset: u32, opcode: u8, imm: u8, text: []const u8 };
/// Raw opcode trace of one stream (`dyld --opcodes`).
pub fn trace(arena: Allocator, stream: []const u8, kind: enum { rebase, bind }, limits: *const Limits) Allocator.Error![]const OpTrace;
```

### 4.5 `macho/function_starts.zig`

**Imports:** core/image, core/reader, core/diag, core/limits.
**Verified oracle:** hello-c `[0x1000004F8, 0x100000524, 0x10000060C]` (dataoff 49472 size 8); `/bin/ls` 50 per
slice, first `0x100000700 0x10000070C 0x10000071C 0x100000780`; `LC_DATA_IN_CODE` datasize 0 on every corpus
fixture (empty entries, present=true).

```zig
//! macho/function_starts.zig — LC_FUNCTION_STARTS uleb deltas + LC_DATA_IN_CODE entries.
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const FunctionStarts = struct { dataoff: u32, datasize: u32, addrs: []const u64, truncated: bool };
pub const DataInCode = struct { dataoff: u32, datasize: u32, entries: []const std.macho.data_in_code_entry, truncated: bool };

/// Null when no LC_FUNCTION_STARTS. Deltas via Cursor.takeUleb (Overflow -> stop + diag); zero delta terminates;
/// addresses outside __TEXT are dropped with one diagnostic. Result sorted ascending, deduped.
pub fn parseFunctionStarts(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?FunctionStarts;
/// Null when no LC_DATA_IN_CODE (datasize 0 is legal: empty entries).
pub fn parseDataInCode(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?DataInCode;
```

### 4.6 `macho/fixups.zig` — unified view + slot resolution

**Imports:** core/image, core/diag, core/limits, macho/dyld_chained, macho/dyld_legacy.
**Rules:** chained if present, else legacy, else `.none`. `resolveSlot(img, vmaddr)`: a bind fixup at `vmaddr`
-> `.bind`; a rebase -> `.rebase(target)`; no fixup -> `.raw(u64 & 0x0000_7fff_ffff_ffff)` (legacy images store
unslid vmaddrs directly; PAC/high bits stripped); unmapped -> null. objc/strings/symbolize never touch pointer
formats — this is the only place that knows them (A's "Pointer" abstraction under B's names).

```zig
//! macho/fixups.zig — unified rebase/bind table over chained or legacy dyld data + slot resolution.
//! Imports: core/image, core/diag, core/limits, macho/dyld_chained, macho/dyld_legacy.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const dyld_chained = @import("dyld_chained.zig");
const dyld_legacy = @import("dyld_legacy.zig");

pub const Source = enum { chained, legacy, none };
pub const FixupKind = enum { rebase, bind, lazy_bind, weak_bind };
pub const Fixup = struct {
    vmaddr: u64,
    kind: FixupKind,
    target: u64, // rebase target (0 for binds)
    symbol: []const u8, // bind symbol ("" for rebases)
    lib_ordinal: i32,
    addend: i64,
    weak_import: bool,
    auth: ?dyld_chained.Auth,
    section: ?u16,
    raw: ?u64,
};
/// What a pointer-sized slot means after dyld: a bound symbol, a rebased address, or the raw on-disk
/// value (legacy images store unslid vmaddrs directly; PAC/high bits stripped).
pub const Slot = union(enum) { bind: *const Fixup, rebase: u64, raw: u64 };

pub const FixupTable = struct {
    source: Source,
    fixups: []const Fixup, // sorted by vmaddr
    chained: ?dyld_chained.ChainedFixups,
    legacy: ?dyld_legacy.DyldInfo,
    pointer_format: ?dyld_chained.PointerFormat,
    counts: struct { rebases: u32, binds: u32, auth_binds: u32, lazy: u32, weak: u32 },
    truncated: bool,

    pub const empty: FixupTable = .{ .source = .none, .fixups = &.{}, .chained = null, .legacy = null, .pointer_format = null, .counts = .{ .rebases = 0, .binds = 0, .auth_binds = 0, .lazy = 0, .weak = 0 }, .truncated = false };
    /// Binary search by vmaddr.
    pub fn at(t: *const FixupTable, vmaddr: u64) ?*const Fixup;
    /// Resolve an 8-byte slot at `vmaddr` (null when unmapped).
    pub fn resolveSlot(t: *const FixupTable, img: *const Image, vmaddr: u64) ?Slot;
    /// Convenience: the address a slot points to after dyld, if it is a rebase/raw pointer.
    pub fn pointerAt(t: *const FixupTable, img: *const Image, vmaddr: u64) ?u64;
    pub fn bindName(t: *const FixupTable, vmaddr: u64) ?[]const u8;
};
/// Chained if present, else legacy, else `.none` (nlist-only imports are attributed by imports.zig).
pub fn build(arena: Allocator, img: *const Image, chained_in: ?*const dyld_chained.ChainedFixups, legacy_in: ?*const dyld_legacy.DyldInfo, limits: *const Limits, diags: *Diagnostics) Allocator.Error!FixupTable;
```

### 4.7 `macho/imports.zig`

**Imports:** core/image, core/loadcmds, core/diag, core/limits, core/version, macho/symbols, macho/fixups, macho/dyld_exports.
**Attribution:** chained/legacy bind ordinal n -> `dl[n-1]`; specials 0/-1/-2/-3 -> `ordinalName`; nlist-only
(no dyld info) -> `GET_LIBRARY_ORDINAL(n_desc)`. `short_name` follows `dyld_info` (`libSystem`, `libncurses.5`,
`Foundation`). Exports = trie when present else defined external N_SECT symbols (`from = .nlist`).
**Verified oracle:** hello-c 6 imports all libSystem; hello-usedylib `_hello_add _hello_mul _hello_global
_hello_print` from libhello (ordinal 1) + 2 rpaths; hello-objc 19; `/bin/ls` 90 (`_humanize_number` from libutil).

```zig
//! macho/imports.zig — import/export tables with dylib attribution.
//! Imports: core/image, core/loadcmds, core/diag, core/limits, core/version, macho/symbols, macho/fixups, macho/dyld_exports.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const SymbolTable = @import("symbols.zig").SymbolTable;
const FixupTable = @import("fixups.zig").FixupTable;
const ExportTrie = @import("dyld_exports.zig").ExportTrie;

pub const DylibRef = struct {
    ordinal: u16,
    cmd: u32,
    path: []const u8,
    short_name: []const u8, // dyld_info style: "libSystem", "Foundation"
    current_version: u32,
    compat_version: u32,
    timestamp: u32,
    weak: bool,
    reexport: bool,
    upward: bool,
    delayed_init: bool,
};
pub const ImportSource = enum { chained, legacy, nlist_only };
pub const ImportEntry = struct {
    symbol: []const u8,
    dylib: ?*const DylibRef,
    ordinal: i32, // raw; negative specials
    weak: bool,
    lazy: bool,
    locations: u32,
    first_location: ?u64,
    source: ImportSource,
};
pub const ImportTable = struct {
    dylibs: []const DylibRef,
    imports: []const ImportEntry, // deduped by (symbol, ordinal), first-appearance order
    truncated: bool,
    pub const empty: ImportTable = .{ .dylibs = &.{}, .imports = &.{}, .truncated = false };
};
pub const ExportFrom = enum { trie, nlist };
pub const ExportEntry = struct { name: []const u8, address: u64, weak: bool, kind: []const u8, reexport_from: ?[]const u8, from: ExportFrom };
pub const ExportTable = struct {
    exports: []const ExportEntry,
    truncated: bool,
    pub const empty: ExportTable = .{ .exports = &.{}, .truncated = false };
};

pub fn dylibs(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const DylibRef;
pub fn rpaths(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const []const u8;
/// Attribution: chained/legacy bind ordinal -> dl[ordinal-1]; nlist-only -> GET_LIBRARY_ORDINAL(n_desc).
pub fn imports(arena: Allocator, img: *const Image, syms: *const SymbolTable, fix: *const FixupTable, dl: []const DylibRef, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ImportTable;
pub fn exports(arena: Allocator, img: *const Image, syms: *const SymbolTable, trie: ?*const ExportTrie, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ExportTable;
/// "self", "main-executable", "flat-namespace", "weak-lookup", short name, or "<bad ordinal N>".
pub fn ordinalName(buf: *[32]u8, ordinal: i32, dl: []const DylibRef) []const u8;
```

### 4.8 `codesign/asn1.zig` — shared BER/DER (graft from C)

**Imports:** core/limits. Used by both `cms.zig` (BER with `0x80` indefinite lengths — Apple platform CMS) and
`entitlements.zig` (strict DER). `Walker` is an explicit-stack pre-order iterator bounded by
`max_asn1_depth`/`max_asn1_nodes`; `read` validates every length against the buffer (`BadLength`/`Truncated`).

```zig
//! codesign/asn1.zig — BER/DER TLV reader shared by cms.zig and entitlements.zig (indefinite lengths,
//! long forms, OID printing, explicit-stack Walker). Imports: core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;

pub const Class = enum(u2) { universal, application, context, private };
pub const Tlv = struct { class: Class, constructed: bool, tag: u32, indefinite: bool, header_len: usize, content: []const u8, total_len: usize };
pub const Error = error{ Truncated, BadLength, TooDeep, TooMany };

/// Handles 0x80 indefinite (content up to the 00 00 end-of-contents pair) and 0x81..0x84 long forms.
pub fn read(bytes: []const u8, off: usize) Error!Tlv;
pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(it: *Iterator) Error!?Tlv;
};
pub fn children(t: Tlv) Iterator;
/// "1.2.840.113635.100.6.1.13"
pub fn oidString(arena: Allocator, content: []const u8) Allocator.Error![]const u8;
pub fn oidEquals(content: []const u8, dotted: []const u8) bool;
pub fn readInteger(content: []const u8) ?i64;
/// UTCTime (0x17) / GeneralizedTime (0x18) -> unix seconds.
pub fn readTime(t: Tlv) ?i64;
pub const Node = struct { depth: u8, tlv: Tlv, offset: usize };
/// Pre-order walk with an explicit stack; depth <= limits.max_asn1_depth, nodes <= limits.max_asn1_nodes.
pub const Walker = struct {
    bytes: []const u8,
    limits: *const Limits,
    stack: [64]Frame = undefined,
    depth: u8 = 0,
    nodes: u32 = 0,
    pub const Frame = struct { end: usize, pos: usize };
    pub fn init(bytes: []const u8, limits: *const Limits) Walker;
    pub fn next(w: *Walker) Error!?Node;
};
```

### 4.9 `codesign/blobs.zig`

**Imports:** core/image, core/reader, core/diag, core/limits, core/version, core/macho_extra.
**Rules:** all fields big-endian via `Reader.u32At(.., .big)`; every blob offset/length validated against the
SuperBlob length and the LC datasize (`blob_malformed`); CD fields read only up to the version's end marker
(0x20100 scatter, 0x20200 team, 0x20300 codeLimit64, 0x20400 execSeg, 0x20500 runtime, 0x20600 linkage);
`hashOffset - n_special*hash_size` underflow -> `blob_malformed`; hash slots clamped by blob length and
`max_code_slots`/`max_special_slots`; cdhash = `hash_type(blob[0..length])` truncated to 20. Slot 0 and
`0x1000..0x1004` all parsed; `best` = sha256 > sha384 > sha256_truncated > sha1 (codesign's `CDHash=`).
**Verified oracle:** hello-c CD v0x20400 flags 0x20002 hashes 13+0 page 4096 codeLimit 49888 cdhash
`f865cf1c…5b`; hello-entitled 3 blobs? no: 5 slots (CD, requirements, entitlements 0xfade7171 514 B, DER 0xfade7172
249 B, CMS wrapper 8 B), nSpecial 7, page 16384; `/bin/ls` CD size 741 platform 26 CMS 4450 B; Sketch dual CD
(sha1 slot 0 + sha256 slot 0x1000).

```zig
//! codesign/blobs.zig — SuperBlob, slot table, CodeDirectory (v0x20100..0x20600), cdhash, special slots.
//! Imports: core/image, core/reader, core/diag, core/limits, core/version, core/macho_extra.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Reader = @import("../core/reader.zig").Reader;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const BlobRef = struct { slot: u32, offset: u32, magic: u32, length: u32, bytes: []const u8, truncated: bool };
pub const HashType = enum(u8) { sha1 = 1, sha256 = 2, sha256_truncated = 3, sha384 = 4, _ };
pub const ExecSeg = struct { base: u64, limit: u64, flags: u64 };
pub const Linkage = struct { hash_type: u8, app_type: u8, app_subtype: u16, offset: u32, size: u32 };

pub const CodeDirectory = struct {
    slot: u32, // 0 or CSSLOT_ALTERNATE_CODEDIRECTORIES + n
    blob: []const u8,
    version: u32,
    flags: u32,
    hash_offset: u32,
    ident_offset: u32,
    n_special_slots: u32,
    n_code_slots: u32,
    code_limit: u64, // codeLimit64 when set
    hash_size: u8,
    hash_type: HashType,
    platform: u8,
    page_size_log2: u8,
    scatter_offset: ?u32,
    team_offset: ?u32,
    exec_seg: ?ExecSeg,
    runtime: ?u32,
    pre_encrypt_offset: ?u32,
    linkage: ?Linkage,
    identifier: []const u8,
    team_id: ?[]const u8,
    cdhash: [20]u8,
    cdhash_full: []const u8, // hash_size bytes, arena
    /// code_hashes[i] = slot i; special_hashes[k] = slot -(k+1); each hash_size bytes; clamped.
    code_hashes: []const []const u8,
    special_hashes: []const []const u8,
    hashes_truncated: bool,

    pub fn pageSize(cd: *const CodeDirectory) u64;
    /// All-zero special slot == not bound (codesign: "Info.plist=not bound").
    pub fn isSpecialSlotBound(cd: *const CodeDirectory, n: u32) bool;
    pub fn isAdhoc(cd: *const CodeDirectory) bool;
    pub fn isLinkerSigned(cd: *const CodeDirectory) bool;
    pub fn hasHardenedRuntime(cd: *const CodeDirectory) bool;
};

pub const Signature = struct {
    dataoff: u32,
    datasize: u32,
    superblob_magic: u32,
    superblob_length: u32,
    count_declared: u32,
    blobs: []const BlobRef,
    /// slot 0 first, then 0x1000..0x1004 in slot order.
    code_directories: []const CodeDirectory,
    /// Index into code_directories of the CD codesign presents as "the" CDHash (sha256 > sha384 > sha1).
    best: ?u8,
    requirements: ?[]const u8,
    entitlements_xml: ?[]const u8,
    entitlements_der: ?[]const u8,
    cms: ?[]const u8,
    ticket: ?[]const u8,
    launch_constraints: [4]?[]const u8, // slots 8..11
    truncated: bool,

    pub fn cd(s: *const Signature) ?*const CodeDirectory;
    pub fn blob(s: *const Signature, slot: u32) ?*const BlobRef;
};

/// Null when no LC_CODE_SIGNATURE.
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Signature;
/// Parse a SuperBlob from bytes (nested code, detached signatures, tests). `dataoff`/`datasize` are recorded only.
pub fn parseSuperBlob(arena: Allocator, r: Reader, dataoff: u32, datasize: u32, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Signature;
pub fn parseCodeDirectory(arena: Allocator, slot: u32, blob: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?CodeDirectory;
/// hash_type(whole CD blob); returns the digest length written into `out` (null for unknown hash types).
pub fn cdhashOf(hash_type: HashType, cd_blob: []const u8, out: *[48]u8) ?u8;
```

### 4.10 `codesign/hashes.zig`

**Imports:** core/image, core/diag, core/limits, codesign/blobs.
**Rules:** code slot k = `hash(file[k*2^page .. min((k+1)*2^page, code_limit))` over the slice bytes; special slots
-2 requirements, -5 XML entitlements, -7 DER entitlements, -8..-11 launch constraints from sibling blobs;
-1 Info.plist / -3 CodeResources are filled by `bundle.zig` via `verifySpecialSlot`. `code_limit > slice` ->
`code_limit_within_slice=false` and only the covered pages are checked.
**Verified oracle:** every signed fixture all pages OK; `fake-upx` >= 1 mismatch (codesign: "invalid signature");
hello-entitled slots -2/-5/-7 match.

```zig
//! codesign/hashes.zig — recompute code-page and special-slot hashes and compare.
//! Imports: core/image, core/diag, core/limits, codesign/blobs.
const std = @import("std");
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const blobs = @import("blobs.zig");

pub const SpecialCheck = struct { requirements: ?bool, entitlements_xml: ?bool, entitlements_der: ?bool, info_plist: ?bool, resources: ?bool, launch_constraints: ?bool };
pub const Verification = struct {
    pages_checked: u32,
    pages_ok: u32,
    mismatches: u32,
    first_bad_page: ?u32,
    special: SpecialCheck,
    special_mismatches: u32,
    code_limit_within_slice: bool,
    hash_type_supported: bool,
    pub fn ok(v: Verification) bool;
};
/// Recomputes every code slot over `img.r.bytes[0..code_limit]` with the CD's hash type and compares; also hashes the
/// requirements/entitlements(XML,DER)/launch-constraint blobs against special slots -2/-5/-7/-8..; Info.plist/CodeResources
/// (slots -1/-3) are filled in by bundle.zig via `verifySpecialSlot`.
pub fn verify(img: *const Image, sig: *const blobs.Signature, cd: *const blobs.CodeDirectory, limits: *const Limits, diags: *Diagnostics) Verification;
/// Hash `bytes` with the CD's hash type and compare with special slot `n` (1-based; -n in codesign terms).
pub fn verifySpecialSlot(cd: *const blobs.CodeDirectory, n: u32, bytes: []const u8) ?bool;
pub fn hashBytes(hash_type: blobs.HashType, bytes: []const u8, out: *[48]u8) ?u8;
```

### 4.11 `codesign/requirements.zig`

**Imports:** core/reader, core/diag, core/limits, core/sanitize.
**Rules:** two-pass, stack-based (graft from C): pass 1 builds a flat post-order node array (opcode, operand
slices, child indices) bounded by `max_requirement_ops`/`max_requirement_depth`, opcode flags masked with
`0x00ffffff`; pass 2 prints with codesign precedence — flat `and` chains, parenthesised `or`, strings quoted only
when not identifier-like, `leaf`/`root`/`certificate N`, match operations, `/* exists */`, OID data as dotted
strings (format-notes 5).
**Verified oracle:** `/bin/ls` 40-byte blob -> `identifier "com.apple.ls" and anchor apple`; Claude's 172-byte DR
text; Burp `always`; ad-hoc fixtures -> synthesized `cdhash H"…"`.

```zig
//! codesign/requirements.zig — CSMAGIC_REQUIREMENTS set + expression pretty-printer (codesign -d -r- text).
//! Imports: core/reader, core/diag, core/limits, core/sanitize.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const RequirementType = enum(u32) { host = 1, guest = 2, designated = 3, library = 4, plugin = 5, _ };
pub const Requirement = struct { type: RequirementType, text: []const u8, raw: []const u8, ops: u32, truncated: bool };
pub const RequirementSet = struct {
    requirements: []const Requirement,
    pub fn designated(s: *const RequirementSet) ?*const Requirement;
};
pub fn parseSet(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!RequirementSet;
/// Two-pass, stack-based: pass 1 builds a flat post-order node array (op, operands, children) bounded by
/// limits.max_requirement_ops/depth; pass 2 emits text with codesign precedence (flat `and`, parenthesised `or`,
/// quoting only non-identifier strings, `leaf`/`root`/`certificate N`, match ops, `/* exists */`).
pub fn prettyPrint(arena: Allocator, expr_blob: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const u8;
/// `cdhash H"<hex>"` — what codesign synthesises when there is no requirements blob.
pub fn synthesizedDesignated(arena: Allocator, cdhash: [20]u8) Allocator.Error![]const u8;
/// `cdhash H"a" or cdhash H"b"` for universal ad-hoc signatures.
pub fn synthesizedDesignatedMulti(arena: Allocator, cdhashes: []const [20]u8) Allocator.Error![]const u8;
```

### 4.12 `codesign/entitlements.zig`

**Imports:** core/diag, core/limits, codesign/blobs, codesign/asn1, plist/plist, plist/xml.
**Rules:** XML blob body is the plist text (`plist/xml`); DER grammar `[APPLICATION 16]{ INTEGER 1, [CONTEXT 16]
SET OF SEQUENCE{ UTF8String key, Value } }` with Value = BOOLEAN | INTEGER | UTF8String | OCTET STRING | SEQUENCE |
[CONTEXT 16] dict (format-notes 5) via `asn1.Walker`; indefinite lengths rejected (`der_malformed`);
`disagreement` = keys or values differ between XML and DER (triage `ent.xml_der_mismatch`). `dangerous` table
(key, why, weight): `com.apple.security.cs.disable-library-validation`, `...allow-jit`,
`...allow-unsigned-executable-memory`, `...allow-dyld-environment-variables`, `...get-task-allow`,
`...debugger`, `com.apple.private.*`.
**Verified oracle:** hello-entitled 5 keys, both blobs, DER == XML (`disagreement=false`).

```zig
//! codesign/entitlements.zig — XML (via plist/xml) and DER (via asn1) entitlements.
//! Imports: core/diag, core/limits, codesign/blobs, codesign/asn1, plist/plist, plist/xml.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const Signature = @import("blobs.zig").Signature;
const plist = @import("../plist/plist.zig");

pub const EntSource = enum { xml, der, both, none };
pub const Entitlements = struct {
    source: EntSource,
    xml: ?plist.Value,
    der: ?plist.Value,
    keys: []const []const u8, // union, sorted
    xml_raw: ?[]const u8,
    der_len: u32,
    disagreement: bool, // XML and DER differ in keys or values -> triage tell

    pub const empty: Entitlements = .{ .source = .none, .xml = null, .der = null, .keys = &.{}, .xml_raw = null, .der_len = 0, .disagreement = false };
    pub fn get(e: *const Entitlements, key: []const u8) ?plist.Value;
    pub fn isTrue(e: *const Entitlements, key: []const u8) bool;
};
pub fn parse(arena: Allocator, sig: *const Signature, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Entitlements;
/// DER grammar (format-notes 5): [APPLICATION 16]{ INTEGER 1, [CONTEXT 16] SET OF SEQUENCE{ UTF8String key, Value } }.
pub fn parseDer(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?plist.Value;
pub const Danger = struct { key: []const u8, why: []const u8, weight: u8 };
/// Table of dangerous keys with explanations (triage `ent.*` rules read it).
pub const dangerous: []const Danger = &.{};
pub fn isDangerous(key: []const u8) ?*const Danger;
```

### 4.13 `codesign/cms.zig`

**Imports:** core/diag, core/limits, core/sanitize, codesign/asn1.
**Rules:** walk every constructed TLV (tags 0x30/0x31/0xa0/0xa3); a definite-length SEQUENCE whose children are
SEQUENCE, SEQUENCE, BIT STRING is a Certificate; TBS = [0] version?, INTEGER serial, SEQUENCE sigalg, SEQUENCE
issuer, SEQUENCE validity, SEQUENCE subject, ..., [3] extensions (marker OIDs come from extension OIDs);
Name = SEQUENCE OF SET OF SEQUENCE{OID, value} with CN 2.5.4.3, OU 2.5.4.11, O 2.5.4.10, C 2.5.4.6, UID
0.9.2342.19200300.100.1.1; chain = leaf (issuer != subject and not an issuer of another) -> root; signingTime
1.2.840.113549.1.9.5 in signed attributes; RFC3161 token presence in unsigned attributes. Certificate count
capped by `max_cms_certs`. `offlineTrust`: platform if `cd_platform != 0` or marker .6.22; app_store .6.1.9;
developer_id .6.1.13; other_certificate when a chain exists; adhoc when `CS_ADHOC` and no chain; unsigned when
no CD.
**Verified oracle:** `/bin/ls` -> `Software Signing / Apple Code Signing Certification Authority / Apple Root CA`;
Claude -> `Developer ID Application: Anthropic PBC (Q6L2SF6YDW) / Developer ID Certification Authority / Apple Root CA`.

```zig
//! codesign/cms.zig — CMS SignedData walker: certificate chain names, marker OIDs, signing time.
//! Imports: core/diag, core/limits, core/sanitize, codesign/asn1.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const CertName = struct { cn: ?[]const u8, ou: ?[]const u8, o: ?[]const u8, c: ?[]const u8, uid: ?[]const u8 };
pub const Certificate = struct {
    subject: CertName,
    issuer: CertName,
    serial_hex: []const u8,
    not_before: ?i64,
    not_after: ?i64,
    is_self_signed: bool,
    sha256: [32]u8,
    der: []const u8,
    /// Apple marker OIDs present as extensions: 1.2.840.113635.100.6.1.13 Developer ID Application,
    /// .6.1.9 Mac App Store, .6.1.14 Developer ID Installer, .6.2.6 Developer ID CA, .6.1.12 Mac Developer,
    /// .6.22 Apple Software Signing.
    marker_oids: []const []const u8,
};
pub const Cms = struct {
    certificates: []const Certificate,
    chain: []const u32, // leaf -> root indices (codesign Authority= order)
    signing_time: ?i64,
    has_timestamp_token: bool,
    digest_algorithm: ?[]const u8,
    signer_count: u32,
    ber_indefinite: bool,
    truncated: bool,
    pub const empty: Cms = .{ .certificates = &.{}, .chain = &.{}, .signing_time = null, .has_timestamp_token = false, .digest_algorithm = null, .signer_count = 0, .ber_indefinite = false, .truncated = false };
    pub fn leaf(c: *const Cms) ?*const Certificate;
    pub fn authorityNames(c: *const Cms, arena: Allocator) Allocator.Error![]const []const u8;
    pub fn hasMarker(c: *const Cms, oid: []const u8) bool;
};
pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Cms;
/// Offline (unverified) trust-ladder approximation from the leaf certificate's marker OIDs; used when
/// Security.framework is unavailable and always labelled "(offline, unverified)".
pub const OfflineTrust = enum { platform, app_store, developer_id, other_certificate, adhoc, unsigned, unknown };
pub fn offlineTrust(c: ?*const Cms, cd_flags: u32, cd_platform: u8) OfflineTrust;
```

### 4.14 `darwin/security.zig`

**Imports:** core/diag, core/sanitize, plist/plist (the DAG entry now matches the prose: `Value` is built from the
`kSecCodeInfoEntitlementsDict` CFDictionary). Externs are listed in §8; the whole body of every pub fn is inside
`if (build_options.have_security)`, so the `-Dsecurity=false` binary references no framework symbol (verified:
links only libSystem).
**Ladder** (zig-api-notes 15.11 matrix): `SecStaticCodeCreateWithPath` (isDirectory=1 for bundles) ->
`SecStaticCodeCheckValidity(kSecCSCheckAllArchitectures | [kSecCSEnforceRevocationChecks])`; validity
`errSecCSUnsigned` -> unsigned; `errSecCSSignatureFailed/Invalid` -> invalid; `errSecCSRevokedNotarization`,
`errSecCertificateRevoked`, `CSSMERR_TP_CERT_REVOKED` -> revoked; then requirements: `anchor apple` == 0 ->
platform; App Store leaf OID 6.1.9 == 0 -> app_store; Developer ID 6.1.13 == 0 and `notarized` == 0 ->
developer_id_notarized; 6.1.13 only -> developer_id; `anchor apple generic` == 0 -> other_certificate; else
adhoc. `--no-network` -> `kSecCSNoNetworkAccess` and no revocation flag (`revocation_checked=false`).
`SecCodeCopySigningInformation(kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSContentInformation)`;
every CF value type-checked with `CFGetTypeID`; certificate array elements checked against
`SecCertificateGetTypeID()` before `SecCertificateCopySubjectSummary` (the crash found by the critic probe).
**Verified oracle:** hello-adhoc/entitled/Hello.app -> 0 + adhoc; hello-fat/x86_64/unsigned -> -67062;
fake-upx -> -67061; `/bin/ls` -> platform; Discord.app -> developer_id_notarized; Sketch.app -> app_store.

```zig
//! darwin/security.zig — Security.framework / CoreFoundation externs (DESIGN.md §8) + trust ladder.
//! Whole bodies gated on build_options.have_security. Imports: core/diag, core/sanitize, plist/plist.
const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const plist = @import("../plist/plist.zig");

pub const available: bool = build_options.have_security;

pub const Trust = enum { platform, app_store, developer_id_notarized, developer_id, other_certificate, adhoc, unsigned, invalid, revoked, unavailable };
pub const RequirementResults = struct { anchor_apple: i32, apple_generic: i32, developer_id: i32, app_store: i32, notarized: i32 };
pub const Verdict = struct {
    available: bool, // false when compiled without Security or --no-security
    reason: ?[]const u8, // why unavailable
    evaluated_path: []const u8, // what Security actually evaluated (bundle promotion)
    create_status: i32,
    validity_status: i32,
    validity_status_name: []const u8,
    revocation_checked: bool,
    network_used: bool,
    requirement_results: RequirementResults,
    trust: Trust,
    identifier: ?[]const u8,
    team_id: ?[]const u8,
    format: ?[]const u8,
    flags: ?u32,
    platform_identifier: ?u32,
    runtime_version: ?u32,
    cdhash: ?[20]u8,
    cdhashes: []const []const u8,
    digest_algorithms: []const u32,
    signing_time: ?i64,
    secure_timestamp: ?i64,
    certificate_chain: []const []const u8, // subject summaries leaf -> root
    designated_requirement: ?[]const u8,
    main_executable: ?[]const u8,
    has_stapled_ticket: bool,
    ticket_len: u32,
    entitlements: ?plist.Value,
    elapsed_ms: u32,
};
pub const Options = struct { revocation: bool = true, network: bool = true, all_archs: bool = true, is_directory: bool = false, content_info: bool = true };

/// Returns `.available=false, .trust=.unavailable` when !build_options.have_security.
pub fn evaluate(arena: Allocator, path_z: [:0]const u8, opts: Options, diags: *Diagnostics) Allocator.Error!Verdict;
pub fn unavailable(reason: []const u8, path: []const u8) Verdict;
/// 83 errSecCS* names + errSecCertificateRevoked + CSSMERR_TP_CERT_REVOKED; "OSStatus(N)" otherwise.
pub fn statusName(status: i32) []const u8;
pub fn trustName(t: Trust) []const u8;
/// Human sentence for the trust ladder line ("ad hoc (linker-signed) -- integrity only, not identity").
pub fn trustSentence(v: *const Verdict, cd_flags: ?u32) []const u8;

// ---- externs (only referenced inside `if (build_options.have_security)` bodies) ----
const CFTypeRef = ?*const anyopaque;
const CFAllocatorRef = ?*const anyopaque;
const CFStringRef = ?*const anyopaque;
const CFURLRef = ?*const anyopaque;
const CFDictionaryRef = ?*const anyopaque;
const CFArrayRef = ?*const anyopaque;
const CFDataRef = ?*const anyopaque;
const CFDateRef = ?*const anyopaque;
const CFErrorRef = ?*const anyopaque;
const CFNumberRef = ?*const anyopaque;
const CFBooleanRef = ?*const anyopaque;
const SecStaticCodeRef = ?*const anyopaque;
const SecRequirementRef = ?*const anyopaque;
const SecCertificateRef = ?*const anyopaque;
const CFIndex = c_long;
const CFTypeID = c_ulong;
const Boolean = u8;
const OSStatus = i32;
const SecCSFlags = u32;
const CFStringEncoding = u32;
const CFNumberType = CFIndex;
const CFAbsoluteTime = f64;
const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
const kCFNumberSInt64Type: CFNumberType = 4;
const kCFAbsoluteTimeIntervalSince1970: f64 = 978307200.0;
const kSecCSDefaultFlags: SecCSFlags = 0;
const kSecCSConsiderExpiration: SecCSFlags = 1 << 31;
const kSecCSEnforceRevocationChecks: SecCSFlags = 1 << 30;
const kSecCSNoNetworkAccess: SecCSFlags = 1 << 29;
const kSecCSCheckAllArchitectures: SecCSFlags = 1 << 0;
const kSecCSDoNotValidateExecutable: SecCSFlags = 1 << 1;
const kSecCSDoNotValidateResources: SecCSFlags = 1 << 2;
const kSecCSCheckNestedCode: SecCSFlags = 1 << 3;
const kSecCSStrictValidate: SecCSFlags = 1 << 4;
const kSecCSInternalInformation: SecCSFlags = 1 << 0;
const kSecCSSigningInformation: SecCSFlags = 1 << 1;
const kSecCSRequirementInformation: SecCSFlags = 1 << 2;
const kSecCSDynamicInformation: SecCSFlags = 1 << 3;
const kSecCSContentInformation: SecCSFlags = 1 << 4;
const errSecSuccess: OSStatus = 0;
const errSecCSUnsigned: OSStatus = -67062;
const errSecCSSignatureFailed: OSStatus = -67061;
const errSecCSSignatureInvalid: OSStatus = -67045;
const errSecCSReqFailed: OSStatus = -67050;
const errSecCSBadResource: OSStatus = -67054;
const errSecCSUnsignedNestedCode: OSStatus = -67022;
const errSecCSRevokedNotarization: OSStatus = -66992;
const errSecCertificateRevoked: OSStatus = -67820;
const CSSMERR_TP_CERT_REVOKED: OSStatus = -2147409652;
extern fn CFURLCreateFromFileSystemRepresentation(allocator: CFAllocatorRef, buffer: [*]const u8, bufLen: CFIndex, isDirectory: Boolean) CFURLRef;
extern fn CFURLGetFileSystemRepresentation(url: CFURLRef, resolveAgainstBase: Boolean, buffer: [*]u8, maxBufLen: CFIndex) Boolean;
extern fn CFStringCreateWithCString(alloc: CFAllocatorRef, cStr: [*:0]const u8, encoding: CFStringEncoding) CFStringRef;
extern fn CFRelease(cf: CFTypeRef) void;
extern fn CFGetTypeID(cf: CFTypeRef) CFTypeID;
extern fn CFStringGetTypeID() CFTypeID;
extern fn CFNumberGetTypeID() CFTypeID;
extern fn CFDateGetTypeID() CFTypeID;
extern fn CFDataGetTypeID() CFTypeID;
extern fn CFArrayGetTypeID() CFTypeID;
extern fn CFDictionaryGetTypeID() CFTypeID;
extern fn CFBooleanGetTypeID() CFTypeID;
extern fn CFBooleanGetValue(b: CFBooleanRef) Boolean;
extern fn CFStringGetLength(theString: CFStringRef) CFIndex;
extern fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: CFStringEncoding) CFIndex;
extern fn CFStringGetCString(theString: CFStringRef, buffer: [*]u8, bufferSize: CFIndex, encoding: CFStringEncoding) Boolean;
extern fn CFDictionaryGetValue(theDict: CFDictionaryRef, key: ?*const anyopaque) ?*const anyopaque;
extern fn CFDictionaryGetCount(theDict: CFDictionaryRef) CFIndex;
extern fn CFDictionaryGetKeysAndValues(theDict: CFDictionaryRef, keys: ?[*]?*const anyopaque, values: ?[*]?*const anyopaque) void;
extern fn CFNumberGetValue(number: CFNumberRef, theType: CFNumberType, valuePtr: *anyopaque) Boolean;
extern fn CFArrayGetCount(theArray: CFArrayRef) CFIndex;
extern fn CFArrayGetValueAtIndex(theArray: CFArrayRef, idx: CFIndex) ?*const anyopaque;
extern fn CFDateGetAbsoluteTime(theDate: CFDateRef) CFAbsoluteTime;
extern fn CFDataGetLength(theData: CFDataRef) CFIndex;
extern fn CFDataGetBytePtr(theData: CFDataRef) [*]const u8;
extern fn CFErrorCopyDescription(err: CFErrorRef) CFStringRef;
extern fn CFErrorGetCode(err: CFErrorRef) CFIndex;
extern fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: SecCSFlags, staticCode: *SecStaticCodeRef) OSStatus;
extern fn SecStaticCodeCheckValidity(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef) OSStatus;
extern fn SecStaticCodeCheckValidityWithErrors(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef, errors: *CFErrorRef) OSStatus;
extern fn SecRequirementCreateWithString(text: CFStringRef, flags: SecCSFlags, requirement: *SecRequirementRef) OSStatus;
extern fn SecRequirementCopyString(requirement: SecRequirementRef, flags: SecCSFlags, text: *CFStringRef) OSStatus;
extern fn SecCodeCopySigningInformation(code: SecStaticCodeRef, flags: SecCSFlags, information: *CFDictionaryRef) OSStatus;
extern fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) CFStringRef;
extern fn SecCertificateGetTypeID() CFTypeID;
extern const kSecCodeInfoIdentifier: CFStringRef;
extern const kSecCodeInfoTeamIdentifier: CFStringRef;
extern const kSecCodeInfoFlags: CFStringRef;
extern const kSecCodeInfoFormat: CFStringRef;
extern const kSecCodeInfoCertificates: CFStringRef;
extern const kSecCodeInfoTime: CFStringRef;
extern const kSecCodeInfoTimestamp: CFStringRef;
extern const kSecCodeInfoCdHashes: CFStringRef;
extern const kSecCodeInfoUnique: CFStringRef;
extern const kSecCodeInfoDigestAlgorithms: CFStringRef;
extern const kSecCodeInfoRuntimeVersion: CFStringRef;
extern const kSecCodeInfoEntitlementsDict: CFStringRef;
extern const kSecCodeInfoDesignatedRequirement: CFStringRef;
extern const kSecCodeInfoStapledNotarizationTicket: CFStringRef;
extern const kSecCodeInfoMainExecutable: CFStringRef;
extern const kSecCodeInfoPlatformIdentifier: CFStringRef;
```

### 4.15 `darwin/xattr.zig`

**Imports:** core/diag, core/sanitize. `listxattr(path, null, 0, 0)` then names; `getxattr` for
`com.apple.quarantine` (ENOATTR -> null); quarantine = `flags;hex-time;agent;uuid` (well_formed=false keeps `raw`);
translocation = path contains `/AppTranslocation/`. Off-macOS every fn returns `Xattrs.empty`.
**Verified oracle:** hello-quarantined `0083;68c3a1b2;Safari;9B2E1C3A-…` -> flags 0x83, 2025-09-12T04:29:38Z.

```zig
//! darwin/xattr.zig — getxattr/listxattr, com.apple.quarantine parsing, AppTranslocation detection.
//! Externs gated on builtin.os.tag == .macos. Imports: core/diag, core/sanitize.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Quarantine = struct { raw: []const u8, flags: ?u16, timestamp: ?i64, agent: ?[]const u8, uuid: ?[]const u8, well_formed: bool };
pub const Xattrs = struct {
    available: bool, // false off-macOS
    names: []const []const u8,
    quarantine: ?Quarantine,
    is_translocated: bool,
    provenance_present: bool, // com.apple.provenance
    pub const empty: Xattrs = .{ .available = false, .names = &.{}, .quarantine = null, .is_translocated = false, .provenance_present = false };
};
/// listxattr + getxattr; ENOATTR -> null quarantine; other errno -> os_error diagnostic.
pub fn read(arena: Allocator, path_z: [:0]const u8, diags: *Diagnostics) Allocator.Error!Xattrs;
/// Pure: "flags;hex-time;agent;uuid".
pub fn parseQuarantine(arena: Allocator, raw: []const u8) Allocator.Error!Quarantine;
/// Pure: contains "/AppTranslocation/".
pub fn isTranslocatedPath(path: []const u8) bool;
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?[*]u8, size: usize, position: u32, options: c_int) isize;
extern "c" fn listxattr(path: [*:0]const u8, namebuf: ?[*]u8, size: usize, options: c_int) isize;
const XATTR_NOFOLLOW: c_int = 0x0001;
```

### 4.16 `darwin/dylib_resolve.zig`

**Imports:** core/loadcmds (Dylib), core/diag. Order: expand `@executable_path`/`@loader_path`; `@rpath/x` against
every LC_RPATH in order (`unresolvable_rpath` when none resolves); absolute path -> `Io.Dir.access` on disk, else
`_dyld_shared_cache_contains_path` -> `shared_cache`; else `missing` (`weak_missing` for LC_LOAD_WEAK_DYLIB).
Triage flags `deps.missing_dylib` only for `missing` (never for cache-resident system dylibs).
**Verified oracle:** `/usr/lib/libSystem.B.dylib` -> shared_cache; `@rpath/libhello.dylib` -> on_disk
(via_rpath `@executable_path`) for the bare hello-usedylib, because the shipped corpus keeps
`tests/corpus/libhello.dylib` next to it and the fixture's first LC_RPATH is `@executable_path`; on_disk inside
Hello.app too; `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib` -> on_disk. (Corrected at integration: the
earlier "missing for the bare hello-usedylib" contradicted the ALGORITHM above on this corpus.)

```zig
//! darwin/dylib_resolve.zig — @rpath/@executable_path/@loader_path expansion + on-disk / shared-cache residency.
//! Imports: core/loadcmds (Dylib type only), core/diag.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Dylib = @import("../core/loadcmds.zig").Dylib;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Status = enum { on_disk, shared_cache, missing, unresolvable_rpath, weak_missing, not_checked };
pub const Resolution = struct { path: []const u8, resolved: ?[]const u8, status: Status, via_rpath: ?[]const u8, weak: bool };
/// `exe_path` is the analysed file; `loader_path` the directory of the image whose LC_RPATHs are used.
pub fn resolveAll(arena: Allocator, io: Io, exe_path: []const u8, dylibs: []const Dylib, rpaths: []const []const u8, diags: *Diagnostics) Allocator.Error![]const Resolution;
/// _dyld_shared_cache_contains_path (macOS 11+); false off-macOS.
pub fn inSharedCache(path_z: [:0]const u8) bool;
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn _dyld_shared_cache_contains_path(path: [*:0]const u8) bool;
```

### 4.17 `objc/objc.zig`

**Imports:** core/image, core/reader, core/diag, core/limits, core/sanitize, core/macho_extra, macho/fixups, macho/symbols.
**Rules** (format-notes 6): every pointer read = `FixupTable.resolveSlot` -> `& PTR_MASK` -> `Image.bytesAtVm`;
`class_ro_t* = data & FAST_DATA_MASK`; small (relative, flag 0x80000000) vs large method lists; every list count
clamped by `max_objc_methods_per_list` and the bytes mapped; visited-address `std.AutoHashMapUnmanaged(u64, void)`
prevents protocol/superclass cycles; categories on external classes name the bound symbol; `__objc_stubs`
stride 32 (size/align check; `-objc_stubs_small` -> diagnostic); selectors from `__objc_selrefs` slots.
**Verified oracle:** hello-objc classes `MachreAnimal : NSObject`, `MachreDog : MachreAnimal`, category
`NSString(MachreExtras)`, protocols `MachreGreeter`, `NSObject`, 15 stubs, 40 selrefs, 11 cfstrings; TextEdit 19
classes (`Document : NSDocument`, 79 methods, 26 ivars, 2 properties); Electron 132 classes.

```zig
//! objc/objc.zig — Objective-C runtime metadata (objc4 new ABI, 64-bit).
//! Imports: core/image, core/reader, core/diag, core/limits, core/sanitize, core/macho_extra, macho/fixups, macho/symbols.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const FixupTable = @import("../macho/fixups.zig").FixupTable;
const SymbolTable = @import("../macho/symbols.zig").SymbolTable;

pub const ImageInfo = struct { version: u32, flags: u32, swift_unstable: u8, swift_stable: u16, has_category_class_properties: bool, is_swift: bool };
pub const Method = struct { name: []const u8, types: []const u8, imp: u64, is_class_method: bool, small: bool };
pub const Ivar = struct { name: []const u8, type: []const u8, offset: ?u32, alignment: u32, size: u32 };
pub const Property = struct { name: []const u8, attributes: []const u8 };
pub const SuperRef = struct { kind: enum { local, external, unresolved, none }, address: u64, name: ?[]const u8 };
pub const Class = struct {
    address: u64,
    name: []const u8,
    superclass: SuperRef, // rebase -> local class name; bind -> external symbol
    is_meta: bool,
    is_swift: bool,
    ro_flags: u32,
    instance_start: u32,
    instance_size: u32,
    methods: []const Method,
    class_methods: []const Method,
    ivars: []const Ivar,
    properties: []const Property,
    protocols: []const []const u8,
};
pub const Category = struct { address: u64, name: []const u8, class_name: []const u8, class_external: bool, instance_methods: []const Method, class_methods: []const Method, protocols: []const []const u8, properties: []const Property };
pub const Protocol = struct { address: u64, name: []const u8, protocols: []const []const u8, instance_methods: []const Method, class_methods: []const Method, optional_instance_methods: []const Method, optional_class_methods: []const Method };
pub const Selector = struct { selref_addr: u64, name: []const u8 };
pub const ClassRef = struct { ref_addr: u64, name: []const u8, external: bool };
pub const Stub = struct { addr: u64, selector: []const u8 };
pub const ObjcInfo = struct {
    present: bool,
    image_info: ?ImageInfo,
    classes: []const Class,
    categories: []const Category,
    protocols: []const Protocol,
    selectors: []const Selector,
    classrefs: []const ClassRef,
    stubs: []const Stub,
    truncated: bool,
    pub const empty: ObjcInfo = .{ .present = false, .image_info = null, .classes = &.{}, .categories = &.{}, .protocols = &.{}, .selectors = &.{}, .classrefs = &.{}, .stubs = &.{}, .truncated = false };
    pub fn classByName(o: *const ObjcInfo, name: []const u8) ?*const Class;
};
pub fn hasObjc(img: *const Image) bool;
/// Every pointer read goes FixupTable.resolveSlot -> mask PTR_MASK -> Image.bytesAtVm; counts clamped;
/// visited-address set prevents protocol/superclass cycles.
pub fn parse(arena: Allocator, img: *const Image, fix: *const FixupTable, syms: *const SymbolTable, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ObjcInfo;
pub const Imp = struct { imp: u64, name: []const u8 }; // "-[Class sel]" / "+[Class sel]"
pub fn methodImps(arena: Allocator, info: *const ObjcInfo) Allocator.Error![]const Imp;
```

### 4.18 `strings/strings.zig`

**Imports:** core/image, core/reader, core/limits, core/diag, core/sanitize, core/macho_extra, macho/fixups.
**Rules:** `__cstring`/`__objc_methname`/`__objc_classname`/`__objc_methtype` NUL-split; `__ustring` UTF-16LE via
`std.unicode.utf16LeToUtf8Alloc` (bounded); `__cfstring` 32-byte entries resolved through `resolveSlot` on `data`
with flags 0x7c8 (UTF-8) / 0x7d0 (UTF-16); `__info_plist` as one string; generic printable runs (ASCII >= min_len,
and UTF-16LE runs) over the remaining file bytes when `generic_scan`. `classify`: url (`http[s]://`, `ftp://`),
ip (dotted quad), path (`/Library/LaunchAgents`… -> launch_agent, `/Users/`, `/tmp/`, `~/`), shell (`/bin/sh`,
`osascript`, `curl `, `chmod +x`, `nohup`), keychain (`security find-`, `SecKeychain`), base64 (>= 32 chars of the
alphabet with `=` padding), user_agent (`Mozilla/`), crypto_wallet (wallet paths/`xpub`), anti_analysis
(`sysctl hw.model`, `VMware`, `VirtualBox`, `ptrace`, `P_TRACED`, `isDebuggerActive`), persistence
(`launchctl`, `crontab`, `LoginItems`), script (`#!/`, `python -c`).
**Verified oracle:** hello-c cstrings at `0x100000668/0x681/0x68e`; `strings --bare --min 6 --limit 200` equals
the `strings -n 6 | head -200` truth section for every healthy fixture.

```zig
//! strings/strings.zig — sectioned string extraction + classification.
//! Imports: core/image, core/reader, core/limits, core/sanitize, core/macho_extra, macho/fixups.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const FixupTable = @import("../macho/fixups.zig").FixupTable;

pub const Kind = enum { cstring, ustring, cfstring, objc_methname, objc_classname, objc_methtype, info_plist, generic_ascii, generic_utf16 };
/// Analyst classification (triage `str.*` rules and `strings --class`).
pub const Class = enum { plain, url, ip, path, shell, launch_agent, keychain, base64, format, user_agent, crypto_wallet, anti_analysis, persistence, script };
pub const Str = struct {
    addr: u64,
    file_offset: u64,
    kind: Kind,
    class: Class,
    section: ?u16,
    text: []const u8, // sanitized UTF-8, cut at max_string_len
    raw_len: u32,
    cut: bool,
    lossy: bool,
};
pub const StringsResult = struct {
    strings: []const Str,
    truncated: bool,
    lossy_count: u32,
    pub const empty: StringsResult = .{ .strings = &.{}, .truncated = false, .lossy_count = 0 };
};
pub const Options = struct {
    min_len: u32 = 4,
    kinds: std.EnumSet(Kind) = .full,
    generic_scan: bool = true,
    dedupe: bool = false,
    classify: bool = true,
};
pub fn extract(arena: Allocator, img: *const Image, fix: *const FixupTable, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!StringsResult;
/// For non-Mach-O files (generic printable runs only).
pub fn extractRaw(arena: Allocator, bytes: []const u8, base_offset: u64, opts: Options, limits: *const Limits) Allocator.Error!StringsResult;
pub fn classify(text: []const u8) Class;
```

### 4.19 `analysis/entropy.zig`

**Imports:** core/image, core/loadcmds. Entropy is computed over **file bytes** per segment/section (tiny `-O0`
`__TEXT` is ~0.5 because of page padding; only random data reaches 8.0). Tells: `high_entropy_segment`
(> 7.0 covering > 20 % of the file), `packer_segment_name`/`packer_section_name` (`packer_names` prefix match),
`no_imports_no_symbols`, `protected_segment` (`SG_PROTECTED_VERSION_1`), `encryption_info` (`cryptid != 0`),
`tiny_text_huge_data`, `entry_outside_text`, `rwx_segment`, `nonstandard_segment_order`.
**Verified oracle:** high-entropy `__RANDOM` 7.997 over 65.8 %; hello-c `__TEXT` 0.54; hello-zig `__TEXT` 6.33;
tells fire only for high-entropy, fake-packed (`__XHDR`), fake-upx (`UPX_DATA`).

```zig
//! analysis/entropy.zig — Shannon entropy per segment/section/file + packer/encryption tells.
//! Imports: core/image, core/loadcmds (EncryptionInfo).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const EncryptionInfo = @import("../core/loadcmds.zig").EncryptionInfo;

pub const Region = struct { name: []const u8, sectname: ?[]const u8, file_offset: u64, size: u64, entropy: f64, file_fraction: f64 };
pub const TellCode = enum { high_entropy_segment, packer_segment_name, packer_section_name, no_imports_no_symbols, protected_segment, encryption_info, tiny_text_huge_data, entry_outside_text, rwx_segment, nonstandard_segment_order };
pub const PackerTell = struct { code: TellCode, detail: []const u8, weight: u8 };
pub const EntropyReport = struct {
    file: f64,
    segments: []const Region,
    sections: []const Region,
    tells: []const PackerTell,
    pub const empty: EntropyReport = .{ .file = 0, .segments = &.{}, .sections = &.{}, .tells = &.{} };
};
pub const Inputs = struct { symbol_count: u32, import_count: u32, encryption: ?EncryptionInfo, entry_vm: ?u64 };
pub fn analyze(arena: Allocator, img: *const Image, in: Inputs) Allocator.Error!EntropyReport;
/// Single pass, 256-bucket histogram, bits/byte; 0 for empty input.
pub fn shannon(bytes: []const u8) f64;
pub const packer_names: []const []const u8 = &.{ "__XHDR", "UPX_DATA", "upxTEXT", "__MPRESS__" };
```

### 4.20 `plist/plist.zig`, `plist/bplist.zig`, `plist/xml.zig`

**Imports:** plist -> diag, limits, sanitize; bplist/xml -> plist, reader, diag, limits.
**bplist:** trailer from the last 32 bytes (file >= 40 B), `offsetIntSize/objectRefSize in {1,2,4,8}`,
`numObjects` clamped to `max_plist_objects` and to the table size, every object offset `< offsetTableOffset`,
explicit stack of `{obj_index, container_slot}` frames with a per-path visiting bitset (cycle ->
`plist_malformed`), depth <= `max_plist_depth`, UTF-16BE strings byte-swapped then `utf16LeToUtf8Alloc`.
**xml:** single-pass tokenizer over <= `max_xml_bytes`, element stack with depth cap, entities `&amp; &lt; &gt;
&quot; &apos; &#N; &#xN;`, `<data>` via `std.base64.standard.decoderWithIgnore(" \n\t\r")`, unknown elements
skipped with one diagnostic.
**Verified oracle:** `Hello.app/Contents/Info.plist` (bplist, 12 keys, `CFBundleIdentifier = com.machre.corpus.Hello`)
deep-equals `Hello-Info.plist.xml`; format-notes 7 `tiny.bplist` (146 B, 19 objects, "héllo", date, -1);
`CodeResources` rules=13 files=1.

```zig
//! plist/plist.zig — Value model + format detection + parseAny. Imports: core/diag, core/limits, core/sanitize.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Value = union(enum) {
    null,
    bool: bool,
    integer: i64,
    uid: u64,
    real: f64,
    date: f64, // seconds since 2001-01-01T00:00:00Z
    string: []const u8,
    data: []const u8,
    array: []const Value,
    dict: []const Entry, // insertion order preserved

    pub const Entry = struct { key: []const u8, value: Value };

    pub fn get(v: Value, key: []const u8) ?Value;
    pub fn getString(v: Value, key: []const u8) ?[]const u8;
    pub fn getBool(v: Value, key: []const u8) ?bool;
    pub fn getInteger(v: Value, key: []const u8) ?i64;
    /// Dotted-path lookup ("CFBundleURLTypes.0.CFBundleURLSchemes").
    pub fn path(v: Value, dotted: []const u8) ?Value;
    pub fn deepEqual(a: Value, b: Value) bool;
    /// data -> {"$data":"<hex>"}, date -> ISO string, uid -> {"$uid":n}; strings sanitized.
    pub fn jsonStringify(v: Value, jw: *std.json.Stringify) std.json.Stringify.Error!void;
};
pub const Format = enum { bplist, xml, unknown };
/// "bplist0" prefix vs "<?xml"/"<plist"/"<!DOCTYPE" (leading whitespace/BOM tolerated).
pub fn detect(bytes: []const u8) Format;
pub fn parseAny(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value;
```

```zig
//! plist/bplist.zig — bplist00 parser (trailer, offset table, iterative decode, cycle/depth guards).
//! Imports: plist/plist, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = @import("plist.zig").Value;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value;
pub const Trailer = struct { sort_version: u8, offset_int_size: u8, object_ref_size: u8, num_objects: u64, top_object: u64, offset_table_offset: u64 };
pub fn readTrailer(bytes: []const u8) ?Trailer;

//! plist/xml.zig — minimal XML plist reader (prologue/DOCTYPE skip, entities, <data> base64, depth cap).
//! Imports: plist/plist, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = @import("plist.zig").Value;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value;
/// Decode `&amp; &lt; &gt; &quot; &apos; &#N; &#xN;` into an arena copy (returns input when no entity).
pub fn decodeEntities(arena: Allocator, text: []const u8) Allocator.Error![]const u8;
```

### 4.21 `bundle/bundle.zig` — portable bundle analysis (graft: C's ResourceVerify)

**Imports:** core/file, core/fat, core/image, core/reader, core/diag, core/limits, core/sanitize, plist/*,
codesign/blobs, codesign/hashes. **Not** darwin/* — `cmd/bundle.zig` adds the Security.framework verdict,
xattrs and (opt-in `--spctl`) the spctl verdict, so the walker stays portable and never spawns a process.
**Rules:** `Io.Dir.walk` (symlinks reported, never descended: `Versions/Current` is not walked twice), entries
<= `max_bundle_entries`, depth <= `max_bundle_depth`; nested `.app/.framework/.xpc/.appex/.bundle/.dylib` under
`Contents/{Frameworks,PlugIns,XPCServices,Helpers,Library/LoginItems,MacOS}` recorded (not recursed beyond depth);
`verifyResources`: sha1 for `files`, sha256 for `files2[*].hash2`, nested code by its own best-CD cdhash vs
`files2[*].cdhash` (`cdhash_match`), `optional` honoured, `unsealed` = regular files under `Contents/` not in
files2 and not omitted by `rules2` (`Info.plist`, `PkgInfo`, `_CodeSignature/*`, `.DS_Store`, `CodeResources`
ticket). Stapled ticket = `Contents/CodeResources` starting `s8ch`.
**Verified oracle:** Hello.app kind app, identifier `com.machre.corpus.Hello`, executable `Contents/MacOS/Hello`,
CodeResources v2 rules 13 files 1, nested `Frameworks/libhello.dylib` cdhash `41b85e20…b754` matches, no ticket,
no unsealed files; Discord.app ticket 2304 B, 15 v1 / 24 v2 entries.

```zig
//! bundle/bundle.zig — .app/.framework/.xpc discovery, Info.plist, nested code, CodeResources seal verification.
//! Portable: no Darwin externs (cmd/bundle.zig adds Security.framework/xattr results).
//! Imports: core/file, core/fat, core/image, core/reader, core/diag, core/limits, core/sanitize, plist/plist, codesign/blobs, codesign/hashes.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const plist = @import("../plist/plist.zig");

pub const Kind = enum { app, framework, xpc, appex, plugin, kext, generic_bundle, unknown };
pub const NestedCode = struct {
    rel_path: []const u8,
    kind: Kind,
    executable_rel: ?[]const u8,
    sealed_cdhash: ?[20]u8, // from CodeResources files2
    sealed_requirement: ?[]const u8,
    actual_cdhash: ?[20]u8, // parsed from the nested code's own LC_CODE_SIGNATURE (best CD)
    cdhash_match: ?bool,
    signed: ?bool,
    arch_names: []const []const u8,
};
pub const ResourceFile = struct { path: []const u8, hash1: ?[20]u8, hash2: ?[32]u8, optional: bool, symlink: ?[]const u8, nested: bool, cdhash: ?[20]u8, requirement: ?[]const u8 };
pub const CodeResources = struct { version: u32, rules: u32, rules2: u32, files: []const ResourceFile, files2: []const ResourceFile, raw: []const u8 };
pub const ResourceVerify = struct { checked: u32, mismatched: []const []const u8, missing: []const []const u8, unsealed: []const []const u8, ok: bool };
pub const Bundle = struct {
    root: []const u8,
    kind: Kind,
    info_plist_path: ?[]const u8,
    info_plist: ?plist.Value,
    info_plist_format: plist.Format,
    info_plist_bytes: ?[]const u8,
    identifier: ?[]const u8,
    executable_rel: ?[]const u8,
    executable_path: ?[]const u8,
    package_type: ?[]const u8,
    version: ?[]const u8,
    short_version: ?[]const u8,
    min_system: ?[]const u8,
    principal_class: ?[]const u8,
    ui_element: bool,
    background_only: bool,
    ats_arbitrary_loads: bool,
    usage_descriptions: []const []const u8,
    url_schemes: []const []const u8,
    frameworks: []const NestedCode,
    helpers: []const NestedCode,
    xpc_services: []const NestedCode,
    plugins: []const NestedCode,
    dylibs: []const NestedCode,
    code_resources: ?CodeResources,
    resource_verify: ?ResourceVerify,
    stapled_ticket: ?struct { path: []const u8, len: u64 },
    provisioning_profile: bool,
    file_count: u32,
    total_size: u64,
    entries_walked: u32,
    truncated: bool,
};
pub const Options = struct { verify_resources: bool = true, hash_nested: bool = true };

/// Directory containing Contents/Info.plist (app/xpc/plugin) or Versions/*/Resources/Info.plist (framework).
pub fn detect(io: Io, path: []const u8) ?Kind;
/// Io.Dir.walk (symlinks reported, never descended), entries <= limits.max_bundle_entries, depth <= max_bundle_depth.
pub fn analyze(arena: Allocator, gpa: Allocator, io: Io, path: []const u8, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Bundle;
/// Hash every sealed file (sha1 for files, sha256 for files2) and compare; nested code via its own cdhash.
pub fn verifyResources(arena: Allocator, gpa: Allocator, io: Io, b: *const Bundle, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ResourceVerify;
pub fn parseCodeResources(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?CodeResources;
/// Main executable path for a bundle root (Contents/MacOS/<CFBundleExecutable> or Versions/Current/<Name>).
pub fn mainExecutable(arena: Allocator, io: Io, path: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?[]const u8;
```

### 4.22 `analysis/analysis.zig` — memoising facade (graft from A/C; implemented by WP0)

**Imports:** everything below `cmd/`. Each getter parses on first use, caches the arena-owned result, and
returns `Allocator.Error!` (OOM propagates to exit 70; it is never swallowed). Absent data -> `null` (or
`.empty` for tables) plus the parser's diagnostics. Getters call each other in DAG order (`fixups` needs
`chained`/`legacy`; `imports` needs `symbols`+`fixups`+`dylibs`; `stubs` needs `symbols`+`fixups`+`objc`).
`security()` returns `security.unavailable(...)` when `options.security == false` or
`!build_options.have_security`. `engine()` opens the Capstone handle once (gpa) and closes it in `deinit`.
WP0 implements this file completely against the stubs (it contains no parsing logic).

```zig
//! analysis/analysis.zig — memoizing lazy facade over every parser for ONE slice. Commands, triage and
//! report go through it so `machre info` never parses symbols/chains/ObjC unless a getter is called.
//! Getters propagate Allocator.Error (never swallow OOM); absent data is `null` / `.empty` + diagnostics.
//! Imports: everything below cmd/.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const symbols_mod = @import("../macho/symbols.zig");
const dyld_chained_mod = @import("../macho/dyld_chained.zig");
const dyld_exports_mod = @import("../macho/dyld_exports.zig");
const dyld_legacy_mod = @import("../macho/dyld_legacy.zig");
const function_starts_mod = @import("../macho/function_starts.zig");
const fixups_mod = @import("../macho/fixups.zig");
const imports_mod = @import("../macho/imports.zig");
const blobs_mod = @import("../codesign/blobs.zig");
const hashes_mod = @import("../codesign/hashes.zig");
const requirements_mod = @import("../codesign/requirements.zig");
const entitlements_mod = @import("../codesign/entitlements.zig");
const cms_mod = @import("../codesign/cms.zig");
const security_mod = @import("../darwin/security.zig");
const xattr_mod = @import("../darwin/xattr.zig");
const dylib_resolve_mod = @import("../darwin/dylib_resolve.zig");
const objc_mod = @import("../objc/objc.zig");
const strings_mod = @import("../strings/strings.zig");
const entropy_mod = @import("entropy.zig");
const functions_mod = @import("../disasm/functions.zig");
const symbolize_mod = @import("../disasm/symbolize.zig");
const engine_mod = @import("../disasm/engine.zig");

pub const Options = struct {
    security: bool = true, // --no-security
    network: bool = true, // --no-network
    resolve_deps: bool = true,
    engine: engine_mod.Options = .{},
};

pub const Analysis = struct {
    gpa: Allocator,
    arena: Allocator,
    io: Io,
    file: *const LoadedFile,
    img: *const Image,
    limits: *const Limits,
    diags: *Diagnostics,
    options: Options,

    // memo slots (null = not computed yet)
    symbols_: ?symbols_mod.SymbolTable = null,
    addr_index_: ?symbols_mod.AddressIndex = null,
    chained_: ?struct { v: ?dyld_chained_mod.ChainedFixups } = null,
    legacy_: ?struct { v: ?dyld_legacy_mod.DyldInfo } = null,
    exports_trie_: ?struct { v: ?dyld_exports_mod.ExportTrie } = null,
    function_starts_: ?struct { v: ?function_starts_mod.FunctionStarts } = null,
    data_in_code_: ?struct { v: ?function_starts_mod.DataInCode } = null,
    fixups_: ?fixups_mod.FixupTable = null,
    dylibs_: ?[]const imports_mod.DylibRef = null,
    rpaths_: ?[]const []const u8 = null,
    imports_: ?imports_mod.ImportTable = null,
    exports_: ?imports_mod.ExportTable = null,
    signature_: ?struct { v: ?blobs_mod.Signature } = null,
    verification_: ?struct { v: ?hashes_mod.Verification } = null,
    requirements_: ?struct { v: ?requirements_mod.RequirementSet } = null,
    entitlements_: ?entitlements_mod.Entitlements = null,
    cms_: ?struct { v: ?cms_mod.Cms } = null,
    security_: ?security_mod.Verdict = null,
    xattrs_: ?xattr_mod.Xattrs = null,
    resolutions_: ?[]const dylib_resolve_mod.Resolution = null,
    objc_: ?objc_mod.ObjcInfo = null,
    strings_: ?strings_mod.StringsResult = null,
    strings_opts_: ?strings_mod.Options = null,
    entropy_: ?entropy_mod.EntropyReport = null,
    functions_: ?functions_mod.FunctionTable = null,
    stubs_: ?symbolize_mod.StubTable = null,
    engine_: ?engine_mod.Engine = null,

    pub fn init(gpa: Allocator, arena: Allocator, io: Io, file: *const LoadedFile, img: *const Image, limits: *const Limits, diags: *Diagnostics, options: Options) Analysis;
    pub fn deinit(a: *Analysis) void;
    pub fn symbols(a: *Analysis) Allocator.Error!*const symbols_mod.SymbolTable;
    pub fn addressIndex(a: *Analysis) Allocator.Error!*const symbols_mod.AddressIndex;
    pub fn chained(a: *Analysis) Allocator.Error!?*const dyld_chained_mod.ChainedFixups;
    pub fn legacy(a: *Analysis) Allocator.Error!?*const dyld_legacy_mod.DyldInfo;
    pub fn exportsTrie(a: *Analysis) Allocator.Error!?*const dyld_exports_mod.ExportTrie;
    pub fn functionStarts(a: *Analysis) Allocator.Error!?*const function_starts_mod.FunctionStarts;
    pub fn dataInCode(a: *Analysis) Allocator.Error!?*const function_starts_mod.DataInCode;
    pub fn fixups(a: *Analysis) Allocator.Error!*const fixups_mod.FixupTable;
    pub fn dylibs(a: *Analysis) Allocator.Error![]const imports_mod.DylibRef;
    pub fn rpaths(a: *Analysis) Allocator.Error![]const []const u8;
    pub fn imports(a: *Analysis) Allocator.Error!*const imports_mod.ImportTable;
    pub fn exports(a: *Analysis) Allocator.Error!*const imports_mod.ExportTable;
    pub fn signature(a: *Analysis) Allocator.Error!?*const blobs_mod.Signature;
    pub fn verification(a: *Analysis) Allocator.Error!?*const hashes_mod.Verification;
    pub fn requirements(a: *Analysis) Allocator.Error!?*const requirements_mod.RequirementSet;
    pub fn entitlements(a: *Analysis) Allocator.Error!*const entitlements_mod.Entitlements;
    pub fn cms(a: *Analysis) Allocator.Error!?*const cms_mod.Cms;
    /// `.available=false` when options.security is false or the build lacks Security.
    pub fn security(a: *Analysis) Allocator.Error!*const security_mod.Verdict;
    pub fn xattrs(a: *Analysis) Allocator.Error!*const xattr_mod.Xattrs;
    pub fn resolutions(a: *Analysis) Allocator.Error![]const dylib_resolve_mod.Resolution;
    pub fn objc(a: *Analysis) Allocator.Error!?*const objc_mod.ObjcInfo;
    /// Re-runs when `opts` differ from the memoized options.
    pub fn strings(a: *Analysis, opts: strings_mod.Options) Allocator.Error!*const strings_mod.StringsResult;
    pub fn entropy(a: *Analysis) Allocator.Error!*const entropy_mod.EntropyReport;
    pub fn functions(a: *Analysis) Allocator.Error!*const functions_mod.FunctionTable;
    pub fn stubs(a: *Analysis) Allocator.Error!*const symbolize_mod.StubTable;
    pub fn annotateCtx(a: *Analysis) Allocator.Error!symbolize_mod.AnnotateCtx;
    /// gpa-owned Capstone handle (when available); freed in deinit.
    pub fn engine(a: *Analysis) engine_mod.OpenError!*engine_mod.Engine;
};
```

### 4.23 `analysis/triage.zig` — rules, scoring, KnockKnock text

**Imports:** analysis/analysis, bundle/bundle, output/*, core/limits, core/diag.
**Rule table** (`id` : category : weight): `sig.unsigned` signature 25 · `sig.adhoc` 10 (3 when linker-signed)
· `sig.invalid` 35 · `sig.revoked` 45 · `sig.devid_not_notarized` 15 · `sig.not_evaluated` 0 (info) ·
`sig.sha1_only` 8 · `sig.hardened_runtime_missing` 8 · `pack.entropy` 25 · `pack.names` 25 ·
`pack.no_imports_no_symbols` 25 · `pack.protected_segment` 20 · `pack.encryption_info` 20 ·
`pack.tiny_text_large_data` 8 · `deps.missing_dylib` 20 · `deps.rpath_frameworks` 5 · `deps.reexport` 10 ·
`deps.dyld_environment` 20 · `deps.weak_unusual` 3 · `hdr.rwx_segment` 30 · `hdr.allow_stack_execution` 20 ·
`hdr.no_pie` 8 · `hdr.unknown_lc_req_dyld` 20 · `hdr.unknown_lc` 5 · `hdr.segment_order` 5 ·
`hdr.text_not_at_zero` 5 · `hdr.unixthread_entry` 8 · `ent.get_task_allow` 10 · `ent.disable_library_validation` 12 ·
`ent.allow_jit` 8 · `ent.allow_unsigned_memory` 12 · `ent.allow_dyld_env` 12 · `ent.debugger` 10 ·
`ent.xml_der_mismatch` 20 · `str.script_interpreters` 8 · `str.persistence_paths` 10 · `str.network_indicators` 5 ·
`str.base64_blobs` 5 · `str.anti_analysis` 10 · `objc.suspicious_selectors` 8 · `sym.stripped` 0 (info) ·
`stubs.mismatch` 15 · `bundle.no_info_plist` 20 · `bundle.executable_mismatch` 20 · `bundle.nested_unsigned` 15 ·
`bundle.resource_mismatch` 25 · `bundle.unsealed` 10 · `bundle.ui_element` 3 · `bundle.ats_insecure` 5 ·
`quarantine.present` 0 (info) · `quarantine.translocated` 0 (info) · `diag.malformed` 10 (error-severity
diagnostics exist). `comptime` asserts every weight < 50 (no single tell is a verdict).
**Positives** (subtract): platform binary -20, notarized Developer ID -15, App Store -15, hardened runtime -3.
**levelFor:** `score < 20` clean; `20..49` notable; `50..99` suspicious **only if** `categories_hit >= 2` else
notable; `>= 100` likely_malicious only if `categories_hit >= 2` else suspicious. `exit_code` = 20 when
`--fail-on=<level>` is reached (default: never), else 0 — `hello-unsigned` (25, one category) is `notable`,
exit 0 (the C-defect).
**Text** (KnockKnock-style, §5.5): verdict line, per-finding rows `Category [SEV] id  detail`, then
`Corroboration:` sentences (packing tell + broken signature -> "file was modified after linking") and a
`Not flagged:` line naming the negative evidence (entropy max, imports present, symbols present, no quarantine).
**Corpus expectations:** hello-c clean (adhoc 3); hello-unsigned/hello-x86_64 notable (25); high-entropy notable
(28, two categories but < 50); fake-upx suspicious (invalid 35 + names 25 = 60, two categories) -> `--fail-on=suspicious`
exits 20; fake-packed notable; hello-entitled lists 4 `ent.*`; `/bin/ls` clean; Hello.app clean/notable
(adhoc only); a synthetic input with only `sig.revoked` stays notable.

```zig
//! analysis/triage.zig — Wardle-style scored anomaly report: table-driven rules, categories, the ">= 2
//! categories" gate for suspicious+, positives that subtract, KnockKnock-style text.
//! Imports: analysis/analysis, bundle/bundle, output/sink, output/json, output/text, every module's types.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Analysis = @import("analysis.zig").Analysis;
const Bundle = @import("../bundle/bundle.zig").Bundle;
const Sink = @import("../output/sink.zig").Sink;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Category = enum { signature, packing, dependencies, header, entitlements, strings, objc, bundle, quarantine, symbols, structure };
pub const Severity = enum(u8) { info, low, medium, high };
pub const Level = enum { clean, notable, suspicious, likely_malicious };

pub const Rule = struct {
    id: []const u8, // stable: "sig.unsigned", "pack.entropy", "deps.missing_dylib", "ent.get_task_allow", ...
    category: Category,
    severity: Severity,
    weight: u8, // < 50 always (comptime-asserted): no single tell is a verdict
    title: []const u8,
    doc: []const u8,
};
/// The rule table (DESIGN.md §4.26 lists every id/category/weight).
pub const rules: []const Rule = &.{};
comptime {
    for (rules) |r| std.debug.assert(r.weight < 50);
}
pub fn byId(id: []const u8) ?*const Rule;

pub const Finding = struct { rule: *const Rule, score: u8, title: []const u8, detail: []const u8, evidence: []const []const u8, corroborates: ?[]const u8 };
pub const Positive = struct { id: []const u8, text: []const u8, credit: u8 };
pub const Summary = struct { signed: bool, trust: []const u8, notarized: ?bool, hardened_runtime: bool, quarantined: bool, packed_hint: bool, encrypted: bool, imports: u32, exports: u32, symbols: u32, dylibs: u32, objc_classes: u32, arch: []const u8 };
pub const Report = struct {
    score: u32,
    level: Level,
    findings: []const Finding, // severity desc, then weight desc
    positives: []const Positive,
    categories_hit: []const Category,
    corroboration: []const []const u8, // human sentences
    not_flagged: []const []const u8, // "Not flagged:" facts (entropy max, imports present, ...)
    summary: Summary,
    per_arch: bool,
    exit_code: u8,
};
pub const Options = struct { fail_on: ?Level = null, explain: bool = false };

/// score = sum(weights) - sum(positive credits), floored at 0; suspicious+ requires >= 2 categories.
pub fn levelFor(score: u32, categories_hit: usize) Level;
pub fn run(arena: Allocator, a: *Analysis, bundle: ?*const Bundle, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Report;
/// Merge per-arch reports of a fat file into one (max level, union of findings).
pub fn merge(arena: Allocator, reports: []const Report) Allocator.Error!Report;
pub fn writeText(r: *const Report, path: []const u8, sink: *Sink) Io.Writer.Error!void;
pub fn writeJson(r: *const Report, sink: *Sink) std.json.Stringify.Error!void;
pub fn levelName(l: Level) []const u8;
```

### 4.24 `disasm/insn.zig`, `capstone.zig`, `arm64.zig`, `x86len.zig`

**Imports:** insn -> core/arch; capstone -> insn, arch; arm64/x86len -> insn.
`Insn.kind/target/reg_write/imm/mem_ref` ALWAYS come from the built-in decoders (`decodeSemantic`); `mnemonic/
operands` come from Capstone when available (`text_from = .capstone`) else from the built-in text decoders.
`capstone.Handle.open(arch, att)` applies `CS_OPT_SYNTAX_ATT` only for x86_64 (invalid on ARM64 handles — C-defect);
`CS_OPT_DETAIL` off, `CS_OPT_SKIPDATA` on. arm64 unknown words -> `.inst 0x%08x` (`kind = .invalid`, valid=false),
never skipped; x86 length decoder never returns 0 (undefined `FF /7` -> 1-byte `db`).

```zig
//! disasm/insn.zig — the one instruction record produced by every backend. Imports: core/arch.
const std = @import("std");
const ArchName = @import("../core/arch.zig").ArchName;

pub const Backend = enum { capstone, builtin_arm64, builtin_x86len };
pub const Kind = enum { other, branch, cond_branch, call, ret, indirect_branch, indirect_call, adrp, adr, add_imm, ldr_imm, ldr_literal, str_imm, mov_imm, movk, lea, push, pop, pac_prologue, pac_epilogue, bti, nop, trap, data, invalid };
pub const MemRef = struct { base: u5, offset: i64, size: u8 };
pub const Insn = struct {
    addr: u64,
    size: u8, // 4 on arm64, 1..15 on x86_64
    bytes: [16]u8,
    mnemonic: []const u8, // arena string (text backend)
    operands: []const u8,
    kind: Kind, // semantic fields ALWAYS from the built-in decoder
    target: ?u64,
    reg_write: ?u5,
    imm: ?u64, // adrp page / add imm / mov imm
    mem_ref: ?MemRef,
    valid: bool,
    text_from: Backend,
    semantic_from: Backend,
    partial: bool, // x86_64 built-in: only kind/size known ("db" mnemonic)
};
pub const Syntax = enum { intel, att };
pub const Listing = struct {
    insns: []const Insn,
    comments: []const ?[]const u8, // parallel: "; symbol stub for: _puts"
    labels: []const ?[]const u8, // parallel: function/label names
    start: u64,
    end: u64,
    partial: bool,
    backend_name: []const u8,
};
pub fn kindName(k: Kind) []const u8;
pub fn backendFor(arch: ArchName, have_capstone: bool) Backend;
```

```zig
//! disasm/capstone.zig — Capstone 5 externs behind build_options.have_capstone. Imports: disasm/insn, core/arch.
const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");
const ArchName = @import("../core/arch.zig").ArchName;

pub const available: bool = build_options.have_capstone;
pub const OpenError = error{ CapstoneUnavailable, CapstoneOpen, UnsupportedArch };

pub const Handle = struct {
    csh: usize,
    arch: ArchName,
    /// `att` is applied only for x86_64 (CS_OPT_SYNTAX_ATT is invalid on an ARM64 handle).
    pub fn open(arch: ArchName, att: bool) OpenError!Handle;
    pub fn close(h: *Handle) void;
};
pub const Text = struct { addr: u64, size: u8, mnemonic: []const u8, operands: []const u8, id: u32 };
/// Decodes `code` (SKIPDATA on, DETAIL off) into arena-owned text records; never fewer than one record per
/// undecodable unit. Used by engine.zig only to overlay text on the built-in decoder's semantic records.
pub fn decodeText(h: *Handle, arena: Allocator, code: []const u8, base: u64, max: u32) Allocator.Error![]Text;
pub fn version() ?struct { major: u8, minor: u8 };

const CsInsn = extern struct { id: c_uint, address: u64, size: u16, bytes: [24]u8, mnemonic: [32]u8, op_str: [160]u8, detail: ?*anyopaque };
comptime {
    std.debug.assert(@sizeOf(CsInsn) == 248);
    std.debug.assert(@offsetOf(CsInsn, "detail") == 240);
}
const CS_ARCH_ARM64: c_int = 1;
const CS_ARCH_X86: c_int = 3;
const CS_MODE_ARM: c_int = 0;
const CS_MODE_64: c_int = 1 << 3;
const CS_OPT_SYNTAX: c_int = 1;
const CS_OPT_DETAIL: c_int = 2;
const CS_OPT_SKIPDATA: c_int = 5;
const CS_OPT_OFF: usize = 0;
const CS_OPT_ON: usize = 3;
const CS_OPT_SYNTAX_ATT: usize = 2;
extern fn cs_version(major: ?*c_int, minor: ?*c_int) c_uint;
extern fn cs_open(arch: c_int, mode: c_int, handle: *usize) c_int;
extern fn cs_close(handle: *usize) c_int;
extern fn cs_option(handle: usize, opt_type: c_int, value: usize) c_int;
extern fn cs_disasm(handle: usize, code: [*]const u8, code_size: usize, address: u64, count: usize, out: *?[*]CsInsn) usize;
extern fn cs_free(out: [*]CsInsn, count: usize) void;
extern fn cs_strerror(code: c_int) [*:0]const u8;
// (extern declarations: see §8)

//! disasm/arm64.zig — built-in arm64 decoder (disasm-notes Part B). Imports: disasm/insn.
const std = @import("std");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");

/// Decodes exactly one 32-bit word at `pc`. Unknown -> mnemonic ".inst", operands "0x%08x", kind .invalid,
/// valid=false. Text is arena-owned (mnemonic/operands built with otool/LLVM spelling rules).
pub fn decodeOne(arena: Allocator, word: u32, pc: u64) Allocator.Error!insn.Insn;
/// Semantic-only decode (no text allocation): kind/target/reg_write/imm/mem_ref. Used by the engine when
/// Capstone supplies the text.
pub fn decodeSemantic(word: u32, pc: u64) insn.Insn;
/// DecodeBitMasks(N, imms, immr) -> wmask for `datasize` (32/64); null for reserved encodings.
pub fn decodeBitMasks(n: u1, imms: u6, immr: u6, datasize: u8) ?u64;
pub fn condName(cond: u4) []const u8;

//! disasm/x86len.zig — built-in x86_64 length decoder + kind/target recognizer (disasm-notes Part C). Imports: disasm/insn.
const std = @import("std");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");

/// Length-decodes one instruction at `bytes[0..]` (size 1..15, always >= 1). Recognized kinds get a mnemonic
/// (call/jmp/jcc/ret/push/pop/mov/lea); everything else is "db" with partial=true.
pub fn decodeOne(arena: Allocator, bytes: []const u8, pc: u64) Allocator.Error!insn.Insn;
pub fn decodeSemantic(bytes: []const u8, pc: u64) insn.Insn;
/// Instruction length only (never 0; 1 for undefined opcodes like FF /7).
pub fn length(bytes: []const u8) u8;
```

### 4.25 `disasm/functions.zig`

**Imports:** core/image, core/limits, core/diag, macho/symbols, macho/function_starts, macho/dyld_exports, objc/objc, disasm/insn.
Discovery order and naming priority in §9.

```zig
//! disasm/functions.zig — function discovery (function starts > symbols > exports > entry/ObjC IMPs > tertiary).
//! Imports: core/image, core/limits, core/diag, macho/symbols, macho/function_starts, macho/dyld_exports, objc/objc, disasm/insn.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const symbols = @import("../macho/symbols.zig");
const FunctionStarts = @import("../macho/function_starts.zig").FunctionStarts;
const ExportTrie = @import("../macho/dyld_exports.zig").ExportTrie;
const ObjcInfo = @import("../objc/objc.zig").ObjcInfo;

pub const Source = enum { function_starts, symbol, export_trie, entry, objc, call_target, unwind, jump_table, heuristic };
pub const Function = struct {
    start: u64,
    end: u64, // exclusive, best effort (next start in the section, or section end)
    name: []const u8, // symbol | export | "-[Class sel]" | "sub_100000524"
    source: Source, // where the START came from
    name_source: Source,
    section: ?u16,
    sources: u16, // bitset of Source
};
pub const FunctionTable = struct {
    functions: []const Function, // sorted by start, non-overlapping
    truncated: bool,
    pub const empty: FunctionTable = .{ .functions = &.{}, .truncated = false };
    pub fn containing(t: *const FunctionTable, addr: u64) ?*const Function;
    pub fn byName(t: *const FunctionTable, name: []const u8) ?*const Function;
    pub fn byStart(t: *const FunctionTable, addr: u64) ?*const Function;
};
pub const Inputs = struct { syms: *const symbols.SymbolTable, index: *const symbols.AddressIndex, starts: ?*const FunctionStarts, trie: ?*const ExportTrie, objc: ?*const ObjcInfo, aggressive: bool = false };
pub fn discover(arena: Allocator, img: *const Image, in: Inputs, limits: *const Limits, diags: *Diagnostics) Allocator.Error!FunctionTable;
```

### 4.26 `disasm/symbolize.zig` — stubs, annotations, xrefs

**Imports:** core/image, core/limits, core/diag, core/sanitize, macho/symbols, macho/fixups, objc/objc, strings/strings, disasm/insn, disasm/functions.
`Stub.resolved_by` records whether Algorithm A (indirect table) or B (pointer slot) produced the name; when both
ran and disagree, `mismatch=true`, `StubTable.mismatches += 1`, a `symbolize/stub_mismatch` warning is recorded
and triage fires `stubs.mismatch` (graft from A). `XrefOptions.include_pointer_slots` adds `pointer_slot` xrefs
from every rebase fixup whose target is in a code section (function-pointer tables, blocks, ObjC IMPs,
`__mod_init_func`/`__init_offsets`). Details in §9.

```zig
//! disasm/symbolize.zig — stub resolution (A: indirect table, B: pointer slot), ADRP/ADD/LDR folding,
//! otool-style ';' annotations, xref table (incl. fixup-derived pointer_slot xrefs).
//! Imports: core/image, core/limits, core/diag, core/sanitize, macho/symbols, macho/fixups, objc/objc, strings/strings, disasm/insn, disasm/functions.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const symbols = @import("../macho/symbols.zig");
const FixupTable = @import("../macho/fixups.zig").FixupTable;
const ObjcInfo = @import("../objc/objc.zig").ObjcInfo;
const StringsResult = @import("../strings/strings.zig").StringsResult;
const insn = @import("insn.zig");
const FunctionTable = @import("functions.zig").FunctionTable;

pub const StubKind = enum { arm64_stubs, arm64e_auth_stubs, x86_64_stubs, objc_stubs, stub_helper, lazy_pointer, non_lazy_pointer };
pub const ResolvedBy = enum { indirect_table, pointer_slot, symbol, none };
pub const Stub = struct {
    addr: u64,
    size: u8,
    kind: StubKind,
    symbol: ?[]const u8, // "_puts" or "_objc_msgSend$sel"
    slot: ?u64, // GOT / la_symbol_ptr / selref slot the stub loads
    dylib: ?[]const u8,
    resolved_by: ResolvedBy,
    /// Algorithms A and B both ran and disagreed (tampered/stripped indirect table) -> triage tell `stubs.mismatch`.
    mismatch: bool,
};
pub const StubTable = struct {
    stubs: []const Stub, // sorted by addr
    mismatches: u32,
    pub const empty: StubTable = .{ .stubs = &.{}, .mismatches = 0 };
    pub fn at(t: *const StubTable, addr: u64) ?*const Stub;
    pub fn slotName(t: *const StubTable, slot_vmaddr: u64) ?[]const u8;
    pub fn byName(t: *const StubTable, name: []const u8) ?*const Stub;
};
pub fn resolveStubs(arena: Allocator, img: *const Image, syms: *const symbols.SymbolTable, fix: *const FixupTable, objc: ?*const ObjcInfo, limits: *const Limits, diags: *Diagnostics) Allocator.Error!StubTable;

pub const AnnotateCtx = struct {
    img: *const Image,
    syms: *const symbols.SymbolTable,
    index: *const symbols.AddressIndex,
    fix: *const FixupTable,
    stubs: *const StubTable,
    funcs: *const FunctionTable,
    objc: ?*const ObjcInfo,
    strings: ?*const StringsResult,
    /// Suppress machre-only comments (data symbols, one-level pointer follow) and print `bl _name`
    /// for direct calls so the listing diffs empty against `otool -tV`.
    otool_compat: bool = false,
};
pub const AnnKind = enum { page, literal_string, cfstring, selector_ref, class_ref, got_symbol, stub, objc_msgsend, function, data_symbol, pointer, literal_value, jump_table, trap };
pub const Annotation = struct { kind: AnnKind, text: []const u8, otool_compatible: bool };
/// Fills listing.comments in place (one optional annotation per instruction; page[reg] state reset at
/// function entry and at every branch target).
pub fn annotate(arena: Allocator, listing: *insn.Listing, ctx: AnnotateCtx, limits: *const Limits) Allocator.Error!void;
/// Best name for an address: "_main", "_main+0x1c", "-[Foo bar]", stub symbol, or null.
pub fn nameFor(ctx: AnnotateCtx, addr: u64, buf: []u8) ?[]const u8;

pub const XrefKind = enum { call, jump, cond_jump, data_ref, string_ref, got_load, objc_selector, objc_class, pointer_slot };
pub const Xref = struct { from: u64, to: u64, kind: XrefKind, target_name: ?[]const u8, from_function: ?u32, via_stub: bool };
pub const XrefTable = struct {
    by_to: []const Xref, // sorted by (to, from)
    by_from: []const Xref, // sorted by (from, to)
    truncated: bool,
    pub const empty: XrefTable = .{ .by_to = &.{}, .by_from = &.{}, .truncated = false };
    pub fn to(t: *const XrefTable, addr: u64) []const Xref;
    pub fn from(t: *const XrefTable, addr: u64) []const Xref;
};
pub const XrefOptions = struct {
    /// Every rebase fixup whose target lands in a code section becomes a `pointer_slot` xref
    /// (function-pointer tables, blocks, ObjC IMPs, __mod_init_func / __init_offsets).
    include_pointer_slots: bool = true,
};
pub fn buildXrefs(arena: Allocator, listings: []const insn.Listing, ctx: AnnotateCtx, opts: XrefOptions, limits: *const Limits) Allocator.Error!XrefTable;
```

### 4.27 `disasm/engine.zig`

**Imports:** disasm/insn, capstone, arm64, x86len, functions, symbolize, core/image, core/arch, core/limits, core/diag.
`decodeRange` always runs the built-in decoder for every unit (4 bytes on arm64; length-decoded on x86_64),
then — when a Capstone handle exists — overlays Capstone's mnemonic/op_str on the record with the same
`(address, size)`; a length disagreement keeps the built-in boundary, marks `text_from = .builtin_*` for that
record and records ONE `disasm/backend_disagree` diagnostic (count in `disagreements`). Decoding is per
function (start -> next start), never a blind sweep; x86 inline jump tables are recognised and emitted as
`.data` records (§9).

```zig
//! disasm/engine.zig — per-function decode loop. The built-in decoder ALWAYS supplies semantic fields;
//! Capstone (when available) overlays mnemonic/op_str text where (address,size) match; length disagreements
//! keep the built-in boundary and log `backend_disagree`.
//! Imports: disasm/insn, disasm/capstone, disasm/arm64, disasm/x86len, disasm/functions, disasm/symbolize, core/image, core/arch, core/limits, core/diag.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Section = @import("../core/image.zig").Section;
const ArchName = @import("../core/arch.zig").ArchName;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const insn = @import("insn.zig");
const capstone = @import("capstone.zig");
const Function = @import("functions.zig").Function;
const FunctionTable = @import("functions.zig").FunctionTable;
const AnnotateCtx = @import("symbolize.zig").AnnotateCtx;

pub const Options = struct {
    backend: ?insn.Backend = null, // null = capstone if available else builtin
    syntax: insn.Syntax = .att, // x86_64 only (otool is AT&T)
    max_insns: u32 = 0,
    annotate: bool = true,
    otool_compat: bool = false,
    show_bytes: bool = false,
};
pub const OpenError = capstone.OpenError || Allocator.Error;

pub const Engine = struct {
    arch: ArchName,
    opts: Options,
    cs: ?capstone.Handle,
    text_backend: insn.Backend,
    semantic_backend: insn.Backend,
    disagreements: u32,

    /// `--backend=capstone` on a build without it -> error.CapstoneUnavailable (CLI exit 6).
    pub fn init(arch: ArchName, opts: Options) OpenError!Engine;
    pub fn deinit(e: *Engine) void;
    pub fn decodeRange(e: *Engine, arena: Allocator, code: []const u8, base: u64, max: u32, diags: *Diagnostics) Allocator.Error![]insn.Insn;
    pub fn backendName(e: *const Engine) []const u8;
    pub fn isPartial(e: *const Engine) bool;
};
pub fn disassembleFunction(arena: Allocator, e: *Engine, img: *const Image, f: *const Function, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error!insn.Listing;
pub fn disassembleRange(arena: Allocator, e: *Engine, img: *const Image, start: u64, len: u64, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error!insn.Listing;
/// One listing per function of the section (functions order); inline jump-table data survives as `.data` records.
pub fn disassembleSection(arena: Allocator, e: *Engine, img: *const Image, sect: *const Section, funcs: *const FunctionTable, ctx: AnnotateCtx, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const insn.Listing;
```

### 4.28 `output/json.zig` and `output/text.zig`

**Imports:** json -> sink, diag, sanitize, file, image, fat, fmt; text -> sink, diag, sanitize, fmt.
`json.str` is the only way a file-derived string reaches JSON: it writes `<key>` (sanitised), and when bytes were
replaced also `<key>_hex` and `<key>_lossy: true`. `json.int` emits a JSON number when the value fits 2^53,
otherwise a hex string. `envelopeBegin/End` write the §6 envelope including `exit_code`.

```zig
//! output/json.zig — JSON conventions helpers every cmd/*.zig uses (so conventions cannot drift).
//! Imports: output/sink, core/diag, core/sanitize, core/file, core/image, core/fat.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;
const sink = @import("sink.zig");
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const FlagName = @import("../core/fmt.zig").FlagName;

pub const Error = sink.Error;

pub fn hex(js: *Stringify, key: []const u8, v: u64) Error!void;
pub fn hexOpt(js: *Stringify, key: []const u8, v: ?u64) Error!void;
/// Numbers: anything that fits 2^53 as a JSON number; larger u64 -> hex string.
pub fn int(js: *Stringify, key: []const u8, v: anytype) Error!void;
/// Sanitized string; when sanitisation changed bytes also writes `<key>_hex` with the originals and `<key>_lossy: true`.
pub fn str(js: *Stringify, arena: Allocator, key: []const u8, s: []const u8) Error!void;
pub fn strOpt(js: *Stringify, arena: Allocator, key: []const u8, s: ?[]const u8) Error!void;
pub fn bytesHex(js: *Stringify, key: []const u8, b: []const u8) Error!void;
pub fn bytesHexOpt(js: *Stringify, key: []const u8, b: ?[]const u8) Error!void;
pub fn uuid(js: *Stringify, key: []const u8, u: [16]u8) Error!void;
pub fn isoTime(js: *Stringify, key: []const u8, unix: ?i64) Error!void;
pub fn boolean(js: *Stringify, key: []const u8, b: bool) Error!void;
pub fn names(js: *Stringify, arena: Allocator, key: []const u8, list: []const []const u8) Error!void;
/// {"value":"0x200085","names":["NOUNDEFS",...]}
pub fn flags(js: *Stringify, key: []const u8, value: u64, table: []const FlagName) Error!void;
/// {"available": false, "reason": "..."}
pub fn unavailable(js: *Stringify, key: []const u8, reason: []const u8) Error!void;
pub fn diagnostics(js: *Stringify, d: *const Diagnostics) Error!void;
/// Opens one element of "arches": {"arch":"arm64","index":0,"offset_in_file":0,"size":50424,"cputype":"0x100000c","cpusubtype":"0x0","caps":"0x0",
pub fn beginArch(js: *Stringify, img: *const Image) Error!void;
pub fn endArch(js: *Stringify) Error!void;
/// {"machre":{"version","schema":1,"command","capstone","security"},"file":{path,size,sha256,mtime,container,fat{...},quarantine,xattrs,translocated},"arches":[
pub fn envelopeBegin(js: *Stringify, arena: Allocator, command: []const u8, file: *LoadedFile, xattr_json: ?*const anyopaque) Error!void;
/// ],"bundle":...,"diagnostics":[...],"diagnostics_dropped":n,"sanitized_strings":n,"exit_code":n}
pub fn envelopeEnd(js: *Stringify, d: *const Diagnostics, exit_code: u8, lossy: u32) Error!void;
/// Per-run tally of strings `str`/`strOpt`/`names` had to replace; `cli.dispatch` resets it and folds
/// it into `Sink.lossy` (threadlocal because `str` never sees the `Sink`).
pub fn lossyCount() u32;
pub fn resetLossyCount() void;
/// "truncated": true, "total": n  (after a --limit cut)
pub fn truncated(js: *Stringify, total: usize) Error!void;
```

```zig
//! output/text.zig — text helpers: aligned tables, key/value rows, flag joining, hexdump, diagnostics footer.
//! Imports: output/sink, core/diag, core/sanitize, core/fmt.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const FlagName = @import("../core/fmt.zig").FlagName;

pub const Align = enum { left, right };
pub const Col = struct { name: []const u8, @"align": Align = .left, max: u16 = 0 };
pub const Table = struct {
    arena: Allocator,
    columns: []const Col,
    rows: std.ArrayList([]const []const u8) = .empty,
    pub fn init(arena: Allocator, columns: []const Col) Table;
    pub fn row(t: *Table, cells: []const []const u8) Allocator.Error!void;
    pub fn rowFmt(t: *Table, comptime fmts: []const []const u8, args: anytype) Allocator.Error!void;
    pub fn render(t: *Table, out: *Io.Writer, indent: u8, limit: u32) Io.Writer.Error!void;
};
pub fn header(out: *Io.Writer, comptime fmt: []const u8, args: anytype) Io.Writer.Error!void;
/// "  key          value" — key padded to 13 columns (fixed so goldens diff byte for byte).
pub fn kv(out: *Io.Writer, indent: u8, key: []const u8, comptime fmt: []const u8, args: anytype) Io.Writer.Error!void;
/// "NOUNDEFS DYLDLINK TWOLEVEL PIE" (+ " 0x..." for unknown bits), joined by `sep`.
pub fn flags(arena: Allocator, value: u64, table: []const FlagName, sep: []const u8) Allocator.Error![]const u8;
pub fn hexdump(out: *Io.Writer, bytes: []const u8, base: u64, limit: u32) Io.Writer.Error!void;
/// Footer: "diagnostics  none" or up to 5 lines + "(N more, use --verbose)", then the "sanitized  N
/// file-derived strings needed sanitisation" tally. Diagnostic messages interpolate file-derived names,
/// so this is where every message is escaped (`.text` policy).
pub fn diagnostics(out: *Io.Writer, d: *const Diagnostics, verbose: bool, lossy: u32) Io.Writer.Error!void;
pub fn prot(buf: *[3]u8, p: u32) []const u8;
/// otool-style architecture banner: "<path> (architecture arm64):" when more than one slice is shown.
pub fn archBanner(out: *Io.Writer, path: []const u8, arch_name: []const u8, multi: bool) Io.Writer.Error!void;
```

### 4.29 `cli/args.zig`, `cli/context.zig`, `cli/cli.zig`, `cmd/<name>.zig`

**Imports:** args -> std; context -> limits, diag, file, image, arch, output/sink, cli/args; cli -> args, context,
output/*, core/*, analysis/analysis, cmd/*. `cli.zig` is dispatch + framing only (~600 lines): it never renders
a payload. Each `cmd/<name>.zig` exports `pub const command: Command` and `pub fn run(ctx: *Context) anyerror!u8`,
imports `cli/context.zig` (never `cli/cli.zig`), and owns both its text and its JSON rendering (through
`output/json.zig` helpers). `cli.runArgv` is the in-process entry used by golden/robustness tests.

```zig
//! cli/context.zig — leaf types shared by cli.zig and every cmd/*.zig (breaks the cmd <-> cli import cycle).
//! Imports: core/limits, core/diag, core/file, core/image, core/arch, output/sink, cli/args.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const ArchName = @import("../core/arch.zig").ArchName;
const Sink = @import("../output/sink.zig").Sink;
const Parsed = @import("args.zig").Parsed;

pub const ExitCode = enum(u8) {
    ok = 0,
    usage = 1,
    io = 2,
    not_macho = 3,
    strict_diagnostics = 4,
    limits = 5,
    feature_unavailable = 6,
    triage_threshold = 20,
    internal = 70,
};

pub const Context = struct {
    io: Io,
    gpa: Allocator,
    arena: Allocator, // per-analysis budgeted arena
    limits: *const Limits,
    diags: *Diagnostics,
    sink: *Sink,
    args: *const Parsed,
    command: []const u8,
    path: [:0]const u8,
    arch: ?ArchName,
    all_archs: bool,
    no_security: bool,
    no_network: bool,
    verbose: u8,
    strict: bool,
    paranoid: bool,
    otool_compat: bool,
    /// Loaded lazily by `cli.loadFile`; commands that only need xattrs/plist never parse images.
    file: ?*LoadedFile = null,
    images: []const Image = &.{},
    /// Set by commands; echoed as "exit_code" in the JSON envelope.
    exit_code: ExitCode = .ok,
};

pub const Command = struct {
    name: []const u8,
    summary: []const u8,
    run: *const fn (ctx: *Context) anyerror!u8,
    /// Command-specific flags (global flags are appended by cli.zig); value-taking flags end with "=".
    flags: []const []const u8,
    aliases: []const []const u8 = &.{},
    /// Needs a Mach-O image (exit 3 otherwise) — false for plist/bundle/quarantine/version.
    needs_macho: bool = true,
};
```

```zig
//! cli/args.zig — generic flag parser (--flag, --flag=value, --flag value, -v, --). Imports: std only.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Parsed = struct {
    positionals: []const [:0]const u8,
    flags: []const Flag,
    pub const Flag = struct { name: []const u8, value: ?[:0]const u8 };

    pub fn flag(p: *const Parsed, name: []const u8) bool;
    pub fn value(p: *const Parsed, name: []const u8) ?[:0]const u8;
    /// base 0 (0x prefix ok)
    pub fn valueInt(p: *const Parsed, comptime T: type, name: []const u8) error{InvalidValue}!?T;
    pub fn values(p: *const Parsed, arena: Allocator, name: []const u8) Allocator.Error![]const [:0]const u8;
    /// Count of a repeatable boolean flag (-v -v / --verbose --verbose).
    pub fn count(p: *const Parsed, name: []const u8) u8;
    /// First flag not in `known` -> usage error.
    pub fn unknown(p: *const Parsed, known: []const []const u8) ?[]const u8;
};
/// `argv` excludes argv[0] and the command name. Flags named "--foo"; `-v` maps to "--verbose", `-q` to "--quiet".
pub fn parse(arena: Allocator, argv: []const [:0]const u8, value_flags: []const []const u8) Allocator.Error!Parsed;

//! cli/cli.zig — dispatch + framing only: global flags, exit-code policy, file loading, arch selection,
//! envelope begin/end, usage text. Imports: cli/args, cli/context, output/*, core/*, analysis/analysis, cmd/*.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const context = @import("context.zig");
pub const Context = context.Context;
pub const Command = context.Command;
pub const ExitCode = context.ExitCode;
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;

const cmd = struct {
    const info = @import("../cmd/info.zig");
    const header = @import("../cmd/header.zig");
    const loadcmds = @import("../cmd/loadcmds.zig");
    const segments = @import("../cmd/segments.zig");
    const symbols = @import("../cmd/symbols.zig");
    const dyld = @import("../cmd/dyld.zig");
    const imports = @import("../cmd/imports.zig");
    const exports = @import("../cmd/exports.zig");
    const codesign = @import("../cmd/codesign.zig");
    const entitlements = @import("../cmd/entitlements.zig");
    const objc = @import("../cmd/objc.zig");
    const strings = @import("../cmd/strings.zig");
    const entropy = @import("../cmd/entropy.zig");
    const plist = @import("../cmd/plist.zig");
    const bundle = @import("../cmd/bundle.zig");
    const quarantine = @import("../cmd/quarantine.zig");
    const disasm = @import("../cmd/disasm.zig");
    const functions = @import("../cmd/functions.zig");
    const xrefs = @import("../cmd/xrefs.zig");
    const triage = @import("../cmd/triage.zig");
    const dump = @import("../cmd/dump.zig");
    const report = @import("../cmd/report.zig");
    const version = @import("../cmd/version.zig");
};

pub const commands: []const Command = &.{
    cmd.info.command,       cmd.header.command,   cmd.loadcmds.command, cmd.segments.command,
    cmd.symbols.command,    cmd.dyld.command,     cmd.imports.command,  cmd.exports.command,
    cmd.codesign.command,   cmd.entitlements.command, cmd.objc.command, cmd.strings.command,
    cmd.entropy.command,    cmd.plist.command,    cmd.bundle.command,   cmd.quarantine.command,
    cmd.disasm.command,     cmd.functions.command, cmd.xrefs.command,   cmd.triage.command,
    cmd.dump.command,       cmd.report.command,   cmd.version.command,
};
pub const global_flags: []const []const u8 = &.{
    "--json", "--arch=", "--all-archs", "--verbose", "--limit=", "--no-security", "--no-network", "--strict",
    "--paranoid", "--max-file-size=", "--color=", "--otool-compat", "--quiet", "--json-compact",
};

/// Entry point: parses global flags, builds Context, dispatches, maps errors to exit codes (DESIGN.md §5).
pub fn run(init: std.process.Init) u8;
/// In-process runner used by tests: argv excludes argv[0]; output goes to `out`; returns the exit code.
pub fn runArgv(gpa: Allocator, io: Io, argv: []const [:0]const u8, out: *Io.Writer, err: *Io.Writer) u8;
pub fn findCommand(name: []const u8) ?*const Command;
/// Shared prologue: load the file (bundle -> its main executable), select arches, parse one Image per arch.
/// Returns null after emitting the not-Mach-O envelope/exit code when the command needs an image.
pub fn loadImages(ctx: *Context) anyerror!?[]const Image;
/// One Analysis per image, sharing ctx.arena/limits/diags and the ctx options.
pub fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis;
/// Text: prints the arch banner when multiple slices are shown; JSON: json.beginArch.
pub fn beginArch(ctx: *Context, img: *const Image, multi: bool) anyerror!void;
pub fn endArch(ctx: *Context) anyerror!void;
pub fn usage(out: *Io.Writer, command: ?*const Command) Io.Writer.Error!void;
pub const version_string: []const u8 = build_options.version;

// every cmd/<name>.zig:
//! cmd/info.zig — one-screen summary: container, header, platform, entry, dylibs, segments, symbol counts, signature summary, quarantine. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;

pub const command: Command = .{
    .name = "info",
    .summary = "one-screen summary: container, header, platform, entry, dylibs, segments, symbol counts, signature summary, quarantine",
    .run = run,
    .flags = &.{"--no-hash"},
    .aliases = &.{},
    .needs_macho = true,
};
/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8;
```

### 4.30 `core/version.zig` and `core/macho_extra.zig`

**Imports:** version -> fmt; macho_extra -> std. Name tables are data (owned by WP0). `mh_flags` uses the
`otool -hv` spelling (`NOUNDEFS DYLDLINK TWOLEVEL PIE`), `mh_flags_full` the summary.json spelling
(`MH_NOUNDEFS`); `cs_flags` uses codesign's (`adhoc,linker-signed,runtime`), `cs_flags_full` summary.json's
(`CS_ADHOC`). `macho_extra.zig` is quoted in full in the skeleton (structs with comptime size asserts:
`fat_arch_64` 32, `encryption_info_command_64` 24, `dylib_use_command` 28, `dyld_chained_fixups_header` 28,
`note_command` 40, `routines_command_64` 72; ObjC field offsets; CS_*/CSSLOT_*/DYLD_CHAINED_* constants).

```zig
//! core/version.zig — name tables for every Mach-O / code-signing enum. Imports: std, core/fmt.
const std = @import("std");
const fmt = @import("fmt.zig");
pub const FlagName = fmt.FlagName;

/// "LC_SEGMENT_64" ...; null for unknown values (callers print "LC_?(0x..)").
pub fn lcName(cmd: u32) ?[]const u8;
/// Always yields a name: "LC_SEGMENT_64" or "LC_?(0x39)".
pub fn lcNameBuf(buf: *[32]u8, cmd: u32) []const u8;
pub fn filetypeName(ft: u32) ?[]const u8;
pub fn platformName(p: u32) ?[]const u8;
pub fn toolName(t: u32) ?[]const u8;
pub fn cpuTypeName(cputype: i32) ?[]const u8;
pub fn sectionTypeName(t: u8) ?[]const u8;
pub fn stabName(n_type: u8) ?[]const u8;
pub fn pointerFormatName(pf: u16) ?[]const u8;
pub fn importFormatName(f: u32) ?[]const u8;
pub fn diceKindName(kind: u16) ?[]const u8;
pub fn csSlotName(slot: u32) ?[]const u8;
pub fn csMagicName(magic: u32) ?[]const u8;
pub fn csSpecialSlotName(index: u32) ?[]const u8;
pub fn csHashTypeName(t: u8) ?[]const u8;
pub fn magicName(magic: u32) ?[]const u8;
/// dyld_info-style short name: "/usr/lib/libSystem.B.dylib" -> "libSystem", ".../Foundation.framework/Versions/C/Foundation" -> "Foundation".
pub fn dylibShortName(path: []const u8) []const u8;
/// Flag tables (bit, name) in the spelling of the reference tool named in the comment.
pub const mh_flags: []const FlagName = &.{}; // otool -hv spelling: NOUNDEFS DYLDLINK TWOLEVEL PIE ...
pub const mh_flags_full: []const FlagName = &.{}; // summary.json spelling: MH_NOUNDEFS ...
pub const sg_flags: []const FlagName = &.{}; // SG_HIGHVM ... SG_READ_ONLY
pub const s_attr_flags: []const FlagName = &.{}; // S_ATTR_PURE_INSTRUCTIONS ...
pub const cs_flags: []const FlagName = &.{}; // codesign spelling: adhoc linker-signed runtime ... (CD flags)
pub const cs_flags_full: []const FlagName = &.{}; // summary.json spelling: CS_ADHOC CS_LINKER_SIGNED ...
pub const exec_seg_flags: []const FlagName = &.{}; // main-binary allow-unsigned debugger jit skip-lv can-load-cdhash can-exec-cdhash
pub const n_desc_flags: []const FlagName = &.{}; // REFERENCED_DYNAMICALLY N_WEAK_REF N_WEAK_DEF ...
pub const export_flags: []const FlagName = &.{}; // WEAK_DEFINITION REEXPORT STUB_AND_RESOLVER STATIC_RESOLVER
pub const objc_ro_flags: []const FlagName = &.{}; // RO_META RO_ROOT ... RO_IS_ARC
pub const objc_image_info_flags: []const FlagName = &.{};
```

---

## 5. CLI spec

```
machre <command> [global flags] [command flags] <path>
machre help [command]          machre version
```

### 5.1 Commands (every one supports `--json`; `needs_macho=false` commands accept any path)

Two mirror columns, because they answer different questions. **byte-compatible mirror** is a promise the
golden rows keep: `machre <cmd> --otool-compat [flags] <path>` and the named Apple command produce output a
`diff` reports as identical on healthy input (§5.6 enumerates the only sanctioned exceptions). **cf.** is a
tool that answers the same question in its own format — useful for cross-checking a fact, never for a diff.

| command | purpose | command flags | byte-compatible mirror (with `--otool-compat`) | cf. (same question, different format) |
|---|---|---|---|---|
| `info` | one-screen summary: container, header, platform, entry, dyld style, dylibs, segments, symbol counts, signature summary, security line, quarantine | `--no-hash` | — (machre's own layout) | `otool -hv`, `dyld_info -platform -uuid -segments -linked_dylibs`, `vtool -show` |
| `header` | Mach header (fat table first for universal files) | `--fat` | `otool -hv`; `--fat` = `lipo -detailed_info` | — |
| `loadcmds` (alias `headers`) | every load command decoded, unknown commands hex-dumped | `--raw` | `otool -h -l` — machre always prints the Mach header first, so bare `otool -l` does **not** match | — |
| `segments` | segments + sections: prot, flags, type, reserved1/2, class, entropy | `--entropy` | — (no Apple tool prints this table) | `otool -l`, `size -m` |
| `symbols` (alias `nm`) | nlist table with stab decoding, library ordinals, indirect table | `--defined --undefined --stabs --indirect --sort=addr\|name --filter=<substr> --mode=nm\|nm-m\|nm-a\|machre` (default nm-m) | `nm -m` (the default mode); `--mode=nm` = `nm`; `--mode=nm-a` = `nm -a` | — |
| `dyld` (alias `fixups`) | chained-fixups header/starts/imports or legacy opcode streams, function starts, data-in-code | `--fixups --chains --opcodes --function-starts --data-in-code --raw` | `--fixups` = `dyld_info -fixups`; `--chains` = `dyld_info -fixup_chains`; `--function-starts` = `dyld_info -function_starts` | `--opcodes` and `--data-in-code` have no Apple equivalent |
| `imports` | imported symbols with dylib attribution + dependency resolution | `--resolve` (default on macOS) `--no-resolve --by-dylib` | `dyld_info -imports` | `otool -L` — which lists the *dylibs*, not the imported symbols, and is **not** a diff target |
| `exports` | export trie / defined external symbols | `--trie` | `dyld_info -exports` | — |
| `codesign` | embedded signature (Zig) + page-hash verification + requirements + entitlements summary + CMS chain + Security.framework verdict + trust ladder | `--entitlements --requirements --hashes --cms --der --no-verify-pages` | `codesign -dvvv` (which writes to **stderr**); `--requirements` = `codesign -d -r -` | `codesign --verify` |
| `entitlements` | XML and/or DER entitlements, dangerous-key annotations | `--xml --der --keys` | `--xml` = `codesign -d --entitlements - --xml` | `codesign -d --entitlements -` (Apple's `[Dict]`/`[Key]` dump, a different format) |
| `objc` | classes/methods/ivars/properties, categories, protocols, selectors, stubs, imageinfo/Swift | `--classes --categories --protocols --selectors --methods --stubs` | — | `dyld_info -objc`, `objdump --macho --objc-meta-data` |
| `strings` | strings by kind with address/section/class | `--min=<n>` (4) `--kind=cstring,ustring,cfstring,objc,info_plist,generic --no-generic --dedupe --bare --class=<c>` | `strings -n <min>` on the file (no `-`, so strings(1) walks sections, not the raw file); `--otool-compat` implies `--bare` | — |
| `entropy` | per-segment/section entropy and packer/encryption tells | `--sections` | — | — |
| `plist` | parse a .plist file, `__TEXT,__info_plist`, or `Contents/Info.plist` | `--format=auto\|bplist\|xml --key=<dotted.path>` | `plutil -p` | — |
| `bundle` | bundle layout, Info.plist essentials, nested code, CodeResources verification, ticket, Security verdict, xattrs | `--files --nested --no-verify --spctl` (opt-in `spctl -a -vv -t exec` subprocess) | — | `codesign -dvvv`, `spctl`, `find` |
| `quarantine` | xattrs, parsed `com.apple.quarantine`, translocation | — | `xattr -l` (key-prefixed lines) — **not** `xattr -p <name>`, which prints the bare value | — |
| `disasm` | disassembly with symbolization | `--func=<name\|addr> --addr=<start>[-<end>\|+<len>] --section=<seg>,<sect> --all --backend=auto\|capstone\|builtin --att\|--intel --no-annotate --bytes --count=<n>` | `otool -tV` over the default `__TEXT,__text` (`--all` adds sections otool never disassembles); §5.6 lists the sanctioned divergences | — |
| `functions` | discovered functions with source and size | `--sort=addr\|name\|size` | `dyld_info -function_starts` | — |
| `xrefs` | cross-references to/from an address or symbol, or the whole table | `--to=<addr\|sym> --from=<addr\|sym> --strings --no-pointer-slots` | — | — |
| `triage` | scored anomaly report + level | `--fail-on=notable\|suspicious\|likely_malicious --explain --spctl` | — | KnockKnock / WhatsYourSign |
| `dump` | hexdump of a section or vm/file range | `--section=<seg>,<sect> --addr=<start>[+len] --offset=<fileoff>[+len] --length=<n>` | — | `otool -s` (byte-swapped 32-bit words, no ASCII column), `xxd` (file offsets, 2-byte groups) |
| `report` (alias `all`) | every payload in one document (text: `info` + `codesign` + `imports` summary + `triage`) | `--only=<cmd,cmd,...>` | — | — |
| `version` | tool version, zig version, capstone/security availability | — | — | — |

Thirteen commands have a byte-compatible mirror: `header`, `loadcmds`, `symbols`, `dyld`, `imports`,
`exports`, `functions`, `codesign`, `entitlements`, `strings`, `quarantine`, `plist`, `disasm`. Those
thirteen are exactly the commands whose renderer reads `ctx.otool_compat` at all. For nine of the other ten —
`info`, `segments`, `objc`, `entropy`, `bundle`, `xrefs`, `triage`, `dump`, `version` — `--otool-compat`
changes nothing in the payload; `report` is the tenth and changes only because it embeds the `codesign`
section, which drops its `--- machre: … ---` blocks.

`--otool-compat` always does two things regardless of command: it suppresses the trailing `diagnostics`
footer (exactly as `-q` does, `cli.zig:276`) and the `N architectures, showing <arch> (use --all-archs)`
notice (`cli.zig:360`), because no Apple tool prints them. Measured: with `-q` already given,
`diff <(machre <cmd> -q F) <(machre <cmd> -q --otool-compat F)` is empty for all nine of those commands
(and for `symbols` in its default `nm-m` mode). On arm64 `--otool-compat` additionally forces `disasm` onto
the built-in text backend even when Capstone is linked, because the spelling must be otool's (§9,
`engine.zig:60`).

Bundles: any command given an `.app`/`.framework`/`.xpc`/`.appex` directory analyses the main executable
(`bundle.mainExecutable`) for Mach-O commands, and the bundle itself for `bundle`, `codesign`, `triage`, `report`.

### 5.2 Global flags (parsed by `cli/args.zig`; every command accepts them)

| flag | meaning |
|---|---|
| `--json` | JSON envelope (§6) on stdout; text otherwise. `--json-compact` = minified |
| `--arch <name>` | analyse only the slice whose `ArchName` matches (`x86_64 x86_64h i386 arm64 arm64v8 arm64e arm64_32 …`); exit 3 if absent |
| `--all-archs` | analyse every valid slice (JSON default). **Text default = the slice with the best `Arch.preferenceRank` against the host (exact host name, then same cputype, then first valid)**; when a fat file has more than one slice the text output starts with `N architectures, showing <arch> (use --all-archs)` and `--all-archs` prints otool-style `<path> (architecture <arch>):` banners |
| `-v`, `--verbose` (repeatable) | more rows/columns; `-v` prints every diagnostic (default: <= 5 + count); `-vv` adds budget/peak memory and per-stage timing |
| `-q`, `--quiet` | suppress the diagnostics footer |
| `--limit <n>` | cap rows in long tables (symbols, strings, fixups, exports, xrefs, instructions); `0` = unlimited (default 0 for JSON, 500 for text) |
| `--no-security` | never call Security.framework; pure-Zig results only (`security: {available:false, reason:"--no-security"}`); triage uses the offline ladder |
| `--no-network` | keep Security.framework but pass `kSecCSNoNetworkAccess` and skip revocation (`revocation_checked:false`) |
| `--strict` | exit 4 when any error-severity diagnostic was recorded (output still produced) |
| `--paranoid` | use `Limits.paranoid` |
| `--max-file-size <bytes>` | override `Limits.max_file_size` (default 2 GiB) |
| `--otool-compat` | suppress machre-only annotations/columns so text diffs cleanly against Apple tools; also suppresses the `diagnostics` footer and the multi-slice notice. The diff contract and its six sanctioned divergences are **§5.6**; the golden rows that enforce it are §10.4 |
| `--color=auto\|always\|never` | ANSI colour (auto: `Io.File.isTty`) |

### 5.3 Exit codes (`cli/context.ExitCode`; echoed as `"exit_code"` in JSON)

| code | meaning |
|---|---|
| 0 | success (diagnostics may have been printed) |
| 1 | usage error (unknown command/flag, bad value, missing path); usage on stderr |
| 2 | file not found / permission denied / I/O error |
| 3 | not a Mach-O and the command needs one; `--arch` not present; fat file with no valid slice |
| 4 | `--strict` and at least one error-severity diagnostic |
| 5 | input exceeds `--max-file-size`, or a Limits cap made the analysis incomplete under `--strict` |
| 6 | feature unavailable (`--backend=capstone` on a build without Capstone; `--spctl` off-macOS) |
| 20 | `triage --fail-on` threshold reached |
| 70 | internal error (OOM past the arena budget, unexpected error); message names the module; never a trap in ReleaseSafe |

### 5.4 Text formats for the representative commands (hello-c; values from `truth/summary.json`, `otool -tV`, `codesign -dvvv`)

Fixed column layout: `text.kv` pads keys to 13 columns; tables are rendered by `text.Table`; the address /
mnemonic / operands columns of listings are TAB-separated exactly like `otool -tV`.

**`machre info tests/corpus/hello-c`**

```
tests/corpus/hello-c: Mach-O 64-bit executable arm64 (thin), 50424 bytes
  sha256       a448ac67a4409dabf8b4955f2ee86d9baff77d143bf1ff702faaa260379b15c5
  magic        0xfeedfacf MH_MAGIC_64   cputype 0x100000c (arm64)   cpusubtype 0x0 (ALL)   caps 0x00
  filetype     2 MH_EXECUTE   ncmds 18   sizeofcmds 1208
  flags        0x200085 (NOUNDEFS,DYLDLINK,TWOLEVEL,PIE)
  uuid         21C9F585-96F5-3A4C-A516-BBBE1808D26E
  platform     macOS   minos 26.0   sdk 26.5   tools ld 1267.0
  source ver   0.0
  dylinker     /usr/lib/dyld
  entry        LC_MAIN entryoff 0x524 -> 0x100000524 (_main)   stacksize 0
  dyld data    chained fixups (format 6 DYLD_CHAINED_PTR_64_OFFSET, 6 imports, 7 fixups)   exports trie (5)   function starts (3)
  dylibs       1
    1  /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1356.0.0)
  segments     5
    __PAGEZERO    vm 0x0+0x100000000        file 0+0          ---/---  0 sects
    __TEXT        vm 0x100000000+0x4000     file 0+16384      r-x/r-x  4 sects
    __DATA_CONST  vm 0x100004000+0x4000     file 16384+16384  rw-/rw-  1 sect   READ_ONLY
    __DATA        vm 0x100008000+0x4000     file 32768+16384  rw-/rw-  1 sect
    __LINKEDIT    vm 0x10000c000+0x4000     file 49152+1272   r--/r--  0 sects
  symbols      12 (6 defined, 6 undefined, 0 stabs)   indirect 11
  signature    ad hoc, linker-signed   identifier "hello-c"   cdhash f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b   pages 13/13 ok
  security     valid (errSecSuccess)   trust: ad hoc   notarized: no
  quarantine   none
  diagnostics  none
```

**`machre codesign tests/corpus/hello-c`** — lines 1–14 are `codesign -dvvv` verbatim (graft from C); the
`--- machre:` sections are additive; `--otool-compat` prints only lines 1–14.

```
Executable=/Users/bcann/programming/mac-security/machre/tests/corpus/hello-c
Identifier=hello-c
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=512 flags=0x20002(adhoc,linker-signed) hashes=13+0 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b
CandidateCDHashFull sha256=f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5bc2b929d3ce74736ef9fd4416
Hash choices=sha256
CDHash=f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
--- machre: embedded signature (LC_CODE_SIGNATURE dataoff=49888 datasize=536) ---
SuperBlob magic=0xfade0cc0 length=532 count=1
  slot 0x0     CodeDirectory   offset 20    length 512  magic 0xfade0c02
CodeDirectory page size=4096 (2^12)  code limit=49888  code slots=13  special slots=0  platform=0
  exec segment base=0x0 limit=0x134 flags=0x1 (main-binary)
  page hashes: 13/13 match the file on disk
Designated requirement (synthesized, no requirements blob):
  designated => cdhash H"f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b"
Entitlements: none (no XML blob, no DER blob)
Certificates: none (no CMS blob)
--- machre: Security.framework ---
SecStaticCodeCheckValidity(kSecCSCheckAllArchitectures | kSecCSEnforceRevocationChecks)   = 0 errSecSuccess
  anchor apple                                                     = -67050 errSecCSReqFailed
  anchor apple generic                                             = -67050 errSecCSReqFailed
  Developer ID (certificate leaf[field.1.2.840.113635.100.6.1.13]) = -67050 errSecCSReqFailed
  Mac App Store (certificate leaf[field.1.2.840.113635.100.6.1.9]) = -67050 errSecCSReqFailed
  notarized                                                        = -67050 errSecCSReqFailed
kSecCodeInfoFlags=0x20002  kSecCodeInfoFormat="Mach-O thin (arm64)"  kSecCodeInfoIdentifier="hello-c"
Trust ladder: AD HOC (linker-signed) -- signature proves integrity only, not identity
```

For a Developer ID app the `Authority=`, `Timestamp=`, `TeamIdentifier=`, `Runtime Version=` lines appear in
codesign's order (from the CMS parser), and the ladder line reads `DEVELOPER ID, notarized (stapled ticket
present)`. `fake-upx` renders `page hashes: 12/13 match; first mismatch page 0 (file offset 0x0)` and
`Trust ladder: INVALID (errSecCSSignatureFailed -67061)`. (Corrected at integration: `gen/malform.py`
renames the segment in the load commands, so the only page the edit touches is page 0.) With `--no-security` the last block is replaced by
`Security.framework: not evaluated (--no-security); offline ladder (unverified): AD HOC`.

**`machre disasm --func _main tests/corpus/hello-c`** — every line except `…554` is byte-identical to
`otool -tV` (address TAB mnemonic TAB operands, `;` comments included). `…554` carries machre's one-level data
annotation (symbol, rebase target and the pointed-to string, graft from C); `--otool-compat` drops it and prints
`bl _add_numbers` / `bl _static_helper` for direct calls, so the listing diffs empty against otool. 58
instructions (0x100000524–0x10000060c, 232 bytes).

```
tests/corpus/hello-c:
(__TEXT,__text) section
_main:
0000000100000524	sub	sp, sp, #0x90
0000000100000528	stp	x29, x30, [sp, #0x80]
000000010000052c	add	x29, sp, #0x80
0000000100000530	adrp	x8, 4 ; 0x100004000
0000000100000534	ldr	x8, [x8, #0x10] ; literal pool symbol address: ___stack_chk_guard
0000000100000538	ldr	x8, [x8]
000000010000053c	stur	x8, [x29, #-0x8]
0000000100000540	mov	w2, #0x0
0000000100000544	str	wzr, [sp, #0x34]
0000000100000548	str	w0, [sp, #0x30]
000000010000054c	str	x1, [sp, #0x28]
0000000100000550	adrp	x8, 8 ; 0x100008000
0000000100000554	ldr	x10, [x8, #0x8] ; _greeting -> 0x100000668 "hello from machre corpus"
0000000100000558	ldr	w8, [sp, #0x30]
000000010000055c	mov	x9, sp
0000000100000560	str	x10, [x9]
0000000100000564	str	x8, [x9, #0x8]
0000000100000568	add	x0, sp, #0x38
000000010000056c	str	x0, [sp, #0x20]
0000000100000570	mov	x3, #0x40
0000000100000574	mov	x1, x3
0000000100000578	adrp	x4, 0 ; 0x100000000
000000010000057c	add	x4, x4, #0x681 ; literal pool for: "%s (%d args)"
0000000100000580	bl	0x10000062c ; symbol stub for: ___snprintf_chk
0000000100000584	ldr	x0, [sp, #0x20]
0000000100000588	bl	0x100000650 ; symbol stub for: _puts
000000010000058c	ldr	w8, [sp, #0x30]
0000000100000590	subs	w8, w8, #0x1
0000000100000594	b.le	0x1000005c8
0000000100000598	b	0x10000059c
000000010000059c	ldr	x8, [sp, #0x28]
00000001000005a0	ldr	x0, [x8, #0x8]
00000001000005a4	adrp	x1, 0 ; 0x100000000
00000001000005a8	add	x1, x1, #0x68e ; literal pool for: "exit"
00000001000005ac	bl	0x10000065c ; symbol stub for: _strcmp
00000001000005b0	cbnz	w0, 0x1000005c8
00000001000005b4	b	0x1000005b8
00000001000005b8	mov	w0, #0x1
00000001000005bc	mov	w1, #0x2
00000001000005c0	bl	0x1000004f8 ; _add_numbers
00000001000005c4	bl	0x100000644 ; symbol stub for: _exit
00000001000005c8	ldr	w0, [sp, #0x30]
00000001000005cc	bl	0x10000060c ; _static_helper
00000001000005d0	mov	w8, #0x0
00000001000005d4	and	w8, w0, w8
00000001000005d8	str	w8, [sp, #0x1c]
00000001000005dc	ldur	x9, [x29, #-0x8]
00000001000005e0	adrp	x8, 4 ; 0x100004000
00000001000005e4	ldr	x8, [x8, #0x10] ; literal pool symbol address: ___stack_chk_guard
00000001000005e8	ldr	x8, [x8]
00000001000005ec	subs	x8, x8, x9
00000001000005f0	b.eq	0x1000005fc
00000001000005f4	b	0x1000005f8
00000001000005f8	bl	0x100000638 ; symbol stub for: ___stack_chk_fail
00000001000005fc	ldr	w0, [sp, #0x1c]
0000000100000600	ldp	x29, x30, [sp, #0x80]
0000000100000604	add	sp, sp, #0x90
0000000100000608	ret
```

Header lines: `NAME:` for named functions, `sub_1000004f8:` for unnamed ones; `--all` walks every function in
`functions` order. The arm64 text above is the built-in decoder's spelling (disasm-notes B.1 = otool's); with
Capstone linked the default listing uses Capstone's text (`mov w0, #1`, `b.le #0x1000005c8`) and identical
address/kind/target/comment columns, while `--otool-compat` and `--backend=builtin` select the built-in text so
the listing is byte-identical in every build (that is what the goldens use). x86_64 without Capstone prints the
header `(__TEXT,__text) section [builtin x86 length decoder: mnemonics limited]` and `partial: true` in JSON.

### 5.5 `machre triage tests/corpus/fake-upx` (KnockKnock-style; graft from C, levels from A)

```
machre triage: tests/corpus/fake-upx [arm64]
LEVEL: SUSPICIOUS (score 60, 2 categories)            trust: INVALID SIGNATURE
Signing     [HIGH]   sig.invalid       embedded CodeDirectory does not match the file: 1/13 page hashes mismatch (first page 0 @ 0x0); Security: errSecCSSignatureFailed (-67061)
Packing     [MEDIUM] pack.names        segment named UPX_DATA (UPX marker) at LC index 2
Signing     [LOW]    sig.adhoc         ad hoc, linker-signed; no certificate chain, not notarized
Corroboration: packing tell (UPX_DATA) is corroborated by a broken signature -> file was modified after linking.
Not flagged: entropy (max 5.16 __LINKEDIT), imports present (6), symbols present (12), no quarantine xattr, PIE, no RWX segment.
```

(The two numbers above were corrected at integration against the shipped `tests/corpus/fake-upx`: it has
exactly one bad page hash, page 0, because `gen/malform.py` renames `__DATA_CONST` (and its sections) to
`UPX_DATA` in the load commands, which all live in page 0; its highest-entropy segment is `__LINKEDIT` at
5.160 bits/byte. The layout — category
column 12, `[SEV]` 9, id 18, the trust word at column 54 — is what the golden pins.)

`hello-c` prints `LEVEL: CLEAN (score 3, 1 category)` with `Signing [LOW] sig.adhoc` and a `Not flagged:` line;
`hello-unsigned` prints `LEVEL: NOTABLE (score 25, 1 category)` and exits 0 unless `--fail-on=notable`.

### 5.6 `--otool-compat`: the parity contract and its six sanctioned divergences

`--otool-compat` is a **diff contract**, not a promise of identity. Three separate reviews drew the line in
three different places because the rule was only implied (§7 item 11 and the `isDataPseudo` comment in
`tests/facts/disasm.zig`), so it is enumerated here and nowhere else.

**The contract.** For healthy input, `machre <cmd> --otool-compat [flags] <path>` diffs empty against the
Apple command named in the §5.1 "byte-compatible mirror" column, *except* for the five classes below. A diff
harness MUST score a difference that falls into one of these classes as **PASS**; anything else is a defect
and must fail the run. Classes (a) and (b) apply to every command; (c), (d) and (e) are `disasm` only.

---

**(a) Same-address symbol aliases — otool's pick is not derivable, so parity here is unattainable.**

When several symbols share one address, otool labels the address with *one* of them, and which one is not a
function of the nlist table. Two measurements:

* *Controlled experiment.* An arm64 fixture with a five-name alias group (`_t0.._t4`, all at one address, in
  that symtab order every time) plus **N unrelated filler symbols defined elsewhere in `__text`**. The alias
  group is byte-identical across every build; only the fillers change. otool's pick cycles:

  | unrelated fillers | otool labels the group |
  |---|---|
  | *(none)* | `_t1` |
  | `_a02` | `_t2` |
  | `_a03,_a02` | `_t3` |
  | `_a00,_a02` | `_t3` |
  | `_a03,_a02,_a03b` | `_t2` |
  | `_a03,_a02,_a00,_a02b,_a01` | `_t2` |
  | seven fillers | `_t4` |

  The choice is a side effect of how otool's whole-table sort/hash happens to order equal keys, so no rule
  over the alias group alone can reproduce it.
* *Population check.* `/usr/lib/dyld` (arm64e) has **129 otool-labelled addresses that carry more than one
  symtab name** (129 alias groups); in **26** of them otool's pick is neither the first nor the last name in
  symtab order. The largest group has **40 aliases and otool picks the 25th** (0-based index 24,
  `__ZN3lsl5BTree…prepareForInsertionEv.cold.3`).
  Reproduce with `nm -p -arch arm64e /usr/lib/dyld` (symtab order, unsorted) joined against the labels in
  `otool -tV -arch arm64e /usr/lib/dyld`.

  **Conclusion: byte-exact parity at an aliased address is UNATTAINABLE and must not be chased.** machre's
  rule is deterministic and written down instead (`disasm/functions.zig:230-246 noteName`): the **first**
  name recorded at an address wins, and the symbol table is walked in symtab order, so that is the **lowest
  symtab index**; a higher-priority source replaces it (symbol > export > objc); at equal rank an external
  symbol replaces a local one. On the seven fixtures of the table above machre labels the group `_t0` every
  single time, while otool cycles `_t1/_t2/_t3/_t4`.

  A diff harness confirms the class by checking that machre's name and otool's name resolve to the **same
  address** in the symbol table; only a name that is *not* an alias of otool's is a defect.

**(b) Control-byte escaping — machre escapes what otool emits raw.** (§7 item 11.)

Rendering is the last place a hostile file acts, through the analyst's terminal: a 16-byte segment name
holding `ESC [ 31 m … CR` recolours the output and overwrites the line above it. Every file-derived string
reaches text output through `Sink.safe`/`Sink.safeMax`, so machre escapes C0 controls, DEL and invalid UTF-8
where otool passes them through. `tests/sanitize_tests.zig:185` asserts the invariant holds *with*
`--otool-compat` too ("`--otool-compat` is byte-exactness with Apple's tools for healthy input only; on
hostile input the escaping wins"). A diff over a fixture containing control bytes is therefore expected to
differ; the diff harness must only run parity rows on healthy fixtures, and score any control-byte
difference as PASS.

**(c) Data records where otool mis-decodes data as instructions.**

x86_64 inline switch tables are 32-bit self-relative case offsets sitting inside `__TEXT,__text` with **no**
`LC_DATA_IN_CODE` entry to mark them (`/bin/ls` x86_64: `LC_DATA_IN_CODE` has `datasize 0`). otool decodes
them as code and then loses the instruction stream. machre recognises the table
(`disasm/engine.zig:152 emitJumpTable` — emit `.long` while each entry still points inside the enclosing
range, stop at the first one that does not) and resynchronises. `/bin/ls` x86_64, table at `0x1000014b0`:

```
machre                              otool -tV
0x1000014b0  .long 0xfffff66d       0x1000014b0  insl  %dx, %es:(%rdi)
0x1000014b4  .long 0xfffffb2e       0x1000014b1  idivb %bh
       …  (91 entries) …           0x1000014b3  ljmpl *(%rsi)
0x100001620  pushq %rbp             0x100001616  .byte 0xff #bad opcode
0x100001621  movq  %rsp, %rbp       0x10000161b  jmpq  *0x55fffff8(%rax)   <- 6 bytes, swallows 0x100001620
```

machre lands on the real function prologue at `0x100001620`; otool is still misaligned there. Records emitted
this way carry `kind = .data`, `valid = true` and a resolved `target`, so JSON consumers can tell them from
real instructions.

**arm64 inline data (`disasm/inline_data.zig`).** The same class, different mechanism. arm64 has no
`LC_DATA_IN_CODE` either — measured 0 entries on /usr/lib/dyld, /bin/ls, /usr/bin/plutil and
/usr/libexec/locationd (arm64e) — and no ELF `$d` mapping symbol, so inline tables must be inferred.

The rule is **positive evidence only**: a region is data when code takes its address (`ADR`, or a `LDR`
literal) and **nothing branches to it** and control cannot fall into it. `LC_FUNCTION_STARTS` is not treated
as proof of code — it is an atom-boundary table and it lists the dyld table below as a "function start".

dyld inlines a 16-byte NEON permute table (`00 01 … 0f`) at `0x1e20`, named by `adr x3, #0x1e20` from two
sites and preceded by four `udf` traps:

```
machre                                 otool -tV
0x1e20  .long 0x03020100               0x1e20  .long 0x03020100
0x1e24  .long 0x07060504               0x1e24  .long 0x07060504
0x1e28  .long 0x0b0a0908               0x1e28  add w8, w8, w10, lsl #2   <- data, decoded as code
0x1e2c  .long 0x0f0e0d0c               0x1e2c  .long 0x0f0e0d0c
0x1e30  udf #0                         0x1e30  udf #0x0                  <- padding, not swallowed
```

The third word is why the pass exists: `0x0b0a0908` is a valid encoding, so otool renders a table entry as
an ordinary `add`. Whole-section measurement: 28 words across 7 copies of that table, and **zero** marked
words in any of ~40 other system binaries; otool agrees on 21 of the 28 and the 7 disagreements are all that
same `add`.

**A trigger that was tried and removed — do not reintroduce it.** An earlier draft also promoted any run of
>= 4 consecutive words the decoder could not name. On dyld that mislabelled ~52 words of a real SHA-256
routine (`sha256h.4s`, `sha256su1.4s`, `rev32.16b`) as data, because the built-in decoder does not implement
the crypto extensions. `valid == false` means *"this decoder cannot name it"*, never *"this is not code"* —
and it is precisely the signal that moves when decoder coverage grows, so a rule keyed on it rots silently.
Pinned by `tests/facts/disasm.zig` ("the arm64 inline data table in dyld is marked"), which asserts the
exact word count.

**Why this must lead decoder coverage, not follow it.** Naming more encodings (e.g. from Arm's
machine-readable ISA spec) converts `.inst` words into confident instructions. Where those words are data,
the result is a plausible lie — the same failure class as a fabricated symbol attribution (§7 item 12), and
worse for an analyst than an honest `.inst`. Expand `arm64.zig` only alongside this pass, never ahead of it.

The same class covers single **alignment pad bytes** between functions, spelled `.byte`/`db` (Capstone's
`CS_OPT_SKIPDATA` output, §4.24). `/bin/ls` x86_64 `0x100004083` is one `0x00` pad between a no-return
`callq _exit` and the next prologue: machre prints `.byte 0x00` and resynchronises on `pushq %rbp` at
`0x100004084`, otool folds the pad into `addb %dl, 0x48(%rbp)` and is misaligned for the rest of the
function. `tests/facts/disasm.zig isDataPseudo` already treats `.long`, `.byte` and `db` as one family.

The **entire** x86_64 `/bin/ls` `--otool-compat` diff is this one class: five hunks, three of them switch
tables (117 `.long` records in total) and two of them single pad bytes (2 `.byte` records), and nothing
else.

**(d) `.inst` and `.long` are DELIBERATELY distinct markers and must never be collapsed.**

* `.inst 0x%08x` = *"a 4-byte word this decoder cannot name."* `valid = false`, `kind = .invalid`
  (`disasm/arm64.zig:6`, §4.24 `disasm/insn.zig`, §9 "One instruction record, two text sources").
  Never skipped, so addresses stay contiguous.
  otool prints `.long` for the same word.
* `.long 0x%08x` = *"this is data."* `valid = true`, `kind = .data`, `target` resolved — class (c) above.

Observed instance: `/usr/lib/dyld` arm64e `0x680c` is `st1.4s { v8, v9, v10, v11 }, [x4], #64` to otool
and to Capstone, and `.inst 0x4c9f2888` to the built-in decoder, which does not yet model the Advanced-SIMD
multi-register load/store group. That is a decoder gap the `.inst` spelling is *meant* to make visible.

Collapsing them would destroy the only signal that separates "machre could not decode this instruction"
(a decoder gap worth fixing) from "machre decided this is not an instruction" (a correct classification).
A diff harness scores a machre `.inst` against an otool `.long` as PASS; it must **not** normalise one
spelling into the other before comparing, because that would also hide a `.inst` where otool decoded a real
instruction — which *is* a defect.

**(e) machre-only annotations that are TRUE and that otool omits because its rule is blind.**

otool only annotates a `ldr <Xt>, [<Xn>, #imm]` when the `adrp` that defined `<Xn>` is the *immediately
preceding* instruction. Measured on `/usr/bin/plutil` (arm64e): of otool's **511** annotated `ldr` lines,
**511 have the defining `adrp` at distance exactly 1** — not one annotation at distance 2 or more. machre
tracks the register across intervening instructions, so it annotates further-away pairs as well. Every extra
annotation was verified true against `dyld_info -fixups -arch arm64e /usr/bin/plutil`:

| address | instruction | adrp distance | machre says | `dyld_info -fixups` at that slot |
|---|---|---|---|---|
| `0x100005928` | `ldr x0, [x26, #0x680]` | 3 | `_OBJC_CLASS_$_NSString` | `0x10002C680 bind Foundation/_OBJC_CLASS_$_NSString` |
| `0x100006e44` | `ldr x0, [x25, #0x680]` | 7 | `_OBJC_CLASS_$_NSString` | `0x10002C680 bind Foundation/_OBJC_CLASS_$_NSString` |
| `0x100006e68` | `ldr x0, [x26, #0x668]` | 7 | `_OBJC_CLASS_$_NSNumber` | `0x10002C668 bind Foundation/_OBJC_CLASS_$_NSNumber` |
| `0x100006e8c` | `ldr x0, [x26, #0x6a8]` | 7 | `_OBJC_CLASS_$_NSArray` | `0x10002C6A8 bind CoreFoundation/_OBJC_CLASS_$_NSArray` |
| `0x100006eb0` | `ldr x0, [x26, #0x6c0]` | 7 | `_OBJC_CLASS_$_NSDictionary` | `0x10002C6C0 bind CoreFoundation/_OBJC_CLASS_$_NSDictionary` |

The machre-only vocabulary is already gated: `symbolize.Annotation.otool_compatible = false` suppresses an
annotation otool would never print *in that form* (`@"…"` for a CFString, `Objc selector ref:`, pointer
targets, resolved function names). This class covers annotations whose **form** is otool's but that otool
simply did not reach. A diff harness scores a machre-only annotation as PASS **only** when the slot resolves
in `dyld_info -fixups`/the symbol table; an annotation with no such backing is a defect. A *missing*
machre annotation where otool has one is a defect **unless** it falls under class (f).

---

**(f) otool-only annotations at a JOIN POINT — machre is conservative where otool ignores control flow.**

The mirror image of (e), and the only sanctioned class in which otool prints an annotation machre does not.
machre drops its tracked `adrp` page at any address that is a **branch target** (§9 `targets` invalidation),
because control arriving via the branch need not have executed the `adrp`. otool models no control flow at
all — its rule is pure adjacency — so it annotates regardless.

Measured: `/usr/libexec/locationd` (arm64e) **10** otool-only annotations, `/usr/libexec/ospredictiond`
**2**. Every one sits at a loop header. Worked case, `locationd 0x1000620dc`:

```
0x1000620d8  adrp x22, #0x10084e000        <- defines the page, OUTSIDE the loop
0x1000620dc  ldr  x0, [x22, #0x470]        <- otool annotates; machre does not
...          bl _objc_msgSend$... (x3)
0x100062104  b.ne #0x1000620dc             <- BACK-EDGE: 0x1000620dc is a join point
```

Here otool happens to be right: the loop body writes `x22` **zero** times, and `x22` is callee-saved
(x19–x30, §Ch8 AAPCS), so the three intervening `bl`s preserve it. But otool did not establish that — it
annotates any adjacent `adrp`/`ldr` pair whether or not a back-edge lands between them, so on a loop that
*does* reassign the base register it would print a confidently wrong symbol. machre's rule is sound and
otool's is correct-by-luck.

**Ruling:** a missing machre annotation is sanctioned **only** when the `ldr` address is a branch target.
A diff harness scores such a line PASS; a missing annotation anywhere else is a defect.

**Deliberately not "fixed".** machre could safely fold across a back-edge when the base register is
callee-saved and provably unwritten on every path into the join. That is a real dataflow upgrade, and it is
declined here on purpose: the failure mode of being too eager is a **fabricated symbol attribution** (the
`relatived` 0x100002f40 defect, §7 item 12), which is strictly worse for an analyst than a missing one. The
conservative direction is the correct default for this tool; revisit only with the join-point dataflow
actually implemented and tested, not by relaxing the invalidation.

---

**Worked example — scoring a real diff.** `machre disasm --section=__TEXT,__text --otool-compat --arch arm64e
/usr/bin/plutil` against `otool -tV -arch arm64e /usr/bin/plutil` produces 122 changed-line pairs:

| count | class | verdict |
|---|---|---|
| 102 | different symbol name: 97 `bl`/`b` operand pairs + 5 `<name>:` label lines. 98 of them have both names in `nm -p`, and **all 98 resolve to the same address** — 0 to different addresses | PASS, class (a) |
| 9 | `; literal pool symbol address: …` machre has and otool does not, all confirmed in `dyld_info -fixups` | PASS, class (e) |
| 11 | `; literal pool for: "…"` where otool escapes an embedded `"` as `\"` and machre does not | **FAIL — a real defect** |

The arm64e `/bin/ls` run of the same command diffs empty.

**Everything else is a defect.** In particular these are NOT sanctioned and must fail a diff run: a
different mnemonic or operand spelling on a decoded instruction; a different immediate base or width;
a different address, size or column layout; a missing or extra line that is not one of (c)–(e); a different
symbol where the two names are not aliases of one address; and any difference at all on the twelve
non-`disasm` mirrors of §5.1.

The 11 failing lines above are the one **open defect** this policy exposes:
`disasm/symbolize.zig:377 escaped()` escapes `\\` and the C0 controls but **not** an embedded `"`, where
otool prints `\"` (e.g. `0x100004604`: machre `""%s" => "`, otool `"\"%s\" => "`). It is a one-line fix in
`escaped()`, not a policy exception, and must not be added to the sanctioned list.

---

## 6. JSON schema

Implemented once in `output/json.zig` + the §3.7 wrapper types; `docs/json-schema.md` (WP9) is the normative key
inventory and `tests/golden_tests.zig` rows with `compare = .json_keys` check that every command's output on
every healthy fixture parses with `std.json.parseFromSlice(std.json.Value, …)` and contains the listed keys.

### 6.1 Envelope (every command)

```json
{ "machre": { "version": "0.1.0", "schema": 1, "command": "info", "capstone": true, "security": true },
  "file": { "path": "tests/corpus/hello-c", "size": 50424,
            "sha256": "a448ac67a4409dabf8b4955f2ee86d9baff77d143bf1ff702faaa260379b15c5",
            "mtime": "2026-09-11T23:47:02Z", "mtime_unix": 1789000022,
            "container": "thin",
            "fat": null,
            "xattrs": [], "quarantine": null, "translocated": false },
  "arches": [ { "arch": "arm64", "index": 0, "offset_in_file": 0, "size": 50424,
                "cputype": "0x100000c", "cpusubtype": "0x0", "caps": "0x0", "valid": true,
                "...command payload...": {} } ],
  "bundle": null,
  "diagnostics": [ { "severity": "warning", "module": "loadcmds", "code": "cmdsize_invalid", "offset": 32, "message": "..." } ],
  "diagnostics_dropped": 0,
  "sanitized_strings": 0,
  "exit_code": 0 }
```

* `file.container` in `thin | fat | not_macho | bundle`; for fat files `file.fat = { "magic": "0xcafebabe",
  "nfat_arch": 2, "arches": [ { "arch", "cputype", "cpusubtype", "offset", "size", "align", "valid" } ] }` lists
  every slice even when `--arch` selected one. `arches` is always an array (one element for thin, N for
  `--all-archs`, exactly one for `--arch`, empty for non-Mach-O) so consumers never branch on container type.
* `file.xattrs/quarantine/translocated` are top level (graft from C) because they are file properties;
  `bundle`, `plist`, `triage` (merged) are top-level siblings of `arches`; per-arch `triage` also exists.
* `exit_code` is inside the document so a pipeline can consume either channel; JSON is always closed (on
  internal error the envelope ends with `"exit_code": 70` and an `error` diagnostic).

### 6.2 Conventions

* Addresses, vm offsets, raw pointers, addends, magics, flags values, cputypes: lowercase `"0x…"` strings
  (`Hex64`). Sizes, counts, file offsets, indices, ordinals: JSON numbers (all < 2^53). Any `u64` that might
  exceed 2^53 is a hex string — never a bare number.
* Digests (cdhash, sha256, per-slot hashes): lowercase hex without `0x` (`HexBytes`), matching `codesign`.
  UUID: `"21C9F585-96F5-3A4C-A516-BBBE1808D26E"`. Times: ISO-8601 UTC strings (`IsoTime`), with `<key>_unix`
  siblings where the source was numeric (quarantine, mtime, signing time).
* Strings from the file go through `json.str`: invalid UTF-8, C0 controls (except `\t\n\r`, which
  `std.json.Stringify` escapes itself) and DEL become U+FFFD; whenever a replacement happened the object
  also carries `<key>_hex` (original bytes) and `<key>_lossy: true`; arrays of file strings carry a per-arch
  `lossy_strings` counter (`strings` items carry `lossy` each). `std.json.Stringify` therefore never falls
  into the number-array form (zig-api-notes 15.5). The envelope's `sanitized_strings` is the per-run total
  across both channels, and a `cli.invalid_utf8` warning carries the same number, so a JSON consumer and a
  terminal reader are told the same thing. The text channel escapes instead of replacing (`\xNN` / `\u{NN}`,
  §3.5) because the analyst has to be able to read what the sample actually contained; the classification of
  what is unsafe is identical between the two.
* Enum-like values are lowercase snake strings (`"severity":"warning"`, `"kind":"rebase"`); flag sets are
  `{"value":"0x200085","names":["NOUNDEFS","DYLDLINK","TWOLEVEL","PIE"]}` (names in the reference tool's
  spelling; `_full` variants in summary.json spelling where a golden compares them).
* Optional data absent -> `null`; absent *features* (compiled out, `--no-security`, `--no-capstone`) ->
  `{"available": false, "reason": "..."}` so "unsigned" and "not checked" are distinguishable.
* `--limit` cuts carry `"truncated": true, "total": N` next to the array. Keys are stable and never reused with a
  different type; additions bump nothing, incompatible changes bump `schema`.

### 6.3 Per-command payload (inside each `arches[i]`, key = command name; top-level where noted)

| command | keys |
|---|---|
| `info` | `header{magic,magic_name,cputype,cputype_name,cpusubtype,cpusubtype_low,caps,filetype,filetype_name,ncmds,sizeofcmds,flags{value,names}}`, `uuid`, `build_version{platform,platform_name,minos,sdk,tools[{tool,name,version}]}`, `version_min{cmd,version,sdk}`, `source_version`, `dylinker`, `entry{kind,entryoff,address,stacksize,symbol}`, `dyld{style,pointer_formats[],imports,fixups,exports,function_starts}`, `dylibs[{ordinal,cmd,path,short_name,current_version,compatibility_version,timestamp,weak,reexport,upward,delayed_init}]`, `id_dylib`, `rpaths[]`, `segments[{name,vmaddr,vmsize,fileoff,filesize,maxprot,initprot,flags{value,names},nsects,entropy,file_fraction}]`, `symbols{total,defined,undefined,stabs,external,local,indirect}`, `code_signature{present,flags{value,names},identifier,team_id,cdhash,hash_type,pages_ok,pages_total}`, `security{available,trust,status,status_name,notarized}`, `encryption{cryptoff,cryptsize,cryptid}|null` |
| `header` | `header{...as info...}`, `fat` (file-level table repeated) |
| `loadcmds` | `load_commands[{index,cmd,cmd_value,cmdsize,offset,requires_dyld, ...typed fields per LC (segments carry sections[]), raw_hex?}]` |
| `segments` | `segments[{...as info..., sections[{index,sectname,segname,addr,size,offset,align,reloff,nreloc,flags{value,type,type_name,attrs[]},reserved1,reserved2,reserved3,class,entropy}]}]` |
| `symbols` | `symtab{symoff,nsyms,stroff,strsize}`, `dysymtab{ilocalsym,nlocalsym,iextdefsym,nextdefsym,iundefsym,nundefsym,tocoff,ntoc,modtaboff,nmodtab,extrefsymoff,nextrefsyms,indirectsymoff,nindirectsyms,extreloff,nextrel,locreloff,nlocrel}`, `counts{defined,undefined,stabs,external,local}`, `symbols[{index,name,nm,type,type_raw,sect,desc,value,external,private_external,weak_ref,weak_def,library_ordinal,library,stab}]`, `indirect[{index,symbol_index,symbol,section}]`, `lossy_strings` |
| `dyld` | `chained_fixups{header{fixups_version,starts_offset,imports_offset,symbols_offset,imports_count,imports_format,symbols_format},imports[{index,lib_ordinal,library,weak,name,addend}],starts[{seg_index,segment,page_size,pointer_format,pointer_format_name,segment_offset,page_count,page_starts[]}],fixups[{address,segment,section,kind,target,symbol,library,addend,auth{key,diversity,addr_div},raw}]}`, `dyld_info{cmd{rebase_off,rebase_size,bind_off,bind_size,weak_bind_off,weak_bind_size,lazy_bind_off,lazy_bind_size,export_off,export_size},rebases[],binds[],lazy_binds[],weak_binds[],threaded}`, `exports_trie{dataoff,datasize,count}`, `function_starts{dataoff,datasize,addresses[]}`, `data_in_code{dataoff,datasize,entries[{offset,length,kind,kind_name}]}` |
| `imports` | `imports[{symbol,library,ordinal,weak,lazy,locations,first_location,source}]`, `dylibs[...]`, `rpaths[]`, `resolution[{path,status,resolved,via_rpath,weak}]` or `resolution:{available:false}` |
| `exports` | `exports[{name,address,offset,kind,weak,reexport{ordinal,library,name},resolver}]`, `source` |
| `codesign` | `code_signature{dataoff,datasize,superblob{magic,magic_name,length,count,slots[{type,type_name,offset,magic,magic_name,length}]},code_directories[{slot,version,flags{value,names},hash_type,hash_type_name,hash_size,page_size,platform,n_code_slots,n_special_slots,code_limit,exec_seg{base,limit,flags{value,names}},runtime,identifier,team_id,cdhash,cdhash_full,special_slots[{slot,name,hash,bound,verified}],pages{checked,ok,mismatches,first_bad}}],best_cdhash,requirements[{type,type_name,text}],designated_requirement{text,synthesized},entitlements{source,keys[],xml,der,disagreement},cms{certificates[{subject{cn,ou,o,c,uid},issuer{cn},serial,not_before,not_after,marker_oids[]}],authority[],signing_time,has_timestamp},offline_trust}`, `security{available,reason,evaluated_path,create_status,validity_status,validity_status_name,revocation_checked,requirements{anchor_apple,apple_generic,developer_id,app_store,notarized},trust,identifier,team_id,format,flags,platform_identifier,runtime_version,cdhash,cdhashes[],certificate_chain[],designated_requirement,main_executable,stapled_ticket{present,length},signing_time,secure_timestamp,entitlements,elapsed_ms}`, `verdict{signed,valid,trust,summary}` |
| `entitlements` | `entitlements{source,keys[],xml,der,xml_raw?,disagreement,dangerous[{key,why,weight}]}` |
| `objc` | `objc{present,image_info{version,flags,swift_unstable,swift_stable,has_category_class_properties,is_swift},classes[{address,name,superclass{kind,address,name},meta,swift,ro_flags{value,names},instance_size,methods[{name,types,imp,class_method}],ivars[{name,type,offset,alignment,size}],properties[{name,attributes}],protocols[]}],categories[],protocols[],selectors[{selref,name}],classrefs[{ref,name,external}],stubs[{address,selector}]}` |
| `strings` | `strings[{address,offset,section,kind,class,text,text_hex?,length,cut,lossy}]`, `total`, `lossy_strings` |
| `entropy` | `entropy{file,segments[{name,offset,size,entropy,file_fraction}],sections[{segment,section,offset,size,entropy}],tells[{code,detail,weight}]}` |
| `plist` (top level) | `plist{format,path,value}` (`plist.Value` JSON form: `<data>` -> `{"$data":"hex"}`, dates -> ISO, uid -> `{"$uid":n}`) |
| `bundle` (top level) | `bundle{root,kind,identifier,executable,executable_path,package_type,version,short_version,min_system,ui_element,background_only,ats_arbitrary_loads,usage_descriptions[],url_schemes[],principal_class,info_plist{format,path,value},frameworks[],helpers[],xpc_services[],plugins[],dylibs[],nested[{path,kind,executable,sealed_cdhash,sealed_requirement,actual_cdhash,cdhash_match,signed,arches[]}],code_resources{version,rules,rules2,files[{path,hash1,hash2,optional}],nested[{path,cdhash,requirement}],verify{checked,mismatched[],missing[],unsealed[],ok}},stapled_ticket{present,path,length},provisioning_profile,file_count,total_size,security{...},spctl{exit,assessment,source,origin}|{available:false}}` |
| `quarantine` (top level) | `xattrs[]`, `quarantine{raw,flags,timestamp,timestamp_unix,agent,uuid,well_formed}|null`, `translocated`, `provenance` |
| `disasm` | `disasm{backend,text_backend,syntax,partial,functions[{name,start,end,source,instructions[{address,size,bytes,mnemonic,operands,kind,target,comment,comment_kind,label}]}],disagreements,truncated}` |
| `functions` | `functions[{name,start,end,size,source,name_source,section}]` |
| `xrefs` | `xrefs[{from,from_function,to,to_name,kind,via_stub}]`, `pointer_slots_included` |
| `triage` (per arch + merged top level) | `triage{score,level,categories_hit[],findings[{id,category,severity,weight,score,title,detail,evidence[],corroborates}],positives[{id,text,credit}],corroboration[],not_flagged[],summary{signed,trust,notarized,hardened_runtime,quarantined,packed_hint,encrypted,imports,exports,symbols,dylibs,objc_classes,arch},exit_code}` |
| `dump` | `dump{segment,section,address,offset,length,hex,ascii}` |
| `report` | every payload above under its command name (`--only` selects) plus top-level `bundle`/`triage` |
| `version` (top level) | `version{machre,zig,capstone{available,version},security{available},host}` |
---

## 7. Robustness & memory strategy

**Threat model.** The input is attacker-controlled bytes or a directory tree. The tool must (a) never crash,
trap or read out of bounds, (b) never allocate unboundedly, (c) never loop unboundedly, (d) never execute or
`dlopen` the input, (e) produce as much correct output as the input permits and say precisely what was wrong.

**Containment mechanisms** (each maps to a test in §10):

1. *One reader, no raw indexing.* `Reader`/`Cursor` are the only way bytes are accessed. `tests/robustness_tests.zig`
   runs `grep -nE '\.bytes\[' src/` through `std.process.run` and asserts that outside `core/reader.zig`,
   `core/sanitize.zig` and fixed-size copies (`Insn.bytes`) no source line indexes a byte slice.
2. *Overflow-free arithmetic.* Offset+size checks go through `Reader.contains/sub` (`std.math.add`); counts are
   multiplied with `std.math.mul` before comparison; ReleaseSafe traps on any `+`/`*` overflow that slipped
   through, and the fuzzers hunt for exactly that.
3. *Clamp every count to what exists.* `n = min(declared, limit, available_bytes / entry_size)`, recorded once as
   `count_clamped` with both numbers. Zero-size entries (cmdsize 0, entsize 0, page_size 0, stride 0) are rejected
   before any division or loop.
4. *Bounded loops.* Every `while` over file-derived state has a step counter with a `Limits` cap: chain walks
   (<= page_size/stride and `max_chain_steps_per_page`), opcode streams (bytes + `max_fixups`), trie nodes, ASN.1
   nodes, plist objects, requirement ops, ObjC lists, instructions, bundle entries.
5. *No recursion on input-shaped data.* Trie, bplist, XML, ASN.1 (CMS + DER), requirements, ObjC protocol lists,
   bundle walk — explicit stacks with depth caps; enforced by review and by fuzzers under `Limits.paranoid`.
6. *Diagnostics, not errors.* Parsers return `Allocator.Error!T` only. `Image.parse` may return
   `error.NotMachO`/`error.Truncated` for the three "not even a header" fixtures; the CLI turns that into exit 3
   with a JSON envelope that still contains file size, sha256, xattrs, entropy and generic strings.
7. *One diagnostic per (module, code) per structure.* `Diagnostics.has` before repeat instances; `max_diagnostics`
   (512) with a `dropped` counter as the last resort.
8. *Size caps.* `Limits.max_file_size` (2 GiB) via `Io.Dir.readFileAlloc(io, path, gpa, .limited64(max))`; a
   larger file -> `error.TooLarge` -> exit 5. Bundles are walked with `max_bundle_entries`; each nested Mach-O
   is loaded lazily with the same cap and freed (`LoadedFile.deinit(gpa)`) after its analysis.
9. *Time caps.* Security.framework calls are bounded by Apple; `--no-network` cancels revocation network access;
   instruction decoding is capped by `max_instructions`; nothing else blocks.
10. *No input execution and no subprocess in the default path.* No `dlopen`, no `NSBundle`; `spctl` runs only
    with the explicit `--spctl` flag (`bundle`/`triage`), and `codesign`/`xattr -w` are used only by tests as
    oracles.
11. *Inert output.* Rendering is the last place a hostile file gets to act, through the analyst's terminal:
    a 16-byte segment name holding `ESC [ 31 m … CR` recolours the output and overwrites the line above it.
    Every file-derived string reaches text output through `Sink.safe`/`Sink.safeMax` and JSON through
    `json.str`; diagnostic messages (which interpolate those names) are escaped once in `text.diagnostics`
    and `json.diagnostics`, so no module can bypass it. `tests/sanitize_tests.zig` asserts the invariant on
    the bytes machre writes — valid UTF-8, no C0 other than `\n`/`\t`, no DEL — for every command in both
    channels, over a crafted fixture, the malformed corpus and a deterministic mutation sweep. This is a
    deliberate improvement over `otool`, which prints the escape raw; `--otool-compat` stays byte-exact for
    healthy input and diverges only where otool would emit a control character. That is divergence class (b)
    of **§5.6**, which enumerates the complete, closed set of six sanctioned `--otool-compat` divergences —
    anything outside it is a defect.

**Allocator strategy.**

* `init.gpa` (leak-checked in Debug, c_allocator in release since `link_libc`) owns: the CLI arg vector, the
  stdout buffer, `LoadedFile.bytes` (freed right after the output is flushed), the Capstone handle, and the
  backing of each analysis arena.
* One `std.heap.ArenaAllocator` per analysis unit (per file; per nested code object inside bundles), wrapped in
  `core.limits.BudgetAllocator` (§3.2) with `max_arena_bytes`, so a parser bomb cannot exceed the budget even in
  aggregate; `error.OutOfMemory` past the budget surfaces as exit 70 with the module name, never as a trap.
  `Diagnostics` live in the same arena and are flushed with it.
* Results are arena-owned slices; no `deinit` methods on result types (nothing to forget). Big transient buffers
  (page-hash computation, the zlib window `[std.compress.flate.max_window_len]u8`) are stack or arena.
* Order at the end of a command: flush sink -> `file.deinit(gpa)` -> arena deinit.

**How tests prove zero-crash on `tests/corpus/malformed/*`.** `tests/robustness_tests.zig` runs every command
(`cli.commands` table) in-process on every malformed fixture with a `Io.Writer.Discarding` sink, with
`Limits.default` and `Limits.paranoid`, in Debug and ReleaseSafe (`zig build test` and `zig build test --release`),
asserting only that it returns with exit code in {0,3,4,5} and that `Diagnostics` is non-empty for the 15
non-empty files plus the specific codes of §10.4. Two more layers: the deterministic 256-mutation sweep per
healthy fixture (seeded `std.Random.DefaultPrng`, graft from A) and `std.testing.fuzz` Smith fuzzers per parser
(plain mode runs each corpus seed once; `zig build test-robustness --fuzz` loops — verified to start on this
nightly, §10.4).
---

## 8. macOS-only layer

Everything below lives in `src/darwin/security.zig`, `src/darwin/xattr.zig`, `src/darwin/dylib_resolve.zig` and
`src/disasm/capstone.zig`, exactly as in `skeleton-reference/` (copied from the compiled probes
`scratchpad/critic/src/sec.zig` and `scratchpad/probe-capstone/src/main.zig`; nothing else is declared).

```zig
// ---- src/darwin/security.zig ----
// ---- externs (only referenced inside `if (build_options.have_security)` bodies) ----
const CFTypeRef = ?*const anyopaque;
const CFAllocatorRef = ?*const anyopaque;
const CFStringRef = ?*const anyopaque;
const CFURLRef = ?*const anyopaque;
const CFDictionaryRef = ?*const anyopaque;
const CFArrayRef = ?*const anyopaque;
const CFDataRef = ?*const anyopaque;
const CFDateRef = ?*const anyopaque;
const CFErrorRef = ?*const anyopaque;
const CFNumberRef = ?*const anyopaque;
const CFBooleanRef = ?*const anyopaque;
const SecStaticCodeRef = ?*const anyopaque;
const SecRequirementRef = ?*const anyopaque;
const SecCertificateRef = ?*const anyopaque;
const CFIndex = c_long;
const CFTypeID = c_ulong;
const Boolean = u8;
const OSStatus = i32;
const SecCSFlags = u32;
const CFStringEncoding = u32;
const CFNumberType = CFIndex;
const CFAbsoluteTime = f64;
const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
const kCFNumberSInt64Type: CFNumberType = 4;
const kCFAbsoluteTimeIntervalSince1970: f64 = 978307200.0;
const kSecCSDefaultFlags: SecCSFlags = 0;
const kSecCSConsiderExpiration: SecCSFlags = 1 << 31;
const kSecCSEnforceRevocationChecks: SecCSFlags = 1 << 30;
const kSecCSNoNetworkAccess: SecCSFlags = 1 << 29;
const kSecCSCheckAllArchitectures: SecCSFlags = 1 << 0;
const kSecCSDoNotValidateExecutable: SecCSFlags = 1 << 1;
const kSecCSDoNotValidateResources: SecCSFlags = 1 << 2;
const kSecCSCheckNestedCode: SecCSFlags = 1 << 3;
const kSecCSStrictValidate: SecCSFlags = 1 << 4;
const kSecCSInternalInformation: SecCSFlags = 1 << 0;
const kSecCSSigningInformation: SecCSFlags = 1 << 1;
const kSecCSRequirementInformation: SecCSFlags = 1 << 2;
const kSecCSDynamicInformation: SecCSFlags = 1 << 3;
const kSecCSContentInformation: SecCSFlags = 1 << 4;
const errSecSuccess: OSStatus = 0;
const errSecCSUnsigned: OSStatus = -67062;
const errSecCSSignatureFailed: OSStatus = -67061;
const errSecCSSignatureInvalid: OSStatus = -67045;
const errSecCSReqFailed: OSStatus = -67050;
const errSecCSBadResource: OSStatus = -67054;
const errSecCSUnsignedNestedCode: OSStatus = -67022;
const errSecCSRevokedNotarization: OSStatus = -66992;
const errSecCertificateRevoked: OSStatus = -67820;
const CSSMERR_TP_CERT_REVOKED: OSStatus = -2147409652;
extern fn CFURLCreateFromFileSystemRepresentation(allocator: CFAllocatorRef, buffer: [*]const u8, bufLen: CFIndex, isDirectory: Boolean) CFURLRef;
extern fn CFURLGetFileSystemRepresentation(url: CFURLRef, resolveAgainstBase: Boolean, buffer: [*]u8, maxBufLen: CFIndex) Boolean;
extern fn CFStringCreateWithCString(alloc: CFAllocatorRef, cStr: [*:0]const u8, encoding: CFStringEncoding) CFStringRef;
extern fn CFRelease(cf: CFTypeRef) void;
extern fn CFGetTypeID(cf: CFTypeRef) CFTypeID;
extern fn CFStringGetTypeID() CFTypeID;
extern fn CFNumberGetTypeID() CFTypeID;
extern fn CFDateGetTypeID() CFTypeID;
extern fn CFDataGetTypeID() CFTypeID;
extern fn CFArrayGetTypeID() CFTypeID;
extern fn CFDictionaryGetTypeID() CFTypeID;
extern fn CFBooleanGetTypeID() CFTypeID;
extern fn CFBooleanGetValue(b: CFBooleanRef) Boolean;
extern fn CFStringGetLength(theString: CFStringRef) CFIndex;
extern fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: CFStringEncoding) CFIndex;
extern fn CFStringGetCString(theString: CFStringRef, buffer: [*]u8, bufferSize: CFIndex, encoding: CFStringEncoding) Boolean;
extern fn CFDictionaryGetValue(theDict: CFDictionaryRef, key: ?*const anyopaque) ?*const anyopaque;
extern fn CFDictionaryGetCount(theDict: CFDictionaryRef) CFIndex;
extern fn CFDictionaryGetKeysAndValues(theDict: CFDictionaryRef, keys: ?[*]?*const anyopaque, values: ?[*]?*const anyopaque) void;
extern fn CFNumberGetValue(number: CFNumberRef, theType: CFNumberType, valuePtr: *anyopaque) Boolean;
extern fn CFArrayGetCount(theArray: CFArrayRef) CFIndex;
extern fn CFArrayGetValueAtIndex(theArray: CFArrayRef, idx: CFIndex) ?*const anyopaque;
extern fn CFDateGetAbsoluteTime(theDate: CFDateRef) CFAbsoluteTime;
extern fn CFDataGetLength(theData: CFDataRef) CFIndex;
extern fn CFDataGetBytePtr(theData: CFDataRef) [*]const u8;
extern fn CFErrorCopyDescription(err: CFErrorRef) CFStringRef;
extern fn CFErrorGetCode(err: CFErrorRef) CFIndex;
extern fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: SecCSFlags, staticCode: *SecStaticCodeRef) OSStatus;
extern fn SecStaticCodeCheckValidity(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef) OSStatus;
extern fn SecStaticCodeCheckValidityWithErrors(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef, errors: *CFErrorRef) OSStatus;
extern fn SecRequirementCreateWithString(text: CFStringRef, flags: SecCSFlags, requirement: *SecRequirementRef) OSStatus;
extern fn SecRequirementCopyString(requirement: SecRequirementRef, flags: SecCSFlags, text: *CFStringRef) OSStatus;
extern fn SecCodeCopySigningInformation(code: SecStaticCodeRef, flags: SecCSFlags, information: *CFDictionaryRef) OSStatus;
extern fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) CFStringRef;
extern fn SecCertificateGetTypeID() CFTypeID;
extern const kSecCodeInfoIdentifier: CFStringRef;
extern const kSecCodeInfoTeamIdentifier: CFStringRef;
extern const kSecCodeInfoFlags: CFStringRef;
extern const kSecCodeInfoFormat: CFStringRef;
extern const kSecCodeInfoCertificates: CFStringRef;
extern const kSecCodeInfoTime: CFStringRef;
extern const kSecCodeInfoTimestamp: CFStringRef;
extern const kSecCodeInfoCdHashes: CFStringRef;
extern const kSecCodeInfoUnique: CFStringRef;
extern const kSecCodeInfoDigestAlgorithms: CFStringRef;
extern const kSecCodeInfoRuntimeVersion: CFStringRef;
extern const kSecCodeInfoEntitlementsDict: CFStringRef;
extern const kSecCodeInfoDesignatedRequirement: CFStringRef;
extern const kSecCodeInfoStapledNotarizationTicket: CFStringRef;
extern const kSecCodeInfoMainExecutable: CFStringRef;
extern const kSecCodeInfoPlatformIdentifier: CFStringRef;

// ---- src/darwin/xattr.zig ----
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?[*]u8, size: usize, position: u32, options: c_int) isize;
extern "c" fn listxattr(path: [*:0]const u8, namebuf: ?[*]u8, size: usize, options: c_int) isize;
const XATTR_NOFOLLOW: c_int = 0x0001;

// ---- src/darwin/dylib_resolve.zig ----
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn _dyld_shared_cache_contains_path(path: [*:0]const u8) bool;

// ---- src/disasm/capstone.zig (Capstone 5.0 ABI; sizes/offsets asserted at comptime) ----
const CsInsn = extern struct { id: c_uint, address: u64, size: u16, bytes: [24]u8, mnemonic: [32]u8, op_str: [160]u8, detail: ?*anyopaque };
comptime {
    std.debug.assert(@sizeOf(CsInsn) == 248);
    std.debug.assert(@offsetOf(CsInsn, "detail") == 240);
}
const CS_ARCH_ARM64: c_int = 1;
const CS_ARCH_X86: c_int = 3;
const CS_MODE_ARM: c_int = 0;
const CS_MODE_64: c_int = 1 << 3;
const CS_OPT_SYNTAX: c_int = 1;
const CS_OPT_DETAIL: c_int = 2;
const CS_OPT_SKIPDATA: c_int = 5;
const CS_OPT_OFF: usize = 0;
const CS_OPT_ON: usize = 3;
const CS_OPT_SYNTAX_ATT: usize = 2;
extern fn cs_version(major: ?*c_int, minor: ?*c_int) c_uint;
extern fn cs_open(arch: c_int, mode: c_int, handle: *usize) c_int;
extern fn cs_close(handle: *usize) c_int;
extern fn cs_option(handle: usize, opt_type: c_int, value: usize) c_int;
extern fn cs_disasm(handle: usize, code: [*]const u8, code_size: usize, address: u64, count: usize, out: *?[*]CsInsn) usize;
extern fn cs_free(out: [*]CsInsn, count: usize) void;
extern fn cs_strerror(code: c_int) [*:0]const u8;
```

**Gating rules.**

* `build_options.have_security` (default `target.result.os.tag == .macos`, overridable with `-Dsecurity=false`)
  gates the *whole body* of every pub fn in `darwin/security.zig` (`if (!build_options.have_security) return
  unavailable(...)`), so the externs are never referenced when the frameworks are not linked — verified: the
  `-Dsecurity=false -Dcapstone=false` binary links only `/usr/lib/libSystem.B.dylib`; with frameworks linked on
  `lib_mod` only, `otool -L` on the executable shows Security and CoreFoundation (link options propagate from the
  imported module).
* `darwin/xattr.zig` and `darwin/dylib_resolve.zig` gate on `builtin.os.tag == .macos` (libSystem symbols; no
  framework needed) and return `Xattrs.empty` / `not_checked` elsewhere.
* `disasm/capstone.zig`: `available = build_options.have_capstone`; `Handle.open` returns
  `error.CapstoneUnavailable` otherwise; the extern block is only referenced inside `if (available)` bodies.
  Capstone is linked statically by default (`-Dcapstone-static=false` links the dylib and the executable then
  carries `LC_RPATH /opt/homebrew/opt/capstone/lib`, disasm-notes A.5). Auto-detection only on native builds
  (`target.query.isNative()`), so `-Dtarget=x86_64-linux` builds without `-Dcapstone=false`.
* Runtime: `--no-security` -> `Analysis.options.security=false` -> `security.unavailable("--no-security", path)`;
  `cmd/codesign.zig` then prints the offline ladder from `cms.offlineTrust` labelled "(offline, unverified)";
  `--no-network` -> `kSecCSNoNetworkAccess`, no `kSecCSEnforceRevocationChecks`, `revocation_checked:false`.
* `SecStaticCodeCreateWithPath` on `Contents/MacOS/<exe>` evaluates the **bundle** (format-notes 12.7); `Verdict.
  evaluated_path`/`main_executable` name what Security actually looked at, and `is_directory=true` is passed for
  bundle roots.
* Non-macOS builds compile and run everything except the three Darwin functions (pure-Zig parsers, plist, bundle
  walking, entropy, strings, built-in disassembly, offline triage).
---

## 9. Disassembly & symbolization plan

**One instruction record, two text sources.** All backends produce `disasm.insn.Insn` (§4.24): `addr`, `size`
(4 on arm64, 1..15 on x86_64), `bytes[16]`, `mnemonic`/`operands` (arena strings), `kind`, `target`, `reg_write`,
`imm`, `mem_ref`, `valid`, `text_from`, `semantic_from`, `partial`. **Semantic fields always come from the built-in
decoders** (`arm64.decodeSemantic` / `x86len.decodeSemantic`), so kind/target/register folding never depend on
Capstone's DETAIL mode; when Capstone is available its mnemonic/op_str text is overlaid on the record with the
same `(address, size)`. A length disagreement keeps the built-in boundary, leaves the built-in text on that record
and logs one `disasm/backend_disagree` diagnostic (`Engine.disagreements`). `valid=false` prints as `.inst
0x%08x` (arm64) / `db 0x..` (x86_64) — never skipped, so addresses are always contiguous. A zero arm64 word is
`udf #0` on Capstone and `.inst 0x00000000` built-in; both are `kind = .trap`.

**Backend selection.** `Options.backend == null` -> Capstone when `build_options.have_capstone` and `Handle.open`
succeeds, else built-in; `Options.otool_compat` on arm64 forces the built-in text backend (otool spelling)
regardless of Capstone availability. `--backend=capstone` on a build without it -> `error.CapstoneUnavailable` -> exit 6.
x86_64 with the built-in backend yields a length-correct listing where only call/jmp/jcc/ret/push/pop/mov/lea are
named (disasm-notes Part C: first 822 boundaries exact, resync after the inline jump table, 539/539 after); the
rest are `db` lines with correct sizes — enough for xrefs and stub resolution, explicitly marked `partial:true`
in JSON and `[builtin x86 length decoder: mnemonics limited]` in text. `--att` (default) selects AT&T on x86_64
only; `--intel` selects Intel; neither affects arm64.

**Function discovery order** (`functions.discover`; later sources only add starts; names by priority symbol >
export > objc > synthetic `sub_<hex>`):

1. `LC_FUNCTION_STARTS` addresses restricted to code sections of `__TEXT`.
2. Defined non-stab `N_SECT` symbols whose `n_sect` is a code section (also name entries from 1).
3. Export-trie entries in code sections.
4. `LC_MAIN` entry (named `_main` only when a symbol says so, else `entry`); `LC_UNIXTHREAD` pc.
5. ObjC method IMPs from classes/categories/protocols (`objc.methodImps`): `-[Class sel]` / `+[Class sel]`.
6. Tertiary, only when (1) is absent or `aggressive`: `bl`/`call rel32` targets inside `__text` not yet starts;
   `b` targets after a `ret`/`b`/`brk`; `pacibsp`/`paciasp`/`bti c` at 4-byte-aligned gaps; jump-table case
   targets (C.4); `__unwind_info` first-level entries — capped by `max_functions`.
   Function ends = next start in the section or section end; `ret`-based shrinking is not attempted.

**Stub resolution** (`symbolize.resolveStubs`, disasm-notes D.2), once per image into a `StubTable`:

| section | detection | entry | A (indirect table) | B (pointer slot) |
|---|---|---|---|---|
| `__TEXT,__stubs` arm64 | `S_SYMBOL_STUBS`, reserved2 = 12 | 12 | `indirect[reserved1 + i]` -> symbol | `adrp x16 ; ldr x16, [x16, #off]` -> GOT slot -> `resolveSlot` bind |
| `__TEXT,__auth_stubs` arm64e | `S_SYMBOL_STUBS`, reserved2 = 16 | 16 | same | `adrp x17 ; add x17 ; ldr x16, [x17] ; braa x16, x17` -> `__auth_got` auth-bind ordinal (`/bin/ls` stub 62 -> `_strcoll`) |
| `__TEXT,__stubs` x86_64 | `S_SYMBOL_STUBS`, reserved2 = 6 | 6 | same | `FF 25 disp32` -> rip-relative slot in `__got` (chained) or `__la_symbol_ptr` (legacy: lazy stream entry by segment+offset, or `__stub_helper` `pushq $off` -> `Bind.stream_offset`) |
| `__TEXT,__objc_stubs` | name, `S_REGULAR` | 32 (size/align check; `-objc_stubs_small` -> diag) | local `_objc_msgSend$sel` symbol when present | `adrp x1 ; ldr x1, [x1, #off]` -> `__objc_selrefs` slot -> rebase target -> `__objc_methname` cstring -> `_objc_msgSend$<sel>` |
| `__TEXT,__stub_helper` (legacy) | name | — | — | `pushq $off` -> lazy-bind entry; used for cross-checks only |

Both algorithms run when possible; `resolved_by` records the winner (A when they agree; B when A is
stripped/absent). When they **disagree**, B wins, `Stub.mismatch=true`, one `symbolize/stub_mismatch` warning is
recorded and triage fires `stubs.mismatch` (tampered/edited indirect tables — a cheap tell, graft from A).

**Annotations** (`symbolize.annotate`; otool's `;` vocabulary first, machre extras only where otool prints nothing):

* Per function, `page[32]?u64` set by `adrp` (`; 0x100004000` printed on the adrp line like otool), invalidated
  when the register is written by any other instruction, at every branch-target label and at function end.
* `add Xd, Xn, #imm` with `page[Xn]` -> `A`: `cstring`/`objc_methname`/`objc_classname`/`objc_methtype` ->
  `; literal pool for: "<text>"`; `cfstring` -> `; @"<text>"` (via `resolveSlot` on `data`); `objc_selrefs` ->
  `; Objc selector ref: <sel>`; `objc_classrefs`/`superrefs` -> `; Objc class ref: _OBJC_CLASS_$_Name`;
  `data`/`bss`/`common`/`const` -> `; <symbol>` when a defined symbol sits at `A` (else `; <section>+0x<off>`
  with `-v`); code -> function name.
* `ldr Xt, [Xn, #imm]` with `page[Xn]` -> slot `S`: `got`/`auth_got`/`la_symbol_ptr`/`nl_symbol_ptr` ->
  `; literal pool symbol address: <bind>`; a rebase slot -> resolved pointer, following **one** level:
  `; <symbol> -> 0x<target> "<string>"` when the target is a string (the `_greeting` line of §5.4),
  `; Objc class ref: …` for classrefs, etc. (`otool_compatible=false`: dropped under `--otool-compat`).
* `ldr Xt, <literal>` -> `; 0x<value>` or the string at the literal address.
* `bl`/`b` (x86 `call`/`jmp` rel32) into a stub section -> `; symbol stub for: <name>`; into `__objc_stubs` ->
  `; "_objc_msgSend$<sel>"` (quoted like otool); into a known function -> `; <name>` (and in `--otool-compat`
  mode the operand itself becomes the name: `bl _add_numbers`, which is what `otool -tV` prints).
* `adr`, `mov`+`movk` pairs -> `; 0x…` when the folded value hits a section. x86_64: `lea disp(%rip)` and
  `call/jmp *disp(%rip)` get the same section-based comments with `##`; `call/jmp` into `__stubs` ->
  `## symbol stub for: _name` (otool prints nothing here; `otool_compatible=false`).
* Conditional branches/`cbz`/`tbz` get no comment; `brk #1` -> `; trap`; PAC prologue/epilogue instructions are
  `kind = .pac_prologue/.pac_epilogue` (JSON only).

**Xref table** (`symbolize.buildXrefs`): from every `Listing` in scope (`--all`, or every discovered function for
the `xrefs` command): each instruction with a `target` or folded address yields `Xref{from,to,kind,target_name,
from_function,via_stub}` with kind `call`, `jump`, `cond_jump`, `data_ref`, `string_ref`, `got_load`,
`objc_selector`, `objc_class`; with `include_pointer_slots` (default on) every rebase fixup whose target lies in a
code section adds a `pointer_slot` xref (function-pointer tables, blocks, ObjC IMPs, `__mod_init_func`,
`__init_offsets`). `xrefs --to _puts` resolves the name through stubs so callers of the stub are reported against
the import with `via_stub:true`. Sorted by `(to, from)` and `(from, to)`; capped by `max_xrefs`.

**Inline data survival** (x86_64, disasm-notes C.4): when the length decoder sees `lea disp(%rip),%rN` whose target
is inside `__text` and not a function start, followed within 8 instructions by `movslq (%rN,%rM,4)`,
`add %rN,…`, `jmp *%rax` with a preceding `cmp $K`, the range `[target, target + 4*(K+1))` is emitted as `.long`
data records (`kind = .data`) and decoding resumes after it; case targets become internal labels. arm64 needs no
skipping. On both arches decoding is per function, never a blind sweep.
---

## 10. Test strategy

### 10.1 Locating the corpus (verified)

`build.zig` passes two FILE paths through the options module (`addOptionPath` hashes its target as a file; a
directory fails with `file_hash IsDir`): `corpus_manifest = tests/corpus/truth/summary.json` and `src_root =
src/root.zig`. `tests/helpers.zig` derives the directories with `std.fs.path.dirname`:

```zig
pub fn corpusDir() []const u8 {
    const truth = std.fs.path.dirname(build_options.corpus_manifest) orelse unreachable; // .../tests/corpus/truth
    return std.fs.path.dirname(truth) orelse unreachable;                               // .../tests/corpus
}
pub fn truthDir() []const u8 { return std.fs.path.dirname(build_options.corpus_manifest) orelse unreachable; }
pub fn srcDir() []const u8 { return std.fs.path.dirname(build_options.src_root) orelse unreachable; }
```

The skeleton's `tests/corpus_tests.zig` already reads `hello-c` (50424 bytes) through `helpers.readFixture`
(`Io.Dir.openDirAbsolute` + `readFileAlloc(.limited(1 << 26))` with `std.testing.io`) and
`tests/robustness_tests.zig` counts the 16 `malformed/*.bin` files — both green. `/bin/ls` is used only by
tests marked `bin-ls` (skipped with `error.SkipZigTest` when absent or not fat). `hello-quarantined`'s xattr is
re-applied by `helpers.ensureQuarantineXattr` (`xattr -w` via `std.process.run`) because xattrs do not survive
copies.

### 10.2 Layers and files

| layer | root (WP0) | per-WP files | step |
|---|---|---|---|
| unit | `src/root.zig` `test { refAllDecls }` + `test` blocks in every `src/**/*.zig` | inside the module files | `zig build test-unit` (`-Dtest-filter=<module>`; names are prefixed `"<module>: "`) |
| corpus facts | `tests/corpus_tests.zig` | `tests/facts/<wp>.zig` | `zig build test-corpus` |
| golden | `tests/golden_tests.zig` (Row table runner) | `tests/golden/<wp>.rows.zig` + `tests/golden/*.txt` | `zig build test-golden` (`-Dupdate-golden=true` regenerates) |
| robustness | `tests/robustness_tests.zig` (malformed matrix, mutation sweep, budget tests) | `tests/fuzz/<wp>.zig` | `zig build test-robustness` (`--fuzz` loops) |
| deps | `tests/deps_tests.zig` (allowed-edge table = §4 header lines) | — | `zig build test-deps` |
| sanitize | `tests/sanitize_tests.zig` (crafted names, malformed corpus, mutation sweep) | — | `zig build test-sanitize` |
| cli | `src/main.zig` tests | — | part of `zig build test` |

Every WP ships: a happy-path unit test on a hand-built byte array (hermetic), one truncation test (every prefix
length of the hand-built input parses without error), one limit test (`Limits.paranoid` -> `count_clamped`/
`limit_reached` + clamped result), its `facts/<wp>.zig` assertions, its `fuzz/<wp>.zig` fuzzers and its golden
rows. Unit examples: `reader` every accessor at `len-1/len/len+1/maxInt`, `Cursor.takeUleb` on 11 × 0x80;
`fat` 2-arch header, `nfat_arch = 1000` clamps to 32; `loadcmds` cmdsize 0/4/12/huge stop the walker;
`blobs` synthetic SuperBlob with a v0x20100 CD and a v0x20600 CD, plus a synthetic SHA-1 + SHA-256 dual CD;
`requirements` the `/bin/ls` 40-byte blob -> `identifier "com.apple.ls" and anchor apple`; `bplist` the 146-byte
`tiny.bplist` (format-notes 7); `arm64` the verified encoding table of disasm-notes Part B as a comptime
`{word, text}` table; `x86len` the 64-byte `/bin/ls` x86_64 prologue with its 20 boundaries; `sanitize` invalid
UTF-8 never reaches `Stringify` as a string (already in `contract/`).

### 10.3 Corpus fact tests (`tests/facts/*.zig`)

One `test` per fixture per WP, loading through the public pipeline (`LoadedFile.load` -> `fat.selectArches` ->
`Image.parse` -> `Analysis` getters) and asserting facts read from `summary.json` at runtime (`helpers.Summary`
accessors: `fixture(name)`, `slice(f, i)`, `int/hex/str/boolean/strings/array/object`):

| fixture | asserted (per slice unless noted; summary.json keys in backticks) |
|---|---|
| all 17 incl. bin-ls (WP0/1: facts/core) | `size`, `sha256`, `container`, `fat_arches[]`, `magic`, `cputype`, `cpusubtype`, `cpusubtype_caps`, `filetype`, `ncmds`, `sizeofcmds`, `flags` + `flags_names`, `load_commands[]` order (via `version.lcName`), every `segments[]{name,vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,flags}` and `sections[]{name,segname,addr,size,offset,align,flags,type}`, `dylibs[]`, `id_dylib`, `rpaths[]`, `dylinker`, `uuid`, `build_version{platform,minos,sdk,tools[]}` (tool id 5 of hello-zig -> `toolName == null`), `version_min`, `source_version`, `entry_point{entryoff,stacksize}`, `symtab{}`, `dysymtab{}` (all 18 fields), `function_starts{dataoff,datasize}`, `data_in_code{dataoff,datasize}`, segment `entropy` (±0.005) and `file_fraction` (±0.001) |
| all (WP2: facts/dyld) | `symbols{total,defined,undefined,stabs,external,local}`, `defined_symbols_first20`/`undefined_symbols_first20` (set equality), `exports_count` + `exports_first20`, `imports_count` + `imports_first20[{symbol,dylib}]`, `nm_undefined_first20`, `dyld_info{...}` offsets, `has_dyld_info/has_chained_fixups/has_exports_trie`, `chained_fixups{header + starts[]}` |
| all signed + bin-ls (WP3: facts/codesign) | `code_signature{present,dataoff,datasize,superblob{magic,length,count,slots[]},code_directory{version,flags,flags_names,hash_type,hash_size,page_size,n_code_slots,n_special_slots,code_limit,exec_seg_*,platform,identifier,team_id,cdhash,cdhash_full},requirements_length,entitlements_keys,has_der_entitlements,der_entitlements_length,cms_signature_length}` and `codesign{identifier,cdhash,flags,signature,format}` |
| hello-c | `dyld -fixups` = 6 binds (`libSystem/…`) + rebase `0x100008008 -> 0x100000668`; function starts `[0x1000004F8,0x100000524,0x10000060C]`; stubs 5 (`___snprintf_chk ___stack_chk_fail _exit _puts _strcmp`, A and B agree, `mismatches == 0`); page hashes 13/13; `disasm --func _main` has **58** instructions and the 9 comments of §5.4 |
| hello-x86_64 | no signature (`security -> errSecCSUnsigned`); x86len boundaries of `_main` = line count of the `otool -tV` section (WP8 adds `otool -tV` to `gen/truth.sh`) |
| hello-fat | 2 arches at 4096/32768; `--arch x86_64` unsigned vs `--arch arm64` signed; `--all-archs --json` has 2 `arches`; text default shows arm64 with the "2 architectures" line |
| hello-objc / Hello.app | classes `MachreAnimal`(super `NSObject` external), `MachreDog`(super `MachreAnimal` local), category `NSString(MachreExtras)`, protocols `MachreGreeter`, `NSObject`; method names from the `dyld_info -objc` truth section; 15 objc stubs resolved to selectors; 4 dylibs; 19 imports; 11 cfstrings |
| libhello.dylib | MH_DYLIB, no `__PAGEZERO`, `LC_ID_DYLIB @rpath/libhello.dylib` 1.2.3/1.0.0, 4 exports, `MH_NO_REEXPORTED_DYLIBS`, not PIE |
| hello-usedylib | imports from `libhello` ordinal 1; 2 rpaths; `dylib_resolve`: `@rpath/libhello.dylib` -> `missing` bare, `on_disk` inside Hello.app; libSystem -> `shared_cache` |
| hello-adhoc / hello-entitled | 3 / 5 slots; CD flags 0x2; page size 16384; special slots -2 (and -5/-7) recomputed hashes match; requirements blob = empty set (12 B); CMS wrapper 8 B; entitlements 5 keys, DER == XML |
| hello-unsigned | no LC_CODE_SIGNATURE, ncmds 17, `security -> errSecCSUnsigned`; triage `notable`, exit 0 |
| high-entropy | `__RANDOM` entropy >= 7.99, fraction >= 0.65; tell `high_entropy_segment`; triage notable (score 28) |
| fake-packed | `__XHDR` between `__DATA_CONST` and `__LINKEDIT`, no `__DATA`; tell `packer_segment_name` |
| fake-upx | `UPX_DATA` tell; `hashes.verify` >= 1 bad page; `security -> errSecCSSignatureFailed`; triage suspicious (60), `--fail-on=suspicious` exits 20 |
| hello-zig | `LC_DYLD_INFO_ONLY` streams 40/56/1776/72; tool id 5 tolerated; 428 symbols; exports `_main __mh_execute_header ___dso_handle` |
| legacy-bind | 4 non-lazy binds + `___stack_chk_guard`, lazy binds past DONE, `dyld_stub_binder`, stubs resolved through `__la_symbol_ptr` |
| hello-quarantined | flags 0x0083, ts 0x68c3a1b2 -> `2025-09-12T04:29:38Z`, agent `Safari`, uuid (xattr re-applied when missing) |
| Hello.app | kind app, identifier `com.machre.corpus.Hello`, executable `Contents/MacOS/Hello`, bplist Info.plist (12 keys) deep-equals `Hello-Info.plist.xml`, CodeResources v2 rules 13 files 1, nested `Frameworks/libhello.dylib` sealed cdhash `41b85e20…b754` == actual, no ticket, `ResourceVerify.ok`, security format `app bundle with Mach-O thin (arm64)` |
| bin-ls | 2 slices; arm64e: 23 rebases + 90 binds, `__auth_stubs` stub 62 -> `_strcoll`, 50 function starts, CMS chain `Software Signing / Apple Code Signing Certification Authority / Apple Root CA`, DR `identifier "com.apple.ls" and anchor apple`, trust `platform`; x86_64: `LC_DYLD_INFO_ONLY`, minos 10.14 |

### 10.4 Golden tests (`tests/golden_tests.zig` + `tests/truth.zig`)

`Row{fixture, argv, golden_file?, truth_cmd?, compare, json_keys, top_level, skip_without_security}` (skeleton
type). Three comparators: (a) **byte-exact** machre text vs `tests/golden/<fixture>.<cmd>.txt` (reviewed
snapshots; `-Dupdate-golden=true` rewrites them); (b) **truth sections** (`truth.load(name)` splits `truth/<name>.txt`
on `===== <cmd> =====` … `--- exit=N`; `truth.find(sections, prefix)`; `expectSameLines` trims trailing whitespace,
drops `Executable=` lines and normalises the tool's `<path>:` banner; `expectSameLineSet` for order-insensitive
listings); (c) **json_keys**: parse with `std.json.parseFromSlice(std.json.Value, …)` and check the §6 key set.
The `--otool-compat` rows are the golden test of the analyst-output contract (§5.6 defines that contract
and the five classes of divergence a row is allowed to show):

| machre invocation | truth section | fixtures | compare |
|---|---|---|---|
| `header --otool-compat` | `otool -hv` | all healthy + bin-ls (`--all-archs`) | same_lines |
| `loadcmds --otool-compat` | `otool -h -l` | all healthy | same_lines |
| `symbols --mode=nm-m --otool-compat` | `nm -m` | all healthy | same_lines |
| `symbols --mode=nm-a --otool-compat` | `nm -a` | all healthy | same_lines |
| `dyld --fixups --otool-compat` | `dyld_info -fixups` | hello-c, hello-objc, legacy-bind, hello-zig (tool output kept as is), bin-ls | same_line_set |
| `dyld --chains --otool-compat` | `dyld_info -fixup_chains` | chained fixtures | same_lines |
| `exports --otool-compat` | `dyld_info -exports` | all healthy | same_line_set |
| `imports --otool-compat` | `dyld_info -imports` | all healthy (ordinal column only for chained) | same_line_set |
| `functions --otool-compat` | `dyld_info -function_starts` | all healthy | same_lines |
| `codesign --otool-compat` | `codesign -dvvv --entitlements -` | signed fixtures + bin-ls | same_lines |
| `codesign --requirements --otool-compat` | `codesign -d -r -` | signed fixtures | same_lines |
| `entitlements --xml` | `codesign -d --entitlements - --xml` | hello-entitled | same_lines |
| `info` platform line | `vtool -show` (values) | all healthy | same_lines (extracted) |
| `plist` | `plutil -p` | Hello.app Info.plist | same_lines |
| `disasm --func _main --otool-compat` | `otool -tV` (WP8 adds the section to `gen/truth.sh` and regenerates `truth/*.txt`) | hello-c, hello-objc, legacy-bind, hello-x86_64 (Capstone builds; kinds/sizes only for builtin x86) | same_lines |
| `strings --bare --min=6 --limit=200` | `strings -n 6 \| head -200` | all healthy | same_lines |
| `info`, `segments`, `symbols`, `codesign`, `disasm --func _main`, `triage` | — (tests/golden/*.txt) | hello-c, hello-objc, legacy-bind, Hello.app, fake-upx | byte_exact (Capstone and builtin text both) |
| every command `--json` | — | every healthy fixture | json_keys (§6.3 inventory) |

### 10.5 Robustness tests (`tests/robustness_tests.zig`; run in Debug and `zig build test --release`)

* **Malformed matrix:** each of the 16 `malformed/*.bin` (+ `fake-upx`) × every command in `cli.commands`
  (`cli.runArgv` with an `Io.Writer.Discarding` sink), with `Limits.default` and `Limits.paranoid`: returns;
  exit in {0,3,4,5}; `diags.items().len > 0` for the 15 non-empty files; specific expectations:
  `cmdsize-zero.bin` -> `cmdsize_invalid`, 0 commands after LC[0]; `cmdsize-huge.bin` -> `cmdsize_invalid`;
  `bogus-ncmds.bin` -> `count_clamped`, 18 commands; `sizeofcmds-too-big.bin` -> `sizeofcmds_invalid`, 18
  commands; `nsects-huge.bin` -> `nsects_invalid`, `__TEXT` section_count 4; `section-offset-past-eof.bin` ->
  `offset_past_eof`; `fat-1000-arches.bin` -> `count_clamped`, both real arches analysable;
  `fat-arch-offset-past-eof.bin` -> arch 0 `valid=false`, arch 1 analysed; `symtab-stroff-past-eof.bin` -> 12
  symbols with empty names and one `truncated`; `symtab-nsyms-huge.bin` -> `count_clamped`;
  `chained-fixups-absurd.bin` / `chained-starts-segcount-huge.bin` -> `truncated`/`count_clamped`, empty fixup
  table, `info` still prints 18 load commands; `dyldinfo-bind-past-eof.bin` -> `truncated`, bind stream skipped;
  `bad-magic.bin`/`empty.bin`/`truncated-header.bin` -> exit 3 with a JSON envelope.
* **Deterministic mutation sweep** (graft from A): `mutationSweep(gpa, io, fixture, seed, 256)` for every healthy
  fixture with `std.Random.DefaultPrng.init(seed)` (seed = fixture-name hash): per mutant 1..8 operations chosen
  from {flip a byte at `random.uintLessThan(len)`, poke an aligned u32 with one of {0, 0xFFFFFFFF, 0x7FFFFFF0,
  len, len+1}, truncate to a random length}, then every command runs under `Limits.paranoid`; completes in
  < 60 s on the corpus and is part of `zig build test`.
* **Smith fuzzers** (`tests/fuzz/<wp>.zig`, one `test "fuzz <module>"` per parser): `std.testing.fuzz(ctx,
  testOne, .{ .corpus = &.{ …fixture bytes… } })`; `testOne` copies the seed, applies `smith.valueRangeAtMost(u8,
  0, 8)` mutations chosen by `smith.value(u32)` / `smith.index(len)`, and runs the parser with `Limits.paranoid`
  asserting only that it returned. Parsers fuzzed: fat, image+loadcmds, symbols, dyld_chained, dyld_exports,
  dyld_legacy, function_starts, blobs+hashes, requirements, entitlements DER, cms/asn1, bplist, xml, objc,
  strings, arm64 decoder (random words), x86len (random bytes), engine (mutated hello-c `__text`), triage
  (random `Inputs`). **Verified on this nightly:** plain mode runs each corpus entry once plus an empty Smith
  (the skeleton's `tests/fuzz/core.zig` is such a test and passes), and `zig build test-robustness --fuzz`
  starts the fuzzer (web UI on `[::1]:<port>`) and loops — it needs the cache directory's `tmp/` subdirectory,
  which the default `.zig-cache` has (a fresh `--cache-dir` without `tmp/` panics with
  `failed to create file 'tmp/libfuzzer.log'`).
* **Budget tests:** `max_arena_bytes = 1 MiB` on `/bin/ls` -> exit 70 with a message, not a trap;
  `max_file_size = 1000` -> exit 5.
* **No-raw-index test:** `std.process.run` of `grep` as in §7 item 1.
* **Deps test:** `tests/deps_tests.zig` walks `src/**/*.zig` (from `helpers.srcDir()`), extracts every
  `@import("…zig")` and fails on an edge missing from `allowed` (§4 table).

Running a subset: `zig build test-unit -Dtest-filter=reader`, `zig build test-corpus -Dtest-filter=hello-objc`,
`zig build test-robustness -Dtest-filter="fuzz dyld_chained"`, everything `zig build test`, release-mode safety
run `zig build test --release`.
---

## 11. build.zig plan

Verbatim from `skeleton-reference/build.zig` (compiled and run on this nightly in every configuration listed at
the top of this document). Facts it relies on: `standardOptimizeOption(.{ .preferred_optimize_mode =
.ReleaseSafe })` registers only `-Drelease` (Build.zig:1323-1329), so an explicit `-Doptimize` option is
registered *first* and wins when given — both `zig build --release` and `zig build -Doptimize=ReleaseSafe`
produce ReleaseSafe (and `--release=fast` still yields ReleaseSafe, verified with `--verbose`); ONE options module
(`opts.createModule()`, Options.zig:436) imported everywhere with `addImport` (two `addOptions` calls fail with
`file exists in modules 'build_options' and 'build_options0'`); `addOptionPath` (Options.zig:424) targets FILES
(`summary.json`, `src/root.zig`), never directories; frameworks/capstone are linked on `lib_mod` only and
propagate to the executable and to every test binary that imports it; Capstone auto-detection only on native
builds; `link_libc` on macOS unconditionally (xattr/dyld externs are in libSystem; `init.gpa` becomes
`c_allocator` in release).

```zig
const std = @import("std");

const capstone_prefix_default = "/opt/homebrew/opt/capstone";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Shipped mode is ReleaseSafe: `zig build --release` (or -Drelease=true). Debug when omitted.
    // `-Doptimize=<mode>` is ALSO accepted (it is registered before the preferred-mode option so
    // scripts written either way work); when given it wins.
    const optimize: std.builtin.OptimizeMode = b.option(std.builtin.OptimizeMode, "optimize", "Explicit optimize mode (overrides --release)") orelse
        b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // ---- feature detection ----
    const capstone_prefix = b.option([]const u8, "capstone-prefix", "Capstone install prefix (default /opt/homebrew/opt/capstone)") orelse capstone_prefix_default;
    const have_capstone: bool = b.option(bool, "capstone", "Link libcapstone (default: auto-detect header on native builds)") orelse blk: {
        if (!target.query.isNative()) break :blk false;
        const hdr = b.fmt("{s}/include/capstone/capstone.h", .{capstone_prefix});
        std.Io.Dir.accessAbsolute(b.graph.io, hdr, .{}) catch break :blk false;
        break :blk true;
    };
    const capstone_static = b.option(bool, "capstone-static", "Link libcapstone.a instead of the dylib (default true)") orelse true;
    const is_macos = target.result.os.tag == .macos;
    const have_security = b.option(bool, "security", "Link Security/CoreFoundation (default: true on macOS)") orelse is_macos;
    const update_golden = b.option(bool, "update-golden", "Rewrite tests/golden/*.txt from current output") orelse false;

    // ---- build_options: ONE module, imported by every compilation. `Module.addOptions` calls
    //      `createModule()` per call and two modules over one options.zig fail with
    //      "file exists in modules 'build_options' and 'build_options0'". ----
    const opts = b.addOptions();
    opts.addOption(bool, "have_capstone", have_capstone);
    opts.addOption(bool, "have_security", have_security);
    opts.addOption(bool, "update_golden", update_golden);
    opts.addOption([]const u8, "version", "0.1.0");
    // addOptionPath hashes its target as a FILE (a directory fails: `file_hash IsDir`), so we pass
    // files and derive directories with std.fs.path.dirname in tests/helpers.zig.
    opts.addOptionPath("corpus_manifest", b.path("tests/corpus/truth/summary.json"));
    opts.addOptionPath("src_root", b.path("src/root.zig"));
    const options_mod = opts.createModule();

    // ---- library module (everything under src/ except main.zig) ----
    const lib_mod = b.addModule("machre", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = is_macos or have_capstone,
    });
    lib_mod.addImport("build_options", options_mod);
    if (have_security) {
        lib_mod.linkFramework("Security", .{});
        lib_mod.linkFramework("CoreFoundation", .{});
    }
    if (have_capstone) {
        lib_mod.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{capstone_prefix}) });
        lib_mod.linkSystemLibrary("capstone", .{
            .use_pkg_config = .no,
            .preferred_link_mode = if (capstone_static) .static else .dynamic,
        });
    }

    // ---- executable ----
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "machre", .module = lib_mod }},
    });
    exe_mod.addImport("build_options", options_mod);
    const exe = b.addExecutable(.{ .name = "machre", .root_module = exe_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run machre (zig build run -- <command> <path>)").dependOn(&run_cmd.step);

    // ---- tests ----
    const filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this string") orelse &.{};

    const unit_tests = b.addTest(.{ .name = "unit", .root_module = lib_mod, .filters = filters });
    const run_unit = b.addRunArtifact(unit_tests);
    const cli_tests = b.addTest(.{ .name = "cli", .root_module = exe_mod, .filters = filters });
    const run_cli = b.addRunArtifact(cli_tests);

    const TestRoot = struct { name: []const u8, path: []const u8, desc: []const u8 };
    const roots = [_]TestRoot{
        .{ .name = "corpus", .path = "tests/corpus_tests.zig", .desc = "Corpus fact tests against tests/corpus/truth/summary.json" },
        .{ .name = "golden", .path = "tests/golden_tests.zig", .desc = "Golden text/JSON output tests (-Dupdate-golden=true to regenerate)" },
        .{ .name = "robustness", .path = "tests/robustness_tests.zig", .desc = "Malformed matrix + mutation sweep + Smith fuzzers (add --fuzz)" },
        .{ .name = "deps", .path = "tests/deps_tests.zig", .desc = "Import-graph policy check over src/**/*.zig" },
        .{ .name = "sanitize", .path = "tests/sanitize_tests.zig", .desc = "Output-inertness: no control bytes or invalid UTF-8 from hostile input" },
    };
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(&run_cli.step);
    b.step("test-unit", "Unit tests inside src/ (-Dtest-filter=<module>)").dependOn(&run_unit.step);
    for (roots) |r| {
        const mod = b.createModule(.{
            .root_source_file = b.path(r.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "machre", .module = lib_mod }},
        });
        mod.addImport("build_options", options_mod);
        const t = b.addTest(.{ .name = r.name, .root_module = mod, .filters = filters });
        const run_t = b.addRunArtifact(t);
        b.step(b.fmt("test-{s}", .{r.name}), r.desc).dependOn(&run_t.step);
        test_step.dependOn(&run_t.step);
    }
}
```

`build.zig.zon`: `.{ .name = .machre, .version = "0.1.0", .fingerprint = 0xee7caf0ceabb3411, .minimum_zig_version
= "0.17.0-dev.1154", .dependencies = .{}, .paths = .{ "build.zig", "build.zig.zon", "src", "tests", "README.md",
"docs" } }` (the fingerprint is the one this nightly generated for the skeleton; keep it).

Usage summary for the README: `zig build` (Debug), `zig build --release` or `zig build -Doptimize=ReleaseSafe`
(shipped), `zig build -Dcapstone=false`, `zig build -Dcapstone-static=false` (dynamic libcapstone + `LC_RPATH`),
`zig build -Dsecurity=false` (pure Zig, links only libSystem), `zig build test`, `zig build test --release`,
`zig build test-unit -Dtest-filter=reader`, `zig build test-robustness --fuzz`, `zig build run -- info /bin/ls`.
---

## 12. Work packages for parallel implementation

**Ground rules.** WP0 runs alone and lands first; it starts from `skeleton-reference/` (§12.0). After WP0 every
file in the tree has exactly one owner and a WP never edits another WP's file: the §3/§4 signatures are the
contract, already compiled, and an interface change is a request to the owning WP (plus WP9 for
`docs/json-schema.md`). Each WP ships its own unit tests inside its files, its `tests/facts/<wp>.zig`,
`tests/fuzz/<wp>.zig`, `tests/golden/<wp>.rows.zig` and golden `.txt` files; the WP0-owned roots import all of
them up front, so the tree compiles at every point. Stubs never panic once WP0 is done: every stubbed parser
returns `.empty`/`null` and records one `not_implemented` info diagnostic, so the malformed matrix is green from
WP0 onward. Sizes are estimated lines of Zig including tests.

### 12.0 The seed: `skeleton-reference/`

`machre/skeleton-reference/` is the compile-checked contract (see the verification record at the top). WP0
begins by copying it over `machre/` (`rsync -a --exclude tests/corpus --exclude README.md skeleton-reference/ ./` from
`machre/` — `skeleton-reference/tests/corpus` is a symlink to the real corpus and must not be copied), pasting the `contract/` bodies into
`src/core/{reader,limits,diag,arch,sanitize,fmt}.zig` and `src/output/sink.zig` (they are drop-in: same
signatures), and replacing every remaining `@panic("todo")` in the WP0-owned files with real code and in the
other files with `.empty`/`null` + `not_implemented`. The skeleton's `root.zig` comptime gate stays forever: any
signature change anywhere breaks `zig build`, not only the tests.

### WP0 — scaffold + kernel (sequential; 1 agent; ~2600 lines beyond the skeleton)

Owns and fully implements: `build.zig`, `build.zig.zon`, `README.md`, `src/main.zig`, `src/root.zig`,
`src/core/*` (reader, limits, diag, arch, sanitize, fmt, version tables, macho_extra, loadcmds, segments, fat,
file, image), `src/output/{sink,json,text}.zig`, `src/cli/{args,context,cli}.zig`, `src/cmd/version.zig`,
`src/analysis/analysis.zig` (memoising facade over the stubs), `tests/helpers.zig`, `tests/truth.zig`, the four
test roots, `tests/deps_tests.zig` (allowed-edge table), the generic malformed matrix + mutation-sweep driver in
`tests/robustness_tests.zig`, `tests/facts/core.zig` for the WP0 facts of §10.3 row 1 (header/load-command/
segment/section/dylib/uuid/build_version/entry/symtab facts across all 17 fixtures), `docs/json-schema.md`
(envelope only). Converts every other stub to `.empty`/`null` + `not_implemented` and makes every `cmd/*.zig`
render the envelope with `"<command>": {"available": false, "reason": "not implemented"}`.
**Acceptance:** `zig build`, `zig build --release`, `zig build -Dsecurity=false -Dcapstone=false`,
`zig build -Dcapstone=true`, `zig build test --summary all` all green (robustness matrix green because every
command returns on every malformed file with the §10.5 diagnostics for `info`/`header`/`loadcmds`/`segments`);
`machre info tests/corpus/hello-c` prints §5.4 minus the symbols/signature/security lines (which print
`not implemented`); `machre info --json --all-archs tests/corpus/hello-fat` has 2 `arches`; `machre header
--otool-compat` and `loadcmds --otool-compat` equal the `otool -hv` / `otool -h -l` truth sections for all 15
healthy fixtures; the 16 malformed fixtures produce the specific diagnostics of §10.5 for the core commands;
`tests/deps_tests.zig` passes with the §4 table.

### WP1 — core commands & text polish (~900)

Owns: `src/cmd/{info,header,loadcmds,segments,dump}.zig`, `tests/golden/core.rows.zig` +
`tests/golden/{hello-c,hello-objc,legacy-bind,libhello.dylib,hello-fat}.{info,header,loadcmds,segments}.txt`,
`tests/fuzz/core.zig` (fat/image/loadcmds fuzzers seeded with hello-c). Depends on: WP0.
**Acceptance:** golden `info`/`segments` text for the five fixtures byte-exact with §5.4 formatting; `header
--otool-compat`/`loadcmds --otool-compat` rows green for all healthy fixtures and both `/bin/ls` slices
(`LC_BUILD_VERSION` minos 10.14 on x86_64 -- corrected at integration: the `/bin/ls` shipped on this macOS
carries `LC_BUILD_VERSION` on both slices and no corpus fixture has `LC_VERSION_MIN_MACOSX` at all, so that
renderer is covered by a synthetic 48-byte Mach-O diffed against `otool -h -l` in `tests/golden/core.rows.zig`;
`LC_DYLD_CHAINED_FIXUPS` on arm64e, tool id 5 on hello-zig printed as `tool 5`); `dump --section=__TEXT,__cstring tests/corpus/hello-c` shows the three strings; JSON key inventory
for the five commands; fuzzers run 10k iterations under `Limits.paranoid` without a trap in `--release`.

### WP2 — symbols, dyld data, imports/exports (~2600)

Owns: `src/macho/*.zig`, `src/cmd/{symbols,dyld,imports,exports}.zig`, `tests/facts/dyld.zig`,
`tests/fuzz/dyld.zig`, `tests/golden/dyld.rows.zig` + golden txt for `symbols`/`dyld --fixups`/`imports`/
`exports` on hello-c, legacy-bind, hello-usedylib. Depends on: WP0.
**Acceptance:** §10.3 row "all (WP2)" for all 17 fixtures; `--otool-compat` rows for `nm -m`, `nm -a`,
`dyld_info -fixups/-fixup_chains/-exports/-imports/-function_starts` on hello-c, hello-objc, legacy-bind,
hello-zig, libhello.dylib, bin-ls (arm64e 23 rebases + 90 binds; x86_64 legacy streams); malformed `symtab-*`,
`chained-*`, `dyldinfo-bind-past-eof` diagnostics as in §10.5; symbol names never reach JSON unsanitised
(`lossy_strings` counted); `FixupTable.resolveSlot` unit tests for fmt 1/2/6/12 raw words from format-notes 4.1.

### WP3 — code signing, pure Zig (~2600)

Owns: `src/codesign/*.zig`, `src/cmd/{codesign,entitlements}.zig`, `tests/facts/codesign.zig`,
`tests/fuzz/codesign.zig`, `tests/golden/codesign.rows.zig` + golden `codesign` txt for hello-c, hello-adhoc,
hello-entitled, fake-upx, bin-ls (arm64e). Depends on: WP0; XML-entitlement keys need WP5 (`plist/xml`) — until
it lands the XML side is `null` and DER carries the keys.
**Acceptance:** §10.3 row "all signed (WP3)"; page-hash verification all OK for every signed fixture, >= 1
mismatch for fake-upx; special slots -2/-5/-7 verified on hello-entitled; requirements pretty-print equals
`codesign -d -r -` for bin-ls (`identifier "com.apple.ls" and anchor apple`) and the synthesized `cdhash H"…"`
form for ad-hoc fixtures; DER entitlements of hello-entitled deep-equal the XML dictionary; CMS chain of
`/bin/ls` = the 3 CNs with marker OID 6.22 on the leaf and `offlineTrust == .platform`; dual-CD synthetic unit
test picks sha256; `codesign --otool-compat` equals `codesign -dvvv --entitlements -` for every signed fixture
(lines 1-14 of §5.4); the §5.4 codesign text for hello-c byte-exact once WP4 lands (Security block renders
`not evaluated` from the stub until then; golden committed after WP4).

### WP4 — Darwin layer (~1300)

Owns: `src/darwin/{security,xattr,dylib_resolve}.zig`, `src/cmd/quarantine.zig`, `tests/facts/darwin.zig`,
`tests/fuzz/darwin.zig` (quarantine parser, CF->plist conversion with synthetic values), `tests/golden/darwin.rows.zig`
+ golden `quarantine` txt for hello-quarantined. Depends on: WP0 (`plist.Value` type exists in the skeleton).
**Acceptance:** the zig-api-notes 15.11 matrix reproduced as tests (hello-adhoc/entitled/Hello.app -> 0 + adhoc;
hello-fat/hello-x86_64/hello-unsigned -> -67062 unsigned; fake-upx -> -67061 invalid; every requirement -67050 on
fixtures; `/bin/ls` -> platform; Discord.app -> developer_id_notarized and Sketch.app -> app_store when present,
skipped otherwise); `kSecCodeInfo*` extraction incl. certificate chain, cdhashes, entitlements dict
(hello-entitled 5 keys); bundle promotion; `--no-security` and `-Dsecurity=false` -> `available=false`;
hello-quarantined parse; `dylib_resolve` statuses of §4.16.

### WP5 — plists and bundles (~1900)

Owns: `src/plist/*.zig`, `src/bundle/bundle.zig`, `src/cmd/{plist,bundle}.zig`, `tests/facts/plist_bundle.zig`,
`tests/fuzz/plist_bundle.zig`, `tests/golden/plist_bundle.rows.zig` + golden `bundle`/`plist` txt for Hello.app
and Hello-Info.plist.xml. Depends on: WP0; WP3 (`blobs.parseSuperBlob` for nested cdhash) and WP4 (security
verdict in `cmd/bundle.zig`) are stub-tolerant until merged.
**Acceptance:** Hello.app Info.plist (bplist) and Hello-Info.plist.xml parse to deep-equal Values with the 12
keys of `summary.json.bundle.info_plist`; `plist` equals the `plutil -p` truth section; tiny.bplist decodes;
CodeResources -> rules 13 / files 1 / nested libhello cdhash `41b85e20…`, `ResourceVerify.ok` for Hello.app
(mismatch after flipping a byte of `Frameworks/libhello.dylib` in a temp copy); `__TEXT,__info_plist` of
`/usr/bin/codesign` parses (skipped if absent); framework layout (`Versions/A`, symlinks not descended), `.xpc`;
a self-referencing bplist dict yields `plist_malformed`, not a hang; fuzzers never trap under `Limits.paranoid`.

### WP6 — ObjC, strings, entropy (~1700)

Owns: `src/objc/objc.zig`, `src/strings/strings.zig`, `src/analysis/entropy.zig`, `src/cmd/{objc,strings,entropy}.zig`,
`tests/facts/objc_strings.zig`, `tests/fuzz/objc_strings.zig`, `tests/golden/objc_strings.rows.zig` + golden
`objc` txt for hello-objc and `entropy` txt for high-entropy. Depends on: WP0; WP2's `FixupTable` (ObjC tests
needing bind resolution are `error.SkipZigTest` while `fixups.source == .none`).
**Acceptance:** hello-objc/Hello.app classes, superclasses, category, protocols, method names equal the
`dyld_info -objc` truth section; 15 stubs -> selectors; 11 cfstrings decoded; `__ustring` unit test with "héllo";
strings for hello-c include the three cstrings; `strings --bare --min=6 --limit=200` equals the truth section for
all healthy fixtures; classifier unit tests (url/ip/path/shell/launch_agent/keychain/base64); entropy per
segment within ±0.005 of `summary.json` for all fixtures; tells fire exactly for high-entropy, fake-packed,
fake-upx; TextEdit expectations (19 classes, `Document : NSDocument`) when present.

### WP7 — instruction decoders (~2600)

Owns: `src/disasm/{insn,capstone,arm64,x86len}.zig`, `tests/facts/decoders.zig`, `tests/fuzz/decoders.zig`.
Depends on: WP0 only.
**Acceptance:** every `{encoding -> text}` pair of disasm-notes Part B (DP-imm incl. DecodeBitMasks, branches/PAC/
hints/barriers/MRS names, DP-reg, loads/stores incl. exclusive/atomic/PAC loads, SIMD/FP subset) as a table
test; `Kind`/`target`/`reg_write`/`imm` correct for `b/bl/b.cond/cbz/tbz/adrp/adr/add/ldr/ldr-literal/mov`;
the 64-byte `/bin/ls` arm64e and x86_64 prologues decode to the otool lines of disasm-notes A.4 (arm64 text exact;
x86 kinds/sizes); x86len reproduces the 1496-instruction boundary run including the jump-table resync;
Capstone text overlay maps the same 64 bytes to identical `(address,size)` records and the `CsInsn` layout
asserts hold; `Handle.open(.arm64, att=true)` does not apply the ATT option; random-word fuzzers never trap and
always advance >= 1 byte.

### WP8 — functions, symbolization, engine (~2200)

Owns: `src/disasm/{functions,symbolize,engine}.zig`, `src/cmd/{disasm,functions,xrefs}.zig`, `tests/facts/disasm.zig`,
`tests/fuzz/disasm.zig`, `tests/golden/disasm.rows.zig` + golden `disasm --func _main` txt for hello-c and
`functions` txt for hello-c/hello-objc; adds `otool -tV`/`otool -Iv` sections to `tests/corpus/gen/truth.sh`
and regenerates `truth/*.txt`. Depends on: WP0, WP2 (symbols/fixups), WP7 (Insn/backends); WP6 for ObjC/string
annotations (stub-tolerant).
**Acceptance:** §5.4 `disasm --func _main` byte-exact (both backends); `disasm --func _main --otool-compat`
equals the `otool -tV` truth section for hello-c, hello-objc, legacy-bind (and hello-x86_64 on Capstone builds);
function discovery = `dyld_info -function_starts` for hello-c (3), hello-objc, bin-ls (50 per slice) plus ObjC
IMP names for hello-objc; stub tables: hello-c 5 (A and B agree, `mismatches == 0`), bin-ls arm64e `__auth_stubs`
62 -> `_strcoll`, legacy-bind via `__la_symbol_ptr`, hello-objc 15 `_objc_msgSend$…`; a unit test with an edited
indirect table yields `mismatch=true` + `stub_mismatch`; `xrefs --to=_puts tests/corpus/hello-c` reports
`0x100000588 call (via stub)`; `xrefs` on legacy-bind lists `pointer_slot` xrefs for the function-pointer table;
`disasm --section=__TEXT,__text --all` on `/bin/ls` x86_64 survives the inline jump table (resync at
`0x100001620`); engine fuzzer never traps; `--backend=capstone` on a `-Dcapstone=false` build -> exit 6.

### WP9 — triage and report (~1200)

Owns: `src/analysis/triage.zig`, `src/cmd/{triage,report}.zig`, `docs/json-schema.md` (final),
`tests/facts/triage.zig`, `tests/fuzz/triage.zig` (random inputs), `tests/golden/triage.rows.zig` + golden
`triage` txt for hello-c, fake-upx, high-entropy, hello-quarantined, Hello.app and the `json_keys` rows for every
command. Depends on: all of WP1–WP8 for full fidelity; compiles and runs against stubs from day one (rules treat
`null` inputs as "unknown", never as "clean").
**Acceptance:** the corpus expectations of §4.23 (levels, scores, exit codes); comptime assert on weights; the
`>= 2 categories` gate (synthetic single-rule inputs never exceed notable); `--fail-on=suspicious` exits 20 on
fake-upx and 0 on hello-c; §5.5 text byte-exact; `report --json` on every healthy fixture parses and contains
every per-command key set; `docs/json-schema.md` matches the key-inventory rows.

### Critical path and staffing

```
WP0 (1 agent, seeded by skeleton-reference) ──> { WP1, WP2, WP3, WP4, WP5, WP6, WP7, WP8, WP9 } in parallel (9 agents)
      WP8 finishes after WP2 + WP7 land (starts on stubs); WP9 finalises last (starts on stubs);
      WP3 XML side after WP5; WP5 nested-cdhash after WP3; WP6 bind-resolved ObjC after WP2.
```

Two levels after WP0; elapsed time is bounded by WP0 + max(WP2, WP3, WP7) + WP8/WP9 integration. Because every
cross-package call is a signature that already compiles in `skeleton-reference/`, the nine agents never need
to talk.
---

## 13. Risks, open questions and the defect ledger

### 13.1 Risks and decided questions

1. **Interface drift.** Mitigated structurally: the signatures are compiled in `skeleton-reference/`, `root.zig`
   references every declaration at comptime, and `tests/deps_tests.zig` polices the import graph. Any change is a
   request to the owning WP and to WP9 (json-schema).
2. **Capstone linking on non-native targets.** Auto-detect requires `target.query.isNative()`; cross builds need
   explicit `-Dcapstone=true` and a matching library (libcapstone.a here is arm64-only).
3. **Capstone operand spelling vs otool.** Capstone prints `#1` where otool prints `#0x1` and `b.le #0x…` where
   otool prints `b.le 0x…` (disasm-notes A.4). Decision: on arm64, `--otool-compat` (and `--backend=builtin`)
   force the built-in decoder for the *text* columns, so the diff against `otool -tV` is empty in every build;
   the byte-exact `disasm` goldens are generated with `--backend=builtin`, and Capstone builds additionally
   compare the address/kind/target/comment columns of the Capstone-text listing. On x86_64 `--otool-compat`
   requires Capstone (AT&T); the built-in listing is `partial`.
4. **x86_64 fallback fidelity.** Without Capstone, x86_64 listings name ~10 instruction kinds (`partial:true`);
   acceptable for triage (xrefs/stubs work), documented prominently; a full x86 decoder is out of scope.
5. **ObjC edge cases.** `-objc_stubs_small`, Swift-only classes, `__objc_nlclslist`, negative relative-method
   offsets, ld64 category merging (corpus-notes 6: `__objc_catlist` under-reports; the report says "categories on
   external classes") — handled defensively with diagnostics; only corpus + TextEdit/Electron facts are verified.
6. **32-bit and big-endian Mach-O.** Header/load commands only; nothing deeper is exercised (no fixture).
7. **Security.framework offline.** Revocation added <= 271 ms with network; offline timeout behaviour is untested —
   `--no-network` exists, `revocation_checked` and `elapsed_ms` are reported.
8. **Golden brittleness.** Text goldens break on formatting tweaks; `-Dupdate-golden=true` + human review of the
   diff is the process; JSON goldens are key-inventory based. Apple-tool wording may change with Xcode updates:
   `truth/TOOLS.txt` records the versions and the golden failure message prints them.
9. **`summary.json` and `src/root.zig` as build inputs.** `addOptionPath` hashes both at configure time;
   regenerating the truth set correctly invalidates test caches; editing `root.zig` re-emits the options module
   (cheap).
10. **Diagnostics volume.** `max_diagnostics = 512` + `dropped`, and the one-per-(module,code)-per-structure rule via
    `Diagnostics.has` — reviewers enforce it.
11. **Fuzz mode.** Verified to start on this macOS nightly (§10.5); the fuzzer needs `<cache-dir>/tmp/` — the
    default cache has it. The design does not depend on `--fuzz` (malformed matrix + mutation sweep + plain-mode
    Smith runs are the gate).
12. **Decided: text-mode default arch** = best `Arch.preferenceRank` against the host (exact name, then same
    cputype, then first valid) with the "N architectures, showing X (use --all-archs)" line (§5.2).
13. **Decided: `report` in text mode** = `info` + `codesign` + `imports` summary (dylibs with resolution status +
    counts) + `triage`; `--only` selects sections; JSON always includes every payload.
14. **Decided: dual CodeDirectory** — every CD is exposed; `best` follows codesign (sha256 wins); triage flags
    SHA-1-only signatures with `sig.sha1_only` (weight 8).
15. **Decided: no `spctl` in the default path** — `--spctl` opt-in on `bundle`/`triage` only (it is not a usable
    oracle for bare Mach-Os anyway: "does not seem to be an app").
16. **Open: vendoring Capstone** via `build.zig.zon` to drop the Homebrew prefix assumption — deferred until the
    built-in decoders prove insufficient.
17. **Open: `report --json` size** on Electron-sized inputs (581k fixups, 11k exports): `--limit` and `--only`
    exist; a per-section row cap default may be needed for pipelines.

### 13.2 Defect ledger — every judge-reported defect and its resolution

| # | source | defect | resolution |
|---|---|---|---|
| 1 | A, C | `addOptionPath` pointed at directories (`tests/corpus`, `tests/golden`) -> `file_hash IsDir`, plain `zig build` fails | **Fixed**: only files are passed (`truth/summary.json`, `src/root.zig`) and directories are derived with `dirname` (§10.1, §11); compiled. |
| 2 | A, C | `Module.addOptions` on several modules -> `file exists in modules 'build_options' and 'build_options0'` | **Fixed**: one `opts.createModule()` + `addImport` everywhere (§11); compiled with 6 test binaries. |
| 3 | A | WP0 gate unachievable with the shipped build.zig | **Fixed**: WP0 starts from the compiled `skeleton-reference/` (§12.0). |
| 4 | A | WP10 monolith (25 files, ~4500 lines, centralised JSON writers) | **Fixed**: each WP owns its `cmd/<name>.zig` including JSON rendering; `cli.zig` is dispatch + framing only; conventions live in `output/json.zig` helpers, not per-type writers (§4.28/§4.29). |
| 5 | A | Core bodies elided, `@panic("unimplemented")` stubs, nothing compiled end-to-end | **Fixed**: §3 bodies are verbatim compiled code (`contract/`), every signature compiles (`skeleton-reference/`), and post-WP0 stubs return `.empty`/`null` + `not_implemented` instead of panicking. |
| 6 | A | `bl 0x1000004f8 ; _add_numbers` vs otool's `bl _add_numbers`; no normalisation for the otool compare | **Fixed**: `--otool-compat` prints `bl _add_numbers` (AnnotateCtx.otool_compat) and the golden row diffs against the `otool -tV` truth section (§9, §10.4). |
| 7 | A | Bundle analysis never hashed sealed files nor compared nested cdhashes; no spctl | **Fixed**: `bundle.verifyResources` / `ResourceVerify` (C's design) with nested `cdhash_match`; `--spctl` opt-in runner in `cmd/bundle.zig` (§4.21). |
| 8 | A, B, C | `std.testing.fuzz` unproven on this nightly | **Fixed**: a Smith test runs in the skeleton's `tests/fuzz/core.zig` (plain mode green) and `zig build test-robustness --fuzz` was started and looped for 75 s (§10.5). |
| 9 | B | `std.EnumSet(Kind).initFull()` does not exist | **Fixed**: `kinds: std.EnumSet(Kind) = .full` (`enums.zig:284`), compiled in `strings.zig`. |
| 10 | B | `BudgetAllocator` depended on an unprobed VTable shape | **Fixed**: VTable shape verified (`mem/Allocator.zig:32-84`); `BudgetAllocator` implemented and tested in `contract/limits.zig` (§3.2). |
| 11 | B | "disasm of `_main` has 65 instructions" | **Fixed**: 58 instructions (0x100000524–0x10000060c, 232 bytes) everywhere (§5.4, §10.3). |
| 12 | B | `pub const empty: SymbolTable;` etc. without initialisers | **Fixed**: every `empty` has a literal initialiser (skeleton compiles them: SymbolTable, ChainedFixups, ExportTrie, DyldInfo, FixupTable, ImportTable, ExportTable, Entitlements, Cms, Xattrs, ObjcInfo, StringsResult, EntropyReport, FunctionTable, StubTable, XrefTable). |
| 13 | B | `cmd/*` <-> `cli/cli.zig` mutual import contradicting the acyclic-DAG check | **Fixed**: `Context`/`Command`/`ExitCode` moved to the leaf `cli/context.zig`; `cmd/*` import only it; the DAG check is now the mechanical `tests/deps_tests.zig` instead of a comptime table (§4). |
| 14 | B | `Options.createModule` cited at :439 (actual :436); `--fuzz` unverified | **Fixed**: citation corrected; fuzz verified (see #8). |
| 15 | B | Text-mode default arch and `all` text content left open | **Fixed**: decided (§13.1 items 12–13, §5.2). |
| 16 | C | `Cursor` declared `pub fn u8/u16/u32/u64` (shadows primitives) | **Fixed**: B's `takeU8/takeInt/u32At/...` names (compiled). |
| 17 | C | `sleb128` traps on 9-byte negative SLEB (shift 63) | **Fixed**: B's `takeSleb` (`@as(i64, -1) << shift`, guarded `shift < 64`); the judges' exact bytes are in `contract/reader.zig` tests and pass in ReleaseSafe. |
| 18 | C | `sink.Str.jsonStringify` 512-byte FBA -> silent wholesale U+FFFD, no `_hex` sibling possible | **Fixed**: `Str.init(arena, bytes, max)` sanitises up front (any length), `jsonStringify` never allocates, and `json.str` emits `<key>_hex`/`<key>_lossy` (§3.7, §6.2). |
| 19 | C | Free-form `Diagnostic.module/code` strings, nothing checked at compile time | **Fixed**: `diag.Module`/`diag.Code` enums (§3.3). |
| 20 | C | Critical path three levels deep; WP0 gate broken | **Fixed**: two levels (§12), WP0 seeded by the compiled skeleton. |
| 21 | C | `hello-unsigned -> suspicious, exit 20` on a single tell | **Fixed**: weights < 50 (comptime), `levelFor` requires >= 2 categories for suspicious+, `hello-unsigned` is `notable` and exits 0 unless `--fail-on=notable` (§4.23). |
| 22 | C | `Io/Writer.zig:2251` citation (actual 2255); fuzz loop not run | **Fixed**: no line number is cited for `Discarding` (looked up via zfn); fuzz run (see #8). |
| 23 | A | `dyld/chained.decodeSlot` returned `Fixup.kind_tag` (not a declaration) | **Fixed**: `Fixup.Kind` is a named union; `decodePointer(raw, format, image_base) ?Fixup.Kind` (compiled). |
| 24 | A | `src/main.zig` owned by two WPs | **Fixed**: WP0 only. |
| 25 | A | No `info_plist` strings kind; no standalone quarantine command | **Fixed**: `strings.Kind.info_plist`; `cmd/quarantine.zig` exists (WP4). |
| 26 | A | Risks #1/#2 were non-issues while the real build breakers went unnoticed | **Addressed**: the verification record at the top lists what was actually compiled and run. |
| 27 | B | `dyld_chained.decodePointer` returned `Fixup.kind_type` | **Fixed**: see #23. |
| 28 | B | `standardOptimizeOption(.{ .preferred_optimize_mode })` removes `-Doptimize=` | **Fixed**: an explicit `-Doptimize` option is registered first and wins; both spellings verified (§11). |
| 29 | B | No fixup-derived xref kind | **Fixed**: `XrefKind.pointer_slot` + `XrefOptions.include_pointer_slots` (§4.26, §9). |
| 30 | B | WP0 the largest package (~3200 lines) | **Mitigated**: the skeleton supplies every signature, all name-table declarations and the §3 bodies; WP0's remaining work is ~2600 lines and `Analysis` is glue; `tests/facts/core.zig` is shared with WP1. |
| 31 | B | `Limits` passed by value | **Fixed**: `*const Limits` on every signature (compiled). |
| 32 | B | DAG table omitted `darwin/security -> plist`; `bundle` coupled to the Darwin layer | **Fixed**: edge listed (§4); `bundle.zig` is portable, `cmd/bundle.zig` composes Security/xattr/spctl results (§4.21). |
| 33 | B | `LoadedFile.bytes` arena-owned, cannot be released early | **Fixed**: gpa-owned bytes + `deinit(gpa)`; nested bundle code objects freed per object (§3.10, §7). |
| 34 | C | `src/testing/corpus.zig` designed around a directory option | **Fixed**: manifest file + `dirname` (§10.1). |
| 35 | C | `capstone.Handle.open` applied `CS_OPT_SYNTAX_ATT` to ARM64 handles | **Fixed**: applied only when `arch == .x86_64` (§4.24). |
| 36 | C | `Analysis` getters swallowed `OutOfMemory` into empty results | **Fixed**: every getter returns `Allocator.Error!…`; OOM is exit 70 (§4.22). |
| 37 | C | LC_DATA_IN_CODE never parsed/rendered | **Fixed**: `function_starts.parseDataInCode`, `dyld --data-in-code`, JSON `data_in_code{...}`, facts row for `data_in_code{dataoff,datasize}`. |
| 38 | C | `darwin/cf.zig` labelled "std only" while importing plist; `spctl` spawned in the default path | **Fixed**: no `cf.zig`; `darwin/security -> plist/plist` declared; `spctl` only with `--spctl`. |
| 39 | B | Comptime "DAG is acyclic" check would need special-casing | **Replaced** by `tests/deps_tests.zig` (mechanical, no special cases). |

**Explicitly rejected suggestions (with reasons):** (a) C's `header`/`loadcmds`/`report` split is adopted but
`report` keeps the alias `all` and `loadcmds` the alias `headers` (B's names) so either vocabulary works; (b) A's
per-result `deinit` methods are not adopted — results stay arena-owned (nothing to forget; the arena budget is
the memory bound) while the *input bytes* got the early-release treatment the judges asked for; (c) A's
`levelFor` thresholds are adopted, C's severity multipliers are not (a single weight table is easier to audit
against "never a single tell"); (d) B's comptime DAG table is dropped in favour of the mechanical import test.
