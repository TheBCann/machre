# machre disassembler notes: Capstone linkage (verified) + pure-Zig fallback decode plan

Verified 2026-09-11 on macOS 26.3 arm64 with Zig `0.17.0-dev.1154+ba5420896`, Homebrew Capstone 5.0.8
(`/opt/homebrew/opt/capstone`), Xcode `otool`/`objdump`/`dyld_info`/`nm`, `clang -c -arch arm64|arm64e`.
Every number below was produced by running a command or compiling code on this machine; the probe
sources live in the scratchpad (paths at the end). Anything marked **(unverified)** is from the ARM ARM /
Intel SDM and was *not* exercised by a probe.

---

## Part A. Linking Capstone from Zig

### A.1 Facts about the installed Capstone

| fact | value |
|---|---|
| header | `/opt/homebrew/opt/capstone/include/capstone/capstone.h` (`CS_API_MAJOR 5`, `CS_API_MINOR 0`, `CS_VERSION_EXTRA 7`) |
| dylib | `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib` (thin arm64, current version 5.0.8, compat 5.0.0); `libcapstone.dylib` is a symlink; `libcapstone.a` (8.7 MB) also present |
| install_name | `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib` (**absolute**, no `@rpath`) |
| runtime `cs_version()` | returns `0x500` (major 5, minor 0) |
| `cs_support(CS_ARCH_ARM64)` / `(CS_ARCH_X86)` | 1 / 1 |

### A.2 ABI facts (hand-declared externs; `@cImport` no longer exists)

**`@cImport` is removed in this nightly**: compiling `@cImport(@cInclude("capstone/capstone.h"))` fails with
`error: invalid builtin function: '@cImport'`. Two working options:

1. Hand-declare the extern functions and `cs_insn` (what the probe does; recommended, no C toolchain needed at build time).
2. `b.addTranslateC(.{ .root_source_file = ..., .target, .optimize })` in `build.zig` (present at `std/Build.zig:1083`)
   and import the resulting module. Not exercised.

Verified with a C `offsetof` probe (`layout.c`) and enforced by `comptime` asserts in the Zig probe:

```
sizeof(cs_insn) = 248, alignof = 8
offsetof: id=0  address=8  size=16  bytes=18  mnemonic=42  op_str=74  detail=240
sizeof(cs_detail) = 1864 ; sizeof(csh) = 8 ; cs_arch/cs_mode/cs_err are 4-byte C enums
CS_MNEMONIC_SIZE = 32 ; bytes[24] ; op_str[160]
CS_ARCH_ARM64 = 1   CS_ARCH_X86 = 3
CS_MODE_ARM = 0 (== CS_MODE_LITTLE_ENDIAN)   CS_MODE_64 = 1<<3 = 8
CS_OPT_SYNTAX = 1   CS_OPT_DETAIL = 2   CS_OPT_SKIPDATA = 5
CS_OPT_OFF = 0   CS_OPT_ON = 3   CS_OPT_SYNTAX_ATT = 2 (Intel is the x86 default)
CS_ERR_OK = 0
```

Zig declarations that link and run (from `probe-capstone/src/main.zig`):

```zig
const Insn = extern struct {
    id: c_uint,            // 0
    address: u64,          // 8
    size: u16,             // 16
    bytes: [24]u8,         // 18
    mnemonic: [32]u8,      // 42
    op_str: [160]u8,       // 74
    detail: ?*anyopaque,   // 240  (cs_detail*; only meaningful with CS_OPT_DETAIL=CS_OPT_ON)
};
comptime { std.debug.assert(@sizeOf(Insn) == 248); std.debug.assert(@offsetOf(Insn, "detail") == 240); }

extern fn cs_version(major: ?*c_int, minor: ?*c_int) c_uint;
extern fn cs_open(arch: c_int, mode: c_int, handle: *usize) c_int;
extern fn cs_close(handle: *usize) c_int;
extern fn cs_option(handle: usize, opt_type: c_int, value: usize) c_int;
extern fn cs_disasm(handle: usize, code: [*]const u8, code_size: usize, address: u64, count: usize, insn: *?[*]Insn) usize;
extern fn cs_free(insn: [*]Insn, count: usize) void;
extern fn cs_strerror(code: c_int) [*:0]const u8;
```

Usage pattern: `cs_open` → `cs_option(h, CS_OPT_DETAIL, CS_OPT_OFF)` → `cs_disasm(h, ptr, len, base, 0, &insns)` (count 0 = all)
→ iterate `insns.?[0..n]`, `std.mem.sliceTo(&ins.mnemonic, 0)` → `cs_free(insns.?, n)` → `cs_close(&h)`.
`cs_disasm` stops at the first undecodable word unless `CS_OPT_SKIPDATA` is on (then emits `.byte` pseudo-insns with `id == 0`).

### A.3 build.zig (verified: builds with `-Dcapstone=true`, `-Dcapstone=false`, and auto-detect)

Filesystem access from `build.zig` in this nightly: the build runner owns an `std.Io` at **`b.graph.io`**; there is no
`b.build_root` field any more — the build root is **`b.root: Cache.Path`** whose `root_dir.handle` is an `std.Io.Dir`.
The simplest configure-time existence check is `std.Io.Dir.accessAbsolute(io, path, .{})`
(`std/Io/Dir.zig:445`; `AccessOptions` is a packed struct `{follow_symlinks, read, write, execute}`; returns `AccessError!void`).

```zig
const std = @import("std");
const capstone_prefix = "/opt/homebrew/opt/capstone";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dcapstone=true|false ; omitted => auto-detect by probing the header at configure time.
    const have_capstone: bool = b.option(bool, "capstone", "Link Homebrew capstone (default: auto-detect)") orelse blk: {
        std.Io.Dir.accessAbsolute(b.graph.io, capstone_prefix ++ "/include/capstone/capstone.h", .{}) catch break :blk false;
        break :blk true;
    };

    const opts = b.addOptions();
    opts.addOption(bool, "have_capstone", have_capstone);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = have_capstone, // capstone needs libc; the pure-Zig build does not
    });
    exe_mod.addOptions("build_options", opts); // source: `const build_options = @import("build_options");`

    if (have_capstone) {
        exe_mod.addIncludePath(.{ .cwd_relative = capstone_prefix ++ "/include" }); // only needed for addTranslateC
        exe_mod.addLibraryPath(.{ .cwd_relative = capstone_prefix ++ "/lib" });     // NOTE: also emits LC_RPATH (see A.5)
        exe_mod.linkSystemLibrary("capstone", .{
            .use_pkg_config = .no, // default is .yes; explicit paths make pkg-config unnecessary
            .preferred_link_mode = if (b.option(bool, "capstone-static", "Link libcapstone.a") orelse false) .static else .dynamic,
        });
    }

    const exe = b.addExecutable(.{ .name = "probe-capstone", .root_module = exe_mod });
    b.installArtifact(exe);
    const run_step = b.step("run", "Run the probe");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    run_step.dependOn(&run_cmd.step);
}
```

`b.path()` panics on absolute paths ("Absolute paths ... can be created via Graph.cwdRelativePath"); use `.{ .cwd_relative = "..." }`
for `/opt/homebrew/...`.

In source, gate everything on `if (build_options.have_capstone) { ... } else { fallback }`. The `extern fn` declarations may
stay in the file even when capstone is off — Zig only emits references for code that is actually analyzed, and the
`-Dcapstone=false` build produced a binary depending only on `/usr/lib/libSystem.B.dylib`.

### A.4 Output vs. `otool -tv` (first 64 bytes of `/bin/ls` `__text`, both slices)

arm64e slice: `__text` addr `0x100000700`, file offset 1792 in the thin slice. x86_64 slice: addr `0x100000718`, offset 1816.
(`otool -t` prints each 32-bit word as an LE integer: word `9101a000` = bytes `00 a0 01 91`.)

| addr | `otool -arch arm64e -tv` | Capstone (`CS_ARCH_ARM64`, `CS_MODE_ARM`) |
|---|---|---|
| 100000700 | `add x0, x0, #0x68` | `add x0, x0, #0x68` |
| 100000708 | `b 0x10000468c ; symbol stub for: _strcoll` | `b #0x10000468c` |
| 10000070c | `mov x8, x0` | `mov x8, x0` |
| 10000071c | `ldr x8, [x1, #0x60]` | `ldr x8, [x1, #0x60]` |
| 10000072c | `cmp x10, x11` | `cmp x10, x11` |
| 100000730 | `b.le 0x10000073c` | `b.le #0x10000073c` |
| 100000734 | `mov w0, #0x1` | `mov w0, #1` |
| 100000738 | `ret` | `ret` |

All 16 arm64 and 20 x86_64 instructions decode identically; the only differences are cosmetic:
Capstone prefixes branch targets with `#`, prints small immediates in decimal, and emits no `;` annotations;
Capstone x86 defaults to Intel syntax (`mov rbp, rsp`, `lea rax, [rsi + 0x68]`) while otool is AT&T
(`movq %rsp, %rbp`) — set `cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT)` (=2) to match otool.

### A.5 Runtime dylib resolution (the "rpath issue") — what actually happens

1. Because libcapstone's install_name is absolute, the linked binary records
   `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib` in `LC_LOAD_DYLIB` (`otool -L`). It runs on this machine with no env.
2. **Zig's `addLibraryPath` additionally emits `LC_RPATH /opt/homebrew/opt/capstone/lib`** into the executable
   (`otool -l | grep -A2 LC_RPATH`). So even a copy whose load command is rewritten to `@rpath/libcapstone.5.dylib` runs.
3. The failure mode only appears on a machine where that path doesn't exist (or if the install_name were `@rpath/...` and no
   rpath were present). Reproduced with `install_name_tool -delete_rpath ... ; -change ... @rpath/libcapstone.5.dylib`:
   ```
   dyld[42963]: Library not loaded: @rpath/libcapstone.5.dylib
     Referenced from: <UUID> .../probe-norpath
     Reason: no LC_RPATH's found
   ```
   Fixes, verified: (a) `DYLD_LIBRARY_PATH=/opt/homebrew/opt/capstone/lib ./probe` runs; (b) `install_name_tool -add_rpath`
   (needs `-headerpad_max_install_names` if the header is full — hit that error) then `codesign -s - -f`;
   (c) **static link**: `-Dcapstone-static=true` (`.preferred_link_mode = .static`) → `otool -L` shows only libSystem,
   binary grows to 9.2 MB (all Capstone arches are in `libcapstone.a`). Recommended for a distributable `machre`.
4. `install_name_tool` changes invalidate the ad-hoc signature; re-sign with `codesign -s - -f` before running.

### A.6 Recommendation for machre

- `-Dcapstone` auto-detect + `build_options.have_capstone` exactly as above; default to `.static` link when the `.a` exists
  so the tool has no runtime dependency; keep the fallback decoder (Part B/C) for `-Dcapstone=false` and for
  `cs_disasm` stopping early on undecodable words.
- Use `CS_OPT_SYNTAX_ATT` for x86 when the user asks for otool-compatible output; otherwise Intel.
- Do the symbolic annotation (`; symbol stub for:`, `; literal pool for:`) yourself (Part D) — Capstone doesn't.

---

## Part B. Pure-Zig arm64 fallback decoder plan

### B.1 Conventions

- Fetch `u32 insn = std.mem.readInt(u32, bytes[i..][0..4], .little)`; PC = section vmaddr + i.
- `bits(x, hi, lo)`; `sext(x, width)`. Both used in `a64probe.zig` (tests pass with `zig test`).
- Register names: `sf`=0 → `w<n>`, 1 → `x<n>`. Register 31 is **`sp`/`wsp`** when it is: `Rn`/`Rd` of ADD/SUB *immediate* (non-flag-setting),
  `Rn`/`Rd` of ADD/SUB *extended-register*, `Rd` of AND/ORR/EOR *immediate* (not ANDS), and `Rn` (base) of every load/store.
  Everywhere else 31 is **`xzr`/`wzr`** (Rm always; Rd of ADDS/SUBS/ANDS; shifted-register forms; Rt of loads/stores; MOVZ/MOVK; CSEL; bitfield...).
- Immediate formatting to match otool/LLVM: `#0x..` hex for data immediates, memory offsets, `brk #0xc471`, `svc #0x80`,
  extr/ror amount (`#0xc`); **decimal** for shift amounts (`lsl #12`, `lsl #3`), extend amounts (`uxtw #2`), bitfield lsb/width
  (`ubfx x16, x17, #8, #4`), `tbz` bit numbers print as `#0x28` in objdump; negative as `#-0x10`; zero memory offset omitted (`[x1]`);
  pre-index `[sp, #-0x10]!`, post-index `[sp], #0x10`. Branch targets as bare hex `0x10000468c` (otool) — pick one style and stick with it.
  Condition codes: `eq ne hs lo mi pl vs vc hi ls ge lt gt le al nv` (cond 0..15; LLVM prints `hs`/`lo`, not `cs`/`cc`).
- PC-relative: `B/BL` target = PC + sext(imm26)·4; `B.cond/CBZ/LDR-literal` = PC + sext(imm19)·4; `TBZ` = PC + sext(imm14)·4;
  `ADR` = PC + sext(immhi:immlo, 21); `ADRP` = (PC & ~0xfff) + sext(immhi:immlo, 21)·4096 (verified: `0x90000068` @ `0x10000075c` → `0x10000c000`).
- Unknown/unallocated: print `.inst 0x%08x` (LLVM's spelling is `.long`/`.inst`; Hopper uses `.inst`). Never skip bytes: every word is 4 bytes.

### B.2 Top-level dispatch (`op0 = bits[28:25]`)

| bits 28..25 | class |
|---|---|
| `100x` | data-processing immediate (B.3) |
| `101x` | branch / exception / system (B.4) |
| `x1x0` | loads and stores (B.6) |
| `x101` | data-processing register (B.5) |
| `x111` | SIMD & FP (B.7) |
| `0000` | reserved (UDF `0x00000000`), `0010` SVE → `.inst` |

### B.3 Data-processing immediate (bits 25..23 = `op0`)

**ADR/ADRP** (`op0=00x`): `op[31] immlo[30:29] 10000 immhi[23:5] Rd`. op=0 ADR, 1 ADRP. Verified: `adr x0,.`=`10000000`, `adrp x1,..`=`90000001`.

**ADD/SUB imm** (`op0=010`, bit 23 = 0): `sf op S 10001 0 sh[22] imm12[21:10] Rn Rd`; op: 0 ADD 1 SUB; S=1 sets flags; `sh=1` → `, lsl #12`.
Verified: `add x0,x1,#0x68`=`9101a020`; `add w2,w3,#1,lsl #12`=`11400462`; `sub sp,sp,#0x40`=`d10103ff`; `subs x4,x5,#7`=`f1001ca4`.
Aliases: `CMP Rn,#imm` = SUBS with Rd=31 (`f10024df`); `CMN` = ADDS Rd=31 (`310004ff`); `MOV Rd,Rn` = ADD imm=0, sh=0 and (Rd==31 or Rn==31): `mov x0,sp`=`910003e0`.
(bit 23 = 1 with `sf=1` is ADDG/SUBG memory tagging — `.inst`.)

**Logical imm** (`op0=100`): `sf opc[30:29] 100100 N[22] immr[21:16] imms[15:10] Rn Rd`; opc: 00 AND, 01 ORR, 10 EOR, 11 ANDS. `sf=0 && N=1` is unallocated.
Immediate = `DecodeBitMasks(N, imms, immr)`; reference implementation in `a64probe.zig` (`decodeBitMasks`) reproduces all six corpus
values `0xff`,`0x1`,`0xffff0000ffff0000`,`0xf0`,`0x80000000`,`0x5555555555555555` and returns `null` for the reserved `N=0, imms=111111`:

```
len    = HighestSetBit(N:NOT(imms))         // 7-bit value; 0 => reserved
levels = Ones(len); if (imms & levels) == levels => reserved
S = imms & levels ; R = immr & levels ; esize = 1 << len
welem = Ones(S+1) (masked to esize) ; elem = ROR(welem, R) within esize
wmask = Replicate(elem) to datasize (32/64)
```
Verified: `and x0,x1,#0xff`=`92401c20`; `orr w2,w3,#0x1`=`32000062`; `eor x4,x5,#0xffff0000ffff0000`=`d2103ca4`; `ands x6,x7,#0xf0`=`f27c0ce6`.
Aliases: `TST Rn,#imm` = ANDS Rd=31 (`7201011f`); `MOV Rd,#bimm` = ORR Rn=31 (`b200f3e9`, LLVM prints `mov x9, #0x5555555555555555`).
Rd=31 with AND/ORR/EOR is `sp`.

**Move wide** (`op0=101`): `sf opc[30:29] 100101 hw[22:21] imm16[20:5] Rd`; opc: 00 MOVN, 10 MOVZ, 11 MOVK (01 unallocated); `sf=0` requires `hw<2`.
Verified: `movz w0,#1`=`52800020`; `movn w0,#0`=`12800000`; `movz x1,#0x1234,lsl #16`=`d2a24681`; `movn x2,#5`=`928000a2`; `movk x3,#0xbeef,lsl #48`=`f2f7dde3`.
MOV alias (LLVM behaviour, matches corpus): MOVZ → `mov Rd, #(imm16<<16*hw)` unless (imm16==0 && hw!=0); prints shifted value (`mov x1, #0x12340000`).
MOVN → `mov Rd, #~(imm16<<16*hw)` (as signed: `mov x2, #-0x6`, `mov w0, #-0x1`) unless (imm16==0 && hw!=0) or (sf=0 && imm16==0xffff). MOVK never aliases.

**Bitfield** (`op0=110`): `sf opc[30:29] 100110 N immr imms Rn Rd`; opc: 00 SBFM, 01 BFM, 10 UBFM; N must equal sf. Let `W = sf?64:32`.
Alias selection (ARM ARM preference, all verified against the corpus):
- UBFM: `LSL Rd,Rn,#(W-1-imms)` if imms != W-1 && imms+1 == immr (`lsl x0,x1,#4`=`d37cec20`: immr=60 imms=59);
  `LSR #immr` if imms == W-1 (`lsr w2,w3,#5`=`53057c62`); `UXTB` if immr==0&&imms==7, `UXTH` imms==15 (32-bit forms `53001ce6`,`53003d28`);
  `UBFIZ Rd,Rn,#((W-immr)%W),#(imms+1)` if imms < immr (`ubfiz w26,w27,#2,#3`=`531e0b7a`: immr=30 imms=2);
  else `UBFX Rd,Rn,#immr,#(imms-immr+1)` (`ubfx x16,x17,#8,#4`=`d3482e30`).
- SBFM: `ASR #immr` if imms == W-1 (`9346fca4`); `SXTB/SXTH/SXTW` for immr==0 && imms==7/15/31 (`93401d6a`,`93403dac`,`93407dee`, Rn printed as w);
  `SBFIZ` if imms < immr (`937d1338`: immr=61 imms=4 → `#3,#5`); else `SBFX` (`13010a72`).
- BFM: `BFC Rd,#lsb,#w` if Rn==31 (v8.2), `BFI` if imms < immr (`bfi x20,x21,#16,#8`=`b3701eb4`: immr=48 imms=7), else `BFXIL` (`b3441ef6`).

**Extract** (`op0=111`): `sf 00 100111 N 0 Rm imms Rn Rd` (N==sf, sf=0 needs imms<32): `EXTR Rd,Rn,Rm,#imms` (`93de33bc`); alias `ROR Rd,Rn,#imms` when Rn==Rm (`93c11c20`).

### B.4 Branches, exception, system (`bits 31..29`, `bits 25..22`)

| pattern (hex mask → value) | insn | fields | verified |
|---|---|---|---|
| `0x7c000000 → 0x14000000` | `B`/`BL` (bit 31 = op) | imm26 | `b .`=`14000000`, `bl .`=`94000000`, `b 0x10000468c`@`0x100000708`=`14000fe1` |
| `0xff000010 → 0x54000000` | `B.cond` | imm19[23:5], cond[3:0] | `b.eq`..`b.al` = `54000000`..`5400000e`; `b.le 0x10000073c`@`0x100000730`=`5400006d` |
| `0x7e000000 → 0x34000000` | `CBZ`(bit24=0)/`CBNZ`(1), sf=bit31 | imm19, Rt | `cbz x0`=`b4000000`, `cbnz w1`=`35000001` |
| `0x7e000000 → 0x36000000` | `TBZ`/`TBNZ` (bit 24) | bit = b5[31]:b40[23:19], imm14[18:5], Rt | `tbz x2,#40`=`b6400002`, `tbnz w3,#3`=`37180003` |
| `0xfffffc1f → 0xd61f0000` | `BR Rn` | Rn[9:5] | `br x4`=`d61f0080` |
| `0xfffffc1f → 0xd63f0000` | `BLR Rn` | | `blr x5`=`d63f00a0` |
| `0xfffffc1f → 0xd65f0000` | `RET {Rn}` (omit when Rn==30) | | `ret`=`d65f03c0`, `ret x6`=`d65f00c0` |
| `0xffffffff → 0xd69f03e0` | `ERET` | | `d69f03e0` |
| `0xfffffc1f → 0xd61f081f/0xd61f0c1f` | `BRAAZ/BRABZ Rn` | | `d61f091f`(x8), `d61f0d3f`(x9) |
| `0xfffffc1f → 0xd63f081f/0xd63f0c1f` | `BLRAAZ/BLRABZ Rn` | | `d63f095f`, `d63f0d7f` |
| `0xfffffc00 → 0xd71f0800/0xd71f0c00` | `BRAA/BRAB Rn,Rm` (Rm in [4:0]) | | `braa x0,x1`=`d71f0801`, `brab x2,x3`=`d71f0c43` |
| `0xfffffc00 → 0xd73f0800/0xd73f0c00` | `BLRAA/BLRAB Rn,Rm` | | `d73f0885`, `d73f0cc7` |
| `0xffffffff → 0xd65f0bff/0xd65f0fff` | `RETAA`/`RETAB` | | `d65f0bff`, `d65f0fff` |
| `0xffffffff → 0xd69f0bff/0xd69f0fff` | `ERETAA`/`ERETAB` | | verified |
| `0xffe0001f → 0xd4000001/2/3` | `SVC/HVC/SMC #imm16[20:5]` | | `svc #0x80`=`d4001001`, `hvc #1`=`d4000022`, `smc #2`=`d4000043` |
| `0xffe0001f → 0xd4200000` | `BRK #imm16` | | `brk #1`=`d4200020`, `brk #0xc471`=`d4388e20` |
| `0xffe0001f → 0xd4400000` | `HLT #imm16` | | `d4400000` |

Hints (`0xfffff01f → 0xd503201f`, CRm[11:8], op2[7:5]; value = `0xd503201f | CRm<<8 | op2<<5`), all verified:
`nop` 0/0 `d503201f`, `yield` 0/1, `wfe` 0/2, `wfi` 0/3, `sev` 0/4, `sevl` 0/5, `xpaclri` 0/7 `d50320ff`,
`pacia1716` 1/0 `d503211f`, `pacib1716` 1/2, `autia1716` 1/4, `autib1716` 1/6, `csdb` 2/4 `d503229f` (`esb` 2/0, `psb csync` 2/1 unverified),
`paciaz` 3/0 `d503231f`, `paciasp` 3/1 `d503233f`, `pacibz` 3/2, `pacibsp` 3/3 `d503237f`, `autiaz` 3/4, `autiasp` 3/5 `d50323bf`, `autibz` 3/6, `autibsp` 3/7 `d50323ff`,
`bti` 4/0 `d503241f`, `bti c` 4/2 `d503245f`, `bti j` 4/4, `bti jc` 4/6 `d50324df`. Unknown CRm/op2 → print `hint #(CRm<<3|op2)`.

Barriers (`0xfffff01f → 0xd503301f`, CRm, op2): `clrex` op2=2 (`d5033f5f`), `dsb` op2=4 (`dsb sy`=`d5033f9f`, `dsb ish`=`d5033b9f`),
`dmb` op2=5 (`d5033fbf`,`d5033bbf`), `isb` op2=6 (`d5033fdf`, print bare `isb` when CRm=15).
CRm names: 15 `sy`, 14 `st`, 13 `ld`, 11 `ish`, 10 `ishst`, 9 `ishld`, 7 `nsh`, 6 `nshst`, 5 `nshld`, 3 `osh`, 2 `oshst`, 1 `oshld`; otherwise `#n`.

PSTATE `MSR (imm)` (`0xfff8f01f → 0xd500401f`, op1[18:16], CRm, op2): `msr daifset,#CRm` = op1=3,op2=6 (`d50342df` for #2); `msr daifclr` op2=7 (`d50342ff`).

`MRS`/`MSR` (register): `0xfff00000 → 0xd5300000` MRS (L=1), `0xd5100000` MSR (L=0); fields `o0[19] op1[18:16] CRn[15:12] CRm[11:8] op2[7:5] Rt[4:0]`;
generic name `S<2+o0>_<op1>_C<CRn>_C<CRm>_<op2>`. Named registers verified by assembling (`objdump` prints upper-case; otool prints the same names):

| name | encoding | example |
|---|---|---|
| `NZCV` | S3_3_C4_C2_0 | `mrs x0,nzcv`=`d53b4200`, `msr nzcv,x1`=`d51b4201` |
| `DAIF` | S3_3_C4_C2_1 | `d53b4225` |
| `FPCR` / `FPSR` | S3_3_C4_C4_0 / _1 | `d53b4406`, `d51b4407`, `d53b4428` |
| `TPIDR_EL0` / `TPIDRRO_EL0` | S3_3_C13_C0_2 / _3 | `d53bd042`, `d53bd063` |
| `CNTVCT_EL0` / `CNTFRQ_EL0` | S3_3_C14_C0_2 / _0 | `d53be044`, `d53be00b` |
| `CTR_EL0` / `DCZID_EL0` | S3_3_C0_C0_1 / _7 | `d53b0029`, `d53b00ea` |
| `MIDR_EL1` | S3_0_C0_C0_0 | `d538000c` |
| `CNTPCT_EL0` S3_3_C14_C0_1, `TPIDR_EL1` S3_0_C13_C0_4, `ID_AA64ISAR0_EL1` S3_0_C0_C6_0, `ID_AA64PFR0_EL1` S3_0_C0_C4_0 | **(unverified)** | |

`SYS`/`SYSL` (`dc`, `ic`, `tlbi`, `at`; `0xfff80000 → 0xd5080000`) → print generic `sys #op1, C<n>, C<m>, #op2, Rt` (user code mostly `dc zva`, `ic ivau`, `dc cvau`).

### B.5 Data-processing register (bit 28 = 0, bits 27..25 = 101)

**Logical shifted register** (`0x1f000000 → 0x0a000000`): `sf opc[30:29] 01010 shift[23:22] N[21] Rm imm6[15:10] Rn Rd`;
opc/N → AND/BIC, ORR/ORN, EOR/EON, ANDS/BICS; shift 00 lsl 01 lsr 10 asr 11 ror (`sf=0` needs imm6<32).
Verified: `and x0,x1,x2`=`8a020020`, `bic w3,w4,w5,lsl #3`=`0a250c83`, `orr x6,x7,x8,lsr #4`=`aa4810e6`, `orn`=`aa2b0149`, `eor ...asr #5`=`ca8e15ac`, `eon`=`ca31020f`, `ands`=`ea140272`, `bics`=`6a3702d5`.
Aliases: `MOV Rd,Rm` = ORR Rn=31, shift=0, imm6=0 (`aa0103e0`); `MVN Rd,Rm{,shift}` = ORN Rn=31 (`aa2303e2`); `TST Rn,Rm{,shift}` = ANDS Rd=31 (`ea05009f`). Omit `, lsl #0`.

**ADD/SUB shifted register** (`0x1f200000 → 0x0b000000`): `sf op S 01011 shift 0 Rm imm6 Rn Rd` (shift 11 reserved).
Verified `8b020020`, `8b020820` (lsl #2), `4b450483` (lsr #1), `eb0800e6` (subs), `ab8b0d49` (adds, asr #3).
Aliases: `CMP Rn,Rm` = SUBS Rd=31 (`eb0b015f`); `CMN` = ADDS Rd=31 (`ab0d019f`); `NEG Rd,Rm` = SUB Rn=31 (`cb0f03ee`); `NEGS` = SUBS Rn=31 (`6b1103f0`).

**ADD/SUB extended register** (`0x1fe00000 → 0x0b200000`): `sf op S 01011 00 1 Rm option[15:13] imm3[12:10] Rn Rd`;
option 000 uxtb 001 uxth 010 uxtw 011 uxtx 100 sxtb 101 sxth 110 sxtw 111 sxtx; Rn/Rd 31 = **sp**; Rm is `w` for options 0-2,4-6, `x` for 3/7 (`w` for all when sf=0).
Print rule (LLVM): if (Rd==31 or Rn==31) and option == (sf?3:2) → print `lsl #imm3` (omit when 0); else print the extend name and `#imm3` if non-zero.
Verified: `add x0,sp,x1`=`8b2163e0` (opt 011 imm3 0 → nothing printed), `add x0,x1,w2,uxtw #2`=`8b224820`, `sub x3,sp,x4,sxtx`=`cb24e3e3`, `cmp sp,x5`=`eb2563ff`, `add x6,x7,w8,sxth`=`8b28a0e6`.

**ADC/SBC** (`0x1fe0fc00 → 0x1a000000`): `sf op S 11010000 Rm 000000 Rn Rd` → ADC/ADCS/SBC/SBCS, `NGC(S)` when Rn==31 **(unverified)**.
**CCMN/CCMP** (`0x1fe00800 → 0x1a400000` reg, `0x1a400800` imm): `sf op 1 11010010 Rm|imm5 cond 0|1 0 Rn 0 nzcv` **(unverified)**.

**Conditional select** (`0x1fe00800 → 0x1a800000`): `sf op S=0 11010100 Rm cond[15:12] op2[11:10] Rn Rd`; op/op2: 0/00 CSEL, 0/01 CSINC, 1/00 CSINV, 1/01 CSNEG.
Verified `9a820020`, `1a851483`, `da88b0e6`, `da8bc549`. Aliases (cond must not be AL/NV, invert = cond ^ 1):
`CSET Rd,inv(cond)` = CSINC Rm=Rn=31 (`1a9f17e0`); `CSETM` = CSINV Rm=Rn=31 (`da9f03e1`); `CINC Rd,Rn,inv` = CSINC Rm==Rn!=31 (`9a83a462`); `CINV` = CSINV Rm==Rn (`5a85b0a4`); `CNEG` = CSNEG Rm==Rn (`da87c4e6`).

**3-source** (`0x1f000000 → 0x1b000000`): `sf 00 11011 op31[23:21] Rm o0[15] Ra Rn Rd`; op31/o0: 000/0 MADD, 000/1 MSUB, 001/0 SMADDL, 001/1 SMSUBL, 010/0 SMULH, 101/0 UMADDL, 101/1 UMSUBL, 110/0 UMULH.
Verified `madd`=`9b020c20`, `msub`=`1b069ca4`, `smaddl`=`9b3045ee`, `umaddl`=`9bb45672`, `smulh`=`9b427c20`, `umulh`=`9bc57c83`.
Aliases (Ra==31): `MUL`=MADD (`9b0a7d28`), `MNEG`=MSUB (`9b0dfd8b`), `SMULL`=SMADDL (`9b387ef6`), `SMNEGL`, `UMULL`=UMADDL (`9bbb7f59`), `UMNEGL`. SMADDL/UMADDL operands print as `x, w, w, x`.

**2-source** (`0x5fe00000 → 0x1ac00000`): `sf 0 S 11010110 Rm opcode[15:10] Rn Rd`; 000010 UDIV, 000011 SDIV, 001000 LSLV, 001001 LSRV, 001010 ASRV, 001011 RORV, 001100 PACGA, 0100xx CRC32B/H/W/X, 0101xx CRC32CB/H/W/X.
Verified `udiv`=`9ac20820`, `sdiv`=`1ac50c83`, `lslv`=`9ac820e6`, `lsrv`=`1acb2549`, `asrv`=`9ace29ac`, `rorv`=`9ad12e0f`, `pacga x0,x1,x2`=`9ac23020`. Print LSLV/LSRV/ASRV/RORV as `lsl/lsr/asr/ror` (LLVM does).

**1-source** (`0x5fe00000 → 0x5ac00000`): `sf 1 S 11010110 opcode2[20:16] opcode[15:10] Rn Rd`.
opcode2=00000: 000000 RBIT, 000001 REV16, 000010 REV (sf=0) / REV32 (sf=1), 000011 REV (sf=1), 000100 CLZ, 000101 CLS.
Verified `rbit x0,x1`=`dac00020`, `rev w2,w3`=`5ac00862`, `rev16 x4,x5`=`dac004a4`, `rev32 x6,x7`=`dac008e6`, `rev x8,x9`=`dac00d28`, `clz`=`dac0116a`, `cls`=`5ac015ac`.
opcode2=00001 (sf=1, PAC): 000000 PACIA `dac10020`, 000001 PACIB `dac10462`, 000010 PACDA `dac108a4`, 000011 PACDB `dac10ce6`, 000100 AUTIA `dac11128`, 000101 AUTIB `dac1156a`, 000110 AUTDA `dac119ac`, 000111 AUTDB `dac11dee`,
001000 PACIZA `dac123f0`, 001001 PACIZB `dac127f1`, 001010 PACDZA, 001011 PACDZB, 001100 AUTIZA `dac133f2`, 001101 AUTIZB `dac137f3`, 001110 AUTDZA, 001111 AUTDZB, 010000 XPACI `dac143f4`, 010001 XPACD `dac147f5`. Z-forms have Rn=11111 and print one operand.

### B.6 Loads and stores (bit 27 = 1, bit 25 = 0)

Size/type helpers: `size[31:30]` 00 B, 01 H, 10 W/S, 11 X/D; `V[26]` = SIMD&FP; for V=1, `opc[23]`=1 with size=00 means Q (128-bit).
FP register letter by size: `b h s d q`.

**LDR (literal)** (`0x3b000000 → 0x18000000`): `opc[31:30] 011 V 00 imm19 Rt`. V=0: 00 `ldr w`, 01 `ldr x`, 10 `ldrsw x`, 11 `prfm`; V=1: 00 `ldr s`, 01 `ldr d`, 10 `ldr q`.
Verified `58000000` (x), `18000001` (w), `1c000002` (s), `5c000003` (d), `9c000004` (q), `98000005` (ldrsw), `d8000000` (prfm pldl1keep, label).
Annotate the target: if it lies in `__const`/`__cstring`/`__got`, print the resolved value or string (Part D).

**LDP/STP** (`0x3a000000 → 0x28000000`): `opc[31:30] 101 V 0 mode[24:23] L[22] imm7[21:15] Rt2 Rn Rt`;
mode 01 post-index, 10 signed offset, 11 pre-index (00 = STNP/LDNP); L=1 load. Register/scale: V=0 opc 00 → `w`/4, 01 → LDPSW `x`/4, 10 → `x`/8; V=1 opc 00 `s`/4, 01 `d`/8, 10 `q`/16. offset = sext(imm7,7)·scale.
Verified `ldp x29,x30,[sp,#0x10]`=`a9417bfd`, `ldp x0,x1,[x2]`=`a9400440`, `stp x29,x30,[sp,#-0x10]!`=`a9bf7bfd`, `ldp x19,x20,[sp],#0x20`=`a8c253f3`, `stp w0,w1,[x2,#8]`=`29010440`, `ldp s0,s1`=`2d400440`, `ldp d2,d3,[x4,#0x10]`=`6d410c82`, `stp q4,q5,[x6,#0x20]`=`ad0114c4`, `ldpsw x0,x1,[x2,#8]`=`69410440`.

**Unsigned-offset** (`0x3b000000 → 0x39000000`): `size 111 V 01 opc[23:22] imm12 Rn Rt`; offset = imm12 << scale, where scale = size (V=0) or size (V=1, or 4 for Q).
V=0 opc: 00 STR, 01 LDR, 10 LDRS* to X (size 00 LDRSB, 01 LDRSH, 10 LDRSW; size 11 = PRFM), 11 LDRS* to W (size 00/01). Mnemonic suffix by size: `strb/ldrb`, `strh/ldrh`, none for W/X.
Verified: `ldr x0,[x1,#0x60]`=`f9403020`, `ldr w2,[x3,#0x10]`=`b9401062`, `ldrb`=`39400ca4`, `ldrh`=`79400ce6`, `ldrsb w8`=`39c00528`, `ldrsb x8`=`39800528`, `ldrsh w`=`79c0056a`, `ldrsh x`=`7980056a`, `ldrsw`=`b98005ac`, `str x`=`f90005ee`, `str w`=`b9000630`, `strb`=`39000672`, `strh`=`790006b4`,
`prfm pldl1keep,[x0,#8]`=`f9800400`, `prfm pstl1strm,[x1]`=`f9800031`; FP: `ldr b0`=`3d400020`, `ldr h1,[x2,#2]`=`7d400441`, `ldr s2,[x3,#4]`=`bd400462`, `ldr d3,[x4,#8]`=`fd400483`, `ldr q4,[x5,#0x10]`=`3dc004a4`.
PRFM operand (Rt): type[4:3] 00 PLD 01 PLI 10 PST; target[2:1] 0 L1 1 L2 2 L3; policy[0] 0 KEEP 1 STRM → `pldl1keep`, `pstl1strm`, ...; else `#imm5`.

**imm9 forms** (`0x3b200000 → 0x38000000`): `size 111 V 00 opc imm9[20:12] op4[11:10] Rn Rt`; op4 00 = `LDUR/STUR` (unscaled, `ldurb/ldurh/ldursb/ldursh/ldursw`), 01 = post-index, 11 = pre-index, 10 = `LDTR/STTR` (unprivileged).
Verified `str x0,[sp,#-0x10]!`=`f81f0fe0`, `ldr x1,[sp],#0x10`=`f84107e1`, `str w2,[x3,#-4]!`=`b81fcc62`, `ldur x0,[x1,#-8]`=`f85f8020`, `stur w2`=`b81fc062`, `ldurb`=`384010a4`, `ldursw`=`b89fc0e6`, `str d5,[x6,#-8]!`=`fc1f8cc5`, `str q0,[sp,#-0x10]!`=`3c9f0fe0`, `ldr q1,[sp],#0x10`=`3cc107e1`.
PAC loads (`0xff200400 → 0xf8200400`): `11 111 0 00 M[23] S[22] 1 imm9 W[11] 1 Rn Rt` → `LDRAA` (M=0) / `LDRAB` (M=1), offset = sext(S:imm9,10)·8, W=1 pre-index. Verified `ldraa x0,[x1]`=`f8200420`, `ldraa x0,[x1,#8]!`=`f8201c20`, `ldrab x2,[x3,#-0x10]`=`f8ffe462`.

**Register offset** (`0x3b200c00 → 0x38200800`): `size 111 V 00 opc 1 Rm option[15:13] S[12] 10 Rn Rt`; option 010 `uxtw` (Wm), 011 `lsl` (Xm), 110 `sxtw` (Wm), 111 `sxtx` (Xm); amount = S ? log2(scale) : 0.
Print: `[Xn, Xm]` for lsl S=0; `[Xn, Xm, lsl #3]`; `[Xn, Wm, uxtw #2]`; `[Xn, Wm, sxtw]`; for byte accesses with S=1 print `lsl #0`.
Verified `ldr x4,[x5,x6]`=`f86668a4`, `ldr x4,[x5,x6,lsl #3]`=`f86678a4`, `ldr w7,[x8,w9,uxtw #2]`=`b8695907`, `ldr x10,[x11,w12,sxtw]`=`f86cc96a`, `ldrb w13,[x14,x15]`=`386f69cd`, `str x16,[x17,x18,sxtx #3]`=`f832fa30`, `str q6,[x7,x8]`=`3ca868e6`.

**Exclusive / acquire-release** (`0x3f000000 → 0x08000000`): `size 001000 o2[23] L[22] o1[21] Rs[20:16] o0[15] Rt2[14:10] Rn Rt`.
o2=0,o1=0: L=0 `STXR{B,H} Ws,Rt,[Xn]` (o0=1 `STLXR`), L=1 `LDXR` (o0=1 `LDAXR`); o2=1,o1=0: L=0 `STLR` (o0=1) / `STLLR` (o0=0), L=1 `LDAR` / `LDLAR`.
o2=0,o1=1 = pair forms `LDXP/STXP`. o2=1,o1=1 = **CAS**: `CAS` (L=0,o0=0) `CASA` (L=1) `CASL` (o0=1) `CASAL` (both); printed `cas Rs, Rt, [Xn]`; `casb/cash` by size.
Verified `ldxr x0,[x1]`=`c85f7c20`, `ldxr w0`=`885f7c20`, `stxr w2,x3,[x4]`=`c8027c83`, `ldaxr`=`c85ffcc5`, `stlxr w7,w8,[x9]`=`8807fd28`, `ldar`=`c8dffd6a`, `stlr`=`c89ffdac`, `ldarb`=`08dffdee`, `stlrb`=`089ffe30`, `cas`=`c8a07c41`, `casa`=`88e37ca4`, `casal`=`c8e6fd07`.

**Atomics (LSE)** (`0x3f200c00 → 0x38200000`): `size 111 0 00 A[23] R[22] 1 Rs o3[15] opc[14:12] 00 Rn Rt`; opc 000 `ldadd`, 001 `ldclr`, 010 `ldeor`, 011 `ldset`, 100 `ldsmax`, 101 `ldsmin`, 110 `ldumax`, 111 `ldumin`; o3=1,opc=000 `swp`; suffix `a`/`l`/`al` from A/R; `b`/`h` from size; `ST<op>` alias when Rt==31.
Verified `ldadd x0,x1,[x2]`=`f8200041`, `ldadda w3,w4,[x5]`=`b8a300a4`, `ldaddal`=`f8e60107`, `swp`=`f829816a`, `ldset`=`f82c31cd`, `ldclr`=`f82f1230`.

### B.7 SIMD & FP (basic data movement only; everything else → `.inst`)

- **FMOV/conversions general↔FP** (`0x5f20fc00 → 0x1e200000`): `sf 0 0 11110 type[23:22] 1 rmode[20:19] opcode[18:16] 000000 Rn Rd`; type 00 S, 01 D, 11 H;
  opcode 111 `fmov Fd,Rn`, 110 `fmov Rd,Fn`, 010 `scvtf`, 011 `ucvtf`, 000/001 `fcvt?s/?u` with rmode 00 N, 01 P, 10 M, 11 Z; 100/101 `fcvtas/au`; type=10 rmode=01 → `fmov x, v.d[1]`.
  Verified `fmov d0,x1`=`9e670020`, `fmov x2,d3`=`9e660062`, `fmov s4,w5`=`1e2700a4`, `fmov w6,s7`=`1e2600e6`, `scvtf d0,x1`=`9e620020`, `scvtf s2,w3`=`1e220062`, `ucvtf`=`9e6300a4`/`1e2300e6`, `fcvtzs w0,d1`=`1e780020`, `fcvtzs x2,s3`=`9e380062`, `fcvtzu`=`1e7900a4`, `fcvtms x6,d7`=`9e7000e6`, `fcvtps w8,s9`=`1e280128`.
- **FP 1-source** (`0x5f207c00 → 0x1e204000`): `opcode[20:15]`: 000000 `fmov`, 000001 `fabs`, 000010 `fneg`, 000011 `fsqrt`, 000100 `fcvt →s`, 000101 `fcvt →d`, 000111 `fcvt →h`, 0010xx `frint{n,p,m,z}`, 001100 `frinta`, 001110 `frintx`, 001111 `frinti`.
  Verified `fmov d8,d9`=`1e604128`, `fabs s2,s3`=`1e20c062`, `fneg`=`1e614020`, `fsqrt`=`1e61c0a4`, `fcvt d0,s1`=`1e22c020`, `fcvt s2,d3`=`1e624062`, `fcvt h4,s5`=`1e23c0a4`.
- **FP 2-source** (`0x5f200c00 → 0x1e200800`): `opcode[15:12]`: 0000 `fmul` 0001 `fdiv` 0010 `fadd` 0011 `fsub` 0100 `fmax` 0101 `fmin` 0110 `fmaxnm` 0111 `fminnm` 1000 `fnmul`. Verified `fadd`=`1e622820`, `fsub`=`1e253883`, `fmul`=`1e6808e6`, `fdiv`=`1e2b1949`.
- **FP compare** (`0x5f203c00 → 0x1e202000`): opcode2[4:0] 00000 `fcmp Fn,Fm`, 01000 `fcmp Fn,#0.0`, 10000 `fcmpe`, 11000 `fcmpe #0.0`. Verified `1e612000`, `1e202048`, `1e642070`.
- **FP immediate** (`0x5f201fe0 → 0x1e201000`): imm8[20:13]; value = (−1)^b7 · 2^(b6 ? e−3 : e+1) · (1 + f/16) with e=imm8[5:4], f=imm8[3:0]; print `#1.00000000`-style (LLVM prints 8 decimals). Verified `fmov d12,#1.0`=`1e6e100c` (imm8 0x70), `fmov s13,#0.5`=`1e2c100d` (0x60).
- **FMADD family** (`0x5f000000 → 0x1f000000`): `M 0 S 11111 type o1[21] Rm o0[15] Ra Rn Rd`: o1/o0 0/0 `fmadd` 0/1 `fmsub` 1/0 `fnmadd` 1/1 `fnmsub`. Verified `1f420c20`, `1f069ca4`. **FCSEL** (`0x5f200c00 → 0x1e200c00`, cond[15:12]): `1e620c20`.
- **MOVI** (`0x9ff80400 → 0x0f000400`): `0 Q op 0111100000 a b c cmode[15:12] o2 1 d e f g h Rd`; imm8 = a:b:c:d:e:f:g:h (bits 18:16 and 9:5);
  cmode 0xx0 32-bit `movi Vd.{2s,4s},#imm8{,lsl #8·x}`, 10x0 16-bit, 1110 op=0 8-bit `movi .16b/.8b`, 1110 op=1 64-bit (each imm8 bit → a byte: Q=0 → scalar `movi d`, Q=1 → `.2d`), 1111 op=0 FMOV imm vector; odd cmode = MVNI/ORR/BIC forms.
  Verified `movi v0.2d,#0`=`6f00e400`, `movi v1.16b,#0xff`=`4f07e7e1`, `movi v2.4s,#1`=`4f000422`, `movi d3,#0`=`2f00e403`.
- **DUP (general)** (`0xbfe0fc00 → 0x0e000c00`), **INS (general)** (`0xffe0fc00 → 0x4e001c00`), **UMOV** (`0xbfe0fc00 → 0x0e003c00`), **SMOV** (`0x0e002c00`): element size from imm5[20:16]: `xxxx1` B (idx=imm5[4:1]), `xxx10` H (imm5[4:2]), `xx100` S (imm5[4:3]), `x1000` D (imm5[4]).
  DUP arrangement: B → `.8b/.16b`, H → `.4h/.8h`, S → `.2s/.4s`, D → `.2d` by Q. LLVM prints INS as `mov Vd.T[i], Rn` and UMOV S/D as `mov Rd, Vn.T[i]` (Darwin objdump/otool spell it `mov.d v0[1], x1`, `dup.4s v0, w1`, `movi.2d v0, #...`; Capstone/ARM syntax is `v0.d[1]`, `v0.4s`, `v0.2d` — pick ARM syntax).
  Verified `dup v0.4s,w1`=`4e040c20`, `dup v2.2d,x3`=`4e080c62`, `dup v4.16b,w5`=`4e010ca4`, `ins v0.d[1],x1`=`4e181c20`, `ins v2.s[0],w3`=`4e041c62`, `umov w0,v1.s[1]`=`0e0c3c20`, `umov x2,v3.d[1]`=`4e183c62`, `umov w4,v5.b[3]`=`0e073ca4`, `smov w6,v7.h[2]`=`0e0a2ce6`.

### B.7a Darwin vs ARM SIMD spelling (verified 2026-09-12)

`otool -tV` and `objdump --macho -d` use Apple's AArch64 printer, which **hoists the vector arrangement
(or the element letter) from the operands onto the mnemonic**; Capstone, `llvm-mc` and the ARM ARM use
the canonical form. The rule, mined from `otool -tV` over ~1M instructions of `/bin/ls /bin/date /bin/cat
plutil grep awk sed perl ssh python3 dyld vim tar openssl nm xxd libcapstone libz` and then confirmed by
assembling a 103-instruction probe (`clang -c -arch arm64` + `otool -tV`):

1. Take the arrangement of the **first operand that has one** (`xtn v18.2s, v18.2d` → `.2s`;
   `uminv b1, v0.16b` → `.16b`, since `b1` is scalar; `sha512h2 q27, q25, v24.2d` → `.2d`).
2. Append it to the mnemonic after a `.`; strip `.T` from **every** vector operand.
3. Indexed elements keep the index and lose the letter: `mov v0.d[1], x1` → `mov.d v0[1], x1`,
   `mov w0, v1.s[1]` → `mov.s w0, v1[1]`, `umov w4, v5.b[3]` → `umov.b w4, v5[3]`,
   `fmov x2, v0.d[1]` → `fmov.d x2, v0[1]`, `ld1 { v0.h }[3], [x10]` → `ld1.h { v0 }[3], [x10]`.
4. Register lists lose it too: `ld1 { v0.16b }, [x2], #16` → `ld1.16b { v0 }, [x2], #16`.
   Note the **decimal** post-index immediate: the SIMD load/store group is the one place otool prints
   that operand in decimal, where the general load/store group prints hex. Assembled and read back with
   `clang -c -arch arm64` + `otool -tV` (probe `ld1probe.s`):
   `ld1 { v0.16b }, [x2], #16` → `ld1.16b { v0 }, [x2], #16`;
   `ld1 { v0.8b }, [x2], #8` → `ld1.8b { v0 }, [x2], #8`;
   `ld1 { v0.16b, v1.16b }, [x3], #32` → `ld1.16b { v0, v1 }, [x3], #32`;
   `ld1 { v0.h }[3], [x10], #2` → `ld1.h { v0 }[3], [x10], #2`;
   contrast `ldr x0, [x1], #16` → `ldr x0, [x1], #0x10` and `str q0, [x1], #16` → `str q0, [x1], #0x10`.
5. Scalars have no arrangement and are untouched: `movi d3, #0…0`, `fadd s0, s1, s2`, `sha1h s0, s1`.

**There is no exception**: in the whole sample no `otool` arm64 line keeps a `vN.T` operand. (The
`rev32.16b`-looking hits a naive `v[0-9]+\.` regex finds are the `v32` inside `rev32`.)

### B.7b Advanced SIMD three same registers (verified 2026-09-12)

`0 Q U 01110 size 1 Rm opcode 1 Rn Rd` — mask `0x9f20_0400`, value `0x0e20_0400`. `/bin/ls` arm64e's
`0x6ee18401` at `0x100002f60` is `sub.2d v1, v0, v1`. Every row below was assembled and read back with
`otool -tV` (probe `simd1.s`, 100 forms):

| opcode[15:11] | U=0 | U=1 | sizes |
|---|---|---|---|
| 00000 | SHADD | UHADD | size≠11 |
| 00001 | SQADD | UQADD | all |
| 00010 | SRHADD | URHADD | size≠11 |
| 00011 | AND/BIC/ORR/ORN by size | EOR/BSL/BIT/BIF by size | always `.8b`/`.16b` |
| 00100 | SHSUB | UHSUB | size≠11 |
| 00101 | SQSUB | UQSUB | all |
| 00110 | CMGT | CMHI | all |
| 00111 | CMGE | CMHS | all |
| 01000/01010 | SSHL / SRSHL | USHL / URSHL | all |
| 01001/01011 | SQSHL / SQRSHL | UQSHL / UQRSHL | all |
| 01100/01101 | SMAX / SMIN | UMAX / UMIN | size≠11 |
| 01110/01111 | SABD / SABA | UABD / UABA | size≠11 |
| 10000 | ADD | SUB | all |
| 10001 | CMTST | CMEQ | all |
| 10010 | MLA | MLS | size≠11 |
| 10011 | MUL (size≠11) | PMUL (size==00) | — |
| 10100/10101 | SMAXP / SMINP | UMAXP / UMINP | size≠11 |
| 10110 | SQDMULH | SQRDMULH | size 01 or 10 |
| 10111 | ADDP | unallocated | all |

`Q == 0` with `size == 11` is reserved (`1d` is not an arrangement). `ORR Vd, Vn, Vn` prints as
`mov Vd.T, Vn.T` (`mov.16b v3, v4`). Floating-point row (opcode `11xxx`, bit 23 = the "minus" column,
bit 22 = sz → `2s/4s` or `2d`): U=0/a=0 FMAXNM FMLA FADD FMULX FCMEQ – FMAX FRECPS; U=0/a=1 FMINNM FMLS
FSUB – – – FMIN FRSQRTS; U=1/a=0 FMAXNMP – FADDP FMUL FCMGE FACGE FMAXP FDIV; U=1/a=1 FMINNMP – FABD – FCMGT FACGT FMINP –.

### B.7c `mov` immediates are printed SIGNED (verified 2026-09-12)

LLVM prints the **MOV aliases** (both the move-wide and the ORR-bitmask one) through `formatImm`, i.e.
signed at the register width; the un-aliased `movz`/`movn`/`movk` and the plain logical forms stay
unsigned. Assembled and confirmed:

| encoding | otool |
|---|---|
| `orr x9, xzr, #0x8888888888888888` | `mov x9, #-0x7777777777777778` |
| `orr w2, wzr, #0xaaaaaaaa` | `mov w2, #-0x55555556` |
| `movz x0, #0x8000, lsl #48` | `mov x0, #-0x8000000000000000` |
| `movn x0, #0` | `mov x0, #-0x1` |
| `and x5, x6, #0xfffffffffffffff8` | `and x5, x6, #0xfffffffffffffff8` (unsigned) |
| `orr x10, x11, #0xffffffffffff0000` | unsigned |
| `eor`, `ands`, `tst` | unsigned |

The i64 minimum is reachable (`mov x0, #0x8000000000000000`), so the magnitude must be taken with
two's complement, not by negating through i64.

### B.8 Suggested Zig structure

```
decodeArm64(insn: u32, pc: u64, ctx: *const Ctx, out: *Io.Writer) !Kind
  switch (op0 = bits 28..25) -> class fn; each class fn returns .{ .mnemonic, .operands, .kind }
  Kind: .other, .branch(target), .call(target), .ret, .cbranch(target), .adrp(reg, page), .add_imm(reg, base_reg, imm), .ldr(reg, base_reg, off), .pac_prologue, .inst(raw)
```
Keep per-register "last ADRP page" state in the caller (Part D) to fold `adrp+add`/`adrp+ldr` pairs.

---

## Part C. x86_64 fallback: instruction-length decoder

Goal: split `__text` into instruction boundaries, recognise CALL/JMP/Jcc/RET/PUSH/POP/MOV/LEA (and rip-relative targets), print
the rest as `db 0x..` bytes. The Python reference (`x86len.py`) implementing exactly the rules below was run over the first
**6000 bytes** of `/bin/ls` x86_64 `__text` (1496 decoded instructions) and compared with `otool -tv` boundaries: **the first 822
boundaries match exactly, the decoder resynchronises immediately after an inline jump table, and 539/539 boundaries after the
table match** (the table is discussed in C.4). Recognised kinds in that slab: 95 call, 162 jcc, 110 jmp, 88 lea, 425 mov, 30 push, 39 pop, 9 ret.

### C.1 Prefix and opcode parsing (64-bit mode)

1. Legacy prefixes (any order, repeat allowed): `66` (opsize → `iz` becomes 2 bytes), `67`, `F0`, `F2`, `F3`, segment `2E 36 3E 26 64 65`.
2. REX `40`–`4F` (must be last before opcode). `REX.W` (bit 3) changes `B8+r` imm to 8 bytes.
3. Opcode: `0F` → 2-byte map; `0F 38` / `0F 3A` → 3-byte maps (always have ModRM; `0F 3A` always has a trailing imm8).
4. VEX `C4` (3-byte: payload 2 bytes; map from byte1[4:0]: 1→0F, 2→0F38, 3→0F3A) / `C5` (2-byte: payload 1, map 0F); EVEX `62` (payload 3): then opcode, ModRM, imm8 if map 0F3A or listed opcodes. **(unverified — `/bin/ls` contains no VEX/EVEX)**. In 64-bit mode `C4/C5/62` are never LES/LDS/BOUND.
5. `FF /7` (ModRM.reg == 7) is undefined → emit 1-byte `db 0xff` (LLVM/otool do the same); without this rule the decoder drifts by one byte in data.

### C.2 ModRM / SIB / displacement

`mod=modrm>>6, reg=(modrm>>3)&7, rm=modrm&7`. mod=3 → register, no more bytes. rm=4 → SIB follows; if mod=0 and SIB.base=5 → disp32.
mod=0 & rm=5 → **RIP-relative disp32** (target = next_insn_addr + disp32). mod=1 → disp8; mod=2 → disp32.

### C.3 One-byte map tables (as implemented and verified)

Has ModRM: `00-3F` where `(op & 7) < 4` (ALU r/m forms); `62`,`63` (MOVSXD); `69`,`6B`; `80-8F`; `C0`,`C1`,`C6`,`C7`; `D0-D3`; `D8-DF` (x87); `F6`,`F7`,`FE`,`FF`.
Immediate sizes (`iz` = 4, or 2 under `66`): `04/0C/14/1C/24/2C/34/3C` ib; `05/0D/…/3D` iz; `68` iz; `69` iz; `6A` ib; `6B` ib; `70-7F` rel8; `80`,`83` ib; `81` iz; `A0-A3` moffs64 (8);
`A8` ib; `A9` iz; `B0-B7` ib; `B8-BF` iz or **8 with REX.W**; `C0/C1` ib; `C2` iw; `C6` ib; `C7` iz; `C8` iw+ib; `CD` ib; `E0-E3`,`EB` rel8; `E8`,`E9` rel32 (always 32 in 64-bit); `E4-E7` ib;
`F6 /0,/1` ib; `F7 /0,/1` iz. Everything else 0.
Two-byte map: no ModRM for `05 06 07 08 09 0A 0B 0C 0D 0E 30-35 37 77 80-8F A0 A1 A2 A8 A9 AA C8-CF`; imm8 after ModRM for `70-73 A4 AC BA C2 C4 C5 C6`; `80-8F` = Jcc rel32.
Kinds: `E8` call rel32; `E9`/`EB` jmp; `70-7F`/`0F 80-8F` jcc; `C3`/`C2` ret; `50-57` push, `58-5F` pop, `FF /6` push; `8D` lea; `88-8B`,`C6`,`C7`,`B0-BF` mov; `FF /2,/3` call r/m, `FF /4,/5` jmp r/m (stubs are `FF 25 disp32` = `jmp *rip+disp`).
Verified targets: `jmp 0x100004385` (E9 at `0x100000725`), `jg 0x100000777` (7F 1A at `0x10000075b`), `lea 0x10000558c` (`48 8D 05 0C 4E 00 00` at `0x100000779` → `0x100000780 + 0x4e0c`).

### C.4 Inline data in `__text` (observed) and how to survive it

`/bin/ls` x86_64 contains a switch jump table **inside `__text`** at `0x1000014b0` (92 × int32 entries, ends `0x100001620`), placed
right after `callq _err` (noreturn) + `nopl` padding, inside a function (no `LC_FUNCTION_STARTS` entry in `[0x1000014a0,0x100001620)`)
and with an **empty `LC_DATA_IN_CODE` table** (`otool -G` → 0 entries for both slices). otool itself prints garbage there (`insl`, `ljmpl`, `.byte 0xff #bad opcode`) and never resyncs at `0x100001620`.
Detection heuristic that recovers it: `leaq disp(%rip), %rN` whose target lies inside `__text` and is not a function start, followed within a few instructions by
`movslq (%rN,%rM,4), %rax ; addq %rN, %rax ; jmpq *%rax` with a preceding `cmpl $K, %reg ; ja` → mark `[target, target + 4·(K+1))` as data (`dd` relative entries → add table base to get case addresses = extra function-internal targets).
Verified: `leaq 0x9bc(%rip), %r13` at `0x100000aed` → `0x1000014b0`; `cmpl $0x5b, %ecx` → 0x5c entries → end `0x100001620`.
General rule: decode **per function** (start from each function start, stop at the next), and after an unconditional `jmp/ret/call-to-noreturn` prefer the next known target/function start over blind linear sweep.

### C.5 otool's x86 immediate spelling vs Capstone's (verified 2026-09-12)

otool prints the MCOperand through LLVM's `formatImm` (**signed** hex) and appends `## imm = 0x<UPPER>`
**only when the signed value is outside [-256, 255]**, padded to column 32 of the operand field
(`PadToColumn`, so at least one space when the operands are already ≥ 32 characters), printing the value
at the narrowest of 16/32/64 bits that holds it (`andq $-0x10000` → `imm = 0xFFFF0000`). Capstone
agrees on nearly everything but prints the *unsigned* value for the cases below, so the rewrite needs
the instruction bytes — the printed text alone cannot say whether a set top bit is a sign bit.

LLVM's X86 disassembler sign-extends the encoded immediate when, and only when:

* it is **1 byte** and is a number rather than a control field — the control ("raw") imm8 opcodes are
  `C0`/`C1` (shift counts), `CD` (`int`), `E4`-`E7` (`in`/`out` port), the 2-byte map `70`-`73`, `A4`,
  `AC`, `BA`, `C2`, `C4`, `C5`, `C6`, and every `0F3A` opcode (which includes the VEX `0F3A` map); or
* it is **8 bytes** (`movabs`, the value is already an i64); or
* it is **narrower than the operand size** (`48 81 /4 id` → `andq $-0xc1`; `68 id` → `pushq $-0xc1`,
  because PUSH's default operand size is 64 in long mode; `C2 iw` → `retq $-0x100`).

A same-width immediate stays unsigned: `81 /4 id` → `andl $0xffffff3f`, `66 81 /4 iw` → `andw $0xff3f`,
`B9 id` → `movl $0xffffff3f`, `66 B9 iw` → `movw $0xff00`. Probes: `ximm.s`, `ximm2.s`, `ximm3.s`,
`io.s`, `b0.s` (assembled with `clang -c -arch x86_64`, read back with `otool -tV`).

Capstone also drops LLVM's `X86InstComments` shuffle notes (`## xmm0 = xmm0[0,1,0,1]`). In a
1.36M-instruction sample of 70 system binaries there were 496 of them: `pshufd` 276, `pshuflw` 75,
`pshufhw` 72 (85% together, reconstructed by machre), then `punpckldq` 27, `unpcklps` 17 and a long
tail of blend/unpck/movddup/pmovzx forms that machre does **not** reproduce.

---

## Part D. Function discovery and stub symbolisation

### D.1 Function discovery (in priority order)

1. **`LC_FUNCTION_STARTS`** (`LC.FUNCTION_STARTS = 0x26`, `linkedit_data_command{dataoff,datasize}`): ULEB128 deltas starting from `__TEXT` vmaddr; a zero delta terminates (the blob is zero-padded).
   Reference decoder `funcstarts.py` reproduces `dyld_info -function_starts` exactly: both slices of `/bin/ls` have 50 functions; arm64e first entries `0x100000700, 0x10000070c, 0x10000071c, 0x100000780, ...`.
   Present in every ld64/lld output including stripped binaries; absent only in hand-crafted/packed files.
2. **Symbol table**: `nlist_64` with `(n_type & N_STAB)==0`, `(n_type & N_TYPE)==N_SECT (0xe)` and `n_sect` == index of `__TEXT,__text` (or any `S_ATTR_PURE_INSTRUCTIONS` section). Gives names for (1). `/bin/ls` is stripped: only `__mh_execute_header` is defined (91 symbols, 90 undefined). Local `s` symbols do survive in many system binaries (e.g. `_objc_msgSend$sel` in plutil).
3. **Exports trie** (`LC_DYLD_EXPORTS_TRIE` for chained-fixup binaries, else `LC_DYLD_INFO(_ONLY).export_off`): dylibs export their public functions here (`dyld_info -exports libcapstone.5.dylib` → `_cs_close @0xEFC` ...). Executables export almost nothing.
4. **`LC_MAIN.entryoff`** (+ `__TEXT` vmaddr) and, for ObjC, every method IMP from `__objc_classlist → class_ro_t.baseMethods` (and categories, protocols): `dyld_info -objc plutil` lists `-[PLUMutableArray initWithCapacity:] @0x100001310` etc. — use as names for function starts.
5. **Tertiary**: targets of `BL`/`call rel32` that land in `__text` but are not yet known; `B` targets that land in a gap after a `ret`/`b`; jump-table case addresses (C.4); `__unwind_info`/`__eh_frame` FDE starts; ADRP+ADD results that land in `__text` (function pointers, blocks).

### D.2 Stub sections and `bl 0x... ; symbol stub for: _name`

Section shapes seen (`otool -l`):

| slice | section | flags | reserved1 | reserved2 | body |
|---|---|---|---|---|---|
| arm64e | `__TEXT,__auth_stubs` | `0x80000408` = PURE_INSTRUCTIONS \| SOME_INSTRUCTIONS \| **S_SYMBOL_STUBS (0x8)** | 0 (indirect-symbol index base) | **16** (stub size) | `adrp x17, page ; add x17, x17, #off ; ldr x16, [x17] ; braa x16, x17` |
| arm64 (non-PAC, typical) | `__TEXT,__stubs` | same | n | **12** | `adrp x16, page ; ldr x16, [x16, #off] ; br x16` **(shape unverified here; only arm64e binaries were at hand)** |
| x86_64 | `__TEXT,__stubs` | `0x80000408` | 0 | **6** | `FF 25 disp32` = `jmpq *disp(%rip)` → `__la_symbol_ptr` (classic) or `__got` (chained) |
| x86_64 classic | `__TEXT,__stub_helper` | `0x80000400` | — | — | `leaq dyld_private(%rip),%r11; pushq %r11; jmpq *dyld_stub_binder@GOT(%rip)` then per-stub `pushq $bind_off ; jmp helper` |
| arm64e | `__DATA_CONST,__auth_got` | `0x6` S_NON_LAZY_SYMBOL_POINTERS | 84 | 0 | chained `dyld_chained_ptr_arm64e_auth_bind` slots |
| arm64e | `__DATA_CONST,__got` | `0x6` | 168 | 0 | |
| x86_64 | `__DATA,__got` / `__DATA,__la_symbol_ptr` | `0x6` / `0x7` (S_LAZY_SYMBOL_POINTERS) | 84 / 91 | 0 | |
| any (ObjC) | `__TEXT,__objc_stubs` | `0x80000400` (S_REGULAR!) | 0 | 0 | 32-byte: `adrp x1, selref@PAGE ; ldr x1, [x1, #off] ; adrp x17, got@PAGE ; add x17, x17, #off ; ldr x16, [x17] ; braa x16, x17 ; brk #1 ; brk #1` |

**Algorithm A (indirect symbol table)** — works for `S_SYMBOL_STUBS`, lazy and non-lazy pointer sections:
`stub_index = (target - sect.addr) / sect.reserved2` (for pointer sections divide by 8) → `indirect_symtab[sect.reserved1 + stub_index]` (u32 array at `LC_DYSYMTAB.indirectsymoff`, `nindirectsyms` entries; `/bin/ls` arm64e: off 68544, 174 entries) → `nlist_64[value]` → name at `stroff + n_strx`.
Special values: `INDIRECT_SYMBOL_LOCAL 0x80000000`, `INDIRECT_SYMBOL_ABS 0x40000000` (may be OR'd) → no name.
Verified: `bl/b 0x10000468c` → `(0x10000468c-0x1000042ac)/16 = 62` → indirect[62] = **70** → symtab #70 = `_strcoll` (`otool -Iv` agrees); stub 0 → indirect[0] = 3 → `___assert_rtn` (`nm -pa` order: 0 = `OPT radr` stab, 1 `__mh_execute_header`, 2 `__DefaultRuneLocale`, 3 `___assert_rtn`).

**Algorithm B (follow the pointer slot)** — needed for `__objc_stubs`, for stripped indirect tables, and as a cross-check:
decode the stub's `adrp Xn, page` + `add Xn, Xn, #off` / `ldr Xm, [Xn, #off]` → slot address (`0x100008028` for stub 0). Then:
- chained fixups (`LC_DYLD_CHAINED_FIXUPS`): the raw slot is a `dyld_chained_ptr_arm64e_auth_bind` `{ordinal:16, zero:16, diversity:16, addrDiv:1, key:2, next:11, bind:1, auth:1}` (pointer_format 1 = `DYLD_CHAINED_PTR_ARM64E`, `imports_format 1 = DYLD_CHAINED_IMPORT`, 90 imports for `/bin/ls`). `0x100008028` holds `0xc009000000000005` → bind=1, auth=1, next=1 (×8 B), key=IA, addrDiv=1, **ordinal 5** → imports[5] = `___assert_rtn` (from libSystem); `dyld_info -fixups` shows the same. Non-auth bind is `dyld_chained_ptr_arm64e_bind {ordinal:16, zero:16, addend:19, next:11, bind:1, auth:1}`; rebase forms have bind=0 and carry the target vmaddr (`target:43, high8:8` / auth: `target:32`). Other pointer formats (`DYLD_CHAINED_PTR_64 = 2`, `64_OFFSET = 6`) use `{ordinal:24, addend:8, reserved:19, next:12, bind:1}`.
- classic (`LC_DYLD_INFO_ONLY`): walk the bind / lazy-bind opcode streams and record `segment+offset → symbol name`; `__la_symbol_ptr` slots initially point into `__stub_helper` (the `pushq $off` there is the lazy-bind stream offset).

**ObjC message stubs**: `bl 0x1000208c0` into `__objc_stubs` → prefer the local symbol `_objc_msgSend$JSONObjectWithData:options:error:` (present as `s` symbols in plutil); if stripped, decode the first `adrp x1`+`ldr x1,[x1,#off]` → `__objc_selrefs` slot → its rebase target (chained rebase or `LC_DYLD_INFO` rebase; on-disk value already holds the vmaddr for non-chained) → cstring in `__TEXT,__objc_methname` → print `bl "_objc_msgSend$sel"` (otool prints the quoted name).

### D.3 Annotation strategy (otool/Hopper-style `;` comments)

Per function, keep `page[reg]` from the most recent `ADRP` (invalidate on any other write to `reg` or at a label/branch target):
- `adrp x8, N` → `; 0x10000c000` (otool prints the resolved page).
- `add Xd, Xn, #off` with `page[Xn]` → address `A`; comment by section: `__cstring`/`__objc_methname`/`__objc_classname` → `; literal pool for: "text"`; `__objc_selrefs` → `; Objc selector ref: sel`; `__objc_classrefs` → `; Objc class ref: _OBJC_CLASS_$_Name`; `__data`/`__common` → symbol name if any; `__text` → function name.
- `ldr Xt, [Xn, #off]` with `page[Xn]` → slot `S`: if `S` is in `__got`/`__auth_got` → bind target name → `; literal pool symbol address: _optarg` (seen at `0x100000d50`); if a rebase → resolved pointer → recurse one level (e.g. `__objc_classrefs` slot → `; Objc class ref: ...`, `__objc_selrefs` → selector string).
- `bl`/`b` target: in a stub section → `; symbol stub for: _name`; in `__objc_stubs` → quoted `_objc_msgSend$sel`; in `__text` with a known function → name (`; -[PLUMutableArray count]` from ObjC metadata); `bl _objc_msgSendSuper2` gets `; Objc message: _objc_msgSendSuper2`.
- `ldr` literal → `; 0x...` value or string; `b.cond`/`cbz`/`tbz` → nothing (targets are inside the function).
- x86_64: `call/jmp rel32` into `__stubs` → `## symbol stub for: _name` (otool prints **nothing** for x86_64, so this is an improvement); `lea disp(%rip)` → same section-based comment; `call *disp(%rip)`/`jmp *disp(%rip)` → `__got` bind name.
- arm64e prologue/epilogue: `pacibsp`…`retab` (seen at `0x100000960` / `0x1000019f0`); a function starting with `pacibsp`/`paciasp`/`bti c` is a strong function-start hint for tertiary discovery.

Mach-O constants (confirmed in `std.macho` and SDK `loader.h`): `S_SYMBOL_STUBS = 0x8`, `S_LAZY_SYMBOL_POINTERS = 0x7`, `S_NON_LAZY_SYMBOL_POINTERS = 0x6`,
`S_ATTR_PURE_INSTRUCTIONS = 0x80000000`, `S_ATTR_SOME_INSTRUCTIONS = 0x400`, `SECTION_TYPE = 0xff`, `INDIRECT_SYMBOL_LOCAL = 0x80000000`, `INDIRECT_SYMBOL_ABS = 0x40000000`,
`N_STAB = 0xe0`, `N_TYPE = 0x0e`, `N_SECT = 0xe`, `LC.FUNCTION_STARTS = 0x26`, `LC.DATA_IN_CODE = 0x29` (`std.macho.data_in_code_entry`), `LC.DYLD_EXPORTS_TRIE = 0x33|LC_REQ_DYLD`, `LC.DYLD_CHAINED_FIXUPS = 0x34|LC_REQ_DYLD`.

---

## Probe files (scratchpad)

- `probe-capstone/build.zig`, `probe-capstone/src/main.zig` — the Zig project; `run-dynamic.txt` = captured output; `layout.c` = C offsetof probe; `cimport.zig` = the failing `@cImport` check; `probe-norpath` = dyld failure repro.
- `disasm-notes/a64.s`, `a64b.s`, `a64e.s` + `*.dis` — clang-assembled arm64/arm64e corpus with `objdump -d` bytes (123 + 156 + 43 instructions).
- `disasm-notes/a64probe.zig` — `zig test`: DecodeBitMasks + field-extraction tests (2/2 pass).
- `disasm-notes/x86len.py` + `x86len-big.out` — length decoder and its 1496-instruction run; `funcstarts.py` — LC_FUNCTION_STARTS decoder.
- `disasm-notes/ls.arm64e`, `ls.x86_64` — thin slices of `/bin/ls` (`lipo -thin`).

---

## Part E. Completeness-critic additions (verified 2026-09-11)

### E.1 Capstone 5.0.8 on arm64e PAC / BTI instructions and zero words (C probe `scratchpad/critic/cspac.c`)
`cs_disasm(CS_ARCH_ARM64, CS_MODE_ARM)` decodes every PAC instruction tried: `pacibsp` (d503237f, id 698), `retab`
(d65f0fff, 735), `brab x2, x3` (d71f0c43, 77), `ldraa x0, [x1]` (f8200420, 559), `braa x0, x1` (d71f0801, 75),
`autibsp` (d50323ff, 42), `bti c` (d503245f, 94), `xpaclri` (d50320ff, 1272), `blraaz x9` (d63f093f, 71),
`paciza x16` (dac123f0, 700), `nop` (d503201f, 677). **A zero word decodes as `udf #0` (id 1155)** — Capstone does
not stop at zero padding between functions, so `CS_OPT_SKIPDATA` only matters for genuinely unallocated encodings
(both runs returned 12/12 instructions). Never use "Capstone stopped" as a function-end signal; use
`LC_FUNCTION_STARTS` (D.1). Capstone's ARM64 PAC mnemonics match `otool`/`objdump` spelling (`retab`, `braa`, `ldraa`).

### E.2 `__objc_stubs` stride
32 bytes per stub with this SDK's ld (hello-objc: 0x1e0 / 32 = 15 stubs, section align 2^5, `reserved2 = 0` because the
section is S_REGULAR). Recover the selector from the first `adrp x1` + `ldr x1, [x1, #off]` pair (D.2, Algorithm B).

### E.3 Annotating `__cfstring` targets
An `adrp/add` pair resolving into `__DATA_CONST,__cfstring` points at a 32-byte constant CFString `{isa, flags, data,
length}` (format-notes 12.1). Print `@"text"` by following `data` (a chained-fixup rebase slot → `__cstring` when
`flags == 0x7c8`, `__TEXT,__ustring` UTF-16LE when `flags == 0x7d0`). ObjC string literals appear nowhere else, so this
is the only way to show them next to `objc_msgSend` calls.

### E.4 Resolving `LC_LOAD_DYLIB` paths for a "missing dependency" heuristic
System libraries have no on-disk file; `_dyld_shared_cache_contains_path("/usr/lib/libSystem.B.dylib")` is true
(zig-api-notes 15.10, format-notes 12.8). Flag a dependency as missing only when it is neither on disk (after
`@rpath` / `@executable_path` / `@loader_path` expansion) nor in the shared cache.
