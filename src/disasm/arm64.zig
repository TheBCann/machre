//! disasm/arm64.zig — built-in arm64 decoder (disasm-notes Part B). Imports: disasm/insn.
//!
//! Text spelling follows otool/LLVM (disasm-notes B.1), verified word-by-word against
//! `otool -arch arm64e -tv` for the 291-encoding corpus of Part B (see the table test below).
//! Three deliberate deviations, all documented at their site:
//!   * unallocated words print `.inst 0x%08x` (DESIGN §4.24) where otool prints `.long`;
//!   * SIMD uses ARM syntax (`dup v0.4s, w1`) in the default listing; `Style.darwin` (selected by
//!     `--otool-compat`) hoists the arrangement onto the mnemonic the way Darwin otool does
//!     (`dup.4s v0, w1`, `mov.d v0[1], x1`, `movi.2d v0, #...`) -- notes B.7;
//!   * `ldr <Xt>, <label>` prints the resolved address like every other literal load, where LLVM
//!     prints the raw offset only for that one encoding.
//! Every path is total: no allocation outside `decodeOne`, no loops over attacker data except the
//! bounded replicate loop in `decodeBitMasks`, and any unrecognised word falls back to `.inst`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");

const Kind = insn.Kind;
const Insn = insn.Insn;
const MemRef = insn.MemRef;

/// Longest operand text any encoding produces ("x10, [x11, w12, sxtw #3]" and friends).
const ops_cap = 96;

// ---------------------------------------------------------------------------------------------
// bit helpers
// ---------------------------------------------------------------------------------------------

fn bits(w: u32, hi: u5, lo: u5) u32 {
    const width: u6 = @as(u6, hi) - @as(u6, lo) + 1;
    const mask: u64 = (@as(u64, 1) << width) - 1;
    return @truncate((w >> lo) & @as(u32, @truncate(mask)));
}
fn bit(w: u32, n: u5) u1 {
    return @truncate(w >> n);
}
fn sext(v: u64, width: u7) i64 {
    if (width == 0 or width >= 64) return @bitCast(v);
    const shift: u6 = @intCast(64 - width);
    return @as(i64, @bitCast(v << shift)) >> shift;
}
fn reg(w: u32, lo: u5) u5 {
    return @truncate(bits(w, lo + 4, lo));
}

// ---------------------------------------------------------------------------------------------
// text buffer
// ---------------------------------------------------------------------------------------------

const Buf = struct {
    data: [ops_cap]u8 = undefined,
    len: u8 = 0,

    fn str(b: *Buf, s: []const u8) void {
        const room: usize = ops_cap - @as(usize, b.len);
        const n = @min(room, s.len);
        @memcpy(b.data[b.len..][0..n], s[0..n]);
        b.len += @intCast(n);
    }
    fn print(b: *Buf, comptime fmt: []const u8, args: anytype) void {
        const written = std.fmt.bufPrint(b.data[b.len..], fmt, args) catch return;
        b.len += @intCast(written.len);
    }
    fn view(b: *const Buf) []const u8 {
        return b.data[0..b.len];
    }
};

/// `x0`..`x30`, `xzr`/`sp`, `w0`..`w30`, `wzr`/`wsp` (disasm-notes B.1 register-31 rules).
fn gpr(b: *Buf, is64: bool, n: u5, sp_form: bool) void {
    if (n == 31) {
        b.str(if (is64) (if (sp_form) "sp" else "xzr") else (if (sp_form) "wsp" else "wzr"));
        return;
    }
    b.print("{c}{d}", .{ @as(u8, if (is64) 'x' else 'w'), @as(u32, n) });
}
/// `#0x1f` — hex with the `0x` prefix even for zero (LLVM `formatImm` with PrintImmHex).
fn hexImm(b: *Buf, v: u64) void {
    b.print("#0x{x}", .{v});
}
/// `#0` for zero, `#0x..` otherwise — the exception-generating instructions (brk/hlt/svc/…).
fn hexImmZeroBare(b: *Buf, v: u64) void {
    if (v == 0) b.str("#0") else b.print("#0x{x}", .{v});
}
/// `#-0x10` / `#0x10`.
fn signedHexImm(b: *Buf, v: i64) void {
    // Two's-complement magnitude: `-v` would overflow for the i64 minimum, which `mov x0,
    // #0x8000000000000000` (an ORR bitmask immediate) really produces.
    if (v < 0) b.print("#-0x{x}", .{~@as(u64, @bitCast(v)) +% 1}) else b.print("#0x{x}", .{@as(u64, @intCast(v))});
}
/// `#5` / `#-5` — shift amounts, extend amounts, bitfield widths, barrier options.
fn decImm(b: *Buf, v: i64) void {
    b.print("#{d}", .{v});
}
/// Branch/label targets: bare hex, otool style.
fn targetAddr(b: *Buf, a: u64) void {
    b.print("0x{x}", .{a});
}

/// SIMD text dialect. `.arm` is ARM's canonical spelling (`movi v0.2d, #0`, `mov v0.d[1], x1`);
/// `.darwin` is what otool and `objdump --macho` print, where the vector arrangement (or the element
/// letter) moves from the operands onto the mnemonic (`movi.2d v0, #0`, `mov.d v0[1], x1`). Verified
/// against `otool -tV` of an assembled corpus covering every form this file emits (disasm-notes B.7).
pub const Style = enum { arm, darwin };

/// `v3.4s` (ARM) or bare `v3` with the arrangement hoisted onto the mnemonic (Darwin).
fn vreg(b: *Buf, st: Style, n: u5, arr: []const u8) void {
    if (st == .darwin) b.print("v{d}", .{@as(u32, n)}) else b.print("v{d}.{s}", .{ @as(u32, n), arr });
}
/// `v3.d[1]` (ARM) or `v3[1]` with the element letter hoisted onto the mnemonic (Darwin).
fn velem(b: *Buf, st: Style, n: u5, letter: u8, index: u32) void {
    if (st == .darwin) b.print("v{d}[{d}]", .{ @as(u32, n), index }) else b.print("v{d}.{c}[{d}]", .{ @as(u32, n), letter, index });
}

pub fn condName(cond: u4) []const u8 {
    return switch (cond) {
        0 => "eq",
        1 => "ne",
        2 => "hs",
        3 => "lo",
        4 => "mi",
        5 => "pl",
        6 => "vs",
        7 => "vc",
        8 => "hi",
        9 => "ls",
        10 => "ge",
        11 => "lt",
        12 => "gt",
        13 => "le",
        14 => "al",
        15 => "nv",
    };
}

// ---------------------------------------------------------------------------------------------
// decoded record
// ---------------------------------------------------------------------------------------------

const Dec = struct {
    /// Static mnemonic; `mlen > 0` means the mnemonic lives in `mbuf` instead (LSE/exclusive suffixes).
    mstatic: []const u8 = ".inst",
    mbuf: [16]u8 = undefined,
    mlen: u8 = 0,
    ops: Buf = .{},
    kind: Kind = .other,
    target: ?u64 = null,
    reg_write: ?u5 = null,
    /// GPR writes BESIDES `reg_write` (LDP's Rt2, a pre/post-index base, LDXP's Rt2, STXR/STXP's status
    /// Rs, CASP's Rs+1). `toInsn` merges these with `reg_write` into `Insn.reg_writes`; keeping them in
    /// one place is what stops the two from drifting apart.
    extra_writes: u32 = 0,
    imm: ?u64 = null,
    mem_ref: ?MemRef = null,
    valid: bool = true,

    /// Records one more written GPR. `sp_form` says whether register 31 is SP (a real write) or XZR
    /// (discarded), exactly as in `regWrite`.
    fn alsoWrites(d: *Dec, r: u5, sp_form: bool) void {
        if (regWrite(r, sp_form)) |x| d.extra_writes |= @as(u32, 1) << x;
    }
    fn mnem(d: *const Dec) []const u8 {
        return if (d.mlen > 0) d.mbuf[0..d.mlen] else d.mstatic;
    }
    fn setMnem(d: *Dec, s: []const u8) void {
        d.mstatic = s;
        d.mlen = 0;
    }
    /// `base` in ARM style, `base.<arrangement>` in Darwin style (the suffix the operands gave up).
    fn simdMnem(d: *Dec, st: Style, base: []const u8, arr: []const u8) void {
        if (st == .darwin) d.buildMnem(&.{ base, ".", arr }) else d.setMnem(base);
    }
    /// Writes a run-time built mnemonic (base + suffixes) into `mbuf`.
    fn buildMnem(d: *Dec, parts: []const []const u8) void {
        var n: usize = 0;
        for (parts) |p| {
            const room = d.mbuf.len - n;
            const k = @min(room, p.len);
            @memcpy(d.mbuf[n..][0..k], p[0..k]);
            n += k;
        }
        d.mlen = @intCast(n);
    }
};

fn undef(w: u32) Dec {
    var d: Dec = .{ .kind = .invalid, .valid = false };
    d.setMnem(".inst");
    d.ops.print("0x{x:0>8}", .{w});
    return d;
}

/// `?u5` register write: register 31 is a write only in SP form.
fn regWrite(rd: u5, sp_form: bool) ?u5 {
    if (rd == 31 and !sp_form) return null;
    return rd;
}

// ---------------------------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------------------------

/// Decodes exactly one 32-bit word at `pc`. Unknown -> mnemonic ".inst", operands "0x%08x", kind .invalid,
/// valid=false. Text is arena-owned (mnemonic/operands built with otool/LLVM spelling rules).
pub fn decodeOne(arena: Allocator, word: u32, pc: u64, style: Style) Allocator.Error!Insn {
    var d = decode(word, pc, style);
    const m = if (d.mlen > 0) try arena.dupe(u8, d.mnem()) else d.mstatic;
    const o = try arena.dupe(u8, d.ops.view());
    return toInsn(&d, word, pc, m, o);
}

/// Semantic-only decode (no text allocation): kind/target/reg_write/imm/mem_ref. Used by the engine when
/// Capstone supplies the text. `mnemonic` carries the static spelling when one exists (never allocated);
/// `operands` is always empty.
pub fn decodeSemantic(word: u32, pc: u64) Insn {
    var d = decode(word, pc, .arm);
    return toInsn(&d, word, pc, if (d.mlen > 0) "" else d.mstatic, "");
}

fn toInsn(d: *const Dec, word: u32, pc: u64, mnemonic: []const u8, operands: []const u8) Insn {
    var raw: [16]u8 = @splat(0);
    std.mem.writeInt(u32, raw[0..4], word, .little);
    return .{
        .addr = pc,
        .size = 4,
        .bytes = raw,
        .mnemonic = mnemonic,
        .operands = operands,
        .kind = d.kind,
        .target = d.target,
        .reg_write = d.reg_write,
        .reg_writes = (if (d.reg_write) |r| @as(u32, 1) << r else 0) | d.extra_writes,
        .imm = d.imm,
        .mem_ref = d.mem_ref,
        .valid = d.valid,
        .text_from = .builtin_arm64,
        .semantic_from = .builtin_arm64,
        .partial = false,
    };
}

/// DecodeBitMasks(N, imms, immr) -> wmask for `datasize` (32/64); null for reserved encodings.
pub fn decodeBitMasks(n: u1, imms: u6, immr: u6, datasize: u8) ?u64 {
    if (datasize != 32 and datasize != 64) return null;
    const not_imms: u6 = ~imms;
    const combined: u7 = (@as(u7, n) << 6) | @as(u7, not_imms);
    if (combined == 0) return null;
    const len: u3 = @intCast(31 - @clz(@as(u32, combined)));
    if (len < 1) return null;
    const esize: u8 = @as(u8, 1) << len;
    if (esize > datasize) return null;
    const levels: u6 = @intCast((@as(u32, 1) << len) - 1);
    const s: u6 = imms & levels;
    if (s == levels) return null; // "imms == levels" is reserved for the immediate forms
    const r: u6 = immr & levels;
    const width: u7 = @as(u7, s) + 1;
    const elem_mask: u64 = if (esize >= 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(esize)) - 1;
    const welem: u64 = (if (width >= 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(width)) - 1) & elem_mask;
    const rot: u6 = @intCast(@as(u32, r) % esize);
    const elem: u64 = if (rot == 0) welem else ((welem >> rot) | (welem << @intCast(esize - rot))) & elem_mask;
    var result: u64 = 0;
    var i: u8 = 0;
    while (i < datasize) : (i += esize) result |= elem << @intCast(i);
    if (datasize == 32) result &= 0xffff_ffff;
    return result;
}

// ---------------------------------------------------------------------------------------------
// top-level dispatch (disasm-notes B.2: op0 = bits 28..25)
// ---------------------------------------------------------------------------------------------

fn decode(w: u32, pc: u64, st: Style) Dec {
    const op0 = bits(w, 28, 25);
    if (op0 & 0b1110 == 0b1000) return dpImm(w, pc);
    if (op0 & 0b1110 == 0b1010) return branchSys(w, pc);
    if (op0 & 0b0101 == 0b0100) return loadStore(w, pc);
    if (op0 & 0b0111 == 0b0101) return dpReg(w);
    if (op0 & 0b0111 == 0b0111) return simdFp(w, st);
    // op0 == 0000 is the reserved class; only UDF is allocated there.
    if (bits(w, 31, 16) == 0) {
        var d: Dec = .{ .kind = .trap };
        d.setMnem("udf");
        hexImm(&d.ops, bits(w, 15, 0));
        return d;
    }
    return undef(w);
}

// ---------------------------------------------------------------------------------------------
// B.3 data-processing immediate
// ---------------------------------------------------------------------------------------------

fn dpImm(w: u32, pc: u64) Dec {
    return switch (bits(w, 25, 23)) {
        0b000, 0b001 => adrClass(w, pc),
        0b010 => addSubImm(w),
        0b100 => logicalImm(w),
        0b101 => moveWide(w),
        0b110 => bitfield(w),
        0b111 => extract(w),
        else => undef(w), // 011 = ADDG/SUBG memory tagging
    };
}

fn adrClass(w: u32, pc: u64) Dec {
    const is_adrp = bit(w, 31) == 1;
    const imm21 = sext((@as(u64, bits(w, 23, 5)) << 2) | bits(w, 30, 29), 21);
    const rd = reg(w, 0);
    // ADR/ADRP's Rd == 31 is XZR, not SP: the computed page is DISCARDED. Reporting it as a write made
    // `symbolize` record `adrp xzr, #page` into the slot it also uses for SP, so a later `ldr x0, [sp,
    // #off]` folded against a page the program never put there. `regWrite(rd, false)` reports nothing,
    // which is what "the result is thrown away" means.
    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (is_adrp) {
        d.setMnem("adrp");
        d.kind = .adrp;
        // `imm` carries the RESOLVED page address; `target` stays null (it is control flow only).
        d.imm = (pc & ~@as(u64, 0xfff)) +% (@as(u64, @bitCast(imm21)) *% 4096);
        gpr(&d.ops, true, rd, false);
        d.ops.print(", {d}", .{imm21});
    } else {
        d.setMnem("adr");
        d.kind = .adr;
        d.imm = pc +% @as(u64, @bitCast(imm21));
        gpr(&d.ops, true, rd, false);
        d.ops.str(", ");
        decImm(&d.ops, imm21);
    }
    return d;
}

fn addSubImm(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const is_sub = bit(w, 30) == 1;
    const sets_flags = bit(w, 29) == 1;
    const shift12 = bit(w, 22) == 1;
    const imm12 = bits(w, 21, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    const value: u64 = @as(u64, imm12) << (if (shift12) @as(u6, 12) else 0);

    var d: Dec = .{};
    // MOV Rd, Rn — ADD with a zero immediate and an SP operand.
    if (!is_sub and !sets_flags and imm12 == 0 and !shift12 and (rd == 31 or rn == 31)) {
        d.setMnem("mov");
        d.reg_write = rd;
        gpr(&d.ops, is64, rd, true);
        d.ops.str(", ");
        gpr(&d.ops, is64, rn, true);
        return d;
    }
    const alias_cmp = sets_flags and rd == 31;
    if (alias_cmp) {
        d.setMnem(if (is_sub) "cmp" else "cmn");
    } else {
        d.setMnem(if (is_sub) (if (sets_flags) "subs" else "sub") else (if (sets_flags) "adds" else "add"));
        d.reg_write = regWrite(rd, !sets_flags);
        gpr(&d.ops, is64, rd, !sets_flags);
        d.ops.str(", ");
    }
    gpr(&d.ops, is64, rn, true);
    d.ops.str(", ");
    hexImm(&d.ops, imm12); // otool prints the raw imm12 and the shift separately
    if (shift12) d.ops.str(", lsl #12");
    if (!is_sub and !sets_flags) {
        d.kind = .add_imm;
        d.imm = value;
    }
    return d;
}

fn logicalImm(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const opc = bits(w, 30, 29);
    const n: u1 = @truncate(bits(w, 22, 22));
    const immr: u6 = @truncate(bits(w, 21, 16));
    const imms: u6 = @truncate(bits(w, 15, 10));
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (!is64 and n == 1) return undef(w);
    const value = decodeBitMasks(n, imms, immr, if (is64) 64 else 32) orelse return undef(w);

    var d: Dec = .{};
    const is_ands = opc == 3;
    if (is_ands and rd == 31) { // TST
        d.setMnem("tst");
        gpr(&d.ops, is64, rn, false);
        d.ops.str(", ");
        hexImm(&d.ops, value);
        return d;
    }
    if (opc == 1 and rn == 31 and rd != 31) { // MOV (bitmask immediate); Rd == SP keeps the ORR form
        d.setMnem("mov");
        d.kind = .mov_imm;
        d.imm = value;
        d.reg_write = rd;
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        // LLVM prints the MOV alias' immediate through formatImm (signed at the register width), so
        // `orr x9, xzr, #0x8888888888888888` reads `mov x9, #-0x7777777777777778` -- but the plain
        // AND/ORR/EOR/ANDS/TST forms below stay unsigned. Verified with `otool -tV` (disasm-notes B.3).
        signedHexImm(&d.ops, if (is64) @bitCast(value) else @as(i64, @as(i32, @bitCast(@as(u32, @truncate(value))))));
        return d;
    }
    d.setMnem(switch (opc) {
        0 => "and",
        1 => "orr",
        2 => "eor",
        else => "ands",
    });
    d.reg_write = regWrite(rd, !is_ands);
    gpr(&d.ops, is64, rd, !is_ands);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    hexImm(&d.ops, value);
    return d;
}

fn moveWide(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const opc = bits(w, 30, 29);
    const hw = bits(w, 22, 21);
    const imm16 = bits(w, 20, 5);
    const rd = reg(w, 0);
    if (opc == 1) return undef(w);
    if (!is64 and hw > 1) return undef(w);
    const shift: u6 = @intCast(16 * hw);
    const shifted: u64 = @as(u64, imm16) << shift;
    const mask: u64 = if (is64) ~@as(u64, 0) else 0xffff_ffff;

    var d: Dec = .{ .reg_write = rd };
    if (opc == 3) { // MOVK never aliases
        d.setMnem("movk");
        d.kind = .movk;
        d.imm = shifted & mask;
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        hexImm(&d.ops, imm16);
        if (hw != 0) d.ops.print(", lsl #{d}", .{shift});
        return d;
    }
    const is_movz = opc == 2;
    const value: u64 = if (is_movz) (shifted & mask) else (~shifted & mask);
    const aliasable = !(imm16 == 0 and hw != 0) and !(!is_movz and !is64 and imm16 == 0xffff);
    if (aliasable) {
        d.setMnem("mov");
        d.kind = .mov_imm;
        d.imm = value;
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        // The MOV alias (MOVZ *and* MOVN) prints through LLVM's formatImm, i.e. signed at the register
        // width: `movz x0, #0x8000, lsl #48` reads `mov x0, #-0x8000000000000000`. The un-aliased
        // movz/movn/movk forms below keep the raw unsigned imm16. Verified with `otool -tV`.
        const signed: i64 = if (is64) @bitCast(value) else @as(i64, @as(i32, @bitCast(@as(u32, @truncate(value)))));
        signedHexImm(&d.ops, signed);
        return d;
    }
    d.setMnem(if (is_movz) "movz" else "movn");
    d.kind = .mov_imm;
    d.imm = value;
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    hexImm(&d.ops, imm16);
    if (hw != 0) d.ops.print(", lsl #{d}", .{shift});
    return d;
}

fn bitfield(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const opc = bits(w, 30, 29);
    const n: u1 = @truncate(bits(w, 22, 22));
    const immr: u32 = bits(w, 21, 16);
    const imms: u32 = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (opc == 3) return undef(w);
    if ((n == 1) != is64) return undef(w);
    const width: u32 = if (is64) 64 else 32;
    if (immr >= width or imms >= width) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    const lsb: u32 = (width - immr) % width;
    const fw: u32 = imms + 1;

    switch (opc) {
        2 => { // UBFM
            if (imms != width - 1 and imms + 1 == immr) {
                d.setMnem("lsl");
                bf3(&d, is64, rd, rn, @intCast(width - 1 - imms));
            } else if (imms == width - 1) {
                d.setMnem("lsr");
                bf3(&d, is64, rd, rn, @intCast(immr));
            } else if (!is64 and immr == 0 and imms == 7) {
                d.setMnem("uxtb");
                bf2w(&d, is64, rd, rn);
            } else if (!is64 and immr == 0 and imms == 15) {
                d.setMnem("uxth");
                bf2w(&d, is64, rd, rn);
            } else if (imms < immr) {
                d.setMnem("ubfiz");
                bf4(&d, is64, rd, rn, lsb, fw);
            } else {
                d.setMnem("ubfx");
                bf4(&d, is64, rd, rn, immr, imms - immr + 1);
            }
        },
        0 => { // SBFM
            if (imms == width - 1) {
                d.setMnem("asr");
                bf3(&d, is64, rd, rn, @intCast(immr));
            } else if (immr == 0 and imms == 7) {
                d.setMnem("sxtb");
                bf2w(&d, is64, rd, rn);
            } else if (immr == 0 and imms == 15) {
                d.setMnem("sxth");
                bf2w(&d, is64, rd, rn);
            } else if (is64 and immr == 0 and imms == 31) {
                d.setMnem("sxtw");
                bf2w(&d, is64, rd, rn);
            } else if (imms < immr) {
                d.setMnem("sbfiz");
                bf4(&d, is64, rd, rn, lsb, fw);
            } else {
                d.setMnem("sbfx");
                bf4(&d, is64, rd, rn, immr, imms - immr + 1);
            }
        },
        else => { // BFM
            if (imms < immr) {
                if (rn == 31) {
                    d.setMnem("bfc");
                    gpr(&d.ops, is64, rd, false);
                    d.ops.str(", ");
                    decImm(&d.ops, lsb);
                    d.ops.str(", ");
                    decImm(&d.ops, fw);
                } else {
                    d.setMnem("bfi");
                    bf4(&d, is64, rd, rn, lsb, fw);
                }
            } else {
                d.setMnem("bfxil");
                bf4(&d, is64, rd, rn, immr, imms - immr + 1);
            }
        },
    }
    return d;
}
fn bf2w(d: *Dec, is64: bool, rd: u5, rn: u5) void {
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, false, rn, false); // source is always the 32-bit view for the extend aliases
}
fn bf3(d: *Dec, is64: bool, rd: u5, rn: u5, amount: u32) void {
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    decImm(&d.ops, amount);
}
fn bf4(d: *Dec, is64: bool, rd: u5, rn: u5, a: u32, b: u32) void {
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    decImm(&d.ops, a);
    d.ops.str(", ");
    decImm(&d.ops, b);
}

fn extract(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const n: u1 = @truncate(bits(w, 22, 22));
    const rm = reg(w, 16);
    const imms = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bits(w, 30, 29) != 0 or bit(w, 21) != 0) return undef(w);
    if ((n == 1) != is64) return undef(w);
    if (!is64 and imms >= 32) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (rn == rm) {
        d.setMnem("ror");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rn, false);
        d.ops.str(", ");
        hexImm(&d.ops, imms);
        return d;
    }
    d.setMnem("extr");
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rm, false);
    d.ops.str(", ");
    hexImm(&d.ops, imms);
    return d;
}

// ---------------------------------------------------------------------------------------------
// B.4 branches, exception generation, system
// ---------------------------------------------------------------------------------------------

fn branchSys(w: u32, pc: u64) Dec {
    if (w & 0x7c00_0000 == 0x1400_0000) { // B / BL
        const is_bl = bit(w, 31) == 1;
        const target = pc +% @as(u64, @bitCast(sext(bits(w, 25, 0), 26) *% 4));
        var d: Dec = .{ .kind = if (is_bl) .call else .branch, .target = target };
        d.setMnem(if (is_bl) "bl" else "b");
        targetAddr(&d.ops, target);
        if (is_bl) d.reg_write = 30;
        return d;
    }
    if (w & 0xff00_0010 == 0x5400_0000) { // B.cond
        const cond: u4 = @truncate(bits(w, 3, 0));
        const target = pc +% @as(u64, @bitCast(sext(bits(w, 23, 5), 19) *% 4));
        var d: Dec = .{ .kind = .cond_branch, .target = target };
        d.buildMnem(&.{ "b.", condName(cond) });
        targetAddr(&d.ops, target);
        return d;
    }
    if (w & 0x7e00_0000 == 0x3400_0000) { // CBZ / CBNZ
        const is64 = bit(w, 31) == 1;
        const target = pc +% @as(u64, @bitCast(sext(bits(w, 23, 5), 19) *% 4));
        var d: Dec = .{ .kind = .cond_branch, .target = target };
        d.setMnem(if (bit(w, 24) == 1) "cbnz" else "cbz");
        gpr(&d.ops, is64, reg(w, 0), false);
        d.ops.str(", ");
        targetAddr(&d.ops, target);
        return d;
    }
    if (w & 0x7e00_0000 == 0x3600_0000) { // TBZ / TBNZ
        const b5 = bit(w, 31);
        const bit_no: u32 = (@as(u32, b5) << 5) | bits(w, 23, 19);
        const target = pc +% @as(u64, @bitCast(sext(bits(w, 18, 5), 14) *% 4));
        var d: Dec = .{ .kind = .cond_branch, .target = target };
        d.setMnem(if (bit(w, 24) == 1) "tbnz" else "tbz");
        gpr(&d.ops, b5 == 1, reg(w, 0), false);
        d.ops.str(", ");
        hexImm(&d.ops, bit_no);
        d.ops.str(", ");
        targetAddr(&d.ops, target);
        return d;
    }
    if (w & 0xffff_ffff == 0xd69f_03e0) return simple("eret", .ret);
    if (w & 0xffff_ffff == 0xd69f_0bff) return simple("eretaa", .ret);
    if (w & 0xffff_ffff == 0xd69f_0fff) return simple("eretab", .ret);
    if (w & 0xffff_ffff == 0xd65f_0bff) return simple("retaa", .ret);
    if (w & 0xffff_ffff == 0xd65f_0fff) return simple("retab", .ret);
    if (w & 0xffff_fc1f == 0xd61f_0000) return oneReg("br", .indirect_branch, reg(w, 5));
    if (w & 0xffff_fc1f == 0xd63f_0000) return oneReg("blr", .indirect_call, reg(w, 5));
    if (w & 0xffff_fc1f == 0xd65f_0000) {
        const rn = reg(w, 5);
        if (rn == 30) return simple("ret", .ret);
        return oneReg("ret", .ret, rn);
    }
    if (w & 0xffff_fc1f == 0xd61f_081f) return oneReg("braaz", .indirect_branch, reg(w, 5));
    if (w & 0xffff_fc1f == 0xd61f_0c1f) return oneReg("brabz", .indirect_branch, reg(w, 5));
    if (w & 0xffff_fc1f == 0xd63f_081f) return oneReg("blraaz", .indirect_call, reg(w, 5));
    if (w & 0xffff_fc1f == 0xd63f_0c1f) return oneReg("blrabz", .indirect_call, reg(w, 5));
    if (w & 0xffff_fc00 == 0xd71f_0800) return twoReg("braa", .indirect_branch, reg(w, 5), reg(w, 0));
    if (w & 0xffff_fc00 == 0xd71f_0c00) return twoReg("brab", .indirect_branch, reg(w, 5), reg(w, 0));
    if (w & 0xffff_fc00 == 0xd73f_0800) return twoReg("blraa", .indirect_call, reg(w, 5), reg(w, 0));
    if (w & 0xffff_fc00 == 0xd73f_0c00) return twoReg("blrab", .indirect_call, reg(w, 5), reg(w, 0));

    if (w & 0xff00_0000 == 0xd400_0000) return exception(w);
    if (w & 0xffff_f01f == 0xd503_201f) return hint(w);
    if (w & 0xffff_f01f == 0xd503_301f) return barrier(w);
    if (w & 0xfff8_f01f == 0xd500_401f) return msrImm(w);
    if (w & 0xfff0_0000 == 0xd530_0000) return sysReg(w, true);
    if (w & 0xfff0_0000 == 0xd510_0000) return sysReg(w, false);
    if (w & 0xfff8_0000 == 0xd508_0000) return sysInsn(w, false);
    if (w & 0xfff8_0000 == 0xd528_0000) return sysInsn(w, true);
    return undef(w);
}

fn simple(mnemonic: []const u8, kind: Kind) Dec {
    var d: Dec = .{ .kind = kind };
    d.setMnem(mnemonic);
    return d;
}
fn oneReg(mnemonic: []const u8, kind: Kind, rn: u5) Dec {
    var d: Dec = .{ .kind = kind };
    d.setMnem(mnemonic);
    gpr(&d.ops, true, rn, false);
    return d;
}
fn twoReg(mnemonic: []const u8, kind: Kind, rn: u5, rm: u5) Dec {
    var d: Dec = .{ .kind = kind };
    d.setMnem(mnemonic);
    gpr(&d.ops, true, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, true, rm, false);
    return d;
}

fn exception(w: u32) Dec {
    if (bits(w, 23, 21) > 5 or bits(w, 4, 2) != 0) return undef(w);
    const opc = bits(w, 23, 21);
    const ll = bits(w, 1, 0);
    const imm16 = bits(w, 20, 5);
    const name: []const u8 = switch (opc) {
        0 => switch (ll) {
            1 => "svc",
            2 => "hvc",
            3 => "smc",
            else => return undef(w),
        },
        1 => if (ll == 0) "brk" else return undef(w),
        2 => if (ll == 0) "hlt" else return undef(w),
        5 => switch (ll) {
            1 => "dcps1",
            2 => "dcps2",
            3 => "dcps3",
            else => return undef(w),
        },
        else => return undef(w),
    };
    var d: Dec = .{ .kind = if (opc == 1 or opc == 2) .trap else .other };
    d.setMnem(name);
    hexImmZeroBare(&d.ops, imm16);
    return d;
}

fn hint(w: u32) Dec {
    const value: u32 = (bits(w, 11, 8) << 3) | bits(w, 7, 5);
    var d: Dec = .{};
    switch (value) {
        0 => {
            d.setMnem("nop");
            d.kind = .nop;
        },
        1 => d.setMnem("yield"),
        2 => d.setMnem("wfe"),
        3 => d.setMnem("wfi"),
        4 => d.setMnem("sev"),
        5 => d.setMnem("sevl"),
        6 => d.setMnem("dgh"),
        7 => d.setMnem("xpaclri"),
        8 => d.setMnem("pacia1716"),
        10 => d.setMnem("pacib1716"),
        12 => d.setMnem("autia1716"),
        14 => d.setMnem("autib1716"),
        16 => d.setMnem("esb"),
        17 => {
            d.setMnem("psb");
            d.ops.str("csync");
        },
        18 => {
            d.setMnem("tsb");
            d.ops.str("csync");
        },
        20 => d.setMnem("csdb"),
        24, 25, 26, 27 => {
            d.setMnem(switch (value) {
                24 => "paciaz",
                25 => "paciasp",
                26 => "pacibz",
                else => "pacibsp",
            });
            d.kind = .pac_prologue;
        },
        28, 29, 30, 31 => {
            d.setMnem(switch (value) {
                28 => "autiaz",
                29 => "autiasp",
                30 => "autibz",
                else => "autibsp",
            });
            d.kind = .pac_epilogue;
        },
        32 => {
            d.setMnem("bti");
            d.kind = .bti;
        },
        34, 36, 38 => {
            d.setMnem("bti");
            d.kind = .bti;
            d.ops.str(switch (value) {
                34 => "c",
                36 => "j",
                else => "jc",
            });
        },
        else => {
            d.setMnem("hint");
            hexImm(&d.ops, value);
        },
    }
    return d;
}

fn barrierOption(crm: u32) ?[]const u8 {
    return switch (crm) {
        15 => "sy",
        14 => "st",
        13 => "ld",
        11 => "ish",
        10 => "ishst",
        9 => "ishld",
        7 => "nsh",
        6 => "nshst",
        5 => "nshld",
        3 => "osh",
        2 => "oshst",
        1 => "oshld",
        else => null,
    };
}

fn barrier(w: u32) Dec {
    const crm = bits(w, 11, 8);
    const op2 = bits(w, 7, 5);
    var d: Dec = .{};
    switch (op2) {
        2 => {
            d.setMnem("clrex");
            if (crm != 15) decImm(&d.ops, crm);
        },
        4, 5 => {
            if (op2 == 4 and crm == 0) {
                d.setMnem("ssbb");
                return d;
            }
            if (op2 == 4 and crm == 4) {
                d.setMnem("pssbb");
                return d;
            }
            d.setMnem(if (op2 == 4) "dsb" else "dmb");
            if (barrierOption(crm)) |name| d.ops.str(name) else decImm(&d.ops, crm);
        },
        6 => {
            d.setMnem("isb");
            if (crm != 15) decImm(&d.ops, crm);
        },
        7 => {
            if (crm != 0) return undef(w);
            d.setMnem("sb");
        },
        else => return undef(w),
    }
    return d;
}

fn msrImm(w: u32) Dec {
    const op1 = bits(w, 18, 16);
    const crm = bits(w, 11, 8);
    const op2 = bits(w, 7, 5);
    const field: []const u8 = switch ((op1 << 3) | op2) {
        (0 << 3) | 3 => "UAO",
        (0 << 3) | 4 => "PAN",
        (0 << 3) | 5 => "SPSel",
        (3 << 3) | 1 => "SSBS",
        (3 << 3) | 2 => "DIT",
        (3 << 3) | 4 => "TCO",
        (3 << 3) | 6 => "DAIFSet",
        (3 << 3) | 7 => "DAIFClr",
        else => return undef(w),
    };
    var d: Dec = .{};
    d.setMnem("msr");
    d.ops.str(field);
    d.ops.str(", ");
    hexImm(&d.ops, crm);
    return d;
}

/// `S<2+o0>_<op1>_C<CRn>_C<CRm>_<op2>` with the names verified by assembling (disasm-notes B.4).
fn sysRegName(b: *Buf, o0: u1, op1: u32, crn: u32, crm: u32, op2: u32) void {
    const key = (@as(u32, o0) << 20) | (op1 << 16) | (crn << 8) | (crm << 4) | op2;
    const named: ?[]const u8 = switch (key) {
        (1 << 20) | (3 << 16) | (4 << 8) | (2 << 4) | 0 => "NZCV",
        (1 << 20) | (3 << 16) | (4 << 8) | (2 << 4) | 1 => "DAIF",
        (1 << 20) | (3 << 16) | (4 << 8) | (4 << 4) | 0 => "FPCR",
        (1 << 20) | (3 << 16) | (4 << 8) | (4 << 4) | 1 => "FPSR",
        (1 << 20) | (3 << 16) | (13 << 8) | (0 << 4) | 2 => "TPIDR_EL0",
        (1 << 20) | (3 << 16) | (13 << 8) | (0 << 4) | 3 => "TPIDRRO_EL0",
        (1 << 20) | (3 << 16) | (14 << 8) | (0 << 4) | 0 => "CNTFRQ_EL0",
        (1 << 20) | (3 << 16) | (14 << 8) | (0 << 4) | 1 => "CNTPCT_EL0",
        (1 << 20) | (3 << 16) | (14 << 8) | (0 << 4) | 2 => "CNTVCT_EL0",
        (1 << 20) | (3 << 16) | (0 << 8) | (0 << 4) | 1 => "CTR_EL0",
        (1 << 20) | (3 << 16) | (0 << 8) | (0 << 4) | 7 => "DCZID_EL0",
        (1 << 20) | (0 << 16) | (0 << 8) | (0 << 4) | 0 => "MIDR_EL1",
        (1 << 20) | (0 << 16) | (13 << 8) | (0 << 4) | 4 => "TPIDR_EL1",
        (1 << 20) | (0 << 16) | (0 << 8) | (6 << 4) | 0 => "ID_AA64ISAR0_EL1",
        (1 << 20) | (0 << 16) | (0 << 8) | (4 << 4) | 0 => "ID_AA64PFR0_EL1",
        else => null,
    };
    if (named) |n| {
        b.str(n);
        return;
    }
    b.print("S{d}_{d}_C{d}_C{d}_{d}", .{ 2 + @as(u32, o0), op1, crn, crm, op2 });
}

fn sysReg(w: u32, is_read: bool) Dec {
    const o0: u1 = @truncate(bits(w, 19, 19));
    const op1 = bits(w, 18, 16);
    const crn = bits(w, 15, 12);
    const crm = bits(w, 11, 8);
    const op2 = bits(w, 7, 5);
    const rt = reg(w, 0);
    var d: Dec = .{};
    if (is_read) {
        d.setMnem("mrs");
        d.reg_write = regWrite(rt, false);
        gpr(&d.ops, true, rt, false);
        d.ops.str(", ");
        sysRegName(&d.ops, o0, op1, crn, crm, op2);
    } else {
        d.setMnem("msr");
        sysRegName(&d.ops, o0, op1, crn, crm, op2);
        d.ops.str(", ");
        gpr(&d.ops, true, rt, false);
    }
    return d;
}

/// Generic `sys`/`sysl` spelling (disasm-notes B.4); the DC/IC/AT/TLBI aliases otool prints are not
/// reproduced — no corpus fixture contains one.
fn sysInsn(w: u32, is_read: bool) Dec {
    const op1 = bits(w, 18, 16);
    const crn = bits(w, 15, 12);
    const crm = bits(w, 11, 8);
    const op2 = bits(w, 7, 5);
    const rt = reg(w, 0);
    var d: Dec = .{};
    if (is_read) {
        d.setMnem("sysl");
        gpr(&d.ops, true, rt, false);
        d.ops.str(", ");
        hexImm(&d.ops, op1);
        d.ops.print(", c{d}, c{d}, ", .{ crn, crm });
        hexImm(&d.ops, op2);
        d.reg_write = regWrite(rt, false);
    } else {
        d.setMnem("sys");
        hexImm(&d.ops, op1);
        d.ops.print(", c{d}, c{d}, ", .{ crn, crm });
        hexImm(&d.ops, op2);
        if (rt != 31) {
            d.ops.str(", ");
            gpr(&d.ops, true, rt, false);
        }
    }
    return d;
}

// ---------------------------------------------------------------------------------------------
// B.5 data-processing register
// ---------------------------------------------------------------------------------------------

const shift_names = [4][]const u8{ "lsl", "lsr", "asr", "ror" };
const extend_names = [8][]const u8{ "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx" };

fn dpReg(w: u32) Dec {
    if (w & 0x1f00_0000 == 0x0a00_0000) return logicalShifted(w);
    if (w & 0x1f20_0000 == 0x0b00_0000) return addSubShifted(w);
    if (w & 0x1fe0_0000 == 0x0b20_0000) return addSubExtended(w);
    if (w & 0x1fe0_fc00 == 0x1a00_0000) return adcSbc(w);
    if (w & 0x1fe0_0000 == 0x1a40_0000) return condCompare(w);
    if (w & 0x1fe0_0000 == 0x1a80_0000) return condSelect(w);
    if (w & 0x5fe0_0000 == 0x1ac0_0000) return twoSource(w);
    if (w & 0x5fe0_0000 == 0x5ac0_0000) return oneSource(w);
    if (w & 0x1f00_0000 == 0x1b00_0000) return threeSource(w);
    return undef(w);
}

fn shiftSuffix(d: *Dec, shift: u32, amount: u32) void {
    if (shift == 0 and amount == 0) return;
    d.ops.str(", ");
    d.ops.str(shift_names[shift & 3]);
    d.ops.str(" ");
    decImm(&d.ops, amount);
}

fn logicalShifted(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const opc = bits(w, 30, 29);
    const shift = bits(w, 23, 22);
    const n = bit(w, 21);
    const rm = reg(w, 16);
    const amount = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (!is64 and amount >= 32) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    // MOV Rd, Rm — ORR with XZR, no shift.
    if (opc == 1 and n == 0 and rn == 31 and shift == 0 and amount == 0) {
        d.setMnem("mov");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        return d;
    }
    if (opc == 1 and n == 1 and rn == 31) { // MVN
        d.setMnem("mvn");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        shiftSuffix(&d, shift, amount);
        return d;
    }
    if (opc == 3 and n == 0 and rd == 31) { // TST
        d.setMnem("tst");
        d.reg_write = null;
        gpr(&d.ops, is64, rn, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        shiftSuffix(&d, shift, amount);
        return d;
    }
    d.setMnem(switch ((opc << 1) | n) {
        0b000 => "and",
        0b001 => "bic",
        0b010 => "orr",
        0b011 => "orn",
        0b100 => "eor",
        0b101 => "eon",
        0b110 => "ands",
        else => "bics",
    });
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rm, false);
    shiftSuffix(&d, shift, amount);
    return d;
}

fn addSubShifted(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const is_sub = bit(w, 30) == 1;
    const sets_flags = bit(w, 29) == 1;
    const shift = bits(w, 23, 22);
    const rm = reg(w, 16);
    const amount = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (shift == 3) return undef(w);
    if (!is64 and amount >= 32) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (sets_flags and rd == 31) { // CMP / CMN
        d.setMnem(if (is_sub) "cmp" else "cmn");
        d.reg_write = null;
        gpr(&d.ops, is64, rn, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        shiftSuffix(&d, shift, amount);
        return d;
    }
    if (is_sub and rn == 31) { // NEG / NEGS
        d.setMnem(if (sets_flags) "negs" else "neg");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        shiftSuffix(&d, shift, amount);
        return d;
    }
    d.setMnem(if (is_sub) (if (sets_flags) "subs" else "sub") else (if (sets_flags) "adds" else "add"));
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rm, false);
    shiftSuffix(&d, shift, amount);
    return d;
}

fn addSubExtended(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const is_sub = bit(w, 30) == 1;
    const sets_flags = bit(w, 29) == 1;
    const rm = reg(w, 16);
    const option = bits(w, 15, 13);
    const imm3 = bits(w, 12, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (imm3 > 4) return undef(w);

    var d: Dec = .{};
    const alias_cmp = sets_flags and rd == 31;
    if (alias_cmp) {
        d.setMnem(if (is_sub) "cmp" else "cmn");
    } else {
        d.setMnem(if (is_sub) (if (sets_flags) "subs" else "sub") else (if (sets_flags) "adds" else "add"));
        d.reg_write = regWrite(rd, !sets_flags);
        gpr(&d.ops, is64, rd, !sets_flags);
        d.ops.str(", ");
    }
    gpr(&d.ops, is64, rn, true);
    d.ops.str(", ");
    const rm_is64 = is64 and (option == 3 or option == 7);
    gpr(&d.ops, rm_is64, rm, false);
    const lsl_form = (rd == 31 or rn == 31) and option == (if (is64) @as(u32, 3) else 2);
    if (lsl_form) {
        if (imm3 != 0) {
            d.ops.str(", lsl ");
            decImm(&d.ops, imm3);
        }
    } else {
        d.ops.str(", ");
        d.ops.str(extend_names[option & 7]);
        if (imm3 != 0) {
            d.ops.str(" ");
            decImm(&d.ops, imm3);
        }
    }
    return d;
}

fn adcSbc(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const is_sub = bit(w, 30) == 1;
    const sets_flags = bit(w, 29) == 1;
    const rm = reg(w, 16);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (is_sub and rn == 31) {
        d.setMnem(if (sets_flags) "ngcs" else "ngc");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rm, false);
        return d;
    }
    d.setMnem(if (is_sub) (if (sets_flags) "sbcs" else "sbc") else (if (sets_flags) "adcs" else "adc"));
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rm, false);
    return d;
}

fn condCompare(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const is_cmp = bit(w, 30) == 1;
    const imm_form = bit(w, 11) == 1;
    const cond: u4 = @truncate(bits(w, 15, 12));
    const nzcv = bits(w, 3, 0);
    const rn = reg(w, 5);
    if (bit(w, 29) != 1 or bit(w, 10) != 0 or bit(w, 4) != 0) return undef(w);
    var d: Dec = .{};
    d.setMnem(if (is_cmp) "ccmp" else "ccmn");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    if (imm_form) hexImm(&d.ops, bits(w, 20, 16)) else gpr(&d.ops, is64, reg(w, 16), false);
    d.ops.str(", ");
    hexImm(&d.ops, nzcv);
    d.ops.str(", ");
    d.ops.str(condName(cond));
    return d;
}

fn condSelect(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const op = bit(w, 30);
    const rm = reg(w, 16);
    const cond: u4 = @truncate(bits(w, 15, 12));
    const op2 = bits(w, 11, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 29) != 0 or op2 > 1) return undef(w);
    const inv: u4 = cond ^ 1;
    const aliasable = cond != 14 and cond != 15;

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (aliasable and rm == 31 and rn == 31 and op2 == 1 and op == 0) { // CSET
        d.setMnem("cset");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        d.ops.str(condName(inv));
        return d;
    }
    if (aliasable and rm == 31 and rn == 31 and op2 == 0 and op == 1) { // CSETM
        d.setMnem("csetm");
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        d.ops.str(condName(inv));
        return d;
    }
    if (aliasable and rm == rn and rm != 31 and !(op == 0 and op2 == 0)) { // CINC / CINV / CNEG
        d.setMnem(switch ((@as(u32, op) << 1) | op2) {
            0b01 => "cinc",
            0b10 => "cinv",
            else => "cneg",
        });
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rn, false);
        d.ops.str(", ");
        d.ops.str(condName(inv));
        return d;
    }
    d.setMnem(switch ((@as(u32, op) << 1) | op2) {
        0b00 => "csel",
        0b01 => "csinc",
        0b10 => "csinv",
        else => "csneg",
    });
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rm, false);
    d.ops.str(", ");
    d.ops.str(condName(cond));
    return d;
}

fn threeSource(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const op31 = bits(w, 23, 21);
    const rm = reg(w, 16);
    const o0 = bit(w, 15);
    const ra = reg(w, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bits(w, 30, 29) != 0) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    const key = (op31 << 1) | o0;
    // High-half multiplies take three operands and no Ra.
    if (is64 and (key == 0b0100 or key == 0b1100)) {
        d.setMnem(if (key == 0b0100) "smulh" else "umulh");
        gpr(&d.ops, true, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, true, rn, false);
        d.ops.str(", ");
        gpr(&d.ops, true, rm, false);
        return d;
    }
    const long = is64 and (op31 == 0b001 or op31 == 0b101);
    if (!long and op31 != 0) return undef(w);
    const base: []const u8 = switch (key) {
        0b0000 => "madd",
        0b0001 => "msub",
        0b0010 => "smaddl",
        0b0011 => "smsubl",
        0b1010 => "umaddl",
        0b1011 => "umsubl",
        else => return undef(w),
    };
    const alias: []const u8 = switch (key) {
        0b0000 => "mul",
        0b0001 => "mneg",
        0b0010 => "smull",
        0b0011 => "smnegl",
        0b1010 => "umull",
        else => "umnegl",
    };
    const src64 = if (long) false else is64;
    if (ra == 31) {
        d.setMnem(alias);
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, src64, rn, false);
        d.ops.str(", ");
        gpr(&d.ops, src64, rm, false);
        return d;
    }
    d.setMnem(base);
    gpr(&d.ops, is64, rd, false);
    d.ops.str(", ");
    gpr(&d.ops, src64, rn, false);
    d.ops.str(", ");
    gpr(&d.ops, src64, rm, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, ra, false);
    return d;
}

fn twoSource(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const rm = reg(w, 16);
    const opcode = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 29) != 0) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    switch (opcode) {
        0b000010, 0b000011, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100 => {
            d.setMnem(switch (opcode) {
                0b000010 => "udiv",
                0b000011 => "sdiv",
                0b001000 => "lsl",
                0b001001 => "lsr",
                0b001010 => "asr",
                0b001011 => "ror",
                else => "pacga",
            });
            if (opcode == 0b001100 and !is64) return undef(w);
            gpr(&d.ops, is64, rd, false);
            d.ops.str(", ");
            gpr(&d.ops, is64, rn, false);
            d.ops.str(", ");
            if (opcode == 0b001100) gpr(&d.ops, true, rm, true) else gpr(&d.ops, is64, rm, false);
        },
        0b010000...0b010111 => {
            const idx = opcode - 0b010000;
            const names = [8][]const u8{ "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch", "crc32cw", "crc32cx" };
            const sz = idx & 3;
            if ((sz == 3) != is64) return undef(w);
            d.setMnem(names[idx & 7]);
            gpr(&d.ops, false, rd, false);
            d.ops.str(", ");
            gpr(&d.ops, false, rn, false);
            d.ops.str(", ");
            gpr(&d.ops, sz == 3, rm, false);
        },
        else => return undef(w),
    }
    return d;
}

fn oneSource(w: u32) Dec {
    const is64 = bit(w, 31) == 1;
    const opcode2 = bits(w, 20, 16);
    const opcode = bits(w, 15, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 29) != 0) return undef(w);

    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    if (opcode2 == 0) {
        const name: []const u8 = switch (opcode) {
            0b000000 => "rbit",
            0b000001 => "rev16",
            0b000010 => if (is64) "rev32" else "rev",
            0b000011 => if (is64) "rev" else return undef(w),
            0b000100 => "clz",
            0b000101 => "cls",
            else => return undef(w),
        };
        d.setMnem(name);
        gpr(&d.ops, is64, rd, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rn, false);
        return d;
    }
    if (opcode2 == 1 and is64) {
        const names = [18][]const u8{
            "pacia",  "pacib",  "pacda",  "pacdb",  "autia",  "autib",  "autda",  "autdb", "paciza",
            "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd",
        };
        if (opcode > 0b010001) return undef(w);
        const z_form = opcode >= 0b001000;
        if (z_form and rn != 31) return undef(w);
        d.setMnem(names[@as(usize, @intCast(opcode))]);
        gpr(&d.ops, true, rd, false);
        if (!z_form) {
            d.ops.str(", ");
            gpr(&d.ops, true, rn, true);
        }
        return d;
    }
    return undef(w);
}

// ---------------------------------------------------------------------------------------------
// B.6 loads and stores
// ---------------------------------------------------------------------------------------------

const fp_letters = [5]u8{ 'b', 'h', 's', 'd', 'q' };

const MemMode = enum { offset, pre, post };

fn memOperand(b: *Buf, rn: u5, off: i64, mode: MemMode) void {
    b.str("[");
    gpr(b, true, rn, true);
    switch (mode) {
        .offset => {
            if (off != 0) {
                b.str(", ");
                signedHexImm(b, off);
            }
            b.str("]");
        },
        .pre => {
            b.str(", ");
            signedHexImm(b, off);
            b.str("]!");
        },
        .post => {
            b.str("], ");
            signedHexImm(b, off);
        },
    }
}

/// PRFM operand (Rt): type[4:3] 00 PLD 01 PLI 10 PST; target[2:1] L1/L2/L3; policy[0] KEEP/STRM.
fn prfmOperand(b: *Buf, rt: u5) void {
    const ty = (rt >> 3) & 3;
    const tgt = (rt >> 1) & 3;
    const policy = rt & 1;
    if (ty == 3 or tgt == 3) {
        hexImm(b, rt);
        return;
    }
    b.str(switch (ty) {
        0 => "pld",
        1 => "pli",
        else => "pst",
    });
    b.str(switch (tgt) {
        0 => "l1",
        1 => "l2",
        else => "l3",
    });
    b.str(if (policy == 1) "strm" else "keep");
}

fn loadStore(w: u32, pc: u64) Dec {
    if (w & 0x3f00_0000 == 0x0800_0000) return exclusive(w);
    if (w & 0x3b00_0000 == 0x1800_0000) return literalLoad(w, pc);
    if (w & 0x3a00_0000 == 0x2800_0000) return pairLoadStore(w);
    if (w & 0x3f20_0c00 == 0x1900_0000) return lrcpcUnscaled(w);
    if (w & 0xff20_0400 == 0xf820_0400) return pacLoad(w);
    if (w & 0x3f20_0c00 == 0x3820_0000) return atomic(w);
    if (w & 0x3b20_0c00 == 0x3820_0800) return registerOffset(w);
    if (w & 0x3b20_0000 == 0x3800_0000) return imm9LoadStore(w);
    if (w & 0x3b00_0000 == 0x3900_0000) return unsignedOffset(w);
    return undef(w);
}

fn literalLoad(w: u32, pc: u64) Dec {
    const opc = bits(w, 31, 30);
    const v = bit(w, 26);
    const rt = reg(w, 0);
    const target = pc +% @as(u64, @bitCast(sext(bits(w, 23, 5), 19) *% 4));
    var d: Dec = .{ .kind = .ldr_literal, .target = target };
    if (v == 1) {
        if (opc == 3) return undef(w);
        d.setMnem("ldr");
        d.reg_write = rt;
        d.ops.print("{c}{d}, ", .{ fp_letters[@as(usize, opc) + 2], @as(u32, rt) });
        targetAddr(&d.ops, target);
        return d;
    }
    switch (opc) {
        0, 1 => {
            d.setMnem("ldr");
            d.reg_write = regWrite(rt, false);
            gpr(&d.ops, opc == 1, rt, false);
            d.ops.str(", ");
            targetAddr(&d.ops, target);
        },
        2 => {
            d.setMnem("ldrsw");
            d.reg_write = regWrite(rt, false);
            gpr(&d.ops, true, rt, false);
            d.ops.str(", ");
            targetAddr(&d.ops, target);
        },
        else => {
            d.setMnem("prfm");
            d.kind = .other;
            prfmOperand(&d.ops, rt);
            d.ops.str(", ");
            targetAddr(&d.ops, target);
        },
    }
    return d;
}

fn pairLoadStore(w: u32) Dec {
    const opc = bits(w, 31, 30);
    const v = bit(w, 26);
    const mode_bits = bits(w, 24, 23);
    const is_load = bit(w, 22) == 1;
    const imm7 = bits(w, 21, 15);
    const rt2 = reg(w, 10);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    if (opc == 3) return undef(w);

    var scale: u3 = undefined;
    var is_ldpsw = false;
    if (v == 1) {
        scale = switch (opc) {
            0 => 2,
            1 => 3,
            else => 4,
        };
    } else {
        switch (opc) {
            0 => scale = 2,
            1 => {
                if (!is_load) return undef(w);
                is_ldpsw = true;
                scale = 2;
            },
            else => scale = 3,
        }
    }
    const off = sext(imm7, 7) * (@as(i64, 1) << scale);
    const mode: MemMode = switch (mode_bits) {
        0b01 => .post,
        0b10 => .offset,
        0b11 => .pre,
        else => .offset, // 00 = LDNP/STNP (no writeback)
    };
    var d: Dec = .{};
    if (is_ldpsw) {
        d.setMnem("ldpsw");
    } else if (mode_bits == 0) {
        d.setMnem(if (is_load) "ldnp" else "stnp");
    } else {
        d.setMnem(if (is_load) "ldp" else "stp");
    }
    if (v == 1) {
        const letter = fp_letters[scale];
        d.ops.print("{c}{d}, {c}{d}, ", .{ letter, @as(u32, rt), letter, @as(u32, rt2) });
    } else {
        const is64 = opc == 2 or is_ldpsw;
        gpr(&d.ops, is64, rt, false);
        d.ops.str(", ");
        gpr(&d.ops, is64, rt2, false);
        d.ops.str(", ");
    }
    memOperand(&d.ops, rn, off, mode);
    d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << scale };
    if (is_load) {
        d.reg_write = regWrite(rt, false);
        d.alsoWrites(rt2, false); // LDP/LDNP/LDPSW write BOTH transfer registers
    }
    if (mode != .offset) d.alsoWrites(rn, true); // pre/post-index writes the base back
    return d;
}

const store_names = [4][]const u8{ "strb", "strh", "str", "str" };
const load_names = [4][]const u8{ "ldrb", "ldrh", "ldr", "ldr" };
const sign_names = [4][]const u8{ "ldrsb", "ldrsh", "ldrsw", "" };
const ustore_names = [4][]const u8{ "sturb", "sturh", "stur", "stur" };
const uload_names = [4][]const u8{ "ldurb", "ldurh", "ldur", "ldur" };
const usign_names = [4][]const u8{ "ldursb", "ldursh", "ldursw", "" };
const tstore_names = [4][]const u8{ "sttrb", "sttrh", "sttr", "sttr" };
const tload_names = [4][]const u8{ "ldtrb", "ldtrh", "ldtr", "ldtr" };
const tsign_names = [4][]const u8{ "ldtrsb", "ldtrsh", "ldtrsw", "" };

const LsForm = enum { scaled, unscaled, unpriv };

/// Mnemonic + register width for the integer load/store encodings, or null when unallocated.
fn intLoadStore(form: LsForm, size: u32, opc: u32) ?struct { name: []const u8, is64: bool, is_load: bool, prfm: bool } {
    switch (opc) {
        0 => return .{ .name = switch (form) {
            .scaled => store_names[size & 3],
            .unscaled => ustore_names[size & 3],
            .unpriv => tstore_names[size & 3],
        }, .is64 = size == 3, .is_load = false, .prfm = false },
        1 => return .{ .name = switch (form) {
            .scaled => load_names[size & 3],
            .unscaled => uload_names[size & 3],
            .unpriv => tload_names[size & 3],
        }, .is64 = size == 3, .is_load = true, .prfm = false },
        2 => {
            if (size == 3) {
                if (form == .unpriv) return null;
                return .{ .name = if (form == .scaled) "prfm" else "prfum", .is64 = true, .is_load = false, .prfm = true };
            }
            return .{ .name = switch (form) {
                .scaled => sign_names[size & 3],
                .unscaled => usign_names[size & 3],
                .unpriv => tsign_names[size & 3],
            }, .is64 = true, .is_load = true, .prfm = false };
        },
        else => {
            if (size >= 2) return null;
            return .{ .name = switch (form) {
                .scaled => sign_names[size & 3],
                .unscaled => usign_names[size & 3],
                .unpriv => tsign_names[size & 3],
            }, .is64 = false, .is_load = true, .prfm = false };
        },
    }
}

fn unsignedOffset(w: u32) Dec {
    const size = bits(w, 31, 30);
    const v = bit(w, 26);
    const opc = bits(w, 23, 22);
    const imm12 = bits(w, 21, 10);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    var d: Dec = .{};
    if (v == 1) {
        const scale: u32 = ((opc >> 1) << 2) | size;
        if (scale > 4) return undef(w);
        const is_load = (opc & 1) == 1;
        const off: i64 = @as(i64, imm12) << @intCast(scale);
        d.setMnem(if (is_load) "ldr" else "str");
        d.ops.print("{c}{d}, ", .{ fp_letters[@as(usize, @intCast(scale))], @as(u32, rt) });
        memOperand(&d.ops, rn, off, .offset);
        d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << @intCast(scale) };
        d.kind = if (is_load) .ldr_imm else .str_imm;
        return d;
    }
    const info = intLoadStore(.scaled, size, opc) orelse return undef(w);
    const off: i64 = @as(i64, imm12) << @intCast(size);
    d.setMnem(info.name);
    if (info.prfm) {
        prfmOperand(&d.ops, rt);
    } else {
        gpr(&d.ops, info.is64, rt, false);
        if (info.is_load) d.reg_write = regWrite(rt, false);
    }
    d.ops.str(", ");
    memOperand(&d.ops, rn, off, .offset);
    d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << @intCast(size) };
    d.kind = if (info.prfm) .other else if (info.is_load) .ldr_imm else .str_imm;
    return d;
}

fn imm9LoadStore(w: u32) Dec {
    const size = bits(w, 31, 30);
    const v = bit(w, 26);
    const opc = bits(w, 23, 22);
    const off = sext(bits(w, 20, 12), 9);
    const op4 = bits(w, 11, 10);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    // op4: 00 LDUR/STUR (unscaled), 01 post-index, 10 LDTR/STTR (unprivileged), 11 pre-index.
    const real_form: LsForm = switch (op4) {
        0b00 => .unscaled,
        0b10 => .unpriv,
        else => .scaled,
    };
    const mode: MemMode = switch (op4) {
        0b01 => .post,
        0b11 => .pre,
        else => .offset,
    };

    var d: Dec = .{};
    if (v == 1) {
        if (op4 == 0b10) return undef(w);
        const scale: u32 = ((opc >> 1) << 2) | size;
        if (scale > 4) return undef(w);
        const is_load = (opc & 1) == 1;
        if (op4 == 0b00) {
            d.setMnem(if (is_load) "ldur" else "stur");
        } else {
            d.setMnem(if (is_load) "ldr" else "str");
        }
        d.ops.print("{c}{d}, ", .{ fp_letters[@as(usize, @intCast(scale))], @as(u32, rt) });
        memOperand(&d.ops, rn, off, mode);
        d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << @intCast(scale) };
        d.kind = if (is_load) .ldr_imm else .str_imm;
        if (mode != .offset) d.alsoWrites(rn, true); // writeback still writes the GPR base
        return d;
    }
    const info = intLoadStore(real_form, size, opc) orelse return undef(w);
    if (info.prfm and op4 != 0b00) return undef(w);
    d.setMnem(info.name);
    if (info.prfm) {
        prfmOperand(&d.ops, rt);
    } else {
        gpr(&d.ops, info.is64, rt, false);
        if (info.is_load) d.reg_write = regWrite(rt, false);
    }
    d.ops.str(", ");
    memOperand(&d.ops, rn, off, mode);
    d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << @intCast(size) };
    d.kind = if (info.prfm) .other else if (info.is_load) .ldr_imm else .str_imm;
    if (mode != .offset) d.alsoWrites(rn, true); // pre/post-index writes the base back
    return d;
}

fn pacLoad(w: u32) Dec {
    const m = bit(w, 23);
    const s = bit(w, 22);
    const imm9 = bits(w, 20, 12);
    const write_back = bit(w, 11) == 1;
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    const off = sext((@as(u64, s) << 9) | imm9, 10) * 8;
    var d: Dec = .{ .kind = .ldr_imm, .reg_write = regWrite(rt, false) };
    d.setMnem(if (m == 1) "ldrab" else "ldraa");
    gpr(&d.ops, true, rt, false);
    d.ops.str(", ");
    memOperand(&d.ops, rn, off, if (write_back) .pre else .offset);
    d.mem_ref = .{ .base = rn, .offset = off, .size = 8 };
    if (write_back) d.alsoWrites(rn, true);
    return d;
}

fn registerOffset(w: u32) Dec {
    const size = bits(w, 31, 30);
    const v = bit(w, 26);
    const opc = bits(w, 23, 22);
    const rm = reg(w, 16);
    const option = bits(w, 15, 13);
    const s = bit(w, 12);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    if (option != 0b010 and option != 0b011 and option != 0b110 and option != 0b111) return undef(w);

    var scale: u32 = size;
    var d: Dec = .{};
    if (v == 1) {
        scale = ((opc >> 1) << 2) | size;
        if (scale > 4) return undef(w);
        const is_load = (opc & 1) == 1;
        d.setMnem(if (is_load) "ldr" else "str");
        d.ops.print("{c}{d}, ", .{ fp_letters[@as(usize, @intCast(scale))], @as(u32, rt) });
        d.kind = if (is_load) .ldr_imm else .str_imm;
    } else {
        const info = intLoadStore(.scaled, size, opc) orelse return undef(w);
        d.setMnem(info.name);
        if (info.prfm) {
            prfmOperand(&d.ops, rt);
        } else {
            gpr(&d.ops, info.is64, rt, false);
            if (info.is_load) d.reg_write = regWrite(rt, false);
        }
        d.ops.str(", ");
        d.kind = if (info.prfm) .other else if (info.is_load) .ldr_imm else .str_imm;
    }
    d.ops.str("[");
    gpr(&d.ops, true, rn, true);
    d.ops.str(", ");
    const rm_is64 = option == 0b011 or option == 0b111;
    gpr(&d.ops, rm_is64, rm, false);
    if (option == 0b011) {
        if (s == 1) {
            d.ops.str(", lsl ");
            decImm(&d.ops, scale);
        }
    } else {
        d.ops.str(", ");
        d.ops.str(extend_names[option & 7]);
        if (s == 1) {
            d.ops.str(" ");
            decImm(&d.ops, scale);
        }
    }
    d.ops.str("]");
    return d;
}

const ar_suffix = [4][]const u8{ "", "l", "a", "al" };
const size_suffix = [4][]const u8{ "b", "h", "", "" };

fn exclusive(w: u32) Dec {
    const size = bits(w, 31, 30);
    const o2 = bit(w, 23);
    const l = bit(w, 22);
    const o1 = bit(w, 21);
    const rs = reg(w, 16);
    const o0 = bit(w, 15);
    const rt2 = reg(w, 10);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    const is64 = size == 3;
    const sfx = size_suffix[size & 3];
    var d: Dec = .{};

    if (o2 == 0 and o1 == 0) {
        if (l == 0) {
            d.buildMnem(&.{ if (o0 == 1) "stlxr" else "stxr", sfx });
            d.reg_write = regWrite(rs, false); // Ws receives the store-exclusive status
            gpr(&d.ops, false, rs, false);
            d.ops.str(", ");
            gpr(&d.ops, is64, rt, false);
            d.ops.str(", ");
        } else {
            d.buildMnem(&.{ if (o0 == 1) "ldaxr" else "ldxr", sfx });
            gpr(&d.ops, is64, rt, false);
            d.ops.str(", ");
            d.reg_write = regWrite(rt, false);
        }
        memOperand(&d.ops, rn, 0, .offset);
        return d;
    }
    if (o2 == 0 and o1 == 1) {
        if (size >= 2) { // LDXP / STXP
            if (l == 0) {
                d.buildMnem(&.{if (o0 == 1) "stlxp" else "stxp"});
                d.reg_write = regWrite(rs, false); // Ws receives the status
                gpr(&d.ops, false, rs, false);
                d.ops.str(", ");
            } else {
                d.buildMnem(&.{if (o0 == 1) "ldaxp" else "ldxp"});
                d.reg_write = regWrite(rt, false);
                d.alsoWrites(rt2, false); // the exclusive PAIR load writes both
            }
            gpr(&d.ops, size == 3, rt, false);
            d.ops.str(", ");
            gpr(&d.ops, size == 3, rt2, false);
            d.ops.str(", ");
            memOperand(&d.ops, rn, 0, .offset);
            return d;
        }
        // CASP: size 0 = 32-bit pair, size 1 = 64-bit pair.
        if (rt2 != 31 or rs % 2 != 0 or rt % 2 != 0) return undef(w);
        const ar = (@as(u32, l) << 1) | o0;
        d.buildMnem(&.{ "casp", ar_suffix[ar & 3] });
        const p64 = size == 1;
        // CASP compares against <Rs,Rs+1> and writes the memory contents BACK into that pair.
        d.reg_write = regWrite(rs, false);
        d.alsoWrites(rs +% 1, false);
        gpr(&d.ops, p64, rs, false);
        d.ops.str(", ");
        gpr(&d.ops, p64, rs + 1, false);
        d.ops.str(", ");
        gpr(&d.ops, p64, rt, false);
        d.ops.str(", ");
        gpr(&d.ops, p64, rt + 1, false);
        d.ops.str(", ");
        memOperand(&d.ops, rn, 0, .offset);
        return d;
    }
    if (o2 == 1 and o1 == 0) {
        if (l == 0) {
            d.buildMnem(&.{ if (o0 == 1) "stlr" else "stllr", sfx });
        } else {
            d.buildMnem(&.{ if (o0 == 1) "ldar" else "ldlar", sfx });
            d.reg_write = regWrite(rt, false);
        }
        gpr(&d.ops, is64, rt, false);
        d.ops.str(", ");
        memOperand(&d.ops, rn, 0, .offset);
        return d;
    }
    // CAS — Rs is compared against memory and RECEIVES the old memory value.
    const ar = (@as(u32, l) << 1) | o0;
    d.buildMnem(&.{ "cas", ar_suffix[ar & 3], sfx });
    d.reg_write = regWrite(rs, false);
    gpr(&d.ops, is64, rs, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rt, false);
    d.ops.str(", ");
    memOperand(&d.ops, rn, 0, .offset);
    return d;
}

const lse_ld = [8][]const u8{ "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin" };
const lse_st = [8][]const u8{ "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin" };

fn atomic(w: u32) Dec {
    const size = bits(w, 31, 30);
    if (bit(w, 26) != 0) return undef(w);
    const a = bit(w, 23);
    const r = bit(w, 22);
    const rs = reg(w, 16);
    const o3 = bit(w, 15);
    const opc = bits(w, 14, 12);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    const is64 = size == 3;
    const sfx = size_suffix[size & 3];
    const ar = (@as(u32, a) << 1) | r;
    var d: Dec = .{};

    if (o3 == 1) {
        if (opc == 0) { // SWP
            d.buildMnem(&.{ "swp", ar_suffix[ar & 3], sfx });
            gpr(&d.ops, is64, rs, false);
            d.ops.str(", ");
            gpr(&d.ops, is64, rt, false);
            d.ops.str(", ");
            memOperand(&d.ops, rn, 0, .offset);
            d.reg_write = regWrite(rt, false);
            return d;
        }
        if (opc == 4 and rs == 31 and a == 1 and r == 0) { // LDAPR
            d.buildMnem(&.{ "ldapr", sfx });
            gpr(&d.ops, is64, rt, false);
            d.ops.str(", ");
            memOperand(&d.ops, rn, 0, .offset);
            d.kind = .ldr_imm;
            d.reg_write = regWrite(rt, false);
            return d;
        }
        return undef(w);
    }
    // ST<op> alias: Rt == xzr and no acquire.
    if (rt == 31 and a == 0) {
        d.buildMnem(&.{ lse_st[opc & 7], ar_suffix[(ar & 1) & 3], sfx });
        gpr(&d.ops, is64, rs, false);
        d.ops.str(", ");
        memOperand(&d.ops, rn, 0, .offset);
        return d;
    }
    d.buildMnem(&.{ lse_ld[opc & 7], ar_suffix[ar & 3], sfx });
    gpr(&d.ops, is64, rs, false);
    d.ops.str(", ");
    gpr(&d.ops, is64, rt, false);
    d.ops.str(", ");
    memOperand(&d.ops, rn, 0, .offset);
    d.reg_write = regWrite(rt, false);
    return d;
}

/// LDAPUR / STLUR family (FEAT_LRCPC2): `size 011001 opc 0 imm9 00 Rn Rt`.
fn lrcpcUnscaled(w: u32) Dec {
    const size = bits(w, 31, 30);
    const opc = bits(w, 23, 22);
    const off = sext(bits(w, 20, 12), 9);
    const rn = reg(w, 5);
    const rt = reg(w, 0);
    const sfx = size_suffix[size & 3];
    var d: Dec = .{};
    switch (opc) {
        0 => {
            d.buildMnem(&.{ "stlur", sfx });
            gpr(&d.ops, size == 3, rt, false);
        },
        1 => {
            d.buildMnem(&.{ "ldapur", sfx });
            gpr(&d.ops, size == 3, rt, false);
            d.reg_write = regWrite(rt, false);
            d.kind = .ldr_imm;
        },
        else => {
            if (size == 3) return undef(w);
            const letter: []const u8 = switch (size) {
                0 => "b",
                1 => "h",
                else => "w",
            };
            d.buildMnem(&.{ "ldapurs", letter });
            gpr(&d.ops, opc == 2, rt, false);
            d.reg_write = regWrite(rt, false);
            d.kind = .ldr_imm;
        },
    }
    d.ops.str(", ");
    memOperand(&d.ops, rn, off, .offset);
    d.mem_ref = .{ .base = rn, .offset = off, .size = @as(u8, 1) << @intCast(size) };
    return d;
}

// ---------------------------------------------------------------------------------------------
// B.7 SIMD & FP (basic data movement; everything else -> .inst)
// ---------------------------------------------------------------------------------------------

fn fpLetter(ty: u32) ?u8 {
    return switch (ty) {
        0 => 's',
        1 => 'd',
        3 => 'h',
        else => null,
    };
}

fn simdFp(w: u32, st: Style) Dec {
    if (w & 0x5f00_0000 == 0x1f00_0000) return fpMulAdd(w);
    if (w & 0x5f20_7c00 == 0x1e20_4000) return fp1Source(w);
    if (w & 0x5f20_0c00 == 0x1e20_0800) return fp2Source(w);
    if (w & 0x5f20_0c00 == 0x1e20_0c00) return fcsel(w);
    if (w & 0x5f20_3c00 == 0x1e20_2000) return fpCompare(w);
    if (w & 0x5f20_1fe0 == 0x1e20_1000) return fpImmediate(w);
    if (w & 0x5f20_fc00 == 0x1e20_0000) return fpIntConvert(w, st);
    if (w & 0x9ff8_0400 == 0x0f00_0400) return movi(w, st);
    if (w & 0xbfe0_fc00 == 0x0e00_0c00) return dupGeneral(w, st);
    if (w & 0xffe0_fc00 == 0x4e00_1c00) return insGeneral(w, st);
    if (w & 0xbfe0_fc00 == 0x0e00_3c00) return movFromVector(w, false, st);
    if (w & 0xbfe0_fc00 == 0x0e00_2c00) return movFromVector(w, true, st);
    if (w & 0x9f20_0400 == 0x0e20_0400) return simdThreeSame(w, st);
    return undef(w);
}

fn fpIntConvert(w: u32, st: Style) Dec {
    const sf = bit(w, 31);
    const ty = bits(w, 23, 22);
    const rmode = bits(w, 20, 19);
    const opcode = bits(w, 18, 16);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 30) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1) return undef(w);
    var d: Dec = .{};

    // FMOV to/from the high half of a 128-bit register.
    if (ty == 2 and rmode == 1 and (opcode == 6 or opcode == 7) and sf == 1) {
        d.simdMnem(st, "fmov", "d"); // otool: `fmov.d x2, v0[1]`
        if (opcode == 6) {
            gpr(&d.ops, true, rd, false);
            d.ops.str(", ");
            velem(&d.ops, st, rn, 'd', 1);
            d.reg_write = regWrite(rd, false);
        } else {
            velem(&d.ops, st, rd, 'd', 1);
            d.ops.str(", ");
            gpr(&d.ops, true, rn, false);
        }
        return d;
    }
    const letter = fpLetter(ty) orelse return undef(w);
    const name: []const u8 = switch (opcode) {
        0 => switch (rmode) {
            0 => "fcvtns",
            1 => "fcvtps",
            2 => "fcvtms",
            else => "fcvtzs",
        },
        1 => switch (rmode) {
            0 => "fcvtnu",
            1 => "fcvtpu",
            2 => "fcvtmu",
            else => "fcvtzu",
        },
        2 => if (rmode == 0) "scvtf" else return undef(w),
        3 => if (rmode == 0) "ucvtf" else return undef(w),
        4 => if (rmode == 0) "fcvtas" else return undef(w),
        5 => if (rmode == 0) "fcvtau" else return undef(w),
        // FEAT_JSCVT: `fjcvtzs Wd, Dn` (sf=0, type=01, rmode=11, opcode=110). Verified against
        // `otool -tV` on assembled `fjcvtzs w0, d1` = 0x1e7e0020 / `fjcvtzs w5, d7` = 0x1e7e00e5.
        6 => if (rmode == 3 and sf == 0 and ty == 1) "fjcvtzs" else if (rmode == 0) "fmov" else return undef(w),
        else => if (rmode == 0) "fmov" else return undef(w),
    };
    d.setMnem(name);
    const gp_dest = opcode == 0 or opcode == 1 or opcode == 4 or opcode == 5 or opcode == 6;
    if (gp_dest) {
        gpr(&d.ops, sf == 1, rd, false);
        d.ops.print(", {c}{d}", .{ letter, @as(u32, rn) });
        d.reg_write = regWrite(rd, false);
    } else {
        d.ops.print("{c}{d}, ", .{ letter, @as(u32, rd) });
        gpr(&d.ops, sf == 1, rn, false);
    }
    return d;
}

fn fp1Source(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const opcode = bits(w, 20, 15);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1) return undef(w);
    const src = fpLetter(ty) orelse return undef(w);
    var d: Dec = .{};
    if (opcode >= 0b000100 and opcode <= 0b000111) { // FCVT
        const dst_ty = opcode & 3;
        if (dst_ty == ty or dst_ty == 2) return undef(w);
        const dst = fpLetter(dst_ty) orelse return undef(w);
        d.setMnem("fcvt");
        d.ops.print("{c}{d}, {c}{d}", .{ dst, @as(u32, rd), src, @as(u32, rn) });
        return d;
    }
    const name: []const u8 = switch (opcode) {
        0b000000 => "fmov",
        0b000001 => "fabs",
        0b000010 => "fneg",
        0b000011 => "fsqrt",
        0b001000 => "frintn",
        0b001001 => "frintp",
        0b001010 => "frintm",
        0b001011 => "frintz",
        0b001100 => "frinta",
        0b001110 => "frintx",
        0b001111 => "frinti",
        else => return undef(w),
    };
    d.setMnem(name);
    d.ops.print("{c}{d}, {c}{d}", .{ src, @as(u32, rd), src, @as(u32, rn) });
    return d;
}

fn fp2Source(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const rm = reg(w, 16);
    const opcode = bits(w, 15, 12);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1) return undef(w);
    const letter = fpLetter(ty) orelse return undef(w);
    const name: []const u8 = switch (opcode) {
        0 => "fmul",
        1 => "fdiv",
        2 => "fadd",
        3 => "fsub",
        4 => "fmax",
        5 => "fmin",
        6 => "fmaxnm",
        7 => "fminnm",
        8 => "fnmul",
        else => return undef(w),
    };
    var d: Dec = .{};
    d.setMnem(name);
    d.ops.print("{c}{d}, {c}{d}, {c}{d}", .{ letter, @as(u32, rd), letter, @as(u32, rn), letter, @as(u32, rm) });
    return d;
}

fn fpCompare(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const rm = reg(w, 16);
    const rn = reg(w, 5);
    const opcode2 = bits(w, 4, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1 or bits(w, 15, 14) != 0) return undef(w);
    const letter = fpLetter(ty) orelse return undef(w);
    var d: Dec = .{};
    switch (opcode2) {
        0b00000, 0b10000 => {
            d.setMnem(if (opcode2 == 0) "fcmp" else "fcmpe");
            d.ops.print("{c}{d}, {c}{d}", .{ letter, @as(u32, rn), letter, @as(u32, rm) });
        },
        0b01000, 0b11000 => {
            if (rm != 0) return undef(w);
            d.setMnem(if (opcode2 == 0b01000) "fcmp" else "fcmpe");
            d.ops.print("{c}{d}, #0.0", .{ letter, @as(u32, rn) });
        },
        else => return undef(w),
    }
    return d;
}

/// imm8 -> IEEE value: (-1)^b7 * 2^(b6 ? e-3 : e+1) * (1 + f/16) (disasm-notes B.7).
fn fpImmValue(imm8: u32) f64 {
    const sign: f64 = if ((imm8 & 0x80) != 0) -1.0 else 1.0;
    const b6: bool = (imm8 & 0x40) != 0;
    const e: i32 = @intCast((imm8 >> 4) & 3);
    const f: f64 = @floatFromInt(imm8 & 0xf);
    const exp: i32 = if (b6) e - 3 else e + 1;
    return sign * std.math.ldexp(1.0 + f / 16.0, exp);
}

fn fpImmediate(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const imm8 = bits(w, 20, 13);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1 or bits(w, 9, 5) != 0) return undef(w);
    const letter = fpLetter(ty) orelse return undef(w);
    var d: Dec = .{};
    d.setMnem("fmov");
    d.ops.print("{c}{d}, #{d:.8}", .{ letter, @as(u32, rd), fpImmValue(imm8) });
    return d;
}

fn fcsel(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const rm = reg(w, 16);
    const cond: u4 = @truncate(bits(w, 15, 12));
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0 or bit(w, 21) != 1) return undef(w);
    const letter = fpLetter(ty) orelse return undef(w);
    var d: Dec = .{};
    d.setMnem("fcsel");
    d.ops.print("{c}{d}, {c}{d}, {c}{d}, ", .{ letter, @as(u32, rd), letter, @as(u32, rn), letter, @as(u32, rm) });
    d.ops.str(condName(cond));
    return d;
}

fn fpMulAdd(w: u32) Dec {
    const ty = bits(w, 23, 22);
    const o1 = bit(w, 21);
    const rm = reg(w, 16);
    const o0 = bit(w, 15);
    const ra = reg(w, 10);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0) return undef(w);
    const letter = fpLetter(ty) orelse return undef(w);
    var d: Dec = .{};
    d.setMnem(switch ((@as(u32, o1) << 1) | o0) {
        0b00 => "fmadd",
        0b01 => "fmsub",
        0b10 => "fnmadd",
        else => "fnmsub",
    });
    d.ops.print("{c}{d}, {c}{d}, {c}{d}, {c}{d}", .{ letter, @as(u32, rd), letter, @as(u32, rn), letter, @as(u32, rm), letter, @as(u32, ra) });
    return d;
}

/// Element size and lane index from imm5 (`xxxx1` B, `xxx10` H, `xx100` S, `x1000` D).
fn imm5Elem(imm5: u32) ?struct { letter: u8, index: u32, size: u2 } {
    if (imm5 & 1 != 0) return .{ .letter = 'b', .index = (imm5 >> 1) & 0xf, .size = 0 };
    if (imm5 & 2 != 0) return .{ .letter = 'h', .index = (imm5 >> 2) & 0x7, .size = 1 };
    if (imm5 & 4 != 0) return .{ .letter = 's', .index = (imm5 >> 3) & 0x3, .size = 2 };
    if (imm5 & 8 != 0) return .{ .letter = 'd', .index = (imm5 >> 4) & 0x1, .size = 3 };
    return null;
}

fn arrangement(size: u2, q: u1) []const u8 {
    return switch (size) {
        0 => if (q == 1) "16b" else "8b",
        1 => if (q == 1) "8h" else "4h",
        2 => if (q == 1) "4s" else "2s",
        3 => "2d",
    };
}

fn dupGeneral(w: u32, st: Style) Dec {
    const q = bit(w, 30);
    const imm5 = bits(w, 20, 16);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0) return undef(w);
    const e = imm5Elem(imm5) orelse return undef(w);
    if (e.size == 3 and q == 0) return undef(w);
    var d: Dec = .{};
    const arr = arrangement(e.size, q);
    d.simdMnem(st, "dup", arr);
    vreg(&d.ops, st, rd, arr);
    d.ops.str(", ");
    gpr(&d.ops, e.size == 3, rn, false);
    return d;
}

fn insGeneral(w: u32, st: Style) Dec {
    const imm5 = bits(w, 20, 16);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    const e = imm5Elem(imm5) orelse return undef(w);
    var d: Dec = .{};
    const lb: [1]u8 = .{e.letter};
    d.simdMnem(st, "mov", &lb); // LLVM prints INS (general) as MOV; otool as `mov.d v0[1], x1`
    velem(&d.ops, st, rd, e.letter, e.index);
    d.ops.str(", ");
    gpr(&d.ops, e.size == 3, rn, false);
    return d;
}

fn movFromVector(w: u32, signed: bool, st: Style) Dec {
    const q = bit(w, 30);
    const imm5 = bits(w, 20, 16);
    const rn = reg(w, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or bit(w, 29) != 0) return undef(w);
    const e = imm5Elem(imm5) orelse return undef(w);
    var d: Dec = .{ .reg_write = regWrite(rd, false) };
    const lb: [1]u8 = .{e.letter};
    if (signed) {
        if (e.size == 3) return undef(w);
        if (e.size == 2 and q == 0) return undef(w);
        d.simdMnem(st, "smov", &lb);
    } else {
        if (e.size == 3 and q == 0) return undef(w);
        if (e.size < 2 and q == 1) return undef(w);
        // UMOV of an S or D element is printed as MOV by LLVM.
        d.simdMnem(st, if (e.size >= 2) "mov" else "umov", &lb);
    }
    gpr(&d.ops, q == 1, rd, false);
    d.ops.str(", ");
    velem(&d.ops, st, rn, e.letter, e.index);
    return d;
}

/// MOVI/MVNI/ORR/BIC (vector, immediate) and FMOV (vector, immediate) (notes B.7).
fn movi(w: u32, st: Style) Dec {
    const q = bit(w, 30);
    const op = bit(w, 29);
    const cmode = bits(w, 15, 12);
    const o2 = bit(w, 11);
    const imm8: u32 = (bits(w, 18, 16) << 5) | bits(w, 9, 5);
    const rd = reg(w, 0);
    if (bit(w, 31) != 0 or o2 != 0) return undef(w);
    var d: Dec = .{};

    if (cmode & 0b1001 == 0b0000 or cmode & 0b1101 == 0b1000) { // 32-bit / 16-bit shifted
        const wide = (cmode & 0b1100) != 0b1000;
        const amount: u32 = if (wide) ((cmode >> 1) & 3) * 8 else ((cmode >> 1) & 1) * 8;
        const size: u2 = if (wide) 2 else 1;
        const arr = arrangement(size, q);
        d.simdMnem(st, if (op == 1) "mvni" else "movi", arr);
        vreg(&d.ops, st, rd, arr);
        d.ops.str(", ");
        hexImm(&d.ops, imm8);
        if (amount != 0) d.ops.print(", lsl #{d}", .{amount});
        return d;
    }
    if (cmode & 0b1001 == 0b0001 or cmode & 0b1101 == 0b1001) { // ORR / BIC immediate
        const wide = (cmode & 0b1100) != 0b1000;
        const amount: u32 = if (wide) ((cmode >> 1) & 3) * 8 else ((cmode >> 1) & 1) * 8;
        const size: u2 = if (wide) 2 else 1;
        const arr = arrangement(size, q);
        d.simdMnem(st, if (op == 1) "bic" else "orr", arr);
        vreg(&d.ops, st, rd, arr);
        d.ops.str(", ");
        hexImm(&d.ops, imm8);
        if (amount != 0) d.ops.print(", lsl #{d}", .{amount});
        return d;
    }
    if (cmode & 0b1110 == 0b1100) { // MSL forms
        const amount: u32 = if ((cmode & 1) == 1) 16 else 8;
        const arr = arrangement(2, q);
        d.simdMnem(st, if (op == 1) "mvni" else "movi", arr);
        vreg(&d.ops, st, rd, arr);
        d.ops.str(", ");
        hexImm(&d.ops, imm8);
        d.ops.print(", msl #{d}", .{amount});
        return d;
    }
    if (cmode == 0b1110) {
        if (op == 0) {
            const arr = arrangement(0, q);
            d.simdMnem(st, "movi", arr);
            vreg(&d.ops, st, rd, arr);
            d.ops.str(", ");
            hexImm(&d.ops, imm8);
            return d;
        }
        // 64-bit "each imm8 bit becomes a byte" form.
        var value: u64 = 0;
        var i: u3 = 0;
        while (true) : (i += 1) {
            if ((imm8 >> i) & 1 == 1) value |= @as(u64, 0xff) << (@as(u6, i) * 8);
            if (i == 7) break;
        }
        // Q = 0 is the scalar form: `movi d3, #0...0`, which carries no arrangement in either dialect.
        if (q == 1) {
            d.simdMnem(st, "movi", "2d");
            vreg(&d.ops, st, rd, "2d");
            d.ops.print(", #{x:0>16}", .{value});
        } else {
            d.setMnem("movi");
            d.ops.print("d{d}, #{x:0>16}", .{ @as(u32, rd), value });
        }
        return d;
    }
    if (cmode == 0b1111) {
        if (op == 1 and q == 0) return undef(w);
        const size: u2 = if (op == 1) 3 else 2;
        const arr = arrangement(size, q);
        d.simdMnem(st, "fmov", arr);
        vreg(&d.ops, st, rd, arr);
        d.ops.print(", #{d:.8}", .{fpImmValue(imm8)});
        return d;
    }
    return undef(w);
}

// ---------------------------------------------------------------------------------------------
// Advanced SIMD three same registers (disasm-notes B.7 sibling family)
// ---------------------------------------------------------------------------------------------

/// Integer/logical row of `0 Q U 01110 size 1 Rm opcode 1 Rn Rd`; null for the reserved size/opcode
/// combinations (`size == 11` on the halving, max/min, abd/aba, mla/mul and pairwise rows, PMUL
/// outside `.8b/.16b`, SQ(R)DMULH outside `.4h/.8h/.2s/.4s`, and the unallocated U=1 opcode 10111).
fn intThreeSameName(u: u1, opcode: u32, size: u2) ?[]const u8 {
    const narrow = size != 3; // "size == 11 -> RESERVED"
    return switch (opcode) {
        0b00000 => if (narrow) (if (u == 0) "shadd" else "uhadd") else null,
        0b00001 => if (u == 0) "sqadd" else "uqadd",
        0b00010 => if (narrow) (if (u == 0) "srhadd" else "urhadd") else null,
        0b00100 => if (narrow) (if (u == 0) "shsub" else "uhsub") else null,
        0b00101 => if (u == 0) "sqsub" else "uqsub",
        0b00110 => if (u == 0) "cmgt" else "cmhi",
        0b00111 => if (u == 0) "cmge" else "cmhs",
        0b01000 => if (u == 0) "sshl" else "ushl",
        0b01001 => if (u == 0) "sqshl" else "uqshl",
        0b01010 => if (u == 0) "srshl" else "urshl",
        0b01011 => if (u == 0) "sqrshl" else "uqrshl",
        0b01100 => if (narrow) (if (u == 0) "smax" else "umax") else null,
        0b01101 => if (narrow) (if (u == 0) "smin" else "umin") else null,
        0b01110 => if (narrow) (if (u == 0) "sabd" else "uabd") else null,
        0b01111 => if (narrow) (if (u == 0) "saba" else "uaba") else null,
        0b10000 => if (u == 0) "add" else "sub",
        0b10001 => if (u == 0) "cmtst" else "cmeq",
        0b10010 => if (narrow) (if (u == 0) "mla" else "mls") else null,
        0b10011 => if (u == 0) (if (narrow) "mul" else null) else (if (size == 0) "pmul" else null),
        0b10100 => if (narrow) (if (u == 0) "smaxp" else "umaxp") else null,
        0b10101 => if (narrow) (if (u == 0) "sminp" else "uminp") else null,
        0b10110 => if (size == 1 or size == 2) (if (u == 0) "sqdmulh" else "sqrdmulh") else null,
        0b10111 => if (u == 0) "addp" else null,
        else => null,
    };
}

/// Floating-point row (opcode 11xxx): bit 23 picks the "minus" column, bit 22 is sz (2s/4s vs 2d).
fn fpThreeSameName(u: u1, a: u1, opcode: u32) ?[]const u8 {
    if (u == 0) {
        if (a == 0) return switch (opcode) {
            0b11000 => "fmaxnm",
            0b11001 => "fmla",
            0b11010 => "fadd",
            0b11011 => "fmulx",
            0b11100 => "fcmeq",
            0b11110 => "fmax",
            0b11111 => "frecps",
            else => null,
        };
        return switch (opcode) {
            0b11000 => "fminnm",
            0b11001 => "fmls",
            0b11010 => "fsub",
            0b11110 => "fmin",
            0b11111 => "frsqrts",
            else => null,
        };
    }
    if (a == 0) return switch (opcode) {
        0b11000 => "fmaxnmp",
        0b11010 => "faddp",
        0b11011 => "fmul",
        0b11100 => "fcmge",
        0b11101 => "facge",
        0b11110 => "fmaxp",
        0b11111 => "fdiv",
        else => null,
    };
    return switch (opcode) {
        0b11000 => "fminnmp",
        0b11010 => "fabd",
        0b11100 => "fcmgt",
        0b11101 => "facgt",
        0b11110 => "fminp",
        else => null,
    };
}

/// Advanced SIMD three same registers: `0 Q U 01110 size 1 Rm opcode 1 Rn Rd` (mask 0x9f20_0400 ->
/// 0x0e20_0400). Covers the integer arithmetic/compare/shift rows, the four logical rows (whose
/// arrangement is always `.8b`/`.16b`), and the floating-point row. `orr Vd.T, Vn.T, Vn.T` prints as
/// `mov` exactly as LLVM does. Every mnemonic here was checked against `otool -tV` of an assembled
/// object holding all 100 forms (see the table test at the end of this file).
fn simdThreeSame(w: u32, st: Style) Dec {
    const q = bit(w, 30);
    const u = bit(w, 29);
    const size: u2 = @truncate(bits(w, 23, 22));
    const rm = reg(w, 16);
    const opcode = bits(w, 15, 11);
    const rn = reg(w, 5);
    const rd = reg(w, 0);

    var d: Dec = .{};
    var name: []const u8 = undefined;
    var arr: []const u8 = undefined;

    if (opcode >= 0b11000) { // floating-point row
        const a = bit(w, 23);
        const sz = bit(w, 22);
        if (sz == 1 and q == 0) return undef(w); // `1d` is not an arrangement
        name = fpThreeSameName(u, a, opcode) orelse return undef(w);
        arr = if (sz == 1) "2d" else (if (q == 1) "4s" else "2s");
    } else if (opcode == 0b00011) { // AND/BIC/ORR/ORN, EOR/BSL/BIT/BIF -- byte arrangement only
        name = if (u == 0) switch (size) {
            0 => "and",
            1 => "bic",
            2 => "orr",
            3 => "orn",
        } else switch (size) {
            0 => "eor",
            1 => "bsl",
            2 => "bit",
            3 => "bif",
        };
        arr = if (q == 1) "16b" else "8b";
        if (u == 0 and size == 2 and rn == rm) { // ORR Vd, Vn, Vn -> MOV
            d.simdMnem(st, "mov", arr);
            vreg(&d.ops, st, rd, arr);
            d.ops.str(", ");
            vreg(&d.ops, st, rn, arr);
            return d;
        }
    } else {
        if (size == 3 and q == 0) return undef(w); // `1d` is not an arrangement
        name = intThreeSameName(u, opcode, size) orelse return undef(w);
        arr = arrangement(size, q);
    }

    d.simdMnem(st, name, arr);
    vreg(&d.ops, st, rd, arr);
    d.ops.str(", ");
    vreg(&d.ops, st, rn, arr);
    d.ops.str(", ");
    vreg(&d.ops, st, rm, arr);
    return d;
}

test "arm64: Darwin (--otool-compat) SIMD spelling and the three-same family" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Every row assembled with `clang -c -arch arm64` and read back with `otool -tV` (notes B.7a/B.7b);
    // the `.arm` column is ARM's canonical spelling, which the default listing keeps.
    const Pair = struct { word: u32, arm_m: []const u8, arm_o: []const u8, dar_m: []const u8, dar_o: []const u8 };
    const rows = [_]Pair{
        .{ .word = 0x6f00e400, .arm_m = "movi", .arm_o = "v0.2d, #0000000000000000", .dar_m = "movi.2d", .dar_o = "v0, #0000000000000000" },
        .{ .word = 0x2f00e403, .arm_m = "movi", .arm_o = "d3, #0000000000000000", .dar_m = "movi", .dar_o = "d3, #0000000000000000" },
        .{ .word = 0x0f0014e5, .arm_m = "orr", .arm_o = "v5.2s, #0x7", .dar_m = "orr.2s", .dar_o = "v5, #0x7" },
        .{ .word = 0x4f03f607, .arm_m = "fmov", .arm_o = "v7.4s, #1.00000000", .dar_m = "fmov.4s", .dar_o = "v7, #1.00000000" },
        .{ .word = 0x4e080c62, .arm_m = "dup", .arm_o = "v2.2d, x3", .dar_m = "dup.2d", .dar_o = "v2, x3" },
        .{ .word = 0x4e181c20, .arm_m = "mov", .arm_o = "v0.d[1], x1", .dar_m = "mov.d", .dar_o = "v0[1], x1" },
        .{ .word = 0x0e0c3c20, .arm_m = "mov", .arm_o = "w0, v1.s[1]", .dar_m = "mov.s", .dar_o = "w0, v1[1]" },
        .{ .word = 0x0e073ca4, .arm_m = "umov", .arm_o = "w4, v5.b[3]", .dar_m = "umov.b", .dar_o = "w4, v5[3]" },
        .{ .word = 0x0e0a2ce6, .arm_m = "smov", .arm_o = "w6, v7.h[2]", .dar_m = "smov.h", .dar_o = "w6, v7[2]" },
        .{ .word = 0x9eae0002, .arm_m = "fmov", .arm_o = "x2, v0.d[1]", .dar_m = "fmov.d", .dar_o = "x2, v0[1]" },
        // three same registers
        .{ .word = 0x6ee18401, .arm_m = "sub", .arm_o = "v1.2d, v0.2d, v1.2d", .dar_m = "sub.2d", .dar_o = "v1, v0, v1" },
        .{ .word = 0x4ea28401, .arm_m = "add", .arm_o = "v1.4s, v0.4s, v2.4s", .dar_m = "add.4s", .dar_o = "v1, v0, v2" },
        .{ .word = 0x0e221c20, .arm_m = "and", .arm_o = "v0.8b, v1.8b, v2.8b", .dar_m = "and.8b", .dar_o = "v0, v1, v2" },
        .{ .word = 0x4ea41c83, .arm_m = "mov", .arm_o = "v3.16b, v4.16b", .dar_m = "mov.16b", .dar_o = "v3, v4" }, // ORR Vd,Vn,Vn
        .{ .word = 0x2e229c20, .arm_m = "pmul", .arm_o = "v0.8b, v1.8b, v2.8b", .dar_m = "pmul.8b", .dar_o = "v0, v1, v2" },
        .{ .word = 0x6ee23c20, .arm_m = "cmhs", .arm_o = "v0.2d, v1.2d, v2.2d", .dar_m = "cmhs.2d", .dar_o = "v0, v1, v2" },
        .{ .word = 0x4e62b420, .arm_m = "sqdmulh", .arm_o = "v0.8h, v1.8h, v2.8h", .dar_m = "sqdmulh.8h", .dar_o = "v0, v1, v2" },
        .{ .word = 0x4ee2bc20, .arm_m = "addp", .arm_o = "v0.2d, v1.2d, v2.2d", .dar_m = "addp.2d", .dar_o = "v0, v1, v2" },
        .{ .word = 0x4e22c420, .arm_m = "fmaxnm", .arm_o = "v0.4s, v1.4s, v2.4s", .dar_m = "fmaxnm.4s", .dar_o = "v0, v1, v2" },
        .{ .word = 0x4ee2fc20, .arm_m = "frsqrts", .arm_o = "v0.2d, v1.2d, v2.2d", .dar_m = "frsqrts.2d", .dar_o = "v0, v1, v2" },
        .{ .word = 0x6e22c420, .arm_m = "fmaxnmp", .arm_o = "v0.4s, v1.4s, v2.4s", .dar_m = "fmaxnmp.4s", .dar_o = "v0, v1, v2" },
        .{ .word = 0x6e62d420, .arm_m = "faddp", .arm_o = "v0.2d, v1.2d, v2.2d", .dar_m = "faddp.2d", .dar_o = "v0, v1, v2" },
    };
    for (rows) |r| {
        const a = try decodeOne(arena, r.word, 0x100000000, .arm);
        try std.testing.expectEqualStrings(r.arm_m, a.mnemonic);
        try std.testing.expectEqualStrings(r.arm_o, a.operands);
        const d = try decodeOne(arena, r.word, 0x100000000, .darwin);
        try std.testing.expectEqualStrings(r.dar_m, d.mnemonic);
        try std.testing.expectEqualStrings(r.dar_o, d.operands);
    }
    // Q = 0 with a `2d` arrangement is reserved in every three-same row.
    try std.testing.expectEqualStrings(".inst", (try decodeOne(arena, 0x2ee18401, 0, .arm)).mnemonic);
    // ... but Q = 0 with `2s` is fine.
    try std.testing.expectEqualStrings("sub.2s", (try decodeOne(arena, 0x2ea18401, 0, .darwin)).mnemonic);
}

test "arm64: the MOV aliases print their immediate signed, the raw logical forms do not" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Row2 = struct { word: u32, operands: []const u8 };
    // otool -tV of an assembled object (notes B.7c).
    const rows = [_]Row2{
        .{ .word = 0xb201e3e9, .operands = "x9, #-0x7777777777777778" }, // orr x9, xzr, #0x8888...
        .{ .word = 0x3201f3e2, .operands = "w2, #-0x55555556" }, // orr w2, wzr, #0xaaaaaaaa
        .{ .word = 0xd2f00000, .operands = "x0, #-0x8000000000000000" }, // movz x0, #0x8000, lsl #48
        .{ .word = 0x92800000, .operands = "x0, #-0x1" }, // movn x0, #0
        .{ .word = 0x92f00000, .operands = "x0, #0x7fffffffffffffff" },
        .{ .word = 0x927df0c5, .operands = "x5, x6, #0xfffffffffffffff8" }, // and (stays unsigned)
        .{ .word = 0xb270bd6a, .operands = "x10, x11, #0xffffffffffff0000" }, // orr (stays unsigned)
    };
    for (rows) |r| {
        const i = try decodeOne(arena, r.word, 0, .arm);
        try std.testing.expectEqualStrings(r.operands, i.operands);
        // the Darwin dialect never changes a scalar immediate
        try std.testing.expectEqualStrings(r.operands, (try decodeOne(arena, r.word, 0, .darwin)).operands);
    }
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

const Row = struct { pc: u64, word: u32, mnemonic: []const u8, operands: []const u8 };

/// disasm-notes Part B, verified encoding by encoding against `otool -arch arm64e -tv` of an object
/// containing exactly these words (see the file header for the three documented deviations).
const table = [_]Row{
    .{ .pc = 0x0, .word = 0x10000000, .mnemonic = "adr", .operands = "x0, #0" },
    .{ .pc = 0x4, .word = 0x90000001, .mnemonic = "adrp", .operands = "x1, 0" },
    .{ .pc = 0x8, .word = 0x9101a020, .mnemonic = "add", .operands = "x0, x1, #0x68" },
    .{ .pc = 0xc, .word = 0x11400462, .mnemonic = "add", .operands = "w2, w3, #0x1, lsl #12" },
    .{ .pc = 0x10, .word = 0xd10103ff, .mnemonic = "sub", .operands = "sp, sp, #0x40" },
    .{ .pc = 0x14, .word = 0xf1001ca4, .mnemonic = "subs", .operands = "x4, x5, #0x7" },
    .{ .pc = 0x18, .word = 0xf10024df, .mnemonic = "cmp", .operands = "x6, #0x9" },
    .{ .pc = 0x1c, .word = 0x310004ff, .mnemonic = "cmn", .operands = "w7, #0x1" },
    .{ .pc = 0x20, .word = 0x910003e0, .mnemonic = "mov", .operands = "x0, sp" },
    .{ .pc = 0x24, .word = 0x92401c20, .mnemonic = "and", .operands = "x0, x1, #0xff" },
    .{ .pc = 0x28, .word = 0x32000062, .mnemonic = "orr", .operands = "w2, w3, #0x1" },
    .{ .pc = 0x2c, .word = 0xd2103ca4, .mnemonic = "eor", .operands = "x4, x5, #0xffff0000ffff0000" },
    .{ .pc = 0x30, .word = 0xf27c0ce6, .mnemonic = "ands", .operands = "x6, x7, #0xf0" },
    .{ .pc = 0x34, .word = 0x7201011f, .mnemonic = "tst", .operands = "w8, #0x80000000" },
    .{ .pc = 0x38, .word = 0xb200f3e9, .mnemonic = "mov", .operands = "x9, #0x5555555555555555" },
    .{ .pc = 0x3c, .word = 0x52800020, .mnemonic = "mov", .operands = "w0, #0x1" },
    .{ .pc = 0x40, .word = 0x12800000, .mnemonic = "mov", .operands = "w0, #-0x1" },
    .{ .pc = 0x44, .word = 0xd2a24681, .mnemonic = "mov", .operands = "x1, #0x12340000" },
    .{ .pc = 0x48, .word = 0x928000a2, .mnemonic = "mov", .operands = "x2, #-0x6" },
    .{ .pc = 0x4c, .word = 0xf2f7dde3, .mnemonic = "movk", .operands = "x3, #0xbeef, lsl #48" },
    .{ .pc = 0x50, .word = 0xd37cec20, .mnemonic = "lsl", .operands = "x0, x1, #4" },
    .{ .pc = 0x54, .word = 0x53057c62, .mnemonic = "lsr", .operands = "w2, w3, #5" },
    .{ .pc = 0x58, .word = 0x53001ce6, .mnemonic = "uxtb", .operands = "w6, w7" },
    .{ .pc = 0x5c, .word = 0x53003d28, .mnemonic = "uxth", .operands = "w8, w9" },
    .{ .pc = 0x60, .word = 0x531e0b7a, .mnemonic = "ubfiz", .operands = "w26, w27, #2, #3" },
    .{ .pc = 0x64, .word = 0xd3482e30, .mnemonic = "ubfx", .operands = "x16, x17, #8, #4" },
    .{ .pc = 0x68, .word = 0x9346fca4, .mnemonic = "asr", .operands = "x4, x5, #6" },
    .{ .pc = 0x6c, .word = 0x93401d6a, .mnemonic = "sxtb", .operands = "x10, w11" },
    .{ .pc = 0x70, .word = 0x93403dac, .mnemonic = "sxth", .operands = "x12, w13" },
    .{ .pc = 0x74, .word = 0x93407dee, .mnemonic = "sxtw", .operands = "x14, w15" },
    .{ .pc = 0x78, .word = 0x937d1338, .mnemonic = "sbfiz", .operands = "x24, x25, #3, #5" },
    .{ .pc = 0x7c, .word = 0x13010a72, .mnemonic = "sbfx", .operands = "w18, w19, #1, #2" },
    .{ .pc = 0x80, .word = 0xb3701eb4, .mnemonic = "bfi", .operands = "x20, x21, #16, #8" },
    .{ .pc = 0x84, .word = 0xb3441ef6, .mnemonic = "bfxil", .operands = "x22, x23, #4, #4" },
    .{ .pc = 0x88, .word = 0x93de33bc, .mnemonic = "extr", .operands = "x28, x29, x30, #0xc" },
    .{ .pc = 0x8c, .word = 0x93c11c20, .mnemonic = "ror", .operands = "x0, x1, #0x7" },
    .{ .pc = 0x90, .word = 0x14000000, .mnemonic = "b", .operands = "0x90" },
    .{ .pc = 0x94, .word = 0x94000000, .mnemonic = "bl", .operands = "0x94" },
    .{ .pc = 0x98, .word = 0x14000fe1, .mnemonic = "b", .operands = "0x401c" },
    .{ .pc = 0x9c, .word = 0x54000000, .mnemonic = "b.eq", .operands = "0x9c" },
    .{ .pc = 0xa0, .word = 0x5400000e, .mnemonic = "b.al", .operands = "0xa0" },
    .{ .pc = 0xa4, .word = 0x5400006d, .mnemonic = "b.le", .operands = "0xb0" },
    .{ .pc = 0xa8, .word = 0xb4000000, .mnemonic = "cbz", .operands = "x0, 0xa8" },
    .{ .pc = 0xac, .word = 0x35000001, .mnemonic = "cbnz", .operands = "w1, 0xac" },
    .{ .pc = 0xb0, .word = 0xb6400002, .mnemonic = "tbz", .operands = "x2, #0x28, 0xb0" },
    .{ .pc = 0xb4, .word = 0x37180003, .mnemonic = "tbnz", .operands = "w3, #0x3, 0xb4" },
    .{ .pc = 0xb8, .word = 0xd61f0080, .mnemonic = "br", .operands = "x4" },
    .{ .pc = 0xbc, .word = 0xd63f00a0, .mnemonic = "blr", .operands = "x5" },
    .{ .pc = 0xc0, .word = 0xd65f03c0, .mnemonic = "ret", .operands = "" },
    .{ .pc = 0xc4, .word = 0xd65f00c0, .mnemonic = "ret", .operands = "x6" },
    .{ .pc = 0xc8, .word = 0xd69f03e0, .mnemonic = "eret", .operands = "" },
    .{ .pc = 0xcc, .word = 0xd61f091f, .mnemonic = "braaz", .operands = "x8" },
    .{ .pc = 0xd0, .word = 0xd61f0d3f, .mnemonic = "brabz", .operands = "x9" },
    .{ .pc = 0xd4, .word = 0xd63f095f, .mnemonic = "blraaz", .operands = "x10" },
    .{ .pc = 0xd8, .word = 0xd63f0d7f, .mnemonic = "blrabz", .operands = "x11" },
    .{ .pc = 0xdc, .word = 0xd71f0801, .mnemonic = "braa", .operands = "x0, x1" },
    .{ .pc = 0xe0, .word = 0xd71f0c43, .mnemonic = "brab", .operands = "x2, x3" },
    .{ .pc = 0xe4, .word = 0xd73f0885, .mnemonic = "blraa", .operands = "x4, x5" },
    .{ .pc = 0xe8, .word = 0xd73f0cc7, .mnemonic = "blrab", .operands = "x6, x7" },
    .{ .pc = 0xec, .word = 0xd65f0bff, .mnemonic = "retaa", .operands = "" },
    .{ .pc = 0xf0, .word = 0xd65f0fff, .mnemonic = "retab", .operands = "" },
    .{ .pc = 0xf4, .word = 0xd4001001, .mnemonic = "svc", .operands = "#0x80" },
    .{ .pc = 0xf8, .word = 0xd4000022, .mnemonic = "hvc", .operands = "#0x1" },
    .{ .pc = 0xfc, .word = 0xd4000043, .mnemonic = "smc", .operands = "#0x2" },
    .{ .pc = 0x100, .word = 0xd4200020, .mnemonic = "brk", .operands = "#0x1" },
    .{ .pc = 0x104, .word = 0xd4388e20, .mnemonic = "brk", .operands = "#0xc471" },
    .{ .pc = 0x108, .word = 0xd4400000, .mnemonic = "hlt", .operands = "#0" },
    .{ .pc = 0x10c, .word = 0xd503201f, .mnemonic = "nop", .operands = "" },
    .{ .pc = 0x110, .word = 0xd50320ff, .mnemonic = "xpaclri", .operands = "" },
    .{ .pc = 0x114, .word = 0xd503211f, .mnemonic = "pacia1716", .operands = "" },
    .{ .pc = 0x118, .word = 0xd503229f, .mnemonic = "csdb", .operands = "" },
    .{ .pc = 0x11c, .word = 0xd503231f, .mnemonic = "paciaz", .operands = "" },
    .{ .pc = 0x120, .word = 0xd503233f, .mnemonic = "paciasp", .operands = "" },
    .{ .pc = 0x124, .word = 0xd503237f, .mnemonic = "pacibsp", .operands = "" },
    .{ .pc = 0x128, .word = 0xd50323bf, .mnemonic = "autiasp", .operands = "" },
    .{ .pc = 0x12c, .word = 0xd50323ff, .mnemonic = "autibsp", .operands = "" },
    .{ .pc = 0x130, .word = 0xd503241f, .mnemonic = "bti", .operands = "" },
    .{ .pc = 0x134, .word = 0xd503245f, .mnemonic = "bti", .operands = "c" },
    .{ .pc = 0x138, .word = 0xd50324df, .mnemonic = "bti", .operands = "jc" },
    .{ .pc = 0x13c, .word = 0xd5033f5f, .mnemonic = "clrex", .operands = "" },
    .{ .pc = 0x140, .word = 0xd5033f9f, .mnemonic = "dsb", .operands = "sy" },
    .{ .pc = 0x144, .word = 0xd5033b9f, .mnemonic = "dsb", .operands = "ish" },
    .{ .pc = 0x148, .word = 0xd5033fbf, .mnemonic = "dmb", .operands = "sy" },
    .{ .pc = 0x14c, .word = 0xd5033bbf, .mnemonic = "dmb", .operands = "ish" },
    .{ .pc = 0x150, .word = 0xd5033fdf, .mnemonic = "isb", .operands = "" },
    .{ .pc = 0x154, .word = 0xd50342df, .mnemonic = "msr", .operands = "DAIFSet, #0x2" },
    .{ .pc = 0x158, .word = 0xd50342ff, .mnemonic = "msr", .operands = "DAIFClr, #0x2" },
    .{ .pc = 0x15c, .word = 0xd53b4200, .mnemonic = "mrs", .operands = "x0, NZCV" },
    .{ .pc = 0x160, .word = 0xd51b4201, .mnemonic = "msr", .operands = "NZCV, x1" },
    .{ .pc = 0x164, .word = 0xd53b4225, .mnemonic = "mrs", .operands = "x5, DAIF" },
    .{ .pc = 0x168, .word = 0xd53b4406, .mnemonic = "mrs", .operands = "x6, FPCR" },
    .{ .pc = 0x16c, .word = 0xd51b4407, .mnemonic = "msr", .operands = "FPCR, x7" },
    .{ .pc = 0x170, .word = 0xd53b4428, .mnemonic = "mrs", .operands = "x8, FPSR" },
    .{ .pc = 0x174, .word = 0xd53bd042, .mnemonic = "mrs", .operands = "x2, TPIDR_EL0" },
    .{ .pc = 0x178, .word = 0xd53bd063, .mnemonic = "mrs", .operands = "x3, TPIDRRO_EL0" },
    .{ .pc = 0x17c, .word = 0xd53be044, .mnemonic = "mrs", .operands = "x4, CNTVCT_EL0" },
    .{ .pc = 0x180, .word = 0xd53be00b, .mnemonic = "mrs", .operands = "x11, CNTFRQ_EL0" },
    .{ .pc = 0x184, .word = 0xd53b0029, .mnemonic = "mrs", .operands = "x9, CTR_EL0" },
    .{ .pc = 0x188, .word = 0xd53b00ea, .mnemonic = "mrs", .operands = "x10, DCZID_EL0" },
    .{ .pc = 0x18c, .word = 0xd538000c, .mnemonic = "mrs", .operands = "x12, MIDR_EL1" },
    .{ .pc = 0x190, .word = 0x8a020020, .mnemonic = "and", .operands = "x0, x1, x2" },
    .{ .pc = 0x194, .word = 0x0a250c83, .mnemonic = "bic", .operands = "w3, w4, w5, lsl #3" },
    .{ .pc = 0x198, .word = 0xaa4810e6, .mnemonic = "orr", .operands = "x6, x7, x8, lsr #4" },
    .{ .pc = 0x19c, .word = 0xaa2b0149, .mnemonic = "orn", .operands = "x9, x10, x11" },
    .{ .pc = 0x1a0, .word = 0xca8e15ac, .mnemonic = "eor", .operands = "x12, x13, x14, asr #5" },
    .{ .pc = 0x1a4, .word = 0xca31020f, .mnemonic = "eon", .operands = "x15, x16, x17" },
    .{ .pc = 0x1a8, .word = 0xea140272, .mnemonic = "ands", .operands = "x18, x19, x20" },
    .{ .pc = 0x1ac, .word = 0x6a3702d5, .mnemonic = "bics", .operands = "w21, w22, w23" },
    .{ .pc = 0x1b0, .word = 0xaa0103e0, .mnemonic = "mov", .operands = "x0, x1" },
    .{ .pc = 0x1b4, .word = 0xaa2303e2, .mnemonic = "mvn", .operands = "x2, x3" },
    .{ .pc = 0x1b8, .word = 0xea05009f, .mnemonic = "tst", .operands = "x4, x5" },
    .{ .pc = 0x1bc, .word = 0x8b020020, .mnemonic = "add", .operands = "x0, x1, x2" },
    .{ .pc = 0x1c0, .word = 0x8b020820, .mnemonic = "add", .operands = "x0, x1, x2, lsl #2" },
    .{ .pc = 0x1c4, .word = 0x4b450483, .mnemonic = "sub", .operands = "w3, w4, w5, lsr #1" },
    .{ .pc = 0x1c8, .word = 0xeb0800e6, .mnemonic = "subs", .operands = "x6, x7, x8" },
    .{ .pc = 0x1cc, .word = 0xab8b0d49, .mnemonic = "adds", .operands = "x9, x10, x11, asr #3" },
    .{ .pc = 0x1d0, .word = 0xeb0b015f, .mnemonic = "cmp", .operands = "x10, x11" },
    .{ .pc = 0x1d4, .word = 0xab0d019f, .mnemonic = "cmn", .operands = "x12, x13" },
    .{ .pc = 0x1d8, .word = 0xcb0f03ee, .mnemonic = "neg", .operands = "x14, x15" },
    .{ .pc = 0x1dc, .word = 0x6b1103f0, .mnemonic = "negs", .operands = "w16, w17" },
    .{ .pc = 0x1e0, .word = 0x8b2163e0, .mnemonic = "add", .operands = "x0, sp, x1" },
    .{ .pc = 0x1e4, .word = 0x8b224820, .mnemonic = "add", .operands = "x0, x1, w2, uxtw #2" },
    .{ .pc = 0x1e8, .word = 0xcb24e3e3, .mnemonic = "sub", .operands = "x3, sp, x4, sxtx" },
    .{ .pc = 0x1ec, .word = 0xeb2563ff, .mnemonic = "cmp", .operands = "sp, x5" },
    .{ .pc = 0x1f0, .word = 0x8b28a0e6, .mnemonic = "add", .operands = "x6, x7, w8, sxth" },
    .{ .pc = 0x1f4, .word = 0x9a820020, .mnemonic = "csel", .operands = "x0, x1, x2, eq" },
    .{ .pc = 0x1f8, .word = 0x1a851483, .mnemonic = "csinc", .operands = "w3, w4, w5, ne" },
    .{ .pc = 0x1fc, .word = 0xda88b0e6, .mnemonic = "csinv", .operands = "x6, x7, x8, lt" },
    .{ .pc = 0x200, .word = 0xda8bc549, .mnemonic = "csneg", .operands = "x9, x10, x11, gt" },
    .{ .pc = 0x204, .word = 0x1a9f17e0, .mnemonic = "cset", .operands = "w0, eq" },
    .{ .pc = 0x208, .word = 0xda9f03e1, .mnemonic = "csetm", .operands = "x1, ne" },
    .{ .pc = 0x20c, .word = 0x9a83a462, .mnemonic = "cinc", .operands = "x2, x3, lt" },
    .{ .pc = 0x210, .word = 0x5a85b0a4, .mnemonic = "cinv", .operands = "w4, w5, ge" },
    .{ .pc = 0x214, .word = 0xda87c4e6, .mnemonic = "cneg", .operands = "x6, x7, le" },
    .{ .pc = 0x218, .word = 0x9b020c20, .mnemonic = "madd", .operands = "x0, x1, x2, x3" },
    .{ .pc = 0x21c, .word = 0x1b069ca4, .mnemonic = "msub", .operands = "w4, w5, w6, w7" },
    .{ .pc = 0x220, .word = 0x9b3045ee, .mnemonic = "smaddl", .operands = "x14, w15, w16, x17" },
    .{ .pc = 0x224, .word = 0x9bb45672, .mnemonic = "umaddl", .operands = "x18, w19, w20, x21" },
    .{ .pc = 0x228, .word = 0x9b427c20, .mnemonic = "smulh", .operands = "x0, x1, x2" },
    .{ .pc = 0x22c, .word = 0x9bc57c83, .mnemonic = "umulh", .operands = "x3, x4, x5" },
    .{ .pc = 0x230, .word = 0x9b0a7d28, .mnemonic = "mul", .operands = "x8, x9, x10" },
    .{ .pc = 0x234, .word = 0x9b0dfd8b, .mnemonic = "mneg", .operands = "x11, x12, x13" },
    .{ .pc = 0x238, .word = 0x9b387ef6, .mnemonic = "smull", .operands = "x22, w23, w24" },
    .{ .pc = 0x23c, .word = 0x9bbb7f59, .mnemonic = "umull", .operands = "x25, w26, w27" },
    .{ .pc = 0x240, .word = 0x9ac20820, .mnemonic = "udiv", .operands = "x0, x1, x2" },
    .{ .pc = 0x244, .word = 0x1ac50c83, .mnemonic = "sdiv", .operands = "w3, w4, w5" },
    .{ .pc = 0x248, .word = 0x9ac820e6, .mnemonic = "lsl", .operands = "x6, x7, x8" },
    .{ .pc = 0x24c, .word = 0x1acb2549, .mnemonic = "lsr", .operands = "w9, w10, w11" },
    .{ .pc = 0x250, .word = 0x9ace29ac, .mnemonic = "asr", .operands = "x12, x13, x14" },
    .{ .pc = 0x254, .word = 0x9ad12e0f, .mnemonic = "ror", .operands = "x15, x16, x17" },
    .{ .pc = 0x258, .word = 0x9ac23020, .mnemonic = "pacga", .operands = "x0, x1, x2" },
    .{ .pc = 0x25c, .word = 0xdac00020, .mnemonic = "rbit", .operands = "x0, x1" },
    .{ .pc = 0x260, .word = 0x5ac00862, .mnemonic = "rev", .operands = "w2, w3" },
    .{ .pc = 0x264, .word = 0xdac004a4, .mnemonic = "rev16", .operands = "x4, x5" },
    .{ .pc = 0x268, .word = 0xdac008e6, .mnemonic = "rev32", .operands = "x6, x7" },
    .{ .pc = 0x26c, .word = 0xdac00d28, .mnemonic = "rev", .operands = "x8, x9" },
    .{ .pc = 0x270, .word = 0xdac0116a, .mnemonic = "clz", .operands = "x10, x11" },
    .{ .pc = 0x274, .word = 0x5ac015ac, .mnemonic = "cls", .operands = "w12, w13" },
    .{ .pc = 0x278, .word = 0xdac10020, .mnemonic = "pacia", .operands = "x0, x1" },
    .{ .pc = 0x27c, .word = 0xdac10462, .mnemonic = "pacib", .operands = "x2, x3" },
    .{ .pc = 0x280, .word = 0xdac108a4, .mnemonic = "pacda", .operands = "x4, x5" },
    .{ .pc = 0x284, .word = 0xdac10ce6, .mnemonic = "pacdb", .operands = "x6, x7" },
    .{ .pc = 0x288, .word = 0xdac11128, .mnemonic = "autia", .operands = "x8, x9" },
    .{ .pc = 0x28c, .word = 0xdac1156a, .mnemonic = "autib", .operands = "x10, x11" },
    .{ .pc = 0x290, .word = 0xdac119ac, .mnemonic = "autda", .operands = "x12, x13" },
    .{ .pc = 0x294, .word = 0xdac11dee, .mnemonic = "autdb", .operands = "x14, x15" },
    .{ .pc = 0x298, .word = 0xdac123f0, .mnemonic = "paciza", .operands = "x16" },
    .{ .pc = 0x29c, .word = 0xdac127f1, .mnemonic = "pacizb", .operands = "x17" },
    .{ .pc = 0x2a0, .word = 0xdac133f2, .mnemonic = "autiza", .operands = "x18" },
    .{ .pc = 0x2a4, .word = 0xdac137f3, .mnemonic = "autizb", .operands = "x19" },
    .{ .pc = 0x2a8, .word = 0xdac143f4, .mnemonic = "xpaci", .operands = "x20" },
    .{ .pc = 0x2ac, .word = 0xdac147f5, .mnemonic = "xpacd", .operands = "x21" },
    .{ .pc = 0x2b0, .word = 0x58000000, .mnemonic = "ldr", .operands = "x0, 0x2b0" },
    .{ .pc = 0x2b4, .word = 0x18000001, .mnemonic = "ldr", .operands = "w1, 0x2b4" },
    .{ .pc = 0x2b8, .word = 0x1c000002, .mnemonic = "ldr", .operands = "s2, 0x2b8" },
    .{ .pc = 0x2bc, .word = 0x5c000003, .mnemonic = "ldr", .operands = "d3, 0x2bc" },
    .{ .pc = 0x2c0, .word = 0x9c000004, .mnemonic = "ldr", .operands = "q4, 0x2c0" },
    .{ .pc = 0x2c4, .word = 0x98000005, .mnemonic = "ldrsw", .operands = "x5, 0x2c4" },
    .{ .pc = 0x2c8, .word = 0xd8000000, .mnemonic = "prfm", .operands = "pldl1keep, 0x2c8" },
    .{ .pc = 0x2cc, .word = 0xa9417bfd, .mnemonic = "ldp", .operands = "x29, x30, [sp, #0x10]" },
    .{ .pc = 0x2d0, .word = 0xa9400440, .mnemonic = "ldp", .operands = "x0, x1, [x2]" },
    .{ .pc = 0x2d4, .word = 0xa9bf7bfd, .mnemonic = "stp", .operands = "x29, x30, [sp, #-0x10]!" },
    .{ .pc = 0x2d8, .word = 0xa8c253f3, .mnemonic = "ldp", .operands = "x19, x20, [sp], #0x20" },
    .{ .pc = 0x2dc, .word = 0x29010440, .mnemonic = "stp", .operands = "w0, w1, [x2, #0x8]" },
    .{ .pc = 0x2e0, .word = 0x2d400440, .mnemonic = "ldp", .operands = "s0, s1, [x2]" },
    .{ .pc = 0x2e4, .word = 0x6d410c82, .mnemonic = "ldp", .operands = "d2, d3, [x4, #0x10]" },
    .{ .pc = 0x2e8, .word = 0xad0114c4, .mnemonic = "stp", .operands = "q4, q5, [x6, #0x20]" },
    .{ .pc = 0x2ec, .word = 0x69410440, .mnemonic = "ldpsw", .operands = "x0, x1, [x2, #0x8]" },
    .{ .pc = 0x2f0, .word = 0xf9403020, .mnemonic = "ldr", .operands = "x0, [x1, #0x60]" },
    .{ .pc = 0x2f4, .word = 0xb9401062, .mnemonic = "ldr", .operands = "w2, [x3, #0x10]" },
    .{ .pc = 0x2f8, .word = 0x39400ca4, .mnemonic = "ldrb", .operands = "w4, [x5, #0x3]" },
    .{ .pc = 0x2fc, .word = 0x79400ce6, .mnemonic = "ldrh", .operands = "w6, [x7, #0x6]" },
    .{ .pc = 0x300, .word = 0x39c00528, .mnemonic = "ldrsb", .operands = "w8, [x9, #0x1]" },
    .{ .pc = 0x304, .word = 0x39800528, .mnemonic = "ldrsb", .operands = "x8, [x9, #0x1]" },
    .{ .pc = 0x308, .word = 0x79c0056a, .mnemonic = "ldrsh", .operands = "w10, [x11, #0x2]" },
    .{ .pc = 0x30c, .word = 0x7980056a, .mnemonic = "ldrsh", .operands = "x10, [x11, #0x2]" },
    .{ .pc = 0x310, .word = 0xb98005ac, .mnemonic = "ldrsw", .operands = "x12, [x13, #0x4]" },
    .{ .pc = 0x314, .word = 0xf90005ee, .mnemonic = "str", .operands = "x14, [x15, #0x8]" },
    .{ .pc = 0x318, .word = 0xb9000630, .mnemonic = "str", .operands = "w16, [x17, #0x4]" },
    .{ .pc = 0x31c, .word = 0x39000672, .mnemonic = "strb", .operands = "w18, [x19, #0x1]" },
    .{ .pc = 0x320, .word = 0x790006b4, .mnemonic = "strh", .operands = "w20, [x21, #0x2]" },
    .{ .pc = 0x324, .word = 0xf9800400, .mnemonic = "prfm", .operands = "pldl1keep, [x0, #0x8]" },
    .{ .pc = 0x328, .word = 0xf9800031, .mnemonic = "prfm", .operands = "pstl1strm, [x1]" },
    .{ .pc = 0x32c, .word = 0x3d400020, .mnemonic = "ldr", .operands = "b0, [x1]" },
    .{ .pc = 0x330, .word = 0x7d400441, .mnemonic = "ldr", .operands = "h1, [x2, #0x2]" },
    .{ .pc = 0x334, .word = 0xbd400462, .mnemonic = "ldr", .operands = "s2, [x3, #0x4]" },
    .{ .pc = 0x338, .word = 0xfd400483, .mnemonic = "ldr", .operands = "d3, [x4, #0x8]" },
    .{ .pc = 0x33c, .word = 0x3dc004a4, .mnemonic = "ldr", .operands = "q4, [x5, #0x10]" },
    .{ .pc = 0x340, .word = 0xf81f0fe0, .mnemonic = "str", .operands = "x0, [sp, #-0x10]!" },
    .{ .pc = 0x344, .word = 0xf84107e1, .mnemonic = "ldr", .operands = "x1, [sp], #0x10" },
    .{ .pc = 0x348, .word = 0xb81fcc62, .mnemonic = "str", .operands = "w2, [x3, #-0x4]!" },
    .{ .pc = 0x34c, .word = 0xf85f8020, .mnemonic = "ldur", .operands = "x0, [x1, #-0x8]" },
    .{ .pc = 0x350, .word = 0xb81fc062, .mnemonic = "stur", .operands = "w2, [x3, #-0x4]" },
    .{ .pc = 0x354, .word = 0x384010a4, .mnemonic = "ldurb", .operands = "w4, [x5, #0x1]" },
    .{ .pc = 0x358, .word = 0xb89fc0e6, .mnemonic = "ldursw", .operands = "x6, [x7, #-0x4]" },
    .{ .pc = 0x35c, .word = 0xfc1f8cc5, .mnemonic = "str", .operands = "d5, [x6, #-0x8]!" },
    .{ .pc = 0x360, .word = 0x3c9f0fe0, .mnemonic = "str", .operands = "q0, [sp, #-0x10]!" },
    .{ .pc = 0x364, .word = 0x3cc107e1, .mnemonic = "ldr", .operands = "q1, [sp], #0x10" },
    .{ .pc = 0x368, .word = 0xf8200420, .mnemonic = "ldraa", .operands = "x0, [x1]" },
    .{ .pc = 0x36c, .word = 0xf8201c20, .mnemonic = "ldraa", .operands = "x0, [x1, #0x8]!" },
    .{ .pc = 0x370, .word = 0xf8ffe462, .mnemonic = "ldrab", .operands = "x2, [x3, #-0x10]" },
    .{ .pc = 0x374, .word = 0xf86668a4, .mnemonic = "ldr", .operands = "x4, [x5, x6]" },
    .{ .pc = 0x378, .word = 0xf86678a4, .mnemonic = "ldr", .operands = "x4, [x5, x6, lsl #3]" },
    .{ .pc = 0x37c, .word = 0xb8695907, .mnemonic = "ldr", .operands = "w7, [x8, w9, uxtw #2]" },
    .{ .pc = 0x380, .word = 0xf86cc96a, .mnemonic = "ldr", .operands = "x10, [x11, w12, sxtw]" },
    .{ .pc = 0x384, .word = 0x386f69cd, .mnemonic = "ldrb", .operands = "w13, [x14, x15]" },
    .{ .pc = 0x388, .word = 0xf832fa30, .mnemonic = "str", .operands = "x16, [x17, x18, sxtx #3]" },
    .{ .pc = 0x38c, .word = 0x3ca868e6, .mnemonic = "str", .operands = "q6, [x7, x8]" },
    .{ .pc = 0x390, .word = 0xc85f7c20, .mnemonic = "ldxr", .operands = "x0, [x1]" },
    .{ .pc = 0x394, .word = 0x885f7c20, .mnemonic = "ldxr", .operands = "w0, [x1]" },
    .{ .pc = 0x398, .word = 0xc8027c83, .mnemonic = "stxr", .operands = "w2, x3, [x4]" },
    .{ .pc = 0x39c, .word = 0xc85ffcc5, .mnemonic = "ldaxr", .operands = "x5, [x6]" },
    .{ .pc = 0x3a0, .word = 0x8807fd28, .mnemonic = "stlxr", .operands = "w7, w8, [x9]" },
    .{ .pc = 0x3a4, .word = 0xc8dffd6a, .mnemonic = "ldar", .operands = "x10, [x11]" },
    .{ .pc = 0x3a8, .word = 0xc89ffdac, .mnemonic = "stlr", .operands = "x12, [x13]" },
    .{ .pc = 0x3ac, .word = 0x08dffdee, .mnemonic = "ldarb", .operands = "w14, [x15]" },
    .{ .pc = 0x3b0, .word = 0x089ffe30, .mnemonic = "stlrb", .operands = "w16, [x17]" },
    .{ .pc = 0x3b4, .word = 0xc8a07c41, .mnemonic = "cas", .operands = "x0, x1, [x2]" },
    .{ .pc = 0x3b8, .word = 0x88e37ca4, .mnemonic = "casa", .operands = "w3, w4, [x5]" },
    .{ .pc = 0x3bc, .word = 0xc8e6fd07, .mnemonic = "casal", .operands = "x6, x7, [x8]" },
    .{ .pc = 0x3c0, .word = 0xf8200041, .mnemonic = "ldadd", .operands = "x0, x1, [x2]" },
    .{ .pc = 0x3c4, .word = 0xb8a300a4, .mnemonic = "ldadda", .operands = "w3, w4, [x5]" },
    .{ .pc = 0x3c8, .word = 0xf8e60107, .mnemonic = "ldaddal", .operands = "x6, x7, [x8]" },
    .{ .pc = 0x3cc, .word = 0xf829816a, .mnemonic = "swp", .operands = "x9, x10, [x11]" },
    .{ .pc = 0x3d0, .word = 0xf82c31cd, .mnemonic = "ldset", .operands = "x12, x13, [x14]" },
    .{ .pc = 0x3d4, .word = 0xf82f1230, .mnemonic = "ldclr", .operands = "x15, x16, [x17]" },
    .{ .pc = 0x3d8, .word = 0x9e670020, .mnemonic = "fmov", .operands = "d0, x1" },
    .{ .pc = 0x3dc, .word = 0x9e660062, .mnemonic = "fmov", .operands = "x2, d3" },
    .{ .pc = 0x3e0, .word = 0x1e2700a4, .mnemonic = "fmov", .operands = "s4, w5" },
    .{ .pc = 0x3e4, .word = 0x1e2600e6, .mnemonic = "fmov", .operands = "w6, s7" },
    .{ .pc = 0x3e8, .word = 0x9e620020, .mnemonic = "scvtf", .operands = "d0, x1" },
    .{ .pc = 0x3ec, .word = 0x1e220062, .mnemonic = "scvtf", .operands = "s2, w3" },
    .{ .pc = 0x3f0, .word = 0x9e6300a4, .mnemonic = "ucvtf", .operands = "d4, x5" },
    .{ .pc = 0x3f4, .word = 0x1e2300e6, .mnemonic = "ucvtf", .operands = "s6, w7" },
    .{ .pc = 0x3f8, .word = 0x1e780020, .mnemonic = "fcvtzs", .operands = "w0, d1" },
    .{ .pc = 0x3fc, .word = 0x9e380062, .mnemonic = "fcvtzs", .operands = "x2, s3" },
    .{ .pc = 0x400, .word = 0x1e7900a4, .mnemonic = "fcvtzu", .operands = "w4, d5" },
    .{ .pc = 0x404, .word = 0x9e7000e6, .mnemonic = "fcvtms", .operands = "x6, d7" },
    .{ .pc = 0x408, .word = 0x1e280128, .mnemonic = "fcvtps", .operands = "w8, s9" },
    .{ .pc = 0x40c, .word = 0x1e604128, .mnemonic = "fmov", .operands = "d8, d9" },
    .{ .pc = 0x410, .word = 0x1e20c062, .mnemonic = "fabs", .operands = "s2, s3" },
    .{ .pc = 0x414, .word = 0x1e614020, .mnemonic = "fneg", .operands = "d0, d1" },
    .{ .pc = 0x418, .word = 0x1e61c0a4, .mnemonic = "fsqrt", .operands = "d4, d5" },
    .{ .pc = 0x41c, .word = 0x1e22c020, .mnemonic = "fcvt", .operands = "d0, s1" },
    .{ .pc = 0x420, .word = 0x1e624062, .mnemonic = "fcvt", .operands = "s2, d3" },
    .{ .pc = 0x424, .word = 0x1e23c0a4, .mnemonic = "fcvt", .operands = "h4, s5" },
    .{ .pc = 0x428, .word = 0x1e622820, .mnemonic = "fadd", .operands = "d0, d1, d2" },
    .{ .pc = 0x42c, .word = 0x1e253883, .mnemonic = "fsub", .operands = "s3, s4, s5" },
    .{ .pc = 0x430, .word = 0x1e6808e6, .mnemonic = "fmul", .operands = "d6, d7, d8" },
    .{ .pc = 0x434, .word = 0x1e2b1949, .mnemonic = "fdiv", .operands = "s9, s10, s11" },
    .{ .pc = 0x438, .word = 0x1e612000, .mnemonic = "fcmp", .operands = "d0, d1" },
    .{ .pc = 0x43c, .word = 0x1e202048, .mnemonic = "fcmp", .operands = "s2, #0.0" },
    .{ .pc = 0x440, .word = 0x1e642070, .mnemonic = "fcmpe", .operands = "d3, d4" },
    .{ .pc = 0x444, .word = 0x1e6e100c, .mnemonic = "fmov", .operands = "d12, #1.00000000" },
    .{ .pc = 0x448, .word = 0x1e2c100d, .mnemonic = "fmov", .operands = "s13, #0.50000000" },
    .{ .pc = 0x44c, .word = 0x1f420c20, .mnemonic = "fmadd", .operands = "d0, d1, d2, d3" },
    .{ .pc = 0x450, .word = 0x1f069ca4, .mnemonic = "fmsub", .operands = "s4, s5, s6, s7" },
    .{ .pc = 0x454, .word = 0x1e620c20, .mnemonic = "fcsel", .operands = "d0, d1, d2, eq" },
    .{ .pc = 0x458, .word = 0x6f00e400, .mnemonic = "movi", .operands = "v0.2d, #0000000000000000" },
    .{ .pc = 0x45c, .word = 0x4f07e7e1, .mnemonic = "movi", .operands = "v1.16b, #0xff" },
    .{ .pc = 0x460, .word = 0x4f000422, .mnemonic = "movi", .operands = "v2.4s, #0x1" },
    .{ .pc = 0x464, .word = 0x2f00e403, .mnemonic = "movi", .operands = "d3, #0000000000000000" },
    .{ .pc = 0x468, .word = 0x4e040c20, .mnemonic = "dup", .operands = "v0.4s, w1" },
    .{ .pc = 0x46c, .word = 0x4e080c62, .mnemonic = "dup", .operands = "v2.2d, x3" },
    .{ .pc = 0x470, .word = 0x4e010ca4, .mnemonic = "dup", .operands = "v4.16b, w5" },
    .{ .pc = 0x474, .word = 0x4e181c20, .mnemonic = "mov", .operands = "v0.d[1], x1" },
    .{ .pc = 0x478, .word = 0x4e041c62, .mnemonic = "mov", .operands = "v2.s[0], w3" },
    .{ .pc = 0x47c, .word = 0x0e0c3c20, .mnemonic = "mov", .operands = "w0, v1.s[1]" },
    .{ .pc = 0x480, .word = 0x4e183c62, .mnemonic = "mov", .operands = "x2, v3.d[1]" },
    .{ .pc = 0x484, .word = 0x0e073ca4, .mnemonic = "umov", .operands = "w4, v5.b[3]" },
    .{ .pc = 0x488, .word = 0x0e0a2ce6, .mnemonic = "smov", .operands = "w6, v7.h[2]" },
    // FEAT_JSCVT. Encodings and spelling from `otool -tV` over assembled `fjcvtzs w0, d1` / `w5, d7`.
    .{ .pc = 0x48c, .word = 0x1e7e0020, .mnemonic = "fjcvtzs", .operands = "w0, d1" },
    .{ .pc = 0x490, .word = 0x1e7e00e5, .mnemonic = "fjcvtzs", .operands = "w5, d7" },
};

test "arm64: every verified disasm-notes Part B encoding decodes to the otool text" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failures: usize = 0;
    for (table) |row| {
        const got = try decodeOne(arena, row.word, row.pc, .arm);
        if (!std.mem.eql(u8, got.mnemonic, row.mnemonic) or !std.mem.eql(u8, got.operands, row.operands)) {
            std.debug.print("0x{x:0>8} @ 0x{x}: expected `{s} {s}` got `{s} {s}`\n", .{ row.word, row.pc, row.mnemonic, row.operands, got.mnemonic, got.operands });
            failures += 1;
        }
        try std.testing.expectEqual(@as(u8, 4), got.size);
        // The semantic-only path must agree on everything but the text.
        const sem = decodeSemantic(row.word, row.pc);
        try std.testing.expectEqual(got.kind, sem.kind);
        try std.testing.expectEqual(got.target, sem.target);
        try std.testing.expectEqual(got.imm, sem.imm);
        try std.testing.expectEqual(got.reg_write, sem.reg_write);
        try std.testing.expectEqual(got.reg_writes, sem.reg_writes);
        // `reg_write` must always be a member of `reg_writes`, or a consumer that invalidates the set
        // would miss the primary destination.
        if (got.reg_write) |r| try std.testing.expect(got.writesReg(r));
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    try std.testing.expect(table.len >= 291);
}

test "arm64: reg_writes reports EVERY register written, not just the destination" {
    // Every encoding below is `otool -tV` ground truth from an assembled .s (see disasm-notes B.6).
    const W = struct {
        fn of(regs: []const u5) u32 {
            var m: u32 = 0;
            for (regs) |r| m |= @as(u32, 1) << r;
            return m;
        }
    };
    // ldp x21, x8, [x20, #0x20] — the fabricated `_CVAFaceTrackingCreate` attribution at
    // /usr/libexec/relatived:0x100002f40 came from x8 being left believed after exactly this word.
    try std.testing.expectEqual(W.of(&.{ 21, 8 }), decodeSemantic(0xa9422295, 0).reg_writes);
    // ldp x29, x30, [sp], #0x10 — post-index also writes the base (SP = bit 31).
    try std.testing.expectEqual(W.of(&.{ 29, 30, 31 }), decodeSemantic(0xa8c17bfd, 0).reg_writes);
    // stp x29, x30, [sp, #-0x10]! — a STORE writes nothing but the written-back base.
    try std.testing.expectEqual(W.of(&.{31}), decodeSemantic(0xa9bf7bfd, 0).reg_writes);
    // ldr x9, [x8, #0x10]! / ldr x9, [x8], #0x10 — Rt AND the base Rn.
    try std.testing.expectEqual(W.of(&.{ 9, 8 }), decodeSemantic(0xf8410d09, 0).reg_writes);
    try std.testing.expectEqual(W.of(&.{ 9, 8 }), decodeSemantic(0xf8410509, 0).reg_writes);
    // ldxp x0, x1, [x2] — the exclusive PAIR load writes both transfer registers.
    try std.testing.expectEqual(W.of(&.{ 0, 1 }), decodeSemantic(0xc87f0440, 0).reg_writes);
    // stxp w3, x4, x5, [x6] / stxr w2, x3, [x4] — the status register Rs is a write.
    try std.testing.expectEqual(W.of(&.{3}), decodeSemantic(0xc82314c4, 0).reg_writes);
    try std.testing.expectEqual(W.of(&.{2}), decodeSemantic(0xc8027c83, 0).reg_writes);
    // casp x0, x1, x2, x3, [x4] — Rs and Rs+1 both receive the old memory contents.
    try std.testing.expectEqual(W.of(&.{ 0, 1 }), decodeSemantic(0x48207c82, 0).reg_writes);
    // cas x0, x1, [x2] — Rs receives the old value.
    try std.testing.expectEqual(W.of(&.{0}), decodeSemantic(0xc8a07c41, 0).reg_writes);
    // ldraa x1, [x2, #0x8]! — PAC load with writeback.
    try std.testing.expectEqual(W.of(&.{ 1, 2 }), decodeSemantic(0xf8201c41, 0).reg_writes);
    // adrp xzr, 0 — Rd == 31 is XZR here, so the page is DISCARDED and nothing is written. Reporting
    // it wrote "register 31" made the symbolizer confuse the destination with SP.
    const azr = decodeSemantic(0x9000001f, 0);
    try std.testing.expectEqual(@as(u32, 0), azr.reg_writes);
    try std.testing.expectEqual(@as(?u5, null), azr.reg_write);
    // ... while `adrp x8, 0` still reports x8.
    try std.testing.expectEqual(W.of(&.{8}), decodeSemantic(0x90000008, 0).reg_writes);
    // A word the decoder cannot name, and every unconditional transfer, must end register tracking.
    try std.testing.expect(decodeSemantic(0x00000000, 0).endsTracking()); // .inst / invalid
    try std.testing.expect(decodeSemantic(0x14000001, 0).endsTracking()); // b
    try std.testing.expect(decodeSemantic(0xd65f03c0, 0).endsTracking()); // ret
    try std.testing.expect(decodeSemantic(0xd61f0100, 0).endsTracking()); // br x8
    try std.testing.expect(!decodeSemantic(0x97ffffce, 0).endsTracking()); // bl returns
    try std.testing.expect(!decodeSemantic(0x5400006d, 0).endsTracking()); // b.le falls through
}

test "arm64: DecodeBitMasks reproduces the six corpus values and rejects the reserved encoding" {
    try std.testing.expectEqual(@as(?u64, 0xff), decodeBitMasks(1, 7, 0, 64));
    try std.testing.expectEqual(@as(?u64, 1), decodeBitMasks(0, 0, 0, 32));
    try std.testing.expectEqual(@as(?u64, 0xffff0000ffff0000), decodeBitMasks(0, 15, 16, 64));
    try std.testing.expectEqual(@as(?u64, 0xf0), decodeBitMasks(1, 3, 60, 64));
    try std.testing.expectEqual(@as(?u64, 0x80000000), decodeBitMasks(0, 0, 1, 32));
    try std.testing.expectEqual(@as(?u64, 0x5555555555555555), decodeBitMasks(0, 0x3c, 0, 64));
    try std.testing.expectEqual(@as(?u64, null), decodeBitMasks(0, 0b111111, 0, 64)); // reserved
    try std.testing.expectEqual(@as(?u64, null), decodeBitMasks(1, 7, 0, 32)); // esize > datasize
    try std.testing.expectEqual(@as(?u64, null), decodeBitMasks(0, 0, 0, 16)); // bad datasize
}

test "arm64: semantic fields for the kinds the engine and symbolizer rely on" {
    // b 0x10000468c @ 0x100000708
    var i = decodeSemantic(0x14000fe1, 0x100000708);
    try std.testing.expectEqual(insn.Kind.branch, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x10000468c), i.target);
    // bl 0x1000004f8 @ 0x1000005c0
    i = decodeSemantic(0x97ffffce, 0x1000005c0);
    try std.testing.expectEqual(insn.Kind.call, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x1000004f8), i.target);
    try std.testing.expectEqual(@as(?u5, 30), i.reg_write);
    // b.le 0x10000073c @ 0x100000730
    i = decodeSemantic(0x5400006d, 0x100000730);
    try std.testing.expectEqual(insn.Kind.cond_branch, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x10000073c), i.target);
    // cbnz w0, 0x1000005c8 @ 0x1000005b0
    i = decodeSemantic(0x350000c0, 0x1000005b0);
    try std.testing.expectEqual(insn.Kind.cond_branch, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x1000005c8), i.target);
    // tbz x2, #40, +0x10
    i = decodeSemantic(0xb6400082, 0x100000000);
    try std.testing.expectEqual(insn.Kind.cond_branch, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x100000010), i.target);
    // adrp x8, 4 @ 0x100000530 -> page 0x100004000
    i = decodeSemantic(0x90000028, 0x100000530);
    try std.testing.expectEqual(insn.Kind.adrp, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x100004000), i.imm);
    try std.testing.expectEqual(@as(?u5, 8), i.reg_write);
    try std.testing.expectEqual(@as(?u64, null), i.target);
    // adr x0, #-4 @ 0x100000100
    i = decodeSemantic(0x10ffffe0, 0x100000100);
    try std.testing.expectEqual(insn.Kind.adr, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x1000000fc), i.imm);
    // add x8, x8, #0x2c
    i = decodeSemantic(0x9100b108, 0x100000760);
    try std.testing.expectEqual(insn.Kind.add_imm, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x2c), i.imm);
    try std.testing.expectEqual(@as(?u5, 8), i.reg_write);
    // ldr x8, [x8, #0x10]
    i = decodeSemantic(0xf9400908, 0x100000534);
    try std.testing.expectEqual(insn.Kind.ldr_imm, i.kind);
    try std.testing.expectEqual(@as(i64, 0x10), i.mem_ref.?.offset);
    try std.testing.expectEqual(@as(u5, 8), i.mem_ref.?.base);
    try std.testing.expectEqual(@as(u8, 8), i.mem_ref.?.size);
    // ldr x0, <literal> @ 0x100000000
    i = decodeSemantic(0x58000040, 0x100000000);
    try std.testing.expectEqual(insn.Kind.ldr_literal, i.kind);
    try std.testing.expectEqual(@as(?u64, 0x100000008), i.target);
    // mov w0, #0x1
    i = decodeSemantic(0x52800020, 0x100000734);
    try std.testing.expectEqual(insn.Kind.mov_imm, i.kind);
    try std.testing.expectEqual(@as(?u64, 1), i.imm);
    // str x10, [x9]
    i = decodeSemantic(0xf900012a, 0x100000560);
    try std.testing.expectEqual(insn.Kind.str_imm, i.kind);
    // ret / br / blr / pacibsp / retab / brk / nop
    try std.testing.expectEqual(insn.Kind.ret, decodeSemantic(0xd65f03c0, 0).kind);
    try std.testing.expectEqual(insn.Kind.indirect_branch, decodeSemantic(0xd61f0200, 0).kind);
    try std.testing.expectEqual(insn.Kind.indirect_call, decodeSemantic(0xd63f0200, 0).kind);
    try std.testing.expectEqual(insn.Kind.pac_prologue, decodeSemantic(0xd503237f, 0).kind);
    try std.testing.expectEqual(insn.Kind.pac_epilogue, decodeSemantic(0xd50323ff, 0).kind);
    try std.testing.expectEqual(insn.Kind.ret, decodeSemantic(0xd65f0fff, 0).kind);
    try std.testing.expectEqual(insn.Kind.trap, decodeSemantic(0xd4200020, 0).kind);
    try std.testing.expectEqual(insn.Kind.nop, decodeSemantic(0xd503201f, 0).kind);
    try std.testing.expectEqual(insn.Kind.bti, decodeSemantic(0xd503245f, 0).kind);
    try std.testing.expectEqual(insn.Kind.trap, decodeSemantic(0x00000000, 0).kind);
}

test "arm64: unallocated words are .inst, never skipped, and always 4 bytes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bad = [_]u32{ 0xffffffff, 0x20000000, 0x12007c00, 0x04000000, 0x00100000 };
    for (bad) |w| {
        const i = try decodeOne(arena, w, 0x1000, .arm);
        try std.testing.expectEqualStrings(".inst", i.mnemonic);
        try std.testing.expectEqual(insn.Kind.invalid, i.kind);
        try std.testing.expect(!i.valid);
        try std.testing.expectEqual(@as(u8, 4), i.size);
        try std.testing.expect(std.mem.startsWith(u8, i.operands, "0x"));
        try std.testing.expectEqual(@as(usize, 10), i.operands.len);
    }
}

test "arm64: the stub shapes of disasm-notes D.2 decode to the fields the symbolizer folds" {
    // arm64e __auth_stubs: adrp x17, page ; add x17, x17, #off ; ldr x16, [x17] ; braa x16, x17
    const stub = [_]u32{ 0x90000051, 0x910a2231, 0xf9400230, 0xd71f0a11 };
    const base: u64 = 0x1000042ac;
    const a = decodeSemantic(stub[0], base);
    try std.testing.expectEqual(insn.Kind.adrp, a.kind);
    try std.testing.expectEqual(@as(?u5, 17), a.reg_write);
    const b = decodeSemantic(stub[1], base + 4);
    try std.testing.expectEqual(insn.Kind.add_imm, b.kind);
    try std.testing.expectEqual(@as(?u64, 0x288), b.imm);
    const c = decodeSemantic(stub[2], base + 8);
    try std.testing.expectEqual(insn.Kind.ldr_imm, c.kind);
    try std.testing.expectEqual(@as(u5, 17), c.mem_ref.?.base);
    try std.testing.expectEqual(@as(i64, 0), c.mem_ref.?.offset);
    const e = decodeSemantic(stub[3], base + 12);
    try std.testing.expectEqual(insn.Kind.indirect_branch, e.kind);
}

test "arm64: every 4-byte window of a real prologue decodes and text is bounded" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var w: u32 = 0;
    var i: u32 = 0;
    // Deterministic sweep of structurally interesting words: every top-level class with random payloads.
    var prng = std.Random.DefaultPrng.init(0x61726d36_34000001);
    const random = prng.random();
    while (i < 20_000) : (i += 1) {
        w = random.int(u32);
        const one = try decodeOne(arena, w, 0x100000000 + @as(u64, i) * 4, .arm);
        try std.testing.expectEqual(@as(u8, 4), one.size);
        try std.testing.expect(one.mnemonic.len > 0);
        try std.testing.expect(one.operands.len <= ops_cap);
        _ = arena_state.reset(.retain_capacity);
    }
}
