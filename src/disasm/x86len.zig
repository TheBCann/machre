//! disasm/x86len.zig — built-in x86_64 length decoder + kind/target recognizer (disasm-notes Part C). Imports: disasm/insn.
//!
//! The decoder answers two questions and no more: how long is the instruction at `bytes[0..]`, and is it
//! one of the control-flow / stack / move shapes the engine and the symbolizer care about. Anything else
//! is emitted as `db` with `partial = true` (DESIGN §4.24); the text is deliberately not otool-compatible
//! — `--backend=capstone` supplies real x86 text when Capstone is linked.
//!
//! The byte-level parse is reused for one more job: `otoolImmOperand` / `pshufComment` at the bottom of
//! this file normalise Capstone's AT&T text into otool's under `--otool-compat` (symbolize.zig calls
//! them). They need the encoding, not the printed text: only the instruction bytes say whether a set top
//! bit is a sign bit (`andl $-0x13`) or part of the value (`andl $0xffffff3f`).
//!
//! Length rules are Part C.1-C.3, validated against `otool -arch x86_64 -tv /bin/ls` (tests/facts/decoders.zig).
//! The decoder never returns 0 and never reads past `bytes`, so a linear sweep over attacker-controlled
//! bytes always terminates.
const std = @import("std");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");

const Kind = insn.Kind;
const Insn = insn.Insn;

/// x86-64 architectural maximum instruction length.
pub const max_len: u8 = 15;

const ops_cap = 96;

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

const reg64_names = [16][]const u8{
    "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
    "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
};
const cc_names = [16][]const u8{
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
};

const Dec = struct {
    len: u8 = 1,
    mnemonic: []const u8 = "db",
    ops: Buf = .{},
    kind: Kind = .other,
    target: ?u64 = null,
    reg_write: ?u5 = null,
    imm: ?u64 = null,
    mem_ref: ?insn.MemRef = null,
    valid: bool = true,
    partial: bool = true,
};

fn at(bytes: []const u8, i: usize) ?u8 {
    if (i >= bytes.len) return null;
    return bytes[i];
}

fn isLegacyPrefix(b: u8) bool {
    return switch (b) {
        0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65 => true,
        else => false,
    };
}

/// One-byte map: does the opcode carry a ModRM byte? (disasm-notes C.3)
fn oneByteHasModrm(op: u8) bool {
    if (op < 0x40) return (op & 7) < 4;
    return switch (op) {
        0x62, 0x63, 0x69, 0x6b => true,
        0x80...0x8f => true,
        0xc0, 0xc1, 0xc6, 0xc7 => true,
        0xd0...0xd3 => true,
        0xd8...0xdf => true,
        0xf6, 0xf7, 0xfe, 0xff => true,
        else => false,
    };
}

/// One-byte map immediate size in bytes; `iz` is 4, or 2 under a 0x66 operand-size prefix.
fn oneByteImm(op: u8, opsize16: bool, rex_w: bool, modrm_reg: u3) u8 {
    const iz: u8 = if (opsize16) 2 else 4;
    if (op < 0x40) {
        if ((op & 7) == 4) return 1;
        if ((op & 7) == 5) return iz;
        return 0;
    }
    return switch (op) {
        0x68, 0x69 => iz,
        0x6a, 0x6b => 1,
        0x70...0x7f => 1,
        0x80, 0x83 => 1,
        0x81 => iz,
        0xa0...0xa3 => 8, // moffs64
        0xa8 => 1,
        0xa9 => iz,
        0xb0...0xb7 => 1,
        0xb8...0xbf => if (rex_w) 8 else iz,
        0xc0, 0xc1 => 1,
        0xc2 => 2,
        0xc6 => 1,
        0xc7 => iz,
        0xc8 => 3, // iw + ib
        0xcd => 1,
        0xe0...0xe7 => 1,
        0xe8, 0xe9 => 4, // rel32, always 32-bit in 64-bit mode
        0xeb => 1,
        0xf6 => if (modrm_reg < 2) 1 else 0,
        0xf7 => if (modrm_reg < 2) iz else 0,
        else => 0,
    };
}

/// Two-byte map (0F xx): opcodes WITHOUT a ModRM byte (disasm-notes C.3).
fn twoByteNoModrm(op: u8) bool {
    return switch (op) {
        0x05...0x0e => true,
        0x30...0x35, 0x37 => true,
        0x77 => true,
        0x80...0x8f => true,
        0xa0, 0xa1, 0xa2, 0xa8, 0xa9, 0xaa => true,
        0xc8...0xcf => true,
        else => false,
    };
}
fn twoByteImm(op: u8, opsize16: bool) u8 {
    return switch (op) {
        0x80...0x8f => 4, // Jcc rel32
        0x70...0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6 => 1,
        else => {
            _ = opsize16;
            return 0;
        },
    };
}

const Parsed = struct {
    len: u8,
    /// 1 = one-byte map, 2 = 0F, 3 = 0F38, 4 = 0F3A.
    map: u3,
    opcode: u8,
    rex: u8,
    opsize16: bool,
    has_modrm: bool,
    modrm: u8,
    /// Offset of the immediate inside the instruction, when there is one.
    imm_off: u8,
    imm_size: u8,
    rip_relative: bool,
    disp32: i32,
    /// `FF /7` and friends: length 1, nothing else is known.
    undefined_opcode: bool,
};

fn parse(bytes: []const u8) Parsed {
    var out: Parsed = .{
        .len = 1,
        .map = 1,
        .opcode = 0,
        .rex = 0,
        .opsize16 = false,
        .has_modrm = false,
        .modrm = 0,
        .imm_off = 0,
        .imm_size = 0,
        .rip_relative = false,
        .disp32 = 0,
        .undefined_opcode = false,
    };
    if (bytes.len == 0) return out;

    var i: usize = 0;
    // 1. legacy prefixes (any order, repeats allowed)
    while (i < bytes.len and i < max_len and isLegacyPrefix(bytes[i])) : (i += 1) {
        if (bytes[i] == 0x66) out.opsize16 = true;
    }
    // 4. VEX / EVEX — payload length is fixed, then an opcode, then a ModRM.
    var vex_map: u3 = 0;
    var vex_imm8 = false;
    if (at(bytes, i)) |b0| {
        if (b0 == 0xc5) {
            i += 2;
            vex_map = 2;
        } else if (b0 == 0xc4) {
            const b1 = at(bytes, i + 1) orelse 0;
            vex_map = switch (b1 & 0x1f) {
                1 => 2,
                2 => 3,
                3 => 4,
                else => 2,
            };
            i += 3;
        } else if (b0 == 0x62) {
            const b1 = at(bytes, i + 1) orelse 0;
            vex_map = switch (b1 & 0x7) {
                1 => 2,
                2 => 3,
                3 => 4,
                else => 2,
            };
            i += 4;
        }
    }
    if (vex_map == 0) {
        // 2. REX (must be the last prefix before the opcode)
        if (at(bytes, i)) |b| {
            if (b >= 0x40 and b <= 0x4f) {
                out.rex = b;
                i += 1;
            }
        }
    }
    // 3. opcode (and the 2/3-byte escape maps)
    var op = at(bytes, i) orelse {
        out.len = clampLen(i, bytes.len);
        return out;
    };
    i += 1;
    var map: u3 = if (vex_map != 0) vex_map else 1;
    if (map == 1 and op == 0x0f) {
        const op2 = at(bytes, i) orelse {
            out.len = clampLen(i, bytes.len);
            return out;
        };
        i += 1;
        if (op2 == 0x38 or op2 == 0x3a) {
            map = if (op2 == 0x38) 3 else 4;
            op = at(bytes, i) orelse {
                out.len = clampLen(i, bytes.len);
                return out;
            };
            i += 1;
        } else {
            map = 2;
            op = op2;
        }
    }
    out.map = map;
    out.opcode = op;
    if (map == 4) vex_imm8 = true;

    const rex_w = (out.rex & 8) != 0;
    var has_modrm = switch (map) {
        1 => oneByteHasModrm(op),
        2 => !twoByteNoModrm(op),
        else => true, // 0F38 / 0F3A always carry a ModRM
    };
    if (vex_map != 0) has_modrm = true;

    var modrm_reg: u3 = 0;
    if (has_modrm) {
        const m = at(bytes, i) orelse {
            out.len = clampLen(i, bytes.len);
            return out;
        };
        out.has_modrm = true;
        out.modrm = m;
        modrm_reg = @truncate((m >> 3) & 7);
        i += 1;
        const mod: u2 = @truncate(m >> 6);
        const rm: u3 = @truncate(m & 7);
        // 5. `FF /7` is undefined: emit one byte so the sweep does not drift (disasm-notes C.1).
        if (map == 1 and op == 0xff and modrm_reg == 7) {
            out.undefined_opcode = true;
            out.len = 1;
            return out;
        }
        var disp: u8 = 0;
        if (mod != 3) {
            var sib_base: u3 = 0;
            var have_sib = false;
            if (rm == 4) {
                const sib = at(bytes, i) orelse {
                    out.len = clampLen(i, bytes.len);
                    return out;
                };
                have_sib = true;
                sib_base = @truncate(sib & 7);
                i += 1;
            }
            switch (mod) {
                0 => {
                    if (rm == 5) {
                        disp = 4;
                        out.rip_relative = true;
                    } else if (have_sib and sib_base == 5) {
                        disp = 4;
                    }
                },
                1 => disp = 1,
                2 => disp = 4,
                3 => {}, // excluded by the `mod != 3` guard above; never trap on input-shaped data
            }
        }
        if (disp == 4) {
            if (i + 4 <= bytes.len) out.disp32 = std.mem.readInt(i32, bytes[i..][0..4], .little);
        }
        i += disp;
    }

    var imm: u8 = switch (map) {
        1 => oneByteImm(op, out.opsize16, rex_w, modrm_reg),
        2 => twoByteImm(op, out.opsize16),
        3 => 0,
        else => 1, // 0F3A always has a trailing imm8
    };
    if (vex_imm8) imm = 1;
    out.imm_off = @intCast(@min(i, max_len));
    out.imm_size = imm;
    i += imm;
    out.len = clampLen(i, bytes.len);
    return out;
}

fn clampLen(want: usize, avail: usize) u8 {
    var n = want;
    if (n == 0) n = 1;
    if (n > max_len) n = max_len;
    if (avail != 0 and n > avail) n = avail;
    if (n == 0) n = 1;
    return @intCast(n);
}

/// Instruction length only (never 0; 1 for undefined opcodes like FF /7).
pub fn length(bytes: []const u8) u8 {
    return parse(bytes).len;
}

fn readImm(bytes: []const u8, off: u8, size: u8) ?i64 {
    const o: usize = off;
    if (o + size > bytes.len) return null;
    return switch (size) {
        1 => @as(i64, @as(i8, @bitCast(bytes[o]))),
        2 => @as(i64, std.mem.readInt(i16, bytes[o..][0..2], .little)),
        4 => @as(i64, std.mem.readInt(i32, bytes[o..][0..4], .little)),
        8 => std.mem.readInt(i64, bytes[o..][0..8], .little),
        else => null,
    };
}

fn decodeInner(bytes: []const u8, pc: u64) Dec {
    var d: Dec = .{};
    const p = parse(bytes);
    d.len = p.len;
    if (bytes.len == 0) {
        d.mnemonic = "db";
        d.valid = false;
        d.kind = .invalid;
        return d;
    }
    if (p.undefined_opcode) {
        dbText(&d, bytes[0..1]);
        return d;
    }
    const next: u64 = pc +% p.len;
    const rex_b: u8 = p.rex & 1;

    if (p.map == 1) {
        switch (p.opcode) {
            0xe8 => { // call rel32
                if (readImm(bytes, p.imm_off, 4)) |rel| {
                    d.mnemonic = "callq";
                    d.kind = .call;
                    d.target = next +% @as(u64, @bitCast(rel));
                    d.partial = false;
                    d.ops.print("0x{x}", .{d.target.?});
                    return d;
                }
            },
            0xe9, 0xeb => { // jmp rel32 / rel8
                const size: u8 = if (p.opcode == 0xe9) 4 else 1;
                if (readImm(bytes, p.imm_off, size)) |rel| {
                    d.mnemonic = "jmp";
                    d.kind = .branch;
                    d.target = next +% @as(u64, @bitCast(rel));
                    d.partial = false;
                    d.ops.print("0x{x}", .{d.target.?});
                    return d;
                }
            },
            0x70...0x7f => { // Jcc rel8
                if (readImm(bytes, p.imm_off, 1)) |rel| {
                    d.mnemonic = cc_names[p.opcode & 0xf];
                    d.kind = .cond_branch;
                    d.target = next +% @as(u64, @bitCast(rel));
                    d.partial = false;
                    d.ops.print("0x{x}", .{d.target.?});
                    return d;
                }
            },
            0xc3 => {
                d.mnemonic = "retq";
                d.kind = .ret;
                d.partial = false;
                return d;
            },
            0xc2 => {
                d.mnemonic = "retq";
                d.kind = .ret;
                d.partial = false;
                if (readImm(bytes, p.imm_off, 2)) |v| d.ops.print("${d}", .{v});
                return d;
            },
            0x50...0x57 => {
                d.mnemonic = "pushq";
                d.kind = .push;
                d.partial = false;
                d.ops.str(reg64_names[(p.opcode - 0x50) + @as(usize, rex_b) * 8]);
                return d;
            },
            0x58...0x5f => {
                d.mnemonic = "popq";
                d.kind = .pop;
                d.partial = false;
                d.ops.str(reg64_names[(p.opcode - 0x58) + @as(usize, rex_b) * 8]);
                return d;
            },
            0x8d => {
                d.mnemonic = "leaq";
                d.kind = .lea;
                if (p.rip_relative) {
                    d.target = next +% @as(u64, @bitCast(@as(i64, p.disp32)));
                    d.imm = d.target;
                }
                return d;
            },
            0x88...0x8b, 0xc6, 0xc7, 0xb0...0xbf => {
                d.mnemonic = "mov";
                d.kind = .other;
                if (p.opcode >= 0xb8 and p.opcode <= 0xbf) {
                    d.kind = .mov_imm;
                    if (readImm(bytes, p.imm_off, p.imm_size)) |v| d.imm = @bitCast(v);
                }
                if (p.rip_relative) d.target = next +% @as(u64, @bitCast(@as(i64, p.disp32)));
                return d;
            },
            0x90 => {
                if (p.rex == 0) {
                    d.mnemonic = "nop";
                    d.kind = .nop;
                    d.partial = false;
                    return d;
                }
            },
            0xcc => {
                d.mnemonic = "int3";
                d.kind = .trap;
                d.partial = false;
                return d;
            },
            0xff => {
                const ext: u3 = @truncate((p.modrm >> 3) & 7);
                switch (ext) {
                    2, 3 => {
                        d.mnemonic = "callq";
                        d.kind = .indirect_call;
                    },
                    4, 5 => {
                        d.mnemonic = "jmpq";
                        d.kind = .indirect_branch;
                    },
                    6 => {
                        d.mnemonic = "pushq";
                        d.kind = .push;
                    },
                    else => {},
                }
                if (d.kind != .other) {
                    // `FF 25 disp32` is the x86_64 stub shape: jmpq *disp(%rip) (disasm-notes D.2).
                    if (p.rip_relative) {
                        d.target = next +% @as(u64, @bitCast(@as(i64, p.disp32)));
                        d.ops.print("*0x{x}(%rip)", .{@as(u64, @bitCast(@as(i64, p.disp32)))});
                    }
                    return d;
                }
            },
            else => {},
        }
    } else if (p.map == 2 and p.opcode >= 0x80 and p.opcode <= 0x8f) { // Jcc rel32
        if (readImm(bytes, p.imm_off, 4)) |rel| {
            d.mnemonic = cc_names[p.opcode & 0xf];
            d.kind = .cond_branch;
            d.target = next +% @as(u64, @bitCast(rel));
            d.partial = false;
            d.ops.print("0x{x}", .{d.target.?});
            return d;
        }
    } else if (p.map == 2 and p.opcode == 0x05) {
        d.mnemonic = "syscall";
        d.partial = false;
        return d;
    } else if (p.map == 2 and p.opcode == 0x0b) {
        d.mnemonic = "ud2";
        d.kind = .trap;
        d.partial = false;
        return d;
    } else if (p.map == 2 and p.opcode == 0x1f) {
        d.mnemonic = "nop";
        d.kind = .nop;
        return d;
    }
    dbText(&d, bytes[0..@min(@as(usize, p.len), bytes.len)]);
    return d;
}

fn dbText(d: *Dec, raw: []const u8) void {
    d.mnemonic = "db";
    d.kind = .other;
    d.partial = true;
    for (raw, 0..) |b, i| {
        if (i != 0) d.ops.str(", ");
        d.ops.print("0x{x:0>2}", .{b});
    }
}

fn toInsn(d: *const Dec, bytes: []const u8, pc: u64, mnemonic: []const u8, operands: []const u8) Insn {
    var raw: [16]u8 = @splat(0);
    const n = @min(@as(usize, d.len), @min(bytes.len, 16));
    if (n > 0) @memcpy(raw[0..n], bytes[0..n]);
    return .{
        .addr = pc,
        .size = d.len,
        .bytes = raw,
        .mnemonic = mnemonic,
        .operands = operands,
        .kind = d.kind,
        .target = d.target,
        .reg_write = d.reg_write,
        // The length decoder names ~10 kinds, so this set is NOT complete for x86_64; it is safe only
        // because `symbolize` never folds an x86 memory base (x86len leaves `mem_ref` null and the
        // rip-relative target is resolved by the decoder itself), and because `Insn.endsTracking`
        // drops the page state on everything it could not name.
        .reg_writes = if (d.reg_write) |r| @as(u32, 1) << r else 0,
        .imm = d.imm,
        .mem_ref = d.mem_ref,
        .valid = d.valid,
        .text_from = .builtin_x86len,
        .semantic_from = .builtin_x86len,
        .partial = d.partial,
    };
}

/// Length-decodes one instruction at `bytes[0..]` (size 1..15, always >= 1). Recognized kinds get a mnemonic
/// (call/jmp/jcc/ret/push/pop/mov/lea); everything else is "db" with partial=true.
pub fn decodeOne(arena: Allocator, bytes: []const u8, pc: u64) Allocator.Error!Insn {
    const d = decodeInner(bytes, pc);
    const ops = try arena.dupe(u8, d.ops.view());
    return toInsn(&d, bytes, pc, d.mnemonic, ops);
}

pub fn decodeSemantic(bytes: []const u8, pc: u64) Insn {
    const d = decodeInner(bytes, pc);
    return toInsn(&d, bytes, pc, d.mnemonic, "");
}

// ---------------------------------------------------------------------------------------------
// otool-compatible text normalisation (--otool-compat, Capstone backend)
// ---------------------------------------------------------------------------------------------
//
// Capstone's AT&T printer and otool's (LLVM's X86ATTInstPrinter) agree on almost everything, but not
// on two points, both verified by assembling probe encodings and reading `otool -tV` back:
//
//   * the immediate. LLVM prints the MCOperand through `formatImm`, i.e. SIGNED hex, and the X86
//     disassembler sign-extends an immediate only when it is narrower than the operand (`83 /4 ib`
//     -> `andl $-0x13`, `48 81 /4 id` -> `andq $-0xc1`, `48 b8 io` -> `movabsq $-0xc1`) or when it is
//     an 8-bit immediate that is a number rather than a control field. A same-width immediate stays
//     unsigned (`81 /4 id` -> `andl $0xffffff3f`, `66 81 /4 iw` -> `andw $0xff3f`), and a control
//     imm8 (shift count, `int`, and the SSE/AVX selector bytes) is never sign-extended
//     (`c0 /4 ib` -> `shlb $0x80`, `0f 70 ib` -> `pshufd $0xe4`).
//   * the trailing `## imm = 0x...`, which LLVM emits only when the signed value is outside
//     [-256, 255], at the operand column 32. Capstone emits it for its own (unsigned) value, so it
//     has to be regenerated rather than kept or blindly dropped.
//
// Capstone also drops LLVM's shuffle comments (`## xmm0 = xmm0[0,1,0,1]`); the PSHUF family, which is
// 85% of them in a 1.4M-instruction system-binary sample, is reconstructed here.

/// Where an immediate sits inside an instruction and how LLVM's X86 disassembler widens it.
pub const ImmInfo = struct { off: u8, size: u8, sign_extend: bool };

/// imm8 bytes that are a control/bit field rather than a number: LLVM never sign-extends these.
fn rawImm8Opcode(map: u3, op: u8) bool {
    return switch (map) {
        // shift/rotate count, `int` vector, `in`/`out` port number
        1 => op == 0xc0 or op == 0xc1 or op == 0xcd or (op >= 0xe4 and op <= 0xe7),
        2 => switch (op) {
            0x70...0x73 => true, // pshuf* selector, ps{r,l}l/psra shift group
            0xa4, 0xac => true, // shld / shrd count
            0xba => true, // bt/bts/btr/btc bit number
            0xc2 => true, // cmpps/cmppd predicate
            0xc4, 0xc5 => true, // pinsrw / pextrw lane
            0xc6 => true, // shufps/shufpd selector
            else => false,
        },
        4 => true, // every 0F3A opcode ends in a control imm8
        else => false,
    };
}

/// The immediate of the instruction at `bytes[0..]` (null when there is none, or it is not a shape
/// AT&T prints with a `$`). `sign_extend` is LLVM's rule, not the CPU's.
pub fn immediateInfo(bytes: []const u8) ?ImmInfo {
    const p = parse(bytes);
    if (p.undefined_opcode) return null;
    if (p.imm_size != 1 and p.imm_size != 2 and p.imm_size != 4 and p.imm_size != 8) return null;
    if (@as(usize, p.imm_off) + p.imm_size > bytes.len) return null;
    const rex_w = (p.rex & 8) != 0;
    // `push imm32` (0x68) has a default operand size of 64 in long mode, so LLVM sign-extends its
    // imm32 where the same imm32 in `andl` stays unsigned (`pushq $-0xc1` vs `andl $0xffffff3f`).
    const stack_op = p.map == 1 and p.opcode == 0x68;
    const opsize_bits: u16 = if (p.opsize16) 16 else (if (rex_w or stack_op) 64 else 32);
    const raw8 = p.imm_size == 1 and rawImm8Opcode(p.map, p.opcode);
    const sign_extend = !raw8 and (p.imm_size == 1 or p.imm_size == 8 or @as(u16, p.imm_size) * 8 < opsize_bits);
    return .{ .off = p.imm_off, .size = p.imm_size, .sign_extend = sign_extend };
}

fn encodedImm(bytes: []const u8, info: ImmInfo) u64 {
    var v: u64 = 0;
    var i: u8 = 0;
    while (i < info.size) : (i += 1) v |= @as(u64, bytes[@as(usize, info.off) + i]) << @intCast(@as(u16, i) * 8);
    return v;
}

fn sext64(v: u64, size: u8) i64 {
    if (size >= 8) return @bitCast(v);
    const shift: u6 = @intCast(64 - @as(u16, size) * 8);
    return @as(i64, @bitCast(v << shift)) >> shift;
}

/// `-0x13` / `0xffffff3f` — LLVM's formatImm, two's-complement safe at the i64 minimum.
fn formatImm(buf: []u8, imm: i64) []const u8 {
    if (imm < 0) return std.fmt.bufPrint(buf, "-0x{x}", .{~@as(u64, @bitCast(imm)) +% 1}) catch "";
    return std.fmt.bufPrint(buf, "0x{x}", .{@as(u64, @bitCast(imm))}) catch "";
}

/// Capstone's own `## imm = ...` trailer, removed so it can be regenerated from the signed value.
fn stripImmComment(ops: []const u8) []const u8 {
    const pos = std.mem.find(u8, ops, "## imm = ") orelse return ops;
    return std.mem.trimEnd(u8, ops[0..pos], " ");
}

/// Span of the `$<number>` operand, or null when there is not exactly one parsable one.
const ImmToken = struct { start: usize, end: usize, value: u64 };
fn findImmToken(ops: []const u8) ?ImmToken {
    const pos = std.mem.findScalar(u8, ops, '$') orelse return null;
    if (std.mem.findScalarPos(u8, ops, pos + 1, '$') != null) return null;
    var end = pos + 1;
    while (end < ops.len) : (end += 1) {
        switch (ops[end]) {
            '-', 'x', '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => break,
        }
    }
    var text = ops[pos + 1 .. end];
    if (text.len == 0) return null;
    const neg = text[0] == '-';
    if (neg) text = text[1..];
    const mag: u64 = blk: {
        if (text.len > 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X'))
            break :blk std.fmt.parseInt(u64, text[2..], 16) catch return null;
        break :blk std.fmt.parseInt(u64, text, 10) catch return null;
    };
    return .{ .start = pos + 1, .end = end, .value = if (neg) ~mag +% 1 else mag };
}

/// LLVM's DecodePSHUF*Mask, rendered as the element list of the `## xmm0 = xmm0[...]` comment.
fn pshufElements(mnemonic: []const u8, imm8: u8, out: *[8]u8) ?u8 {
    const sel = struct {
        fn at(imm: u8, i: u3) u8 {
            return @intCast((imm >> (@as(u3, @intCast(i)) * 2)) & 3);
        }
    };
    if (std.mem.eql(u8, mnemonic, "pshufd") or std.mem.eql(u8, mnemonic, "pshufw")) {
        var i: u3 = 0;
        while (i < 4) : (i += 1) out[i] = sel.at(imm8, i);
        return 4;
    }
    if (std.mem.eql(u8, mnemonic, "pshuflw")) {
        var i: u3 = 0;
        while (i < 4) : (i += 1) out[i] = sel.at(imm8, i);
        out[4] = 4;
        out[5] = 5;
        out[6] = 6;
        out[7] = 7;
        return 8;
    }
    if (std.mem.eql(u8, mnemonic, "pshufhw")) {
        out[0] = 0;
        out[1] = 1;
        out[2] = 2;
        out[3] = 3;
        var i: u3 = 0;
        while (i < 4) : (i += 1) out[4 + @as(usize, i)] = 4 + sel.at(imm8, i);
        return 8;
    }
    return null;
}

/// `xmm0 = xmm0[0,1,0,1]` for the PSHUF family; null for everything else (Capstone's text then stands).
fn shuffleComment(buf: []u8, mnemonic: []const u8, ops: []const u8, bytes: []const u8) ?[]const u8 {
    var els: [8]u8 = undefined;
    const info = immediateInfo(bytes) orelse return null;
    if (info.size != 1) return null;
    const n = pshufElements(mnemonic, bytes[info.off], &els) orelse return null;
    // Capstone prints `$imm, <src>, <dst>`; a memory source is spelled `mem` by LLVM.
    var it = std.mem.splitSequence(u8, ops, ", ");
    _ = it.next() orelse return null;
    const src = it.next() orelse return null;
    const dst = it.next() orelse return null;
    if (it.next() != null) return null;
    if (dst.len < 2 or dst[0] != '%') return null;
    const src_name: []const u8 = if (src.len > 1 and src[0] == '%') src[1..] else "mem";
    var w: usize = 0;
    const head = std.fmt.bufPrint(buf, "{s} = {s}[", .{ dst[1..], src_name }) catch return null;
    w = head.len;
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const part = std.fmt.bufPrint(buf[w..], "{s}{d}", .{ if (i == 0) "" else ",", els[i] }) catch return null;
        w += part.len;
    }
    if (w >= buf.len) return null;
    buf[w] = ']';
    return buf[0 .. w + 1];
}

/// Rewrites the `$<immediate>` of one AT&T operand string into otool's spelling (LLVM's signed
/// `formatImm` over the value the X86 disassembler would have produced). Returns `ops` unchanged
/// whenever the rules above do not apply, so an encoding this file does not model can never corrupt
/// text; the `## imm = ...` trailer is left to the caller (symbolize.zig owns comments).
pub fn otoolImmOperand(arena: Allocator, ops: []const u8, bytes: []const u8) Allocator.Error![]const u8 {
    if (bytes.len == 0) return ops;
    const base = stripImmComment(ops);
    const tok = findImmToken(base) orelse return base;
    const info = immediateInfo(bytes) orelse return base;
    const enc = encodedImm(bytes, info);
    const mask: u64 = if (info.size >= 8) ~@as(u64, 0) else (@as(u64, 1) << @intCast(@as(u16, info.size) * 8)) - 1;
    // Capstone and the built-in parser must agree on which bytes the immediate is, or the rewrite is
    // skipped: a disagreement means this file mis-modelled the encoding.
    if ((tok.value & mask) != enc) return base;
    const imm: i64 = if (info.sign_extend) sext64(enc, info.size) else @bitCast(enc);
    var tbuf: [24]u8 = undefined;
    const text = formatImm(&tbuf, imm);
    if (std.mem.eql(u8, text, base[tok.start..tok.end])) return base;
    const out = try arena.alloc(u8, base.len - (tok.end - tok.start) + text.len);
    @memcpy(out[0..tok.start], base[0..tok.start]);
    @memcpy(out[tok.start..][0..text.len], text);
    const tail = base[tok.end..];
    @memcpy(out[tok.start + text.len ..][0..tail.len], tail);
    return out;
}

/// `xmm0 = xmm0[0,1,0,1]` for the PSHUF family, written into `buf`; null for everything else.
pub fn pshufComment(buf: []u8, mnemonic: []const u8, ops: []const u8, bytes: []const u8) ?[]const u8 {
    return shuffleComment(buf, mnemonic, ops, bytes);
}

test "x86len: otool immediate spelling (signed only where LLVM sign-extends)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // `bytes` and `want` are `clang -c -arch x86_64` + `otool -tV` ground truth (disasm-notes C.5);
    // `ops` is what Capstone's AT&T printer produces for the same bytes.
    const Row = struct { bytes: []const u8, ops: []const u8, want: []const u8 };
    const rows = [_]Row{
        // imm8 narrower than the operand -> signed
        .{ .bytes = &.{ 0x83, 0xe1, 0xed }, .ops = "$0xffffffed, %ecx", .want = "$-0x13, %ecx" },
        // 8-bit operand, imm8 -> still signed
        .{ .bytes = &.{ 0x24, 0xf8 }, .ops = "$0xf8, %al", .want = "$-0x8, %al" },
        .{ .bytes = &.{ 0xa8, 0x80 }, .ops = "$0x80, %al", .want = "$-0x80, %al" },
        // imm32 at operand size 32 / imm16 at operand size 16 -> unsigned
        .{ .bytes = &.{ 0x81, 0xe1, 0x3f, 0xff, 0xff, 0xff }, .ops = "$0xffffff3f, %ecx", .want = "$0xffffff3f, %ecx" },
        .{ .bytes = &.{ 0x66, 0x81, 0xe1, 0x3f, 0xff }, .ops = "$0xff3f, %cx", .want = "$0xff3f, %cx" },
        // imm32 with REX.W (operand size 64) -> signed
        .{ .bytes = &.{ 0x48, 0x81, 0xe1, 0x3f, 0xff, 0xff, 0xff }, .ops = "$0xffffffffffffff3f, %rcx", .want = "$-0xc1, %rcx" },
        // imm64 -> the i64 itself, two's complement safe at the minimum
        .{ .bytes = &.{ 0x48, 0xb9, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .ops = "$0xffffffffffffff3f, %rcx", .want = "$-0xc1, %rcx" },
        .{ .bytes = &.{ 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 }, .ops = "$0x8000000000000000, %rax", .want = "$-0x8000000000000000, %rax" },
        // push imm32: default operand size 64 in long mode -> signed
        .{ .bytes = &.{ 0x68, 0x3f, 0xff, 0xff, 0xff }, .ops = "$-0xc1", .want = "$-0xc1" },
        // control imm8 bytes are never sign-extended
        .{ .bytes = &.{ 0xc0, 0xe1, 0x80 }, .ops = "$0x80, %cl", .want = "$0x80, %cl" },
        .{ .bytes = &.{ 0xcd, 0x80 }, .ops = "$0x80", .want = "$0x80" },
        .{ .bytes = &.{ 0xe4, 0xff }, .ops = "$0xff, %al", .want = "$0xff, %al" },
        .{ .bytes = &.{ 0x0f, 0xba, 0xe1, 0x80 }, .ops = "$0x80, %ecx", .want = "$0x80, %ecx" },
        .{ .bytes = &.{ 0x66, 0x0f, 0x70, 0xc0, 0xe4 }, .ops = "$0xe4, %xmm0, %xmm0", .want = "$0xe4, %xmm0, %xmm0" },
        // Capstone's own `## imm = ...` trailer is dropped (symbolize.zig regenerates it)
        .{ .bytes = &.{ 0x83, 0xe1, 0xed }, .ops = "$0xffffffed, %ecx               ## imm = 0xFFFFFFED", .want = "$-0x13, %ecx" },
        // no immediate at all: untouched
        .{ .bytes = &.{ 0x48, 0x89, 0xe5 }, .ops = "%rsp, %rbp", .want = "%rsp, %rbp" },
    };
    for (rows) |r| {
        const got = try otoolImmOperand(a, r.ops, r.bytes);
        std.testing.expectEqualStrings(r.want, got) catch |e| {
            std.debug.print("  -> bytes {x}\n", .{r.bytes});
            return e;
        };
    }
}

test "x86len: LLVM's PSHUF shuffle comments" {
    var buf: [96]u8 = undefined;
    // 66 0f 70 /r ib -> pshufd; imm 0xe4 is the identity, 0x1b reverses, 0x00 broadcasts lane 0.
    try std.testing.expectEqualStrings(
        "xmm0 = xmm0[0,1,2,3]",
        pshufComment(&buf, "pshufd", "$0xe4, %xmm0, %xmm0", &.{ 0x66, 0x0f, 0x70, 0xc0, 0xe4 }).?,
    );
    try std.testing.expectEqualStrings(
        "xmm3 = xmm3[0,0,0,0]",
        pshufComment(&buf, "pshufd", "$0x0, %xmm3, %xmm3", &.{ 0x66, 0x0f, 0x70, 0xdb, 0x00 }).?,
    );
    // a memory source is spelled `mem`
    try std.testing.expectEqualStrings(
        "xmm0 = mem[3,2,1,0]",
        pshufComment(&buf, "pshufd", "$0x1b, -0x60(%rbp), %xmm0", &.{ 0x66, 0x0f, 0x70, 0x45, 0xa0, 0x1b }).?,
    );
    // the low/high halves keep the identity on the half the instruction does not touch
    try std.testing.expectEqualStrings(
        "xmm0 = xmm0[0,1,0,1,4,5,6,7]",
        pshufComment(&buf, "pshuflw", "$0x44, %xmm0, %xmm0", &.{ 0xf2, 0x0f, 0x70, 0xc0, 0x44 }).?,
    );
    try std.testing.expectEqualStrings(
        "xmm0 = xmm0[0,1,2,3,4,5,4,5]",
        pshufComment(&buf, "pshufhw", "$0x44, %xmm0, %xmm0", &.{ 0xf3, 0x0f, 0x70, 0xc0, 0x44 }).?,
    );
    // everything else keeps Capstone's (comment-free) text
    try std.testing.expect(pshufComment(&buf, "palignr", "$0x88, %xmm1, %xmm0", &.{ 0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x88 }) == null);
    try std.testing.expect(pshufComment(&buf, "movq", "%rsp, %rbp", &.{ 0x48, 0x89, 0xe5 }) == null);
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

/// The first 64 bytes of `/bin/ls` x86_64 `__text` (addr 0x100000718, file offset 1816) — the 20
/// boundaries of disasm-notes A.4. Kept here as a hermetic unit test; tests/facts/decoders.zig
/// re-reads the live file and diffs the whole 6000-byte run against `otool -tv`.
const ls_prologue = [_]u8{
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xc7, 0x68, 0x48, 0x83, 0xc6, 0x68, 0x5d, 0xe9, 0x5b, 0x3c,
    0x00, 0x00, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x46, 0x68, 0x48, 0x8d, 0x77, 0x68, 0x48, 0x89,
    0xc7, 0x5d, 0xe9, 0x46, 0x3c, 0x00, 0x00, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf9, 0x48, 0x8b,
    0x56, 0x60, 0x48, 0x8b, 0x7f, 0x60, 0x4c, 0x8b, 0x47, 0x30, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x4c,
};
const ls_prologue_sizes = [_]u8{ 1, 3, 4, 4, 1, 5, 1, 3, 4, 4, 3, 1, 5, 1, 3, 3, 4, 4, 4, 5 };

test "x86len: the /bin/ls x86_64 prologue splits into the otool boundaries" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var off: usize = 0;
    var idx: usize = 0;
    var pc: u64 = 0x100000718;
    while (off < ls_prologue.len and idx < ls_prologue_sizes.len) : (idx += 1) {
        const one = try decodeOne(arena, ls_prologue[off..], pc);
        try std.testing.expectEqual(ls_prologue_sizes[idx], one.size);
        off += one.size;
        pc += one.size;
    }
    try std.testing.expectEqual(@as(usize, 20), idx);
}

test "x86len: kinds, targets and the stub shape" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // push %rbp / mov %rsp,%rbp / pop %rbp
    try std.testing.expectEqual(insn.Kind.push, decodeSemantic(&[_]u8{0x55}, 0).kind);
    try std.testing.expectEqual(insn.Kind.pop, decodeSemantic(&[_]u8{0x5d}, 0).kind);
    try std.testing.expectEqual(insn.Kind.ret, decodeSemantic(&[_]u8{0xc3}, 0).kind);
    // jmp 0x100004385 at 0x100000725 (E9 5B 3C 00 00)
    const j = decodeSemantic(&[_]u8{ 0xe9, 0x5b, 0x3c, 0x00, 0x00 }, 0x100000725);
    try std.testing.expectEqual(insn.Kind.branch, j.kind);
    try std.testing.expectEqual(@as(?u64, 0x100004385), j.target);
    try std.testing.expectEqual(@as(u8, 5), j.size);
    // jg 0x100000777 at 0x10000075b (7F 1A)
    const jg = decodeSemantic(&[_]u8{ 0x7f, 0x1a }, 0x10000075b);
    try std.testing.expectEqual(insn.Kind.cond_branch, jg.kind);
    try std.testing.expectEqual(@as(?u64, 0x100000777), jg.target);
    // leaq 0x4e0c(%rip), %rax at 0x100000779 -> 0x10000558c
    const lea = decodeSemantic(&[_]u8{ 0x48, 0x8d, 0x05, 0x0c, 0x4e, 0x00, 0x00 }, 0x100000779);
    try std.testing.expectEqual(insn.Kind.lea, lea.kind);
    try std.testing.expectEqual(@as(u8, 7), lea.size);
    try std.testing.expectEqual(@as(?u64, 0x10000558c), lea.target);
    // callq rel32
    const call = decodeSemantic(&[_]u8{ 0xe8, 0x10, 0x00, 0x00, 0x00 }, 0x100000000);
    try std.testing.expectEqual(insn.Kind.call, call.kind);
    try std.testing.expectEqual(@as(?u64, 0x100000015), call.target);
    // x86_64 stub: FF 25 disp32 = jmpq *disp(%rip)
    const stub = try decodeOne(arena, &[_]u8{ 0xff, 0x25, 0x20, 0x30, 0x00, 0x00 }, 0x100000e00);
    try std.testing.expectEqual(insn.Kind.indirect_branch, stub.kind);
    try std.testing.expectEqual(@as(u8, 6), stub.size);
    try std.testing.expectEqual(@as(?u64, 0x100003e26), stub.target);
    // FF /2 = indirect call
    try std.testing.expectEqual(insn.Kind.indirect_call, decodeSemantic(&[_]u8{ 0xff, 0x15, 0, 0, 0, 0 }, 0).kind);
    // 0F 8F rel32 = jg
    const jg32 = decodeSemantic(&[_]u8{ 0x0f, 0x8f, 0x00, 0x01, 0x00, 0x00 }, 0x100000000);
    try std.testing.expectEqual(insn.Kind.cond_branch, jg32.kind);
    try std.testing.expectEqual(@as(u8, 6), jg32.size);
    try std.testing.expectEqual(@as(?u64, 0x100000106), jg32.target);
}

test "x86len: length rules of disasm-notes C.1-C.3" {
    const cases = [_]struct { bytes: []const u8, len: u8 }{
        .{ .bytes = &[_]u8{ 0x48, 0x89, 0xe5 }, .len = 3 }, // mov %rsp,%rbp
        .{ .bytes = &[_]u8{ 0x48, 0x83, 0xc7, 0x68 }, .len = 4 }, // add $0x68,%rdi
        .{ .bytes = &[_]u8{ 0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8 }, .len = 10 }, // movabs (REX.W B8+r)
        .{ .bytes = &[_]u8{ 0xb8, 1, 2, 3, 4 }, .len = 5 }, // mov $imm32,%eax
        .{ .bytes = &[_]u8{ 0x66, 0xb8, 1, 2 }, .len = 4 }, // 66 -> iz is 2 bytes
        .{ .bytes = &[_]u8{ 0x8b, 0x04, 0x25, 0, 0, 0, 0 }, .len = 7 }, // SIB base=5, mod=0 -> disp32
        .{ .bytes = &[_]u8{ 0x8b, 0x45, 0x08 }, .len = 3 }, // mod=1 -> disp8
        .{ .bytes = &[_]u8{ 0x8b, 0x85, 0, 1, 0, 0 }, .len = 6 }, // mod=2 -> disp32
        .{ .bytes = &[_]u8{ 0x8b, 0x05, 0, 0, 0, 0 }, .len = 6 }, // RIP-relative
        .{ .bytes = &[_]u8{ 0xff, 0xff }, .len = 1 }, // FF /7 is undefined -> 1 byte
        .{ .bytes = &[_]u8{ 0x0f, 0x38, 0x00, 0xc1 }, .len = 4 }, // 0F38 always has ModRM
        .{ .bytes = &[_]u8{ 0x0f, 0x3a, 0x0f, 0xc1, 0x04 }, .len = 5 }, // 0F3A always has a trailing imm8
        .{ .bytes = &[_]u8{ 0xc8, 0x00, 0x10, 0x00 }, .len = 4 }, // enter iw, ib
        .{ .bytes = &[_]u8{ 0xf7, 0xc0, 1, 0, 0, 0 }, .len = 6 }, // F7 /0 -> iz
        .{ .bytes = &[_]u8{ 0xf7, 0xd0 }, .len = 2 }, // F7 /2 -> no imm
        .{ .bytes = &[_]u8{ 0x6a, 0x10 }, .len = 2 }, // push imm8
        .{ .bytes = &[_]u8{ 0x68, 1, 2, 3, 4 }, .len = 5 }, // push imm32
        .{ .bytes = &[_]u8{ 0xa1, 1, 2, 3, 4, 5, 6, 7, 8 }, .len = 9 }, // moffs64
        .{ .bytes = &[_]u8{ 0x0f, 0x05 }, .len = 2 }, // syscall (no ModRM)
        .{ .bytes = &[_]u8{ 0x0f, 0xba, 0xe0, 0x01 }, .len = 4 }, // bt r/m,imm8
    };
    for (cases) |c| try std.testing.expectEqual(c.len, length(c.bytes));
}

test "x86len: never returns 0 and never over-runs the buffer" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqual(@as(u8, 1), length(&[_]u8{}));
    var prng = std.Random.DefaultPrng.init(0x78383620_6c656e01);
    const random = prng.random();
    var buf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 50_000) : (i += 1) {
        random.bytes(&buf);
        const n = random.uintLessThan(usize, buf.len + 1);
        const slice = buf[0..n];
        const len = length(slice);
        try std.testing.expect(len >= 1 and len <= max_len);
        if (n > 0) try std.testing.expect(len <= n);
        const one = try decodeOne(arena, slice, 0x100000000);
        try std.testing.expectEqual(len, one.size);
        try std.testing.expect(one.mnemonic.len > 0);
        _ = arena_state.reset(.retain_capacity);
    }
}

test "x86len: a linear sweep over arbitrary bytes always terminates" {
    var prng = std.Random.DefaultPrng.init(0x78383620_6c656e02);
    const random = prng.random();
    var buf: [4096]u8 = undefined;
    var round: u32 = 0;
    while (round < 64) : (round += 1) {
        random.bytes(&buf);
        var off: usize = 0;
        var steps: u32 = 0;
        while (off < buf.len) : (steps += 1) {
            const len = length(buf[off..]);
            try std.testing.expect(len >= 1);
            off += len;
        }
        try std.testing.expect(steps <= buf.len);
    }
}
