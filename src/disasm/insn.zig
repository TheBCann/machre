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
    reg_write: ?u5, // primary destination, when the instruction has one
    /// EVERY general-purpose register this instruction writes, as a bit set (bit n = Xn/Wn), primary
    /// destination included. A single `?u5` cannot describe LDP (Rt AND Rt2), a pre/post-index load
    /// (Rt AND the base Rn), LDXP, STXR/STXP (the status Rs) or CAS/CASP (Rs, Rs+1), and a consumer
    /// that invalidates only `reg_write` therefore keeps believing a register that has been clobbered.
    /// A write to X31 that the encoding discards (XZR) sets no bit; a write to SP sets bit 31.
    /// Zero is the safe-by-omission default only for records that write nothing (`.data` fillers).
    reg_writes: u32 = 0,
    imm: ?u64, // adrp page / add imm / mov imm
    mem_ref: ?MemRef,
    valid: bool,
    text_from: Backend,
    semantic_from: Backend,
    partial: bool, // x86_64 built-in: only kind/size known ("db" mnemonic)

    /// The `size` bytes actually decoded (`bytes` is a fixed 16-byte tail-padded copy).
    pub fn raw(i: *const Insn) []const u8 {
        const n: usize = @min(@as(usize, i.size), 16);
        return i.bytes[0..16][0..n];
    }
    /// True for control-flow instructions that end a basic block.
    pub fn isTerminator(i: *const Insn) bool {
        return switch (i.kind) {
            .branch, .ret, .indirect_branch, .trap => true,
            else => false,
        };
    }
    /// True when this instruction writes GPR `r` (`r` == 31 means SP, never XZR).
    pub fn writesReg(i: *const Insn, r: u5) bool {
        return i.reg_writes & (@as(u32, 1) << r) != 0;
    }
    /// True when control leaves the basic block here, or when the word could not be decoded at all —
    /// either way a register-tracking consumer must drop everything it believes.
    pub fn endsTracking(i: *const Insn) bool {
        if (!i.valid) return true;
        return switch (i.kind) {
            .invalid, .branch, .indirect_branch, .ret, .trap => true,
            else => false,
        };
    }
    /// True when the instruction transfers control to `target` and returns (`bl`, `call`).
    pub fn isCall(i: *const Insn) bool {
        return i.kind == .call or i.kind == .indirect_call;
    }
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

    pub const empty: Listing = .{ .insns = &.{}, .comments = &.{}, .labels = &.{}, .start = 0, .end = 0, .partial = false, .backend_name = "none" };
};
pub fn kindName(k: Kind) []const u8 {
    return @tagName(k);
}
/// Text backend for `arch`: Capstone when linked and the arch is supported, else the built-in decoder.
/// Semantic fields always come from the built-in decoder regardless of what this returns.
pub fn backendFor(arch: ArchName, have_capstone: bool) Backend {
    return switch (arch) {
        .arm64, .arm64e, .arm64v8, .arm64_32 => if (have_capstone) .capstone else .builtin_arm64,
        .x86_64, .x86_64h => if (have_capstone) .capstone else .builtin_x86len,
        else => if (have_capstone) .capstone else .builtin_x86len,
    };
}
/// The built-in (never-Capstone) backend for `arch`; null when no built-in decoder covers it.
pub fn builtinBackendFor(arch: ArchName) ?Backend {
    return switch (arch) {
        .arm64, .arm64e, .arm64v8, .arm64_32 => .builtin_arm64,
        .x86_64, .x86_64h => .builtin_x86len,
        else => null,
    };
}
pub fn backendName(b: Backend) []const u8 {
    return switch (b) {
        .capstone => "capstone",
        .builtin_arm64 => "builtin arm64",
        .builtin_x86len => "builtin x86 length decoder",
    };
}

test "insn: backend selection and record helpers" {
    try std.testing.expectEqual(Backend.builtin_arm64, backendFor(.arm64e, false));
    try std.testing.expectEqual(Backend.capstone, backendFor(.arm64e, true));
    try std.testing.expectEqual(Backend.builtin_x86len, backendFor(.x86_64, false));
    try std.testing.expectEqual(Backend.builtin_arm64, builtinBackendFor(.arm64).?);
    try std.testing.expect(builtinBackendFor(.ppc) == null);
    try std.testing.expectEqualStrings("builtin arm64", backendName(.builtin_arm64));
    try std.testing.expectEqualStrings("adrp", kindName(.adrp));
    var bytes: [16]u8 = @splat(0);
    bytes[0] = 0xc0;
    bytes[1] = 0x03;
    bytes[2] = 0x5f;
    bytes[3] = 0xd6;
    const i: Insn = .{ .addr = 0x100, .size = 4, .bytes = bytes, .mnemonic = "ret", .operands = "", .kind = .ret, .target = null, .reg_write = null, .imm = null, .mem_ref = null, .valid = true, .text_from = .builtin_arm64, .semantic_from = .builtin_arm64, .partial = false };
    try std.testing.expectEqual(@as(usize, 4), i.raw().len);
    try std.testing.expect(i.isTerminator());
    try std.testing.expect(!i.isCall());
    try std.testing.expect(i.endsTracking()); // `ret` leaves the block
    try std.testing.expect(!i.writesReg(0));
    var j = i;
    j.reg_writes = (1 << 3) | (1 << 31);
    try std.testing.expect(j.writesReg(3) and j.writesReg(31) and !j.writesReg(4));
    try std.testing.expectEqual(@as(usize, 0), Listing.empty.insns.len);
}
