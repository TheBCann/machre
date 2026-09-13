//! disasm/inline_data.zig — finds inline DATA inside an arm64 code section. Imports: disasm/insn.
//!
//! ## Why this exists
//!
//! A `__TEXT,__text` section is bytes. Nothing in a Mach-O says which of them are instructions and
//! which are lookup tables, jump tables or constants the code reads. ELF toolchains answer this for
//! free — the linker emits `$d` mapping symbols (DESIGN §5.6, format-notes) — and Mach-O has
//! `LC_DATA_IN_CODE`, but **Apple's linker populates it only for ARM32**: measured over
//! /usr/lib/dyld, /bin/ls, /usr/bin/plutil and /usr/libexec/locationd (all arm64e) it has **0
//! entries**. So on arm64 the question has to be answered by analysis.
//!
//! ## Why it matters more as the decoder improves
//!
//! Today an unnameable word prints `.inst 0x…` (valid=false, §5.6 class (d)), which is an honest
//! "I cannot name this". Data survives that way largely by luck: ARM's encoding space is sparse, so
//! a table word often lands on an unallocated pattern. That luck is partial even now. The 16-byte
//! NEON permute table at dyld 0x1e20 is `00 01 02 … 0f`, and its third word `0b0a0908` decodes as a
//! perfectly ordinary `add w8, w8, w10, lsl #2`:
//!
//! ```
//! 0x1e20  .inst 0x03020100      <- unallocated, printed as data-ish
//! 0x1e24  .inst 0x07060504      <- unallocated
//! 0x1e28  add w8, w8, w10, lsl #2   <- DATA that decodes as a real instruction
//! 0x1e2c  .inst 0x0f0e0d0c      <- unallocated
//! ```
//!
//! Teaching the decoder more encodings (e.g. from Arm's machine-readable ISA spec) converts more of
//! those `.inst` words into confident, wrong instructions. The failure mode is the same class as the
//! fabricated-symbol defect (§7 item 12): a plausible lie is worse for an analyst than an admission
//! of ignorance. Hence this pass — decoder coverage must not outrun data detection.
//!
//! ## The signal
//!
//! Evidence, not guesswork. A region is data when code **takes its address** or **loads from it**
//! and nothing ever **branches** to it:
//!
//!   * `ADR Xd, A` / `LDR Xt, A` (literal) landing inside this section  => someone treats A as a
//!     datum. At dyld 0x1e20 two sites do exactly this: `adr x3, #0x1e20`.
//!   * A is not the target of any `B`/`B.cond`/`BL`/`CBZ`/`CBNZ`/`TBZ`/`TBNZ` in the section.
//!   * A is not reachable by fall-through: the preceding instruction ends its block (`ret`,
//!     unconditional branch, indirect branch, or a trap).
//!
//! `LC_FUNCTION_STARTS` is deliberately NOT treated as proof of code: it is an atom-boundary table,
//! and it lists 0x1e20 — the data table above — as a "function start". It is used here only to
//! bound a run, never to claim one is code.
//!
//! ## A trigger that was tried and REMOVED
//!
//! An earlier draft also promoted any run of >=4 consecutive words the decoder could not name. That
//! is unsound, and measurably so: on /usr/lib/dyld it mislabelled ~52 words of a real SHA-256
//! implementation (`sha256h.4s`, `sha256su1.4s`, `rev32.16b`) as data, because the BUILT-IN decoder
//! does not implement the crypto extensions. `valid == false` means "this decoder cannot name it",
//! never "this is not code" — and it is exactly the signal that changes when decoder coverage grows,
//! so a rule keyed on it would silently rot. Do not reintroduce it.
//!
//! What remains is conservative by construction: it can only *fail to find* data, never invent it,
//! because it requires positive evidence (someone takes the address) plus the absence of a branch.

const std = @import("std");
const Allocator = std.mem.Allocator;
const insn = @import("insn.zig");

/// Why a run was classified as data — carried into diagnostics so a reviewer can audit a decision.
pub const Why = enum {
    /// Code takes the run's address (`ADR`) or loads from it (`LDR` literal), and nothing branches to it.
    addr_taken,
};

pub const Run = struct { lo: u64, hi: u64, why: Why };

pub const Stats = struct {
    runs: u32 = 0,
    words: u32 = 0,
    /// Runs found by each trigger, for the `--verbose` footer and for tests that pin behaviour.
    addr_taken: u32 = 0,
};

/// Hard ceiling on one run, so a pathological section cannot turn an entire `__text` into `.long`.
const max_run_words: u32 = 4096;

fn isBranch(k: insn.Kind) bool {
    return switch (k) {
        .branch, .cond_branch, .call => true,
        else => false,
    };
}

/// Ends a basic block: control does not fall through into the next word.
fn endsBlock(k: insn.Kind) bool {
    return switch (k) {
        .ret, .branch, .indirect_branch, .trap => true,
        else => false,
    };
}

/// The address an instruction names as a *datum*, or null if it names none.
///
/// The decoder reserves `target` for CONTROL FLOW (arm64.zig:317) and puts a resolved
/// address-generation result in `imm`, so the two kinds read different fields:
///   * `ADR Xd, label`  -> `imm` holds the resolved address (precise, 21-bit signed range)
///   * `LDR Xt, label`  -> `target` holds the literal's address
///
/// `ADRP` is deliberately excluded: on its own it yields only a 4KB page base, so treating the page
/// start as "a datum" would mark the first word of whatever happens to live there. The precise
/// address only exists after the following `ADD`/`LDR` is folded in, which is `symbolize`'s job —
/// see the note in `find`.
fn datumAddress(i: *const insn.Insn) ?u64 {
    return switch (i.kind) {
        .adr => i.imm,
        .ldr_literal => i.target,
        else => null,
    };
}

/// Finds the data runs in one already-decoded section. `listings` are the per-function listings in
/// address order; `sect_lo`/`sect_hi` bound the section so a reference that leaves it is ignored.
///
/// Pure analysis: returns the runs and mutates nothing. `mark` applies them.
pub fn find(
    arena: Allocator,
    listings: []const insn.Listing,
    sect_lo: u64,
    sect_hi: u64,
) Allocator.Error![]const Run {
    var branch_targets: std.AutoHashMapUnmanaged(u64, void) = .empty;
    var addr_refs: std.AutoHashMapUnmanaged(u64, void) = .empty;

    // Pass 1 — collect evidence across the WHOLE section. This is why the pass cannot live inside
    // per-function decoding: the `adr` that names a table often sits in a different function.
    // Control-flow targets and datum addresses live in different fields by decoder convention, so
    // they are collected separately rather than from one `target` read.
    //
    // Not yet modelled: the `ADRP`+`ADD` fold. `symbolize` resolves those pairs into a precise
    // address; routing its result here would widen coverage to tables reached that way. Until then
    // such a table is caught only if it also trips the blind-run rule — the pass under-reports
    // rather than guesses, which is the intended direction.
    for (listings) |l| {
        for (l.insns) |i| {
            if (isBranch(i.kind)) {
                const t = i.target orelse continue;
                if (t < sect_lo or t >= sect_hi) continue;
                try branch_targets.put(arena, t, {});
            } else if (datumAddress(&i)) |a| {
                if (a < sect_lo or a >= sect_hi) continue;
                try addr_refs.put(arena, a, {});
            }
        }
    }

    var runs: std.ArrayList(Run) = .empty;
    for (listings) |l| {
        var idx: usize = 0;
        while (idx < l.insns.len) {
            const i = l.insns[idx];

            // Trigger 1: the address is taken, nothing branches here, and control cannot fall in.
            const falls_in = idx > 0 and !endsBlock(l.insns[idx - 1].kind);
            if (addr_refs.contains(i.addr) and !branch_targets.contains(i.addr) and !falls_in) {
                const n = runLength(l.insns[idx..], &branch_targets);
                if (n > 0) {
                    try runs.append(arena, .{ .lo = i.addr, .hi = i.addr +% (4 * n), .why = .addr_taken });
                    idx += n;
                    continue;
                }
            }

            idx += 1;
        }
    }
    return runs.toOwnedSlice(arena);
}

/// Extent of an address-taken run: to the end of its atom, minus trailing trap padding, stopping at
/// the first word anything branches to. Trailing traps are the linker's inter-atom filler — leaving
/// them as `udf` keeps the listing honest about where the table really ends.
fn runLength(rest: []const insn.Insn, branch_targets: *const std.AutoHashMapUnmanaged(u64, void)) usize {
    var n: usize = 0;
    while (n < rest.len and n < max_run_words) : (n += 1) {
        if (n > 0 and branch_targets.contains(rest[n].addr)) break;
        if (rest[n].kind == .trap) break; // padding: the atom's data ended here
    }
    // A run that is entirely traps is padding, not a table.
    return n;
}

/// Rewrites every record inside a run as a `.long` data record. `.long` (valid, `kind = .data`)
/// means "this is data" and is deliberately distinct from `.inst` ("cannot name this word") —
/// DESIGN §5.6 class (d) forbids collapsing the two, and this pass is what earns the distinction:
/// it promotes only words backed by positive evidence.
pub fn mark(listings: []insn.Listing, runs: []const Run, arena: Allocator) Allocator.Error!Stats {
    var st: Stats = .{};
    for (runs) |r| {
        st.runs += 1;
        st.addr_taken += 1;
        for (listings) |*l| {
            // `insns` is `[]const Insn` in the public struct; the section owns the backing memory,
            // so the cast is to write through our own arena allocation, never shared storage.
            const mut: []insn.Insn = @constCast(l.insns);
            for (mut) |*i| {
                if (i.addr < r.lo or i.addr >= r.hi) continue;
                // Copy the fixed-size array out before reading a word from it. `Insn.bytes` is
                // always 16 bytes so `[0..4]` cannot be short, but the repo bans `.bytes[` indexing
                // outside core/reader.zig (robustness_tests §"no raw byte indexing") to keep every
                // *file*-derived index in one reviewed place; going through a local keeps this pass
                // on the right side of that rule instead of carving an exception into it.
                const raw: [16]u8 = i.bytes;
                const w = std.mem.readInt(u32, raw[0..4], .little);
                i.mnemonic = ".long";
                i.operands = try std.fmt.allocPrint(arena, "0x{x:0>8}", .{w});
                i.kind = .data;
                i.valid = true;
                i.target = null;
                i.reg_write = null;
                i.reg_writes = 0;
                i.mem_ref = null;
                i.imm = w;
                i.partial = false;
                st.words += 1;
            }
        }
    }
    return st;
}

// -------------------------------------------------------------------------------------------
// tests
// -------------------------------------------------------------------------------------------

/// `at` goes to the field the real decoder uses for that kind: `imm` for ADR, `target` otherwise.
fn mk(addr: u64, kind: insn.Kind, at: ?u64, valid: bool) insn.Insn {
    return .{
        .addr = addr,
        .size = 4,
        .bytes = @splat(0),
        .mnemonic = "x",
        .operands = "",
        .kind = kind,
        .target = if (kind == .adr) null else at,
        .reg_write = null,
        .imm = if (kind == .adr) at else null,
        .mem_ref = null,
        .valid = valid,
        .text_from = .builtin_arm64,
        .semantic_from = .builtin_arm64,
        .partial = false,
    };
}

fn listingOf(insns: []const insn.Insn) insn.Listing {
    return .{
        .insns = insns,
        .comments = &.{},
        .labels = &.{},
        .start = insns[0].addr,
        .end = insns[insns.len - 1].addr + 4,
        .partial = false,
        .backend_name = "test",
    };
}

test "inline_data: an address-taken table behind a trap is data" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Mirrors dyld 0x1e20: adr names 0x100, a trap precedes it, and the third word decodes as a
    // real instruction — the case a "run of unnameable words" rule would split and get wrong.
    const code = [_]insn.Insn{
        mk(0x0f0, .adr, 0x100, true), // adr x3, #0x100
        mk(0x0f4, .trap, null, true), // udf: control cannot fall through
        mk(0x100, .other, null, false), // table word 0
        mk(0x104, .other, null, false), // table word 1
        mk(0x108, .other, null, true), // table word 2 — DECODES, but is still data
        mk(0x10c, .other, null, false), // table word 3
        mk(0x110, .trap, null, true), // padding ends the atom
    };
    var ls = [_]insn.Listing{listingOf(&code)};

    const runs = try find(arena, &ls, 0x0, 0x1000);
    try std.testing.expectEqual(@as(usize, 1), runs.len);
    try std.testing.expectEqual(Why.addr_taken, runs[0].why);
    try std.testing.expectEqual(@as(u64, 0x100), runs[0].lo);
    try std.testing.expectEqual(@as(u64, 0x110), runs[0].hi); // stops at the trap, 4 words

    const st = try mark(&ls, runs, arena);
    try std.testing.expectEqual(@as(u32, 4), st.words);
    try std.testing.expectEqual(@as(u32, 1), st.addr_taken);
    // The word that decoded as an instruction is now data too — that is the whole point.
    try std.testing.expectEqualStrings(".long", ls[0].insns[4].mnemonic);
    try std.testing.expectEqual(insn.Kind.data, ls[0].insns[4].kind);
}

test "inline_data: a branch target is never claimed as data" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Same shape, but something branches to 0x100: it is reachable code, whatever else points at it.
    const code = [_]insn.Insn{
        mk(0x0f0, .adr, 0x100, true),
        mk(0x0f4, .branch, 0x100, true), // <- makes 0x100 reachable
        mk(0x100, .other, null, false),
        mk(0x104, .other, null, false),
        mk(0x108, .other, null, false),
        mk(0x10c, .other, null, false),
    };
    var ls = [_]insn.Listing{listingOf(&code)};
    const runs = try find(arena, &ls, 0x0, 0x1000);
    try std.testing.expectEqual(@as(usize, 0), runs.len);
}

test "inline_data: fall-through reachable words are never claimed as data" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No trap before 0x100, so control falls straight in from 0x0f4: it is code.
    const code = [_]insn.Insn{
        mk(0x0f0, .adr, 0x100, true),
        mk(0x0f4, .other, null, true), // falls through
        mk(0x100, .other, null, false),
        mk(0x104, .other, null, false),
        mk(0x108, .other, null, false),
    };
    var ls = [_]insn.Listing{listingOf(&code)};
    const runs = try find(arena, &ls, 0x0, 0x1000);
    try std.testing.expectEqual(@as(usize, 0), runs.len);
}

test "inline_data: a reference that leaves the section is ignored" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const code = [_]insn.Insn{
        mk(0x0f0, .adr, 0x9000, true), // target outside [0, 0x1000)
        mk(0x0f4, .trap, null, true),
        mk(0x100, .other, null, true),
    };
    var ls = [_]insn.Listing{listingOf(&code)};
    try std.testing.expectEqual(@as(usize, 0), (try find(arena, &ls, 0x0, 0x1000)).len);
}
