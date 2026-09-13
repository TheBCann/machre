//! tests/fuzz/decoders.zig — Smith fuzzers + deterministic sweeps for the instruction decoders (DESIGN §10.5).
//!
//! The decoders take no `Limits` and allocate nothing but the text of one instruction, so the invariants
//! under test are the ones the engine's sweep depends on: every call returns, every arm64 word is exactly
//! 4 bytes, every x86 length is in 1..15 and never exceeds the bytes offered, and a linear sweep over any
//! byte string terminates. A trap, an out-of-bounds read or a non-advancing decode fails the test by
//! crashing or timing out, in Debug and in ReleaseSafe.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");

const arm64 = machre.disasm.arm64;
const x86len = machre.disasm.x86len;
const capstone = machre.disasm.capstone;
const insn = machre.disasm.insn;

/// Decodes one word both ways and checks the invariants; returns the size so nothing is optimised away.
fn oneArm64(arena: std.mem.Allocator, word: u32, pc: u64) !u8 {
    const text = try arm64.decodeOne(arena, word, pc, .arm);
    const sem = arm64.decodeSemantic(word, pc);
    if (text.size != 4 or sem.size != 4) return error.BadSize;
    if (text.kind != sem.kind) return error.KindMismatch;
    if (text.mnemonic.len == 0) return error.EmptyMnemonic;
    // A target, when present, must be 4-byte aligned relative to the PC (every arm64 branch is).
    if (text.target) |t| {
        if ((t & 3) != (pc & 3)) return error.MisalignedTarget;
    }
    std.mem.doNotOptimizeAway(text.operands.len);
    return text.size;
}

test "fuzz/decoders: 200k random arm64 words never trap and always decode to 4 bytes" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_a641);
    const random = prng.random();
    var i: u32 = 0;
    var bytes: u64 = 0;
    while (i < 200_000) : (i += 1) {
        bytes += try oneArm64(arena_state.allocator(), random.int(u32), 0x1_0000_0000 +% (@as(u64, i) *% 4));
        if (i % 1024 == 0) _ = arena_state.reset(.retain_capacity);
    }
    try std.testing.expectEqual(@as(u64, 200_000 * 4), bytes);
}

test "fuzz/decoders: structured arm64 sweep — every class with every field pattern" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    // Walk the top-level class field (bits 28..25) and the class-specific op field exhaustively while
    // filling the rest with adversarial patterns: this reaches decode paths a uniform sample rarely hits.
    const fills = [_]u32{ 0x0000_0000, 0xffff_ffff, 0x5555_5555, 0xaaaa_aaaa, 0x8000_0001, 0x7fff_fffe };
    var class: u32 = 0;
    while (class < 16) : (class += 1) {
        var rest: u32 = 0;
        while (rest < 64) : (rest += 1) {
            for (fills) |fill| {
                const word = (fill & ~@as(u32, 0x1fe0_0000)) | (class << 25) | (rest << 21);
                _ = try oneArm64(arena_state.allocator(), word, 0x1_0000_0000);
            }
            _ = arena_state.reset(.retain_capacity);
        }
    }
    // Every hint / barrier / PSTATE encoding.
    var crm: u32 = 0;
    while (crm < 16) : (crm += 1) {
        var op2: u32 = 0;
        while (op2 < 8) : (op2 += 1) {
            _ = try oneArm64(arena_state.allocator(), 0xd503_201f | (crm << 8) | (op2 << 5), 0);
            _ = try oneArm64(arena_state.allocator(), 0xd503_301f | (crm << 8) | (op2 << 5), 0);
            _ = try oneArm64(arena_state.allocator(), 0xd500_401f | (crm << 8) | (op2 << 5), 0);
            _ = arena_state.reset(.retain_capacity);
        }
    }
    // Every DecodeBitMasks (N, imms, immr) triple for both data sizes: never traps, never divides by zero.
    var n: u32 = 0;
    while (n < 2) : (n += 1) {
        var imms: u32 = 0;
        while (imms < 64) : (imms += 1) {
            var immr: u32 = 0;
            while (immr < 64) : (immr += 1) {
                std.mem.doNotOptimizeAway(arm64.decodeBitMasks(@intCast(n), @intCast(imms), @intCast(immr), 32));
                std.mem.doNotOptimizeAway(arm64.decodeBitMasks(@intCast(n), @intCast(imms), @intCast(immr), 64));
            }
        }
    }
}

test "fuzz/decoders: 200k random x86 byte strings always advance by 1..15 and never over-read" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_7836);
    const random = prng.random();
    var buf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 200_000) : (i += 1) {
        random.bytes(&buf);
        const n = random.uintLessThan(usize, buf.len + 1);
        const slice = buf[0..n];
        const len = x86len.length(slice);
        try std.testing.expect(len >= 1 and len <= x86len.max_len);
        if (n > 0) try std.testing.expect(len <= n);
        const one = try x86len.decodeOne(arena_state.allocator(), slice, 0x1_0000_0000 +% @as(u64, i));
        try std.testing.expectEqual(len, one.size);
        try std.testing.expectEqual(len, x86len.decodeSemantic(slice, 0).size);
        try std.testing.expect(one.mnemonic.len > 0);
        if (i % 1024 == 0) _ = arena_state.reset(.retain_capacity);
    }
}

test "fuzz/decoders: exhaustive x86 opcode space with every prefix combination" {
    var buf: [16]u8 = undefined;
    const prefixes = [_][]const u8{
        &.{},         &.{0x66},             &.{0x67},       &.{0xf2},             &.{0xf3},
        &.{0x48},     &.{ 0x66, 0x48 },     &.{0x4f},       &.{ 0xf3, 0x48 },     &.{0x64},
        &.{0x0f},     &.{ 0x0f, 0x38 },     &.{ 0x0f, 0x3a }, &.{ 0xc4, 0x02 },   &.{0xc5},
        &.{ 0x62, 0x01, 0x02 },
    };
    for (prefixes) |p| {
        var op: u32 = 0;
        while (op < 256) : (op += 1) {
            var modrm: u32 = 0;
            while (modrm < 256) : (modrm += 8) { // step over the reg field, covering every /digit
                @memset(&buf, 0x90);
                @memcpy(buf[0..p.len], p);
                buf[p.len] = @intCast(op);
                if (p.len + 1 < buf.len) buf[p.len + 1] = @intCast(modrm);
                const len = x86len.length(&buf);
                try std.testing.expect(len >= 1 and len <= x86len.max_len);
                // Truncated views must never report more bytes than exist.
                var take: usize = 1;
                while (take <= buf.len) : (take += 1) {
                    const l2 = x86len.length(buf[0..take]);
                    try std.testing.expect(l2 >= 1 and l2 <= take);
                }
            }
        }
    }
}

test "fuzz/decoders: a linear sweep over mutated hello-c __text bytes always terminates" {
    const gpa = std.testing.allocator;
    const seed = try helpers.readFixture(std.testing.io, gpa, "hello-c");
    defer gpa.free(seed);
    const buf = try gpa.alloc(u8, seed.len);
    defer gpa.free(buf);
    var prng = std.Random.DefaultPrng.init(0x6d61_6368_7265_5357);
    const random = prng.random();
    var round: u32 = 0;
    while (round < 64) : (round += 1) {
        @memcpy(buf, seed);
        var k: u8 = 0;
        const ops = random.intRangeAtMost(u8, 1, 8);
        while (k < ops) : (k += 1) buf[random.uintLessThan(usize, buf.len)] ^= random.int(u8);
        const len = random.uintLessThan(usize, buf.len + 1);
        const code = buf[0..len];

        // arm64: every aligned word.
        var i: usize = 0;
        while (i + 4 <= code.len) : (i += 4) {
            const one = arm64.decodeSemantic(std.mem.readInt(u32, code[i..][0..4], .little), 0x1_0000_0000 + i);
            std.mem.doNotOptimizeAway(one.kind);
        }
        // x86: a linear sweep must reach the end in at most `len` steps.
        var off: usize = 0;
        var steps: usize = 0;
        while (off < code.len) : (steps += 1) {
            const n = x86len.length(code[off..]);
            try std.testing.expect(n >= 1);
            off += n;
        }
        try std.testing.expect(steps <= code.len);
    }
}

// Smith fuzzer: arbitrary 32-bit words through the arm64 decoder.
test "fuzz/decoders: smith arm64 words" {
    const Ctx = struct {
        gpa: std.mem.Allocator,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var n: u8 = 0;
            while (n < 64 and !smith.eos()) : (n += 1) {
                const word = smith.value(u32);
                const pc = @as(u64, smith.value(u32)) << 2;
                _ = try oneArm64(arena, word, pc);
            }
            // An empty Smith still exercises the two boundary words.
            _ = try oneArm64(arena, 0x0000_0000, 0);
            _ = try oneArm64(arena, 0xffff_ffff, 0);
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = std.testing.allocator }, Ctx.testOne, .{ .corpus = &.{
        "\x20\xa0\x01\x91", // add x0, x1, #0x68
        "\xe1\x0f\x00\x14", // b .+0x3f84
        "\x7f\x23\x03\xd5", // pacibsp
        "\x00\x00\x00\x00", // udf #0
        "",
    } });
}

// Smith fuzzer: arbitrary byte strings through the x86 length decoder.
test "fuzz/decoders: smith x86 length decoder" {
    const Ctx = struct {
        gpa: std.mem.Allocator,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const code = buf[0..n];
            var off: usize = 0;
            var steps: usize = 0;
            while (off < code.len) : (steps += 1) {
                const one = try x86len.decodeOne(arena, code[off..], 0x1_0000_0000 + off);
                if (one.size == 0) return error.NoProgress;
                if (one.size > code.len - off) return error.OverRead;
                off += one.size;
            }
            if (steps > code.len) return error.TooManySteps;
            // The empty input must still be total.
            if (x86len.length(code[code.len..]) == 0) return error.NoProgress;
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = std.testing.allocator }, Ctx.testOne, .{ .corpus = &.{
        "\x55\x48\x89\xe5\x48\x83\xc7\x68", // push/mov/add prologue
        "\xe9\x5b\x3c\x00\x00", // jmp rel32
        "\xff\x25\x20\x30\x00\x00", // x86_64 stub
        "\xff\xff\xff\xff", // FF /7 (undefined) x4
        "",
    } });
}

// Smith fuzzer: Capstone's own decoder on arbitrary bytes (skipped on -Dcapstone=false).
test "fuzz/decoders: smith capstone text overlay" {
    if (!capstone.available) return error.SkipZigTest;
    const Ctx = struct {
        gpa: std.mem.Allocator,
        fn testOne(ctx: @This(), smith: *std.testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            inline for (.{ machre.core.arch.ArchName.arm64e, machre.core.arch.ArchName.x86_64 }) |arch| {
                var h = try capstone.Handle.open(arch, arch == .x86_64);
                defer h.close();
                const recs = try capstone.decodeText(&h, arena, buf[0..n], 0x1_0000_0000, 0);
                var prev: u64 = 0;
                for (recs) |r| {
                    if (r.size == 0) return error.ZeroSizeRecord;
                    if (r.addr < prev) return error.NonMonotonic;
                    prev = r.addr;
                }
            }
        }
    };
    try std.testing.fuzz(Ctx{ .gpa = std.testing.allocator }, Ctx.testOne, .{ .corpus = &.{
        "\x20\xa0\x01\x91\xe8\x03\x00\xaa",
        "\x55\x48\x89\xe5",
        "",
    } });
}

test "fuzz/decoders: backendFor is total over every ArchName" {
    inline for (comptime std.meta.tags(machre.core.arch.ArchName)) |a| {
        std.mem.doNotOptimizeAway(insn.backendFor(a, true));
        std.mem.doNotOptimizeAway(insn.backendFor(a, false));
        std.mem.doNotOptimizeAway(insn.builtinBackendFor(a));
    }
}
