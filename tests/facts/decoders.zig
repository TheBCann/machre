//! tests/facts/decoders.zig — corpus fact tests for WP7 (instruction decoders).
//!
//! Ground truth is produced programmatically: `otool -arch <a> -tv /bin/ls` is run through
//! `std.process.run` and diffed line by line against the built-in decoders (DESIGN §10.3 row
//! "bin-ls", disasm-notes A.4 / C.4). Every test that needs `/bin/ls` or `otool` returns
//! `error.SkipZigTest` when they are absent, and the Capstone tests skip on `-Dcapstone=false`.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");

const Limits = machre.core.limits.Limits;
const Diagnostics = machre.core.diag.Diagnostics;
const LoadedFile = machre.core.file.LoadedFile;
const Image = machre.core.image.Image;
const ArchName = machre.core.arch.ArchName;
const arm64 = machre.disasm.arm64;
const x86len = machre.disasm.x86len;
const capstone = machre.disasm.capstone;
const insn = machre.disasm.insn;

const bin_ls = "/bin/ls";

const Slice = struct {
    file: LoadedFile,
    img: Image,
    fn deinit(s: *Slice, gpa: std.mem.Allocator) void {
        s.file.deinit(gpa);
    }
};

/// Loads `path` and returns the slice whose arch is `want`, or null when the file or the slice is absent.
fn openSlice(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, path: []const u8, want: ArchName, limits: *const Limits, diags: *Diagnostics) !?Slice {
    var f = LoadedFile.load(gpa, arena, io, path, limits, diags) catch return null;
    errdefer f.deinit(gpa);
    var i: usize = 0;
    while (i < f.sliceCount()) : (i += 1) {
        const a = f.sliceArch(i) orelse continue;
        if (a.name != want) continue;
        const r = f.sliceReader(i) orelse continue;
        const off = f.sliceOffset(i) orelse 0;
        const img = Image.parse(arena, r, off, @intCast(i), limits, diags) catch continue;
        return Slice{ .file = f, .img = img };
    }
    f.deinit(gpa);
    return null;
}

/// One `otool -tv` row: address plus the text with otool's own `; …` comment removed.
const ToolRow = struct { addr: u64, mnemonic: []const u8, operands: []const u8 };

/// Runs `otool -arch <arch> -tv <path>` and parses its instruction rows (arena-owned).
fn otoolRows(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: std.Io, arch: []const u8, path: []const u8) !?[]const ToolRow {
    const res = std.process.run(gpa, io, .{
        .argv = &.{ "/usr/bin/otool", "-arch", arch, "-tv", path },
        .stdout_limit = .limited(16 << 20),
    }) catch return null;
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    var rows: std.ArrayList(ToolRow) = .empty;
    var it = std.mem.splitScalar(u8, res.stdout, '\n');
    while (it.next()) |line| {
        if (line.len < 17 or line[16] != '\t') continue;
        const addr = std.fmt.parseInt(u64, line[0..16], 16) catch continue;
        var rest = line[17..];
        if (std.mem.find(u8, rest, " ; ")) |c| rest = rest[0..c];
        const tab = std.mem.findScalar(u8, rest, '\t');
        const mnemonic = if (tab) |t| rest[0..t] else rest;
        const operands = if (tab) |t| std.mem.trim(u8, rest[t + 1 ..], " \t\r") else "";
        try rows.append(arena, .{
            .addr = addr,
            .mnemonic = try arena.dupe(u8, std.mem.trim(u8, mnemonic, " \t\r")),
            .operands = try arena.dupe(u8, operands),
        });
    }
    if (rows.items.len == 0) return null;
    return try rows.toOwnedSlice(arena);
}

test "facts/decoders: bin-ls arm64e __text prologue decodes to the otool -tV text" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var limits: Limits = .default;
    var diags = Diagnostics.init(arena, limits.max_diagnostics);

    var slice = (try openSlice(gpa, arena, io, bin_ls, .arm64e, &limits, &diags)) orelse return error.SkipZigTest;
    defer slice.deinit(gpa);
    const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
    const rows = (try otoolRows(gpa, arena, io, "arm64e", bin_ls)) orelse return error.SkipZigTest;

    // disasm-notes A.4: __text starts at 0x100000700 in the arm64e slice.
    try std.testing.expectEqual(@as(u64, 0x100000700), text.addr);
    const code = (slice.img.bytesAtVm(text.addr, 64) orelse return error.SkipZigTest).bytes;
    try std.testing.expectEqual(@as(usize, 64), code.len);

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const pc = text.addr + i * 4;
        const word = std.mem.readInt(u32, code[i * 4 ..][0..4], .little);
        const got = try arm64.decodeOne(arena, word, pc, .arm);
        const row = rows[i];
        try std.testing.expectEqual(pc, row.addr);
        try std.testing.expectEqualStrings(row.mnemonic, got.mnemonic);
        try std.testing.expectEqualStrings(row.operands, got.operands);
        try std.testing.expectEqual(@as(u8, 4), got.size);
        try std.testing.expect(got.valid);
    }
    // A.4 spot checks on the semantic fields.
    const b_stub = arm64.decodeSemantic(std.mem.readInt(u32, code[8..][0..4], .little), text.addr + 8);
    try std.testing.expectEqual(insn.Kind.branch, b_stub.kind);
    try std.testing.expectEqual(@as(?u64, 0x10000468c), b_stub.target);
}

test "facts/decoders: bin-ls arm64e __text decodes every word, no gaps, otool parity" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var limits: Limits = .default;
    var diags = Diagnostics.init(arena, limits.max_diagnostics);

    var slice = (try openSlice(gpa, arena, io, bin_ls, .arm64e, &limits, &diags)) orelse return error.SkipZigTest;
    defer slice.deinit(gpa);
    const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
    const rows = (try otoolRows(gpa, arena, io, "arm64e", bin_ls)) orelse return error.SkipZigTest;
    const code = (slice.img.bytesAtVm(text.addr, text.size) orelse return error.SkipZigTest).bytes;

    // Every 4-byte word is one instruction: the row count must equal the word count exactly.
    try std.testing.expectEqual(code.len / 4, rows.len);

    // A second arena for the per-instruction text: the image, `code` and `rows` live in `arena`
    // and must survive the whole loop.
    var tmp_state = std.heap.ArenaAllocator.init(gpa);
    defer tmp_state.deinit();
    var matched: usize = 0;
    var unknown: usize = 0;
    var simd_syntax: usize = 0;
    var unexpected: usize = 0;
    var i: usize = 0;
    while (i + 4 <= code.len) : (i += 4) {
        const pc = text.addr + i;
        const word = std.mem.readInt(u32, code[i..][0..4], .little);
        const got = try arm64.decodeOne(tmp_state.allocator(), word, pc, .arm);
        const row = rows[i / 4];
        try std.testing.expectEqual(pc, row.addr);
        if (std.mem.eql(u8, got.mnemonic, row.mnemonic) and std.mem.eql(u8, got.operands, row.operands)) {
            matched += 1;
        } else if (!got.valid) {
            unknown += 1;
        } else if (std.mem.findScalar(u8, row.mnemonic, '.') != null) {
            // Darwin spells SIMD as `movi.2d v0, #…`; the notes prescribe ARM syntax (`movi v0.2d, #…`).
            simd_syntax += 1;
        } else {
            std.debug.print("\nunexpected text for 0x{x:0>8} @0x{x}: otool `{s} {s}` machre `{s} {s}`\n", .{ word, pc, row.mnemonic, row.operands, got.mnemonic, got.operands });
            unexpected += 1;
        }
        _ = tmp_state.reset(.retain_capacity);
    }
    const total = code.len / 4;
    try std.testing.expect(total > 3800);
    // Every scalar integer / branch / load-store / system word in the whole of `/bin/ls` __text
    // is byte-identical to otool; the only differences are the documented SIMD syntax choice and
    // the handful of words outside the B.7 subset, which print `.inst` rather than a wrong mnemonic.
    try std.testing.expectEqual(@as(usize, 0), unexpected);
    try std.testing.expect(unknown <= 8);
    try std.testing.expect(simd_syntax <= 32);
    try std.testing.expect(matched + unknown + simd_syntax == total);
    try std.testing.expect(matched * 1000 / total >= 995);
}

test "facts/decoders: bin-ls x86_64 prologue — kinds and sizes match the otool -tV lines" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var limits: Limits = .default;
    var diags = Diagnostics.init(arena, limits.max_diagnostics);

    var slice = (try openSlice(gpa, arena, io, bin_ls, .x86_64, &limits, &diags)) orelse return error.SkipZigTest;
    defer slice.deinit(gpa);
    const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
    const rows = (try otoolRows(gpa, arena, io, "x86_64", bin_ls)) orelse return error.SkipZigTest;
    const code = (slice.img.bytesAtVm(text.addr, 64) orelse return error.SkipZigTest).bytes;

    // disasm-notes A.4: the first 64 bytes hold 20 instructions (the 20th ends at byte 63).
    var off: usize = 0;
    var i: usize = 0;
    while (off < 63) : (i += 1) {
        const pc = text.addr + off;
        const one = try x86len.decodeOne(arena, code[off..], pc);
        const row = rows[i];
        try std.testing.expectEqual(pc, row.addr);
        // Size parity: the next otool row is exactly `size` bytes on.
        if (i + 1 < rows.len) try std.testing.expectEqual(pc + one.size, rows[i + 1].addr);
        // Kind parity against otool's own mnemonic.
        const expect_kind: ?insn.Kind = if (std.mem.startsWith(u8, row.mnemonic, "push")) .push else if (std.mem.startsWith(u8, row.mnemonic, "pop")) .pop else if (std.mem.startsWith(u8, row.mnemonic, "ret")) .ret else if (std.mem.startsWith(u8, row.mnemonic, "call")) .call else if (std.mem.eql(u8, row.mnemonic, "jmp")) .branch else if (std.mem.startsWith(u8, row.mnemonic, "lea")) .lea else null;
        if (expect_kind) |k| try std.testing.expectEqual(k, one.kind);
        // The branch targets otool printed must be reproduced exactly.
        if (one.target) |t| {
            if (one.kind == .branch or one.kind == .call or one.kind == .cond_branch) {
                var buf: [32]u8 = undefined;
                const want = try std.fmt.bufPrint(&buf, "0x{x}", .{t});
                try std.testing.expectEqualStrings(want, row.operands);
            }
        }
        off += one.size;
    }
    try std.testing.expectEqual(@as(usize, 20), i);
    try std.testing.expectEqual(@as(usize, 63), off);
}

test "facts/decoders: bin-ls x86_64 length decoder reproduces the otool boundary run" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var limits: Limits = .default;
    var diags = Diagnostics.init(arena, limits.max_diagnostics);

    var slice = (try openSlice(gpa, arena, io, bin_ls, .x86_64, &limits, &diags)) orelse return error.SkipZigTest;
    defer slice.deinit(gpa);
    const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
    const rows = (try otoolRows(gpa, arena, io, "x86_64", bin_ls)) orelse return error.SkipZigTest;
    // disasm-notes A.4: the x86_64 __text starts at 0x100000718.
    try std.testing.expectEqual(@as(u64, 0x100000718), text.addr);

    // disasm-notes Part C: the first 6000 bytes of __text are the reference boundary run
    // (1496 instructions on the machine the notes were written on; the exact total depends on the
    // macOS build of /bin/ls, so the assertions below compare against the live `otool` instead).
    const run_len: u64 = 6000;
    const code = (slice.img.bytesAtVm(text.addr, run_len) orelse return error.SkipZigTest).bytes;
    try std.testing.expectEqual(@as(usize, run_len), code.len);

    // otool's boundary set for the same range, plus its per-region row counts.
    var tool: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer tool.deinit(gpa);
    // The inline jump table of C.4: int32 entries at 0x1000014b0, ending at 0x100001620. otool
    // prints garbage inside it (`insl`, `ljmpl`, `.byte 0xff #bad opcode`) and so do we.
    const table_start: u64 = 0x1000014b0;
    const table_end: u64 = 0x100001620;
    var tool_before: usize = 0;
    var tool_resync: ?u64 = null;
    for (rows) |r| {
        if (r.addr < text.addr or r.addr >= text.addr + run_len) continue;
        try tool.put(gpa, r.addr, {});
        if (r.addr < table_start) tool_before += 1;
        if (r.addr >= table_end and (tool_resync == null or r.addr < tool_resync.?)) tool_resync = r.addr;
    }
    try std.testing.expect(tool.count() > 1000);
    try std.testing.expect(tool_before > 700);
    const resync_at = tool_resync orelse return error.SkipZigTest;
    // "resynchronises immediately after an inline jump table": otool's own first post-table
    // boundary is within one instruction of the table end.
    try std.testing.expect(resync_at >= table_end and resync_at - table_end < 16);

    var tmp_state = std.heap.ArenaAllocator.init(gpa);
    defer tmp_state.deinit();
    var count: usize = 0;
    var before: usize = 0;
    var after: usize = 0;
    var post_table: usize = 0;
    var merges: usize = 0;
    var first_post: ?u64 = null;
    var off: usize = 0;
    while (off < code.len) {
        const pc = text.addr + off;
        const one = try x86len.decodeOne(tmp_state.allocator(), code[off..], pc);
        try std.testing.expect(one.size >= 1 and one.size <= 15);
        try std.testing.expectEqual(pc, one.addr);
        count += 1;
        if (pc < table_start) {
            if (tool.contains(pc)) before += 1;
            // No otool boundary may fall strictly inside one of our instructions.
            var k: u8 = 1;
            while (k < one.size) : (k += 1) {
                if (tool.contains(pc + k)) merges += 1;
            }
        } else if (pc >= table_end) {
            if (first_post == null) first_post = pc;
            post_table += 1;
            if (tool.contains(pc)) after += 1;
        }
        off += one.size;
        _ = tmp_state.reset(.retain_capacity);
    }
    // Before the inline data the two decoders agree on every single boundary.
    try std.testing.expectEqual(@as(usize, 0), merges);
    try std.testing.expectEqual(tool_before, before);
    // And the sweep resynchronises onto otool's own first post-table boundary and never drifts again.
    try std.testing.expectEqual(@as(?u64, resync_at), first_post);
    try std.testing.expectEqual(post_table, after);
    // Order of magnitude of the Part C reference run (1496 on the notes' machine).
    try std.testing.expect(count > 1400 and count < 1700);
}

test "facts/decoders: x86 decoder never stalls on the whole bin-ls __text" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var limits: Limits = .paranoid;
    var diags = Diagnostics.init(arena_state.allocator(), limits.max_diagnostics);

    var slice = (try openSlice(gpa, arena_state.allocator(), io, bin_ls, .x86_64, &limits, &diags)) orelse return error.SkipZigTest;
    defer slice.deinit(gpa);
    const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
    const code = (slice.img.bytesAtVm(text.addr, text.size) orelse return error.SkipZigTest).bytes;
    var off: usize = 0;
    var steps: usize = 0;
    while (off < code.len) : (steps += 1) {
        off += x86len.length(code[off..]);
    }
    try std.testing.expect(steps > 1000);
    try std.testing.expect(steps <= code.len);
}

test "facts/decoders: Capstone maps the bin-ls prologues to the same (address, size) records" {
    if (!capstone.available) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var limits: Limits = .default;
    var diags = Diagnostics.init(arena, limits.max_diagnostics);

    // arm64e: 16 words, 16 Capstone records, all 4 bytes.
    {
        var slice = (try openSlice(gpa, arena, io, bin_ls, .arm64e, &limits, &diags)) orelse return error.SkipZigTest;
        defer slice.deinit(gpa);
        const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
        const code = (slice.img.bytesAtVm(text.addr, 64) orelse return error.SkipZigTest).bytes;
        var h = try capstone.Handle.open(.arm64e, false);
        defer h.close();
        const recs = try capstone.decodeText(&h, arena, code, text.addr, 0);
        try std.testing.expectEqual(@as(usize, 16), recs.len);
        for (recs, 0..) |r, i| {
            const pc = text.addr + i * 4;
            try std.testing.expectEqual(pc, r.addr);
            try std.testing.expectEqual(@as(u8, 4), r.size);
            const built = arm64.decodeSemantic(std.mem.readInt(u32, code[i * 4 ..][0..4], .little), pc);
            try std.testing.expectEqual(built.size, r.size);
            try std.testing.expect(r.mnemonic.len > 0);
        }
    }
    // x86_64: Capstone's boundaries equal the built-in length decoder's over the 64-byte prologue.
    {
        var slice = (try openSlice(gpa, arena, io, bin_ls, .x86_64, &limits, &diags)) orelse return error.SkipZigTest;
        defer slice.deinit(gpa);
        const text = slice.img.sectionByName("__TEXT", "__text") orelse return error.SkipZigTest;
        const code = (slice.img.bytesAtVm(text.addr, 64) orelse return error.SkipZigTest).bytes;
        var h = try capstone.Handle.open(.x86_64, true);
        defer h.close();
        const recs = try capstone.decodeText(&h, arena, code, text.addr, 0);
        try std.testing.expect(recs.len >= 20);
        var off: usize = 0;
        var i: usize = 0;
        while (off < 63 and i < recs.len) : (i += 1) {
            try std.testing.expectEqual(text.addr + off, recs[i].addr);
            try std.testing.expectEqual(x86len.length(code[off..]), recs[i].size);
            off += recs[i].size;
        }
        try std.testing.expectEqual(@as(usize, 20), i);
    }
}

test "facts/decoders: Handle.open(.arm64, att=true) does not apply the ATT option" {
    if (!capstone.available) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // CS_OPT_SYNTAX_ATT is invalid on an ARM64 handle; open() must silently skip it (DESIGN §4.24).
    var h = try capstone.Handle.open(.arm64, true);
    defer h.close();
    const recs = try capstone.decodeText(&h, arena, &[_]u8{ 0xc0, 0x03, 0x5f, 0xd6 }, 0x100000000, 0);
    try std.testing.expectEqual(@as(usize, 1), recs.len);
    try std.testing.expectEqualStrings("ret", recs[0].mnemonic);
    // The version probe must agree with the ABI the externs were written against.
    const v = capstone.version().?;
    try std.testing.expectEqual(@as(u8, 5), v.major);
}

test "facts/decoders: unsupported arch and a missing Capstone both surface as typed errors" {
    if (capstone.available) {
        try std.testing.expectError(error.UnsupportedArch, capstone.Handle.open(.ppc64, false));
    } else {
        try std.testing.expectError(error.CapstoneUnavailable, capstone.Handle.open(.arm64, false));
        try std.testing.expect(capstone.version() == null);
    }
    try std.testing.expectEqual(insn.Backend.builtin_arm64, insn.backendFor(.arm64e, false));
    try std.testing.expectEqual(insn.Backend.builtin_x86len, insn.backendFor(.x86_64, false));
}

test "facts/decoders: every corpus fixture's __text decodes without a stall" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var checked: usize = 0;
    for (helpers.healthy_fixtures) |name| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var limits: Limits = .paranoid;
        var diags = Diagnostics.init(arena, limits.max_diagnostics);
        const path = try helpers.fixturePath(arena, name);
        var f = LoadedFile.load(gpa, arena, io, path, &limits, &diags) catch continue;
        defer f.deinit(gpa);
        var idx: usize = 0;
        while (idx < f.sliceCount()) : (idx += 1) {
            const a = f.sliceArch(idx) orelse continue;
            const r = f.sliceReader(idx) orelse continue;
            const off = f.sliceOffset(idx) orelse 0;
            const img = Image.parse(arena, r, off, @intCast(idx), &limits, &diags) catch continue;
            const text = img.sectionByName("__TEXT", "__text") orelse continue;
            const vb = img.bytesAtVm(text.addr, text.size) orelse continue;
            checked += 1;
            switch (a.name) {
                .arm64, .arm64e, .arm64v8 => {
                    var i: usize = 0;
                    while (i + 4 <= vb.bytes.len) : (i += 4) {
                        const one = arm64.decodeSemantic(std.mem.readInt(u32, vb.bytes[i..][0..4], .little), text.addr + i);
                        try std.testing.expectEqual(@as(u8, 4), one.size);
                    }
                },
                .x86_64, .x86_64h => {
                    var i: usize = 0;
                    while (i < vb.bytes.len) {
                        const n = x86len.length(vb.bytes[i..]);
                        try std.testing.expect(n >= 1);
                        i += n;
                    }
                },
                else => {},
            }
        }
    }
    try std.testing.expect(checked >= 10);
}
