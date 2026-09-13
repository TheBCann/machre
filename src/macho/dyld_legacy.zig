//! macho/dyld_legacy.zig — LC_DYLD_INFO(_ONLY) rebase/bind/weak/lazy opcode streams (incl. THREADED).
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const reader_mod = @import("../core/reader.zig");
const Reader = reader_mod.Reader;
const Cursor = reader_mod.Cursor;

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;

pub const Rebase = struct { seg_index: u8, seg_offset: u64, vmaddr: ?u64, type: u8, stream_offset: u32 };
pub const BindKind = enum { bind, weak, lazy };
pub const Bind = struct {
    seg_index: u8,
    seg_offset: u64,
    vmaddr: ?u64,
    lib_ordinal: i32,
    symbol: []const u8,
    flags: u8,
    type: u8,
    addend: i64,
    kind: BindKind,
    /// Offset of this entry's first opcode in its stream (lazy: what __stub_helper's `pushq $off` refers to).
    stream_offset: u32,

    pub fn weakImport(b: Bind) bool {
        return b.flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0;
    }
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
        .rebases = &.{},
        .binds = &.{},
        .threaded = null,
        .truncated = false,
        .counts = .{ .rebase = 0, .bind = 0, .weak = 0, .lazy = 0 },
    };
};

const State = struct {
    arena: Allocator,
    img: *const Image,
    limits: *const Limits,
    diags: *Diagnostics,
    out: *DyldInfo,
    rebases: *std.ArrayList(Rebase),
    binds: *std.ArrayList(Bind),
    ptr_size: u64,

    fn vmOf(s: *State, seg_index: u8, seg_offset: u64) ?u64 {
        if (seg_index >= s.img.segments.len) {
            if (!s.diags.has(.legacy, .ordinal_out_of_range))
                s.diags.warn(.legacy, .ordinal_out_of_range, null, "opcode stream names segment {d} but the image has {d}", .{ seg_index, s.img.segments.len });
            return null;
        }
        return s.img.segments[seg_index].vmaddr +% seg_offset;
    }
    fn budgetLeft(s: *State) u64 {
        const used: u64 = s.rebases.items.len + s.binds.items.len;
        return s.limits.max_fixups -| used;
    }
    fn limitHit(s: *State) void {
        if (!s.diags.has(.legacy, .limit_reached))
            s.diags.warn(.legacy, .limit_reached, null, "dyld opcode stream produced more than limits.max_fixups {d} entries; clamped", .{s.limits.max_fixups});
        s.out.truncated = true;
    }
};

/// Null when no LC_DYLD_INFO(_ONLY).
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?DyldInfo {
    const c = img.findCmd(.DYLD_INFO_ONLY) orelse img.findCmd(.DYLD_INFO) orelse return null;
    const di = c.reader().structAt(std.macho.dyld_info_command, 0, c.endian) orelse {
        diags.err(.legacy, .cmdsize_invalid, c.offset, "LC_DYLD_INFO is shorter than 48 bytes", .{});
        var v = DyldInfo.empty;
        v.truncated = true;
        return v;
    };
    var out = DyldInfo.empty;
    out.cmd = di;
    var rebases: std.ArrayList(Rebase) = .empty;
    var binds: std.ArrayList(Bind) = .empty;
    var st: State = .{
        .arena = arena,
        .img = img,
        .limits = limits,
        .diags = diags,
        .out = &out,
        .rebases = &rebases,
        .binds = &binds,
        .ptr_size = if (img.hdr.is_64) 8 else 4,
    };
    if (di.rebase_size != 0) {
        if (streamReader(img, di.rebase_off, di.rebase_size, limits, diags, &out, "rebase")) |r| try runRebase(&st, r);
    }
    if (di.bind_size != 0) {
        if (streamReader(img, di.bind_off, di.bind_size, limits, diags, &out, "bind")) |r| try runBind(&st, r, .bind);
    }
    if (di.weak_bind_size != 0) {
        if (streamReader(img, di.weak_bind_off, di.weak_bind_size, limits, diags, &out, "weak bind")) |r| try runBind(&st, r, .weak);
    }
    if (di.lazy_bind_size != 0) {
        if (streamReader(img, di.lazy_bind_off, di.lazy_bind_size, limits, diags, &out, "lazy bind")) |r| try runBind(&st, r, .lazy);
    }
    out.rebases = try rebases.toOwnedSlice(arena);
    out.binds = try binds.toOwnedSlice(arena);
    out.counts.rebase = @intCast(out.rebases.len);
    for (out.binds) |b| switch (b.kind) {
        .bind => out.counts.bind += 1,
        .weak => out.counts.weak += 1,
        .lazy => out.counts.lazy += 1,
    };
    return out;
}

fn streamReader(img: *const Image, off: u32, size: u32, limits: *const Limits, diags: *Diagnostics, out: *DyldInfo, what: []const u8) ?Reader {
    if (off >= img.r.len() or !img.r.contains(off, size)) {
        diags.err(.legacy, .truncated, off, "{s} stream at offset {d} size {d} lies outside the {d}-byte slice; skipped", .{ what, off, size, img.r.len() });
        out.truncated = true;
        return null;
    }
    if (size > limits.max_opcode_bytes) {
        diags.warn(.legacy, .limit_reached, off, "{s} stream is {d} bytes, more than limits.max_opcode_bytes {d}; skipped", .{ what, size, limits.max_opcode_bytes });
        out.truncated = true;
        return null;
    }
    return img.linkeditReader(off, size, diags, .legacy);
}

fn runRebase(s: *State, r: Reader) Allocator.Error!void {
    var c = r.cursor(0).?;
    var seg_index: u8 = 0;
    var seg_offset: u64 = 0;
    var rtype: u8 = 0;
    while (!c.atEnd()) {
        const op_off: u32 = @intCast(c.pos);
        const byte = c.takeU8() catch return;
        const op = byte & REBASE_OPCODE_MASK;
        const imm = byte & REBASE_IMMEDIATE_MASK;
        switch (op) {
            0x00 => return, // DONE
            0x10 => rtype = imm, // SET_TYPE_IMM
            0x20 => { // SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm;
                seg_offset = c.takeUleb() catch return malformed(s, op_off, "rebase");
            },
            0x30 => seg_offset +%= (c.takeUlebWrapping() catch return malformed(s, op_off, "rebase")), // ADD_ADDR_ULEB
            0x40 => seg_offset +%= @as(u64, imm) * s.ptr_size, // ADD_ADDR_IMM_SCALED
            0x50 => { // DO_REBASE_IMM_TIMES
                if (!try doRebase(s, &seg_index, &seg_offset, rtype, imm, 0, op_off)) return;
            },
            0x60 => { // DO_REBASE_ULEB_TIMES
                const n = c.takeUleb() catch return malformed(s, op_off, "rebase");
                if (!try doRebase(s, &seg_index, &seg_offset, rtype, n, 0, op_off)) return;
            },
            0x70 => { // DO_REBASE_ADD_ADDR_ULEB
                const skip = c.takeUlebWrapping() catch return malformed(s, op_off, "rebase");
                if (!try doRebase(s, &seg_index, &seg_offset, rtype, 1, skip, op_off)) return;
            },
            0x80 => { // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                const n = c.takeUleb() catch return malformed(s, op_off, "rebase");
                const skip = c.takeUlebWrapping() catch return malformed(s, op_off, "rebase");
                if (!try doRebase(s, &seg_index, &seg_offset, rtype, n, skip, op_off)) return;
            },
            else => {
                if (!s.diags.has(.legacy, .opcode_malformed))
                    s.diags.warn(.legacy, .opcode_malformed, r.base + op_off, "unknown rebase opcode 0x{x} at stream offset {d}; stopped", .{ op, op_off });
                s.out.truncated = true;
                return;
            },
        }
    }
}

/// Emits `count` rebases, `ptr_size + skip` apart. Returns false when the fixup budget ran out.
fn doRebase(s: *State, seg_index: *u8, seg_offset: *u64, rtype: u8, count: u64, skip: u64, op_off: u32) Allocator.Error!bool {
    var n = count;
    const left = s.budgetLeft();
    if (n > left) {
        s.limitHit();
        n = left;
        if (n == 0) return false;
    }
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        try s.rebases.append(s.arena, .{
            .seg_index = seg_index.*,
            .seg_offset = seg_offset.*,
            .vmaddr = s.vmOf(seg_index.*, seg_offset.*),
            .type = rtype,
            .stream_offset = op_off,
        });
        seg_offset.* +%= s.ptr_size +% skip;
    }
    return n == count;
}

fn runBind(s: *State, r: Reader, kind: BindKind) Allocator.Error!void {
    var c = r.cursor(0).?;
    var seg_index: u8 = 0;
    var seg_offset: u64 = 0;
    var lib_ordinal: i32 = 0;
    var symbol: []const u8 = "";
    var flags: u8 = 0;
    var btype: u8 = 0;
    var addend: i64 = 0;
    var entry_begin: u32 = 0;
    while (!c.atEnd()) {
        const op_off: u32 = @intCast(c.pos);
        const byte = c.takeU8() catch return;
        const op = byte & BIND_OPCODE_MASK;
        const imm = byte & BIND_IMMEDIATE_MASK;
        switch (op) {
            0x00 => { // DONE: ends a non-lazy stream; the lazy stream continues past every DONE
                if (kind != .lazy) return;
                entry_begin = @intCast(c.pos);
                lib_ordinal = 0;
                symbol = "";
                flags = 0;
                btype = 0;
                addend = 0;
            },
            0x10 => lib_ordinal = imm, // SET_DYLIB_ORDINAL_IMM
            0x20 => { // SET_DYLIB_ORDINAL_ULEB
                const v = c.takeUleb() catch return malformed(s, op_off, "bind");
                lib_ordinal = if (v > std.math.maxInt(i32)) 0 else @intCast(v);
            },
            0x30 => lib_ordinal = if (imm == 0) 0 else @as(i32, imm) - 16, // SET_DYLIB_SPECIAL_IMM
            0x40 => { // SET_SYMBOL_TRAILING_FLAGS_IMM
                flags = imm;
                symbol = c.takeCstr(s.limits.max_symbol_name) catch return malformed(s, op_off, "bind");
            },
            0x50 => btype = imm, // SET_TYPE_IMM
            0x60 => addend = c.takeSleb() catch return malformed(s, op_off, "bind"), // SET_ADDEND_SLEB
            0x70 => { // SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm;
                seg_offset = c.takeUleb() catch return malformed(s, op_off, "bind");
            },
            0x80 => seg_offset +%= (c.takeUlebWrapping() catch return malformed(s, op_off, "bind")), // ADD_ADDR_ULEB
            0x90 => { // DO_BIND
                if (!try doBind(s, kind, seg_index, &seg_offset, lib_ordinal, symbol, flags, btype, addend, 1, 0, if (kind == .lazy) entry_begin else op_off)) return;
            },
            0xA0 => { // DO_BIND_ADD_ADDR_ULEB
                const skip = c.takeUlebWrapping() catch return malformed(s, op_off, "bind");
                if (!try doBind(s, kind, seg_index, &seg_offset, lib_ordinal, symbol, flags, btype, addend, 1, skip, if (kind == .lazy) entry_begin else op_off)) return;
            },
            0xB0 => { // DO_BIND_ADD_ADDR_IMM_SCALED
                if (!try doBind(s, kind, seg_index, &seg_offset, lib_ordinal, symbol, flags, btype, addend, 1, @as(u64, imm) * s.ptr_size, if (kind == .lazy) entry_begin else op_off)) return;
            },
            0xC0 => { // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                const n = c.takeUleb() catch return malformed(s, op_off, "bind");
                const skip = c.takeUlebWrapping() catch return malformed(s, op_off, "bind");
                if (!try doBind(s, kind, seg_index, &seg_offset, lib_ordinal, symbol, flags, btype, addend, n, skip, if (kind == .lazy) entry_begin else op_off)) return;
            },
            0xD0 => { // THREADED
                switch (imm) {
                    0 => {
                        const size = c.takeUleb() catch return malformed(s, op_off, "bind");
                        s.out.threaded = .{ .ordinal_table_size = @min(size, s.limits.max_imports), .applies = if (s.out.threaded) |t| t.applies else 0 };
                    },
                    1 => {
                        const prev = s.out.threaded orelse Threaded{ .ordinal_table_size = 0, .applies = 0 };
                        s.out.threaded = .{ .ordinal_table_size = prev.ordinal_table_size, .applies = prev.applies +| 1 };
                    },
                    else => {
                        if (!s.diags.has(.legacy, .opcode_malformed))
                            s.diags.warn(.legacy, .opcode_malformed, r.base + op_off, "unknown THREADED sub-opcode {d} at stream offset {d}", .{ imm, op_off });
                        s.out.truncated = true;
                    },
                }
            },
            else => {
                if (!s.diags.has(.legacy, .opcode_malformed))
                    s.diags.warn(.legacy, .opcode_malformed, r.base + op_off, "unknown bind opcode 0x{x} at stream offset {d}; stopped", .{ op, op_off });
                s.out.truncated = true;
                return;
            },
        }
    }
}

fn doBind(
    s: *State,
    kind: BindKind,
    seg_index: u8,
    seg_offset: *u64,
    lib_ordinal: i32,
    symbol: []const u8,
    flags: u8,
    btype: u8,
    addend: i64,
    count: u64,
    skip: u64,
    stream_offset: u32,
) Allocator.Error!bool {
    var n = count;
    const left = s.budgetLeft();
    if (n > left) {
        s.limitHit();
        n = left;
        if (n == 0) return false;
    }
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        try s.binds.append(s.arena, .{
            .seg_index = seg_index,
            .seg_offset = seg_offset.*,
            .vmaddr = s.vmOf(seg_index, seg_offset.*),
            .lib_ordinal = lib_ordinal,
            .symbol = symbol,
            .flags = flags,
            .type = btype,
            .addend = addend,
            .kind = kind,
            .stream_offset = stream_offset,
        });
        seg_offset.* +%= s.ptr_size +% skip;
    }
    return n == count;
}

fn malformed(s: *State, off: u32, what: []const u8) void {
    if (!s.diags.has(.legacy, .opcode_malformed))
        s.diags.warn(.legacy, .opcode_malformed, off, "{s} stream: malformed LEB128 or unterminated string at offset {d}; stopped", .{ what, off });
    s.out.truncated = true;
}

pub const OpTrace = struct { offset: u32, opcode: u8, imm: u8, text: []const u8 };
/// Raw opcode trace of one stream (`dyld --opcodes`).
pub fn trace(arena: Allocator, stream: []const u8, kind: enum { rebase, bind }, limits: *const Limits) Allocator.Error![]const OpTrace {
    var out: std.ArrayList(OpTrace) = .empty;
    const r = Reader.init(stream, 0);
    var c = r.cursor(0) orelse return &.{};
    var steps: u32 = 0;
    while (!c.atEnd() and steps < limits.max_fixups) : (steps += 1) {
        const off: u32 = @intCast(c.pos);
        const byte = c.takeU8() catch break;
        const op = byte & 0xF0;
        const imm = byte & 0x0F;
        var text: []const u8 = "";
        if (kind == .rebase) {
            text = switch (op) {
                0x00 => "REBASE_OPCODE_DONE",
                0x10 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_SET_TYPE_IMM({d})", .{imm}),
                0x20 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg={d}, off=0x{x})", .{ imm, c.takeUleb() catch 0 }),
                0x30 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_ADD_ADDR_ULEB(0x{x})", .{c.takeUlebWrapping() catch 0}),
                0x40 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_ADD_ADDR_IMM_SCALED({d})", .{imm}),
                0x50 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_DO_REBASE_IMM_TIMES({d})", .{imm}),
                0x60 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_DO_REBASE_ULEB_TIMES({d})", .{c.takeUleb() catch 0}),
                0x70 => try std.fmt.allocPrint(arena, "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB(0x{x})", .{c.takeUlebWrapping() catch 0}),
                0x80 => blk: {
                    const n = c.takeUleb() catch 0;
                    const skip = c.takeUlebWrapping() catch 0;
                    break :blk try std.fmt.allocPrint(arena, "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(count={d}, skip=0x{x})", .{ n, skip });
                },
                else => "REBASE_OPCODE_?",
            };
        } else {
            text = switch (op) {
                0x00 => "BIND_OPCODE_DONE",
                0x10 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM({d})", .{imm}),
                0x20 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB({d})", .{c.takeUleb() catch 0}),
                0x30 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM({d})", .{if (imm == 0) @as(i32, 0) else @as(i32, imm) - 16}),
                0x40 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM(flags=0x{x}, \"{s}\")", .{ imm, c.takeCstr(limits.max_symbol_name) catch "" }),
                0x50 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_TYPE_IMM({d})", .{imm}),
                0x60 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_ADDEND_SLEB({d})", .{c.takeSleb() catch 0}),
                0x70 => try std.fmt.allocPrint(arena, "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg={d}, off=0x{x})", .{ imm, c.takeUleb() catch 0 }),
                0x80 => try std.fmt.allocPrint(arena, "BIND_OPCODE_ADD_ADDR_ULEB(0x{x})", .{c.takeUlebWrapping() catch 0}),
                0x90 => "BIND_OPCODE_DO_BIND",
                0xA0 => try std.fmt.allocPrint(arena, "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB(0x{x})", .{c.takeUlebWrapping() catch 0}),
                0xB0 => try std.fmt.allocPrint(arena, "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED({d})", .{imm}),
                0xC0 => blk: {
                    const n = c.takeUleb() catch 0;
                    const skip = c.takeUlebWrapping() catch 0;
                    break :blk try std.fmt.allocPrint(arena, "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB(count={d}, skip=0x{x})", .{ n, skip });
                },
                0xD0 => if (imm == 0)
                    try std.fmt.allocPrint(arena, "BIND_OPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB({d})", .{c.takeUleb() catch 0})
                else
                    "BIND_OPCODE_THREADED_APPLY",
                else => "BIND_OPCODE_?",
            };
        }
        try out.append(arena, .{ .offset = off, .opcode = op, .imm = imm, .text = text });
    }
    return out.toOwnedSlice(arena);
}

// ---- tests ----
const test_bind_stream = [_]u8{
    0x13, // SET_DYLIB_ORDINAL_IMM(3)
    0x40, '_', 'x', 0x00, // SET_SYMBOL_TRAILING_FLAGS_IMM(0) "_x"
    0x51, // SET_TYPE_IMM(1)
    0x72, 0x90, 0x01, // SET_SEGMENT_AND_OFFSET_ULEB(seg 2, 0x90)
    0x90, // DO_BIND
    0x00, // DONE
};

test "dyld_legacy: bind opcode stream decodes the format-notes sample" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ops = try trace(a, &test_bind_stream, .bind, &Limits.default);
    try std.testing.expectEqual(@as(usize, 6), ops.len);
    try std.testing.expectEqualStrings("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM(3)", ops[0].text);
    try std.testing.expectEqualStrings("BIND_OPCODE_DO_BIND", ops[4].text);
    try std.testing.expectEqualStrings("BIND_OPCODE_DONE", ops[5].text);
    const rb = [_]u8{ 0x11, 0x22, 0x50, 0x53, 0x43, 0x70, 0x18, 0x52, 0x42, 0x80, 0xc5, 0x01, 0x18 };
    const rops = try trace(a, &rb, .rebase, &Limits.default);
    try std.testing.expectEqualStrings("REBASE_OPCODE_SET_TYPE_IMM(1)", rops[0].text);
    try std.testing.expectEqualStrings("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg=2, off=0x50)", rops[1].text);
    try std.testing.expectEqualStrings("REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(count=197, skip=0x18)", rops[rops.len - 1].text);
}

test "dyld_legacy: trace never runs past the end for any prefix" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var len: usize = 0;
    while (len <= test_bind_stream.len) : (len += 1) {
        _ = try trace(a, test_bind_stream[0..len], .bind, &Limits.paranoid);
        _ = try trace(a, test_bind_stream[0..len], .rebase, &Limits.paranoid);
    }
}
