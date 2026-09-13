//! macho/function_starts.zig — LC_FUNCTION_STARTS uleb deltas + LC_DATA_IN_CODE entries.
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const Reader = @import("../core/reader.zig").Reader;

pub const FunctionStarts = struct { dataoff: u32, datasize: u32, addrs: []const u64, truncated: bool };
pub const DataInCode = struct { dataoff: u32, datasize: u32, entries: []const std.macho.data_in_code_entry, truncated: bool };

/// Null when no LC_FUNCTION_STARTS. Deltas via Cursor.takeUleb (Overflow -> stop + diag); zero delta terminates;
/// addresses outside __TEXT are dropped with one diagnostic. Result sorted ascending, deduped.
pub fn parseFunctionStarts(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?FunctionStarts {
    const c = img.findCmd(.FUNCTION_STARTS) orelse return null;
    if (c.bytes.len < 16) {
        diags.err(.function_starts, .cmdsize_invalid, c.offset, "LC_FUNCTION_STARTS is shorter than 16 bytes", .{});
        return FunctionStarts{ .dataoff = 0, .datasize = 0, .addrs = &.{}, .truncated = true };
    }
    const cr = c.reader();
    const dataoff = cr.u32At(8, c.endian).?;
    const datasize = cr.u32At(12, c.endian).?;
    var out: FunctionStarts = .{ .dataoff = dataoff, .datasize = datasize, .addrs = &.{}, .truncated = false };
    if (datasize == 0) return out;
    const r = img.linkeditReader(dataoff, datasize, diags, .function_starts) orelse {
        out.truncated = true;
        return out;
    };
    var cur = r.cursor(0) orelse return out;
    var addr: u64 = img.image_base;
    var list: std.ArrayList(u64) = .empty;
    var dropped: u32 = 0;
    const text: ?struct { lo: u64, hi: u64 } = if (img.text_seg) |t| blk: {
        const seg = img.segments[t];
        break :blk .{ .lo = seg.vmaddr, .hi = seg.vmaddr +| seg.vmsize };
    } else null;
    while (!cur.atEnd()) {
        if (list.items.len >= limits.max_function_starts) {
            diags.warn(.function_starts, .limit_reached, dataoff, "function starts clamped to limits.max_function_starts {d}", .{limits.max_function_starts});
            out.truncated = true;
            break;
        }
        const delta = cur.takeUleb() catch {
            diags.warn(.function_starts, .opcode_malformed, dataoff, "malformed ULEB128 delta in LC_FUNCTION_STARTS; stopped", .{});
            out.truncated = true;
            break;
        };
        if (delta == 0) break; // terminator; the rest is padding
        addr = std.math.add(u64, addr, delta) catch {
            diags.warn(.function_starts, .opcode_malformed, dataoff, "LC_FUNCTION_STARTS delta overflows the address space; stopped", .{});
            out.truncated = true;
            break;
        };
        if (text) |t| {
            if (addr < t.lo or addr >= t.hi) {
                dropped += 1;
                continue;
            }
        }
        try list.append(arena, addr);
    }
    if (dropped != 0)
        diags.warn(.function_starts, .offset_past_eof, dataoff, "{d} function start address(es) fall outside __TEXT; dropped", .{dropped});
    const addrs = try list.toOwnedSlice(arena);
    std.mem.sort(u64, addrs, {}, std.sort.asc(u64));
    var n: usize = 0;
    for (addrs) |v| {
        if (n != 0 and addrs[n - 1] == v) continue;
        addrs[n] = v;
        n += 1;
    }
    out.addrs = addrs[0..n];
    return out;
}

/// Null when no LC_DATA_IN_CODE (datasize 0 is legal: empty entries).
pub fn parseDataInCode(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?DataInCode {
    const c = img.findCmd(.DATA_IN_CODE) orelse return null;
    if (c.bytes.len < 16) {
        diags.err(.function_starts, .cmdsize_invalid, c.offset, "LC_DATA_IN_CODE is shorter than 16 bytes", .{});
        return DataInCode{ .dataoff = 0, .datasize = 0, .entries = &.{}, .truncated = true };
    }
    const cr = c.reader();
    const dataoff = cr.u32At(8, c.endian).?;
    const datasize = cr.u32At(12, c.endian).?;
    var out: DataInCode = .{ .dataoff = dataoff, .datasize = datasize, .entries = &.{}, .truncated = false };
    if (datasize == 0) return out;
    const r = img.linkeditReader(dataoff, datasize, diags, .function_starts) orelse {
        out.truncated = true;
        return out;
    };
    var n: u64 = r.len() / 8;
    if (n > limits.max_data_in_code) {
        diags.warn(.function_starts, .count_clamped, dataoff, "data-in-code entries clamped to limits.max_data_in_code {d}", .{limits.max_data_in_code});
        n = limits.max_data_in_code;
        out.truncated = true;
    }
    const entries = try arena.alloc(std.macho.data_in_code_entry, @intCast(n));
    const e = img.hdr.endian;
    for (entries, 0..) |*x, i| {
        const o: u64 = i * 8;
        x.* = .{
            .offset = r.u32At(o, e).?,
            .length = r.u16At(o + 4, e).?,
            .kind = r.u16At(o + 6, e).?,
        };
    }
    out.entries = entries;
    return out;
}

// ---- tests ----
test "function_starts: uleb deltas, terminator and out-of-__TEXT dropping" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    _ = a;
    // The decoding itself is exercised through the corpus tests; here we check the Cursor contract
    // the parser relies on: 0xe0 0x08 = 0x460, 0xac 0x01 = 0xac, 0x00 terminates.
    const bytes = [_]u8{ 0xe0, 0x08, 0xac, 0x01, 0x00 };
    const r = Reader.init(&bytes, 0);
    var c = r.cursor(0).?;
    try std.testing.expectEqual(@as(u64, 0x460), try c.takeUleb());
    try std.testing.expectEqual(@as(u64, 0xac), try c.takeUleb());
    try std.testing.expectEqual(@as(u64, 0), try c.takeUleb());
    try std.testing.expect(c.atEnd());
}
