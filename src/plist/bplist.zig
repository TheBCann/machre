//! plist/bplist.zig — bplist00 parser (trailer, offset table, iterative decode, cycle/depth guards).
//! Imports: plist/plist, core/reader, core/diag, core/limits.
//!
//! Every read goes through `core.Reader`; the decoder is an explicit DFS stack with a per-path
//! "on the current path" bitset, so a self-referencing container yields `plist_malformed` instead of
//! looping, and every count is clamped to what the file can hold.
const std = @import("std");
const Allocator = std.mem.Allocator;
const plist = @import("plist.zig");
const Value = plist.Value;
const Reader = @import("../core/reader.zig").Reader;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const trailer_size: u64 = 32;
pub const header_size: u64 = 8;

pub const Trailer = struct {
    sort_version: u8,
    offset_int_size: u8,
    object_ref_size: u8,
    num_objects: u64,
    top_object: u64,
    offset_table_offset: u64,
};

/// Reads the 32-byte trailer; null when the file is too short, is not `bplist0*`, or the integer
/// widths are not one of {1,2,4,8}.
pub fn readTrailer(bytes: []const u8) ?Trailer {
    if (bytes.len < header_size + trailer_size) return null;
    if (!std.mem.startsWith(u8, bytes, "bplist0")) return null;
    const r = Reader.init(bytes, 0);
    const off: u64 = bytes.len - trailer_size;
    const t: Trailer = .{
        .sort_version = r.u8At(off + 5) orelse return null,
        .offset_int_size = r.u8At(off + 6) orelse return null,
        .object_ref_size = r.u8At(off + 7) orelse return null,
        .num_objects = r.u64At(off + 8, .big) orelse return null,
        .top_object = r.u64At(off + 16, .big) orelse return null,
        .offset_table_offset = r.u64At(off + 24, .big) orelse return null,
    };
    if (!validIntSize(t.offset_int_size) or !validIntSize(t.object_ref_size)) return null;
    return t;
}
fn validIntSize(n: u8) bool {
    return n == 1 or n == 2 or n == 4 or n == 8;
}

/// Marker byte (+ extended count) of one object.
const Marker = struct {
    kind: u4,
    lo: u4,
    /// Byte offset of the payload (after the marker and any extended-count integer).
    payload: u64,
    /// Element/byte count for the counted types; `lo` for the rest.
    count: u64,
};

/// A decoded object: either a finished scalar or a container header the caller must expand.
const Decoded = union(enum) {
    scalar: Value,
    array: struct { count: u64, refs: u64 },
    dict: struct { count: u64, key_refs: u64, val_refs: u64 },
};

const Ctx = struct {
    arena: Allocator,
    r: Reader,
    limits: *const Limits,
    diags: *Diagnostics,
    t: Trailer,
    /// offsets[i] = file offset of object i, or `maxInt(u64)` when the entry was out of range.
    offsets: []const u64,
    /// One bit per object, set while the object is on the current DFS path.
    on_path: []u8,
    objects_decoded: u32 = 0,

    fn bad(c: *Ctx, off: ?u64, comptime fmt: []const u8, args: anytype) void {
        if (!c.diags.has(.plist, .plist_malformed)) c.diags.warn(.plist, .plist_malformed, off, fmt, args);
    }
    fn onPath(c: *const Ctx, i: u64) bool {
        const byte = i >> 3;
        if (byte >= c.on_path.len) return false;
        return c.on_path[@intCast(byte)] & (@as(u8, 1) << @intCast(i & 7)) != 0;
    }
    fn setPath(c: *Ctx, i: u64, on: bool) void {
        const byte = i >> 3;
        if (byte >= c.on_path.len) return;
        const mask = @as(u8, 1) << @intCast(i & 7);
        if (on) c.on_path[@intCast(byte)] |= mask else c.on_path[@intCast(byte)] &= ~mask;
    }
};

/// `null` when the bytes are not a usable bplist (no trailer, absurd table); otherwise a tree that is
/// as complete as the file allows, with one diagnostic per problem class.
pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Value {
    if (bytes.len > limits.max_plist_bytes) {
        diags.warn(.plist, .limit_reached, null, "bplist {d} bytes exceeds max_plist_bytes {d}", .{ bytes.len, limits.max_plist_bytes });
        return null;
    }
    const t = readTrailer(bytes) orelse {
        diags.warn(.plist, .plist_malformed, null, "bplist trailer missing or malformed ({d} bytes)", .{bytes.len});
        return null;
    };
    const objects_end: u64 = @as(u64, bytes.len) - trailer_size; // >= header_size (readTrailer checked)
    if (t.offset_table_offset < header_size or t.offset_table_offset > objects_end) {
        diags.warn(.plist, .plist_malformed, null, "bplist offset table at 0x{x} is outside the file ({d} bytes)", .{ t.offset_table_offset, bytes.len });
        return null;
    }
    const table_room: u64 = objects_end - t.offset_table_offset;
    var n = t.num_objects;
    if (n > limits.max_plist_objects) {
        diags.warn(.plist, .count_clamped, null, "bplist numObjects {d} clamped to max_plist_objects {d}", .{ n, limits.max_plist_objects });
        n = limits.max_plist_objects;
    }
    const fits = table_room / t.offset_int_size;
    if (n > fits) {
        diags.warn(.plist, .count_clamped, t.offset_table_offset, "bplist numObjects {d} clamped to {d} (offset table holds {d} bytes)", .{ n, fits, table_room });
        n = fits;
    }
    if (n == 0) {
        diags.warn(.plist, .plist_malformed, null, "bplist has no readable objects", .{});
        return null;
    }
    if (t.top_object >= n) {
        diags.warn(.plist, .plist_malformed, null, "bplist topObject {d} out of range ({d} objects)", .{ t.top_object, n });
        return null;
    }

    const r = Reader.init(bytes, 0);
    const offsets = try arena.alloc(u64, @intCast(n));
    var bad_offsets: usize = 0;
    for (offsets, 0..) |*slot, i| {
        const at = t.offset_table_offset + @as(u64, i) * t.offset_int_size;
        const v = readBigUint(r, at, t.offset_int_size) orelse 0;
        // Objects live strictly between the header and the offset table.
        if (v < header_size or v >= t.offset_table_offset) {
            bad_offsets += 1;
            slot.* = std.math.maxInt(u64);
        } else slot.* = v;
    }
    if (bad_offsets != 0) diags.warn(.plist, .plist_malformed, t.offset_table_offset, "bplist: {d} of {d} object offsets point outside the object area", .{ bad_offsets, offsets.len });

    var ctx: Ctx = .{
        .arena = arena,
        .r = r,
        .limits = limits,
        .diags = diags,
        .t = t,
        .offsets = offsets,
        .on_path = try arena.alloc(u8, (offsets.len + 7) / 8),
    };
    @memset(ctx.on_path, 0);
    return try decode(&ctx, t.top_object);
}

fn readBigUint(r: Reader, off: u64, size: u8) ?u64 {
    return switch (size) {
        1 => @as(u64, r.u8At(off) orelse return null),
        2 => @as(u64, r.u16At(off, .big) orelse return null),
        4 => @as(u64, r.u32At(off, .big) orelse return null),
        8 => r.u64At(off, .big) orelse return null,
        else => null,
    };
}
fn readBigUintAny(r: Reader, off: u64, nbytes: u8) ?u64 {
    var v: u64 = 0;
    var i: u8 = 0;
    while (i < nbytes) : (i += 1) {
        const b = r.u8At(off +| i) orelse return null;
        v = (v << 8) | b;
    }
    return v;
}

fn readMarker(c: *Ctx, off: u64) ?Marker {
    const m = c.r.u8At(off) orelse return null;
    const kind: u4 = @intCast(m >> 4);
    const lo: u4 = @intCast(m & 0xf);
    var payload = off +| 1;
    var count: u64 = lo;
    const counted = switch (kind) {
        0x4, 0x5, 0x6, 0x7, 0xa, 0xb, 0xc, 0xd => true,
        else => false,
    };
    if (counted and lo == 0xf) {
        const im = c.r.u8At(payload) orelse return null;
        if (im >> 4 != 0x1) return null;
        const size_log: u4 = @intCast(im & 0xf);
        if (size_log > 3) return null;
        const nbytes: u8 = @as(u8, 1) << @intCast(size_log);
        count = readBigUintAny(c.r, payload +| 1, nbytes) orelse return null;
        payload = payload +| 1 +| nbytes;
    }
    return .{ .kind = kind, .lo = lo, .payload = payload, .count = count };
}

/// Explicit-stack DFS. Containers are allocated on first visit and filled in place.
fn decode(c: *Ctx, top: u64) Allocator.Error!?Value {
    const Kind = enum { array, dict };
    const Frame = struct {
        obj: u64,
        kind: Kind,
        items: []Value,
        entries: []Value.Entry,
        n: u64,
        i: u64,
        key_refs: u64,
        val_refs: u64,
        /// null = this is the root container.
        dest: ?*Value,
    };
    var stack: std.ArrayList(Frame) = .empty;
    var root: Value = .null;

    var pending_obj = top;
    var pending_dest: ?*Value = null;
    // Outer loop: expand `pending_obj` into `pending_dest`, then drain the stack.
    while (true) {
        const d = try decodeObject(c, pending_obj);
        switch (d) {
            .scalar => |v| {
                if (pending_dest) |p| p.* = v else root = v;
            },
            .array, .dict => {
                if (c.onPath(pending_obj)) {
                    c.bad(null, "bplist object {d} refers to itself (cycle)", .{pending_obj});
                } else {
                    c.setPath(pending_obj, true);
                    var f: Frame = .{
                        .obj = pending_obj,
                        .kind = if (d == .dict) .dict else .array,
                        .items = &.{},
                        .entries = &.{},
                        .n = 0,
                        .i = 0,
                        .key_refs = 0,
                        .val_refs = 0,
                        .dest = pending_dest,
                    };
                    switch (d) {
                        .array => |a| {
                            f.n = a.count;
                            f.key_refs = a.refs;
                            f.items = try c.arena.alloc(Value, @intCast(a.count));
                            for (f.items) |*it| it.* = .null;
                        },
                        .dict => |dd| {
                            f.n = dd.count;
                            f.key_refs = dd.key_refs;
                            f.val_refs = dd.val_refs;
                            f.entries = try c.arena.alloc(Value.Entry, @intCast(dd.count));
                            for (f.entries) |*e| e.* = .{ .key = "", .value = .null };
                        },
                        else => unreachable,
                    }
                    try stack.append(c.arena, f);
                }
            },
        }

        // Drain: find the next child to expand, or finish containers.
        var next: ?struct { obj: u64, dest: *Value } = null;
        while (stack.items.len != 0 and next == null) {
            const idx = stack.items.len - 1;
            if (stack.items[idx].i >= stack.items[idx].n) {
                const f = stack.items[idx];
                c.setPath(f.obj, false);
                _ = stack.pop();
                const finished: Value = switch (f.kind) {
                    .array => .{ .array = f.items },
                    .dict => .{ .dict = f.entries },
                };
                if (f.dest) |p| p.* = finished else root = finished;
                continue;
            }
            const i = stack.items[idx].i;
            stack.items[idx].i += 1;
            const kind = stack.items[idx].kind;
            const key_refs = stack.items[idx].key_refs;
            const val_refs = stack.items[idx].val_refs;
            const slot: *Value = switch (kind) {
                .array => &stack.items[idx].items[@intCast(i)],
                .dict => &stack.items[idx].entries[@intCast(i)].value,
            };
            if (kind == .dict) {
                const key_ref = readBigUint(c.r, key_refs + i * c.t.object_ref_size, c.t.object_ref_size) orelse {
                    c.bad(key_refs, "bplist dict key reference {d} is truncated", .{i});
                    continue;
                };
                stack.items[idx].entries[@intCast(i)].key = try decodeKey(c, key_ref);
            }
            const ref_base = if (kind == .dict) val_refs else key_refs;
            const child_ref = readBigUint(c.r, ref_base + i * c.t.object_ref_size, c.t.object_ref_size) orelse {
                c.bad(ref_base, "bplist object reference {d} is truncated", .{i});
                continue;
            };
            if (stack.items.len >= c.limits.max_plist_depth) {
                if (!c.diags.has(.plist, .limit_reached)) c.diags.warn(.plist, .limit_reached, null, "bplist nesting deeper than max_plist_depth {d}", .{c.limits.max_plist_depth});
                continue;
            }
            next = .{ .obj = child_ref, .dest = slot };
        }
        if (next) |nx| {
            pending_obj = nx.obj;
            pending_dest = nx.dest;
            continue;
        }
        if (stack.items.len == 0) break;
    }
    return root;
}

/// Reads one object header. Unreadable objects decode to `.scalar = .null` after one diagnostic.
fn decodeObject(c: *Ctx, obj: u64) Allocator.Error!Decoded {
    c.objects_decoded += 1;
    if (c.objects_decoded > c.limits.max_plist_objects) {
        if (!c.diags.has(.plist, .limit_reached)) c.diags.warn(.plist, .limit_reached, null, "bplist expanded more than max_plist_objects {d} objects", .{c.limits.max_plist_objects});
        return .{ .scalar = .null };
    }
    if (obj >= c.offsets.len) {
        c.bad(null, "bplist object reference {d} out of range ({d} objects)", .{ obj, c.offsets.len });
        return .{ .scalar = .null };
    }
    const off = c.offsets[@intCast(obj)];
    if (off == std.math.maxInt(u64)) return .{ .scalar = .null };
    const m = readMarker(c, off) orelse {
        c.bad(off, "bplist object {d} has a malformed marker", .{obj});
        return .{ .scalar = .null };
    };
    switch (m.kind) {
        0x0 => return .{ .scalar = switch (m.lo) {
            0x0, 0xf => .null,
            0x8 => .{ .bool = false },
            0x9 => .{ .bool = true },
            else => blk: {
                c.bad(off, "bplist object {d}: unknown simple marker 0x0{x}", .{ obj, m.lo });
                break :blk .null;
            },
        } },
        0x1 => return .{ .scalar = .{ .integer = readInt(c, off, m) } },
        0x2 => return .{ .scalar = .{ .real = readReal(c, off, m) } },
        0x3 => {
            if (m.lo != 3) {
                c.bad(off, "bplist object {d}: date marker 0x3{x} is not 0x33", .{ obj, m.lo });
                return .{ .scalar = .null };
            }
            const bits = c.r.u64At(m.payload, .big) orelse {
                c.bad(off, "bplist object {d}: truncated date", .{obj});
                return .{ .scalar = .null };
            };
            return .{ .scalar = .{ .date = @bitCast(bits) } };
        },
        0x4 => {
            const want = m.count;
            const take = @min(want, c.limits.max_string_len);
            if (take != want and !c.diags.has(.plist, .limit_reached)) c.diags.warn(.plist, .limit_reached, off, "bplist data of {d} bytes cut to {d}", .{ want, take });
            const s = c.r.sliceAt(m.payload, take) orelse {
                c.bad(off, "bplist object {d}: data of {d} bytes is truncated", .{ obj, want });
                return .{ .scalar = .null };
            };
            return .{ .scalar = .{ .data = s } };
        },
        0x5, 0x6 => return .{ .scalar = .{ .string = try readString(c, obj, off, m) } },
        0x8 => {
            const nbytes: u8 = @as(u8, m.lo) + 1;
            if (nbytes > 8) {
                c.bad(off, "bplist object {d}: uid of {d} bytes", .{ obj, nbytes });
                return .{ .scalar = .null };
            }
            return .{ .scalar = .{ .uid = readBigUintAny(c.r, m.payload, nbytes) orelse 0 } };
        },
        0xa, 0xc, 0xd => {
            const per: u64 = if (m.kind == 0xd) 2 else 1;
            var count = m.count;
            const room: u64 = if (m.payload < c.t.offset_table_offset)
                (c.t.offset_table_offset - m.payload) / (@as(u64, c.t.object_ref_size) * per)
            else
                0;
            if (count > room) {
                if (!c.diags.has(.plist, .count_clamped)) c.diags.warn(.plist, .count_clamped, off, "bplist object {d}: {d} elements clamped to {d}", .{ obj, count, room });
                count = room;
            }
            if (count > c.limits.max_plist_objects) count = c.limits.max_plist_objects;
            if (m.kind == 0xd) return .{ .dict = .{
                .count = count,
                .key_refs = m.payload,
                .val_refs = m.payload + count * c.t.object_ref_size,
            } };
            return .{ .array = .{ .count = count, .refs = m.payload } };
        },
        else => {
            c.bad(off, "bplist object {d}: unsupported marker 0x{x}{x}", .{ obj, m.kind, m.lo });
            return .{ .scalar = .null };
        },
    }
}

/// Dict keys must be strings; anything else becomes "" with one diagnostic.
fn decodeKey(c: *Ctx, obj: u64) Allocator.Error![]const u8 {
    if (obj >= c.offsets.len) {
        c.bad(null, "bplist dict key reference {d} out of range", .{obj});
        return "";
    }
    const off = c.offsets[@intCast(obj)];
    if (off == std.math.maxInt(u64)) return "";
    const m = readMarker(c, off) orelse {
        c.bad(off, "bplist dict key {d} has a malformed marker", .{obj});
        return "";
    };
    if (m.kind != 0x5 and m.kind != 0x6) {
        c.bad(off, "bplist dict key {d} is not a string (marker 0x{x}{x})", .{ obj, m.kind, m.lo });
        return "";
    }
    return readString(c, obj, off, m);
}

fn readString(c: *Ctx, obj: u64, off: u64, m: Marker) Allocator.Error![]const u8 {
    const cap = c.limits.max_string_len;
    if (m.kind == 0x5) {
        const count = @min(m.count, cap);
        const s = c.r.sliceAt(m.payload, count) orelse {
            c.bad(off, "bplist object {d}: ASCII string of {d} bytes is truncated", .{ obj, m.count });
            return "";
        };
        return plist.internString(c.arena, s, c.limits, c.diags);
    }
    // UTF-16BE, `count` code units.
    const units = @min(m.count, cap / 2);
    const raw = c.r.sliceAt(m.payload, units * 2) orelse {
        c.bad(off, "bplist object {d}: UTF-16 string of {d} units is truncated", .{ obj, m.count });
        return "";
    };
    const buf = try c.arena.alloc(u16, @intCast(units));
    for (buf, 0..) |*u, i| u.* = (@as(u16, raw[i * 2]) << 8) | raw[i * 2 + 1];
    const utf8 = std.unicode.utf16LeToUtf8Alloc(c.arena, buf) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            if (!c.diags.has(.plist, .invalid_utf8)) c.diags.warn(.plist, .invalid_utf8, off, "bplist object {d}: UTF-16 string has unpaired surrogates", .{obj});
            return plist.internString(c.arena, try lossyUtf16(c.arena, buf), c.limits, c.diags);
        },
    };
    return plist.internString(c.arena, utf8, c.limits, c.diags);
}

/// Unpaired surrogates become U+FFFD so the result is always valid UTF-8.
fn lossyUtf16(arena: Allocator, units: []const u16) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < units.len) {
        const u = units[i];
        if (u >= 0xd800 and u < 0xdc00 and i + 1 < units.len and units[i + 1] >= 0xdc00 and units[i + 1] < 0xe000) {
            const cp: u21 = 0x10000 + ((@as(u21, u - 0xd800) << 10) | (units[i + 1] - 0xdc00));
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch 0;
            try out.appendSlice(arena, buf[0..n]);
            i += 2;
            continue;
        }
        if (u >= 0xd800 and u < 0xe000) {
            try out.appendSlice(arena, "\u{FFFD}");
        } else {
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(@intCast(u), &buf) catch 0;
            try out.appendSlice(arena, buf[0..n]);
        }
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

/// 1/2/4-byte ints are unsigned, 8-byte ints signed, 16-byte ints keep their low 64 bits.
fn readInt(c: *Ctx, off: u64, m: Marker) i64 {
    if (m.lo > 4) {
        c.bad(off, "bplist integer of 2^{d} bytes", .{m.lo});
        return 0;
    }
    const nbytes: u8 = @as(u8, 1) << @intCast(m.lo);
    if (nbytes <= 4) {
        const v = readBigUintAny(c.r, m.payload, nbytes) orelse {
            c.bad(off, "bplist integer is truncated", .{});
            return 0;
        };
        return @intCast(v);
    }
    if (nbytes == 8) {
        const v = c.r.u64At(m.payload, .big) orelse {
            c.bad(off, "bplist integer is truncated", .{});
            return 0;
        };
        return @bitCast(v);
    }
    const lo = c.r.u64At(m.payload + 8, .big) orelse {
        c.bad(off, "bplist 128-bit integer is truncated", .{});
        return 0;
    };
    return @bitCast(lo);
}

fn readReal(c: *Ctx, off: u64, m: Marker) f64 {
    switch (m.lo) {
        2 => {
            const bits = c.r.u32At(m.payload, .big) orelse {
                c.bad(off, "bplist float is truncated", .{});
                return 0;
            };
            return @as(f32, @bitCast(bits));
        },
        3 => {
            const bits = c.r.u64At(m.payload, .big) orelse {
                c.bad(off, "bplist double is truncated", .{});
                return 0;
            };
            return @bitCast(bits);
        },
        else => {
            c.bad(off, "bplist real of 2^{d} bytes", .{m.lo});
            return 0;
        },
    }
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

/// The 146-byte example of format-notes §7: 19 objects, 8 keys, "héllo", a date, -1, an array, a bool.
/// Byte-for-byte the layout documented there (offsets 08 19 1b … 5e, trailer 1/1/19/0/0x5f); `plutil -p`
/// accepts it.
pub const tiny: []const u8 = &[_]u8{
    0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x11, 0x12, 0x51, 0x74, 0x51, 0x73, 0x51, 0x64, 0x51,
    0x69, 0x51, 0x72, 0x51, 0x61, 0x51, 0x68, 0x51, 0x62, 0x33, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x65, 0x00, 0x68, 0x00, 0xe9, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x43, 0x01, 0x02,
    0x03, 0x11, 0x01, 0x2c, 0x23, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa2, 0x0f, 0x10,
    0x10, 0x01, 0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x68, 0x69, 0x09, 0x08,
    0x19, 0x1b, 0x1d, 0x1f, 0x21, 0x23, 0x25, 0x27, 0x29, 0x32, 0x3d, 0x41, 0x44, 0x4d, 0x50, 0x52,
    0x5b, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x5f,
};

test "bplist: tiny.bplist of format-notes 7 decodes exactly" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 32);
    try std.testing.expectEqual(@as(usize, 146), tiny.len);
    const t = readTrailer(tiny).?;
    try std.testing.expectEqual(@as(u8, 1), t.offset_int_size);
    try std.testing.expectEqual(@as(u8, 1), t.object_ref_size);
    try std.testing.expectEqual(@as(u64, 19), t.num_objects);
    try std.testing.expectEqual(@as(u64, 0), t.top_object);
    try std.testing.expectEqual(@as(u64, 0x5f), t.offset_table_offset);

    const v = (try parse(arena, tiny, &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(usize, 8), v.dict.len);
    try std.testing.expectEqual(@as(f64, 1.0), v.get("t").?.date);
    try std.testing.expectEqualStrings("héllo", v.getString("s").?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, v.get("d").?.data);
    try std.testing.expectEqual(@as(?i64, 300), v.getInteger("i"));
    try std.testing.expectEqual(@as(f64, 1.5), v.get("r").?.real);
    try std.testing.expectEqual(@as(usize, 2), v.get("a").?.array.len);
    try std.testing.expectEqual(@as(i64, 1), v.get("a").?.array[0].integer);
    try std.testing.expectEqual(@as(i64, -1), v.get("a").?.array[1].integer);
    try std.testing.expectEqualStrings("hi", v.getString("h").?);
    try std.testing.expectEqual(@as(?bool, true), v.getBool("b"));
    try std.testing.expectEqual(@as(usize, 0), diags.items().len);
}

test "bplist: every truncation of tiny.bplist parses without error" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var i: usize = 0;
    while (i <= tiny.len) : (i += 1) {
        var diags = Diagnostics.init(arena, 8);
        _ = try parse(arena, tiny[0..i], &Limits.default, &diags);
    }
}

test "bplist: a self-referencing dict is plist_malformed, not a hang" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    // object 0 = dict{ key obj1 -> value obj0 }, object 1 = "k"
    const bytes = [_]u8{
        'b',  'p',  'l',  'i',  's',  't',  '0', '0',
        0xd1, 0x01, 0x00, // 0x08 dict of 1: key ref 1, value ref 0 (itself)
        0x51, 0x6b, //       0x0b "k"
        0x08, 0x0b, //       0x0d offset table
        // trailer
        0,    0,    0,    0,    0,    0,    1,   1,
        0,    0,    0,    0,    0,    0,    0,   2, // numObjects
        0,    0,    0,    0,    0,    0,    0,   0, // topObject
        0,    0,    0,    0,    0,    0,    0,   0x0d, // offsetTableOffset
    };
    const v = (try parse(arena, &bytes, &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(usize, 1), v.dict.len);
    try std.testing.expectEqualStrings("k", v.dict[0].key);
    try std.testing.expect(v.dict[0].value == .null);
    try std.testing.expect(diags.has(.plist, .plist_malformed));
}

test "bplist: paranoid depth limit clamps instead of exploding" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    var lim = Limits.paranoid;
    lim.max_plist_depth = 2;
    const bytes = [_]u8{
        'b',  'p',  'l',  'i',  's',  't',  '0', '0',
        0xa1, 0x01, // 0x08 [ -> 1 ]
        0xa1, 0x02, // 0x0a [ -> 2 ]
        0xa1, 0x03, // 0x0c [ -> 3 ]
        0x51, 0x78, // 0x0e "x"
        0x08, 0x0a, 0x0c, 0x0e, // 0x10 offset table
        // trailer
        0,    0,    0,    0,    0,    0,    1,   1,
        0,    0,    0,    0,    0,    0,    0,   4,
        0,    0,    0,    0,    0,    0,    0,   0,
        0,    0,    0,    0,    0,    0,    0,   0x10,
    };
    const v = (try parse(arena, &bytes, &lim, &diags)).?;
    try std.testing.expect(v == .array);
    try std.testing.expectEqual(@as(usize, 1), v.array.len);
    try std.testing.expect(v.array[0].array[0] == .null);
    try std.testing.expect(diags.has(.plist, .limit_reached));
}

test "bplist: absurd trailers are rejected without overflowing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 32);
    var bytes: [64]u8 = @splat(0);
    @memcpy(bytes[0..8], "bplist00");
    @memset(bytes[32..64], 0xff); // numObjects/topObject/offsetTableOffset = maxInt
    bytes[32 + 6] = 1;
    bytes[32 + 7] = 1;
    try std.testing.expect(try parse(arena, &bytes, &Limits.default, &diags) == null);
    try std.testing.expect(diags.items().len > 0);
    try std.testing.expect(readTrailer("short") == null);
    var zeros: [64]u8 = @splat(0);
    try std.testing.expect(readTrailer(&zeros) == null);
    // valid header, offsetIntSize 3 -> rejected
    var bad_size: [64]u8 = @splat(0);
    @memcpy(bad_size[0..8], "bplist00");
    bad_size[32 + 6] = 3;
    bad_size[32 + 7] = 1;
    try std.testing.expect(readTrailer(&bad_size) == null);
}
