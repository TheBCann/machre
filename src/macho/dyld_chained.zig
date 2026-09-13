//! macho/dyld_chained.zig — LC_DYLD_CHAINED_FIXUPS. Imports: core/image, core/reader, core/diag, core/limits, core/macho_extra.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const Reader = @import("../core/reader.zig").Reader;
const extra = @import("../core/macho_extra.zig");

pub const PointerFormat = enum(u16) {
    arm64e = 1,
    @"64" = 2,
    @"32" = 3,
    @"32_cache" = 4,
    @"32_firmware" = 5,
    @"64_offset" = 6,
    arm64e_kernel = 7,
    @"64_kernel_cache" = 8,
    arm64e_userland = 9,
    arm64e_firmware = 10,
    x86_64_kernel_cache = 11,
    arm64e_userland24 = 12,
    arm64e_shared_cache = 13,
    arm64e_segmented = 14,
    _,

    /// Bytes between two links of a chain; null for formats this build cannot walk.
    pub fn stride(f: PointerFormat) ?u8 {
        return switch (f) {
            .arm64e, .arm64e_userland, .arm64e_userland24, .arm64e_shared_cache => 8,
            .@"64", .@"32", .@"32_cache", .@"32_firmware", .@"64_offset", .arm64e_kernel, .@"64_kernel_cache", .arm64e_firmware, .arm64e_segmented => 4,
            .x86_64_kernel_cache => 1,
            else => null,
        };
    }
    pub fn is32(f: PointerFormat) bool {
        return switch (f) {
            .@"32", .@"32_cache", .@"32_firmware" => true,
            else => false,
        };
    }
    /// True for the arm64e family (11-bit `next`, PAC-capable).
    pub fn isArm64e(f: PointerFormat) bool {
        return switch (f) {
            .arm64e, .arm64e_kernel, .arm64e_userland, .arm64e_firmware, .arm64e_userland24, .arm64e_shared_cache => true,
            else => false,
        };
    }
    /// The parenthesised description `dyld_info -fixup_chains` appends after the name.
    pub fn describe(f: PointerFormat) []const u8 {
        return switch (f) {
            .arm64e => "(authenticated arm64e, 8-byte stride, target vmadddr)",
            .@"64" => "(generic 64-bit, 4-byte stride, target vmaddr)",
            .@"32" => "(generic 32-bit)",
            .@"64_offset" => "(generic 64-bit, 4-byte stride, target vmoffset)",
            .arm64e_kernel => "(authenticated arm64e, 4-byte stride, target vmoffset)",
            .arm64e_userland => "(authenticated arm64e, 8-byte stride, target vmoffset)",
            .arm64e_userland24 => "(authenticated arm64e, 8-byte stride, target vmoffset, 24-bit bind ordinals)",
            else => "",
        };
    }
};
pub const ImportFormat = enum(u32) { import = 1, import_addend = 2, import_addend64 = 3, _ };

pub const Import = struct { lib_ordinal: i32, weak: bool, name: []const u8, addend: i64, name_offset: u32 };
pub const SegmentStarts = struct {
    seg_index: u32,
    size: u32,
    page_size: u16,
    pointer_format: u16,
    segment_offset: u64,
    max_valid_pointer: u32,
    page_count: u16,
    page_starts: []const u16, // clamped
    chain_starts: []const u16, // MULTI (32-bit formats) only
};
pub const Header = struct { fixups_version: u32, starts_offset: u32, imports_offset: u32, symbols_offset: u32, imports_count: u32, imports_format: u32, symbols_format: u32 };

pub const Auth = struct { key: u2, diversity: u16, addr_div: bool };

pub const Fixup = struct {
    vmaddr: u64,
    file_offset: u64,
    seg_index: u16,
    raw: u64,
    kind: Kind,

    pub const Kind = union(enum) {
        rebase: struct { target: u64, auth: ?Auth, high8: u8 },
        bind: struct { import_index: u32, addend: i64, auth: ?Auth },
    };
};

pub const ChainedFixups = struct {
    header: Header,
    imports: []const Import,
    imports_declared: u32,
    symbols_compressed: bool,
    starts: []const SegmentStarts,
    seg_count_declared: u32,
    fixups: []const Fixup, // in walk order (segment, page, chain)
    truncated: bool,

    pub const empty: ChainedFixups = .{
        .header = .{ .fixups_version = 0, .starts_offset = 0, .imports_offset = 0, .symbols_offset = 0, .imports_count = 0, .imports_format = 0, .symbols_format = 0 },
        .imports = &.{},
        .imports_declared = 0,
        .symbols_compressed = false,
        .starts = &.{},
        .seg_count_declared = 0,
        .fixups = &.{},
        .truncated = false,
    };
    /// "<bad ordinal N>" when out of range.
    pub fn importName(c: *const ChainedFixups, i: u32) []const u8 {
        if (i >= c.imports.len) return "<bad ordinal>";
        return c.imports[i].name;
    }
    pub fn importAt(c: *const ChainedFixups, i: u32) ?*const Import {
        if (i >= c.imports.len) return null;
        return &c.imports[i];
    }
    pub fn pointerFormat(c: *const ChainedFixups) ?PointerFormat {
        if (c.starts.len == 0) return null;
        return @enumFromInt(c.starts[0].pointer_format);
    }
};

fn signExtend(value: u64, comptime bits: u6) i64 {
    const sign: u64 = @as(u64, 1) << (bits - 1);
    if (value & sign != 0) {
        const mask: u64 = ~((@as(u64, 1) << bits) - 1);
        return @bitCast(value | mask);
    }
    return @bitCast(value);
}

/// Decode one raw pointer without walking (symbolize/objc read slots directly). Null for unknown formats.
pub fn decodePointer(raw: u64, format: PointerFormat, image_base: u64) ?Fixup.Kind {
    switch (format) {
        .@"64", .@"64_offset" => {
            if ((raw >> 63) & 1 != 0) {
                return .{ .bind = .{ .import_index = @truncate(raw & 0xff_ffff), .addend = @intCast((raw >> 24) & 0xff), .auth = null } };
            }
            const target: u64 = raw & 0xf_ffff_ffff;
            const high8: u8 = @truncate((raw >> 36) & 0xff);
            const base: u64 = if (format == .@"64_offset") image_base +% target else target;
            return .{ .rebase = .{ .target = base | (@as(u64, high8) << 56), .auth = null, .high8 = high8 } };
        },
        .arm64e, .arm64e_kernel, .arm64e_userland, .arm64e_userland24, .arm64e_firmware, .arm64e_shared_cache => {
            const authed = (raw >> 63) & 1 != 0;
            const is_bind = (raw >> 62) & 1 != 0;
            const auth: ?Auth = if (authed) .{
                .key = @truncate((raw >> 49) & 3),
                .diversity = @truncate((raw >> 32) & 0xffff),
                .addr_div = (raw >> 48) & 1 != 0,
            } else null;
            if (is_bind) {
                const ord: u32 = if (format == .arm64e_userland24) @truncate(raw & 0xff_ffff) else @truncate(raw & 0xffff);
                const addend: i64 = if (authed) 0 else signExtend((raw >> 32) & 0x7ffff, 19);
                return .{ .bind = .{ .import_index = ord, .addend = addend, .auth = auth } };
            }
            if (authed) {
                const target: u64 = raw & 0xffff_ffff;
                return .{ .rebase = .{ .target = image_base +% target, .auth = auth, .high8 = 0 } };
            }
            const target: u64 = raw & 0x7ff_ffff_ffff;
            const high8: u8 = @truncate((raw >> 43) & 0xff);
            const value: u64 = switch (format) {
                .arm64e, .arm64e_firmware => target | (@as(u64, high8) << 56),
                else => (image_base +% target) | (@as(u64, high8) << 56),
            };
            return .{ .rebase = .{ .target = value, .auth = null, .high8 = high8 } };
        },
        .@"32" => {
            const v: u32 = @truncate(raw);
            if ((v >> 31) & 1 != 0) {
                return .{ .bind = .{ .import_index = v & 0xf_ffff, .addend = @intCast((v >> 20) & 0x3f), .auth = null } };
            }
            return .{ .rebase = .{ .target = v & 0x3ff_ffff, .auth = null, .high8 = 0 } };
        },
        .@"32_cache" => {
            const v: u32 = @truncate(raw);
            return .{ .rebase = .{ .target = v & 0x3fff_ffff, .auth = null, .high8 = 0 } };
        },
        .@"32_firmware" => {
            const v: u32 = @truncate(raw);
            return .{ .rebase = .{ .target = v & 0x3ff_ffff, .auth = null, .high8 = 0 } };
        },
        else => return null,
    }
}

/// `next` field of a raw pointer in `format` (0 = end of chain).
pub fn nextOf(raw: u64, format: PointerFormat) ?u16 {
    return switch (format) {
        .arm64e, .arm64e_kernel, .arm64e_userland, .arm64e_userland24, .arm64e_firmware, .arm64e_shared_cache => @truncate((raw >> 51) & 0x7ff),
        .@"64", .@"64_offset", .@"64_kernel_cache", .x86_64_kernel_cache => @truncate((raw >> 51) & 0xfff),
        .@"32" => @truncate((raw >> 26) & 0x1f),
        .@"32_cache" => @truncate((raw >> 30) & 0x3),
        .@"32_firmware" => @truncate((raw >> 26) & 0x3f),
        else => null,
    };
}

/// Null when no LC_DYLD_CHAINED_FIXUPS. Walk rules in DESIGN.md §4.6 (format-notes 4.1).
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?ChainedFixups {
    const c = img.findCmd(.DYLD_CHAINED_FIXUPS) orelse return null;
    const cr = c.reader();
    if (c.bytes.len < 16) {
        diags.err(.chained, .cmdsize_invalid, c.offset, "LC_DYLD_CHAINED_FIXUPS is shorter than 16 bytes", .{});
        return truncatedResult();
    }
    const dataoff = cr.u32At(8, c.endian).?;
    const datasize = cr.u32At(12, c.endian).?;
    const payload = img.linkeditReader(dataoff, datasize, diags, .chained) orelse return truncatedResult();
    return try parseBytes(arena, img, payload, limits, diags);
}

fn truncatedResult() ChainedFixups {
    var v = ChainedFixups.empty;
    v.truncated = true;
    return v;
}

/// Walk an arbitrary chained-fixups payload (tests, nested images).
pub fn parseBytes(arena: Allocator, img: *const Image, payload: Reader, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ChainedFixups {
    var out = ChainedFixups.empty;
    const e = img.hdr.endian;
    if (payload.len() < 28) {
        diags.err(.chained, .truncated, payload.base, "chained fixups payload is {d} bytes, shorter than the 28-byte header", .{payload.len()});
        out.truncated = true;
        return out;
    }
    out.header = .{
        .fixups_version = payload.u32At(0, e).?,
        .starts_offset = payload.u32At(4, e).?,
        .imports_offset = payload.u32At(8, e).?,
        .symbols_offset = payload.u32At(12, e).?,
        .imports_count = payload.u32At(16, e).?,
        .imports_format = payload.u32At(20, e).?,
        .symbols_format = payload.u32At(24, e).?,
    };
    const h = out.header;
    out.imports_declared = h.imports_count;
    out.symbols_compressed = h.symbols_format == 1;
    if (h.fixups_version != 0 and !diags.has(.chained, .version_unsupported))
        diags.warn(.chained, .version_unsupported, payload.base, "chained fixups version {d} is not 0; parsing anyway", .{h.fixups_version});
    const len: u64 = payload.len();
    if (h.starts_offset >= len or h.imports_offset >= len or (h.imports_count != 0 and h.symbols_offset >= len)) {
        diags.err(.chained, .truncated, payload.base, "chained fixups header offsets (starts {d}, imports {d}, symbols {d}) lie outside the {d}-byte payload", .{ h.starts_offset, h.imports_offset, h.symbols_offset, len });
        out.truncated = true;
        return out;
    }

    // ---- symbol pool (optionally zlib-compressed) ----
    var pool: []const u8 = (payload.sub(@min(h.symbols_offset, len), null) orelse payload).bytes;
    if (out.symbols_compressed) {
        pool = inflate(arena, pool, limits) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => blk: {
                diags.warn(.chained, .truncated, payload.base + h.symbols_offset, "zlib symbol pool could not be decompressed; import names unavailable", .{});
                out.truncated = true;
                break :blk "";
            },
        };
    }

    // ---- imports ----
    const entry_size: u32 = switch (h.imports_format) {
        1 => 4,
        2 => 8,
        3 => 16,
        else => 0,
    };
    if (entry_size == 0) {
        diags.warn(.chained, .unknown_value, payload.base + 20, "unknown chained imports_format {d}; imports skipped", .{h.imports_format});
    } else {
        var n: u64 = h.imports_count;
        const avail: u64 = (len - h.imports_offset) / entry_size;
        if (n > avail) {
            diags.warn(.chained, .count_clamped, payload.base + 16, "imports_count {d} but only {d} entries fit in the payload; clamped", .{ h.imports_count, avail });
            n = avail;
            out.truncated = true;
        }
        if (n > limits.max_imports) {
            diags.warn(.chained, .count_clamped, payload.base + 16, "imports_count {d} clamped to limits.max_imports {d}", .{ h.imports_count, limits.max_imports });
            n = limits.max_imports;
            out.truncated = true;
        }
        const imps = try arena.alloc(Import, @intCast(n));
        const pr = Reader.init(pool, 0);
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const o: u64 = @as(u64, h.imports_offset) + @as(u64, i) * entry_size;
            var imp: Import = .{ .lib_ordinal = 0, .weak = false, .name = "", .addend = 0, .name_offset = 0 };
            switch (h.imports_format) {
                1, 2 => {
                    const v = payload.u32At(o, e).?;
                    imp.lib_ordinal = ordinal8(@truncate(v & 0xff));
                    imp.weak = (v >> 8) & 1 != 0;
                    imp.name_offset = v >> 9;
                    if (h.imports_format == 2) imp.addend = @as(i32, @bitCast(payload.u32At(o + 4, e).?));
                },
                3 => {
                    const v = payload.u64At(o, e).?;
                    imp.lib_ordinal = ordinal16(@truncate(v & 0xffff));
                    imp.weak = (v >> 16) & 1 != 0;
                    imp.name_offset = @truncate(v >> 32);
                    imp.addend = @bitCast(payload.u64At(o + 8, e).?);
                },
                else => unreachable,
            }
            if (pr.cstrAt(imp.name_offset, limits.max_symbol_name)) |s| {
                imp.name = s.bytes;
                if (!s.terminated and !diags.has(.chained, .string_unterminated))
                    diags.warn(.chained, .string_unterminated, payload.base + h.symbols_offset + imp.name_offset, "import {d}: name is not NUL-terminated inside the symbol pool", .{i});
            } else if (!diags.has(.chained, .string_unterminated)) {
                diags.warn(.chained, .string_unterminated, payload.base + h.symbols_offset, "import {d}: name_offset {d} lies outside the symbol pool", .{ i, imp.name_offset });
            }
            imps[i] = imp;
        }
        out.imports = imps;
    }

    // ---- starts_in_image ----
    const seg_count_declared = payload.u32At(h.starts_offset, e) orelse {
        diags.err(.chained, .truncated, payload.base + h.starts_offset, "starts_in_image header is truncated", .{});
        out.truncated = true;
        return out;
    };
    out.seg_count_declared = seg_count_declared;
    var seg_count: u64 = seg_count_declared;
    const seg_avail: u64 = (len - h.starts_offset - 4) / 4;
    if (seg_count > seg_avail or seg_count > img.segments.len) {
        diags.warn(.chained, .count_clamped, payload.base + h.starts_offset, "starts_in_image seg_count {d} clamped to {d} ({d} segments, {d} offsets fit)", .{ seg_count_declared, @min(seg_avail, img.segments.len), img.segments.len, seg_avail });
        seg_count = @min(seg_avail, img.segments.len);
        out.truncated = true;
    }

    var starts: std.ArrayList(SegmentStarts) = .empty;
    var fixups: std.ArrayList(Fixup) = .empty;
    var si: u32 = 0;
    while (si < seg_count) : (si += 1) {
        const so = payload.u32At(@as(u64, h.starts_offset) + 4 + @as(u64, si) * 4, e) orelse break;
        if (so == 0) continue;
        const base: u64 = @as(u64, h.starts_offset) + so;
        const size = payload.u32At(base, e) orelse {
            if (!diags.has(.chained, .truncated))
                diags.warn(.chained, .truncated, payload.base + base, "starts_in_segment for segment {d} lies outside the payload", .{si});
            out.truncated = true;
            continue;
        };
        var ss: SegmentStarts = .{
            .seg_index = si,
            .size = size,
            .page_size = payload.u16At(base + 4, e) orelse 0,
            .pointer_format = payload.u16At(base + 6, e) orelse 0,
            .segment_offset = payload.u64At(base + 8, e) orelse 0,
            .max_valid_pointer = payload.u32At(base + 16, e) orelse 0,
            .page_count = payload.u16At(base + 20, e) orelse 0,
            .page_starts = &.{},
            .chain_starts = &.{},
        };
        var pc: u64 = ss.page_count;
        const pavail: u64 = if (base + 22 <= len) (len - base - 22) / 2 else 0;
        if (pc > pavail) {
            if (!diags.has(.chained, .count_clamped))
                diags.warn(.chained, .count_clamped, payload.base + base + 20, "segment {d}: page_count {d} but only {d} page starts fit; clamped", .{ si, ss.page_count, pavail });
            pc = pavail;
            out.truncated = true;
        }
        const ps = try arena.alloc(u16, @intCast(pc));
        var pi: u32 = 0;
        while (pi < pc) : (pi += 1) ps[pi] = payload.u16At(base + 22 + @as(u64, pi) * 2, e).?;
        ss.page_starts = ps;
        // chain_starts[] follows page_start[] for MULTI pages (declared size tells how far it runs)
        const after: u64 = base + 22 + pc * 2;
        if (ss.size > 22 + pc * 2 and base + ss.size <= len) {
            const extra_words: u64 = (ss.size - (22 + pc * 2)) / 2;
            const cs = try arena.alloc(u16, @intCast(@min(extra_words, limits.max_chain_steps_per_page)));
            for (cs, 0..) |*w, k| w.* = payload.u16At(after + k * 2, e) orelse 0;
            ss.chain_starts = cs;
        }
        try starts.append(arena, ss);
        try walkSegment(arena, img, payload, &ss, &fixups, limits, diags, &out);
    }
    out.starts = try starts.toOwnedSlice(arena);
    out.fixups = try fixups.toOwnedSlice(arena);
    return out;
}

/// 8-bit lib_ordinal: 0xF1..0xFF are the negative specials -15..-1.
fn ordinal8(v: u8) i32 {
    if (v > 0xf0) return @as(i32, v) - 256;
    return v;
}
fn ordinal16(v: u16) i32 {
    if (v > 0xfff0) return @as(i32, v) - 65536;
    return v;
}

fn inflate(arena: Allocator, compressed: []const u8, limits: *const Limits) ![]const u8 {
    var in: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&in, .zlib, &window);
    return d.reader.allocRemaining(arena, .limited(limits.max_strtab));
}

fn walkSegment(arena: Allocator, img: *const Image, payload: Reader, ss: *const SegmentStarts, fixups: *std.ArrayList(Fixup), limits: *const Limits, diags: *Diagnostics, out: *ChainedFixups) Allocator.Error!void {
    _ = payload;
    if (ss.seg_index >= img.segments.len) return;
    const seg = img.segments[ss.seg_index];
    const fmt: PointerFormat = @enumFromInt(ss.pointer_format);
    const stride: u64 = fmt.stride() orelse {
        if (!diags.has(.chained, .unknown_value))
            diags.warn(.chained, .unknown_value, seg.cmd_offset, "segment {s}: unsupported pointer_format {d}; chain not walked", .{ seg.name, ss.pointer_format });
        out.truncated = true;
        return;
    };
    if (ss.page_size == 0) {
        if (!diags.has(.chained, .unknown_value))
            diags.warn(.chained, .unknown_value, seg.cmd_offset, "segment {s}: page_size 0; chain not walked", .{seg.name});
        out.truncated = true;
        return;
    }
    const ptr_size: u64 = if (fmt.is32()) 4 else 8;
    const max_steps: u64 = @min(@as(u64, ss.page_size) / stride + 1, limits.max_chain_steps_per_page);
    var p: u32 = 0;
    while (p < ss.page_starts.len) : (p += 1) {
        const start = ss.page_starts[p];
        if (start == extra.DYLD_CHAINED_PTR_START_NONE) continue;
        const page_base: u64 = @as(u64, p) * ss.page_size;
        if (start & extra.DYLD_CHAINED_PTR_START_MULTI != 0) {
            var k: usize = start & 0x7fff;
            while (k < ss.chain_starts.len) : (k += 1) {
                const w = ss.chain_starts[k];
                try walkChain(arena, img, ss, seg, fmt, stride, ptr_size, max_steps, page_base, w & 0x7fff, fixups, limits, diags, out);
                if (w & extra.DYLD_CHAINED_PTR_START_LAST != 0) break;
            }
            continue;
        }
        try walkChain(arena, img, ss, seg, fmt, stride, ptr_size, max_steps, page_base, start, fixups, limits, diags, out);
    }
}

fn walkChain(
    arena: Allocator,
    img: *const Image,
    ss: *const SegmentStarts,
    seg: @import("../core/image.zig").Segment,
    fmt: PointerFormat,
    stride: u64,
    ptr_size: u64,
    max_steps: u64,
    page_base: u64,
    start: u16,
    fixups: *std.ArrayList(Fixup),
    limits: *const Limits,
    diags: *Diagnostics,
    out: *ChainedFixups,
) Allocator.Error!void {
    var off: u64 = page_base + start;
    var steps: u64 = 0;
    const page_end: u64 = page_base + ss.page_size;
    const e = img.hdr.endian;
    if (off + ptr_size > page_end) {
        chainBroken(diags, out, seg.name, seg.fileoff + off);
        return;
    }
    while (steps < max_steps) : (steps += 1) {
        if (fixups.items.len >= limits.max_fixups) {
            if (!diags.has(.chained, .limit_reached))
                diags.warn(.chained, .limit_reached, null, "fixups clamped to limits.max_fixups {d}", .{limits.max_fixups});
            out.truncated = true;
            return;
        }
        const fo: u64 = seg.fileoff + off;
        const raw: u64 = if (ptr_size == 4)
            (img.r.u32At(fo, e) orelse {
                chainBroken(diags, out, seg.name, fo);
                return;
            })
        else
            (img.r.u64At(fo, e) orelse {
                chainBroken(diags, out, seg.name, fo);
                return;
            });
        if (decodePointer(raw, fmt, img.image_base)) |kind| {
            try fixups.append(arena, .{
                .vmaddr = seg.vmaddr +% off,
                .file_offset = img.slice_offset + fo,
                .seg_index = @truncate(ss.seg_index),
                .raw = raw,
                .kind = kind,
            });
        }
        const next = nextOf(raw, fmt) orelse return;
        if (next == 0) return;
        off += @as(u64, next) * stride;
        if (off + ptr_size > page_end) {
            chainBroken(diags, out, seg.name, seg.fileoff + off);
            return;
        }
    }
    if (!diags.has(.chained, .limit_reached))
        diags.warn(.chained, .limit_reached, null, "chain in segment {s} exceeded {d} steps per page; stopped", .{ seg.name, max_steps });
    out.truncated = true;
}

fn chainBroken(diags: *Diagnostics, out: *ChainedFixups, segname: []const u8, off: u64) void {
    if (!diags.has(.chained, .chain_broken))
        diags.warn(.chained, .chain_broken, off, "chain in segment {s} leaves its page or the slice at offset {d}; stopped", .{ segname, off });
    out.truncated = true;
}

// ---- tests ----
test "dyld_chained: decodePointer for formats 1, 2, 6 and 12 (format-notes 4.1 worked examples)" {
    // 64_OFFSET bind: __got slot 0 of enumerateProcess, ordinal 0, next 2.
    const k1 = decodePointer(0x8010000000000000, .@"64_offset", 0x100000000).?;
    try std.testing.expectEqual(@as(u32, 0), k1.bind.import_index);
    try std.testing.expectEqual(@as(?u16, 2), nextOf(0x8010000000000000, .@"64_offset"));
    const k2 = decodePointer(0x8000000000000010, .@"64_offset", 0x100000000).?;
    try std.testing.expectEqual(@as(u32, 16), k2.bind.import_index);
    try std.testing.expectEqual(@as(?u16, 0), nextOf(0x8000000000000010, .@"64_offset"));
    // arm64e auth bind: /bin/ls __auth_got, key IA, addrDiv 1, div 0, ordinal 0, next 1.
    const k3 = decodePointer(0xC009000000000000, .arm64e, 0x100000000).?;
    try std.testing.expectEqual(@as(u32, 0), k3.bind.import_index);
    try std.testing.expectEqual(@as(u2, 0), k3.bind.auth.?.key);
    try std.testing.expect(k3.bind.auth.?.addr_div);
    try std.testing.expectEqual(@as(u16, 0), k3.bind.auth.?.diversity);
    try std.testing.expectEqual(@as(?u16, 1), nextOf(0xC009000000000000, .arm64e));
    // arm64e rebase: /bin/ls __const raw 0x0048000100004A03 -> target 0x100004A03, next 9.
    const k4 = decodePointer(0x0048000100004A03, .arm64e, 0x100000000).?;
    try std.testing.expectEqual(@as(u64, 0x100004A03), k4.rebase.target);
    try std.testing.expectEqual(@as(u8, 0), k4.rebase.high8);
    try std.testing.expectEqual(@as(?u16, 9), nextOf(0x0048000100004A03, .arm64e));
    // arm64e_userland24 rebase (TextEdit __objc_classlist[0]) -> 0x100030740, next 1.
    const k5 = decodePointer(0x0008000000030740, .arm64e_userland24, 0x100000000).?;
    try std.testing.expectEqual(@as(u64, 0x100030740), k5.rebase.target);
    try std.testing.expectEqual(@as(?u16, 1), nextOf(0x0008000000030740, .arm64e_userland24));
    // 64 (dylib base 0) rebase: Electron __objc_classlist[0] -> 0xA4B1718, next 2.
    const k6 = decodePointer(0x001000000A4B1718, .@"64", 0).?;
    try std.testing.expectEqual(@as(u64, 0xA4B1718), k6.rebase.target);
    try std.testing.expectEqual(@as(?u16, 2), nextOf(0x001000000A4B1718, .@"64"));
    try std.testing.expect(decodePointer(0, .arm64e_segmented, 0) == null);
    try std.testing.expectEqual(@as(?u8, 8), PointerFormat.stride(.arm64e));
    try std.testing.expectEqual(@as(?u8, 4), PointerFormat.stride(.@"64_offset"));
    try std.testing.expect(PointerFormat.is32(.@"32") and !PointerFormat.is32(.@"64"));
}

test "dyld_chained: signed 19-bit addend and special library ordinals" {
    try std.testing.expectEqual(@as(i64, -1), signExtend(0x7ffff, 19));
    try std.testing.expectEqual(@as(i64, 1), signExtend(1, 19));
    try std.testing.expectEqual(@as(i32, 0), ordinal8(0));
    try std.testing.expectEqual(@as(i32, -1), ordinal8(0xff));
    try std.testing.expectEqual(@as(i32, -2), ordinal8(0xfe));
    try std.testing.expectEqual(@as(i32, -3), ordinal8(0xfd));
    try std.testing.expectEqual(@as(i32, 3), ordinal8(3));
    try std.testing.expectEqual(@as(i32, -1), ordinal16(0xffff));
    try std.testing.expectEqual(@as(i32, 250), ordinal16(250));
}
