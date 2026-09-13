//! core/fat.zig — fat/universal container detection and slice selection.
//! Imports: reader, arch, diag, limits.
const std = @import("std");
const macho = std.macho;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const arch_mod = @import("arch.zig");
const Arch = arch_mod.Arch;
const ArchName = arch_mod.ArchName;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;

pub const FatArch = struct {
    arch: Arch,
    offset: u64,
    size: u64,
    @"align": u32, // log2
    /// false when the slice range is outside the file, overlaps another, or its magic is not Mach-O.
    valid: bool,
};

pub const Fat = struct { is_64: bool, nfat_arch_declared: u32, arches: []const FatArch };

pub const Container = union(enum) {
    /// One Mach-O at file offset 0.
    thin: Arch,
    /// FAT_MAGIC / FAT_MAGIC_64 header; `arches` clamped to limits.max_fat_arches.
    fat: Fat,
    /// Neither: still analysable for xattr/plist/bundle/entropy/strings.
    not_macho,

    /// Number of analysable Mach-O slices (valid fat arches only).
    pub fn sliceCount(c: Container) usize {
        return switch (c) {
            .thin => 1,
            .fat => |f| blk: {
                var n: usize = 0;
                for (f.arches) |a| if (a.valid) {
                    n += 1;
                };
                break :blk n;
            },
            .not_macho => 0,
        };
    }
    /// "thin" | "fat" | "not_macho" (JSON `file.container`).
    pub fn containerName(c: Container) []const u8 {
        return switch (c) {
            .thin => "thin",
            .fat => "fat",
            .not_macho => "not_macho",
        };
    }
};

fn isMachMagic(m: u32) bool {
    return m == macho.MH_MAGIC_64 or m == macho.MH_CIGAM_64 or m == macho.MH_MAGIC or m == macho.MH_CIGAM;
}

/// Magic read big-endian; `nfat_arch > max_fat_arches` -> clamp + count_clamped; per arch:
/// offset+size <= r.len() else valid=false + offset_past_eof; pairwise overlap -> overlap;
/// slice magic must be MH_*; FAT_MAGIC_64 uses 32-byte entries.
pub fn parse(arena: Allocator, r: Reader, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Container {
    const magic_be = r.u32At(0, .big) orelse return .not_macho;
    const magic_le = r.u32At(0, .little).?;
    if (isMachMagic(magic_le)) {
        const cputype: i32 = @bitCast(r.u32At(4, if (magic_le == macho.MH_MAGIC_64 or magic_le == macho.MH_MAGIC) .little else .big) orelse 0);
        const cpusubtype: i32 = @bitCast(r.u32At(8, if (magic_le == macho.MH_MAGIC_64 or magic_le == macho.MH_MAGIC) .little else .big) orelse 0);
        return .{ .thin = Arch.fromCpu(cputype, cpusubtype) };
    }
    const is_64 = switch (magic_be) {
        macho.FAT_MAGIC => false,
        macho.FAT_MAGIC_64 => true,
        else => return .not_macho,
    };
    const declared = r.u32At(4, .big) orelse return .not_macho;
    const entry_size: u64 = if (is_64) 32 else 20;
    var n: u32 = declared;
    if (n > limits.max_fat_arches) {
        diags.warn(.fat, .count_clamped, 4, "nfat_arch {d} clamped to {d}", .{ declared, limits.max_fat_arches });
        n = limits.max_fat_arches;
    }
    const fit: u64 = (r.len() -| 8) / entry_size;
    if (n > fit) {
        if (!diags.has(.fat, .count_clamped))
            diags.warn(.fat, .count_clamped, 4, "nfat_arch {d} but only {d} fat_arch entries fit in the file", .{ declared, fit });
        n = @intCast(fit);
    }
    const arches = try arena.alloc(FatArch, n);
    for (arches, 0..) |*fa, i| {
        const o: u64 = 8 + @as(u64, i) * entry_size;
        const cputype: i32 = @bitCast(r.u32At(o, .big).?);
        const cpusubtype: i32 = @bitCast(r.u32At(o + 4, .big).?);
        var offset: u64 = undefined;
        var size: u64 = undefined;
        var alignment: u32 = undefined;
        if (is_64) {
            offset = r.u64At(o + 8, .big).?;
            size = r.u64At(o + 16, .big).?;
            alignment = r.u32At(o + 24, .big).?;
        } else {
            offset = r.u32At(o + 8, .big).?;
            size = r.u32At(o + 12, .big).?;
            alignment = r.u32At(o + 16, .big).?;
        }
        var valid = true;
        if (!r.contains(offset, size)) {
            valid = false;
            if (!diags.has(.fat, .offset_past_eof))
                diags.err(.fat, .offset_past_eof, o + 8, "fat_arch[{d}] offset {d} + size {d} lies outside the {d}-byte file", .{ i, offset, size, r.len() });
        } else if (size < 28 or !isMachMagic(r.u32At(offset, .little).?)) {
            valid = false;
            if (!diags.has(.fat, .bad_magic))
                diags.err(.fat, .bad_magic, offset, "fat_arch[{d}] at offset {d} does not start with a Mach-O magic", .{ i, offset });
        }
        fa.* = .{ .arch = Arch.fromCpu(cputype, cpusubtype), .offset = offset, .size = size, .@"align" = alignment, .valid = valid };
    }
    // pairwise overlap among valid slices
    for (arches, 0..) |*a, i| {
        if (!a.valid) continue;
        for (arches[0..i]) |b| {
            if (!b.valid) continue;
            const a_end = a.offset + a.size;
            const b_end = b.offset + b.size;
            if (a.offset < b_end and b.offset < a_end) {
                a.valid = false;
                if (!diags.has(.fat, .overlap))
                    diags.err(.fat, .overlap, 8 + @as(u64, i) * entry_size, "fat_arch[{d}] overlaps an earlier slice", .{i});
                break;
            }
        }
    }
    return .{ .fat = .{ .is_64 = is_64, .nfat_arch_declared = declared, .arches = arches } };
}

pub const SelectReason = enum { thin, all, requested, host, first };
pub const Selection = struct { indices: []const u32, reason: SelectReason };
pub const SelectError = error{ ArchNotFound, NoValidArch } || Allocator.Error;

/// Applies --arch / --all-archs: `wanted` wins (ArchNotFound if absent); `all` = every valid slice;
/// otherwise the best `Arch.preferenceRank` against `host`, falling back to the first valid slice.
pub fn selectArches(arena: Allocator, c: Container, wanted: ?ArchName, all: bool, host: Arch) SelectError!Selection {
    switch (c) {
        .not_macho => return error.NoValidArch,
        .thin => |a| {
            if (wanted) |w| if (!a.matches(w)) return error.ArchNotFound;
            const idx = try arena.alloc(u32, 1);
            idx[0] = 0;
            return .{ .indices = idx, .reason = if (wanted != null) .requested else .thin };
        },
        .fat => |f| {
            var list: std.ArrayList(u32) = .empty;
            if (wanted) |w| {
                for (f.arches, 0..) |a, i| if (a.valid and a.arch.matches(w)) try list.append(arena, @intCast(i));
                if (list.items.len == 0) return error.ArchNotFound;
                return .{ .indices = try list.toOwnedSlice(arena), .reason = .requested };
            }
            if (all) {
                for (f.arches, 0..) |a, i| if (a.valid) try list.append(arena, @intCast(i));
                if (list.items.len == 0) return error.NoValidArch;
                return .{ .indices = try list.toOwnedSlice(arena), .reason = .all };
            }
            var best: ?u32 = null;
            var best_rank: u8 = 255;
            for (f.arches, 0..) |a, i| {
                if (!a.valid) continue;
                const rank = a.arch.preferenceRank(host);
                if (rank < best_rank) {
                    best_rank = rank;
                    best = @intCast(i);
                }
            }
            const b = best orelse return error.NoValidArch;
            try list.append(arena, b);
            return .{ .indices = try list.toOwnedSlice(arena), .reason = if (best_rank < 2) .host else .first };
        },
    }
}

fn be32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .big);
}
fn le32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
/// Two-arch fat file: x86_64 slice at 64 (size 32) and arm64 slice at 96 (size 32).
fn buildFat(buf: *[128]u8, nfat: u32) void {
    @memset(buf, 0);
    be32(buf, 0, macho.FAT_MAGIC);
    be32(buf, 4, nfat);
    be32(buf, 8, 0x01000007);
    be32(buf, 12, 3);
    be32(buf, 16, 64);
    be32(buf, 20, 32);
    be32(buf, 24, 12);
    be32(buf, 28, 0x0100000c);
    be32(buf, 32, 0);
    be32(buf, 36, 96);
    be32(buf, 40, 32);
    be32(buf, 44, 14);
    le32(buf, 64, macho.MH_MAGIC_64);
    le32(buf, 68, 0x01000007);
    le32(buf, 96, macho.MH_MAGIC_64);
    le32(buf, 100, 0x0100000c);
}

test "fat: 2-arch header, selection, nfat_arch 1000 clamps to 32" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [128]u8 = undefined;
    buildFat(&buf, 2);
    var d = Diagnostics.init(a, 64);
    const c = try parse(a, Reader.init(&buf, 0), &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 2), c.sliceCount());
    try std.testing.expectEqual(ArchName.x86_64, c.fat.arches[0].arch.name);
    try std.testing.expectEqual(ArchName.arm64, c.fat.arches[1].arch.name);
    try std.testing.expectEqual(@as(usize, 0), d.items().len);
    const host = Arch.fromCpu(0x0100000c, 0);
    const sel = try selectArches(a, c, null, false, host);
    try std.testing.expectEqual(@as(u32, 1), sel.indices[0]);
    try std.testing.expectEqual(SelectReason.host, sel.reason);
    const all = try selectArches(a, c, null, true, host);
    try std.testing.expectEqual(@as(usize, 2), all.indices.len);
    const req = try selectArches(a, c, .x86_64, false, host);
    try std.testing.expectEqual(@as(u32, 0), req.indices[0]);
    try std.testing.expectError(error.ArchNotFound, selectArches(a, c, .arm64e, false, host));
    // absurd nfat_arch
    buildFat(&buf, 1000);
    var d2 = Diagnostics.init(a, 64);
    const c2 = try parse(a, Reader.init(&buf, 0), &Limits.default, &d2);
    try std.testing.expect(d2.has(.fat, .count_clamped));
    try std.testing.expect(c2.fat.arches.len <= 32);
    try std.testing.expectEqual(@as(usize, 2), c2.sliceCount());
    // offset past EOF invalidates one slice, the other is still selectable
    buildFat(&buf, 2);
    be32(&buf, 16, 0x7FFFFFF0);
    var d3 = Diagnostics.init(a, 64);
    const c3 = try parse(a, Reader.init(&buf, 0), &Limits.default, &d3);
    try std.testing.expect(!c3.fat.arches[0].valid and c3.fat.arches[1].valid);
    try std.testing.expect(d3.has(.fat, .offset_past_eof));
    try std.testing.expectError(error.ArchNotFound, selectArches(a, c3, .x86_64, false, host));
    // thin and not-Mach-O
    try std.testing.expectEqual(Container.not_macho, try parse(a, Reader.init("\xde\xad\xbe\xef", 0), &Limits.default, &d3));
    try std.testing.expectEqual(Container.not_macho, try parse(a, Reader.init("", 0), &Limits.default, &d3));
    const thin = try parse(a, Reader.init(buf[96..], 0), &Limits.default, &d3);
    try std.testing.expectEqual(ArchName.arm64, thin.thin.name);
    try std.testing.expectError(error.NoValidArch, selectArches(a, .not_macho, null, false, host));
    // every prefix parses
    var len: usize = 0;
    while (len <= buf.len) : (len += 1) _ = try parse(a, Reader.init(buf[0..len], 0), &Limits.paranoid, &d3);
}
