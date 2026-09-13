//! macho/fixups.zig — unified rebase/bind table over chained or legacy dyld data + slot resolution.
//! Imports: core/image, core/diag, core/limits, macho/dyld_chained, macho/dyld_legacy.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const dyld_chained = @import("dyld_chained.zig");
const dyld_legacy = @import("dyld_legacy.zig");

pub const Source = enum { chained, legacy, none };
pub const FixupKind = enum { rebase, bind, lazy_bind, weak_bind };
pub const Fixup = struct {
    vmaddr: u64,
    kind: FixupKind,
    target: u64, // rebase target (0 for binds)
    symbol: []const u8, // bind symbol ("" for rebases)
    lib_ordinal: i32,
    addend: i64,
    weak_import: bool,
    auth: ?dyld_chained.Auth,
    section: ?u16,
    raw: ?u64,

    pub fn isBind(f: Fixup) bool {
        return f.kind != .rebase;
    }
};
/// What a pointer-sized slot means after dyld: a bound symbol, a rebased address, or the raw on-disk
/// value (legacy images store unslid vmaddrs directly; PAC/high bits stripped).
pub const Slot = union(enum) { bind: *const Fixup, rebase: u64, raw: u64 };

/// Mask that strips PAC bits / the chained high8 from a raw on-disk pointer.
pub const pointer_mask: u64 = 0x0000_7fff_ffff_ffff;

pub const FixupTable = struct {
    source: Source,
    fixups: []const Fixup, // sorted by vmaddr
    chained: ?dyld_chained.ChainedFixups,
    legacy: ?dyld_legacy.DyldInfo,
    pointer_format: ?dyld_chained.PointerFormat,
    counts: struct { rebases: u32, binds: u32, auth_binds: u32, lazy: u32, weak: u32 },
    truncated: bool,

    pub const empty: FixupTable = .{ .source = .none, .fixups = &.{}, .chained = null, .legacy = null, .pointer_format = null, .counts = .{ .rebases = 0, .binds = 0, .auth_binds = 0, .lazy = 0, .weak = 0 }, .truncated = false };

    /// Binary search by vmaddr; a bind wins over a rebase at the same address (that is what dyld leaves behind).
    pub fn at(t: *const FixupTable, vmaddr: u64) ?*const Fixup {
        var lo: usize = 0;
        var hi: usize = t.fixups.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.fixups[mid].vmaddr < vmaddr) lo = mid + 1 else hi = mid;
        }
        if (lo >= t.fixups.len or t.fixups[lo].vmaddr != vmaddr) return null;
        const best: *const Fixup = &t.fixups[lo];
        var i = lo;
        while (i < t.fixups.len and t.fixups[i].vmaddr == vmaddr) : (i += 1) {
            if (t.fixups[i].isBind()) return &t.fixups[i];
        }
        return best;
    }
    /// Resolve an 8-byte slot at `vmaddr` (null when unmapped).
    pub fn resolveSlot(t: *const FixupTable, img: *const Image, vmaddr: u64) ?Slot {
        if (t.at(vmaddr)) |f| {
            if (f.isBind()) return .{ .bind = f };
            return .{ .rebase = f.target };
        }
        const raw: u64 = if (img.hdr.is_64)
            (img.u64AtVm(vmaddr) orelse return null)
        else
            @as(u64, img.u32AtVm(vmaddr) orelse return null);
        return .{ .raw = raw & pointer_mask };
    }
    /// Convenience: the address a slot points to after dyld, if it is a rebase/raw pointer.
    pub fn pointerAt(t: *const FixupTable, img: *const Image, vmaddr: u64) ?u64 {
        return switch (t.resolveSlot(img, vmaddr) orelse return null) {
            .bind => null,
            .rebase => |v| v,
            .raw => |v| if (v == 0) null else v,
        };
    }
    pub fn bindName(t: *const FixupTable, vmaddr: u64) ?[]const u8 {
        const f = t.at(vmaddr) orelse return null;
        if (!f.isBind()) return null;
        return f.symbol;
    }
};

fn lessByAddr(_: void, a: Fixup, b: Fixup) bool {
    return a.vmaddr < b.vmaddr;
}

/// Chained if present, else legacy, else `.none` (nlist-only imports are attributed by imports.zig).
pub fn build(arena: Allocator, img: *const Image, chained_in: ?*const dyld_chained.ChainedFixups, legacy_in: ?*const dyld_legacy.DyldInfo, limits: *const Limits, diags: *Diagnostics) Allocator.Error!FixupTable {
    _ = diags;
    var out = FixupTable.empty;
    var list: std.ArrayList(Fixup) = .empty;
    if (chained_in) |ch| {
        out.source = .chained;
        out.chained = ch.*;
        out.truncated = ch.truncated;
        out.pointer_format = ch.pointerFormat();
        for (ch.fixups) |f| {
            if (list.items.len >= limits.max_fixups) {
                out.truncated = true;
                break;
            }
            var u: Fixup = .{
                .vmaddr = f.vmaddr,
                .kind = .rebase,
                .target = 0,
                .symbol = "",
                .lib_ordinal = 0,
                .addend = 0,
                .weak_import = false,
                .auth = null,
                .section = sectionIndex(img, f.vmaddr),
                .raw = f.raw,
            };
            switch (f.kind) {
                .rebase => |rb| {
                    u.target = rb.target;
                    u.auth = rb.auth;
                },
                .bind => |bd| {
                    u.kind = .bind;
                    u.auth = bd.auth;
                    u.addend = bd.addend;
                    if (ch.importAt(bd.import_index)) |imp| {
                        u.symbol = imp.name;
                        u.lib_ordinal = imp.lib_ordinal;
                        u.weak_import = imp.weak;
                        u.addend +%= imp.addend;
                    } else {
                        u.symbol = ch.importName(bd.import_index);
                    }
                },
            }
            try list.append(arena, u);
        }
    } else if (legacy_in) |lg| {
        out.source = .legacy;
        out.legacy = lg.*;
        out.truncated = lg.truncated;
        for (lg.rebases) |rb| {
            if (list.items.len >= limits.max_fixups) {
                out.truncated = true;
                break;
            }
            const va = rb.vmaddr orelse continue;
            const stored: ?u64 = if (img.hdr.is_64) img.u64AtVm(va) else if (img.u32AtVm(va)) |v32| @as(u64, v32) else null;
            try list.append(arena, .{
                .vmaddr = va,
                .kind = .rebase,
                .target = stored orelse 0,
                .symbol = "",
                .lib_ordinal = 0,
                .addend = 0,
                .weak_import = false,
                .auth = null,
                .section = sectionIndex(img, va),
                .raw = stored,
            });
        }
        for (lg.binds) |bd| {
            if (list.items.len >= limits.max_fixups) {
                out.truncated = true;
                break;
            }
            const va = bd.vmaddr orelse continue;
            try list.append(arena, .{
                .vmaddr = va,
                .kind = switch (bd.kind) {
                    .bind => .bind,
                    .weak => .weak_bind,
                    .lazy => .lazy_bind,
                },
                .target = 0,
                .symbol = bd.symbol,
                .lib_ordinal = bd.lib_ordinal,
                .addend = bd.addend,
                .weak_import = bd.weakImport(),
                .auth = null,
                .section = sectionIndex(img, va),
                .raw = null,
            });
        }
    } else {
        return out;
    }
    const fixups = try list.toOwnedSlice(arena);
    std.mem.sort(Fixup, fixups, {}, lessByAddr);
    out.fixups = fixups;
    for (fixups) |f| switch (f.kind) {
        .rebase => out.counts.rebases += 1,
        .bind, .lazy_bind, .weak_bind => {
            out.counts.binds += 1;
            if (f.auth != null) out.counts.auth_binds += 1;
            if (f.kind == .lazy_bind) out.counts.lazy += 1;
            if (f.kind == .weak_bind) out.counts.weak += 1;
        },
    };
    return out;
}

fn sectionIndex(img: *const Image, vmaddr: u64) ?u16 {
    const s = img.sectionForVm(vmaddr) orelse return null;
    return s.index;
}

// ---- tests ----
test "fixups: resolveSlot over a synthetic chained table" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const imports = [_]dyld_chained.Import{
        .{ .lib_ordinal = 1, .weak = false, .name = "_puts", .addend = 0, .name_offset = 0 },
    };
    var ch = dyld_chained.ChainedFixups.empty;
    ch.imports = &imports;
    const cfix = [_]dyld_chained.Fixup{
        .{ .vmaddr = 0x100004000, .file_offset = 0x4000, .seg_index = 2, .raw = 0x8010000000000000, .kind = .{ .bind = .{ .import_index = 0, .addend = 0, .auth = null } } },
        .{ .vmaddr = 0x100008008, .file_offset = 0x8008, .seg_index = 3, .raw = 0, .kind = .{ .rebase = .{ .target = 0x100000668, .auth = null, .high8 = 0 } } },
    };
    ch.fixups = &cfix;
    var d = Diagnostics.init(a, 16);
    var buf: [256]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], std.macho.MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[4..8], 0x0100000c, .little);
    const Reader = @FieldType(Image, "r");
    const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
    const t = try build(a, &img, &ch, null, &Limits.default, &d);
    try std.testing.expectEqual(Source.chained, t.source);
    try std.testing.expectEqual(@as(u32, 1), t.counts.rebases);
    try std.testing.expectEqual(@as(u32, 1), t.counts.binds);
    try std.testing.expectEqualStrings("_puts", t.at(0x100004000).?.symbol);
    try std.testing.expectEqual(@as(i32, 1), t.at(0x100004000).?.lib_ordinal);
    try std.testing.expectEqual(@as(u64, 0x100000668), t.at(0x100008008).?.target);
    try std.testing.expectEqualStrings("_puts", t.bindName(0x100004000).?);
    try std.testing.expect(t.bindName(0x100008008) == null);
    switch (t.resolveSlot(&img, 0x100008008).?) {
        .rebase => |v| try std.testing.expectEqual(@as(u64, 0x100000668), v),
        else => return error.TestUnexpectedResult,
    }
    switch (t.resolveSlot(&img, 0x100004000).?) {
        .bind => |f| try std.testing.expectEqualStrings("_puts", f.symbol),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(t.resolveSlot(&img, 0x999999999) == null);
    try std.testing.expect(FixupTable.empty.at(0) == null);
}

test "fixups: resolveSlot over raw words in pointer formats 1, 2, 6 and 12 (format-notes 4.1)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const base: u64 = 0x100000000;
    const Case = struct { raw: u64, fmt: dyld_chained.PointerFormat, vmaddr: u64 };
    const cases = [_]Case{
        .{ .raw = 0x8010000000000000, .fmt = .@"64_offset", .vmaddr = 0x100004000 }, // bind, ordinal 0
        .{ .raw = 0x0048000100004A03, .fmt = .arm64e, .vmaddr = 0x100008318 }, // rebase -> 0x100004A03
        .{ .raw = 0x0008000000030740, .fmt = .arm64e_userland24, .vmaddr = 0x100010000 }, // rebase -> 0x100030740
        .{ .raw = 0x001000000A4B1718, .fmt = .@"64", .vmaddr = 0x100020000 }, // rebase -> 0xA4B1718 (dylib base 0)
    };
    const imports = [_]dyld_chained.Import{.{ .lib_ordinal = 1, .weak = false, .name = "___chkstk_darwin", .addend = 0, .name_offset = 0 }};
    var cfix: [cases.len]dyld_chained.Fixup = undefined;
    for (cases, 0..) |cs, i| {
        const image_base: u64 = if (cs.fmt == .@"64") 0 else base;
        cfix[i] = .{ .vmaddr = cs.vmaddr, .file_offset = 0, .seg_index = 0, .raw = cs.raw, .kind = dyld_chained.decodePointer(cs.raw, cs.fmt, image_base).? };
    }
    var ch = dyld_chained.ChainedFixups.empty;
    ch.imports = &imports;
    ch.fixups = &cfix;
    var d = Diagnostics.init(a, 16);
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], std.macho.MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[4..8], 0x0100000c, .little);
    const Reader = @FieldType(Image, "r");
    const img = try Image.parse(a, Reader.init(&buf, 0), 0, 0, &Limits.default, &d);
    const t = try build(a, &img, &ch, null, &Limits.default, &d);
    switch (t.resolveSlot(&img, 0x100004000).?) {
        .bind => |f| {
            try std.testing.expectEqualStrings("___chkstk_darwin", f.symbol);
            try std.testing.expectEqual(@as(i32, 1), f.lib_ordinal);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (t.resolveSlot(&img, 0x100008318).?) {
        .rebase => |v| try std.testing.expectEqual(@as(u64, 0x100004A03), v),
        else => return error.TestUnexpectedResult,
    }
    switch (t.resolveSlot(&img, 0x100010000).?) {
        .rebase => |v| try std.testing.expectEqual(@as(u64, 0x100030740), v),
        else => return error.TestUnexpectedResult,
    }
    switch (t.resolveSlot(&img, 0x100020000).?) {
        .rebase => |v| try std.testing.expectEqual(@as(u64, 0xA4B1718), v),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(?u64, 0x100004A03), t.pointerAt(&img, 0x100008318));
    try std.testing.expect(t.pointerAt(&img, 0x100004000) == null);
    // an address with no fixup and no mapped bytes resolves to null, never a trap
    try std.testing.expect(t.resolveSlot(&img, 0xDEAD_BEEF_0000) == null);
}
