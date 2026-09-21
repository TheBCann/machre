//! macho/imports.zig — import/export tables with dylib attribution.
//! Imports: core/image, core/loadcmds, core/diag, core/limits, core/version, macho/symbols, macho/fixups, macho/dyld_exports.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const loadcmds = @import("../core/loadcmds.zig");
const version = @import("../core/version.zig");
const symbols_mod = @import("symbols.zig");
const SymbolTable = symbols_mod.SymbolTable;
const fixups_mod = @import("fixups.zig");
const FixupTable = fixups_mod.FixupTable;
const exports_mod = @import("dyld_exports.zig");
const ExportTrie = exports_mod.ExportTrie;

pub const DylibRef = struct {
    ordinal: u16,
    cmd: u32,
    path: []const u8,
    short_name: []const u8, // dyld_info style: "libSystem", "Foundation"
    current_version: u32,
    compat_version: u32,
    timestamp: u32,
    weak: bool,
    reexport: bool,
    upward: bool,
    delayed_init: bool,
};
pub const ImportSource = enum { chained, legacy, nlist_only };
pub const ImportEntry = struct {
    symbol: []const u8,
    dylib: ?*const DylibRef,
    ordinal: i32, // raw; negative specials
    weak: bool,
    lazy: bool,
    locations: u32,
    first_location: ?u64,
    source: ImportSource,
};
pub const ImportTable = struct {
    dylibs: []const DylibRef,
    imports: []const ImportEntry, // deduped by (symbol, ordinal), first-appearance order
    truncated: bool,
    pub const empty: ImportTable = .{ .dylibs = &.{}, .imports = &.{}, .truncated = false };
};
pub const ExportFrom = enum { trie, nlist };
pub const ExportEntry = struct { name: []const u8, address: u64, weak: bool, kind: []const u8, reexport_from: ?[]const u8, from: ExportFrom };
pub const ExportTable = struct {
    exports: []const ExportEntry,
    truncated: bool,
    pub const empty: ExportTable = .{ .exports = &.{}, .truncated = false };
};

pub fn dylibs(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const DylibRef {
    var list: std.ArrayList(DylibRef) = .empty;
    var ordinal: u16 = 0;
    for (img.cmds) |c| {
        if (!loadcmds.isDylibLoadCmd(c.cmd)) continue;
        ordinal += 1;
        if (list.items.len >= limits.max_dylibs) {
            diags.warn(.imports, .count_clamped, c.offset, "more than limits.max_dylibs {d} dylib load commands; clamped", .{limits.max_dylibs});
            break;
        }
        const d = (try loadcmds.decodeDylib(arena, c, ordinal, diags)) orelse {
            // The ordinal is still spent -- dyld counts load commands, not successful decodes --
            // so the list now has a hole. `dylibFor` resolves by stored ordinal, not position.
            diags.warn(.imports, .cmdsize_invalid, c.offset, "dylib load command is too small to decode; ordinal {d} will not resolve", .{ordinal});
            continue;
        };
        try list.append(arena, .{
            .ordinal = ordinal,
            .cmd = c.cmd,
            .path = d.name,
            .short_name = version.dylibShortName(d.name),
            .current_version = d.current_version,
            .compat_version = d.compat_version,
            .timestamp = d.timestamp,
            .weak = d.weak,
            .reexport = d.reexport,
            .upward = d.upward,
            .delayed_init = d.delayed_init,
        });
    }
    return list.toOwnedSlice(arena);
}

pub fn rpaths(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = img.cmdIterator(.RPATH);
    while (it.next()) |c| {
        if (list.items.len >= limits.max_rpaths) {
            diags.warn(.imports, .count_clamped, c.offset, "more than limits.max_rpaths {d} LC_RPATH commands; clamped", .{limits.max_rpaths});
            break;
        }
        const s = loadcmds.decodeLcStr(c, 8, diags) orelse continue;
        try list.append(arena, s.text);
    }
    return list.toOwnedSlice(arena);
}

/// (symbol, ordinal) -> index into the import list. Keyed by an arena-owned "<ordinal>\x00<symbol>"
/// string so dedup stays O(1) per bind even on a file with a million bind opcodes.
const Dedup = struct {
    map: std.StringHashMapUnmanaged(u32) = .empty,

    fn key(arena: Allocator, symbol: []const u8, ordinal: i32) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(arena, "{d}\x00{s}", .{ ordinal, symbol });
    }
    fn find(d: *Dedup, arena: Allocator, list: []ImportEntry, symbol: []const u8, ordinal: i32) Allocator.Error!?*ImportEntry {
        const k = try key(arena, symbol, ordinal);
        const i = d.map.get(k) orelse return null;
        if (i >= list.len) return null;
        return &list[i];
    }
    fn put(d: *Dedup, arena: Allocator, symbol: []const u8, ordinal: i32, index: usize) Allocator.Error!void {
        try d.map.put(arena, try key(arena, symbol, ordinal), @intCast(index));
    }
};

/// Resolve a positive library ordinal to its `DylibRef`, matching `DylibRef.ordinal`.
///
/// `dl` is NOT indexable by `ordinal - 1`. `dylibs()` spends an ordinal on every dylib load
/// command but drops the ones `decodeDylib` rejects, so a single malformed LC_LOAD_DYLIB leaves
/// a hole and shifts every later entry -- which would silently attribute an import to the wrong
/// library. Ordinals are assigned in ascending order and never repeat, so the positional guess is
/// exact whenever nothing was dropped, and the scan settles the rest.
fn dylibFor(dl: []const DylibRef, ordinal: i32) ?*const DylibRef {
    if (ordinal <= 0) return null;
    const want = std.math.cast(u16, ordinal) orelse return null;
    const guess: usize = @intCast(ordinal - 1);
    if (guess < dl.len and dl[guess].ordinal == want) return &dl[guess];
    for (dl) |*d| {
        if (d.ordinal == want) return d;
    }
    return null;
}

/// Attribution: chained/legacy bind ordinal -> the DylibRef whose `.ordinal` matches (see
/// `dylibFor`, NOT dl[ordinal-1]); nlist-only -> GET_LIBRARY_ORDINAL(n_desc).
pub fn imports(arena: Allocator, img: *const Image, syms: *const SymbolTable, fix: *const FixupTable, dl: []const DylibRef, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ImportTable {
    _ = img;
    var out = ImportTable.empty;
    out.dylibs = dl;
    out.truncated = fix.truncated;
    var list: std.ArrayList(ImportEntry) = .empty;
    var dedup: Dedup = .{};
    switch (fix.source) {
        .chained => {
            const ch = &fix.chained.?;
            // One pass over the fixups counts the slots per import index (O(fixups), not O(n*m)).
            const locations = try arena.alloc(u32, ch.imports.len);
            const first = try arena.alloc(?u64, ch.imports.len);
            @memset(locations, 0);
            @memset(first, null);
            for (ch.fixups) |f| switch (f.kind) {
                .bind => |b| if (b.import_index < locations.len) {
                    locations[b.import_index] +|= 1;
                    if (first[b.import_index] == null) first[b.import_index] = f.vmaddr;
                },
                else => {},
            };
            // Import-table order is what `dyld_info -imports` prints.
            for (ch.imports, 0..) |imp, i| {
                if (list.items.len >= limits.max_imports) {
                    out.truncated = true;
                    break;
                }
                try list.append(arena, .{
                    .symbol = imp.name,
                    .dylib = dylibFor(dl, imp.lib_ordinal),
                    .ordinal = imp.lib_ordinal,
                    .weak = imp.weak,
                    .lazy = false,
                    .locations = locations[i],
                    .first_location = first[i],
                    .source = .chained,
                });
            }
        },
        .legacy => {
            const lg = &fix.legacy.?;
            for (lg.binds) |b| {
                if (b.symbol.len == 0) continue;
                if (try dedup.find(arena, list.items, b.symbol, b.lib_ordinal)) |e| {
                    e.locations +|= 1;
                    if (b.kind == .lazy) e.lazy = true;
                    if (e.first_location == null) e.first_location = b.vmaddr;
                    continue;
                }
                if (list.items.len >= limits.max_imports) {
                    out.truncated = true;
                    break;
                }
                try dedup.put(arena, b.symbol, b.lib_ordinal, list.items.len);
                try list.append(arena, .{
                    .symbol = b.symbol,
                    .dylib = dylibFor(dl, b.lib_ordinal),
                    .ordinal = b.lib_ordinal,
                    .weak = b.weakImport(),
                    .lazy = b.kind == .lazy,
                    .locations = 1,
                    .first_location = b.vmaddr,
                    .source = .legacy,
                });
            }
        },
        .none => {
            for (syms.symbols) |s| {
                if (s.isStab()) continue;
                if (s.kind() != .undefined and s.kind() != .prebound) continue;
                if (s.name.len == 0) continue;
                const ord: i32 = ordinalFromDesc(s.libraryOrdinal());
                if ((try dedup.find(arena, list.items, s.name, ord)) != null) continue;
                if (list.items.len >= limits.max_imports) {
                    out.truncated = true;
                    break;
                }
                try dedup.put(arena, s.name, ord, list.items.len);
                try list.append(arena, .{
                    .symbol = s.name,
                    .dylib = dylibFor(dl, ord),
                    .ordinal = ord,
                    .weak = s.isWeakRef(),
                    .lazy = false,
                    .locations = 0,
                    .first_location = null,
                    .source = .nlist_only,
                });
            }
        },
    }
    for (list.items) |e| {
        if (e.ordinal > 0 and e.dylib == null and !diags.has(.imports, .ordinal_out_of_range))
            diags.warn(.imports, .ordinal_out_of_range, null, "import {s}: library ordinal {d} has no matching dylib load command", .{ e.symbol, e.ordinal });
    }
    out.imports = try list.toOwnedSlice(arena);
    return out;
}

/// GET_LIBRARY_ORDINAL semantics: 0xff EXECUTABLE_ORDINAL -> -1, 0xfe DYNAMIC_LOOKUP_ORDINAL -> -2,
/// 0 SELF_LIBRARY_ORDINAL -> 0; 1..0xfd (MAX_LIBRARY_ORDINAL) are real dylib ordinals.
fn ordinalFromDesc(v: u8) i32 {
    return switch (v) {
        0xff => -1,
        0xfe => -2,
        else => v,
    };
}

pub fn exports(arena: Allocator, img: *const Image, syms: *const SymbolTable, trie: ?*const ExportTrie, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ExportTable {
    _ = diags;
    var out = ExportTable.empty;
    var list: std.ArrayList(ExportEntry) = .empty;
    if (trie) |t| {
        out.truncated = t.truncated;
        for (t.exports) |x| {
            if (list.items.len >= limits.max_exports) {
                out.truncated = true;
                break;
            }
            try list.append(arena, .{
                .name = x.name,
                .address = x.address,
                .weak = x.weak,
                .kind = switch (x.kind) {
                    .regular => "regular",
                    .thread_local => "thread-local",
                    .absolute => "absolute",
                    _ => "unknown",
                },
                .reexport_from = if (x.reexport) |re| re.import_name else null,
                .from = .trie,
            });
        }
    } else {
        for (syms.symbols) |s| {
            if (s.isStab() or !s.isExternal()) continue;
            if (s.kind() != .section and s.kind() != .absolute) continue;
            if (s.name.len == 0) continue;
            if (list.items.len >= limits.max_exports) {
                out.truncated = true;
                break;
            }
            try list.append(arena, .{
                .name = s.name,
                .address = s.n_value,
                .weak = s.isWeakDef(),
                .kind = if (s.kind() == .absolute) "absolute" else "regular",
                .reexport_from = null,
                .from = .nlist,
            });
        }
    }
    _ = img;
    out.exports = try list.toOwnedSlice(arena);
    return out;
}

/// "self", "main-executable", "flat-namespace", "weak-lookup", short name, or "<bad ordinal N>".
pub fn ordinalName(buf: *[32]u8, ordinal: i32, dl: []const DylibRef) []const u8 {
    return switch (ordinal) {
        0 => "self",
        -1 => "main-executable",
        -2 => "flat-namespace",
        -3 => "weak-lookup",
        else => blk: {
            if (dylibFor(dl, ordinal)) |d| break :blk d.short_name;
            break :blk std.fmt.bufPrint(buf, "<bad ordinal {d}>", .{ordinal}) catch "<bad ordinal>";
        },
    };
}

// ---- tests ----
test "imports: ordinalName covers the specials and out-of-range ordinals" {
    var buf: [32]u8 = undefined;
    const dl = [_]DylibRef{
        .{ .ordinal = 1, .cmd = 0xc, .path = "/usr/lib/libSystem.B.dylib", .short_name = "libSystem", .current_version = 0, .compat_version = 0, .timestamp = 0, .weak = false, .reexport = false, .upward = false, .delayed_init = false },
    };
    try std.testing.expectEqualStrings("libSystem", ordinalName(&buf, 1, &dl));
    try std.testing.expectEqualStrings("self", ordinalName(&buf, 0, &dl));
    try std.testing.expectEqualStrings("main-executable", ordinalName(&buf, -1, &dl));
    try std.testing.expectEqualStrings("flat-namespace", ordinalName(&buf, -2, &dl));
    try std.testing.expectEqualStrings("weak-lookup", ordinalName(&buf, -3, &dl));
    try std.testing.expectEqualStrings("<bad ordinal 9>", ordinalName(&buf, 9, &dl));
    try std.testing.expect(dylibFor(&dl, 1) != null and dylibFor(&dl, 2) == null and dylibFor(&dl, -1) == null);
    try std.testing.expectEqual(@as(i32, -1), ordinalFromDesc(0xff));
    try std.testing.expectEqual(@as(i32, -2), ordinalFromDesc(0xfe));
    try std.testing.expectEqual(@as(i32, 3), ordinalFromDesc(3));
    try std.testing.expectEqualStrings("libSystem", version.dylibShortName("/usr/lib/libSystem.B.dylib"));
    try std.testing.expectEqualStrings("Foundation", version.dylibShortName("/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"));
}

test "imports: a gap in the ordinals does not shift attribution onto the wrong dylib" {
    // Regression: dylibFor/ordinalName indexed dl[ordinal-1]. `dylibs()` spends an ordinal on
    // every dylib load command but drops the ones decodeDylib rejects, so one malformed
    // LC_LOAD_DYLIB made every later import resolve to its neighbour -- a crafted binary could
    // make an import appear to come from a benign library. Ordinal 2 is the dropped one here.
    const mk = struct {
        fn f(ord: u16, short: []const u8) DylibRef {
            return .{ .ordinal = ord, .cmd = 0xc, .path = short, .short_name = short, .current_version = 0, .compat_version = 0, .timestamp = 0, .weak = false, .reexport = false, .upward = false, .delayed_init = false };
        }
    }.f;
    const dl = [_]DylibRef{ mk(1, "libSystem"), mk(3, "libEvil") };
    var buf: [32]u8 = undefined;

    // The hole resolves to nothing -- NOT to the entry that happens to sit at that index.
    try std.testing.expect(dylibFor(&dl, 2) == null);
    try std.testing.expectEqualStrings("<bad ordinal 2>", ordinalName(&buf, 2, &dl));
    // And the shifted entry is still reachable by its real ordinal.
    try std.testing.expectEqualStrings("libEvil", dylibFor(&dl, 3).?.short_name);
    try std.testing.expectEqualStrings("libEvil", ordinalName(&buf, 3, &dl));
    // The unshifted prefix and the specials are unaffected.
    try std.testing.expectEqualStrings("libSystem", dylibFor(&dl, 1).?.short_name);
    try std.testing.expect(dylibFor(&dl, 4) == null and dylibFor(&dl, 0) == null);
    // An ordinal past u16 cannot match any DylibRef.ordinal and must not be @intCast into one.
    try std.testing.expect(dylibFor(&dl, 0x1_0001) == null);
    try std.testing.expectEqualStrings("<bad ordinal 65537>", ordinalName(&buf, 0x1_0001, &dl));
}
