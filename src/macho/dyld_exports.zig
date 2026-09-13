//! macho/dyld_exports.zig — export trie (LC_DYLD_EXPORTS_TRIE or dyld_info.export_off), iterative walker.
//! Imports: core/image, core/reader, core/diag, core/limits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const reader_mod = @import("../core/reader.zig");
const Reader = reader_mod.Reader;
const Cursor = reader_mod.Cursor;

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;
pub const EXPORT_SYMBOL_FLAGS_STATIC_RESOLVER: u64 = 0x20;

pub const ExportKind = enum(u2) { regular = 0, thread_local = 1, absolute = 2, _ };
pub const Reexport = struct { ordinal: u32, import_name: []const u8 };
pub const StubResolver = struct { stub: u64, resolver: u64 };
pub const Export = struct {
    name: []const u8,
    flags: u64,
    address: u64, // image_base + offset (0 for reexports)
    offset: u64,
    kind: ExportKind,
    weak: bool,
    reexport: ?Reexport,
    stub_resolver: ?StubResolver,
};
pub const ExportTrie = struct {
    source: enum { exports_trie, dyld_info },
    dataoff: u32,
    datasize: u32,
    exports: []const Export, // trie (DFS) order
    nodes_visited: u32,
    truncated: bool,
    pub const empty: ExportTrie = .{ .source = .exports_trie, .dataoff = 0, .datasize = 0, .exports = &.{}, .nodes_visited = 0, .truncated = false };
    pub fn byName(t: *const ExportTrie, name: []const u8) ?*const Export {
        for (t.exports) |*x| if (std.mem.eql(u8, x.name, name)) return x;
        return null;
    }
};

/// Null when neither LC_DYLD_EXPORTS_TRIE nor dyld_info export_off exists.
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?ExportTrie {
    var source: @FieldType(ExportTrie, "source") = .exports_trie;
    var dataoff: u32 = 0;
    var datasize: u32 = 0;
    if (img.findCmd(.DYLD_EXPORTS_TRIE)) |c| {
        if (c.bytes.len < 16) return null;
        dataoff = c.reader().u32At(8, c.endian).?;
        datasize = c.reader().u32At(12, c.endian).?;
    } else {
        const c = img.findCmd(.DYLD_INFO_ONLY) orelse img.findCmd(.DYLD_INFO) orelse return null;
        const di = c.reader().structAt(std.macho.dyld_info_command, 0, c.endian) orelse return null;
        source = .dyld_info;
        dataoff = di.export_off;
        datasize = di.export_size;
    }
    var out = ExportTrie.empty;
    out.source = source;
    out.dataoff = dataoff;
    out.datasize = datasize;
    if (datasize == 0) return out;
    const trie = img.linkeditReader(dataoff, datasize, diags, .exports) orelse {
        out.truncated = true;
        return out;
    };
    var walked = try parseBytes(arena, trie.bytes, img.image_base, limits, diags);
    walked.source = source;
    walked.dataoff = dataoff;
    walked.datasize = datasize;
    return walked;
}

const Frame = struct {
    node_off: u32,
    /// Length of the accumulated name before this node's edge label was appended.
    name_len_before: u32,
    /// Cursor position of the next child record (0 = node not opened yet).
    child_cursor: u32,
    child_index: u8,
    child_count: u8,
    opened: bool,
};

/// Walk an arbitrary trie payload (tests, nested).
pub fn parseBytes(arena: Allocator, trie: []const u8, image_base: u64, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ExportTrie {
    var out = ExportTrie.empty;
    if (trie.len == 0) return out;
    const r = Reader.init(trie, 0);
    var exports: std.ArrayList(Export) = .empty;
    var name: std.ArrayList(u8) = .empty;
    var frames: std.ArrayList(Frame) = .empty;
    var visited = try std.DynamicBitSetUnmanaged.initEmpty(arena, trie.len);
    try frames.append(arena, .{ .node_off = 0, .name_len_before = 0, .child_cursor = 0, .child_index = 0, .child_count = 0, .opened = false });

    while (frames.items.len != 0) {
        const f = &frames.items[frames.items.len - 1];
        if (!f.opened) {
            f.opened = true;
            if (out.nodes_visited >= limits.max_trie_nodes) {
                if (!diags.has(.exports, .limit_reached))
                    diags.warn(.exports, .limit_reached, f.node_off, "export trie node count reached limits.max_trie_nodes {d}; stopped", .{limits.max_trie_nodes});
                out.truncated = true;
                break;
            }
            if (visited.isSet(f.node_off)) {
                if (!diags.has(.exports, .trie_malformed))
                    diags.warn(.exports, .trie_malformed, f.node_off, "export trie node at {d} is reachable twice; cycle guard stopped the walk", .{f.node_off});
                out.truncated = true;
                name.shrinkRetainingCapacity(f.name_len_before); // drop this edge's label so siblings start clean
                _ = frames.pop();
                continue;
            }
            visited.set(f.node_off);
            out.nodes_visited += 1;
            const opened = openNode(arena, r, f.node_off, name.items, image_base, &exports, limits, diags, &out) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    out.truncated = true;
                    name.shrinkRetainingCapacity(f.name_len_before);
                    _ = frames.pop();
                    continue;
                },
            };
            f.child_cursor = opened.child_cursor;
            f.child_count = opened.child_count;
            f.child_index = 0;
        }
        if (f.child_index >= f.child_count) {
            name.shrinkRetainingCapacity(f.name_len_before);
            _ = frames.pop();
            continue;
        }
        f.child_index += 1;
        var c = r.cursor(f.child_cursor) orelse {
            f.child_index = f.child_count;
            continue;
        };
        const label = c.takeCstr(limits.max_symbol_name) catch {
            if (!diags.has(.exports, .trie_malformed))
                diags.warn(.exports, .trie_malformed, f.child_cursor, "export trie: child edge label at {d} is not terminated inside the trie", .{f.child_cursor});
            out.truncated = true;
            f.child_index = f.child_count;
            continue;
        };
        const child_off = c.takeUleb() catch {
            if (!diags.has(.exports, .trie_malformed))
                diags.warn(.exports, .trie_malformed, f.child_cursor, "export trie: child node offset at {d} is malformed", .{f.child_cursor});
            out.truncated = true;
            f.child_index = f.child_count;
            continue;
        };
        f.child_cursor = @intCast(c.pos);
        if (child_off >= trie.len) {
            if (!diags.has(.exports, .trie_malformed))
                diags.warn(.exports, .trie_malformed, f.child_cursor, "export trie: child node offset {d} lies outside the {d}-byte trie", .{ child_off, trie.len });
            out.truncated = true;
            continue;
        }
        if (frames.items.len >= limits.max_trie_depth) {
            if (!diags.has(.exports, .limit_reached))
                diags.warn(.exports, .limit_reached, f.child_cursor, "export trie depth reached limits.max_trie_depth {d}", .{limits.max_trie_depth});
            out.truncated = true;
            continue;
        }
        const before: u32 = @intCast(name.items.len);
        if (name.items.len + label.len > limits.max_symbol_name) {
            if (!diags.has(.exports, .limit_reached))
                diags.warn(.exports, .limit_reached, f.child_cursor, "export trie: symbol name longer than limits.max_symbol_name {d}", .{limits.max_symbol_name});
            out.truncated = true;
            continue;
        }
        try name.appendSlice(arena, label);
        try frames.append(arena, .{ .node_off = @intCast(child_off), .name_len_before = before, .child_cursor = 0, .child_index = 0, .child_count = 0, .opened = false });
    }
    out.exports = try exports.toOwnedSlice(arena);
    return out;
}

const Opened = struct { child_cursor: u32, child_count: u8 };

fn openNode(
    arena: Allocator,
    r: Reader,
    node_off: u32,
    name: []const u8,
    image_base: u64,
    exports: *std.ArrayList(Export),
    limits: *const Limits,
    diags: *Diagnostics,
    out: *ExportTrie,
) (Allocator.Error || Cursor.Error)!Opened {
    var c = r.cursor(node_off) orelse return error.Truncated;
    const terminal_size = try c.takeUleb();
    const after_terminal_size: u64 = c.pos;
    if (terminal_size != 0) {
        const end = std.math.add(u64, after_terminal_size, terminal_size) catch return error.Overflow;
        if (end > r.len()) {
            if (!diags.has(.exports, .trie_malformed))
                diags.warn(.exports, .trie_malformed, node_off, "export trie: terminal payload at node {d} ends past the trie", .{node_off});
            return error.Truncated;
        }
        if (exports.items.len >= limits.max_exports) {
            if (!diags.has(.exports, .limit_reached))
                diags.warn(.exports, .limit_reached, node_off, "exports clamped to limits.max_exports {d}", .{limits.max_exports});
            out.truncated = true;
        } else {
            const flags = try c.takeUleb();
            var x: Export = .{
                .name = try arena.dupe(u8, name),
                .flags = flags,
                .address = 0,
                .offset = 0,
                .kind = @enumFromInt(@as(u2, @truncate(flags & EXPORT_SYMBOL_FLAGS_KIND_MASK))),
                .weak = flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0,
                .reexport = null,
                .stub_resolver = null,
            };
            if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0) {
                const ord = try c.takeUleb();
                const imp = c.takeCstr(limits.max_symbol_name) catch "";
                x.reexport = .{ .ordinal = @truncate(ord), .import_name = imp };
            } else if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0) {
                const stub = try c.takeUleb();
                const resolver = try c.takeUleb();
                x.stub_resolver = .{ .stub = stub, .resolver = resolver };
                x.offset = stub;
                x.address = image_base +% stub;
            } else {
                const off = try c.takeUleb();
                x.offset = off;
                x.address = if (x.kind == .absolute) off else image_base +% off;
            }
            try exports.append(arena, x);
        }
        try c.seek(@intCast(end));
    }
    const child_count = try c.takeU8();
    return .{ .child_cursor = @intCast(c.pos), .child_count = child_count };
}

// ---- tests ----
test "dyld_exports: the verified enumerateProcess trie (format-notes 4.2)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var d = Diagnostics.init(a, 32);
    const trie = [_]u8{
        0x00, 0x01, '_', 0x00, 0x17, // node0: no terminal, 1 child "_" -> 0x17
        0x00, 0x00, 0x00, 0x00, // padding ld64 leaves behind
        0x02, 0x00, 0x00, 0x00, // @0x09 terminal 2: flags 0 offset 0; 0 children
        0x03, 0x00, 0xe0, 0x08, 0x00, // @0x0d terminal 3: flags 0 offset 0x460; 0 children
        0x03, 0x00, 0x8c, 0x0a, 0x00, // @0x12 terminal 3: flags 0 offset 0x50c; 0 children
        0x00, 0x03, // @0x17 no terminal, 3 children
        '_', 'm', 'h', '_', 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'h', 'e', 'a', 'd', 'e', 'r', 0x00, 0x09,
        'g', 'e', 't', 'A', 'u', 'd', 'i', 't', 'T', 'o', 'k', 'e', 'n', 0x00, 0x0d,
        'm', 'a', 'i', 'n', 0x00, 0x12,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const t = try parseBytes(a, &trie, 0x100000000, &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 3), t.exports.len);
    try std.testing.expectEqualStrings("__mh_execute_header", t.exports[0].name);
    try std.testing.expectEqual(@as(u64, 0), t.exports[0].offset);
    try std.testing.expectEqual(@as(u64, 0x100000000), t.exports[0].address);
    try std.testing.expectEqualStrings("_getAuditToken", t.exports[1].name);
    try std.testing.expectEqual(@as(u64, 0x460), t.exports[1].offset);
    try std.testing.expectEqualStrings("_main", t.exports[2].name);
    try std.testing.expectEqual(@as(u64, 0x50c), t.exports[2].offset);
    try std.testing.expect(t.byName("_main") != null and t.byName("_nope") == null);
    try std.testing.expect(!t.truncated);
    try std.testing.expectEqual(@as(usize, 0), d.items().len);
}

test "dyld_exports: every prefix of the trie parses and a self-referencing child is caught" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const trie = [_]u8{ 0x00, 0x01, '_', 0x00, 0x05, 0x00, 0x01, 'x', 0x00, 0x00 }; // node@5 child "x" -> node 0 (cycle)
    var d = Diagnostics.init(a, 32);
    const t = try parseBytes(a, &trie, 0, &Limits.default, &d);
    try std.testing.expect(t.truncated);
    try std.testing.expect(d.has(.exports, .trie_malformed));
    var len: usize = 0;
    while (len <= trie.len) : (len += 1) {
        var d2 = Diagnostics.init(a, 32);
        _ = try parseBytes(a, trie[0..len], 0, &Limits.paranoid, &d2);
    }
    // a node whose child offset is past the end
    const bad = [_]u8{ 0x00, 0x01, 'a', 0x00, 0x7f };
    var d3 = Diagnostics.init(a, 32);
    const t3 = try parseBytes(a, &bad, 0, &Limits.default, &d3);
    try std.testing.expect(t3.truncated and t3.exports.len == 0);
}

test "dyld_exports: a cycle in one child does not leak its edge label into the next sibling" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // root @0: no terminal, 2 children: "x" -> node 0 (a cycle), "y" -> node 9 (a real export).
    const trie = [_]u8{
        0x00, 0x02, 'x', 0x00, 0x00, 'y', 0x00, 0x09, 0x00,
        0x02, 0x00, 0x2a, 0x00, // @9: terminal size 2 (flags 0, offset 0x2a), 0 children
    };
    var d = Diagnostics.init(a, 32);
    const t = try parseBytes(a, &trie, 0x100000000, &Limits.default, &d);
    try std.testing.expect(t.truncated);
    try std.testing.expectEqual(@as(usize, 1), t.exports.len);
    try std.testing.expectEqualStrings("y", t.exports[0].name);
    try std.testing.expectEqual(@as(u64, 0x2a), t.exports[0].offset);
}
