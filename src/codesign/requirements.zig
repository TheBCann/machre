//! codesign/requirements.zig — CSMAGIC_REQUIREMENTS set + expression pretty-printer (codesign -d -r- text).
//! Imports: core/reader, core/diag, core/limits, core/sanitize.
const std = @import("std");
const Allocator = std.mem.Allocator;
const reader_mod = @import("../core/reader.zig");
const Reader = reader_mod.Reader;
const Cursor = reader_mod.Cursor;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");

pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
/// Expression-form requirement (the only `kind` Apple emits).
pub const exprForm: u32 = 1;

pub const RequirementType = enum(u32) {
    host = 1,
    guest = 2,
    designated = 3,
    library = 4,
    plugin = 5,
    _,
    /// codesign's spelling of the `<type> => ...` prefix.
    pub fn label(t: RequirementType) []const u8 {
        return switch (t) {
            .host => "host",
            .guest => "guest",
            .designated => "designated",
            .library => "library",
            .plugin => "plugin",
            _ => "requirement",
        };
    }
};
pub const Requirement = struct { type: RequirementType, text: []const u8, raw: []const u8, ops: u32, truncated: bool };
pub const RequirementSet = struct {
    requirements: []const Requirement,

    pub const empty: RequirementSet = .{ .requirements = &.{} };
    pub fn designated(s: *const RequirementSet) ?*const Requirement {
        for (s.requirements) |*r| if (r.type == .designated) return r;
        return null;
    }
};

/// Expression opcodes (`ExprOp`); the high byte carries flags and is masked off before dispatch.
const Op = enum(u32) {
    false_ = 0,
    true_ = 1,
    ident = 2,
    apple_anchor = 3,
    anchor_hash = 4,
    info_key_value = 5,
    and_ = 6,
    or_ = 7,
    cdhash = 8,
    not = 9,
    info_key_field = 10,
    cert_field = 11,
    trusted_cert = 12,
    trusted_certs = 13,
    cert_generic = 14,
    apple_generic_anchor = 15,
    entitlement_field = 16,
    cert_policy = 17,
    named_anchor = 18,
    named_code = 19,
    platform = 20,
    notarized = 21,
    cert_field_date = 22,
    legacy_dev_id = 23,
    _,
};
const op_flag_mask: u32 = 0xff000000;

const Node = struct {
    op: u32,
    children: [2]u32 = .{ 0, 0 },
    n_children: u8 = 0,
    filled: u8 = 0,
    slot: i32 = 0,
    int_val: i32 = 0,
    data1: []const u8 = &.{},
    data2: []const u8 = &.{},
    match: u32 = 0,
    has_match: bool = false,
    /// Set when an operand could not be read (printed as `/* malformed */`).
    bad: bool = false,
};

fn arity(op: u32) u8 {
    return switch (@as(Op, @enumFromInt(op))) {
        .and_, .or_ => 2,
        .not => 1,
        else => 0,
    };
}

/// A parsed expression tree (flat, post-order safe: children are indices into `nodes`).
const Tree = struct { nodes: []const Node, root: u32, ops: u32, truncated: bool };

fn takeData(c: *Cursor, limits: *const Limits) Cursor.Error![]const u8 {
    const len = try c.takeInt(u32, .big);
    if (len > limits.max_blob_len) return error.Truncated;
    const bytes = try c.takeBytes(len);
    const pad = (4 - (len % 4)) % 4;
    c.skip(pad) catch {}; // trailing padding may be absent in a truncated blob
    return bytes;
}

/// Pass 1: flat node array built with an explicit stack (never recursion).
fn parseExpr(arena: Allocator, expr: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Tree {
    const r = Reader.init(expr, 0);
    var c = r.cursor(0) orelse return null;
    var nodes: std.ArrayList(Node) = .empty;
    const max_depth: usize = @max(limits.max_requirement_depth, 1);
    var stack: std.ArrayList(u32) = .empty;
    var truncated = false;

    while (true) {
        if (nodes.items.len >= limits.max_requirement_ops) {
            diags.warn(.requirements, .limit_reached, null, "requirement expression exceeds {d} opcodes", .{limits.max_requirement_ops});
            truncated = true;
            break;
        }
        const raw_op = c.takeInt(u32, .big) catch {
            if (nodes.items.len != 0 or stack.items.len != 0) {
                if (!diags.has(.requirements, .truncated))
                    diags.warn(.requirements, .truncated, null, "requirement expression ends in the middle of an opcode", .{});
                truncated = true;
            }
            break;
        };
        const op = raw_op & ~op_flag_mask;
        var n: Node = .{ .op = op, .n_children = arity(op) };
        readOperands(&c, &n, limits) catch {
            n.bad = true;
            truncated = true;
            if (!diags.has(.requirements, .opcode_malformed))
                diags.warn(.requirements, .opcode_malformed, null, "requirement opcode {d} has truncated operands", .{op});
        };
        const idx: u32 = @intCast(nodes.items.len);
        try nodes.append(arena, n);
        if (stack.items.len != 0) {
            const parent = stack.items[stack.items.len - 1];
            const p = &nodes.items[parent];
            if (p.filled < 2) {
                p.children[p.filled] = idx;
                p.filled += 1;
            }
        }
        if (n.n_children != 0 and !n.bad) {
            if (stack.items.len >= max_depth) {
                diags.warn(.requirements, .limit_reached, null, "requirement expression nests deeper than {d}", .{max_depth});
                truncated = true;
                break;
            }
            try stack.append(arena, idx);
        } else {
            // This node is complete: pop every parent it completed.
            while (stack.items.len != 0) {
                const top = stack.items[stack.items.len - 1];
                if (nodes.items[top].filled >= nodes.items[top].n_children) {
                    _ = stack.pop();
                } else break;
            }
            if (stack.items.len == 0) break;
        }
    }
    if (nodes.items.len == 0) return null;
    const n_ops: u32 = @intCast(nodes.items.len);
    return .{ .nodes = try nodes.toOwnedSlice(arena), .root = 0, .ops = n_ops, .truncated = truncated };
}

fn readOperands(c: *Cursor, n: *Node, limits: *const Limits) Cursor.Error!void {
    switch (@as(Op, @enumFromInt(n.op))) {
        .ident, .cdhash, .named_anchor, .named_code => n.data1 = try takeData(c, limits),
        .anchor_hash => {
            n.slot = @bitCast(try c.takeInt(u32, .big));
            n.data1 = try takeData(c, limits);
        },
        .info_key_value => {
            n.data1 = try takeData(c, limits);
            n.data2 = try takeData(c, limits);
        },
        .info_key_field, .entitlement_field => {
            n.data1 = try takeData(c, limits);
            try readMatch(c, n, limits);
        },
        .cert_field, .cert_generic, .cert_policy, .cert_field_date => {
            n.slot = @bitCast(try c.takeInt(u32, .big));
            n.data1 = try takeData(c, limits);
            try readMatch(c, n, limits);
        },
        .trusted_cert => n.slot = @bitCast(try c.takeInt(u32, .big)),
        .platform => n.int_val = @bitCast(try c.takeInt(u32, .big)),
        else => {},
    }
}
fn readMatch(c: *Cursor, n: *Node, limits: *const Limits) Cursor.Error!void {
    n.match = try c.takeInt(u32, .big);
    n.has_match = true;
    if (n.match != 0 and n.match != 14) n.data2 = try takeData(c, limits);
}

fn slotName(buf: *[24]u8, slot: i32) []const u8 {
    if (slot == 0) return "leaf";
    if (slot == -1) return "root";
    return std.fmt.bufPrint(buf, "{d}", .{slot}) catch "?";
}
fn isIdentLike(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!(std.ascii.isAlphabetic(s[0]) or s[0] == '_')) return false;
    for (s) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return false;
    return true;
}
/// codesign quotes anything that is not a bare identifier and hex-escapes non-printable data.
fn writeString(out: *std.ArrayList(u8), arena: Allocator, s: []const u8) Allocator.Error!void {
    if (isIdentLike(s)) return out.appendSlice(arena, s);
    if (!sanitize.isClean(s, .text)) {
        try out.appendSlice(arena, "H\"");
        try out.print(arena, "{x}", .{s});
        try out.append(arena, '"');
        return;
    }
    try out.append(arena, '"');
    for (s) |ch| {
        if (ch == '"' or ch == '\\') try out.append(arena, '\\');
        try out.append(arena, ch);
    }
    try out.append(arena, '"');
}
fn writeHexData(out: *std.ArrayList(u8), arena: Allocator, s: []const u8) Allocator.Error!void {
    try out.appendSlice(arena, "H\"");
    try out.print(arena, "{x}", .{s});
    try out.append(arena, '"');
}
fn writeMatch(out: *std.ArrayList(u8), arena: Allocator, n: Node) Allocator.Error!void {
    switch (n.match) {
        0 => return out.appendSlice(arena, " /* exists */"),
        14 => return out.appendSlice(arena, " /* absent */"),
        else => {},
    }
    const opstr: []const u8 = switch (n.match) {
        1 => " = ",
        2 => " ~ ",
        3 => " = ",
        4 => " = ",
        5 => " < ",
        6 => " > ",
        7 => " <= ",
        8 => " >= ",
        9 => " = ",
        10 => " < ",
        11 => " > ",
        12 => " <= ",
        13 => " >= ",
        else => " ?= ",
    };
    try out.appendSlice(arena, opstr);
    if (n.match == 4) try out.append(arena, '*');
    try writeString(out, arena, n.data2);
    if (n.match == 3) try out.append(arena, '*');
}
/// Dotted form of a DER OID content field ("2a 86 48 …" -> "1.2.840.…"); hex when it does not decode.
fn writeOid(out: *std.ArrayList(u8), arena: Allocator, content: []const u8) Allocator.Error!void {
    if (content.len == 0) return out.appendSlice(arena, "?");
    var pos: usize = 0;
    var first = true;
    while (pos < content.len) {
        var v: u64 = 0;
        var ok = false;
        while (pos < content.len) {
            const b = content[pos];
            pos += 1;
            if (v > (std.math.maxInt(u64) >> 7)) return writeHexData(out, arena, content);
            v = (v << 7) | (b & 0x7f);
            if (b & 0x80 == 0) {
                ok = true;
                break;
            }
        }
        if (!ok) return writeHexData(out, arena, content);
        if (first) {
            const a: u64 = @min(v / 40, 2);
            try out.print(arena, "{d}.{d}", .{ a, v - a * 40 });
            first = false;
        } else try out.print(arena, ".{d}", .{v});
    }
    return;
}

const prec_or: u8 = 1;
const prec_and: u8 = 2;

const Work = union(enum) { node: struct { idx: u32, ctx: u8 }, lit: []const u8 };

/// Pass 2: print with codesign precedence using an explicit work stack.
fn renderTree(arena: Allocator, t: Tree) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var stack: std.ArrayList(Work) = .empty;
    try stack.append(arena, .{ .node = .{ .idx = t.root, .ctx = 0 } });
    var steps: u32 = 0;
    while (stack.pop()) |w| {
        steps += 1;
        if (steps > 8 * @as(u32, @intCast(t.nodes.len)) + 64) break;
        switch (w) {
            .lit => |s| try out.appendSlice(arena, s),
            .node => |nd| {
                if (nd.idx >= t.nodes.len) {
                    try out.appendSlice(arena, "/* malformed */");
                    continue;
                }
                const n = t.nodes[nd.idx];
                if (n.bad) {
                    try out.appendSlice(arena, "/* malformed */");
                    continue;
                }
                switch (@as(Op, @enumFromInt(n.op))) {
                    .and_, .or_ => {
                        const is_and = n.op == @intFromEnum(Op.and_);
                        const prec: u8 = if (is_and) prec_and else prec_or;
                        const parens = nd.ctx > prec;
                        if (n.filled < 2) {
                            try out.appendSlice(arena, "/* malformed */");
                            continue;
                        }
                        if (parens) try stack.append(arena, .{ .lit = ")" });
                        try stack.append(arena, .{ .node = .{ .idx = n.children[1], .ctx = prec } });
                        try stack.append(arena, .{ .lit = if (is_and) " and " else " or " });
                        try stack.append(arena, .{ .node = .{ .idx = n.children[0], .ctx = prec } });
                        if (parens) try out.append(arena, '(');
                    },
                    .not => {
                        if (n.filled < 1) {
                            try out.appendSlice(arena, "/* malformed */");
                            continue;
                        }
                        try out.append(arena, '!');
                        try stack.append(arena, .{ .node = .{ .idx = n.children[0], .ctx = 3 } });
                    },
                    else => try writeLeaf(&out, arena, n),
                }
            },
        }
    }
    return out.toOwnedSlice(arena);
}

fn writeLeaf(out: *std.ArrayList(u8), arena: Allocator, n: Node) Allocator.Error!void {
    var buf: [24]u8 = undefined;
    switch (@as(Op, @enumFromInt(n.op))) {
        .false_ => try out.appendSlice(arena, "never"),
        .true_ => try out.appendSlice(arena, "always"),
        .ident => {
            try out.appendSlice(arena, "identifier ");
            try writeString(out, arena, n.data1);
        },
        .apple_anchor => try out.appendSlice(arena, "anchor apple"),
        .apple_generic_anchor => try out.appendSlice(arena, "anchor apple generic"),
        .anchor_hash => {
            try out.print(arena, "certificate {s} = ", .{slotName(&buf, n.slot)});
            try writeHexData(out, arena, n.data1);
        },
        .info_key_value => {
            try out.appendSlice(arena, "info[");
            try out.appendSlice(arena, n.data1);
            try out.appendSlice(arena, "] = ");
            try writeString(out, arena, n.data2);
        },
        .cdhash => {
            try out.appendSlice(arena, "cdhash ");
            try writeHexData(out, arena, n.data1);
        },
        .info_key_field => {
            try out.appendSlice(arena, "info[");
            try out.appendSlice(arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .entitlement_field => {
            try out.appendSlice(arena, "entitlement[");
            try out.appendSlice(arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .cert_field => {
            try out.print(arena, "certificate {s}[", .{slotName(&buf, n.slot)});
            try out.appendSlice(arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .cert_generic => {
            try out.print(arena, "certificate {s}[field.", .{slotName(&buf, n.slot)});
            try writeOid(out, arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .cert_policy => {
            try out.print(arena, "certificate {s}[policy.", .{slotName(&buf, n.slot)});
            try writeOid(out, arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .cert_field_date => {
            try out.print(arena, "certificate {s}[timestamp.", .{slotName(&buf, n.slot)});
            try writeOid(out, arena, n.data1);
            try out.append(arena, ']');
            try writeMatch(out, arena, n);
        },
        .trusted_cert => try out.print(arena, "certificate {s} trusted", .{slotName(&buf, n.slot)}),
        .trusted_certs => try out.appendSlice(arena, "anchor trusted"),
        .named_anchor => {
            try out.appendSlice(arena, "anchor apple ");
            try writeString(out, arena, n.data1);
        },
        .named_code => {
            try out.append(arena, '(');
            try out.appendSlice(arena, n.data1);
            try out.append(arena, ')');
        },
        .platform => try out.print(arena, "platform = {d}", .{n.int_val}),
        .notarized => try out.appendSlice(arena, "notarized"),
        .legacy_dev_id => try out.appendSlice(arena, "legacy"),
        // handled by renderTree; reaching them here means a malformed tree, never a trap
        .and_, .or_, .not => try out.appendSlice(arena, "/* malformed */"),
        _ => try out.print(arena, "/* opcode {d} */", .{n.op}),
    }
}

/// Strips a CSMAGIC_REQUIREMENT header (magic, length, kind) when present.
fn exprBytes(blob: []const u8, diags: *Diagnostics) []const u8 {
    if (blob.len < 12) return blob;
    const r = Reader.init(blob, 0);
    const magic = r.u32At(0, .big) orelse return blob;
    if (magic != CSMAGIC_REQUIREMENT) return blob;
    const len = r.u32At(4, .big) orelse @as(u32, @intCast(blob.len));
    const kind = r.u32At(8, .big) orelse exprForm;
    if (kind != exprForm and !diags.has(.requirements, .unknown_value))
        diags.warn(.requirements, .unknown_value, null, "requirement kind {d} is not exprForm", .{kind});
    const end = @min(@as(u64, len), blob.len);
    // `len` counts the 12-byte header, so anything below it is malformed -- and `blob[12..end]`
    // would trap with start > end rather than yield an empty expression.
    if (end < 12) {
        if (!diags.has(.requirements, .blob_malformed))
            diags.warn(.requirements, .blob_malformed, null, "requirement blob declares length {d} (< 12, its own header)", .{len});
        return blob[0..0];
    }
    return blob[12..@intCast(end)];
}

const Rendered = struct { text: []const u8, ops: u32, truncated: bool };
fn render(arena: Allocator, expr_blob: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Rendered {
    const expr = exprBytes(expr_blob, diags);
    const tree = try parseExpr(arena, expr, limits, diags) orelse return .{ .text = "", .ops = 0, .truncated = expr.len != 0 };
    return .{ .text = try renderTree(arena, tree), .ops = tree.ops, .truncated = tree.truncated };
}

pub fn parseSet(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!RequirementSet {
    const r = Reader.init(bytes, 0);
    if (r.len() < 12) {
        if (r.len() != 0) diags.err(.requirements, .truncated, null, "requirements blob is {d} bytes", .{r.len()});
        return .empty;
    }
    const magic = r.u32At(0, .big).?;
    if (magic == CSMAGIC_REQUIREMENT) {
        // A bare requirement where a set was expected: present it as the designated one.
        const rr = try render(arena, bytes, limits, diags);
        const one = try arena.alloc(Requirement, 1);
        one[0] = .{ .type = .designated, .text = rr.text, .raw = bytes, .ops = rr.ops, .truncated = rr.truncated };
        return .{ .requirements = one };
    }
    if (magic != CSMAGIC_REQUIREMENTS) {
        diags.err(.requirements, .blob_malformed, null, "requirements blob magic 0x{x} is not CSMAGIC_REQUIREMENTS", .{magic});
        return .empty;
    }
    var total: u64 = r.u32At(4, .big).?;
    if (total > r.len()) {
        diags.warn(.requirements, .truncated, null, "requirements blob declares {d} bytes, {d} present", .{ total, r.len() });
        total = r.len();
    }
    var count: u64 = r.u32At(8, .big).?;
    const room: u64 = if (total >= 12) (total - 12) / 8 else 0;
    if (count > room or count > limits.max_superblob_slots) {
        const clamped = @min(count, @min(room, @as(u64, limits.max_superblob_slots)));
        diags.warn(.requirements, .count_clamped, null, "requirements set declares {d} entries, using {d}", .{ count, clamped });
        count = clamped;
    }
    var list: std.ArrayList(Requirement) = .empty;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const rtype = r.u32At(12 + i * 8, .big) orelse break;
        // u64 for the same reason as blobs.zig's slot offset: `off + 8` wraps at u32 width.
        const off: u64 = r.u32At(16 + i * 8, .big) orelse break;
        if (off + 8 > total) {
            diags.warn(.requirements, .blob_malformed, off, "requirement {d} lies outside the blob", .{i});
            continue;
        }
        const blen = r.u32At(off + 4, .big) orelse continue;
        const avail = @min(@as(u64, blen), total - off);
        const raw = r.sliceAt(off, avail) orelse continue;
        const rr = try render(arena, raw, limits, diags);
        try list.append(arena, .{ .type = @enumFromInt(rtype), .text = rr.text, .raw = raw, .ops = rr.ops, .truncated = rr.truncated or avail < blen });
    }
    return .{ .requirements = try list.toOwnedSlice(arena) };
}

/// Two-pass, stack-based: pass 1 builds a flat post-order node array (op, operands, children) bounded by
/// limits.max_requirement_ops/depth; pass 2 emits text with codesign precedence (flat `and`, parenthesised `or`,
/// quoting only non-identifier strings, `leaf`/`root`/`certificate N`, match ops, `/* exists */`).
pub fn prettyPrint(arena: Allocator, expr_blob: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const u8 {
    const rr = try render(arena, expr_blob, limits, diags);
    return rr.text;
}
/// `cdhash H"<hex>"` — what codesign synthesises when there is no requirements blob.
pub fn synthesizedDesignated(arena: Allocator, cdhash: [20]u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "cdhash H\"{x}\"", .{&cdhash});
}
/// `cdhash H"a" or cdhash H"b"` for universal ad-hoc signatures.
pub fn synthesizedDesignatedMulti(arena: Allocator, cdhashes: []const [20]u8) Allocator.Error![]const u8 {
    if (cdhashes.len == 0) return "";
    var out: std.ArrayList(u8) = .empty;
    for (cdhashes, 0..) |h, i| {
        if (i != 0) try out.appendSlice(arena, " or ");
        try out.print(arena, "cdhash H\"{x}\"", .{&h});
    }
    return out.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------------------------
// tests

fn expectText(expected: []const u8, blob: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 32);
    const text = try prettyPrint(arena, blob, &Limits.default, &d);
    try std.testing.expectEqualStrings(expected, text);
}

test "requirements: /bin/ls 40-byte blob decodes to codesign's text" {
    // fade0c00 00000028 00000001 | and(ident "com.apple.ls", appleAnchor)
    const blob = [_]u8{
        0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x06, // and
        0x00, 0x00, 0x00, 0x02, // ident
        0x00, 0x00, 0x00, 0x0c, 'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e', '.', 'l', 's',
        0x00, 0x00, 0x00, 0x03, // anchor apple
    };
    try expectText("identifier \"com.apple.ls\" and anchor apple", &blob);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 32);
    // The same blob inside a requirements set.
    var set_buf: [64]u8 = @splat(0);
    std.mem.writeInt(u32, set_buf[0..4], CSMAGIC_REQUIREMENTS, .big);
    std.mem.writeInt(u32, set_buf[4..8], 20 + blob.len, .big);
    std.mem.writeInt(u32, set_buf[8..12], 1, .big);
    std.mem.writeInt(u32, set_buf[12..16], 3, .big); // designated
    std.mem.writeInt(u32, set_buf[16..20], 20, .big);
    @memcpy(set_buf[20..][0..blob.len], &blob);
    const set = try parseSet(arena, set_buf[0 .. 20 + blob.len], &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 1), set.requirements.len);
    try std.testing.expectEqualStrings("identifier \"com.apple.ls\" and anchor apple", set.designated().?.text);
    try std.testing.expectEqual(@as(u32, 3), set.designated().?.ops);
    try std.testing.expect(!d.hasErrors());
}

test "requirements: precedence, matches, oids, synthesized text" {
    // always
    try expectText("always", &[_]u8{ 0xfa, 0xde, 0x0c, 0x00, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1 });
    // or inside and gets parentheses; and inside and stays flat
    // and( ident "a", or( cdhash H"01", cdhash H"02" ) )
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const a = std.testing.allocator;
    try appendU32(&buf, a, 6); // and
    try appendU32(&buf, a, 2); // ident
    try appendU32(&buf, a, 1);
    try buf.appendSlice(a, &[_]u8{ 'a', 0, 0, 0 });
    try appendU32(&buf, a, 7); // or
    try appendU32(&buf, a, 8); // cdhash
    try appendU32(&buf, a, 1);
    try buf.appendSlice(a, &[_]u8{ 0x01, 0, 0, 0 });
    try appendU32(&buf, a, 8);
    try appendU32(&buf, a, 1);
    try buf.appendSlice(a, &[_]u8{ 0x02, 0, 0, 0 });
    try expectText("identifier a and (cdhash H\"01\" or cdhash H\"02\")", buf.items);

    // certGeneric with an exists match and an OID operand
    var b2: std.ArrayList(u8) = .empty;
    defer b2.deinit(a);
    try appendU32(&b2, a, 14); // certGeneric
    try appendU32(&b2, a, 0); // leaf
    try appendU32(&b2, a, 10);
    try b2.appendSlice(a, &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0d, 0, 0 });
    try appendU32(&b2, a, 0); // exists
    try expectText("certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */", b2.items);

    // certField equal with a value that needs quoting (starts with a digit)
    var b3: std.ArrayList(u8) = .empty;
    defer b3.deinit(a);
    try appendU32(&b3, a, 11); // certField
    try appendU32(&b3, a, 0);
    try appendU32(&b3, a, 10);
    try b3.appendSlice(a, "subject.OU");
    try b3.appendSlice(a, &[_]u8{ 0, 0 });
    try appendU32(&b3, a, 1); // equal
    try appendU32(&b3, a, 10);
    try b3.appendSlice(a, "53Q6R32WPB");
    try b3.appendSlice(a, &[_]u8{ 0, 0 });
    try expectText("certificate leaf[subject.OU] = \"53Q6R32WPB\"", b3.items);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const h: [20]u8 = .{ 0xf8, 0x65, 0xcf, 0x1c, 0xb3, 0xb6, 0x5e, 0x2c, 0xf6, 0x8e, 0x9a, 0x86, 0x25, 0xa7, 0xab, 0xda, 0x5f, 0x83, 0xee, 0x5b };
    try std.testing.expectEqualStrings("cdhash H\"f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b\"", try synthesizedDesignated(arena, h));
    try std.testing.expectEqualStrings("cdhash H\"f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b\" or cdhash H\"f865cf1cb3b65e2cf68e9a8625a7abda5f83ee5b\"", try synthesizedDesignatedMulti(arena, &.{ h, h }));
}

fn appendU32(list: *std.ArrayList(u8), a: Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try list.appendSlice(a, &b);
}

test "requirements: truncation and absurd input never trap" {
    const blob = [_]u8{
        0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 'c', 'o', 'm', '.',
        'a',  'p',  'p',  'l',  'e',  '.',  'l',  's',  0x00, 0x00, 0x00, 0x03,
    };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (0..blob.len + 1) |n| {
        var d = Diagnostics.init(arena, 32);
        _ = try prettyPrint(arena, blob[0..n], &Limits.paranoid, &d);
        _ = try parseSet(arena, blob[0..n], &Limits.paranoid, &d);
    }
    // A deeply nested and-chain terminates at the depth cap.
    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(std.testing.allocator);
    for (0..4096) |_| try appendU32(&deep, std.testing.allocator, 6);
    var d2 = Diagnostics.init(arena, 32);
    const txt = try prettyPrint(arena, deep.items, &Limits.paranoid, &d2);
    try std.testing.expect(txt.len < 1 << 20);
    // Absurd data length in an operand.
    var bad = [_]u8{ 0, 0, 0, 2, 0xff, 0xff, 0xff, 0xff };
    var d3 = Diagnostics.init(arena, 32);
    try std.testing.expectEqualStrings("/* malformed */", try prettyPrint(arena, &bad, &Limits.default, &d3));
}

test "requirements: an entry offset near maxInt(u32) is rejected, not wrapped" {
    // Regression: `off + 8 > total` at u32 width trapped on the add before it could reject.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]u32{ 0xffff_ffff, 0xffff_fff8, 0x8000_0000 }) |bad_off| {
        var d = Diagnostics.init(arena, 16);
        var buf: [20]u8 = undefined;
        @memset(&buf, 0);
        std.mem.writeInt(u32, buf[0..4], CSMAGIC_REQUIREMENTS, .big);
        std.mem.writeInt(u32, buf[4..8], buf.len, .big);
        std.mem.writeInt(u32, buf[8..12], 1, .big); // one entry
        std.mem.writeInt(u32, buf[12..16], 3, .big); // kSecDesignatedRequirementType
        std.mem.writeInt(u32, buf[16..20], bad_off, .big);
        const set = try parseSet(arena, &buf, &Limits.default, &d);
        try std.testing.expectEqual(@as(usize, 0), set.requirements.len);
        try std.testing.expect(d.has(.requirements, .blob_malformed));
    }
}

test "requirements: a declared length below its own header yields no expression" {
    // Regression: exprBytes clamped `end` to the declared length and then sliced blob[12..end],
    // so a length under 12 gave start > end -- a trap, not an empty expression.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]u32{ 0, 1, 8, 11 }) |bad_len| {
        var d = Diagnostics.init(arena, 16);
        var buf: [16]u8 = undefined;
        @memset(&buf, 0);
        std.mem.writeInt(u32, buf[0..4], CSMAGIC_REQUIREMENT, .big);
        std.mem.writeInt(u32, buf[4..8], bad_len, .big);
        std.mem.writeInt(u32, buf[8..12], 1, .big); // exprForm
        try std.testing.expectEqualStrings("", try prettyPrint(arena, &buf, &Limits.default, &d));
        // Reachable through the set path too -- parseSet treats a bare requirement as designated.
        _ = try parseSet(arena, &buf, &Limits.default, &d);
        try std.testing.expect(d.has(.requirements, .blob_malformed));
    }
}
