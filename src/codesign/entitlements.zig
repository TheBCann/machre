//! codesign/entitlements.zig — XML (via plist/xml) and DER (via asn1) entitlements.
//! Imports: core/diag, core/limits, codesign/blobs, codesign/asn1, plist/plist, plist/xml.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const blobs = @import("blobs.zig");
const Signature = blobs.Signature;
const asn1 = @import("asn1.zig");
const plist = @import("../plist/plist.zig");
const plist_xml = @import("../plist/xml.zig");

/// `[APPLICATION 16]` — the outer tag of a DER entitlements blob.
pub const der_outer_tag: u8 = 0x70;
/// `[CONTEXT 16]` — a DER entitlements dictionary.
pub const der_dict_tag: u8 = 0xb0;
/// Seconds between the Unix and the CoreFoundation epochs (plist dates are CF-relative).
const cf_epoch_offset: f64 = 978307200.0;

pub const EntSource = enum { xml, der, both, none };
pub const Entitlements = struct {
    source: EntSource,
    xml: ?plist.Value,
    der: ?plist.Value,
    keys: []const []const u8, // union, sorted
    xml_raw: ?[]const u8,
    /// Length of the DER blob including its 8-byte header (0 when absent).
    der_len: u32,
    disagreement: bool, // XML and DER differ in keys or values -> triage tell

    pub const empty: Entitlements = .{ .source = .none, .xml = null, .der = null, .keys = &.{}, .xml_raw = null, .der_len = 0, .disagreement = false };
    pub fn get(e: *const Entitlements, key: []const u8) ?plist.Value {
        if (e.xml) |v| if (dictGet(v, key)) |x| return x;
        if (e.der) |v| if (dictGet(v, key)) |x| return x;
        return null;
    }
    pub fn isTrue(e: *const Entitlements, key: []const u8) bool {
        const v = e.get(key) orelse return false;
        return switch (v) {
            .bool => |b| b,
            .integer => |i| i != 0,
            else => false,
        };
    }
    /// The value tree codesign prints. codesign renders the CANONICAL dictionary
    /// (`kSecCodeInfoEntitlementsDict`), which comes from the DER blob whenever one is present and only
    /// falls back to the XML blob otherwise -- verified against `codesign -dvvv --entitlements -` and
    /// `-d --entitlements - --xml` on tests/corpus/hello-entitled, whose two blobs carry the same five
    /// keys in different orders (DER is sorted, XML is the author's order).
    pub fn preferred(e: *const Entitlements) ?plist.Value {
        return e.der orelse e.xml;
    }
};

/// Local dictionary lookup: `plist.Value.get` belongs to WP5 and is still a stub.
fn dictGet(v: plist.Value, key: []const u8) ?plist.Value {
    return switch (v) {
        .dict => |entries| blk: {
            for (entries) |e| if (std.mem.eql(u8, e.key, key)) break :blk e.value;
            break :blk null;
        },
        else => null,
    };
}

pub fn parse(arena: Allocator, sig: *const Signature, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Entitlements {
    var e: Entitlements = .empty;
    e.xml_raw = sig.entitlements_xml;
    if (sig.blob(7)) |b| e.der_len = b.length;
    const have_xml = sig.entitlements_xml != null;
    const have_der = sig.entitlements_der != null;
    e.source = if (have_xml and have_der) .both else if (have_xml) .xml else if (have_der) .der else .none;
    if (e.source == .none) return e;

    if (sig.entitlements_xml) |raw| e.xml = try plist_xml.parse(arena, raw, limits, diags);
    if (sig.entitlements_der) |raw| e.der = try parseDer(arena, raw, limits, diags);

    var keys: std.ArrayList([]const u8) = .empty;
    if (e.xml) |v| try collectKeys(arena, &keys, v, limits);
    if (e.der) |v| try collectKeys(arena, &keys, v, limits);
    std.mem.sort([]const u8, keys.items, {}, lessThanString);
    // De-duplicate the union (the two blobs normally carry the same keys).
    var uniq: std.ArrayList([]const u8) = .empty;
    for (keys.items) |k| {
        if (uniq.items.len != 0 and std.mem.eql(u8, uniq.items[uniq.items.len - 1], k)) continue;
        try uniq.append(arena, k);
    }
    e.keys = try uniq.toOwnedSlice(arena);

    if (e.xml != null and e.der != null) {
        e.disagreement = !valuesEqual(e.xml.?, e.der.?);
        if (e.disagreement)
            diags.warn(.entitlements, .heuristic, null, "XML and DER entitlements do not agree", .{});
    }
    return e;
}

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}
fn collectKeys(arena: Allocator, out: *std.ArrayList([]const u8), v: plist.Value, limits: *const Limits) Allocator.Error!void {
    switch (v) {
        .dict => |entries| for (entries) |e| {
            if (out.items.len >= limits.max_entitlement_keys) return;
            try out.append(arena, e.key);
        },
        else => {},
    }
}

/// Iterative deep comparison (no recursion on input-shaped data); `plist.Value.deepEqual` is WP5's.
pub fn valuesEqual(a: plist.Value, b: plist.Value) bool {
    const Pair = struct { a: plist.Value, b: plist.Value };
    var stack: [64]Pair = undefined;
    var depth: usize = 1;
    stack[0] = .{ .a = a, .b = b };
    var steps: u32 = 0;
    while (depth != 0) {
        steps += 1;
        if (steps > 1 << 16) return false;
        depth -= 1;
        const p = stack[depth];
        if (std.meta.activeTag(p.a) != std.meta.activeTag(p.b)) return false;
        switch (p.a) {
            .null => {},
            .bool => if (p.a.bool != p.b.bool) return false,
            .integer => if (p.a.integer != p.b.integer) return false,
            .uid => if (p.a.uid != p.b.uid) return false,
            .real => if (p.a.real != p.b.real) return false,
            .date => if (p.a.date != p.b.date) return false,
            .string => if (!std.mem.eql(u8, p.a.string, p.b.string)) return false,
            .data => if (!std.mem.eql(u8, p.a.data, p.b.data)) return false,
            .array => {
                if (p.a.array.len != p.b.array.len) return false;
                for (p.a.array, p.b.array) |x, y| {
                    if (depth >= stack.len) return false;
                    stack[depth] = .{ .a = x, .b = y };
                    depth += 1;
                }
            },
            .dict => {
                if (p.a.dict.len != p.b.dict.len) return false;
                for (p.a.dict) |ea| {
                    const vb = dictGet(p.b, ea.key) orelse return false;
                    if (depth >= stack.len) return false;
                    stack[depth] = .{ .a = ea.value, .b = vb };
                    depth += 1;
                }
            },
        }
    }
    return true;
}

const Frame = struct {
    /// null key = the root (or an array element)
    key: ?[]const u8,
    is_dict: bool,
    it: asn1.Iterator,
    entries: std.ArrayList(plist.Value.Entry),
    items: std.ArrayList(plist.Value),
};

/// DER grammar (format-notes 5): [APPLICATION 16]{ INTEGER 1, [CONTEXT 16] SET OF SEQUENCE{ UTF8String key, Value } }.
pub fn parseDer(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?plist.Value {
    if (bytes.len == 0) return null;
    const outer = asn1.read(bytes, 0) catch |e| {
        derBad(diags, "outer value: {t}", .{e});
        return null;
    };
    if (outer.indefinite) {
        derBad(diags, "indefinite lengths are not valid DER", .{});
        return null;
    }
    if (outer.class != .application or outer.tag != 16) {
        derBad(diags, "outer tag is class {t} tag {d}, expected [APPLICATION 16]", .{ outer.class, outer.tag });
        return null;
    }
    var it = asn1.children(outer);
    const ver = it.next() catch null orelse {
        derBad(diags, "missing version integer", .{});
        return null;
    };
    if (ver.tag != asn1.tag_integer or asn1.readInteger(ver.content) != 1)
        diags.info(.entitlements, .unknown_value, null, "DER entitlements version is not 1", .{});
    const dict_tlv = it.next() catch null orelse {
        derBad(diags, "missing entitlements dictionary", .{});
        return null;
    };
    if (!(dict_tlv.class == .context and dict_tlv.tag == 16)) {
        derBad(diags, "dictionary tag is class {t} tag {d}, expected [CONTEXT 16]", .{ dict_tlv.class, dict_tlv.tag });
        return null;
    }

    const max_depth: usize = @min(@as(usize, 32), @max(limits.max_der_depth, 1));
    var stack: [32]Frame = undefined;
    var depth: usize = 1;
    stack[0] = .{ .key = null, .is_dict = true, .it = asn1.children(dict_tlv), .entries = .empty, .items = .empty };
    var nodes: u32 = 0;
    var result: ?plist.Value = null;

    while (depth != 0) {
        const top = &stack[depth - 1];
        nodes += 1;
        if (nodes > limits.max_der_nodes) {
            diags.warn(.entitlements, .limit_reached, null, "DER entitlements exceed {d} nodes", .{limits.max_der_nodes});
            break;
        }
        const child_opt: ?asn1.Tlv = top.it.next() catch |e| blk: {
            derBad(diags, "malformed element: {t}", .{e});
            break :blk null;
        };
        const child = child_opt orelse {
            // Frame complete: build its value and attach it to the parent.
            const value: plist.Value = if (top.is_dict)
                .{ .dict = try top.entries.toOwnedSlice(arena) }
            else
                .{ .array = try top.items.toOwnedSlice(arena) };
            const key = top.key;
            depth -= 1;
            if (depth == 0) {
                result = value;
                break;
            }
            const parent = &stack[depth - 1];
            if (parent.is_dict) {
                try parent.entries.append(arena, .{ .key = key orelse "", .value = value });
            } else try parent.items.append(arena, value);
            continue;
        };
        if (child.indefinite) {
            derBad(diags, "indefinite lengths are not valid DER", .{});
            break;
        }
        if (top.is_dict) {
            // Entry ::= SEQUENCE { UTF8String key, Value }
            if (child.tag != asn1.tag_sequence or !child.constructed) {
                derBad(diags, "dictionary entry is tag {d}, expected SEQUENCE", .{child.tag});
                continue;
            }
            var eit = asn1.children(child);
            const key_tlv = (eit.next() catch null) orelse {
                derBad(diags, "dictionary entry has no key", .{});
                continue;
            };
            if (key_tlv.tag != asn1.tag_utf8_string and key_tlv.tag != asn1.tag_printable_string) {
                derBad(diags, "dictionary key is tag {d}, expected UTF8String", .{key_tlv.tag});
                continue;
            }
            const val_tlv = (eit.next() catch null) orelse {
                derBad(diags, "dictionary entry has no value", .{});
                continue;
            };
            if (top.entries.items.len >= limits.max_entitlement_keys) {
                diags.warn(.entitlements, .limit_reached, null, "more than {d} entitlement keys", .{limits.max_entitlement_keys});
                break;
            }
            if (containerKind(val_tlv)) |is_dict| {
                if (depth >= max_depth) {
                    diags.warn(.entitlements, .limit_reached, null, "DER entitlements nest deeper than {d}", .{max_depth});
                    continue;
                }
                stack[depth] = .{ .key = key_tlv.content, .is_dict = is_dict, .it = asn1.children(val_tlv), .entries = .empty, .items = .empty };
                depth += 1;
            } else if (scalar(val_tlv, diags)) |v| {
                try top.entries.append(arena, .{ .key = key_tlv.content, .value = v });
            }
        } else {
            if (containerKind(child)) |is_dict| {
                if (depth >= max_depth) {
                    diags.warn(.entitlements, .limit_reached, null, "DER entitlements nest deeper than {d}", .{max_depth});
                    continue;
                }
                stack[depth] = .{ .key = null, .is_dict = is_dict, .it = asn1.children(child), .entries = .empty, .items = .empty };
                depth += 1;
            } else if (scalar(child, diags)) |v| {
                try top.items.append(arena, v);
            }
        }
    }
    return result;
}

fn derBad(diags: *Diagnostics, comptime fmt: []const u8, args: anytype) void {
    if (!diags.has(.entitlements, .der_malformed)) diags.warn(.entitlements, .der_malformed, null, "DER entitlements: " ++ fmt, args);
}
/// true = dictionary, false = array, null = not a container.
fn containerKind(t: asn1.Tlv) ?bool {
    if (t.class == .context and t.tag == 16 and t.constructed) return true;
    if (t.class == .universal and t.tag == asn1.tag_sequence and t.constructed) return false;
    return null;
}
fn scalar(t: asn1.Tlv, diags: *Diagnostics) ?plist.Value {
    if (t.class != .universal) {
        derBad(diags, "unexpected class {t} tag {d}", .{ t.class, t.tag });
        return null;
    }
    return switch (t.tag) {
        asn1.tag_boolean => .{ .bool = t.content.len != 0 and t.content[t.content.len - 1] != 0 },
        asn1.tag_integer => .{ .integer = asn1.readInteger(t.content) orelse 0 },
        asn1.tag_utf8_string, asn1.tag_printable_string, asn1.tag_ia5_string => .{ .string = t.content },
        asn1.tag_octet_string, asn1.tag_bit_string => .{ .data = t.content },
        asn1.tag_null => .null,
        asn1.tag_utc_time, asn1.tag_generalized_time => blk: {
            const unix = asn1.readTime(t) orelse break :blk plist.Value.null;
            break :blk .{ .date = @as(f64, @floatFromInt(unix)) - cf_epoch_offset };
        },
        else => blk: {
            derBad(diags, "unsupported value tag {d}", .{t.tag});
            break :blk null;
        },
    };
}

pub const Danger = struct { key: []const u8, why: []const u8, weight: u8 };
/// Table of dangerous keys with explanations (triage `ent.*` rules read it).
/// `com.apple.private.*` is matched by prefix; every weight stays well below the triage cap of 50.
pub const dangerous: []const Danger = &.{
    .{ .key = "com.apple.security.cs.disable-library-validation", .why = "any signed library may be loaded into the process (injection)", .weight = 25 },
    .{ .key = "com.apple.security.cs.allow-jit", .why = "writable+executable memory is allowed", .weight = 15 },
    .{ .key = "com.apple.security.cs.allow-unsigned-executable-memory", .why = "unsigned code may be executed from memory", .weight = 25 },
    .{ .key = "com.apple.security.cs.allow-dyld-environment-variables", .why = "DYLD_* environment variables are honoured (library injection)", .weight = 20 },
    .{ .key = "com.apple.security.cs.disable-executable-page-protection", .why = "executable pages may be rewritten at runtime", .weight = 25 },
    .{ .key = "com.apple.security.get-task-allow", .why = "any process may attach a debugger and read/write memory", .weight = 20 },
    .{ .key = "com.apple.security.cs.debugger", .why = "the process may debug other processes", .weight = 25 },
    .{ .key = "com.apple.private.*", .why = "private Apple entitlement: only Apple-signed code normally carries these", .weight = 30 },
};
pub fn isDangerous(key: []const u8) ?*const Danger {
    for (dangerous) |*d| {
        if (std.mem.endsWith(u8, d.key, ".*")) {
            if (std.mem.startsWith(u8, key, d.key[0 .. d.key.len - 1])) return d;
        } else if (std.mem.eql(u8, key, d.key)) return d;
    }
    return null;
}

// ---------------------------------------------------------------------------------------------
// tests

/// The hello-entitled DER shape: [APPLICATION 16]{ INTEGER 1, [CONTEXT 16] { entries } }.
fn buildDer(a: Allocator) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    // com.apple.security.cs.allow-jit = true
    try appendEntry(&body, a, "com.apple.security.cs.allow-jit", &[_]u8{ 0x01, 0x01, 0xff });
    // com.apple.application-identifier = "MACHRE.hello-entitled"
    try appendEntry(&body, a, "com.apple.application-identifier", &[_]u8{ 0x0c, 0x15, 'M', 'A', 'C', 'H', 'R', 'E', '.', 'h', 'e', 'l', 'l', 'o', '-', 'e', 'n', 't', 'i', 't', 'l', 'e', 'd' });
    var dict: std.ArrayList(u8) = .empty;
    try dict.append(a, der_dict_tag);
    try appendLen(&dict, a, body.items.len);
    try dict.appendSlice(a, body.items);
    var inner: std.ArrayList(u8) = .empty;
    try inner.appendSlice(a, &[_]u8{ 0x02, 0x01, 0x01 });
    try inner.appendSlice(a, dict.items);
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, der_outer_tag);
    try appendLen(&out, a, inner.items.len);
    try out.appendSlice(a, inner.items);
    return out.toOwnedSlice(a);
}
fn appendLen(l: *std.ArrayList(u8), a: Allocator, n: usize) !void {
    if (n < 0x80) return l.append(a, @intCast(n));
    if (n < 0x100) {
        try l.append(a, 0x81);
        return l.append(a, @intCast(n));
    }
    try l.append(a, 0x82);
    try l.append(a, @intCast(n >> 8));
    try l.append(a, @intCast(n & 0xff));
}
fn appendEntry(l: *std.ArrayList(u8), a: Allocator, key: []const u8, value: []const u8) !void {
    var entry: std.ArrayList(u8) = .empty;
    try entry.append(a, 0x0c);
    try appendLen(&entry, a, key.len);
    try entry.appendSlice(a, key);
    try entry.appendSlice(a, value);
    try l.append(a, 0x30);
    try appendLen(l, a, entry.items.len);
    try l.appendSlice(a, entry.items);
}

test "entitlements: DER dictionary decodes to plist values" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 32);
    const der = try buildDer(arena);
    const v = (try parseDer(arena, der, &Limits.default, &d)).?;
    try std.testing.expectEqual(@as(usize, 2), v.dict.len);
    try std.testing.expectEqualStrings("com.apple.security.cs.allow-jit", v.dict[0].key);
    try std.testing.expect(v.dict[0].value.bool);
    try std.testing.expectEqualStrings("MACHRE.hello-entitled", v.dict[1].value.string);
    try std.testing.expect(!d.hasErrors());

    var sig: Signature = .empty;
    sig.entitlements_der = der;
    sig.blobs = &[_]blobs.BlobRef{.{ .slot = 7, .offset = 0, .magic = blobs.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, .length = @intCast(der.len + 8), .bytes = der, .truncated = false }};
    const e = try parse(arena, &sig, &Limits.default, &d);
    try std.testing.expectEqual(EntSource.der, e.source);
    try std.testing.expectEqual(@as(usize, 2), e.keys.len);
    try std.testing.expectEqualStrings("com.apple.application-identifier", e.keys[0]); // sorted
    try std.testing.expect(e.isTrue("com.apple.security.cs.allow-jit"));
    try std.testing.expect(!e.isTrue("com.apple.security.get-task-allow"));
    try std.testing.expect(!e.disagreement);
    try std.testing.expectEqual(@as(u32, @intCast(der.len + 8)), e.der_len);
    try std.testing.expect(isDangerous("com.apple.security.cs.allow-jit") != null);
    try std.testing.expect(isDangerous("com.apple.private.tcc.allow") != null);
    try std.testing.expect(isDangerous("com.apple.security.network.client") == null);
}

test "entitlements: nested dictionaries and arrays, equality, malformed input" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const a = arena;
    var d = Diagnostics.init(arena, 64);
    // key -> SEQUENCE { UTF8String "a", UTF8String "b" }, key2 -> [CONTEXT 16] { "k" -> true }
    var inner_dict: std.ArrayList(u8) = .empty;
    try appendEntry(&inner_dict, a, "k", &[_]u8{ 0x01, 0x01, 0xff });
    var dict_val: std.ArrayList(u8) = .empty;
    try dict_val.append(a, der_dict_tag);
    try appendLen(&dict_val, a, inner_dict.items.len);
    try dict_val.appendSlice(a, inner_dict.items);
    var arr: std.ArrayList(u8) = .empty;
    try arr.appendSlice(a, &[_]u8{ 0x0c, 0x01, 'a', 0x0c, 0x01, 'b' });
    var arr_val: std.ArrayList(u8) = .empty;
    try arr_val.append(a, 0x30);
    try appendLen(&arr_val, a, arr.items.len);
    try arr_val.appendSlice(a, arr.items);
    var body: std.ArrayList(u8) = .empty;
    try appendEntry(&body, a, "arr", arr_val.items);
    try appendEntry(&body, a, "dict", dict_val.items);
    var dict: std.ArrayList(u8) = .empty;
    try dict.append(a, der_dict_tag);
    try appendLen(&dict, a, body.items.len);
    try dict.appendSlice(a, body.items);
    var inner: std.ArrayList(u8) = .empty;
    try inner.appendSlice(a, &[_]u8{ 0x02, 0x01, 0x01 });
    try inner.appendSlice(a, dict.items);
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, der_outer_tag);
    try appendLen(&out, a, inner.items.len);
    try out.appendSlice(a, inner.items);

    const v = (try parseDer(arena, out.items, &Limits.default, &d)).?;
    try std.testing.expectEqual(@as(usize, 2), v.dict.len);
    try std.testing.expectEqualStrings("arr", v.dict[0].key);
    try std.testing.expectEqual(@as(usize, 2), v.dict[0].value.array.len);
    try std.testing.expectEqualStrings("b", v.dict[0].value.array[1].string);
    try std.testing.expect(v.dict[1].value.dict[0].value.bool);
    try std.testing.expect(valuesEqual(v, v));
    const other = (try parseDer(arena, try buildDer(arena), &Limits.default, &d)).?;
    try std.testing.expect(!valuesEqual(v, other));

    // Every prefix parses without an error return and without a trap.
    for (0..out.items.len + 1) |n| {
        var dd = Diagnostics.init(arena, 8);
        _ = try parseDer(arena, out.items[0..n], &Limits.paranoid, &dd);
    }
    // Indefinite lengths are rejected.
    var dd2 = Diagnostics.init(arena, 8);
    try std.testing.expect((try parseDer(arena, &[_]u8{ 0x70, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 }, &Limits.default, &dd2)) == null);
    try std.testing.expect(dd2.has(.entitlements, .der_malformed));
}
