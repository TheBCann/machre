//! cmd/entitlements.zig — entitlements (XML and/or DER) with dangerous-key annotations. Owned by WP3 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, codesign/entitlements, plist/plist, core/sanitize.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const sink = @import("../output/sink.zig");
const text = @import("../output/text.zig");
const sanitize = @import("../core/sanitize.zig");
const Sink = @import("../output/sink.zig").Sink;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const ent_mod = @import("../codesign/entitlements.zig");
const Entitlements = ent_mod.Entitlements;
const plist = @import("../plist/plist.zig");

pub const command: Command = .{
    .name = "entitlements",
    .summary = "entitlements (XML and/or DER) with dangerous-key annotations",
    .run = run,
    .flags = &.{ "--xml", "--der", "--keys" },
    .aliases = &.{},
    .needs_macho = true,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const multi = ctx.images.len > 1;
    const want_xml = ctx.args.flag("--xml");
    const want_der = ctx.args.flag("--der");
    const want_keys = ctx.args.flag("--keys");
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network });
        defer an.deinit();
        const e = try an.entitlements();
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try writeJson(&ctx.sink.json, ctx.arena, e);
            try json.endArch(&ctx.sink.json);
            continue;
        }
        const out = ctx.sink.out;
        if (multi and !ctx.otool_compat) {
            var buf: [32]u8 = undefined;
            try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), true);
        }
        if (want_xml) {
            // codesign's `--xml` re-serialises the dictionary canonically (one line, sorted keys),
            // it does not echo the embedded blob; match that so the output diffs clean.
            if (e.preferred()) |value| try writeXmlPlist(ctx.sink, value);
            continue;
        }
        if (want_der) {
            if (e.der) |v| try writeCodesignDict(ctx.sink, v);
            continue;
        }
        if (want_keys) {
            for (e.keys) |k| {
                try out.print("{s}\n", .{try ctx.sink.safeMax(k, ctx.limits.max_symbol_name)});
            }
            continue;
        }
        if (ctx.otool_compat) {
            if (e.preferred()) |v| try writeCodesignDict(ctx.sink, v);
            continue;
        }
        try writeText(ctx, out, e);
    }
    return 0;
}

fn writeText(ctx: *Context, out: *Io.Writer, e: *const Entitlements) !void {
    if (e.source == .none) {
        try out.writeAll("entitlements: none (no CSSLOT_ENTITLEMENTS and no CSSLOT_DER_ENTITLEMENTS blob)\n");
        return;
    }
    try out.print("entitlements: {d} keys (source {t}", .{ e.keys.len, e.source });
    if (e.xml_raw) |raw| try out.print(", XML payload {d} B", .{raw.len});
    if (e.der_len != 0) try out.print(", DER blob {d} B", .{e.der_len});
    try out.writeAll(")\n");
    if (e.disagreement) try out.writeAll("  WARNING: the XML and DER blobs do not agree\n");
    if (e.source == .both and e.xml == null and e.der != null)
        try out.writeAll("  note: the XML entitlements blob did not parse; values below come from the DER blob\n");
    const v = e.preferred() orelse {
        try out.writeAll("  (blob present but not parseable)\n");
        return;
    };
    switch (v) {
        .dict => |entries| for (entries) |entry| {
            const key = try ctx.sink.safeMax(entry.key, ctx.limits.max_symbol_name);
            const val = try scalarText(ctx.sink, entry.value, ctx.limits.max_symbol_name);
            try out.print("  {s} = {s}", .{ key, val });
            if (ent_mod.isDangerous(entry.key)) |d| try out.print("   [dangerous: {s}]", .{d.why});
            try out.writeByte('\n');
        },
        else => try out.writeAll("  (entitlements are not a dictionary)\n"),
    }
}

/// One-line rendering of a scalar value ("true", "MACHRE.hello", "<3 items>").
fn scalarText(snk: *Sink, v: plist.Value, max: u32) Allocator.Error![]const u8 {
    const arena = snk.arena;
    return switch (v) {
        .null => "null",
        .bool => |b| if (b) "true" else "false",
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        .uid => |u| try std.fmt.allocPrint(arena, "uid({d})", .{u}),
        .real => |f| try std.fmt.allocPrint(arena, "{d}", .{f}),
        .date => |d| try std.fmt.allocPrint(arena, "date({d})", .{d}),
        .string => |s| try snk.safeMax(s, max),
        .data => |d| try std.fmt.allocPrint(arena, "<{d} bytes>", .{d.len}),
        .array => |a| try std.fmt.allocPrint(arena, "<array, {d} items>", .{a.len}),
        .dict => |d| try std.fmt.allocPrint(arena, "<dict, {d} keys>", .{d.len}),
    };
}

fn entryLess(_: void, a: plist.Value.Entry, b: plist.Value.Entry) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}
/// CoreFoundation's property-list writer emits dictionary keys in sorted order at every level, so both
/// codesign renderings below sort before printing; an already-sorted DER dictionary is unchanged.
fn sortedEntries(arena: Allocator, entries: []const plist.Value.Entry) Allocator.Error![]const plist.Value.Entry {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        if (std.mem.lessThan(u8, entries[i].key, entries[i - 1].key)) {
            const copy = try arena.dupe(plist.Value.Entry, entries);
            std.mem.sort(plist.Value.Entry, copy, {}, entryLess);
            return copy;
        }
    }
    return entries;
}

const Work = union(enum) {
    value: struct { v: plist.Value, indent: u8 },
    line: struct { textv: []const u8, indent: u8 },
};

/// codesign's `-d --entitlements -` tree ("[Dict]" / TAB "[Key] x" / TAB "[Value]" / TAB TAB "[Bool] true").
/// Iterative: plist values come from the file, so no recursion.
pub fn writeCodesignDict(snk: *Sink, root: plist.Value) !void {
    const out = snk.out;
    const arena = snk.arena;
    var stack: std.ArrayList(Work) = .empty;
    try stack.append(arena, .{ .value = .{ .v = root, .indent = 0 } });
    var steps: u32 = 0;
    while (stack.pop()) |w| {
        steps += 1;
        if (steps > 1 << 20) break;
        switch (w) {
            .line => |l| {
                try out.splatByteAll('\t', l.indent);
                try out.writeAll(l.textv);
                try out.writeByte('\n');
            },
            .value => |item| {
                const indent = item.indent;
                switch (item.v) {
                    .dict => |raw_entries| {
                        const entries = try sortedEntries(arena, raw_entries);
                        try out.splatByteAll('\t', indent);
                        try out.writeAll("[Dict]\n");
                        var i = entries.len;
                        while (i > 0) {
                            i -= 1;
                            try stack.append(arena, .{ .value = .{ .v = entries[i].value, .indent = indent +| 2 } });
                            try stack.append(arena, .{ .line = .{ .textv = "[Value]", .indent = indent +| 1 } });
                            const key = try snk.safe(entries[i].key);
                            try stack.append(arena, .{ .line = .{ .textv = try std.fmt.allocPrint(arena, "[Key] {s}", .{key}), .indent = indent +| 1 } });
                        }
                    },
                    .array => |items| {
                        try out.splatByteAll('\t', indent);
                        try out.writeAll("[Array]\n");
                        var i = items.len;
                        while (i > 0) {
                            i -= 1;
                            try stack.append(arena, .{ .value = .{ .v = items[i], .indent = indent +| 1 } });
                        }
                    },
                    .string => |s| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[String] {s}\n", .{try snk.safe(s)});
                    },
                    .bool => |b| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[Bool] {s}\n", .{if (b) "true" else "false"});
                    },
                    .integer => |n| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[Integer] {d}\n", .{n});
                    },
                    .real => |f| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[Real] {d}\n", .{f});
                    },
                    .data => |d| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[Data] {x}\n", .{d});
                    },
                    .date => |d| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[Date] {d}\n", .{d});
                    },
                    .uid => |u| {
                        try out.splatByteAll('\t', indent);
                        try out.print("[UID] {d}\n", .{u});
                    },
                    .null => {
                        try out.splatByteAll('\t', indent);
                        try out.writeAll("[Null]\n");
                    },
                }
            },
        }
    }
}

/// codesign's `-d --entitlements - --xml` form: the canonical one-line XML plist.
pub fn writeXmlPlist(snk: *Sink, root: plist.Value) !void {
    const out = snk.out;
    const arena = snk.arena;
    try out.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"https://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\">");
    const Item = union(enum) { v: plist.Value, lit: []const u8 };
    var stack: std.ArrayList(Item) = .empty;
    try stack.append(arena, .{ .v = root });
    var steps: u32 = 0;
    while (stack.pop()) |it| {
        steps += 1;
        if (steps > 1 << 20) break;
        switch (it) {
            .lit => |l| try out.writeAll(l),
            .v => |v| switch (v) {
                .null => try out.writeAll("<string></string>"),
                .bool => |b| try out.writeAll(if (b) "<true/>" else "<false/>"),
                .integer => |n| try out.print("<integer>{d}</integer>", .{n}),
                .uid => |u| try out.print("<integer>{d}</integer>", .{u}),
                .real => |f| try out.print("<real>{d}</real>", .{f}),
                .date => |d| try out.print("<date>{f}</date>", .{@import("../core/fmt.zig").Iso8601{ .unix_secs = @intFromFloat(d + 978307200.0) }}),
                .string => |str| {
                    try out.writeAll("<string>");
                    try writeXmlEscaped(snk, str);
                    try out.writeAll("</string>");
                },
                .data => |d| {
                    try out.writeAll("<data>");
                    const enc = std.base64.standard.Encoder;
                    const buf = try arena.alloc(u8, enc.calcSize(d.len));
                    try out.writeAll(enc.encode(buf, d));
                    try out.writeAll("</data>");
                },
                .array => |items| {
                    try out.writeAll("<array>");
                    try stack.append(arena, .{ .lit = "</array>" });
                    var i = items.len;
                    while (i > 0) {
                        i -= 1;
                        try stack.append(arena, .{ .v = items[i] });
                    }
                },
                .dict => |raw_entries| {
                    const entries = try sortedEntries(arena, raw_entries);
                    try out.writeAll("<dict>");
                    try stack.append(arena, .{ .lit = "</dict>" });
                    var i = entries.len;
                    while (i > 0) {
                        i -= 1;
                        try stack.append(arena, .{ .v = entries[i].value });
                        try stack.append(arena, .{ .lit = try std.fmt.allocPrint(arena, "<key>{s}</key>", .{try xmlEscape(snk, entries[i].key)}) });
                    }
                },
            },
        }
    }
    try out.writeAll("</plist>\n");
}
/// `.text` (not `.json`) because this XML is also read by a human in a terminal: a control character
/// is illegal in XML 1.0 anyway, so escaping it costs nothing and keeps the output inert.
fn xmlEscape(snk: *Sink, s: []const u8) Allocator.Error![]const u8 {
    const arena = snk.arena;
    const clean = try snk.safeMax(s, json.max_str);
    var out: std.ArrayList(u8) = .empty;
    for (clean) |ch| switch (ch) {
        '&' => try out.appendSlice(arena, "&amp;"),
        '<' => try out.appendSlice(arena, "&lt;"),
        '>' => try out.appendSlice(arena, "&gt;"),
        else => try out.append(arena, ch),
    };
    return out.toOwnedSlice(arena);
}
fn writeXmlEscaped(snk: *Sink, s: []const u8) !void {
    try snk.out.writeAll(try xmlEscape(snk, s));
}

/// `plist.Value` as JSON (data -> {"$data":"hex"}, uid -> {"$uid":n}), every string sanitised.
/// Local until `plist.Value.jsonStringify` (WP5) is implemented.
pub fn jsonValue(js: *Stringify, arena: Allocator, root: plist.Value) !void {
    const Item = union(enum) { v: plist.Value, end_obj, end_arr, key: []const u8 };
    var stack: std.ArrayList(Item) = .empty;
    try stack.append(arena, .{ .v = root });
    var steps: u32 = 0;
    while (stack.pop()) |it| {
        steps += 1;
        if (steps > 1 << 20) break;
        switch (it) {
            .end_obj => try js.endObject(),
            .end_arr => try js.endArray(),
            .key => |k| {
                const s = try sink.Str.init(arena, k, json.max_str);
                try js.objectField(s.text);
            },
            .v => |v| switch (v) {
                .null => try js.write(null),
                .bool => |b| try js.write(b),
                .integer => |n| try js.write(n),
                .real => |f| try js.write(f),
                .date => |d| try js.write(sink.IsoTime{ .secs = @intFromFloat(d + 978307200.0) }),
                .uid => |u| {
                    try js.beginObject();
                    try json.int(js, "$uid", u);
                    try js.endObject();
                },
                .string => |s| try js.write(try sink.Str.init(arena, s, json.max_str)),
                .data => |d| {
                    try js.beginObject();
                    try json.bytesHex(js, "$data", d);
                    try js.endObject();
                },
                .array => |items| {
                    try js.beginArray();
                    try stack.append(arena, .end_arr);
                    var i = items.len;
                    while (i > 0) {
                        i -= 1;
                        try stack.append(arena, .{ .v = items[i] });
                    }
                },
                .dict => |entries| {
                    try js.beginObject();
                    try stack.append(arena, .end_obj);
                    var i = entries.len;
                    while (i > 0) {
                        i -= 1;
                        try stack.append(arena, .{ .v = entries[i].value });
                        try stack.append(arena, .{ .key = entries[i].key });
                    }
                },
            },
        }
    }
}

/// `"entitlements": {...}` — shared with cmd/codesign.zig.
pub fn writeJson(js: *Stringify, arena: Allocator, e: *const Entitlements) !void {
    try js.objectField("entitlements");
    try js.beginObject();
    try js.objectField("source");
    try js.write(@tagName(e.source));
    try json.names(js, arena, "keys", e.keys);
    try js.objectField("xml");
    if (e.xml) |v| try jsonValue(js, arena, v) else try js.write(null);
    try js.objectField("der");
    if (e.der) |v| try jsonValue(js, arena, v) else try js.write(null);
    try json.strOpt(js, arena, "xml_raw", e.xml_raw);
    try json.int(js, "der_length", e.der_len);
    try json.boolean(js, "disagreement", e.disagreement);
    try js.objectField("dangerous");
    try js.beginArray();
    for (e.keys) |k| {
        if (ent_mod.isDangerous(k)) |d| {
            try js.beginObject();
            try json.str(js, arena, "key", k);
            try js.objectField("why");
            try js.write(d.why);
            try json.int(js, "weight", d.weight);
            try js.endObject();
        }
    }
    try js.endArray();
    try js.endObject();
}

test "cmd/entitlements: codesign dict rendering matches codesign -d --entitlements -" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const v: plist.Value = .{ .dict = &.{
        .{ .key = "com.apple.application-identifier", .value = .{ .string = "MACHRE.hello-entitled" } },
        .{ .key = "com.apple.security.cs.allow-jit", .value = .{ .bool = true } },
        .{ .key = "nested", .value = .{ .array = &.{ .{ .integer = 7 }, .{ .dict = &.{.{ .key = "k", .value = .{ .bool = false } }} } } } },
    } };
    var snk = Sink.init(.text, &w, .{}, arena);
    try writeCodesignDict(&snk, v);
    try std.testing.expectEqualStrings(
        "[Dict]\n" ++
            "\t[Key] com.apple.application-identifier\n\t[Value]\n\t\t[String] MACHRE.hello-entitled\n" ++
            "\t[Key] com.apple.security.cs.allow-jit\n\t[Value]\n\t\t[Bool] true\n" ++
            "\t[Key] nested\n\t[Value]\n\t\t[Array]\n\t\t\t[Integer] 7\n\t\t\t[Dict]\n\t\t\t\t[Key] k\n\t\t\t\t[Value]\n\t\t\t\t\t[Bool] false\n",
        w.buffered(),
    );
}

test "cmd/entitlements: JSON value form is parseable and sanitised" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var js: Stringify = .{ .writer = &w, .options = .{} };
    const v: plist.Value = .{ .dict = &.{
        .{ .key = "bad\xffkey", .value = .{ .string = "ok" } },
        .{ .key = "data", .value = .{ .data = &.{ 0xde, 0xad } } },
        .{ .key = "arr", .value = .{ .array = &.{ .{ .bool = true }, .{ .integer = -3 } } } },
    } };
    try jsonValue(&js, arena, v);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, w.buffered(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try std.testing.expectEqualStrings("dead", o.get("data").?.object.get("$data").?.string);
    try std.testing.expectEqual(@as(i64, -3), o.get("arr").?.array.items[1].integer);
    try std.testing.expect(o.get("bad\u{FFFD}key") != null);
}
