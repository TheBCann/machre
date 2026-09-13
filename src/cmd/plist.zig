//! cmd/plist.zig — parse a .plist file, __TEXT,__info_plist, or Contents/Info.plist. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
//!
//! Text output is `plutil -p`-compatible (sorted keys, the same scalar spellings), so
//! `machre plist --otool-compat <plist>` diffs empty against `plutil -p <plist>`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const sanitize = @import("../core/sanitize.zig");
const Sink = @import("../output/sink.zig").Sink;
const plist = @import("../plist/plist.zig");
const bplist = @import("../plist/bplist.zig");
const xml = @import("../plist/xml.zig");
const bundle = @import("../bundle/bundle.zig");

pub const command: Command = .{
    .name = "plist",
    .summary = "parse a .plist file, __TEXT,__info_plist, or Contents/Info.plist",
    .run = run,
    .flags = &.{ "--format=", "--key=" },
    .aliases = &.{},
    .needs_macho = false,
};

pub const Origin = enum {
    /// The argument itself is a property list.
    file,
    /// `__TEXT,__info_plist` of the (first selected) Mach-O slice.
    info_plist_section,
    /// `Contents/Info.plist` (or `Versions/A/Resources/Info.plist`) of a bundle directory.
    bundle_info_plist,
    none,
};
pub const Source = struct {
    bytes: []const u8,
    origin: Origin,
    /// Where the bytes came from, for the JSON `path` field.
    path: []const u8,
};

/// Resolution order: a bundle directory's Info.plist, then the file itself when it already looks like a
/// property list, then `__TEXT,__info_plist`, then the Info.plist of the bundle the file lives in (the
/// promotion `SecStaticCodeCreateWithPath` performs, format-notes 12.7).
pub fn findSource(ctx: *Context) Allocator.Error!Source {
    const is_dir = blk: {
        const st = Io.Dir.cwd().statFile(ctx.io, ctx.path, .{}) catch break :blk false;
        break :blk st.kind == .directory;
    };
    if (is_dir) {
        if (try bundle.readInfoPlist(ctx.arena, ctx.io, ctx.path, ctx.limits, ctx.diags)) |ip| {
            return .{ .bytes = ip.bytes, .origin = .bundle_info_plist, .path = try std.fmt.allocPrint(ctx.arena, "{s}/{s}", .{ ctx.display_path, ip.rel_path }) };
        }
        ctx.diags.err(.plist, .not_available, null, "'{s}' is a directory but not a bundle with an Info.plist", .{ctx.display_path});
        return .{ .bytes = &.{}, .origin = .none, .path = ctx.path };
    }
    if (ctx.file) |file| {
        if (plist.detect(file.bytes) != .unknown) return .{ .bytes = file.bytes, .origin = .file, .path = ctx.path };
    }
    for (ctx.images) |*img| {
        const sect = img.sectionByName("__TEXT", "__info_plist") orelse continue;
        const r = img.sectionReader(sect) orelse continue;
        return .{ .bytes = r.bytes, .origin = .info_plist_section, .path = try std.fmt.allocPrint(ctx.arena, "{s} (__TEXT,__info_plist)", .{ctx.display_path}) };
    }
    if (try bundle.enclosingBundle(ctx.arena, ctx.io, ctx.path, ctx.limits)) |root| {
        if (try bundle.readInfoPlist(ctx.arena, ctx.io, root, ctx.limits, ctx.diags)) |ip| {
            return .{ .bytes = ip.bytes, .origin = .bundle_info_plist, .path = try std.fmt.allocPrint(ctx.arena, "{s}/{s}", .{ root, ip.rel_path }) };
        }
    }
    if (ctx.images.len != 0) {
        ctx.diags.err(.plist, .not_available, null, "no __TEXT,__info_plist section and no enclosing bundle", .{});
        return .{ .bytes = &.{}, .origin = .none, .path = ctx.path };
    }
    const file = ctx.file orelse return .{ .bytes = &.{}, .origin = .none, .path = ctx.path };
    return .{ .bytes = file.bytes, .origin = .file, .path = ctx.path };
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    var want: ?plist.Format = null;
    if (ctx.args.value("--format")) |f| {
        if (std.mem.eql(u8, f, "bplist")) {
            want = .bplist;
        } else if (std.mem.eql(u8, f, "xml")) {
            want = .xml;
        } else if (!std.mem.eql(u8, f, "auto")) {
            ctx.diags.err(.cli, .unknown_value, null, "--format: expected auto|bplist|xml, got '{s}'", .{f});
            if (!ctx.sink.isJson()) try ctx.sink.out.print("machre plist: --format: expected auto|bplist|xml, got '{s}'\n", .{f});
            return @intFromEnum(context.ExitCode.usage);
        }
    }
    const src = try findSource(ctx);
    const detected = plist.detect(src.bytes);
    const format = want orelse detected;
    var value: ?plist.Value = null;
    if (src.origin != .none) {
        value = switch (format) {
            .bplist => try bplist.parse(ctx.arena, src.bytes, ctx.limits, ctx.diags),
            .xml => try xml.parse(ctx.arena, src.bytes, ctx.limits, ctx.diags),
            .unknown => try plist.parseAny(ctx.arena, src.bytes, ctx.limits, ctx.diags),
        };
    }
    var shown = value;
    if (ctx.args.value("--key")) |k| {
        if (value) |v| {
            shown = v.path(k);
            if (shown == null) ctx.diags.err(.plist, .not_available, null, "key path '{s}' is not present", .{k});
        }
    }

    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        for (ctx.images) |*img| {
            try json.beginArch(js, img);
            try json.endArch(js);
        }
        try json.endArches(js);
        try js.objectField("plist");
        try js.beginObject();
        try js.objectField("format");
        try js.write(@tagName(format));
        try js.objectField("detected_format");
        try js.write(@tagName(detected));
        try js.objectField("source");
        try js.write(@tagName(src.origin));
        try json.str(js, ctx.arena, "path", src.path);
        try json.int(js, "size", src.bytes.len);
        if (ctx.args.value("--key")) |k| try json.str(js, ctx.arena, "key", k);
        try js.objectField("value");
        if (shown) |v| try js.write(v) else try js.write(null);
        try js.endObject();
    } else if (shown) |v| {
        try renderPlutil(ctx.sink, v, 0);
    } else if (!ctx.otool_compat) {
        try ctx.sink.out.print("{s}: no property list found ({s})\n", .{ ctx.display_path, @tagName(src.origin) });
    }
    if (value == null) return @intFromEnum(context.ExitCode.not_macho);
    if (shown == null) return @intFromEnum(context.ExitCode.not_macho);
    return 0;
}

// ---------------------------------------------------------------------------------------------
// `plutil -p` rendering (shared with cmd/bundle.zig)
// ---------------------------------------------------------------------------------------------

const Frame = struct { v: plist.Value, i: usize, order: []const usize, indent: u32 };

/// Writes `v` exactly as `plutil -p` does: dict keys sorted, two-space indents, containers opened on
/// the key line and closed at the key line's indent. Iterative (no recursion on input-shaped data).
pub fn renderPlutil(snk: *Sink, v: plist.Value, base_indent: u32) !void {
    const out = snk.out;
    const arena = snk.arena;
    if (!plist.isContainer(v)) {
        try writeIndent(out, base_indent);
        try writeScalar(snk, v);
        try out.writeByte('\n');
        return;
    }
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(arena);
    try writeIndent(out, base_indent);
    try out.writeAll(if (v == .dict) "{" else "[");
    try out.writeByte('\n');
    try stack.append(arena, .{ .v = v, .i = 0, .order = try sortedOrder(arena, v), .indent = base_indent });
    while (stack.items.len != 0) {
        const top = &stack.items[stack.items.len - 1];
        if (top.i >= top.order.len) {
            const indent = top.indent;
            const closer: []const u8 = if (top.v == .dict) "}" else "]";
            _ = stack.pop();
            try writeIndent(out, indent);
            try out.writeAll(closer);
            try out.writeByte('\n');
            continue;
        }
        const idx = top.order[top.i];
        const child_indent = top.indent + 2;
        top.i += 1;
        try writeIndent(out, child_indent);
        switch (top.v) {
            .dict => |entries| try out.print("\"{s}\" => ", .{try snk.safe(entries[idx].key)}),
            .array => try out.print("{d} => ", .{idx}),
            else => {},
        }
        const child = plist.childAt(top.v, idx);
        if (!plist.isContainer(child) or stack.items.len >= plist.max_walk_depth) {
            try writeScalar(snk, child);
            try out.writeByte('\n');
            continue;
        }
        try out.writeAll(if (child == .dict) "{" else "[");
        try out.writeByte('\n');
        try stack.append(arena, .{ .v = child, .i = 0, .order = try sortedOrder(arena, child), .indent = child_indent });
    }
}

fn writeIndent(out: *Io.Writer, n: u32) !void {
    try out.splatByteAll(' ', n);
}

/// Child visit order: dict entries sorted like `plutil -p`, array items in index order. A key that
/// occurs twice in the file is rendered once (CoreFoundation keeps the last one); the JSON form keeps
/// both entries so a duplicate key is still visible.
fn sortedOrder(arena: Allocator, v: plist.Value) Allocator.Error![]const usize {
    const n = plist.containerLen(v);
    const order = try arena.alloc(usize, n);
    for (order, 0..) |*o, i| o.* = i;
    switch (v) {
        .dict => |entries| {
            std.mem.sort(usize, order, entries, lessByKey); // stable: equal keys keep file order
            var kept: usize = 0;
            for (order, 0..) |idx, i| {
                if (i + 1 < order.len and std.mem.eql(u8, entries[idx].key, entries[order[i + 1]].key)) continue;
                order[kept] = idx;
                kept += 1;
            }
            return order[0..kept];
        },
        else => {},
    }
    return order;
}
fn lessByKey(entries: []const plist.Value.Entry, a: usize, b: usize) bool {
    return keyLess(entries[a].key, entries[b].key);
}
/// ASCII punctuation in ICU root-collation order (what CoreFoundation, and therefore `plutil -p`, uses):
/// punctuation < symbols < digits < letters, and `.` sorts before `(`.
const punct_order = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";

/// Primary collation weight of one byte: controls, then punctuation, then digits, then
/// case-insensitive letters, then everything else (non-ASCII bytes).
fn collationWeight(c: u8) u16 {
    if (c < 0x20 or c == 0x7f) return c;
    if (std.mem.findScalar(u8, punct_order, c)) |i| return 0x100 + @as(u16, @intCast(i));
    if (isDigit(c)) return 0x200 + @as(u16, c - '0');
    const l = lower(c);
    if (l >= 'a' and l <= 'z') return 0x300 + @as(u16, l - 'a');
    return 0x400 + @as(u16, c);
}

/// Approximates CoreFoundation's localized, numeric-aware key ordering: ICU-root primary weights,
/// digit runs compared as numbers, ties broken byte-wise. Exact for the ASCII keys plists use
/// (verified against `plutil -p` on Info.plist and CodeResources); non-ASCII keys sort after ASCII.
pub fn keyLess(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        if (isDigit(a[i]) and isDigit(b[j])) {
            const ea = digitRunEnd(a, i);
            const eb = digitRunEnd(b, j);
            const na = numAt(a[i..ea]);
            const nb = numAt(b[j..eb]);
            if (na != nb) return na < nb;
            i = ea;
            j = eb;
            continue;
        }
        const ca = collationWeight(a[i]);
        const cb = collationWeight(b[j]);
        if (ca != cb) return ca < cb;
        i += 1;
        j += 1;
    }
    if (a.len != b.len) return a.len < b.len;
    return std.mem.lessThan(u8, a, b);
}
fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
fn digitRunEnd(s: []const u8, from: usize) usize {
    var i = from;
    while (i < s.len and isDigit(s[i])) i += 1;
    return i;
}
fn numAt(s: []const u8) u64 {
    var v: u64 = 0;
    for (s) |c| v = v *| 10 +| (c - '0');
    return v;
}
fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Scalar spellings copied from `plutil -p`: bare numbers, unquoted booleans, `{length = N, bytes = 0x…}`
/// for data (each byte printed without zero padding, exactly as CoreFoundation does) and
/// `YYYY-MM-DD HH:MM:SS +0000` for dates.
pub fn writeScalar(snk: *Sink, v: plist.Value) !void {
    const out = snk.out;
    switch (v) {
        .null => try out.writeAll("null"),
        .bool => |b| try out.writeAll(if (b) "true" else "false"),
        .integer => |i| try out.print("{d}", .{i}),
        .uid => |u| try out.print("{{CF$UID = {d}}}", .{u}),
        .real => |r| try out.print("{d}", .{r}),
        .string => |s| try out.print("\"{s}\"", .{try snk.safe(s)}),
        .data => |d| {
            try out.print("{{length = {d}, bytes = 0x", .{d.len});
            // CoreFoundation prints every byte with %x (no zero padding) and elides anything past
            // 24 bytes as "<first 16> ... <last 8>".
            if (d.len <= 24) {
                for (d) |b| try out.print("{x}", .{b});
            } else {
                for (d[0..16]) |b| try out.print("{x}", .{b});
                try out.writeAll(" ... ");
                for (d[d.len - 8 ..]) |b| try out.print("{x}", .{b});
            }
            try out.writeAll("}");
        },
        .date => |d| try writeDate(out, d),
        else => try out.writeAll("?"),
    }
}
fn writeDate(out: *Io.Writer, cf_seconds: f64) !void {
    if (!std.math.isFinite(cf_seconds) or cf_seconds < -6.2e10 or cf_seconds > 6.2e10) {
        try out.print("{d}", .{cf_seconds});
        return;
    }
    const unix: i64 = @as(i64, @intFromFloat(cf_seconds)) + plist.cf_epoch_offset;
    var buf: [20]u8 = undefined;
    const iso = sanitize.iso8601(&buf, unix);
    // "YYYY-MM-DDTHH:MM:SSZ" -> "YYYY-MM-DD HH:MM:SS +0000"
    if (iso.len >= 20) {
        try out.print("{s} {s} +0000", .{ iso[0..10], iso[11..19] });
    } else try out.writeAll(iso);
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

test "plist cmd: plutil rendering of the tiny bplist" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = @import("../core/diag.zig").Diagnostics.init(arena, 16);
    const Limits = @import("../core/limits.zig").Limits;
    const v = (try bplist.parse(arena, bplist.tiny, &Limits.default, &diags)).?;
    var w: Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    var snk = Sink.init(.text, &w.writer, .{}, arena);
    try renderPlutil(&snk, v, 0);
    try std.testing.expectEqualStrings(
        \\{
        \\  "a" => [
        \\    0 => 1
        \\    1 => -1
        \\  ]
        \\  "b" => true
        \\  "d" => {length = 3, bytes = 0x123}
        \\  "h" => "hi"
        \\  "i" => 300
        \\  "r" => 1.5
        \\  "s" => "héllo"
        \\  "t" => 2001-01-01 00:00:01 +0000
        \\}
        \\
    , w.written());
}

test "plist cmd: key ordering matches plutil for the common cases" {
    try std.testing.expect(keyLess("CFBundleDevelopmentRegion", "CFBundleExecutable"));
    try std.testing.expect(keyLess("CFBundleShortVersionString", "CFBundleSupportedPlatforms"));
    try std.testing.expect(keyLess("CFBundleVersion", "LSMinimumSystemVersion"));
    try std.testing.expect(keyLess("apple", "Zebra")); // case-insensitive, like CFStringCompare
    try std.testing.expect(keyLess("d2", "d16")); // numeric runs
    try std.testing.expect(!keyLess("d16", "d2"));
    try std.testing.expect(keyLess("a", "ab"));
    try std.testing.expect(!keyLess("a", "a"));
}

test "plist cmd: empty containers render like plutil" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const entries = [_]plist.Value.Entry{
        .{ .key = "empty_a", .value = .{ .array = &.{} } },
        .{ .key = "empty_d", .value = .{ .dict = &.{} } },
    };
    var w: Io.Writer.Allocating = .init(std.testing.allocator);
    defer w.deinit();
    var snk2 = Sink.init(.text, &w.writer, .{}, arena);
    try renderPlutil(&snk2, .{ .dict = &entries }, 0);
    try std.testing.expectEqualStrings("{\n  \"empty_a\" => [\n  ]\n  \"empty_d\" => {\n  }\n}\n", w.written());
}
