//! output/sink.zig — the output abstraction + JSON wrapper types. Imports: core/sanitize.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const sanitize = @import("../core/sanitize.zig");

pub const Mode = enum { text, json };
pub const Options = struct { verbose: u8 = 0, color: bool = false, limit: u32 = 0, pretty_json: bool = true, otool_compat: bool = false, quiet: bool = false };

pub const Sink = struct {
    mode: Mode,
    out: *Io.Writer,
    json: std.json.Stringify,
    opts: Options,
    arena: Allocator,
    /// How many file-derived strings needed escaping on their way out (reported by `cli.zig` as a
    /// `cli.invalid_utf8` diagnostic so the analyst knows the sample tried to write control bytes).
    lossy: u32 = 0,

    pub fn init(mode: Mode, out: *Io.Writer, opts: Options, arena: Allocator) Sink {
        return .{
            .mode = mode,
            .out = out,
            .json = .{ .writer = out, .options = .{ .whitespace = if (opts.pretty_json) .indent_2 else .minified } },
            .opts = opts,
            .arena = arena,
        };
    }
    pub fn isJson(s: *const Sink) bool {
        return s.mode == .json;
    }
    pub fn flush(s: *Sink) Io.Writer.Error!void {
        return s.out.flush();
    }
    /// The one way a file-derived string becomes text output: control characters, C1/bidi code points
    /// and invalid UTF-8 are escaped (`core/sanitize.zig`), legitimate UTF-8 is preserved, and the
    /// per-run lossy counter is bumped. Returns `bytes` itself when nothing had to change.
    pub fn safe(s: *Sink, bytes: []const u8) Allocator.Error![]const u8 {
        return sanitize.forText(s.arena, bytes, &s.lossy);
    }
    /// `safe` with an explicit input cap (the caller's `Limits` value).
    pub fn safeMax(s: *Sink, bytes: []const u8, max: u32) Allocator.Error![]const u8 {
        const r = try sanitize.string(s.arena, bytes, .text, max);
        if (r.lossy) s.lossy +|= 1;
        return r.text;
    }
    /// `safe` for an optional string; `null` renders as `fallback`.
    pub fn safeOr(s: *Sink, bytes: ?[]const u8, fallback: []const u8) Allocator.Error![]const u8 {
        return if (bytes) |b| s.safe(b) else fallback;
    }
};
pub const Error = Io.Writer.Error || Allocator.Error;

/// Pre-sanitized string: `jsonStringify` never allocates and never yields a number array.
pub const Str = struct {
    text: []const u8,
    lossy: bool,
    pub fn init(arena: Allocator, bytes: []const u8, max: u32) Allocator.Error!Str {
        const s = try sanitize.string(arena, bytes, .json, max);
        return .{ .text = s.text, .lossy = s.lossy };
    }
    pub fn jsonStringify(self: Str, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        return jw.write(self.text);
    }
};
pub const Hex64 = struct {
    v: u64,
    pub fn jsonStringify(self: Hex64, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        var buf: [20]u8 = undefined;
        return jw.write(std.fmt.bufPrint(&buf, "0x{x}", .{self.v}) catch unreachable);
    }
};
pub const HexBytes = struct {
    bytes: []const u8,
    pub fn jsonStringify(self: HexBytes, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        try jw.beginWriteRaw();
        try jw.writer.writeByte('"');
        try jw.writer.printHex(self.bytes, .lower);
        try jw.writer.writeByte('"');
        jw.endWriteRaw();
    }
};
pub const IsoTime = struct {
    secs: i64,
    pub fn jsonStringify(self: IsoTime, jw: *std.json.Stringify) std.json.Stringify.Error!void {
        var buf: [20]u8 = undefined;
        return jw.write(sanitize.iso8601(&buf, self.secs));
    }
};

test "sink: wrapper types serialize as strings via std.json.Stringify.value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var s = Sink.init(.json, &w, .{ .pretty_json = false }, a);
    const Rec = struct { name: Str, raw: Hex64, digest: HexBytes, when: IsoTime, small: u32 };
    const rec: Rec = .{
        .name = try Str.init(a, "bad\xffname", 4096),
        .raw = .{ .v = 0x8010000000000000 },
        .digest = .{ .bytes = &[_]u8{ 0xf8, 0x65, 0xcf } },
        .when = .{ .secs = 0x68c3a1b2 },
        .small = 7,
    };
    try std.json.Stringify.value(rec, .{}, s.out);
    try std.testing.expectEqualStrings(
        "{\"name\":\"bad\u{FFFD}name\",\"raw\":\"0x8010000000000000\",\"digest\":\"f865cf\",\"when\":\"2025-09-12T04:29:38Z\",\"small\":7}",
        w.buffered(),
    );
    try std.testing.expect(rec.name.lossy);
    try s.json.beginObject();
    try s.json.objectField("k");
    try s.json.write(@as(u32, 1));
    try s.json.endObject();
}
