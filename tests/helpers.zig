//! tests/helpers.zig — corpus location, fixture loading, summary.json accessors. Owned by WP0.
const std = @import("std");
const build_options = @import("build_options");
const machre = @import("machre");

/// All four are absolute, joined against the build root in build.zig. They used to be derived here
/// with dirname() from an `addOptionPath` value, which stopped being absolute in Zig dev.2257.
pub fn corpusDir() []const u8 {
    return build_options.corpus_dir;
}
pub fn truthDir() []const u8 {
    return build_options.truth_dir;
}
pub fn srcDir() []const u8 {
    return build_options.src_dir;
}
/// .../tests/golden (sibling of tests/corpus). Takes an allocator it no longer needs so the ~8
/// `try helpers.goldenDir(arena)` call sites stay untouched.
pub fn goldenDir(arena: std.mem.Allocator) ![]const u8 {
    _ = arena;
    return build_options.golden_dir;
}
pub fn openCorpus(io: std.Io) !std.Io.Dir {
    return std.Io.Dir.openDirAbsolute(io, corpusDir(), .{});
}
pub fn readFixture(io: std.Io, gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var dir = try openCorpus(io);
    defer dir.close(io);
    return dir.readFileAlloc(io, name, gpa, .limited(1 << 26));
}
/// Absolute path of a corpus fixture; names starting with "/" (e.g. "/bin/ls") pass through.
pub fn fixturePath(arena: std.mem.Allocator, name: []const u8) ![:0]const u8 {
    if (name.len > 0 and name[0] == '/') return std.fmt.allocPrintSentinel(arena, "{s}", .{name}, 0);
    return std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ corpusDir(), name }, 0);
}
pub const healthy_fixtures: []const []const u8 = &.{
    "hello-c",           "hello-x86_64",   "hello-fat",    "hello-objc",  "libhello.dylib", "hello-usedylib", "hello-adhoc",
    "hello-entitled",    "hello-unsigned", "high-entropy", "fake-packed", "fake-upx",       "hello-zig",      "legacy-bind",
    "hello-quarantined",
};
pub const malformed_fixtures: []const []const u8 = &.{
    "truncated-header.bin",         "bogus-ncmds.bin",           "cmdsize-zero.bin",                 "cmdsize-huge.bin",           "fat-1000-arches.bin",
    "fat-arch-offset-past-eof.bin", "sizeofcmds-too-big.bin",    "section-offset-past-eof.bin",      "nsects-huge.bin",            "symtab-stroff-past-eof.bin",
    "symtab-nsyms-huge.bin",        "chained-fixups-absurd.bin", "chained-starts-segcount-huge.bin", "dyldinfo-bind-past-eof.bin", "bad-magic.bin",
    "empty.bin",
};
/// summary.json fixture name -> path relative to the corpus dir (or absolute).
pub fn summaryFixturePath(arena: std.mem.Allocator, name: []const u8) ![:0]const u8 {
    if (std.mem.eql(u8, name, "bin-ls")) return fixturePath(arena, "/bin/ls");
    if (std.mem.eql(u8, name, "Hello.app")) return fixturePath(arena, "Hello.app/Contents/MacOS/Hello");
    return fixturePath(arena, name);
}

/// Parsed truth/summary.json (`fixtures.<name>` -> per-fixture object; `slices[i]` -> per-slice object).
pub const Summary = struct {
    parsed: std.json.Parsed(std.json.Value),
    pub fn deinit(s: *Summary) void {
        s.parsed.deinit();
    }
    /// The per-fixture object `fixtures.<name>`.
    pub fn fixture(s: *const Summary, name: []const u8) ?std.json.Value {
        const all = object(s.parsed.value, "fixtures") orelse return null;
        return switch (all) {
            .object => |o| o.get(name),
            else => null,
        };
    }
    pub fn fixtureNamed(s: *const Summary, name: []const u8) ?std.json.Value {
        return s.fixture(name);
    }
    pub fn slice(f: std.json.Value, i: usize) ?std.json.Value {
        const arr = array(f, "slices") orelse return null;
        if (i >= arr.len) return null;
        return arr[i];
    }
    pub fn int(v: std.json.Value, key: []const u8) ?i64 {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            else => null,
        };
    }
    /// "0x..." string -> u64
    pub fn hex(v: std.json.Value, key: []const u8) ?u64 {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .string => |s| parseHex(s),
            .integer => |i| @bitCast(i),
            else => null,
        };
    }
    pub fn str(v: std.json.Value, key: []const u8) ?[]const u8 {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .string => |s| s,
            else => null,
        };
    }
    pub fn boolean(v: std.json.Value, key: []const u8) ?bool {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .bool => |b| b,
            else => null,
        };
    }
    pub fn strings(arena: std.mem.Allocator, v: std.json.Value, key: []const u8) ![]const []const u8 {
        const arr = array(v, key) orelse return &.{};
        const out = try arena.alloc([]const u8, arr.len);
        for (arr, 0..) |e, i| out[i] = switch (e) {
            .string => |s| s,
            else => "",
        };
        return out;
    }
    pub fn array(v: std.json.Value, key: []const u8) ?[]const std.json.Value {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .array => |a| a.items,
            else => null,
        };
    }
    pub fn object(v: std.json.Value, key: []const u8) ?std.json.Value {
        const x = get(v, key) orelse return null;
        return switch (x) {
            .object => x,
            else => null,
        };
    }
    /// Raw member (null JSON -> null).
    pub fn get(v: std.json.Value, key: []const u8) ?std.json.Value {
        return switch (v) {
            .object => |o| blk: {
                const x = o.get(key) orelse break :blk null;
                break :blk if (x == .null) null else x;
            },
            else => null,
        };
    }
    pub fn parseHex(s: []const u8) ?u64 {
        const body = if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) s[2..] else s;
        return std.fmt.parseInt(u64, body, 16) catch null;
    }
};
pub fn loadSummary(gpa: std.mem.Allocator, io: std.Io) !Summary {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, build_options.corpus_manifest, gpa, .limited(1 << 26));
    defer gpa.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, bytes, .{});
    return .{ .parsed = parsed };
}
/// Runs a machre command in-process and returns (exit code, stdout).
pub fn runMachre(arena: std.mem.Allocator, io: std.Io, argv: []const [:0]const u8) !struct { code: u8, out: []const u8 } {
    var outw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer outw.deinit();
    var errbuf: [256]u8 = undefined;
    var errw: std.Io.Writer.Discarding = .init(&errbuf);
    const code = machre.cli.runArgv(std.testing.allocator, io, argv, &outw.writer, &errw.writer);
    return .{ .code = code, .out = try arena.dupe(u8, outw.written()) };
}
/// Ensures the corpus quarantine xattr is present (re-applies with `xattr -w` via std.process.run when missing).
pub fn ensureQuarantineXattr(gpa: std.mem.Allocator, io: std.Io) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const path = try fixturePath(arena.allocator(), "hello-quarantined");
    const res = try std.process.run(gpa, io, .{ .argv = &.{ "/usr/bin/xattr", "-w", "com.apple.quarantine", "0083;68c3a1b2;Safari;9B2E1C3A-5F4D-4E6B-8A7C-1D2E3F4A5B6C", path } });
    gpa.free(res.stdout);
    gpa.free(res.stderr);
}

test "helpers: summary accessors" {
    var s = try loadSummary(std.testing.allocator, std.testing.io);
    defer s.deinit();
    const hc = s.fixtureNamed("hello-c").?;
    try std.testing.expectEqual(@as(?i64, 50424), Summary.int(hc, "size"));
    try std.testing.expectEqualStrings("thin", Summary.str(hc, "container").?);
    const sl = Summary.slice(hc, 0).?;
    try std.testing.expectEqual(@as(?u64, 0xfeedfacf), Summary.hex(sl, "magic"));
    try std.testing.expectEqual(@as(?u64, 0x200085), Summary.hex(sl, "flags"));
    try std.testing.expectEqual(@as(usize, 18), Summary.array(sl, "load_commands").?.len);
    try std.testing.expect(Summary.get(sl, "version_min") == null);
    try std.testing.expect(s.fixtureNamed("nope") == null);
}
