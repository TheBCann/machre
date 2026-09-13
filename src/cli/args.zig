//! cli/args.zig — generic flag parser (--flag, --flag=value, --flag value, -v, --). Imports: std only.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Parsed = struct {
    positionals: []const [:0]const u8,
    flags: []const Flag,
    pub const Flag = struct { name: []const u8, value: ?[:0]const u8 };

    /// True when `name` ("--json") occurs at least once.
    pub fn flag(p: *const Parsed, name: []const u8) bool {
        for (p.flags) |f| if (std.mem.eql(u8, f.name, name)) return true;
        return false;
    }
    /// Last value given for `name`, null when absent or valueless.
    pub fn value(p: *const Parsed, name: []const u8) ?[:0]const u8 {
        var out: ?[:0]const u8 = null;
        for (p.flags) |f| if (std.mem.eql(u8, f.name, name)) {
            if (f.value) |v| out = v;
        };
        return out;
    }
    /// base 0 (0x prefix ok)
    pub fn valueInt(p: *const Parsed, comptime T: type, name: []const u8) error{InvalidValue}!?T {
        const v = p.value(name) orelse return null;
        return std.fmt.parseInt(T, v, 0) catch return error.InvalidValue;
    }
    /// Every value given for `name`, in order.
    pub fn values(p: *const Parsed, arena: Allocator, name: []const u8) Allocator.Error![]const [:0]const u8 {
        var list: std.ArrayList([:0]const u8) = .empty;
        for (p.flags) |f| if (std.mem.eql(u8, f.name, name)) {
            if (f.value) |v| try list.append(arena, v);
        };
        return list.toOwnedSlice(arena);
    }
    /// Count of a repeatable boolean flag (-v -v / --verbose --verbose).
    pub fn count(p: *const Parsed, name: []const u8) u8 {
        var n: u8 = 0;
        for (p.flags) |f| if (std.mem.eql(u8, f.name, name)) {
            n +|= 1;
        };
        return n;
    }
    /// First flag not in `known` -> usage error. Entries ending in "=" match flags of that name.
    pub fn unknown(p: *const Parsed, known: []const []const u8) ?[]const u8 {
        for (p.flags) |f| {
            var ok = false;
            for (known) |k| {
                const base = if (k.len > 0 and k[k.len - 1] == '=') k[0 .. k.len - 1] else k;
                if (std.mem.eql(u8, f.name, base)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) return f.name;
        }
        return null;
    }
};

fn takesValue(name: []const u8, value_flags: []const []const u8) bool {
    for (value_flags) |k| {
        if (k.len == 0 or k[k.len - 1] != '=') continue;
        if (std.mem.eql(u8, k[0 .. k.len - 1], name)) return true;
    }
    return false;
}

/// `argv` excludes argv[0] and the command name. Flags named "--foo"; `-v` maps to "--verbose", `-q` to "--quiet".
/// `value_flags` lists the flags that take a value ("--arch="); `--flag=value` always works, `--flag value`
/// only for those. `--` ends flag parsing.
pub fn parse(arena: Allocator, argv: []const [:0]const u8, value_flags: []const []const u8) Allocator.Error!Parsed {
    var pos: std.ArrayList([:0]const u8) = .empty;
    var flags: std.ArrayList(Parsed.Flag) = .empty;
    var i: usize = 0;
    var only_positionals = false;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (only_positionals or a.len < 2 or a[0] != '-') {
            try pos.append(arena, a);
            continue;
        }
        if (std.mem.eql(u8, a, "--")) {
            only_positionals = true;
            continue;
        }
        if (a[1] != '-') {
            // short flags: -v -q -h, possibly bundled (-vv)
            for (a[1..]) |ch| {
                const name: []const u8 = switch (ch) {
                    'v' => "--verbose",
                    'q' => "--quiet",
                    'h' => "--help",
                    else => try std.fmt.allocPrint(arena, "-{c}", .{ch}),
                };
                try flags.append(arena, .{ .name = name, .value = null });
            }
            continue;
        }
        if (std.mem.findScalar(u8, a, '=')) |eq| {
            try flags.append(arena, .{ .name = a[0..eq], .value = a[eq + 1 ..] });
            continue;
        }
        if (takesValue(a, value_flags) and i + 1 < argv.len) {
            try flags.append(arena, .{ .name = a, .value = argv[i + 1] });
            i += 1;
            continue;
        }
        try flags.append(arena, .{ .name = a, .value = null });
    }
    return .{ .positionals = try pos.toOwnedSlice(arena), .flags = try flags.toOwnedSlice(arena) };
}

test "args: flags, values, shorts, positionals, unknown" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = [_][:0]const u8{ "--json", "--arch=arm64", "--limit", "10", "-vv", "-q", "--", "--not-a-flag", "path" };
    const p = try parse(a, &argv, &.{ "--arch=", "--limit=" });
    try std.testing.expect(p.flag("--json") and !p.flag("--strict"));
    try std.testing.expectEqualStrings("arm64", p.value("--arch").?);
    try std.testing.expectEqual(@as(?u32, 10), try p.valueInt(u32, "--limit"));
    try std.testing.expectEqual(@as(u8, 2), p.count("--verbose"));
    try std.testing.expect(p.flag("--quiet"));
    try std.testing.expectEqual(@as(usize, 2), p.positionals.len);
    try std.testing.expectEqualStrings("--not-a-flag", p.positionals[0]);
    try std.testing.expect(p.unknown(&.{ "--json", "--arch=", "--limit=", "--verbose", "--quiet" }) == null);
    try std.testing.expectEqualStrings("--json", p.unknown(&.{"--arch="}).?);
    const bad = [_][:0]const u8{"--limit=zz"};
    const pb = try parse(a, &bad, &.{"--limit="});
    try std.testing.expectError(error.InvalidValue, pb.valueInt(u32, "--limit"));
    const vs = try p.values(a, "--arch");
    try std.testing.expectEqual(@as(usize, 1), vs.len);
}
