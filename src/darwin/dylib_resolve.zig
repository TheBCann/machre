//! darwin/dylib_resolve.zig — @rpath/@executable_path/@loader_path expansion + on-disk / shared-cache residency.
//! Imports: core/loadcmds (Dylib type only), core/diag.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Dylib = @import("../core/loadcmds.zig").Dylib;
const Diagnostics = @import("../core/diag.zig").Diagnostics;

pub const Status = enum { on_disk, shared_cache, missing, unresolvable_rpath, weak_missing, not_checked };
pub const Resolution = struct { path: []const u8, resolved: ?[]const u8, status: Status, via_rpath: ?[]const u8, weak: bool };

/// Caps applied before any filesystem work (this module may not import core/limits; §4 DAG).
const max_dylibs: usize = 4096;
const max_rpaths: usize = 128;
const max_path_bytes: usize = 4096;

pub const executable_path_prefix: []const u8 = "@executable_path";
pub const loader_path_prefix: []const u8 = "@loader_path";
pub const rpath_prefix: []const u8 = "@rpath";

/// `exe_path` is the analysed file; `loader_path` the directory of the image whose LC_RPATHs are used.
pub fn resolveAll(arena: Allocator, io: Io, exe_path: []const u8, dylibs: []const Dylib, rpaths: []const []const u8, diags: *Diagnostics) Allocator.Error![]const Resolution {
    if (dylibs.len == 0) return &.{};
    var n = dylibs.len;
    if (n > max_dylibs) {
        diags.warn(.dylib_resolve, .count_clamped, null, "{d} dylibs declared; resolving only {d}", .{ dylibs.len, max_dylibs });
        n = max_dylibs;
    }
    var rp = rpaths;
    if (rp.len > max_rpaths) {
        diags.warn(.dylib_resolve, .count_clamped, null, "{d} LC_RPATHs declared; using only {d}", .{ rpaths.len, max_rpaths });
        rp = rp[0..max_rpaths];
    }
    // The main image is its own loader, so @loader_path == @executable_path here.
    const base_dir = std.fs.path.dirname(exe_path) orelse ".";
    const out = try arena.alloc(Resolution, n);
    for (dylibs[0..n], 0..) |d, i| out[i] = try resolveOne(arena, io, base_dir, d, rp, diags);
    return out;
}

fn resolveOne(arena: Allocator, io: Io, base_dir: []const u8, d: Dylib, rpaths: []const []const u8, diags: *Diagnostics) Allocator.Error!Resolution {
    var res: Resolution = .{ .path = d.name, .resolved = null, .status = .not_checked, .via_rpath = null, .weak = d.weak };
    if (!is_macos) return res;
    if (d.name.len == 0 or d.name.len > max_path_bytes) {
        if (!diags.has(.dylib_resolve, .not_available))
            diags.warn(.dylib_resolve, .not_available, null, "dylib name of length {d} cannot be resolved", .{d.name.len});
        res.status = if (d.weak) .weak_missing else .missing;
        return res;
    }
    if (std.mem.startsWith(u8, d.name, rpath_prefix) and atBoundary(d.name, rpath_prefix.len)) {
        const suffix = trimLeadingSep(d.name[rpath_prefix.len..]);
        for (rpaths) |rp| {
            const base = try expand(arena, rp, base_dir, base_dir) orelse continue;
            const cand = try joinPath(arena, base, suffix) orelse continue;
            if (try residency(arena, io, cand)) |st| {
                res.status = st;
                res.resolved = cand;
                res.via_rpath = rp;
                return res;
            }
        }
        res.status = if (d.weak) .weak_missing else .unresolvable_rpath;
        return res;
    }
    const cand = try expand(arena, d.name, base_dir, base_dir) orelse {
        res.status = if (d.weak) .weak_missing else .unresolvable_rpath;
        return res;
    };
    if (try residency(arena, io, cand)) |st| {
        res.status = st;
        res.resolved = cand;
        return res;
    }
    res.status = if (d.weak) .weak_missing else .missing;
    return res;
}

/// on_disk (a real file) > shared_cache (dyld-only system image) > null (neither).
fn residency(arena: Allocator, io: Io, path: []const u8) Allocator.Error!?Status {
    if (path.len == 0 or path.len > max_path_bytes) return null;
    Io.Dir.cwd().access(io, path, .{}) catch {
        const z = try arena.dupeSentinel(u8, path, 0);
        return if (inSharedCache(z)) .shared_cache else null;
    };
    return .on_disk;
}

/// Expands a leading @executable_path / @loader_path; returns null for a spec machre cannot expand
/// (a nested @rpath inside an LC_RPATH) or one that would exceed `max_path_bytes`.
fn expand(arena: Allocator, spec: []const u8, exe_dir: []const u8, loader_dir: []const u8) Allocator.Error!?[]const u8 {
    if (spec.len == 0 or spec.len > max_path_bytes) return null;
    if (std.mem.startsWith(u8, spec, executable_path_prefix) and atBoundary(spec, executable_path_prefix.len))
        return joinPath(arena, exe_dir, trimLeadingSep(spec[executable_path_prefix.len..]));
    if (std.mem.startsWith(u8, spec, loader_path_prefix) and atBoundary(spec, loader_path_prefix.len))
        return joinPath(arena, loader_dir, trimLeadingSep(spec[loader_path_prefix.len..]));
    if (std.mem.startsWith(u8, spec, rpath_prefix) and atBoundary(spec, rpath_prefix.len)) return null;
    return spec;
}

/// True when `prefix_len` ends the string or is followed by a separator, so "@rpathX" is not "@rpath".
fn atBoundary(s: []const u8, prefix_len: usize) bool {
    return s.len == prefix_len or s[prefix_len] == '/';
}
fn trimLeadingSep(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and s[i] == '/') i += 1;
    return s[i..];
}
fn joinPath(arena: Allocator, base: []const u8, rel: []const u8) Allocator.Error!?[]const u8 {
    if (rel.len == 0) return base;
    const b = if (base.len > 1 and base[base.len - 1] == '/') base[0 .. base.len - 1] else base;
    if (b.len + 1 + rel.len > max_path_bytes) return null;
    return try std.fmt.allocPrint(arena, "{s}/{s}", .{ b, rel });
}

/// _dyld_shared_cache_contains_path (macOS 11+); false off-macOS.
pub fn inSharedCache(path_z: [:0]const u8) bool {
    if (!is_macos) return false;
    if (path_z.len == 0 or path_z.len > max_path_bytes) return false;
    return _dyld_shared_cache_contains_path(path_z.ptr);
}
pub const is_macos = builtin.os.tag == .macos;
extern "c" fn _dyld_shared_cache_contains_path(path: [*:0]const u8) bool;

// ---- tests ----

fn testDylib(name: []const u8, weak: bool) Dylib {
    return .{
        .cmd = if (weak) @intFromEnum(std.macho.LC.LOAD_WEAK_DYLIB) else @intFromEnum(std.macho.LC.LOAD_DYLIB),
        .name = name,
        .name_terminated = true,
        .timestamp = 2,
        .current_version = 0x10000,
        .compat_version = 0x10000,
        .flags = 0,
        .ordinal = 1,
        .weak = weak,
        .reexport = false,
        .upward = false,
        .delayed_init = false,
        .use_command = false,
    };
}

test "dylib_resolve: expansion and boundary rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("/x/y/libz.dylib", (try expand(a, "@executable_path/libz.dylib", "/x/y", "/l")).?);
    try std.testing.expectEqualStrings("/l/libz.dylib", (try expand(a, "@loader_path/libz.dylib", "/x/y", "/l")).?);
    try std.testing.expectEqualStrings("/x/y", (try expand(a, "@executable_path", "/x/y", "/l")).?);
    try std.testing.expectEqualStrings("/x/y/../Frameworks", (try expand(a, "@executable_path/../Frameworks", "/x/y", "/l")).?);
    try std.testing.expect((try expand(a, "@rpath/lib.dylib", "/x", "/l")) == null);
    // "@executable_pathX" is not the @executable_path token.
    try std.testing.expectEqualStrings("@executable_pathX/l", (try expand(a, "@executable_pathX/l", "/x", "/l")).?);
    try std.testing.expectEqualStrings("/usr/lib/libSystem.B.dylib", (try expand(a, "/usr/lib/libSystem.B.dylib", "/x", "/l")).?);
    try std.testing.expect((try expand(a, "", "/x", "/l")) == null);
    try std.testing.expectEqualStrings("/x/y/z", (try joinPath(a, "/x/y/", "z")).?);
}

test "dylib_resolve: off-macOS and empty input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 8);
    try std.testing.expectEqual(@as(usize, 0), (try resolveAll(a, std.testing.io, "/x/exe", &.{}, &.{}, &diags)).len);
    const one = try resolveAll(a, std.testing.io, "/x/exe", &.{testDylib("/definitely/not/here.dylib", false)}, &.{}, &diags);
    try std.testing.expectEqual(@as(usize, 1), one.len);
    try std.testing.expectEqual(if (is_macos) Status.missing else Status.not_checked, one[0].status);
}

test "dylib_resolve: statuses for absolute, rpath, weak and cache paths" {
    if (!is_macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 16);
    const dylibs = [_]Dylib{
        testDylib("/usr/lib/libSystem.B.dylib", false), // shared cache only
        testDylib("/definitely/not/here.dylib", false), // missing
        testDylib("/definitely/not/here.dylib", true), // weak_missing
        testDylib("@rpath/definitely-not-here.dylib", false), // unresolvable_rpath
        testDylib("@rpath/definitely-not-here.dylib", true), // weak_missing
        testDylib("@rpath/usr/lib/libSystem.B.dylib", false), // resolves through an absolute rpath
    };
    const res = try resolveAll(a, std.testing.io, "/bin/ls", &dylibs, &.{ "@executable_path", "/" }, &diags);
    try std.testing.expectEqual(Status.shared_cache, res[0].status);
    try std.testing.expectEqual(Status.missing, res[1].status);
    try std.testing.expectEqual(Status.weak_missing, res[2].status);
    try std.testing.expectEqual(Status.unresolvable_rpath, res[3].status);
    try std.testing.expectEqual(Status.weak_missing, res[4].status);
    try std.testing.expectEqual(Status.shared_cache, res[5].status);
    try std.testing.expectEqualStrings("/", res[5].via_rpath.?);
    try std.testing.expect(inSharedCache("/usr/lib/libSystem.B.dylib"));
    try std.testing.expect(!inSharedCache("/definitely/not/here.dylib"));
    try std.testing.expect(!inSharedCache(""));
}

test "dylib_resolve: a hostile name never escapes the caps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 16);
    const huge = try a.alloc(u8, max_path_bytes + 1);
    @memset(huge, 'a');
    const dylibs = [_]Dylib{ testDylib(huge, false), testDylib("", false), testDylib("\xff\xfe/x", false) };
    const res = try resolveAll(a, std.testing.io, "/x/exe", &dylibs, &.{"@rpath/loop"}, &diags);
    try std.testing.expectEqual(@as(usize, 3), res.len);
    for (res) |r| try std.testing.expect(r.status == .missing or r.status == .not_checked);
}
