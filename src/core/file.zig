//! core/file.zig — the loaded input file. Imports: reader, fat, arch, limits, diag.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Reader = @import("reader.zig").Reader;
const fat = @import("fat.zig");
const Arch = @import("arch.zig").Arch;
const Limits = @import("limits.zig").Limits;
const Diagnostics = @import("diag.zig").Diagnostics;

pub const LoadedFile = struct {
    path: []const u8, // arena-owned
    path_z: [:0]const u8, // arena-owned NUL-terminated copy for C APIs
    /// Whole file. Owned by `gpa` (freed by `deinit`), NOT by the analysis arena, so a large input can
    /// be released before the arena is torn down (bundles: per nested code object).
    bytes: []const u8,
    size: u64,
    mtime_unix: i64,
    is_dir: bool, // true for bundles/directories (bytes is empty; container = .not_macho)
    container: fat.Container,
    sha256: ?[32]u8 = null,
    /// True when `bytes` came from `load` (gpa-owned).
    owned: bool = false,

    pub const LoadError = error{ FileNotFound, AccessDenied, TooLarge, Unexpected } || Allocator.Error;

    /// Stats the path, reads at most `limits.max_file_size` bytes (`Io.Dir.readFileAlloc(.., .limited64(..))`;
    /// larger -> error.TooLarge), classifies the container via fat.parse. Directories -> is_dir=true.
    pub fn load(gpa: Allocator, arena: Allocator, io: Io, path: []const u8, limits: *const Limits, diags: *Diagnostics) LoadError!LoadedFile {
        const cwd = Io.Dir.cwd();
        const st = cwd.statFile(io, path, .{}) catch |e| return mapErr(e);
        const path_z = try arena.dupeSentinel(u8, path, 0);
        var f: LoadedFile = .{
            .path = path_z,
            .path_z = path_z,
            .bytes = &.{},
            .size = st.size,
            .mtime_unix = st.mtime.toSeconds(),
            .is_dir = st.kind == .directory,
            .container = .not_macho,
        };
        if (f.is_dir) return f;
        if (st.size > limits.max_file_size) return error.TooLarge;
        // +1 so a file that grew past the cap between stat and read is still rejected.
        const cap: u64 = limits.max_file_size +| 1;
        const bytes = cwd.readFileAlloc(io, path, gpa, .limited64(cap)) catch |e| switch (e) {
            error.StreamTooLong => return error.TooLarge,
            error.OutOfMemory => return error.OutOfMemory,
            else => return mapErr(e),
        };
        if (bytes.len > limits.max_file_size) {
            gpa.free(bytes);
            return error.TooLarge;
        }
        f.bytes = bytes;
        f.owned = true;
        f.size = bytes.len;
        f.container = try fat.parse(arena, f.reader(), limits, diags);
        return f;
    }
    fn mapErr(e: anyerror) LoadError {
        return switch (e) {
            error.FileNotFound, error.NotDir => error.FileNotFound,
            error.AccessDenied, error.PermissionDenied => error.AccessDenied,
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unexpected,
        };
    }
    /// Same classification over caller-provided bytes (tests, fuzzers, nested code already in memory).
    pub fn fromBytes(arena: Allocator, path: []const u8, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!LoadedFile {
        const path_z = try arena.dupeSentinel(u8, path, 0);
        var f: LoadedFile = .{
            .path = path_z,
            .path_z = path_z,
            .bytes = bytes,
            .size = bytes.len,
            .mtime_unix = 0,
            .is_dir = false,
            .container = .not_macho,
        };
        f.container = try fat.parse(arena, f.reader(), limits, diags);
        return f;
    }
    /// Frees `bytes` when they were allocated by `load` (no-op for `fromBytes`).
    pub fn deinit(f: *LoadedFile, gpa: Allocator) void {
        if (f.owned) gpa.free(f.bytes);
        f.bytes = &.{};
        f.owned = false;
    }
    pub fn reader(f: *const LoadedFile) Reader {
        return Reader.init(f.bytes, 0);
    }
    /// The `index`-th analysable slice (valid fat arches only; thin = index 0).
    fn fatArch(f: *const LoadedFile, index: usize) ?fat.FatArch {
        switch (f.container) {
            .fat => |ft| {
                if (index >= ft.arches.len) return null;
                const a = ft.arches[index];
                return if (a.valid) a else null;
            },
            else => return null,
        }
    }
    /// Slice reader for Mach-O `index` (0 for thin; only valid fat arches count).
    pub fn sliceReader(f: *const LoadedFile, index: usize) ?Reader {
        switch (f.container) {
            .thin => return if (index == 0) f.reader() else null,
            .fat => {
                const a = f.fatArch(index) orelse return null;
                return f.reader().sub(a.offset, a.size);
            },
            .not_macho => return null,
        }
    }
    pub fn sliceOffset(f: *const LoadedFile, index: usize) ?u64 {
        switch (f.container) {
            .thin => return if (index == 0) 0 else null,
            .fat => return if (f.fatArch(index)) |a| a.offset else null,
            .not_macho => return null,
        }
    }
    pub fn sliceArch(f: *const LoadedFile, index: usize) ?Arch {
        switch (f.container) {
            .thin => |a| return if (index == 0) a else null,
            .fat => return if (f.fatArch(index)) |a| a.arch else null,
            .not_macho => return null,
        }
    }
    /// Number of fat_arch entries (thin: 1); invalid entries are counted so indices stay stable.
    pub fn sliceCount(f: *const LoadedFile) usize {
        return switch (f.container) {
            .thin => 1,
            .fat => |ft| ft.arches.len,
            .not_macho => 0,
        };
    }
    /// Memoized SHA-256 of the whole file.
    pub fn digest(f: *LoadedFile) [32]u8 {
        if (f.sha256) |d| return d;
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(f.bytes, &out, .{});
        f.sha256 = out;
        return out;
    }
};

test "file: fromBytes classifies and slices" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var d = Diagnostics.init(a, 16);
    var buf: [64]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], std.macho.MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[4..8], 0x0100000c, .little);
    var f = try LoadedFile.fromBytes(a, "x", &buf, &Limits.default, &d);
    defer f.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), f.sliceCount());
    try std.testing.expectEqual(@as(?u64, 0), f.sliceOffset(0));
    try std.testing.expect(f.sliceReader(1) == null);
    try std.testing.expectEqualStrings("x", f.path_z);
    const dg = f.digest();
    try std.testing.expectEqual(dg, f.digest());
    var nm = try LoadedFile.fromBytes(a, "y", "hello", &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 0), nm.sliceCount());
    try std.testing.expect(nm.sliceArch(0) == null);
    nm.deinit(std.testing.allocator);
}

test "file: load reads the corpus header fixture and rejects oversize files" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var d = Diagnostics.init(a, 16);
    try std.testing.expectError(error.FileNotFound, LoadedFile.load(std.testing.allocator, a, io, "/nonexistent/machre-file", &Limits.default, &d));
    var lim = Limits.default;
    lim.max_file_size = 100;
    try std.testing.expectError(error.TooLarge, LoadedFile.load(std.testing.allocator, a, io, "/bin/ls", &lim, &d));
    var f = try LoadedFile.load(std.testing.allocator, a, io, "/bin/ls", &Limits.default, &d);
    defer f.deinit(std.testing.allocator);
    try std.testing.expect(f.size > 0 and f.bytes.len == f.size and !f.is_dir);
    var dir = try LoadedFile.load(std.testing.allocator, a, io, "/bin", &Limits.default, &d);
    defer dir.deinit(std.testing.allocator);
    try std.testing.expect(dir.is_dir and dir.sliceCount() == 0);
}
