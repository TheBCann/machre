//! bundle/bundle.zig — .app/.framework/.xpc discovery, Info.plist, nested code, CodeResources seal verification.
//! Portable: no Darwin externs (cmd/bundle.zig adds Security.framework/xattr results).
//! Imports: core/file, core/fat, core/arch, core/image, core/diag, core/limits, plist/plist, codesign/blobs.
//!
//! The tree walk is bounded on every axis (`max_bundle_entries`, `max_bundle_depth`), symlinks are
//! recorded but never descended, and no subprocess is ever spawned.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const plist = @import("../plist/plist.zig");
const blobs = @import("../codesign/blobs.zig");
const fat = @import("../core/fat.zig");
const Arch = @import("../core/arch.zig").Arch;

pub const Kind = enum { app, framework, xpc, appex, plugin, kext, generic_bundle, unknown };
pub const NestedCode = struct {
    rel_path: []const u8,
    kind: Kind,
    executable_rel: ?[]const u8,
    sealed_cdhash: ?[20]u8, // from CodeResources files2
    sealed_requirement: ?[]const u8,
    actual_cdhash: ?[20]u8, // parsed from the nested code's own LC_CODE_SIGNATURE (best CD)
    /// Arch whose slice `actual_cdhash` came from: the host-preferred one, i.e. the slice
    /// `codesign -dvvv` reports. Null when no slice carried a readable CodeDirectory.
    cdhash_arch: ?[]const u8,
    /// Arch whose slice cdhash equals `sealed_cdhash`, null when none does. A universal binary
    /// carries one CodeDirectory per slice, so only one of them can match the single sealed value.
    matched_arch: ?[]const u8,
    cdhash_match: ?bool,
    signed: ?bool,
    arch_names: []const []const u8,
};
pub const ResourceFile = struct { path: []const u8, hash1: ?[20]u8, hash2: ?[32]u8, optional: bool, symlink: ?[]const u8, nested: bool, cdhash: ?[20]u8, requirement: ?[]const u8 };
pub const CodeResources = struct {
    /// 2 when a `files2` dict is present, else 1.
    version: u32,
    /// Number of entries in the v1 `rules` dict.
    rules: u32,
    /// Number of entries in the v2 `rules2` dict — this is the count `codesign -dvvv` prints for a v2 seal.
    rules2: u32,
    files: []const ResourceFile,
    files2: []const ResourceFile,
    raw: []const u8,
    /// `rules2` keys carrying `omit: true` (paths matching them are not expected to be sealed).
    omit_rules: []const []const u8,
    /// `rules2` keys carrying `nested: true` (code-bearing directories).
    nested_rules: []const []const u8,

    /// What `codesign -dvvv` prints: the active rule count for this seal version.
    pub fn activeRules(cr: *const CodeResources) u32 {
        return if (cr.version >= 2) cr.rules2 else cr.rules;
    }
    /// What `codesign -dvvv` counts as "files".
    pub fn activeFiles(cr: *const CodeResources) usize {
        return if (cr.version >= 2) cr.files2.len else cr.files.len;
    }
    pub fn find(cr: *const CodeResources, path: []const u8) ?*const ResourceFile {
        for (cr.files2) |*f| if (std.mem.eql(u8, f.path, path)) return f;
        for (cr.files) |*f| if (std.mem.eql(u8, f.path, path)) return f;
        return null;
    }
};
pub const ResourceVerify = struct { checked: u32, mismatched: []const []const u8, missing: []const []const u8, unsealed: []const []const u8, ok: bool };

/// One entry seen by the bundle walk (paths are relative to the bundle root).
pub const Entry = struct {
    path: []const u8,
    kind: enum { file, dir, sym_link, other },
    size: u64,
    link_target: ?[]const u8,
};

pub const Bundle = struct {
    root: []const u8,
    kind: Kind,
    info_plist_path: ?[]const u8,
    info_plist: ?plist.Value,
    info_plist_format: plist.Format,
    info_plist_bytes: ?[]const u8,
    identifier: ?[]const u8,
    executable_rel: ?[]const u8,
    executable_path: ?[]const u8,
    package_type: ?[]const u8,
    version: ?[]const u8,
    short_version: ?[]const u8,
    min_system: ?[]const u8,
    principal_class: ?[]const u8,
    ui_element: bool,
    background_only: bool,
    ats_arbitrary_loads: bool,
    usage_descriptions: []const []const u8,
    url_schemes: []const []const u8,
    frameworks: []const NestedCode,
    helpers: []const NestedCode,
    xpc_services: []const NestedCode,
    plugins: []const NestedCode,
    dylibs: []const NestedCode,
    code_resources: ?CodeResources,
    resource_verify: ?ResourceVerify,
    stapled_ticket: ?struct { path: []const u8, len: u64 },
    provisioning_profile: bool,
    file_count: u32,
    total_size: u64,
    entries_walked: u32,
    truncated: bool,
    /// The "Contents" / "Versions/A" prefix that resource-seal paths are relative to.
    contents_rel: []const u8 = "Contents",
    /// Every entry the walk saw (arena-owned), used by `verifyResources` for the unsealed list.
    entries: []const Entry = &.{},

    /// Every nested code object in one slice (frameworks + helpers + xpc + plugins + dylibs).
    pub fn nestedAll(b: *const Bundle, arena: Allocator) Allocator.Error![]const NestedCode {
        var out: std.ArrayList(NestedCode) = .empty;
        for ([_][]const NestedCode{ b.frameworks, b.helpers, b.xpc_services, b.plugins, b.dylibs }) |list| {
            try out.appendSlice(arena, list);
        }
        return out.toOwnedSlice(arena);
    }
};
pub const Options = struct { verify_resources: bool = true, hash_nested: bool = true };

/// Bundle extensions we recognise by name.
fn kindFromExtension(name: []const u8) ?Kind {
    const table = [_]struct { ext: []const u8, kind: Kind }{
        .{ .ext = ".app", .kind = .app },
        .{ .ext = ".framework", .kind = .framework },
        .{ .ext = ".xpc", .kind = .xpc },
        .{ .ext = ".appex", .kind = .appex },
        .{ .ext = ".kext", .kind = .kext },
        .{ .ext = ".bundle", .kind = .generic_bundle },
        .{ .ext = ".plugin", .kind = .plugin },
        .{ .ext = ".qlgenerator", .kind = .plugin },
        .{ .ext = ".mdimporter", .kind = .plugin },
        .{ .ext = ".prefPane", .kind = .plugin },
        .{ .ext = ".saver", .kind = .plugin },
        .{ .ext = ".component", .kind = .plugin },
        .{ .ext = ".osax", .kind = .plugin },
        .{ .ext = ".wdgt", .kind = .plugin },
        .{ .ext = ".systemextension", .kind = .plugin },
    };
    for (table) |e| if (std.mem.endsWith(u8, name, e.ext)) return e.kind;
    return null;
}

/// Where a bundle keeps its Info.plist and _CodeSignature.
pub const Layout = struct {
    kind: Kind,
    /// "Contents", "Versions/A" or "" (flat framework/bundle).
    contents_rel: []const u8,
    /// Path of Info.plist relative to the bundle root.
    info_plist_rel: []const u8,
    /// Directory holding the main executable, relative to the bundle root.
    macos_rel: []const u8,
};

/// Directory containing Contents/Info.plist (app/xpc/plugin) or Versions/*/Resources/Info.plist (framework).
pub fn detect(io: Io, path: []const u8) ?Kind {
    var buf: [512]u8 = undefined;
    const l = layoutOf(io, path, &buf) orelse return null;
    return l.kind;
}

/// Probes the three known layouts; `buf` backs the returned paths, so it must outlive the result.
fn layoutOf(io: Io, path: []const u8, buf: *[512]u8) ?Layout {
    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, path, .{}) catch return null;
    defer dir.close(io);
    const name = std.fs.path.basename(path);
    const by_ext = kindFromExtension(name);

    if (dir.statFile(io, "Contents/Info.plist", .{})) |st| {
        if (st.kind == .file) return .{
            .kind = by_ext orelse .generic_bundle,
            .contents_rel = "Contents",
            .info_plist_rel = "Contents/Info.plist",
            .macos_rel = "Contents/MacOS",
        };
    } else |_| {}

    // Framework: Versions/Current -> A (a symlink); Versions/<v>/Resources/Info.plist.
    const versions = [_][]const u8{ "Versions/Current", "Versions/A", "Versions/B", "Versions/C" };
    for (versions) |v| {
        const ip = std.fmt.bufPrint(buf, "{s}/Resources/Info.plist", .{v}) catch continue;
        if (dir.statFile(io, ip, .{})) |st| {
            if (st.kind != .file) continue;
            // bufPrint again so the returned slices all live in `buf` and do not overlap.
            const all = std.fmt.bufPrint(buf, "{s}\x00{s}/Resources/Info.plist\x00{s}", .{ v, v, v }) catch continue;
            var it = std.mem.splitScalar(u8, all, 0);
            const contents = it.next() orelse continue;
            const info = it.next() orelse continue;
            const macos = it.next() orelse continue;
            return .{ .kind = .framework, .contents_rel = contents, .info_plist_rel = info, .macos_rel = macos };
        } else |_| {}
    }
    // Unversioned framework (no Versions/ tree, as Firefox's ChannelPrefs.framework): Resources/Info.plist
    // with the executable beside it at the framework root.
    if (by_ext) |k| {
        if (k == .framework) {
            if (dir.statFile(io, "Resources/Info.plist", .{})) |st| {
                if (st.kind == .file) return .{
                    .kind = .framework,
                    .contents_rel = "",
                    .info_plist_rel = "Resources/Info.plist",
                    .macos_rel = "",
                };
            } else |_| {}
        }
    }
    // Flat bundle (iOS-style framework, some .kext): Info.plist at the root. Only accepted when the
    // directory carries a bundle extension, so `X.app/Contents` (which also holds an Info.plist) is
    // never mistaken for a bundle of its own.
    if (by_ext) |k| {
        if (dir.statFile(io, "Info.plist", .{})) |st| {
            if (st.kind == .file) return .{
                .kind = k,
                .contents_rel = "",
                .info_plist_rel = "Info.plist",
                .macos_rel = "",
            };
        } else |_| {}
    }
    return null;
}

/// Raw bytes of the two files the CodeDirectory seals by PATH rather than by an embedded blob:
/// Info.plist (special slot -1) and _CodeSignature/CodeResources (slot -3). `codesign` hashes them
/// off disk, so verifying those slots needs the bundle directory, not the Mach-O.
pub const SealedFiles = struct { info_plist: ?[]const u8 = null, code_resources: ?[]const u8 = null };

pub fn sealedFiles(arena: Allocator, io: Io, path: []const u8, limits: *const Limits) Allocator.Error!SealedFiles {
    var buf: [512]u8 = undefined;
    const l = layoutOf(io, path, &buf) orelse return .{};
    var dir = Io.Dir.cwd().openDir(io, path, .{}) catch return .{};
    defer dir.close(io);
    var out: SealedFiles = .{};
    if (dir.readFileAlloc(io, l.info_plist_rel, arena, .limited64(limits.max_plist_bytes))) |b| {
        out.info_plist = b;
    } else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
    const cs_rel = try joinRel(arena, l.contents_rel, "_CodeSignature/CodeResources");
    if (dir.readFileAlloc(io, cs_rel, arena, .limited64(limits.max_xml_bytes))) |b| {
        out.code_resources = b;
    } else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
    return out;
}

fn joinRel(arena: Allocator, a: []const u8, b: []const u8) Allocator.Error![]const u8 {
    if (a.len == 0) return arena.dupe(u8, b);
    if (b.len == 0) return arena.dupe(u8, a);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ a, b });
}

/// Main executable path for a bundle root (Contents/MacOS/<CFBundleExecutable> or Versions/Current/<Name>).
pub fn mainExecutable(arena: Allocator, io: Io, path: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?[]const u8 {
    var buf: [512]u8 = undefined;
    const l = layoutOf(io, path, &buf) orelse return null;
    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, path, .{}) catch {
        diags.warn(.bundle, .os_error, null, "cannot open bundle directory", .{});
        return null;
    };
    defer dir.close(io);

    var exe_name: ?[]const u8 = null;
    if (try readPlistFile(arena, io, dir, l.info_plist_rel, limits, diags)) |res| {
        if (res.value) |v| exe_name = v.getString("CFBundleExecutable");
    }
    var name_buf: [256]u8 = undefined;
    if (exe_name == null) {
        // Fall back to the bundle name without its extension.
        const base = std.fs.path.basename(path);
        const dot = std.mem.findScalarLast(u8, base, '.') orelse base.len;
        if (dot != 0 and dot <= name_buf.len) {
            @memcpy(name_buf[0..dot], base[0..dot]);
            exe_name = name_buf[0..dot];
        }
    }
    const name = exe_name orelse return null;
    if (name.len == 0 or std.mem.findScalar(u8, name, '/') != null) {
        diags.warn(.bundle, .plist_malformed, null, "CFBundleExecutable is not a plain file name", .{});
        return null;
    }
    const rel = try joinRel(arena, l.macos_rel, name);
    const st = dir.statFile(io, rel, .{}) catch {
        diags.warn(.bundle, .not_available, null, "bundle executable '{s}' is missing", .{rel});
        return null;
    };
    if (st.kind != .file) return null;
    return try joinRel(arena, path, rel);
}

/// Walks up from `path` looking for the bundle that contains it, the way `SecStaticCodeCreateWithPath`
/// promotes `X.app/Contents/MacOS/exe` to `X.app` (format-notes 12.7). At most `max_up` levels; returns
/// the bundle root (arena-owned) or null.
pub fn enclosingBundle(arena: Allocator, io: Io, path: []const u8, limits: *const Limits) Allocator.Error!?[]const u8 {
    _ = limits;
    const max_up = 6;
    var cur: []const u8 = path;
    var up: u32 = 0;
    while (up < max_up) : (up += 1) {
        cur = std.fs.path.dirname(cur) orelse return null;
        if (cur.len == 0) return null;
        var lbuf: [512]u8 = undefined;
        if (layoutOf(io, cur, &lbuf) != null) return try arena.dupe(u8, cur);
    }
    return null;
}

pub const InfoPlist = struct { rel_path: []const u8, bytes: []const u8, format: plist.Format, value: ?plist.Value };

/// Reads (and parses) the Info.plist of the bundle rooted at `path`; null when `path` is not a bundle.
/// Cheap: it never walks the tree, so `cmd/plist.zig` can use it on a directory argument.
pub fn readInfoPlist(arena: Allocator, io: Io, path: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?InfoPlist {
    var lbuf: [512]u8 = undefined;
    const l = layoutOf(io, path, &lbuf) orelse return null;
    const rel = try arena.dupe(u8, l.info_plist_rel);
    var dir = Io.Dir.cwd().openDir(io, path, .{}) catch return null;
    defer dir.close(io);
    const f = try readPlistFile(arena, io, dir, rel, limits, diags) orelse return null;
    return .{ .rel_path = rel, .bytes = f.bytes, .format = f.format, .value = f.value };
}

const PlistFile = struct { bytes: []const u8, value: ?plist.Value, format: plist.Format };

fn readPlistFile(arena: Allocator, io: Io, dir: Io.Dir, rel: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?PlistFile {
    const bytes = dir.readFileAlloc(io, rel, arena, .limited64(limits.max_plist_bytes)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound => return null,
        else => {
            diags.warn(.bundle, .os_error, null, "cannot read '{s}': {t}", .{ rel, e });
            return null;
        },
    };
    const fmt = plist.detect(bytes);
    const v = try plist.parseAny(arena, bytes, limits, diags);
    return .{ .bytes = bytes, .value = v, .format = fmt };
}

/// Io.Dir.walk (symlinks reported, never descended), entries <= limits.max_bundle_entries, depth <= max_bundle_depth.
pub fn analyze(arena: Allocator, gpa: Allocator, io: Io, path: []const u8, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Bundle {
    var lbuf: [512]u8 = undefined;
    const l = layoutOf(io, path, &lbuf) orelse {
        diags.warn(.bundle, .not_available, null, "'{s}' is not a bundle (no Contents/Info.plist, Versions/*/Resources/Info.plist or Info.plist)", .{std.fs.path.basename(path)});
        return null;
    };
    const contents_rel = try arena.dupe(u8, l.contents_rel);
    const info_rel = try arena.dupe(u8, l.info_plist_rel);
    const macos_rel = try arena.dupe(u8, l.macos_rel);

    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, path, .{ .iterate = true }) catch {
        diags.err(.bundle, .os_error, null, "cannot open bundle directory", .{});
        return null;
    };
    defer dir.close(io);

    var b: Bundle = .{
        .root = try arena.dupe(u8, path),
        .kind = l.kind,
        .info_plist_path = null,
        .info_plist = null,
        .info_plist_format = .unknown,
        .info_plist_bytes = null,
        .identifier = null,
        .executable_rel = null,
        .executable_path = null,
        .package_type = null,
        .version = null,
        .short_version = null,
        .min_system = null,
        .principal_class = null,
        .ui_element = false,
        .background_only = false,
        .ats_arbitrary_loads = false,
        .usage_descriptions = &.{},
        .url_schemes = &.{},
        .frameworks = &.{},
        .helpers = &.{},
        .xpc_services = &.{},
        .plugins = &.{},
        .dylibs = &.{},
        .code_resources = null,
        .resource_verify = null,
        .stapled_ticket = null,
        .provisioning_profile = false,
        .file_count = 0,
        .total_size = 0,
        .entries_walked = 0,
        .truncated = false,
        .contents_rel = contents_rel,
    };

    // ---- walk ----
    var entries: std.ArrayList(Entry) = .empty;
    try walk(arena, gpa, io, dir, limits, diags, &entries, &b);
    b.entries = entries.items;

    // ---- Info.plist ----
    if (try readPlistFile(arena, io, dir, info_rel, limits, diags)) |ip| {
        b.info_plist_path = info_rel;
        b.info_plist_bytes = ip.bytes;
        b.info_plist_format = ip.format;
        b.info_plist = ip.value;
        if (ip.value) |v| try fillFromInfoPlist(arena, &b, v);
    } else {
        diags.warn(.bundle, .not_available, null, "Info.plist is missing at '{s}'", .{info_rel});
    }
    if (b.executable_rel) |name| {
        const rel = try joinRel(arena, macos_rel, name);
        if (dir.statFile(io, rel, .{})) |st| {
            if (st.kind == .file) {
                b.executable_rel = rel;
                b.executable_path = try joinRel(arena, b.root, rel);
            }
        } else |_| {
            diags.warn(.bundle, .not_available, null, "bundle executable '{s}' is missing", .{rel});
            b.executable_rel = rel;
        }
    }

    // ---- CodeResources / ticket / profile ----
    const cs_rel = try joinRel(arena, contents_rel, "_CodeSignature/CodeResources");
    if (dir.readFileAlloc(io, cs_rel, arena, .limited64(limits.max_xml_bytes))) |bytes| {
        b.code_resources = try parseCodeResources(arena, bytes, limits, diags);
    } else |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound => {},
        else => diags.warn(.bundle, .os_error, null, "cannot read '{s}': {t}", .{ cs_rel, e }),
    }
    const ticket_rel = try joinRel(arena, contents_rel, "CodeResources");
    if (dir.readFileAlloc(io, ticket_rel, arena, .limited64(1 << 22))) |bytes| {
        if (bytes.len >= 4 and std.mem.startsWith(u8, bytes, "s8ch")) {
            b.stapled_ticket = .{ .path = ticket_rel, .len = bytes.len };
        } else if (bytes.len != 0) {
            diags.info(.bundle, .unknown_value, null, "'{s}' exists but does not start with the 's8ch' ticket magic", .{ticket_rel});
        }
    } else |_| {}
    const profile_rel = try joinRel(arena, contents_rel, "embedded.provisionprofile");
    if (dir.statFile(io, profile_rel, .{})) |_| {
        b.provisioning_profile = true;
    } else |_| {}

    // ---- nested code ----
    try collectNested(arena, gpa, io, dir, &b, opts, limits, diags);

    // ---- resource verification ----
    if (opts.verify_resources and b.code_resources != null) {
        b.resource_verify = try verifyResources(arena, gpa, io, &b, limits, diags);
    }
    return b;
}

/// Explicit-stack breadth of the tree via `Io.Dir.Walker`; directories deeper than `max_bundle_depth`
/// are left immediately, symlinks are recorded but never followed.
fn walk(arena: Allocator, gpa: Allocator, io: Io, dir: Io.Dir, limits: *const Limits, diags: *Diagnostics, out: *std.ArrayList(Entry), b: *Bundle) Allocator.Error!void {
    var walker = dir.walk(gpa) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer walker.deinit();
    while (true) {
        const maybe = walker.next(io) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                diags.warn(.bundle, .os_error, null, "bundle walk stopped: {t}", .{e});
                break;
            },
        };
        const e = maybe orelse break;
        b.entries_walked += 1;
        if (b.entries_walked > limits.max_bundle_entries) {
            b.truncated = true;
            diags.warn(.bundle, .limit_reached, null, "bundle has more than max_bundle_entries {d} entries", .{limits.max_bundle_entries});
            break;
        }
        const rel = try arena.dupe(u8, e.path);
        const too_deep = e.kind == .directory and e.depth() >= limits.max_bundle_depth;
        var entry: Entry = .{
            .path = rel,
            .kind = switch (e.kind) {
                .file => .file,
                .directory => .dir,
                .sym_link => .sym_link,
                else => .other,
            },
            .size = 0,
            .link_target = null,
        };
        switch (e.kind) {
            .file => {
                if (e.dir.statFile(io, e.basename, .{ .follow_symlinks = false })) |st| {
                    entry.size = st.size;
                    b.total_size +|= st.size;
                } else |_| {}
                b.file_count += 1;
            },
            .sym_link => {
                var lbuf: [1024]u8 = undefined;
                if (e.dir.readLink(io, e.basename, &lbuf)) |n| {
                    entry.link_target = try arena.dupe(u8, lbuf[0..@min(n, lbuf.len)]);
                } else |_| {}
            },
            else => {},
        }
        try out.append(arena, entry);
        if (too_deep) {
            b.truncated = true;
            if (!diags.has(.bundle, .limit_reached)) diags.warn(.bundle, .limit_reached, null, "bundle nesting deeper than max_bundle_depth {d}", .{limits.max_bundle_depth});
            walker.leave(io);
        }
    }
}

fn fillFromInfoPlist(arena: Allocator, b: *Bundle, v: plist.Value) Allocator.Error!void {
    b.identifier = v.getString("CFBundleIdentifier");
    b.executable_rel = v.getString("CFBundleExecutable");
    b.package_type = v.getString("CFBundlePackageType");
    b.version = v.getString("CFBundleVersion");
    b.short_version = v.getString("CFBundleShortVersionString");
    b.min_system = v.getString("LSMinimumSystemVersion");
    b.principal_class = v.getString("NSPrincipalClass");
    b.ui_element = v.getBool("LSUIElement") orelse false;
    b.background_only = v.getBool("LSBackgroundOnly") orelse false;
    if (v.path("NSAppTransportSecurity.NSAllowsArbitraryLoads")) |x| {
        b.ats_arbitrary_loads = switch (x) {
            .bool => |bb| bb,
            .integer => |i| i != 0,
            else => false,
        };
    }
    if (b.package_type == null and b.kind == .framework) b.package_type = "FMWK";

    var usage: std.ArrayList([]const u8) = .empty;
    switch (v) {
        .dict => |entries| for (entries) |e| {
            if (std.mem.endsWith(u8, e.key, "UsageDescription")) try usage.append(arena, e.key);
        },
        else => {},
    }
    b.usage_descriptions = try usage.toOwnedSlice(arena);

    var schemes: std.ArrayList([]const u8) = .empty;
    if (v.get("CFBundleURLTypes")) |types| switch (types) {
        .array => |items| for (items) |t| {
            const list = t.get("CFBundleURLSchemes") orelse continue;
            switch (list) {
                .array => |ss| for (ss) |s| switch (s) {
                    .string => |str| try schemes.append(arena, str),
                    else => {},
                },
                else => {},
            }
        },
        else => {},
    };
    b.url_schemes = try schemes.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------------------------
// CodeResources
// ---------------------------------------------------------------------------------------------

/// Parses `_CodeSignature/CodeResources` (an XML plist). `null` when it is not a plist at all.
pub fn parseCodeResources(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?CodeResources {
    const root = try plist.parseAny(arena, bytes, limits, diags) orelse {
        diags.warn(.bundle, .plist_malformed, null, "CodeResources is not a property list", .{});
        return null;
    };
    if (root != .dict) {
        diags.warn(.bundle, .plist_malformed, null, "CodeResources root is a {s}, not a dict", .{root.typeName()});
        return null;
    }
    var cr: CodeResources = .{
        .version = 1,
        .rules = 0,
        .rules2 = 0,
        .files = &.{},
        .files2 = &.{},
        .raw = bytes,
        .omit_rules = &.{},
        .nested_rules = &.{},
    };
    if (root.get("files")) |f| cr.files = try parseSealedFiles(arena, f, false, limits, diags);
    if (root.get("files2")) |f| {
        cr.files2 = try parseSealedFiles(arena, f, true, limits, diags);
        cr.version = 2;
    }
    if (root.get("rules")) |r| cr.rules = @intCast(dictLen(r));
    if (root.get("rules2")) |r| {
        cr.rules2 = @intCast(dictLen(r));
        var omit: std.ArrayList([]const u8) = .empty;
        var nested: std.ArrayList([]const u8) = .empty;
        switch (r) {
            .dict => |entries| for (entries) |e| {
                if (e.value.getBool("omit") orelse false) try omit.append(arena, e.key);
                if (e.value.getBool("nested") orelse false) try nested.append(arena, e.key);
            },
            else => {},
        }
        cr.omit_rules = try omit.toOwnedSlice(arena);
        cr.nested_rules = try nested.toOwnedSlice(arena);
    }
    return cr;
}
fn dictLen(v: plist.Value) usize {
    return switch (v) {
        .dict => |d| d.len,
        else => 0,
    };
}

fn parseSealedFiles(arena: Allocator, v: plist.Value, v2: bool, limits: *const Limits, diags: *Diagnostics) Allocator.Error![]const ResourceFile {
    var out: std.ArrayList(ResourceFile) = .empty;
    switch (v) {
        .dict => |entries| for (entries) |e| {
            if (out.items.len >= limits.max_bundle_entries) {
                diags.warn(.bundle, .limit_reached, null, "CodeResources lists more than max_bundle_entries {d} files", .{limits.max_bundle_entries});
                break;
            }
            var f: ResourceFile = .{ .path = e.key, .hash1 = null, .hash2 = null, .optional = false, .symlink = null, .nested = false, .cdhash = null, .requirement = null };
            switch (e.value) {
                // v1 short form: path -> <data> sha1
                .data => |d| f.hash1 = fixed(20, d),
                .dict => {
                    if (e.value.get("hash")) |h| if (h == .data) {
                        f.hash1 = fixed(20, h.data);
                    };
                    if (e.value.get("hash2")) |h| if (h == .data) {
                        f.hash2 = fixed(32, h.data);
                    };
                    if (e.value.get("cdhash")) |h| if (h == .data) {
                        f.cdhash = fixed(20, h.data);
                        f.nested = true;
                    };
                    f.requirement = e.value.getString("requirement");
                    f.symlink = e.value.getString("symlink");
                    f.optional = e.value.getBool("optional") orelse false;
                },
                else => diags.info(.bundle, .unknown_value, null, "CodeResources entry '{s}' has an unexpected shape", .{e.key}),
            }
            if (v2 and f.hash2 == null and f.cdhash == null and f.symlink == null and f.hash1 == null) {
                diags.info(.bundle, .unknown_value, null, "CodeResources files2 entry '{s}' seals nothing", .{e.key});
            }
            try out.append(arena, f);
        },
        else => diags.warn(.bundle, .plist_malformed, null, "CodeResources {s} is not a dict", .{if (v2) "files2" else "files"}),
    }
    return out.toOwnedSlice(arena);
}
fn fixed(comptime n: usize, d: []const u8) ?[n]u8 {
    if (d.len != n) return null;
    var out: [n]u8 = undefined;
    @memcpy(&out, d[0..n]);
    return out;
}

// ---------------------------------------------------------------------------------------------
// nested code
// ---------------------------------------------------------------------------------------------

const NestedDir = struct { rel: []const u8, bucket: enum { frameworks, helpers, xpc, plugins } };

fn collectNested(arena: Allocator, gpa: Allocator, io: Io, dir: Io.Dir, b: *Bundle, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!void {
    const dirs = [_]NestedDir{
        .{ .rel = "Frameworks", .bucket = .frameworks },
        .{ .rel = "SharedFrameworks", .bucket = .frameworks },
        .{ .rel = "Libraries", .bucket = .frameworks },
        .{ .rel = "XPCServices", .bucket = .xpc },
        .{ .rel = "PlugIns", .bucket = .plugins },
        .{ .rel = "Plug-ins", .bucket = .plugins },
        .{ .rel = "Helpers", .bucket = .helpers },
        .{ .rel = "Library/LoginItems", .bucket = .helpers },
        .{ .rel = "Library/Automator", .bucket = .plugins },
        .{ .rel = "Library/Spotlight", .bucket = .plugins },
        .{ .rel = "MacOS", .bucket = .helpers },
    };
    var frameworks: std.ArrayList(NestedCode) = .empty;
    var helpers: std.ArrayList(NestedCode) = .empty;
    var xpc: std.ArrayList(NestedCode) = .empty;
    var plugins: std.ArrayList(NestedCode) = .empty;
    var dylibs: std.ArrayList(NestedCode) = .empty;
    var found: u32 = 0;

    for (b.entries) |e| {
        if (e.kind != .file and e.kind != .dir) continue;
        const under = relativeToContents(b, e.path) orelse continue;
        // The main executable is covered by the CodeDirectory, not by the resource seal.
        if (b.executable_rel) |x| if (std.mem.eql(u8, e.path, x)) continue;
        var bucket: ?@TypeOf(dirs[0].bucket) = null;
        var parent_len: usize = 0;
        for (dirs) |d| {
            if (under.len > d.rel.len + 1 and std.mem.startsWith(u8, under, d.rel) and under[d.rel.len] == '/') {
                if (d.rel.len > parent_len) {
                    bucket = d.bucket;
                    parent_len = d.rel.len;
                }
            }
        }
        const is_dylib = e.kind == .file and (std.mem.endsWith(u8, e.path, ".dylib") or std.mem.endsWith(u8, e.path, ".so"));
        const ext_kind = if (e.kind == .dir) kindFromExtension(e.path) else null;
        if (bucket == null and !is_dylib) continue;
        if (e.kind == .dir and ext_kind == null) continue;
        // Only the immediate child of a nested directory counts (deeper entries belong to it).
        if (bucket != null and std.mem.findScalarPos(u8, under, parent_len + 1, '/') != null) continue;
        found += 1;
        if (found > limits.max_nested_code) {
            diags.warn(.bundle, .limit_reached, null, "more than max_nested_code {d} nested code objects", .{limits.max_nested_code});
            break;
        }
        var nc: NestedCode = .{
            .rel_path = e.path,
            .kind = ext_kind orelse .unknown,
            .executable_rel = null,
            .sealed_cdhash = null,
            .sealed_requirement = null,
            .actual_cdhash = null,
            .cdhash_arch = null,
            .matched_arch = null,
            .cdhash_match = null,
            .signed = null,
            .arch_names = &.{},
        };
        if (b.code_resources) |*cr| {
            if (cr.find(under)) |rf| {
                nc.sealed_cdhash = rf.cdhash;
                nc.sealed_requirement = rf.requirement;
            }
        }
        // Resolve the file whose signature we must read.
        var exe_rel: ?[]const u8 = null;
        if (e.kind == .file) {
            exe_rel = e.path;
        } else {
            const abs = try joinRel(arena, b.root, e.path);
            if (try mainExecutable(arena, io, abs, limits, diags)) |p| {
                exe_rel = if (p.len > b.root.len + 1) p[b.root.len + 1 ..] else p;
            }
        }
        nc.executable_rel = exe_rel;
        if (opts.hash_nested) {
            if (exe_rel) |rel| try readNestedSignature(arena, gpa, io, dir, rel, &nc, limits, diags);
        }
        if (nc.sealed_cdhash != null and nc.actual_cdhash != null) nc.cdhash_match = nc.matched_arch != null;
        switch (bucket orelse .frameworks) {
            .frameworks => if (is_dylib) try dylibs.append(arena, nc) else try frameworks.append(arena, nc),
            .helpers => try helpers.append(arena, nc),
            .xpc => try xpc.append(arena, nc),
            .plugins => try plugins.append(arena, nc),
        }
    }
    b.frameworks = try frameworks.toOwnedSlice(arena);
    b.helpers = try helpers.toOwnedSlice(arena);
    b.xpc_services = try xpc.toOwnedSlice(arena);
    b.plugins = try plugins.toOwnedSlice(arena);
    b.dylibs = try dylibs.toOwnedSlice(arena);
}

/// Path relative to the bundle's contents dir ("Contents/Frameworks/x" -> "Frameworks/x"), or null
/// when the entry is outside it.
fn relativeToContents(b: *const Bundle, rel: []const u8) ?[]const u8 {
    if (b.contents_rel.len == 0) return rel;
    if (!std.mem.startsWith(u8, rel, b.contents_rel)) return null;
    if (rel.len <= b.contents_rel.len) return null;
    if (rel[b.contents_rel.len] != '/') return null;
    return rel[b.contents_rel.len + 1 ..];
}

/// Loads one nested Mach-O, records its arch names and its own best-CD cdhash, and frees it again.
///
/// A universal nested binary carries one CodeDirectory per slice, so it has one cdhash per slice,
/// while `CodeResources` seals exactly one value. `actual_cdhash` is therefore taken from the
/// host-preferred slice — the same `fat.selectArches` choice `cmd/codesign.zig` makes, so it equals
/// what `codesign -dvvv` prints — and the seal is compared against every slice, recording in
/// `matched_arch` which one it sealed (an app signed on a different-arch host seals that host's).
fn readNestedSignature(arena: Allocator, gpa: Allocator, io: Io, dir: Io.Dir, rel: []const u8, nc: *NestedCode, limits: *const Limits, diags: *Diagnostics) Allocator.Error!void {
    const bytes = dir.readFileAlloc(io, rel, gpa, .limited64(limits.max_file_size)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            diags.info(.bundle, .os_error, null, "cannot read nested code '{s}': {t}", .{ rel, e });
            return;
        },
    };
    defer gpa.free(bytes);
    const file = try LoadedFile.fromBytes(arena, rel, bytes, limits, diags);
    if (file.container == .not_macho) return;

    // The slice codesign(1) speaks for. `bundle` takes no --arch: a resource seal is a property of
    // the bundle, not of one slice, so the host preference is the only defensible default.
    const preferred: ?u32 = if (fat.selectArches(arena, file.container, null, false, Arch.host())) |sel|
        (if (sel.indices.len == 0) null else sel.indices[0])
    else |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => null,
    };

    var names: std.ArrayList([]const u8) = .empty;
    var signed = false;
    var first_hash: ?[20]u8 = null;
    var first_arch: ?[]const u8 = null;
    var i: usize = 0;
    while (i < file.sliceCount()) : (i += 1) {
        const r = file.sliceReader(i) orelse continue;
        const off = file.sliceOffset(i) orelse continue;
        const img = Image.parse(arena, r, off, @intCast(i), limits, diags) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        var nbuf: [32]u8 = undefined;
        const arch_name = try arena.dupe(u8, img.arch.displayName(&nbuf));
        try names.append(arena, arch_name);
        if (img.findCmd(.CODE_SIGNATURE) == null) continue;
        signed = true;
        const sig = try blobs.parse(arena, &img, limits, diags) orelse continue;
        const cd = sig.cd() orelse continue;
        if (preferred != null and i == preferred.?) {
            nc.actual_cdhash = cd.cdhash;
            nc.cdhash_arch = arch_name;
        } else if (first_hash == null) {
            first_hash = cd.cdhash;
            first_arch = arch_name;
        }
        if (nc.matched_arch == null) {
            if (nc.sealed_cdhash) |want| {
                if (std.mem.eql(u8, &want, &cd.cdhash)) nc.matched_arch = arch_name;
            }
        }
    }
    // No preference, or a preferred slice that carries no signature: fall back to the first signed one.
    if (nc.actual_cdhash == null) {
        nc.actual_cdhash = first_hash;
        nc.cdhash_arch = first_arch;
    }
    nc.arch_names = try names.toOwnedSlice(arena);
    nc.signed = signed;
}

// ---------------------------------------------------------------------------------------------
// resource verification
// ---------------------------------------------------------------------------------------------

/// Hash every sealed file (sha1 for files, sha256 for files2) and compare; nested code via its own cdhash.
pub fn verifyResources(arena: Allocator, gpa: Allocator, io: Io, b: *const Bundle, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ResourceVerify {
    var mismatched: std.ArrayList([]const u8) = .empty;
    var missing: std.ArrayList([]const u8) = .empty;
    var unsealed: std.ArrayList([]const u8) = .empty;
    var checked: u32 = 0;
    const cr = b.code_resources orelse return .{ .checked = 0, .mismatched = &.{}, .missing = &.{}, .unsealed = &.{}, .ok = false };

    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, b.root, .{}) catch {
        diags.warn(.bundle, .os_error, null, "cannot open bundle directory for verification", .{});
        return .{ .checked = 0, .mismatched = &.{}, .missing = &.{}, .unsealed = &.{}, .ok = false };
    };
    defer dir.close(io);

    for ([_][]const ResourceFile{ cr.files, cr.files2 }) |list| {
        for (list) |f| {
            if (f.hash1 == null and f.hash2 == null and f.symlink == null) continue; // nested code: cdhash path
            const rel = try joinRel(arena, b.contents_rel, f.path);
            if (f.symlink) |target| {
                var lbuf: [1024]u8 = undefined;
                const n = dir.readLink(io, rel, &lbuf) catch {
                    if (!f.optional) try missing.append(arena, f.path);
                    continue;
                };
                checked += 1;
                if (!std.mem.eql(u8, lbuf[0..@min(n, lbuf.len)], target)) try mismatched.append(arena, f.path);
                continue;
            }
            const bytes = dir.readFileAlloc(io, rel, gpa, .limited64(limits.max_file_size)) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    if (!f.optional) try missing.append(arena, f.path);
                    continue;
                },
            };
            defer gpa.free(bytes);
            checked += 1;
            if (f.hash2) |want| {
                var got: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &got, .{});
                if (!std.mem.eql(u8, &want, &got)) {
                    try mismatched.append(arena, f.path);
                    continue;
                }
            }
            if (f.hash1) |want| {
                var got: [20]u8 = undefined;
                std.crypto.hash.Sha1.hash(bytes, &got, .{});
                if (!std.mem.eql(u8, &want, &got)) try mismatched.append(arena, f.path);
            }
        }
    }

    // Nested code sealed by cdhash.
    var nested_unknown: u32 = 0;
    for (try b.nestedAll(arena)) |nc| {
        if (nc.sealed_cdhash == null) continue;
        switch (nc.cdhash_match orelse {
            nested_unknown += 1;
            continue;
        }) {
            true => checked += 1,
            false => {
                checked += 1;
                try mismatched.append(arena, nc.rel_path);
            },
        }
    }
    if (nested_unknown != 0 and !diags.has(.bundle, .not_implemented)) {
        diags.info(.bundle, .not_implemented, null, "{d} nested cdhash seal(s) not checked (code-signature parsing unavailable)", .{nested_unknown});
    }

    // Files under the contents dir that nothing seals.
    for (b.entries) |e| {
        if (e.kind != .file) continue;
        const under = relativeToContents(b, e.path) orelse continue;
        if (isAlwaysExempt(b, under, e.path)) continue;
        if (cr.find(under) != null) continue;
        if (matchesAnyRule(cr.omit_rules, under, diags)) continue;
        if (isInsideNested(b, e.path)) continue;
        try unsealed.append(arena, under);
    }

    const ok = mismatched.items.len == 0 and missing.items.len == 0 and unsealed.items.len == 0;
    return .{
        .checked = checked,
        .mismatched = try mismatched.toOwnedSlice(arena),
        .missing = try missing.toOwnedSlice(arena),
        .unsealed = try unsealed.toOwnedSlice(arena),
        .ok = ok,
    };
}

/// Files the seal never covers: the seal itself, the Info.plist and PkgInfo (CD slots -1/-3), the
/// stapled ticket, .DS_Store and the main executable.
fn isAlwaysExempt(b: *const Bundle, under: []const u8, full: []const u8) bool {
    if (std.mem.startsWith(u8, under, "_CodeSignature/")) return true;
    // The Mac App Store receipt is written after signing and is never part of the seal.
    if (std.mem.startsWith(u8, under, "_MASReceipt/")) return true;
    if (std.mem.eql(u8, under, "Info.plist")) return true;
    if (std.mem.eql(u8, under, "PkgInfo")) return true;
    if (std.mem.eql(u8, under, "CodeResources")) return true;
    if (std.mem.eql(u8, under, "embedded.provisionprofile")) return true;
    if (std.mem.eql(u8, std.fs.path.basename(under), ".DS_Store")) return true;
    if (b.executable_rel) |x| if (std.mem.eql(u8, full, x)) return true;
    return false;
}
/// True when the file belongs to a nested code object (which carries its own seal).
fn isInsideNested(b: *const Bundle, full: []const u8) bool {
    for ([_][]const NestedCode{ b.frameworks, b.helpers, b.xpc_services, b.plugins, b.dylibs }) |list| {
        for (list) |nc| {
            if (std.mem.eql(u8, nc.rel_path, full)) return true;
            if (full.len > nc.rel_path.len and std.mem.startsWith(u8, full, nc.rel_path) and full[nc.rel_path.len] == '/') return true;
        }
    }
    return false;
}
fn matchesAnyRule(rules: []const []const u8, path: []const u8, diags: *Diagnostics) bool {
    for (rules) |r| if (regexSearch(r, path)) |ok| {
        if (ok) return true;
    } else {
        if (!diags.has(.bundle, .unknown_value)) diags.info(.bundle, .unknown_value, null, "CodeResources rule '{s}' uses regex features machre does not evaluate", .{r});
    };
    return false;
}

// ---------------------------------------------------------------------------------------------
// the bounded regex subset used by CodeResources rules
// ---------------------------------------------------------------------------------------------

const Re = struct {
    steps: u32 = 0,
    limit: u32 = 20000,
    unsupported: bool = false,

    fn step(re: *Re) bool {
        re.steps += 1;
        return re.steps <= re.limit;
    }
};
/// Continuation: what to match after the current (sub-)pattern is exhausted.
const Cont = struct { pat: []const u8, pi: usize, next: ?*const Cont };

/// POSIX-ish `re.search` over the subset CodeResources rules use: `^ $ . * + ? \c [set] (a|b)`.
/// Returns null when the pattern uses something outside that subset.
pub fn regexSearch(pat: []const u8, text: []const u8) ?bool {
    if (pat.len == 0 or pat.len > 512) return null;
    var re: Re = .{};
    if (pat[0] == '^') {
        const ok = matchHere(&re, pat, 1, text, 0, null);
        return if (re.unsupported) null else ok;
    }
    var start: usize = 0;
    while (true) : (start += 1) {
        if (matchHere(&re, pat, 0, text, start, null)) return if (re.unsupported) null else true;
        if (re.unsupported) return null;
        if (start >= text.len) return false;
    }
}

fn matchHere(re: *Re, pat: []const u8, pi_in: usize, text: []const u8, ti_in: usize, cont: ?*const Cont) bool {
    var pi = pi_in;
    var ti = ti_in;
    while (true) {
        if (!re.step() or re.unsupported) return false;
        if (pi >= pat.len) {
            if (cont) |c| return matchHere(re, c.pat, c.pi, text, ti, c.next);
            return true;
        }
        if (pat[pi] == '$' and pi + 1 == pat.len) {
            if (ti != text.len) return false;
            pi += 1;
            continue;
        }
        const atom = parseAtom(re, pat, pi) orelse {
            re.unsupported = true;
            return false;
        };
        const quant: u8 = if (atom.next < pat.len and (pat[atom.next] == '*' or pat[atom.next] == '+' or pat[atom.next] == '?')) pat[atom.next] else 0;
        const after = if (quant == 0) atom.next else atom.next + 1;
        if (atom.group) |body| {
            var c: Cont = .{ .pat = pat, .pi = after, .next = cont };
            if (quant == '?' and matchHere(re, pat, after, text, ti, cont)) return true;
            if (quant == '*' or quant == '+') {
                re.unsupported = true; // no repeated groups in any Apple rule set
                return false;
            }
            var it = AltIterator{ .body = body };
            while (it.next()) |alt| {
                if (matchHere(re, alt, 0, text, ti, &c)) return true;
            }
            return false;
        }
        switch (quant) {
            0 => {
                if (ti >= text.len or !atomMatches(atom, text[ti])) return false;
                pi = after;
                ti += 1;
            },
            '?' => {
                if (matchHere(re, pat, after, text, ti, cont)) return true;
                if (ti >= text.len or !atomMatches(atom, text[ti])) return false;
                pi = after;
                ti += 1;
            },
            '+' => {
                if (ti >= text.len or !atomMatches(atom, text[ti])) return false;
                var k = ti + 1;
                while (true) {
                    if (!re.step()) return false;
                    if (matchHere(re, pat, after, text, k, cont)) return true;
                    if (k >= text.len or !atomMatches(atom, text[k])) return false;
                    k += 1;
                }
            },
            '*' => {
                var k = ti;
                while (true) {
                    if (!re.step()) return false;
                    if (matchHere(re, pat, after, text, k, cont)) return true;
                    if (k >= text.len or !atomMatches(atom, text[k])) return false;
                    k += 1;
                }
            },
            else => unreachable,
        }
    }
}

const Atom = struct {
    /// Literal byte, or 0 when `any`/`class`/`group` applies.
    lit: u8 = 0,
    any: bool = false,
    class: ?[]const u8 = null, // the text between [ and ]
    group: ?[]const u8 = null, // the text between ( and )
    next: usize,
};

fn parseAtom(re: *Re, pat: []const u8, pi: usize) ?Atom {
    const c = pat[pi];
    switch (c) {
        '\\' => {
            if (pi + 1 >= pat.len) return null;
            return .{ .lit = pat[pi + 1], .next = pi + 2 };
        },
        '.' => return .{ .any = true, .next = pi + 1 },
        '[' => {
            const end = std.mem.findScalarPos(u8, pat, pi + 1, ']') orelse return null;
            return .{ .class = pat[pi + 1 .. end], .next = end + 1 };
        },
        '(' => {
            var depth: u32 = 1;
            var i = pi + 1;
            while (i < pat.len) : (i += 1) {
                if (!re.step()) return null;
                if (pat[i] == '\\') {
                    i += 1;
                    continue;
                }
                if (pat[i] == '(') depth += 1;
                if (pat[i] == ')') {
                    depth -= 1;
                    if (depth == 0) return .{ .group = pat[pi + 1 .. i], .next = i + 1 };
                }
            }
            return null;
        },
        ')', '|' => return null,
        else => return .{ .lit = c, .next = pi + 1 },
    }
}
fn atomMatches(a: Atom, b: u8) bool {
    if (a.any) return true;
    if (a.class) |set| return classMatches(set, b);
    return a.lit == b;
}
fn classMatches(set_in: []const u8, b: u8) bool {
    var set = set_in;
    var negate = false;
    if (set.len != 0 and set[0] == '^') {
        negate = true;
        set = set[1..];
    }
    var i: usize = 0;
    var hit = false;
    while (i < set.len) {
        if (i + 2 < set.len and set[i + 1] == '-') {
            if (b >= set[i] and b <= set[i + 2]) hit = true;
            i += 3;
            continue;
        }
        if (set[i] == b) hit = true;
        i += 1;
    }
    return hit != negate;
}
/// Splits a group body at top-level `|`.
const AltIterator = struct {
    body: []const u8,
    pos: usize = 0,
    done: bool = false,
    fn next(it: *AltIterator) ?[]const u8 {
        if (it.done) return null;
        var depth: u32 = 0;
        var i = it.pos;
        while (i < it.body.len) : (i += 1) {
            if (it.body[i] == '\\') {
                i += 1;
                continue;
            }
            if (it.body[i] == '(') depth += 1;
            if (it.body[i] == ')' and depth != 0) depth -= 1;
            if (it.body[i] == '|' and depth == 0) {
                const alt = it.body[it.pos..i];
                it.pos = i + 1;
                return alt;
            }
        }
        it.done = true;
        return it.body[it.pos..];
    }
};

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

test "bundle: the CodeResources regex subset matches Apple's default rules" {
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^Info\\.plist$", "Info.plist"));
    try std.testing.expectEqual(@as(?bool, false), regexSearch("^Info\\.plist$", "Resources/Info.plist"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^PkgInfo$", "PkgInfo"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^(.*/)?\\.DS_Store$", ".DS_Store"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^(.*/)?\\.DS_Store$", "Resources/a/.DS_Store"));
    try std.testing.expectEqual(@as(?bool, false), regexSearch("^(.*/)?\\.DS_Store$", "Resources/DS_Store"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch(".*\\.dSYM($|/)", "x.dSYM"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch(".*\\.dSYM($|/)", "x.dSYM/Contents"));
    try std.testing.expectEqual(@as(?bool, false), regexSearch(".*\\.dSYM($|/)", "x.dSYMx"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^[^/]+$", "libhello.dylib"));
    try std.testing.expectEqual(@as(?bool, false), regexSearch("^[^/]+$", "a/b"));
    const nested = "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/";
    try std.testing.expectEqual(@as(?bool, true), regexSearch(nested, "Frameworks/libhello.dylib"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch(nested, "Library/LoginItems/x.app"));
    try std.testing.expectEqual(@as(?bool, false), regexSearch(nested, "Resources/x"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^Resources/.*\\.lproj/", "Resources/en.lproj/x"));
    try std.testing.expectEqual(@as(?bool, true), regexSearch("^.*", "anything"));
    // Pathological patterns terminate (budget) rather than hanging.
    _ = regexSearch("^(a|b", "aaaa");
    _ = regexSearch(".*.*.*.*.*.*x", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

test "bundle: parseCodeResources on a hand-built v2 seal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    const xml_text =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0"><dict>
        \\<key>files</key><dict/>
        \\<key>files2</key><dict>
        \\  <key>Frameworks/libhello.dylib</key><dict>
        \\    <key>cdhash</key><data>QbheIDu4wiSvu1zAK7Sl0oBJt1Q=</data>
        \\    <key>requirement</key><string>cdhash H"41b85e203bb8c224afbb5cc02bb4a5d28049b754"</string>
        \\  </dict>
        \\  <key>Resources/app.txt</key><dict>
        \\    <key>hash2</key><data>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</data>
        \\  </dict>
        \\</dict>
        \\<key>rules</key><dict><key>^Resources/</key><true/></dict>
        \\<key>rules2</key><dict>
        \\  <key>^Info\.plist$</key><dict><key>omit</key><true/><key>weight</key><real>20</real></dict>
        \\  <key>^.*</key><true/>
        \\</dict>
        \\</dict></plist>
    ;
    const cr = (try parseCodeResources(arena, xml_text, &Limits.default, &diags)).?;
    try std.testing.expectEqual(@as(u32, 2), cr.version);
    try std.testing.expectEqual(@as(u32, 1), cr.rules);
    try std.testing.expectEqual(@as(u32, 2), cr.rules2);
    try std.testing.expectEqual(@as(usize, 0), cr.files.len);
    try std.testing.expectEqual(@as(usize, 2), cr.files2.len);
    const nested = cr.find("Frameworks/libhello.dylib").?;
    try std.testing.expect(nested.nested);
    try std.testing.expectEqualStrings(
        "41b85e203bb8c224afbb5cc02bb4a5d28049b754",
        try std.fmt.allocPrint(arena, "{x}", .{&nested.cdhash.?}),
    );
    const res = cr.find("Resources/app.txt").?;
    try std.testing.expect(res.hash2 != null and res.hash1 == null);
    try std.testing.expectEqual(@as(usize, 1), cr.omit_rules.len);
    try std.testing.expectEqualStrings("^Info\\.plist$", cr.omit_rules[0]);
}

test "bundle: parseCodeResources survives garbage" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 16);
    try std.testing.expect(try parseCodeResources(arena, "\x00\x01\x02", &Limits.paranoid, &diags) == null);
    try std.testing.expect(try parseCodeResources(arena, "<plist><array/></plist>", &Limits.paranoid, &diags) == null);
    const cr = (try parseCodeResources(arena, "<plist><dict><key>files2</key><string>x</string></dict></plist>", &Limits.paranoid, &diags)).?;
    try std.testing.expectEqual(@as(usize, 0), cr.files2.len);
    try std.testing.expect(diags.has(.bundle, .plist_malformed));
}

test "bundle: detect and mainExecutable on the corpus Hello.app" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diags = Diagnostics.init(arena, 32);
    // src/bundle/bundle.zig -> ../../tests/corpus/Hello.app
    const root = "tests/corpus/Hello.app";
    Io.Dir.cwd().access(io, root, .{}) catch return error.SkipZigTest;
    try std.testing.expectEqual(@as(?Kind, .app), detect(io, root));
    const exe = (try mainExecutable(arena, io, root, &Limits.default, &diags)).?;
    try std.testing.expectEqualStrings("tests/corpus/Hello.app/Contents/MacOS/Hello", exe);
    try std.testing.expect(detect(io, "tests/corpus") == null);
}
