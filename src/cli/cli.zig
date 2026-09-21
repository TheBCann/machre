//! cli/cli.zig — dispatch + framing only: global flags, exit-code policy, file loading, arch selection,
//! envelope begin/end, usage text. Imports: cli/args, cli/context, output/*, core/*, analysis/analysis, cmd/*.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const args_mod = @import("args.zig");
const context = @import("context.zig");
pub const Context = context.Context;
pub const Command = context.Command;
pub const ExitCode = context.ExitCode;
const Image = @import("../core/image.zig").Image;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const fat = @import("../core/fat.zig");
const sanitize = @import("../core/sanitize.zig");
const arch_mod = @import("../core/arch.zig");
const limits_mod = @import("../core/limits.zig");
const Limits = limits_mod.Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sink_mod = @import("../output/sink.zig");
const Sink = sink_mod.Sink;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Analysis = @import("../analysis/analysis.zig").Analysis;
const bundle_mod = @import("../bundle/bundle.zig");
const xattr_mod = @import("../darwin/xattr.zig");

const cmd = struct {
    const info = @import("../cmd/info.zig");
    const header = @import("../cmd/header.zig");
    const loadcmds = @import("../cmd/loadcmds.zig");
    const segments = @import("../cmd/segments.zig");
    const symbols = @import("../cmd/symbols.zig");
    const dyld = @import("../cmd/dyld.zig");
    const imports = @import("../cmd/imports.zig");
    const exports = @import("../cmd/exports.zig");
    const codesign = @import("../cmd/codesign.zig");
    const entitlements = @import("../cmd/entitlements.zig");
    const objc = @import("../cmd/objc.zig");
    const strings = @import("../cmd/strings.zig");
    const entropy = @import("../cmd/entropy.zig");
    const plist = @import("../cmd/plist.zig");
    const bundle = @import("../cmd/bundle.zig");
    const quarantine = @import("../cmd/quarantine.zig");
    const disasm = @import("../cmd/disasm.zig");
    const functions = @import("../cmd/functions.zig");
    const xrefs = @import("../cmd/xrefs.zig");
    const triage = @import("../cmd/triage.zig");
    const dump = @import("../cmd/dump.zig");
    const report = @import("../cmd/report.zig");
    const version = @import("../cmd/version.zig");
};

pub const commands: []const Command = &.{
    cmd.info.command,     cmd.header.command,       cmd.loadcmds.command, cmd.segments.command,
    cmd.symbols.command,  cmd.dyld.command,         cmd.imports.command,  cmd.exports.command,
    cmd.codesign.command, cmd.entitlements.command, cmd.objc.command,     cmd.strings.command,
    cmd.entropy.command,  cmd.plist.command,        cmd.bundle.command,   cmd.quarantine.command,
    cmd.disasm.command,   cmd.functions.command,    cmd.xrefs.command,    cmd.triage.command,
    cmd.dump.command,     cmd.report.command,       cmd.version.command,
};
pub const global_flags: []const []const u8 = &.{
    "--json",     "--arch=",          "--all-archs", "--verbose",      "--limit=", "--no-security",  "--no-network",       "--strict",
    "--paranoid", "--max-file-size=", "--color=",    "--otool-compat", "--quiet",  "--json-compact", "--max-arena-bytes=", "--help",
};

/// Entry point: parses global flags, builds Context, dispatches, maps errors to exit codes (DESIGN.md §5).
pub fn run(init: std.process.Init) u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const argv = init.minimal.args.toSlice(arena) catch return @intFromEnum(ExitCode.internal);
    var out_buf: [64 * 1024]u8 = undefined;
    var out_fw: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    var err_buf: [4096]u8 = undefined;
    var err_fw: Io.File.Writer = .initStreaming(.stderr(), io, &err_buf);
    const rest: []const [:0]const u8 = if (argv.len > 0) argv[1..] else argv;
    const code = runArgv(init.gpa, io, rest, &out_fw.interface, &err_fw.interface);
    out_fw.interface.flush() catch {};
    err_fw.interface.flush() catch {};
    return code;
}

/// In-process runner used by tests: argv excludes argv[0]; output goes to `out`; returns the exit code.
pub fn runArgv(gpa: Allocator, io: Io, argv: []const [:0]const u8, out: *Io.Writer, err: *Io.Writer) u8 {
    return runInner(gpa, io, argv, out, err) catch |e| {
        err.print("machre: internal error: {t}\n", .{e}) catch {};
        return @intFromEnum(ExitCode.internal);
    };
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub fn findCommand(name: []const u8) ?*const Command {
    for (commands) |*c| {
        if (eql(c.name, name)) return c;
        for (c.aliases) |al| if (eql(al, name)) return c;
    }
    return null;
}

fn usageError(err: *Io.Writer, command: ?*const Command, comptime fmt: []const u8, a: anytype) Io.Writer.Error!u8 {
    try err.print("machre: " ++ fmt ++ "\n", a);
    try usage(err, command);
    return @intFromEnum(ExitCode.usage);
}

fn runInner(gpa: Allocator, io: Io, argv: []const [:0]const u8, out: *Io.Writer, err: *Io.Writer) !u8 {
    if (argv.len == 0) return usageError(err, null, "no command given", .{});
    const first = argv[0];
    if (eql(first, "help") or eql(first, "--help") or eql(first, "-h")) {
        const c = if (argv.len > 1) findCommand(argv[1]) else null;
        try usage(out, c);
        return 0;
    }
    const command = findCommand(if (eql(first, "--version") or eql(first, "-V")) "version" else first) orelse
        return usageError(err, null, "unknown command '{s}'", .{first});

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const raw_arena = arena_state.allocator();

    const known = try std.mem.concat(raw_arena, []const u8, &.{ global_flags, command.flags });
    const parsed = try args_mod.parse(raw_arena, argv[1..], known);
    if (parsed.flag("--help")) {
        try usage(out, command);
        return 0;
    }
    if (parsed.unknown(known)) |u| return usageError(err, command, "{s}: unknown flag '{s}'", .{ command.name, u });
    const needs_path = !eql(command.name, "version");
    if (parsed.positionals.len > 1) return usageError(err, command, "{s}: expected one path, got {d}", .{ command.name, parsed.positionals.len });
    if (needs_path and parsed.positionals.len == 0) return usageError(err, command, "{s}: missing <path>", .{command.name});
    const path: [:0]const u8 = if (parsed.positionals.len > 0) parsed.positionals[0] else "";

    var limits: Limits = if (parsed.flag("--paranoid")) Limits.paranoid else Limits.default;
    if (parsed.valueInt(u64, "--max-file-size") catch return usageError(err, command, "--max-file-size: invalid value", .{})) |v| limits.max_file_size = v;
    if (parsed.valueInt(u64, "--max-arena-bytes") catch return usageError(err, command, "--max-arena-bytes: invalid value", .{})) |v| limits.max_arena_bytes = v;
    const limit_rows = parsed.valueInt(u32, "--limit") catch return usageError(err, command, "--limit: invalid value", .{});
    const json_mode = parsed.flag("--json") or parsed.flag("--json-compact");
    var arch: ?arch_mod.ArchName = null;
    if (parsed.value("--arch")) |s| {
        arch = arch_mod.ArchName.parse(s) orelse return usageError(err, command, "--arch: unknown architecture '{s}'", .{s});
    }
    var color = false;
    if (parsed.value("--color")) |c| {
        if (eql(c, "always")) {
            color = true;
        } else if (eql(c, "never")) {
            color = false;
        } else if (eql(c, "auto")) {
            color = Io.File.stdout().isTty(io) catch false;
        } else return usageError(err, command, "--color: expected auto|always|never", .{});
    }

    var budget = limits_mod.BudgetAllocator.init(raw_arena, limits.max_arena_bytes);
    const arena = budget.allocator();
    var diags = Diagnostics.init(arena, limits.max_diagnostics);
    const opts: sink_mod.Options = .{
        .verbose = parsed.count("--verbose"),
        .color = color,
        .limit = limit_rows orelse (if (json_mode) 0 else 500),
        .pretty_json = !parsed.flag("--json-compact"),
        .otool_compat = parsed.flag("--otool-compat"),
        .quiet = parsed.flag("--quiet"),
    };
    var snk = Sink.init(if (json_mode) .json else .text, out, opts, arena);
    var ctx: Context = .{
        .io = io,
        .gpa = gpa,
        .arena = arena,
        .limits = &limits,
        .diags = &diags,
        .sink = &snk,
        .args = &parsed,
        .command = command.name,
        .path = path,
        .display_path = try sanitize.forText(arena, path, null),
        .arch = arch,
        .all_archs = parsed.flag("--all-archs") or (json_mode and arch == null),
        .no_security = parsed.flag("--no-security") or !build_options.have_security,
        .no_network = parsed.flag("--no-network"),
        .verbose = parsed.count("--verbose"),
        .strict = parsed.flag("--strict"),
        .paranoid = parsed.flag("--paranoid"),
        .otool_compat = parsed.flag("--otool-compat"),
    };
    const code = dispatch(&ctx, command, &budget, err) catch |e| switch (e) {
        error.WriteFailed => return @intFromEnum(ExitCode.io),
        else => return e,
    };
    try snk.flush();
    return code;
}

/// Loads the file, selects arches, frames the envelope, runs the command and maps exit codes.
fn dispatch(ctx: *Context, command: *const Command, budget: *limits_mod.BudgetAllocator, err: *Io.Writer) !u8 {
    const out = ctx.sink.out;
    const js = &ctx.sink.json;
    var file_storage: LoadedFile = undefined;
    var have_file = false;
    defer if (have_file) file_storage.deinit(ctx.gpa);

    json.resetLossyCount(); // per-run tally; `runArgv` may be called many times in one process
    const needs_path = !eql(command.name, "version");
    var runnable = true;
    if (needs_path) {
        file_storage = LoadedFile.load(ctx.gpa, ctx.arena, ctx.io, ctx.path, ctx.limits, ctx.diags) catch |e| blk: {
            try noteLoadError(ctx, e);
            runnable = false;
            break :blk try LoadedFile.fromBytes(ctx.arena, ctx.path, &.{}, ctx.limits, ctx.diags);
        };
        have_file = true;
        ctx.file = &file_storage;
        if (runnable) {
            const imgs = loadImages(ctx) catch |e| switch (e) {
                error.OutOfMemory => blk: {
                    ctx.diags.err(.cli, .limit_reached, null, "out of memory while loading: arena budget {d} bytes (peak {d})", .{ ctx.limits.max_arena_bytes, budget.peak });
                    try err.print("machre {s}: OutOfMemory (arena budget {d} bytes)\n", .{ command.name, ctx.limits.max_arena_bytes });
                    ctx.exit_code = .internal;
                    break :blk null;
                },
                else => return e,
            };
            if (imgs) |list| {
                ctx.images = list;
            } else runnable = false;
        }
    }
    if (ctx.sink.isJson()) {
        // file.xattrs / file.quarantine / file.translocated are file properties (DESIGN.md §6.1).
        var xattr_value: std.json.Value = .null;
        var have_xattrs = false;
        if (have_file) {
            const xa = try xattr_mod.read(ctx.arena, file_storage.path_z, ctx.diags);
            xattr_value = try xattr_mod.envelopeJson(ctx.arena, xa);
            have_xattrs = true;
        }
        try json.envelopeBegin(js, ctx.arena, command.name, if (have_file) &file_storage else &empty_file, if (have_xattrs) &xattr_value else null);
    }
    var code: u8 = @intFromEnum(ctx.exit_code);
    if (runnable) {
        code = command.run(ctx) catch |e| blk: {
            switch (e) {
                error.OutOfMemory => ctx.diags.err(.cli, .limit_reached, null, "out of memory: arena budget {d} bytes (peak {d}, {d} refused allocations)", .{ ctx.limits.max_arena_bytes, budget.peak, budget.failures }),
                error.WriteFailed => return e,
                else => ctx.diags.err(.cli, .os_error, null, "internal error in command {s}: {t}", .{ command.name, e }),
            }
            try err.print("machre {s}: {t}\n", .{ command.name, e });
            break :blk @intFromEnum(ExitCode.internal);
        };
        if (code == 0 and ctx.exit_code != .ok) code = @intFromEnum(ctx.exit_code);
    }
    if (code == 0 and ctx.strict and ctx.diags.hasErrors()) code = @intFromEnum(ExitCode.strict_diagnostics);
    const lossy = ctx.sink.lossy +| json.lossyCount();
    if (lossy != 0) ctx.diags.warn(.cli, .invalid_utf8, null, "{d} file-derived string(s) contained control characters or invalid UTF-8 and were escaped for output", .{lossy});
    if (ctx.sink.isJson()) {
        try json.envelopeEnd(js, ctx.diags, code, lossy);
        try out.writeByte('\n');
    } else if (needs_path and !ctx.sink.opts.quiet and !ctx.otool_compat) {
        try text.diagnostics(out, ctx.diags, ctx.verbose > 0, lossy);
    }
    if (!ctx.sink.isJson() and code != 0 and code != @intFromEnum(ExitCode.strict_diagnostics)) {
        for (ctx.diags.items()) |d| if (d.severity == .@"error" and (d.module == .file or d.module == .cli or d.module == .fat or d.module == .header)) {
            try err.print("machre: {s}: {s}\n", .{ ctx.display_path, d.message });
            break;
        };
    }
    return code;
}

var empty_file: LoadedFile = .{ .path = "", .path_z = "", .bytes = &.{}, .size = 0, .mtime_unix = 0, .is_dir = false, .container = .not_macho };

/// Shared prologue: load the file (bundle -> its main executable), select arches, parse one Image per arch.
/// Returns null after emitting the not-Mach-O envelope/exit code when the command needs an image.
/// Records a `LoadedFile.LoadError` as a diagnostic and picks the matching exit code. Shared by the
/// top-level load and by the bundle's main-executable load in `loadImages`, which used to let these
/// escape: a bundle whose executable was too large or unreadable exited 70 "internal error" and
/// emitted no JSON envelope at all, while the identical thin-file case exited 5 with one.
fn noteLoadError(ctx: *Context, e: LoadedFile.LoadError) error{OutOfMemory}!void {
    switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooLarge => {
            ctx.diags.err(.file, .limit_reached, null, "file exceeds --max-file-size {d} bytes", .{ctx.limits.max_file_size});
            ctx.exit_code = .limits;
        },
        error.FileNotFound => {
            ctx.diags.err(.file, .os_error, null, "file not found", .{});
            ctx.exit_code = .io;
        },
        error.AccessDenied => {
            ctx.diags.err(.file, .os_error, null, "permission denied", .{});
            ctx.exit_code = .io;
        },
        error.Unexpected => {
            ctx.diags.err(.file, .os_error, null, "unexpected I/O error", .{});
            ctx.exit_code = .io;
        },
    }
}

pub fn loadImages(ctx: *Context) anyerror!?[]const Image {
    const file = ctx.file orelse return null;
    const needs = findCommand(ctx.command).?.needs_macho;
    if (file.is_dir) {
        const dir_path = file.path; // arena-owned; survives the swap below
        const exe = try bundle_mod.mainExecutable(ctx.arena, ctx.io, file.path, ctx.limits, ctx.diags);
        if (exe) |p| {
            // Analyse the bundle's main executable in place of the directory, but remember that the
            // command was handed a bundle (ctx.path alone cannot say so once `file` is replaced).
            var inner = LoadedFile.load(ctx.gpa, ctx.arena, ctx.io, p, ctx.limits, ctx.diags) catch |e| {
                try noteLoadError(ctx, e);
                return null;
            };
            ctx.bundle_path = dir_path;
            file.deinit(ctx.gpa);
            file.* = inner;
            inner = undefined;
        } else {
            if (needs) {
                ctx.diags.err(.file, .not_available, null, "directory is not an analysable bundle (or bundle support is not implemented)", .{});
                ctx.exit_code = .not_macho;
                return null;
            }
            return &.{};
        }
    }
    if (file.container == .not_macho) {
        if (needs) {
            ctx.diags.err(.file, .bad_magic, 0, "not a Mach-O or fat file ({d} bytes)", .{file.size});
            ctx.exit_code = .not_macho;
            return null;
        }
        return &.{};
    }
    const sel = fat.selectArches(ctx.arena, file.container, ctx.arch, ctx.all_archs, arch_mod.Arch.host()) catch |e| switch (e) {
        error.ArchNotFound => {
            ctx.diags.err(.fat, .not_available, null, "requested architecture {s} not present", .{@tagName(ctx.arch.?)});
            ctx.exit_code = .not_macho;
            return if (needs) null else &.{};
        },
        error.NoValidArch => {
            ctx.diags.err(.fat, .not_available, null, "fat file has no valid architecture slice", .{});
            ctx.exit_code = .not_macho;
            return if (needs) null else &.{};
        },
        error.OutOfMemory => return e,
    };
    var list: std.ArrayList(Image) = .empty;
    for (sel.indices) |idx| {
        const r = file.sliceReader(idx) orelse continue;
        const off = file.sliceOffset(idx) orelse continue;
        const img = Image.parse(ctx.arena, r, off, idx, ctx.limits, ctx.diags) catch |e| switch (e) {
            error.NotMachO => {
                ctx.diags.err(.header, .bad_magic, off, "slice {d} is not a Mach-O image", .{idx});
                continue;
            },
            error.Truncated => {
                ctx.diags.err(.header, .truncated, off, "slice {d}: Mach-O header truncated", .{idx});
                continue;
            },
            error.OutOfMemory => return e,
        };
        try list.append(ctx.arena, img);
    }
    if (list.items.len == 0) {
        if (needs) {
            ctx.exit_code = .not_macho;
            return null;
        }
        return &.{};
    }
    if (!ctx.sink.isJson() and !ctx.otool_compat and (sel.reason == .host or sel.reason == .first) and file.container.sliceCount() > 1) {
        var buf: [32]u8 = undefined;
        try ctx.sink.out.print("{d} architectures, showing {s} (use --all-archs)\n", .{ file.container.sliceCount(), list.items[0].arch.displayName(&buf) });
    }
    return try list.toOwnedSlice(ctx.arena);
}

/// One Analysis per image, sharing ctx.arena/limits/diags and the ctx options.
pub fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis {
    return Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
        .security = !ctx.no_security,
        .network = !ctx.no_network,
        .engine = .{ .otool_compat = ctx.otool_compat },
    });
}
/// Text: prints the arch banner when multiple slices are shown; JSON: json.beginArch.
pub fn beginArch(ctx: *Context, img: *const Image, multi: bool) anyerror!void {
    if (ctx.sink.isJson()) return json.beginArch(&ctx.sink.json, img);
    var buf: [32]u8 = undefined;
    if (multi) try text.archBanner(ctx.sink.out, ctx.display_path, img.arch.displayName(&buf), true);
}
pub fn endArch(ctx: *Context) anyerror!void {
    if (ctx.sink.isJson()) return json.endArch(&ctx.sink.json);
}

pub fn usage(out: *Io.Writer, command: ?*const Command) Io.Writer.Error!void {
    if (command) |c| {
        try out.print("usage: machre {s} [global flags] [command flags] <path>\n\n  {s}\n\n", .{ c.name, c.summary });
        if (c.aliases.len > 0) {
            try out.writeAll("aliases:");
            for (c.aliases) |al| try out.print(" {s}", .{al});
            try out.writeAll("\n\n");
        }
        if (c.flags.len > 0) {
            try out.writeAll("command flags:\n");
            for (c.flags) |f| try out.print("  {s}{s}\n", .{ f, if (f[f.len - 1] == '=') "<value>" else "" });
            try out.writeAll("\n");
        }
    } else {
        try out.print("machre {s} - Mach-O reverse-engineering and triage tool\n\nusage: machre <command> [global flags] [command flags] <path>\n       machre help [command]\n\ncommands:\n", .{version_string});
        for (commands) |c| {
            try out.print("  {s:<13}{s}\n", .{ c.name, c.summary });
        }
        try out.writeAll("\n");
    }
    try out.writeAll(
        \\global flags:
        \\  --json                JSON envelope on stdout (--json-compact: minified)
        \\  --arch <name>         analyse only this slice (x86_64 x86_64h i386 arm64 arm64v8 arm64e arm64_32 ...)
        \\  --all-archs           analyse every valid slice (default for --json)
        \\  -v, --verbose         more rows/columns; every diagnostic (repeatable)
        \\  -q, --quiet           suppress the diagnostics footer
        \\  --limit <n>           cap rows in long tables (0 = unlimited; default 500 for text, 0 for JSON)
        \\  --no-security         never call Security.framework
        \\  --no-network          no revocation network access
        \\  --strict              exit 4 when an error-severity diagnostic was recorded
        \\  --paranoid            tiny parser limits (fuzzing, hostile input)
        \\  --max-file-size <n>   input size cap in bytes (default 2 GiB)
        \\  --max-arena-bytes <n> analysis memory budget in bytes (default 2 GiB)
        \\  --otool-compat        text output byte-compatible with the Apple tool each command mirrors
        \\  --color=auto|always|never
        \\
        \\exit codes: 0 ok, 1 usage, 2 io, 3 not Mach-O, 4 --strict diagnostics, 5 limits, 6 feature unavailable, 20 triage threshold, 70 internal
        \\
    );
}
pub const version_string: []const u8 = build_options.version;

test "cli: command lookup and flag tables" {
    try std.testing.expect(findCommand("info") != null);
    try std.testing.expect(findCommand("nm") != null and findCommand("headers") != null and findCommand("all") != null);
    try std.testing.expect(findCommand("nope") == null);
    try std.testing.expectEqual(@as(usize, 23), commands.len);
    for (commands) |c| for (c.flags) |f| try std.testing.expect(std.mem.startsWith(u8, f, "--"));
}

test "cli: runArgv usage, version and unknown command" {
    const gpa = std.testing.allocator;
    var outw: Io.Writer.Allocating = .init(gpa);
    defer outw.deinit();
    var errw: Io.Writer.Allocating = .init(gpa);
    defer errw.deinit();
    try std.testing.expectEqual(@as(u8, 1), runArgv(gpa, std.testing.io, &.{}, &outw.writer, &errw.writer));
    try std.testing.expectEqual(@as(u8, 1), runArgv(gpa, std.testing.io, &.{"bogus"}, &outw.writer, &errw.writer));
    try std.testing.expectEqual(@as(u8, 1), runArgv(gpa, std.testing.io, &.{ "info", "--nope", "x" }, &outw.writer, &errw.writer));
    try std.testing.expectEqual(@as(u8, 0), runArgv(gpa, std.testing.io, &.{"help"}, &outw.writer, &errw.writer));
    outw.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), runArgv(gpa, std.testing.io, &.{"version"}, &outw.writer, &errw.writer));
    try std.testing.expect(std.mem.find(u8, outw.written(), "machre") != null);
    outw.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 2), runArgv(gpa, std.testing.io, &.{ "info", "--json", "/nonexistent/x" }, &outw.writer, &errw.writer));
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, outw.written(), .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 2), parsed.value.object.get("exit_code").?.integer);
}
