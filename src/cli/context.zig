//! cli/context.zig — leaf types shared by cli.zig and every cmd/*.zig (breaks the cmd <-> cli import cycle).
//! Imports: core/limits, core/diag, core/file, core/image, core/arch, output/sink, cli/args.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const ArchName = @import("../core/arch.zig").ArchName;
const Sink = @import("../output/sink.zig").Sink;
const Parsed = @import("args.zig").Parsed;

pub const ExitCode = enum(u8) {
    ok = 0,
    usage = 1,
    io = 2,
    not_macho = 3,
    strict_diagnostics = 4,
    limits = 5,
    feature_unavailable = 6,
    triage_threshold = 20,
    internal = 70,
};

pub const Context = struct {
    io: Io,
    gpa: Allocator,
    arena: Allocator, // per-analysis budgeted arena
    limits: *const Limits,
    diags: *Diagnostics,
    sink: *Sink,
    args: *const Parsed,
    command: []const u8,
    /// The path as given on the command line. Use this to OPEN things; never write it to output —
    /// argv is attacker-influenced whenever a filename comes out of an archive, a download, or a
    /// sample set, and a raw `\x1b` here reaches the terminal exactly as one from inside the file
    /// would (DESIGN §5.6).
    path: [:0]const u8,
    /// `path` made inert for display: control characters and invalid UTF-8 escaped. Sanitising is
    /// a no-op on ordinary paths (the sanitiser returns its input unchanged when clean), so this
    /// aliases `path` in the common case and costs nothing. Every renderer prints THIS.
    display_path: []const u8,
    arch: ?ArchName,
    all_archs: bool,
    no_security: bool,
    no_network: bool,
    verbose: u8,
    strict: bool,
    paranoid: bool,
    otool_compat: bool,
    /// Set by `cli.loadImages` when `path` was a bundle directory and `file` was replaced by the
    /// bundle's main executable; `cmd/codesign.zig` needs it to render codesign's bundle-shaped
    /// `Format=`/`Info.plist entries=`/`Sealed Resources version=` lines.
    bundle_path: ?[]const u8 = null,
    /// Loaded lazily by `cli.loadFile`; commands that only need xattrs/plist never parse images.
    file: ?*LoadedFile = null,
    images: []const Image = &.{},
    /// Set by commands; echoed as "exit_code" in the JSON envelope.
    exit_code: ExitCode = .ok,
};

pub const Command = struct {
    name: []const u8,
    summary: []const u8,
    run: *const fn (ctx: *Context) anyerror!u8,
    /// Command-specific flags (global flags are appended by cli.zig); value-taking flags end with "=".
    flags: []const []const u8,
    aliases: []const []const u8 = &.{},
    /// Needs a Mach-O image (exit 3 otherwise) — false for plist/bundle/quarantine/version.
    needs_macho: bool = true,
};
