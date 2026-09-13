//! cmd/triage.zig — scored anomaly report + verdict (Wardle rules; never a single tell). Owned by WP9 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, analysis/triage, bundle/bundle.
//!
//! One `triage.Report` per selected slice; a fat file also gets the merged report (max level, union of
//! findings) as the top-level `triage` payload. `--fail-on=<level>` turns the verdict into exit code 20.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const Analysis = @import("../analysis/analysis.zig").Analysis;
const triage = @import("../analysis/triage.zig");
const bundle_mod = @import("../bundle/bundle.zig");

pub const command: Command = .{
    .name = "triage",
    .summary = "scored anomaly report + verdict (Wardle rules; never a single tell)",
    .run = run,
    .flags = &.{ "--fail-on=", "--explain", "--spctl" },
    .aliases = &.{},
    .needs_macho = true,
};

pub const Spctl = struct {
    available: bool,
    reason: ?[]const u8 = null,
    exit: u8 = 0,
    assessment: ?[]const u8 = null,
    source: ?[]const u8 = null,
    origin: ?[]const u8 = null,
};

/// `--fail-on=notable|suspicious|likely_malicious`; null when the flag is absent.
pub fn parseFailOn(s: ?[]const u8) error{InvalidValue}!?triage.Level {
    const v = s orelse return null;
    return std.meta.stringToEnum(triage.Level, v) orelse error.InvalidValue;
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const fail_on = parseFailOn(ctx.args.value("--fail-on")) catch {
        ctx.diags.err(.cli, .unknown_value, null, "--fail-on: expected notable|suspicious|likely_malicious", .{});
        return @intFromEnum(context.ExitCode.usage);
    };
    const opts: triage.Options = .{ .fail_on = fail_on, .explain = ctx.args.flag("--explain") };

    // A bundle path (or a file inside one) is triaged as the bundle it belongs to: cli.loadImages has
    // already swapped the directory for its main executable, so `ctx.path` is the only way back.
    const root = if (bundle_mod.detect(ctx.io, ctx.path) != null)
        ctx.path
    else
        try bundle_mod.enclosingBundle(ctx.arena, ctx.io, ctx.path, ctx.limits);
    const bun: ?*const bundle_mod.Bundle = if (root) |r| blk: {
        const b = try bundle_mod.analyze(ctx.arena, ctx.gpa, ctx.io, r, .{}, ctx.limits, ctx.diags);
        if (b == null) break :blk null;
        const p = try ctx.arena.create(bundle_mod.Bundle);
        p.* = b.?;
        break :blk p;
    } else null;

    var reports: std.ArrayList(triage.Report) = .empty;
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
            .security = !ctx.no_security,
            .network = !ctx.no_network,
        });
        defer an.deinit();
        try reports.append(ctx.arena, try triage.run(ctx.arena, &an, bun, opts, ctx.limits, ctx.diags));
    }
    if (reports.items.len == 0) {
        if (ctx.sink.isJson()) {
            try json.endArches(&ctx.sink.json);
            try json.unavailable(&ctx.sink.json, "triage", "no analysable Mach-O slice");
        } else {
            try ctx.sink.out.print("machre triage: {s}: no analysable Mach-O slice\n", .{ctx.display_path});
        }
        return @intFromEnum(context.ExitCode.not_macho);
    }
    const merged = try triage.merge(ctx.arena, reports.items);
    const spctl: ?Spctl = if (ctx.args.flag("--spctl")) try runSpctl(ctx, root orelse ctx.path) else null;

    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        for (ctx.images, 0..) |*img, i| {
            try json.beginArch(js, img);
            try js.objectField("triage");
            try triage.writeJson(&reports.items[i], ctx.sink);
            try json.endArch(js);
        }
        try json.endArches(js);
        try js.objectField("triage");
        try triage.writeJson(&merged, ctx.sink);
        if (spctl) |s| try writeSpctlJson(ctx, s);
    } else {
        // `--explain` is "verbose findings": it adds the rule's `why:` line under each row, which is
        // exactly what `triage.writeText` prints when the sink is verbose.
        const saved_verbose = ctx.sink.opts.verbose;
        if (opts.explain) ctx.sink.opts.verbose = @max(saved_verbose, 1);
        defer ctx.sink.opts.verbose = saved_verbose;
        for (reports.items, 0..) |*r, i| {
            if (i != 0) try ctx.sink.out.writeByte('\n');
            try triage.writeText(r, ctx.display_path, ctx.sink);
        }
        if (reports.items.len > 1) {
            try ctx.sink.out.writeByte('\n');
            try triage.writeText(&merged, ctx.display_path, ctx.sink);
        }
        if (spctl) |s| try writeSpctlText(ctx, s);
    }
    if (spctl) |s| if (!s.available) return @intFromEnum(context.ExitCode.feature_unavailable);
    return merged.exit_code;
}

// ---------------------------------------------------------------------------------------------
// Gatekeeper (the one subprocess machre ever runs, and only behind --spctl)
// ---------------------------------------------------------------------------------------------

fn runSpctl(ctx: *Context, path: []const u8) Allocator.Error!Spctl {
    if (builtin.os.tag != .macos) {
        ctx.diags.err(.triage, .not_available, null, "--spctl needs macOS", .{});
        return .{ .available = false, .reason = "not macOS" };
    }
    const res = std.process.run(ctx.gpa, ctx.io, .{ .argv = &.{ "/usr/sbin/spctl", "-a", "-vv", "-t", "exec", path } }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            ctx.diags.err(.triage, .os_error, null, "cannot run /usr/sbin/spctl: {t}", .{e});
            return .{ .available = false, .reason = "spctl could not be run" };
        },
    };
    defer ctx.gpa.free(res.stdout);
    defer ctx.gpa.free(res.stderr);
    var s: Spctl = .{ .available = true, .exit = switch (res.term) {
        .exited => |c| c,
        else => 255,
    } };
    for ([_][]const u8{ res.stdout, res.stderr }) |blob| {
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |line| {
            const t = std.mem.trim(u8, line, " \t\r");
            if (std.mem.endsWith(u8, t, ": accepted")) s.assessment = "accepted";
            if (std.mem.endsWith(u8, t, ": rejected")) s.assessment = "rejected";
            if (std.mem.startsWith(u8, t, "source=")) s.source = try ctx.arena.dupe(u8, t["source=".len..]);
            if (std.mem.startsWith(u8, t, "origin=")) s.origin = try ctx.arena.dupe(u8, t["origin=".len..]);
        }
    }
    if (s.assessment == null) s.assessment = if (s.exit == 0) "accepted" else "rejected";
    return s;
}

fn writeSpctlText(ctx: *Context, s: Spctl) !void {
    if (!s.available) {
        try ctx.sink.out.print("Gatekeeper: unavailable ({s})\n", .{try ctx.sink.safeOr(s.reason, "unknown")});
        return;
    }
    try ctx.sink.out.print("Gatekeeper: {s} (spctl exit {d}", .{ try ctx.sink.safeOr(s.assessment, "unknown"), s.exit });
    if (s.source) |src| try ctx.sink.out.print(", source={s}", .{try ctx.sink.safe(src)});
    if (s.origin) |o| try ctx.sink.out.print(", origin={s}", .{try ctx.sink.safe(o)});
    try ctx.sink.out.writeAll(")\n");
}

fn writeSpctlJson(ctx: *Context, s: Spctl) !void {
    const js = &ctx.sink.json;
    if (!s.available) return json.unavailable(js, "spctl", s.reason orelse "unavailable");
    try js.objectField("spctl");
    try js.beginObject();
    try json.int(js, "exit", s.exit);
    try json.strOpt(js, ctx.arena, "assessment", s.assessment);
    try json.strOpt(js, ctx.arena, "source", s.source);
    try json.strOpt(js, ctx.arena, "origin", s.origin);
    try js.endObject();
}

// ---------------------------------------------------------------------------------------------
// tests

test "triage cmd: command table and --fail-on parsing" {
    try std.testing.expectEqualStrings("triage", command.name);
    try std.testing.expect(command.needs_macho);
    try std.testing.expectEqual(@as(?triage.Level, null), try parseFailOn(null));
    try std.testing.expectEqual(@as(?triage.Level, .notable), try parseFailOn("notable"));
    try std.testing.expectEqual(@as(?triage.Level, .suspicious), try parseFailOn("suspicious"));
    try std.testing.expectEqual(@as(?triage.Level, .likely_malicious), try parseFailOn("likely_malicious"));
    try std.testing.expectError(error.InvalidValue, parseFailOn("clean-ish"));
    try std.testing.expectError(error.InvalidValue, parseFailOn(""));
}
