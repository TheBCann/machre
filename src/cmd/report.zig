//! cmd/report.zig — every analysis in one document. Owned by WP9 (DESIGN.md §12).
//! Imports: cli/context, output/*, and every cmd/* renderer it composes.
//!
//! `report` owns no renderer of its own: it runs the other commands and splices their payloads into a
//! single envelope, so a key can never drift between `machre <cmd> --json` and `machre report --json`.
//! In JSON each sub-command is rendered into a private `{"arches":[…], …top level…}` document which is
//! parsed back and merged key by key (per-arch payloads into `arches[i]`, top-level payloads next to
//! them). Text mode is the DESIGN §5.1 document: `info` + `codesign` + `imports` + `triage`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const sink_mod = @import("../output/sink.zig");
const Sink = sink_mod.Sink;

const sub = struct {
    const info = @import("info.zig");
    const header = @import("header.zig");
    const loadcmds = @import("loadcmds.zig");
    const segments = @import("segments.zig");
    const symbols = @import("symbols.zig");
    const dyld = @import("dyld.zig");
    const imports = @import("imports.zig");
    const exports = @import("exports.zig");
    const codesign = @import("codesign.zig");
    const entitlements = @import("entitlements.zig");
    const objc = @import("objc.zig");
    const strings = @import("strings.zig");
    const entropy = @import("entropy.zig");
    const functions = @import("functions.zig");
    const disasm = @import("disasm.zig");
    const xrefs = @import("xrefs.zig");
    const quarantine = @import("quarantine.zig");
    const bundle = @import("bundle.zig");
    const plist = @import("plist.zig");
    const triage = @import("triage.zig");
    const version = @import("version.zig");
};

/// Every command `report` can render, in document order. `--only` selects a subset by name.
pub const all_sections: []const *const Command = &.{
    &sub.info.command,       &sub.header.command,       &sub.loadcmds.command, &sub.segments.command,
    &sub.symbols.command,    &sub.dyld.command,         &sub.imports.command,  &sub.exports.command,
    &sub.codesign.command,   &sub.entitlements.command, &sub.objc.command,     &sub.strings.command,
    &sub.entropy.command,    &sub.functions.command,    &sub.disasm.command,   &sub.xrefs.command,
    &sub.quarantine.command, &sub.bundle.command,       &sub.plist.command,    &sub.triage.command,
    &sub.version.command,
};
/// JSON default: everything except the two unbounded listings, which `--only` can still ask for.
pub const default_json: []const []const u8 = &.{
    "info",       "header",   "loadcmds",     "segments", "symbols", "dyld",    "imports",
    "exports",    "codesign", "entitlements", "objc",     "strings", "entropy", "functions",
    "quarantine", "bundle",   "plist",        "triage",   "version",
};
/// Text default (DESIGN §5.1): `info` + `codesign` + `imports` summary + `triage`.
pub const default_text: []const []const u8 = &.{ "info", "codesign", "imports", "triage" };

pub const command: Command = .{
    .name = "report",
    .summary = "every analysis in one document (text: info + codesign + imports + triage)",
    .run = run,
    .flags = &.{"--only="},
    .aliases = &.{"all"},
    .needs_macho = false,
};

fn findSection(name: []const u8) ?*const Command {
    for (all_sections) |c| {
        if (std.mem.eql(u8, c.name, name)) return c;
        for (c.aliases) |al| if (std.mem.eql(u8, al, name)) return c;
    }
    return null;
}

/// Splits `--only=a,b,c`; null selects `fallback`. Unknown names are an error the caller reports.
pub fn selectSections(arena: Allocator, only: ?[]const u8, fallback: []const []const u8) error{ OutOfMemory, UnknownSection }![]const *const Command {
    var out: std.ArrayList(*const Command) = .empty;
    if (only) |spec| {
        var it = std.mem.splitScalar(u8, spec, ',');
        while (it.next()) |raw| {
            const name = std.mem.trim(u8, raw, " ");
            if (name.len == 0) continue;
            const c = findSection(name) orelse return error.UnknownSection;
            var seen = false;
            for (out.items) |o| if (o == c) {
                seen = true;
            };
            if (!seen) try out.append(arena, c);
        }
    } else {
        for (fallback) |n| if (findSection(n)) |c| try out.append(arena, c);
    }
    return out.toOwnedSlice(arena);
}

/// Keys `json.beginArch` writes: slice metadata, not a command payload.
const arch_meta: []const []const u8 = &.{ "arch", "index", "offset_in_file", "size", "cputype", "cpusubtype", "caps", "valid" };

fn isArchMeta(k: []const u8) bool {
    for (arch_meta) |m| if (std.mem.eql(u8, m, k)) return true;
    return false;
}

pub fn run(ctx: *Context) anyerror!u8 {
    const sections = selectSections(ctx.arena, ctx.args.value("--only"), if (ctx.sink.isJson()) default_json else default_text) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.UnknownSection => {
            ctx.diags.err(.cli, .unknown_value, null, "--only: unknown command name", .{});
            return @intFromEnum(context.ExitCode.usage);
        },
    };
    if (ctx.sink.isJson()) return runJson(ctx, sections);
    return runText(ctx, sections);
}

// ---------------------------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------------------------

fn runText(ctx: *Context, sections: []const *const Command) !u8 {
    const out = ctx.sink.out;
    try out.print("===== machre report: {s} =====\n", .{ctx.display_path});
    var worst: u8 = 0;
    for (sections) |c| {
        try out.print("\n----- {s} -----\n", .{c.name});
        worst = @max(worst, try runSection(ctx, c));
    }
    return if (worst == @intFromEnum(context.ExitCode.triage_threshold)) worst else 0;
}

/// Runs one sub-command with the caller's sink; its own exit code never becomes the report's unless it
/// is the triage threshold (a section that has nothing to say is not a failure of the document).
fn runSection(ctx: *Context, c: *const Command) !u8 {
    const saved_cmd = ctx.command;
    const saved_exit = ctx.exit_code;
    ctx.command = c.name;
    defer {
        ctx.command = saved_cmd;
        ctx.exit_code = saved_exit;
    }
    return c.run(ctx) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed => return e,
        else => {
            ctx.diags.err(.cli, .os_error, null, "report section {s}: {t}", .{ c.name, e });
            return 0;
        },
    };
}

// ---------------------------------------------------------------------------------------------
// json
// ---------------------------------------------------------------------------------------------

/// One sub-command's output, parsed back: `arches[i]` payload objects plus its top-level payloads.
const Captured = struct { name: []const u8, doc: std.json.Value, exit: u8 };

fn capture(ctx: *Context, c: *const Command) !Captured {
    var buf: std.Io.Writer.Allocating = .init(ctx.arena); // arena-owned: the parse aliases these bytes
    var sub_sink = Sink.init(.json, &buf.writer, ctx.sink.opts, ctx.arena);
    const saved_sink = ctx.sink;
    const saved_cmd = ctx.command;
    const saved_exit = ctx.exit_code;
    ctx.sink = &sub_sink;
    ctx.command = c.name;
    defer {
        ctx.sink = saved_sink;
        ctx.command = saved_cmd;
        ctx.exit_code = saved_exit;
    }
    const js = &sub_sink.json;
    try js.beginObject();
    try js.objectField("arches");
    try js.beginArray();
    var exit: u8 = 0;
    if (c.run(ctx)) |code| {
        exit = code;
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => ctx.diags.err(.cli, .os_error, null, "report section {s}: {t}", .{ c.name, e }),
    }
    // Unwind to "arches", then close it as an array: `closeAll` assumes object in a release build.
    try json.closeAll(js, 2);
    try json.endArches(js); // closes "arches" (anything a failed section left open went above)
    try js.endObject();
    try sub_sink.flush();
    const doc = std.json.parseFromSliceLeaky(std.json.Value, ctx.arena, buf.written(), .{}) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            ctx.diags.err(.cli, .unknown_value, null, "report section {s}: its JSON did not parse back ({t})", .{ c.name, e });
            return .{ .name = c.name, .doc = .null, .exit = exit };
        },
    };
    return .{ .name = c.name, .doc = doc, .exit = exit };
}

fn archPayload(cap: Captured, i: usize) ?std.json.Value {
    const o = switch (cap.doc) {
        .object => |obj| obj,
        else => return null,
    };
    const arches = o.get("arches") orelse return null;
    const items = switch (arches) {
        .array => |a| a.items,
        else => return null,
    };
    if (i >= items.len) return null;
    return items[i];
}

/// Which captured section may write `key`: the section named exactly like it when one was selected
/// (`segments --entropy` and `entropy` both emit an "entropy" object — the `entropy` command owns the
/// name), otherwise the first section that produced it. Without this a merged envelope could carry the
/// same key twice, which is legal JSON but a parse error for `std.json` and for most consumers.
fn mayWrite(caps: []const Captured, i: usize, key: []const u8, written: []const []const u8) bool {
    for (written) |w| if (std.mem.eql(u8, w, key)) return false;
    for (caps, 0..) |c, j| if (std.mem.eql(u8, c.name, key)) return j == i;
    return true;
}

fn runJson(ctx: *Context, sections: []const *const Command) !u8 {
    var caps: std.ArrayList(Captured) = .empty;
    for (sections) |c| try caps.append(ctx.arena, try capture(ctx, c));

    const js = &ctx.sink.json;
    for (ctx.images, 0..) |*img, i| {
        try json.beginArch(js, img);
        var written: std.ArrayList([]const u8) = .empty;
        for (caps.items, 0..) |cap, ci| {
            const payload = archPayload(cap, i) orelse continue;
            switch (payload) {
                .object => |po| {
                    var it = po.iterator();
                    while (it.next()) |e| {
                        const k = e.key_ptr.*;
                        if (isArchMeta(k)) continue;
                        if (!mayWrite(caps.items, ci, k, written.items)) continue;
                        try written.append(ctx.arena, k);
                        try js.objectField(k);
                        try js.write(e.value_ptr.*);
                    }
                },
                else => {},
            }
        }
        try json.endArch(js);
    }
    try json.endArches(js);
    // Top-level payloads (bundle, plist, quarantine, triage, spctl): every key of the captured
    // document except "arches", under the same ownership rule.
    var written: std.ArrayList([]const u8) = .empty;
    for (caps.items, 0..) |cap, ci| {
        const o = switch (cap.doc) {
            .object => |obj| obj,
            else => continue,
        };
        var it = o.iterator();
        while (it.next()) |e| {
            const k = e.key_ptr.*;
            if (std.mem.eql(u8, k, "arches")) continue;
            if (!mayWrite(caps.items, ci, k, written.items)) continue;
            try written.append(ctx.arena, k);
            try js.objectField(k);
            try js.write(e.value_ptr.*);
        }
    }
    var worst: u8 = 0;
    for (caps.items) |cap| if (cap.exit == @intFromEnum(context.ExitCode.triage_threshold)) {
        worst = cap.exit;
    };
    return worst;
}

// ---------------------------------------------------------------------------------------------
// tests

test "report: section selection" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const def = try selectSections(a, null, default_text);
    try std.testing.expectEqual(@as(usize, 4), def.len);
    try std.testing.expectEqualStrings("info", def[0].name);
    try std.testing.expectEqualStrings("triage", def[3].name);
    const only = try selectSections(a, "triage, codesign ,triage", default_text);
    try std.testing.expectEqual(@as(usize, 2), only.len); // deduped, order given
    try std.testing.expectEqualStrings("triage", only[0].name);
    try std.testing.expectEqualStrings("codesign", only[1].name);
    try std.testing.expectError(error.UnknownSection, selectSections(a, "info,nope", default_text));
    // every default name resolves, and `nm`-style aliases work
    const j = try selectSections(a, null, default_json);
    try std.testing.expectEqual(default_json.len, j.len);
    const alias = try selectSections(a, "nm", default_text);
    try std.testing.expectEqualStrings("symbols", alias[0].name);
    try std.testing.expect(isArchMeta("cputype") and !isArchMeta("info"));
    const caps = [_]Captured{
        .{ .name = "segments", .doc = .null, .exit = 0 },
        .{ .name = "entropy", .doc = .null, .exit = 0 },
    };
    // the command named like the key owns it, wherever it sits in the document
    try std.testing.expect(!mayWrite(&caps, 0, "entropy", &.{}));
    try std.testing.expect(mayWrite(&caps, 1, "entropy", &.{}));
    try std.testing.expect(mayWrite(&caps, 0, "segments", &.{}));
    // a key no section is named after goes to the first writer, once
    try std.testing.expect(mayWrite(&caps, 0, "lossy_strings", &.{}));
    try std.testing.expect(!mayWrite(&caps, 1, "lossy_strings", &.{"lossy_strings"}));
}

test "report: command table" {
    try std.testing.expectEqualStrings("report", command.name);
    try std.testing.expectEqualStrings("all", command.aliases[0]);
    // `report` never lists itself (that would recurse) and covers every per-arch command
    for (all_sections) |c| try std.testing.expect(!std.mem.eql(u8, c.name, "report"));
    for (default_json) |n| try std.testing.expect(findSection(n) != null);
    for (default_text) |n| try std.testing.expect(findSection(n) != null);
}
