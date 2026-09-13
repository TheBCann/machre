//! cmd/bundle.zig — bundle layout, Info.plist essentials, nested code, CodeResources seal verification, ticket. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
//!
//! The walker itself is portable (`bundle/bundle.zig`); this file adds the Security.framework verdict and,
//! only with the explicit `--spctl` flag, the Gatekeeper assessment (the one subprocess machre ever runs).
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const bundle = @import("../bundle/bundle.zig");
const plist = @import("../plist/plist.zig");
const security = @import("../darwin/security.zig");
const plist_cmd = @import("plist.zig");

pub const command: Command = .{
    .name = "bundle",
    .summary = "bundle layout, Info.plist essentials, nested code, CodeResources seal verification, ticket",
    .run = run,
    .flags = &.{ "--files", "--nested", "--no-verify", "--spctl" },
    .aliases = &.{},
    .needs_macho = false,
};

pub const Spctl = struct {
    available: bool,
    reason: ?[]const u8 = null,
    exit: u8 = 0,
    assessment: ?[]const u8 = null,
    source: ?[]const u8 = null,
    origin: ?[]const u8 = null,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const opts: bundle.Options = .{ .verify_resources = !ctx.args.flag("--no-verify"), .hash_nested = true };
    // A file inside a bundle is promoted to its bundle, exactly as SecStaticCodeCreateWithPath does.
    const root = if (bundle.detect(ctx.io, ctx.path) != null)
        ctx.path
    else
        (try bundle.enclosingBundle(ctx.arena, ctx.io, ctx.path, ctx.limits)) orelse ctx.path;
    const b = try bundle.analyze(ctx.arena, ctx.gpa, ctx.io, root, opts, ctx.limits, ctx.diags);
    if (b == null) {
        if (ctx.sink.isJson()) {
            try closeArches(ctx);
            try json.unavailable(&ctx.sink.json, "bundle", "not a bundle directory");
        } else {
            try ctx.sink.out.print("{s}: not a bundle (no Contents/Info.plist, Versions/*/Resources/Info.plist or Info.plist)\n", .{ctx.display_path});
        }
        return @intFromEnum(context.ExitCode.not_macho);
    }
    const bb = b.?;

    const root_z = try ctx.arena.dupeSentinel(u8, bb.root, 0);
    const verdict = if (ctx.no_security)
        security.unavailable("--no-security", bb.root)
    else
        try security.evaluate(ctx.arena, root_z, .{ .revocation = true, .network = !ctx.no_network, .is_directory = true }, ctx.diags);

    var spctl: ?Spctl = null;
    if (ctx.args.flag("--spctl")) {
        spctl = try runSpctl(ctx, bb.root);
        if (!spctl.?.available) {
            if (ctx.sink.isJson()) {
                try writeAll(ctx, &bb, &verdict, spctl);
            } else {
                try writeText(ctx, &bb, &verdict, spctl);
            }
            return @intFromEnum(context.ExitCode.feature_unavailable);
        }
    }
    if (ctx.sink.isJson()) try writeAll(ctx, &bb, &verdict, spctl) else try writeText(ctx, &bb, &verdict, spctl);
    return 0;
}

fn closeArches(ctx: *Context) !void {
    const js = &ctx.sink.json;
    for (ctx.images) |*img| {
        try json.beginArch(js, img);
        try json.endArch(js);
    }
    try json.endArches(js);
}

// ---------------------------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------------------------

fn kindName(k: bundle.Kind) []const u8 {
    return @tagName(k);
}
/// "yes" / "NO" / "unchecked", with the sealing architecture appended when the seal names a slice
/// other than the host-preferred one the `actual` column shows (an app signed on the other arch).
fn matchLabel(arena: Allocator, n: bundle.NestedCode) ![]const u8 {
    const m = n.cdhash_match orelse return "unchecked";
    if (!m) return "NO";
    const matched = n.matched_arch orelse return "yes";
    const shown = n.cdhash_arch orelse return "yes";
    if (std.mem.eql(u8, matched, shown)) return "yes";
    return std.fmt.allocPrint(arena, "yes ({s})", .{matched});
}

/// Text label for a nested object: a bare dylib has no bundle `Kind`, so name it by its extension.
fn nestedKindName(n: bundle.NestedCode) []const u8 {
    if (n.kind != .unknown) return @tagName(n.kind);
    if (std.mem.endsWith(u8, n.rel_path, ".dylib")) return "dylib";
    if (std.mem.endsWith(u8, n.rel_path, ".so")) return "shared object";
    return "executable";
}

fn writeText(ctx: *Context, b: *const bundle.Bundle, v: *const security.Verdict, spctl: ?Spctl) !void {
    const out = ctx.sink.out;
    const arena = ctx.arena;
    const snk = ctx.sink;
    try out.print("{s}: {s} bundle, {d} files, {d} bytes\n", .{ try snk.safe(b.root), kindName(b.kind), b.file_count, b.total_size });
    try text.kv(out, 2, "identifier", "{s}", .{try snk.safeOr(b.identifier, "(none)")});
    try text.kv(out, 2, "package", "{s}", .{try snk.safeOr(b.package_type, "(none)")});
    try text.kv(out, 2, "executable", "{s}", .{try snk.safeOr(b.executable_rel, "(none)")});
    if (b.info_plist_path) |p| {
        try text.kv(out, 2, "info.plist", "{s}   {s}   {d} entries", .{ try snk.safe(p), @tagName(b.info_plist_format), entryCount(b.info_plist) });
    } else {
        try text.kv(out, 2, "info.plist", "(none)", .{});
    }
    try text.kv(out, 2, "version", "{s}   short {s}   min system {s}", .{ try snk.safeOr(b.version, "-"), try snk.safeOr(b.short_version, "-"), try snk.safeOr(b.min_system, "-") });
    if (b.principal_class) |p| try text.kv(out, 2, "principal", "{s}", .{try snk.safe(p)});
    try text.kv(out, 2, "flags", "{s}", .{try bundleFlags(arena, b)});
    if (b.url_schemes.len != 0) try text.kv(out, 2, "url schemes", "{s}", .{try snk.safe(try std.mem.join(arena, ", ", b.url_schemes))});
    if (b.usage_descriptions.len != 0) try text.kv(out, 2, "usage keys", "{s}", .{try snk.safe(try std.mem.join(arena, ", ", b.usage_descriptions))});

    const nested = try b.nestedAll(arena);
    try text.kv(out, 2, "nested code", "{d}", .{nested.len});
    if (nested.len != 0) {
        var t = text.Table.init(arena, &.{ .{ .name = "path" }, .{ .name = "kind" }, .{ .name = "arch" }, .{ .name = "sealed" }, .{ .name = "actual" }, .{ .name = "match" } });
        for (nested) |n| {
            try t.rowFmt(&.{ "{s}", "{s}", "{s}", "{s}", "{s}", "{s}" }, .{
                try snk.safe(n.rel_path),
                nestedKindName(n),
                if (n.arch_names.len == 0) "-" else try snk.safe(try std.mem.join(arena, ",", n.arch_names)),
                try hexOrDash(arena, n.sealed_cdhash),
                try hexOrDash(arena, n.actual_cdhash),
                try matchLabel(arena, n),
            });
        }
        try t.render(out, 4, ctx.sink.opts.limit);
        if (ctx.args.flag("--nested")) {
            for (nested) |n| if (n.sealed_requirement) |r| try out.print("    {s}: {s}\n", .{ try snk.safe(n.rel_path), try snk.safe(r) });
        }
    }

    if (b.code_resources) |*cr| {
        try text.kv(out, 2, "resources", "Sealed Resources version={d} rules={d} files={d}", .{ cr.version, cr.activeRules(), cr.activeFiles() });
    } else {
        try text.kv(out, 2, "resources", "none", .{});
    }
    if (b.resource_verify) |rv| {
        try text.kv(out, 2, "verify", "{s}   {d} checked, {d} mismatched, {d} missing, {d} unsealed", .{ if (rv.ok) "ok" else "FAILED", rv.checked, rv.mismatched.len, rv.missing.len, rv.unsealed.len });
        for (rv.mismatched) |p| try out.print("    mismatched  {s}\n", .{try snk.safe(p)});
        for (rv.missing) |p| try out.print("    missing     {s}\n", .{try snk.safe(p)});
        for (rv.unsealed) |p| try out.print("    unsealed    {s}\n", .{try snk.safe(p)});
    } else {
        try text.kv(out, 2, "verify", "not performed", .{});
    }
    if (b.stapled_ticket) |t| {
        try text.kv(out, 2, "ticket", "{s} ({d} bytes)", .{ try snk.safe(t.path), t.len });
    } else {
        try text.kv(out, 2, "ticket", "none", .{});
    }
    try text.kv(out, 2, "profile", "{s}", .{if (b.provisioning_profile) "embedded.provisionprofile present" else "none"});
    if (v.available) {
        try text.kv(out, 2, "security", "{s} ({d})   trust: {s}", .{ v.validity_status_name, v.validity_status, security.trustName(v.trust) });
    } else {
        try text.kv(out, 2, "security", "not evaluated ({s})", .{v.reason orelse "unavailable"});
    }
    if (spctl) |s| {
        if (s.available) {
            try text.kv(out, 2, "spctl", "{s}   source {s}   origin {s}", .{ try snk.safeOr(s.assessment, "-"), try snk.safeOr(s.source, "-"), try snk.safeOr(s.origin, "-") });
        } else {
            try text.kv(out, 2, "spctl", "unavailable ({s})", .{s.reason orelse "-"});
        }
    }
    if (ctx.verbose > 0) {
        if (b.info_plist) |pv| {
            try text.kv(out, 2, "info.plist", "contents:", .{});
            try plist_cmd.renderPlutil(snk, pv, 4);
        }
    }
    if (ctx.args.flag("--files")) {
        var t = text.Table.init(arena, &.{ .{ .name = "size", .@"align" = .right }, .{ .name = "path" } });
        for (b.entries) |e| {
            if (e.kind == .dir) continue;
            try t.rowFmt(&.{ "{d}", "{s}" }, .{ e.size, try snk.safe(e.path) });
        }
        try text.kv(out, 2, "files", "{d} of {d} entries", .{ b.file_count, b.entries_walked });
        try t.render(out, 4, ctx.sink.opts.limit);
    }
}

fn entryCount(v: ?plist.Value) usize {
    const x = v orelse return 0;
    return plist.containerLen(x);
}
fn hexOrDash(arena: Allocator, h: ?[20]u8) Allocator.Error![]const u8 {
    const x = h orelse return "-";
    return std.fmt.allocPrint(arena, "{x}", .{&x});
}
fn bundleFlags(arena: Allocator, b: *const bundle.Bundle) Allocator.Error![]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    if (b.ui_element) try list.append(arena, "LSUIElement");
    if (b.background_only) try list.append(arena, "LSBackgroundOnly");
    if (b.ats_arbitrary_loads) try list.append(arena, "NSAllowsArbitraryLoads");
    if (b.truncated) try list.append(arena, "walk-truncated");
    if (list.items.len == 0) return "none";
    return std.mem.join(arena, " ", list.items);
}

// ---------------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------------

fn writeAll(ctx: *Context, b: *const bundle.Bundle, v: *const security.Verdict, spctl: ?Spctl) !void {
    const js = &ctx.sink.json;
    const arena = ctx.arena;
    try closeArches(ctx);
    try js.objectField("bundle");
    try js.beginObject();
    try json.str(js, arena, "root", b.root);
    try js.objectField("kind");
    try js.write(kindName(b.kind));
    try json.strOpt(js, arena, "identifier", b.identifier);
    try json.strOpt(js, arena, "executable", b.executable_rel);
    try json.strOpt(js, arena, "executable_path", b.executable_path);
    try json.strOpt(js, arena, "package_type", b.package_type);
    try json.strOpt(js, arena, "version", b.version);
    try json.strOpt(js, arena, "short_version", b.short_version);
    try json.strOpt(js, arena, "min_system", b.min_system);
    try json.boolean(js, "ui_element", b.ui_element);
    try json.boolean(js, "background_only", b.background_only);
    try json.boolean(js, "ats_arbitrary_loads", b.ats_arbitrary_loads);
    try json.names(js, arena, "usage_descriptions", b.usage_descriptions);
    try json.names(js, arena, "url_schemes", b.url_schemes);
    try json.strOpt(js, arena, "principal_class", b.principal_class);

    try js.objectField("info_plist");
    try js.beginObject();
    try js.objectField("format");
    try js.write(@tagName(b.info_plist_format));
    try json.strOpt(js, arena, "path", b.info_plist_path);
    try json.int(js, "entries", entryCount(b.info_plist));
    try js.objectField("value");
    if (b.info_plist) |pv| try js.write(pv) else try js.write(null);
    try js.endObject();

    try writeNestedArray(ctx, "frameworks", b.frameworks);
    try writeNestedArray(ctx, "helpers", b.helpers);
    try writeNestedArray(ctx, "xpc_services", b.xpc_services);
    try writeNestedArray(ctx, "plugins", b.plugins);
    try writeNestedArray(ctx, "dylibs", b.dylibs);
    try writeNestedArray(ctx, "nested", try b.nestedAll(arena));

    try js.objectField("code_resources");
    if (b.code_resources) |*cr| {
        try js.beginObject();
        try json.int(js, "version", cr.version);
        try json.int(js, "rules", cr.rules);
        try json.int(js, "rules2", cr.rules2);
        try json.int(js, "active_rules", cr.activeRules());
        try js.objectField("files");
        try js.beginArray();
        for ([_][]const bundle.ResourceFile{ cr.files, cr.files2 }) |list| {
            for (list) |f| {
                if (f.cdhash != null) continue; // nested code is listed under "nested"
                try js.beginObject();
                try json.str(js, arena, "path", f.path);
                if (f.hash1) |h| try json.bytesHex(js, "hash1", &h) else try json.bytesHexOpt(js, "hash1", null);
                if (f.hash2) |h| try json.bytesHex(js, "hash2", &h) else try json.bytesHexOpt(js, "hash2", null);
                try json.boolean(js, "optional", f.optional);
                try json.strOpt(js, arena, "symlink", f.symlink);
                try js.endObject();
            }
        }
        try js.endArray();
        try js.objectField("nested");
        try js.beginArray();
        for ([_][]const bundle.ResourceFile{ cr.files, cr.files2 }) |list| {
            for (list) |f| {
                const cd = f.cdhash orelse continue;
                try js.beginObject();
                try json.str(js, arena, "path", f.path);
                try json.bytesHex(js, "cdhash", &cd);
                try json.strOpt(js, arena, "requirement", f.requirement);
                try js.endObject();
            }
        }
        try js.endArray();
        try js.objectField("verify");
        if (b.resource_verify) |rv| {
            try js.beginObject();
            try json.int(js, "checked", rv.checked);
            try json.names(js, arena, "mismatched", rv.mismatched);
            try json.names(js, arena, "missing", rv.missing);
            try json.names(js, arena, "unsealed", rv.unsealed);
            try json.boolean(js, "ok", rv.ok);
            try js.endObject();
        } else try unavailableValue(js, "--no-verify");
        try js.endObject();
    } else try js.write(null);

    try js.objectField("stapled_ticket");
    if (b.stapled_ticket) |t| {
        try js.beginObject();
        try json.boolean(js, "present", true);
        try json.str(js, arena, "path", t.path);
        try json.int(js, "length", t.len);
        try js.endObject();
    } else {
        try js.beginObject();
        try json.boolean(js, "present", false);
        try json.strOpt(js, arena, "path", null);
        try json.int(js, "length", @as(u32, 0));
        try js.endObject();
    }
    try json.boolean(js, "provisioning_profile", b.provisioning_profile);
    try json.int(js, "file_count", b.file_count);
    try json.int(js, "total_size", b.total_size);
    try json.int(js, "entries_walked", b.entries_walked);
    try json.boolean(js, "truncated", b.truncated);

    try js.objectField("security");
    try js.beginObject();
    try json.boolean(js, "available", v.available);
    try json.strOpt(js, arena, "reason", v.reason);
    try json.str(js, arena, "evaluated_path", v.evaluated_path);
    try json.int(js, "status", v.validity_status);
    try js.objectField("status_name");
    try js.write(v.validity_status_name);
    try js.objectField("trust");
    try js.write(security.trustName(v.trust));
    try json.strOpt(js, arena, "identifier", v.identifier);
    try json.strOpt(js, arena, "team_id", v.team_id);
    try json.strOpt(js, arena, "format", v.format);
    if (v.cdhash) |h| try json.bytesHex(js, "cdhash", &h) else try json.bytesHexOpt(js, "cdhash", null);
    try json.boolean(js, "stapled_ticket", v.has_stapled_ticket);
    try js.endObject();

    try js.objectField("spctl");
    if (spctl) |s| {
        try js.beginObject();
        try json.boolean(js, "available", s.available);
        try json.strOpt(js, arena, "reason", s.reason);
        try json.int(js, "exit", s.exit);
        try json.strOpt(js, arena, "assessment", s.assessment);
        try json.strOpt(js, arena, "source", s.source);
        try json.strOpt(js, arena, "origin", s.origin);
        try js.endObject();
    } else try unavailableValue(js, "--spctl not given");

    try js.endObject();
}

/// `{"available": false, "reason": ...}` written as a value (the object field is already open).
fn unavailableValue(js: *std.json.Stringify, reason: []const u8) !void {
    try js.beginObject();
    try json.boolean(js, "available", false);
    try js.objectField("reason");
    try js.write(reason);
    try js.endObject();
}

fn writeNestedArray(ctx: *Context, key: []const u8, list: []const bundle.NestedCode) !void {
    const js = &ctx.sink.json;
    const arena = ctx.arena;
    try js.objectField(key);
    try js.beginArray();
    for (list) |n| {
        try js.beginObject();
        try json.str(js, arena, "path", n.rel_path);
        try js.objectField("kind");
        try js.write(kindName(n.kind));
        try json.strOpt(js, arena, "executable", n.executable_rel);
        if (n.sealed_cdhash) |h| try json.bytesHex(js, "sealed_cdhash", &h) else try json.bytesHexOpt(js, "sealed_cdhash", null);
        try json.strOpt(js, arena, "sealed_requirement", n.sealed_requirement);
        if (n.actual_cdhash) |h| try json.bytesHex(js, "actual_cdhash", &h) else try json.bytesHexOpt(js, "actual_cdhash", null);
        // Which slice produced actual_cdhash (the host-preferred one, as codesign -dvvv reports it)
        // and which slice the CodeResources seal turned out to name; they differ only when the app
        // was signed on a host of the other architecture.
        try json.strOpt(js, arena, "cdhash_arch", n.cdhash_arch);
        try json.strOpt(js, arena, "matched_arch", n.matched_arch);
        try js.objectField("cdhash_match");
        if (n.cdhash_match) |m| try js.write(m) else try js.write(null);
        try js.objectField("signed");
        if (n.signed) |s| try js.write(s) else try js.write(null);
        try json.names(js, arena, "arches", n.arch_names);
        try js.endObject();
    }
    try js.endArray();
}

// ---------------------------------------------------------------------------------------------
// spctl (the only subprocess machre ever runs, and only behind --spctl)
// ---------------------------------------------------------------------------------------------

fn runSpctl(ctx: *Context, path: []const u8) Allocator.Error!Spctl {
    if (builtin.os.tag != .macos) {
        ctx.diags.err(.bundle, .not_available, null, "--spctl needs macOS", .{});
        return .{ .available = false, .reason = "not macOS" };
    }
    const res = std.process.run(ctx.gpa, ctx.io, .{ .argv = &.{ "/usr/sbin/spctl", "-a", "-vv", "-t", "exec", path } }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            ctx.diags.err(.bundle, .os_error, null, "cannot run /usr/sbin/spctl: {t}", .{e});
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

test "bundle cmd: flag table and helpers" {
    try std.testing.expectEqualStrings("bundle", command.name);
    try std.testing.expect(!command.needs_macho);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("-", try hexOrDash(arena, null));
    var cd: [20]u8 = @splat(0);
    cd[0] = 0x41;
    cd[1] = 0xb8;
    try std.testing.expectEqualStrings("41b800", (try hexOrDash(arena, cd))[0..6]);
    var b: bundle.Bundle = undefined;
    b.ui_element = true;
    b.background_only = false;
    b.ats_arbitrary_loads = true;
    b.truncated = false;
    try std.testing.expectEqualStrings("LSUIElement NSAllowsArbitraryLoads", try bundleFlags(arena, &b));
}
