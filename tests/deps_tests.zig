//! tests/deps_tests.zig — mechanical import-policy check: every `@import("...zig")` in src/**/*.zig must be an
//! edge allowed by DESIGN.md §4 (table below). Owned by WP0.
const std = @import("std");
const helpers = @import("helpers.zig");

pub const Edge = struct { from: []const u8, to: []const u8 };

/// One source file and the files it may import (paths relative to src/). Derived from the "Imports:"
/// line of every §4 listing, plus the WP0 decisions recorded in README.md: `cmd/*` may import other
/// `cmd/*` renderers, `cli/cli.zig` imports `bundle/bundle.zig` for `mainExecutable`.
pub const Node = struct { file: []const u8, imports: []const []const u8 };
pub const table: []const Node = &.{
    .{ .file = "root.zig", .imports = &.{"*"} },
    .{ .file = "main.zig", .imports = &.{} },
    .{ .file = "core/reader.zig", .imports = &.{} },
    .{ .file = "core/limits.zig", .imports = &.{} },
    .{ .file = "core/diag.zig", .imports = &.{} },
    .{ .file = "core/arch.zig", .imports = &.{} },
    .{ .file = "core/sanitize.zig", .imports = &.{} },
    .{ .file = "core/fmt.zig", .imports = &.{"core/sanitize.zig"} },
    .{ .file = "core/version.zig", .imports = &.{"core/fmt.zig"} },
    .{ .file = "core/macho_extra.zig", .imports = &.{} },
    .{ .file = "core/loadcmds.zig", .imports = &.{ "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/version.zig", "core/macho_extra.zig" } },
    .{ .file = "core/segments.zig", .imports = &.{} },
    .{ .file = "core/fat.zig", .imports = &.{ "core/reader.zig", "core/arch.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "core/file.zig", .imports = &.{ "core/reader.zig", "core/fat.zig", "core/arch.zig", "core/limits.zig", "core/diag.zig" } },
    .{ .file = "core/image.zig", .imports = &.{ "core/reader.zig", "core/loadcmds.zig", "core/segments.zig", "core/arch.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "macho/symbols.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/sanitize.zig", "core/version.zig" } },
    .{ .file = "macho/dyld_chained.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/macho_extra.zig" } },
    .{ .file = "macho/dyld_exports.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "macho/dyld_legacy.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "macho/function_starts.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "macho/fixups.zig", .imports = &.{ "core/image.zig", "core/diag.zig", "core/limits.zig", "macho/dyld_chained.zig", "macho/dyld_legacy.zig" } },
    .{ .file = "macho/imports.zig", .imports = &.{ "core/image.zig", "core/loadcmds.zig", "core/diag.zig", "core/limits.zig", "core/version.zig", "macho/symbols.zig", "macho/fixups.zig", "macho/dyld_exports.zig" } },
    .{ .file = "codesign/asn1.zig", .imports = &.{"core/limits.zig"} },
    .{ .file = "codesign/blobs.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/version.zig", "core/macho_extra.zig" } },
    .{ .file = "codesign/hashes.zig", .imports = &.{ "core/image.zig", "core/diag.zig", "core/limits.zig", "codesign/blobs.zig" } },
    .{ .file = "codesign/requirements.zig", .imports = &.{ "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/sanitize.zig" } },
    .{ .file = "codesign/entitlements.zig", .imports = &.{ "core/diag.zig", "core/limits.zig", "codesign/blobs.zig", "codesign/asn1.zig", "plist/plist.zig", "plist/xml.zig" } },
    .{ .file = "codesign/cms.zig", .imports = &.{ "core/diag.zig", "core/limits.zig", "core/sanitize.zig", "codesign/asn1.zig" } },
    .{ .file = "darwin/security.zig", .imports = &.{ "core/diag.zig", "core/sanitize.zig", "plist/plist.zig" } },
    .{ .file = "darwin/xattr.zig", .imports = &.{ "core/diag.zig", "core/sanitize.zig" } },
    .{ .file = "darwin/dylib_resolve.zig", .imports = &.{ "core/loadcmds.zig", "core/diag.zig" } },
    .{ .file = "objc/objc.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/sanitize.zig", "core/macho_extra.zig", "macho/fixups.zig", "macho/symbols.zig" } },
    .{ .file = "strings/strings.zig", .imports = &.{ "core/image.zig", "core/reader.zig", "core/limits.zig", "core/diag.zig", "core/sanitize.zig", "core/macho_extra.zig", "macho/fixups.zig" } },
    .{ .file = "analysis/entropy.zig", .imports = &.{ "core/image.zig", "core/loadcmds.zig" } },
    // §4.20 puts `parseAny` in plist.zig, so it must dispatch to the two format parsers; the §4.20
    // "Imports:" header line predates that signature.
    .{ .file = "plist/plist.zig", .imports = &.{ "core/diag.zig", "core/limits.zig", "core/sanitize.zig", "plist/bplist.zig", "plist/xml.zig" } },
    .{ .file = "plist/bplist.zig", .imports = &.{ "plist/plist.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "plist/xml.zig", .imports = &.{ "plist/plist.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig" } },
    .{ .file = "bundle/bundle.zig", .imports = &.{ "core/file.zig", "core/fat.zig", "core/arch.zig", "core/image.zig", "core/reader.zig", "core/diag.zig", "core/limits.zig", "core/sanitize.zig", "plist/plist.zig", "plist/bplist.zig", "plist/xml.zig", "codesign/blobs.zig", "codesign/hashes.zig" } },
    .{ .file = "analysis/analysis.zig", .imports = &.{ "core/*", "macho/*", "codesign/*", "darwin/*", "objc/objc.zig", "strings/strings.zig", "plist/*", "bundle/bundle.zig", "analysis/entropy.zig", "disasm/*" } },
    .{ .file = "analysis/triage.zig", .imports = &.{ "analysis/analysis.zig", "bundle/bundle.zig", "output/sink.zig", "output/json.zig", "output/text.zig", "core/limits.zig", "core/diag.zig", "core/*", "macho/*", "codesign/*", "darwin/*", "objc/objc.zig", "strings/strings.zig", "plist/*", "analysis/entropy.zig", "disasm/*" } },
    .{ .file = "disasm/insn.zig", .imports = &.{"core/arch.zig"} },
    .{ .file = "disasm/capstone.zig", .imports = &.{ "disasm/insn.zig", "core/arch.zig", "core/sanitize.zig" } },
    .{ .file = "disasm/arm64.zig", .imports = &.{"disasm/insn.zig"} },
    .{ .file = "disasm/x86len.zig", .imports = &.{"disasm/insn.zig"} },
    .{ .file = "disasm/inline_data.zig", .imports = &.{"disasm/insn.zig"} },
    .{ .file = "disasm/functions.zig", .imports = &.{ "core/image.zig", "core/limits.zig", "core/diag.zig", "macho/symbols.zig", "macho/function_starts.zig", "macho/dyld_exports.zig", "objc/objc.zig", "disasm/insn.zig" } },
    .{ .file = "disasm/symbolize.zig", .imports = &.{ "core/image.zig", "core/limits.zig", "core/diag.zig", "core/sanitize.zig", "macho/symbols.zig", "macho/fixups.zig", "objc/objc.zig", "strings/strings.zig", "disasm/insn.zig", "disasm/functions.zig", "disasm/x86len.zig" } },
    .{ .file = "disasm/engine.zig", .imports = &.{ "disasm/insn.zig", "disasm/capstone.zig", "disasm/arm64.zig", "disasm/x86len.zig", "disasm/inline_data.zig", "disasm/functions.zig", "disasm/symbolize.zig", "core/image.zig", "core/arch.zig", "core/limits.zig", "core/diag.zig" } },
    .{ .file = "output/sink.zig", .imports = &.{"core/sanitize.zig"} },
    .{ .file = "output/json.zig", .imports = &.{ "output/sink.zig", "core/diag.zig", "core/sanitize.zig", "core/file.zig", "core/image.zig", "core/fat.zig", "core/fmt.zig" } },
    .{ .file = "output/text.zig", .imports = &.{ "output/sink.zig", "core/diag.zig", "core/sanitize.zig", "core/fmt.zig" } },
    .{ .file = "cli/args.zig", .imports = &.{} },
    .{ .file = "cli/context.zig", .imports = &.{ "core/limits.zig", "core/diag.zig", "core/file.zig", "core/image.zig", "core/arch.zig", "output/sink.zig", "cli/args.zig" } },
    .{ .file = "cli/cli.zig", .imports = &.{ "cli/args.zig", "cli/context.zig", "output/*", "core/*", "analysis/analysis.zig", "bundle/bundle.zig", "darwin/xattr.zig", "cmd/*" } },
    .{ .file = "cmd/*", .imports = &.{ "cli/context.zig", "output/*", "analysis/analysis.zig", "core/*", "macho/*", "codesign/*", "darwin/*", "objc/objc.zig", "strings/strings.zig", "analysis/entropy.zig", "analysis/triage.zig", "plist/*", "bundle/bundle.zig", "disasm/*", "cmd/*" } },
};
/// Legacy flat view of the table (kept for callers that want (from, to) pairs).
pub const allowed: []const Edge = &.{};

fn matches(pattern: []const u8, path: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const dir = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, path, dir) and std.mem.findScalar(u8, path[dir.len..], '/') == null;
    }
    return std.mem.eql(u8, pattern, path);
}
fn allowedEdge(from: []const u8, to: []const u8) bool {
    for (table) |n| if (matches(n.file, from)) {
        for (n.imports) |p| if (matches(p, to)) return true;
    };
    return false;
}
/// Resolves `rel` (as written in @import) against the importing file's directory; "a/../b" normalised.
fn resolve(arena: std.mem.Allocator, from: []const u8, rel: []const u8) ![]const u8 {
    const dir = std.fs.path.dirname(from) orelse "";
    const joined = if (dir.len == 0) try arena.dupe(u8, rel) else try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, rel });
    var parts: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, joined, '/');
    while (it.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".")) continue;
        if (std.mem.eql(u8, p, "..")) {
            _ = parts.pop();
            continue;
        }
        try parts.append(arena, p);
    }
    return std.mem.join(arena, "/", parts.items);
}

test "deps: src dir resolves" {
    try std.testing.expect(std.mem.endsWith(u8, helpers.srcDir(), "src"));
}

test "deps: every @import edge in src/**/*.zig is allowed by the DESIGN.md §4 table" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dir = try std.Io.Dir.openDirAbsolute(io, helpers.srcDir(), .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    var files: usize = 0;
    var bad: usize = 0;
    while (try walker.next(io)) |e| {
        if (e.kind != .file or !std.mem.endsWith(u8, e.basename, ".zig")) continue;
        files += 1;
        const from = try arena.dupe(u8, e.path);
        const src = try dir.readFileAlloc(io, e.path, arena, .limited(1 << 22));
        var pos: usize = 0;
        while (std.mem.findPos(u8, src, pos, "@import(\"")) |i| {
            const start = i + "@import(\"".len;
            const end = std.mem.findScalarPos(u8, src, start, '"') orelse break;
            pos = end + 1;
            const rel = src[start..end];
            if (!std.mem.endsWith(u8, rel, ".zig")) continue; // std, builtin, build_options
            const to = try resolve(arena, from, rel);
            if (!allowedEdge(from, to)) {
                std.debug.print("disallowed import edge: {s} -> {s}\n", .{ from, to });
                bad += 1;
            }
        }
    }
    try std.testing.expect(files > 60);
    if (bad != 0) return error.DisallowedImportEdge;
}

test "deps: matcher semantics" {
    try std.testing.expect(matches("core/*", "core/reader.zig"));
    try std.testing.expect(!matches("core/*", "core/sub/x.zig"));
    try std.testing.expect(allowedEdge("cmd/info.zig", "cli/context.zig"));
    try std.testing.expect(!allowedEdge("cmd/info.zig", "cli/cli.zig"));
    try std.testing.expect(!allowedEdge("core/reader.zig", "core/diag.zig"));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("core/diag.zig", try resolve(arena.allocator(), "cmd/info.zig", "../core/diag.zig"));
    try std.testing.expectEqualStrings("core/limits.zig", try resolve(arena.allocator(), "core/reader.zig", "limits.zig"));
}
