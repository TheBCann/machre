//! core/diag.zig — problems are data. Imports: std only.
//! core/diag.zig — problems are data. Imports: std only.
const std = @import("std");

pub const Severity = enum(u8) { info, warning, @"error" };

pub const Module = enum {
    file,
    fat,
    header,
    loadcmds,
    segments,
    symbols,
    chained,
    exports,
    legacy,
    function_starts,
    fixups,
    imports,
    codesign,
    requirements,
    entitlements,
    cms,
    security,
    xattr,
    dylib_resolve,
    objc,
    strings,
    entropy,
    plist,
    bundle,
    disasm,
    functions,
    symbolize,
    analysis,
    triage,
    cli,
};

/// Stable machine-readable codes (JSON emits the tag name). Add, never renumber/rename.
pub const Code = enum {
    truncated,
    /// arm64 inline-data run found inside a code section (disasm/inline_data.zig).
    inline_data,
    bad_magic,
    count_clamped,
    cmdsize_invalid,
    sizeofcmds_invalid,
    nsects_invalid,
    offset_past_eof,
    overlap,
    unaligned,
    unknown_value,
    string_unterminated,
    invalid_utf8,
    ordinal_out_of_range,
    chain_broken,
    trie_malformed,
    opcode_malformed,
    blob_malformed,
    hash_mismatch,
    version_unsupported,
    der_malformed,
    plist_malformed,
    limit_reached,
    not_available,
    not_implemented,
    os_error,
    backend_disagree,
    stub_mismatch,
    heuristic,
};

pub const Diag = struct {
    severity: Severity,
    module: Module,
    code: Code,
    /// Absolute file offset where the problem was observed, when meaningful.
    offset: ?u64,
    /// Arena-owned, already sanitized (printable ASCII only).
    message: []const u8,
};

pub const Diagnostics = struct {
    arena: std.mem.Allocator,
    list: std.ArrayList(Diag) = .empty,
    dropped: u32 = 0,
    max: u32,
    counts: [3]u32 = .{ 0, 0, 0 },

    pub fn init(arena: std.mem.Allocator, max: u32) Diagnostics {
        return .{ .arena = arena, .max = max };
    }
    /// Never fails visibly: on OOM the diagnostic is counted in `dropped`.
    pub fn add(d: *Diagnostics, severity: Severity, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.counts[@intFromEnum(severity)] += 1;
        if (d.list.items.len >= d.max) {
            d.dropped += 1;
            return;
        }
        const msg = std.fmt.allocPrint(d.arena, fmt, args) catch {
            d.dropped += 1;
            return;
        };
        d.list.append(d.arena, .{ .severity = severity, .module = module, .code = code, .offset = offset, .message = msg }) catch {
            d.dropped += 1;
        };
    }
    pub fn warn(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.warning, module, code, offset, fmt, args);
    }
    pub fn err(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.@"error", module, code, offset, fmt, args);
    }
    pub fn info(d: *Diagnostics, module: Module, code: Code, offset: ?u64, comptime fmt: []const u8, args: anytype) void {
        d.add(.info, module, code, offset, fmt, args);
    }
    /// True when a diagnostic with this (module, code) was already recorded.
    pub fn has(d: *const Diagnostics, module: Module, code: Code) bool {
        for (d.list.items) |it| if (it.module == module and it.code == code) return true;
        return false;
    }
    pub fn hasErrors(d: *const Diagnostics) bool {
        return d.counts[@intFromEnum(Severity.@"error")] != 0;
    }
    pub fn items(d: *const Diagnostics) []const Diag {
        return d.list.items;
    }
};

test "diag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var d = Diagnostics.init(arena.allocator(), 2);
    d.warn(.loadcmds, .cmdsize_invalid, 32, "cmdsize {d}", .{@as(u32, 0)});
    d.err(.symbols, .truncated, null, "x", .{});
    d.err(.symbols, .truncated, null, "y", .{});
    try std.testing.expectEqual(@as(usize, 2), d.items().len);
    try std.testing.expectEqual(@as(u32, 1), d.dropped);
    try std.testing.expect(d.hasErrors());
}
