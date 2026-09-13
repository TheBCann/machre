//! machre library root: re-exports every module and forces semantic analysis of every pub declaration
//! (Zig analyzes lazily; without this a signature error in an unreferenced function would go unnoticed).
const std = @import("std");
pub const build_options = @import("build_options");

pub const core = struct {
    pub const reader = @import("core/reader.zig");
    pub const limits = @import("core/limits.zig");
    pub const diag = @import("core/diag.zig");
    pub const arch = @import("core/arch.zig");
    pub const sanitize = @import("core/sanitize.zig");
    pub const fmt = @import("core/fmt.zig");
    pub const version = @import("core/version.zig");
    pub const macho_extra = @import("core/macho_extra.zig");
    pub const loadcmds = @import("core/loadcmds.zig");
    pub const segments = @import("core/segments.zig");
    pub const fat = @import("core/fat.zig");
    pub const file = @import("core/file.zig");
    pub const image = @import("core/image.zig");
};
pub const macho = struct {
    pub const symbols = @import("macho/symbols.zig");
    pub const dyld_chained = @import("macho/dyld_chained.zig");
    pub const dyld_exports = @import("macho/dyld_exports.zig");
    pub const dyld_legacy = @import("macho/dyld_legacy.zig");
    pub const function_starts = @import("macho/function_starts.zig");
    pub const fixups = @import("macho/fixups.zig");
    pub const imports = @import("macho/imports.zig");
};
pub const codesign = struct {
    pub const asn1 = @import("codesign/asn1.zig");
    pub const blobs = @import("codesign/blobs.zig");
    pub const hashes = @import("codesign/hashes.zig");
    pub const requirements = @import("codesign/requirements.zig");
    pub const entitlements = @import("codesign/entitlements.zig");
    pub const cms = @import("codesign/cms.zig");
};
pub const darwin = struct {
    pub const security = @import("darwin/security.zig");
    pub const xattr = @import("darwin/xattr.zig");
    pub const dylib_resolve = @import("darwin/dylib_resolve.zig");
};
pub const objc = @import("objc/objc.zig");
pub const strings = @import("strings/strings.zig");
pub const plist = struct {
    pub const plist = @import("plist/plist.zig");
    pub const bplist = @import("plist/bplist.zig");
    pub const xml = @import("plist/xml.zig");
};
pub const bundle = @import("bundle/bundle.zig");
pub const analysis = struct {
    pub const entropy = @import("analysis/entropy.zig");
    pub const analysis = @import("analysis/analysis.zig");
    pub const triage = @import("analysis/triage.zig");
};
pub const disasm = struct {
    pub const insn = @import("disasm/insn.zig");
    pub const capstone = @import("disasm/capstone.zig");
    pub const arm64 = @import("disasm/arm64.zig");
    pub const x86len = @import("disasm/x86len.zig");
    pub const functions = @import("disasm/functions.zig");
    pub const symbolize = @import("disasm/symbolize.zig");
    pub const engine = @import("disasm/engine.zig");
};
pub const output = struct {
    pub const sink = @import("output/sink.zig");
    pub const json = @import("output/json.zig");
    pub const text = @import("output/text.zig");
};
pub const cli = @import("cli/cli.zig");
pub const args = @import("cli/args.zig");
pub const context = @import("cli/context.zig");

// Convenience aliases used by tests and README examples.
pub const Reader = core.reader.Reader;
pub const Cursor = core.reader.Cursor;
pub const Limits = core.limits.Limits;
pub const Diagnostics = core.diag.Diagnostics;
pub const LoadedFile = core.file.LoadedFile;
pub const Image = core.image.Image;
pub const Analysis = analysis.analysis.Analysis;

/// References every pub declaration recursively (our own types only; std/builtin aliases are skipped)
/// so `zig build` — not only `zig build test` — semantically checks every signature and body.
pub fn refAllDeclsRecursive(comptime T: type, comptime depth: u8) void {
    @setEvalBranchQuota(200000);
    inline for (comptime std.meta.declarations(T)) |name| {
        const D = @field(T, name);
        if (@TypeOf(D) == type) {
            switch (@typeInfo(D)) {
                .@"struct", .@"enum", .@"union", .@"opaque" => {
                    if (depth > 0 and !isForeign(D)) refAllDeclsRecursive(D, depth - 1);
                },
                else => {},
            }
        }
        _ = &@field(T, name);
    }
}
fn isForeign(comptime T: type) bool {
    const n = @typeName(T);
    return std.mem.startsWith(u8, n, "std.") or std.mem.startsWith(u8, n, "builtin.") or std.mem.startsWith(u8, n, "build_options");
}
comptime {
    @setEvalBranchQuota(200000);
    refAllDeclsRecursive(@This(), 6);
}

test {
    std.testing.refAllDecls(@This());
}
