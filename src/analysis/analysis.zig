//! analysis/analysis.zig — memoizing lazy facade over every parser for ONE slice. Commands, triage and
//! report go through it so `machre info` never parses symbols/chains/ObjC unless a getter is called.
//! Getters propagate Allocator.Error (never swallow OOM); absent data is `null` / `.empty` + diagnostics.
//! Imports: everything below cmd/.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");
const LoadedFile = @import("../core/file.zig").LoadedFile;
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const loadcmds = @import("../core/loadcmds.zig");
const symbols_mod = @import("../macho/symbols.zig");
const dyld_chained_mod = @import("../macho/dyld_chained.zig");
const dyld_exports_mod = @import("../macho/dyld_exports.zig");
const dyld_legacy_mod = @import("../macho/dyld_legacy.zig");
const function_starts_mod = @import("../macho/function_starts.zig");
const fixups_mod = @import("../macho/fixups.zig");
const imports_mod = @import("../macho/imports.zig");
const blobs_mod = @import("../codesign/blobs.zig");
const hashes_mod = @import("../codesign/hashes.zig");
const bundle_mod = @import("../bundle/bundle.zig");
const requirements_mod = @import("../codesign/requirements.zig");
const entitlements_mod = @import("../codesign/entitlements.zig");
const cms_mod = @import("../codesign/cms.zig");
const security_mod = @import("../darwin/security.zig");
const xattr_mod = @import("../darwin/xattr.zig");
const dylib_resolve_mod = @import("../darwin/dylib_resolve.zig");
const objc_mod = @import("../objc/objc.zig");
const strings_mod = @import("../strings/strings.zig");
const entropy_mod = @import("entropy.zig");
const functions_mod = @import("../disasm/functions.zig");
const symbolize_mod = @import("../disasm/symbolize.zig");
const engine_mod = @import("../disasm/engine.zig");

pub const Options = struct {
    security: bool = true, // --no-security
    network: bool = true, // --no-network
    /// Set when the command was handed a bundle directory (`Context.bundle_path`). Special slots
    /// -1/-3 are sealed by path, so verifying them needs the bundle, not the Mach-O.
    bundle_path: ?[]const u8 = null,
    resolve_deps: bool = true,
    engine: engine_mod.Options = .{},
};

pub const Analysis = struct {
    gpa: Allocator,
    arena: Allocator,
    io: Io,
    file: *const LoadedFile,
    img: *const Image,
    limits: *const Limits,
    diags: *Diagnostics,
    options: Options,

    // memo slots (null = not computed yet)
    symbols_: ?symbols_mod.SymbolTable = null,
    addr_index_: ?symbols_mod.AddressIndex = null,
    chained_: ?struct { v: ?dyld_chained_mod.ChainedFixups } = null,
    legacy_: ?struct { v: ?dyld_legacy_mod.DyldInfo } = null,
    exports_trie_: ?struct { v: ?dyld_exports_mod.ExportTrie } = null,
    function_starts_: ?struct { v: ?function_starts_mod.FunctionStarts } = null,
    data_in_code_: ?struct { v: ?function_starts_mod.DataInCode } = null,
    fixups_: ?fixups_mod.FixupTable = null,
    dylibs_: ?[]const imports_mod.DylibRef = null,
    rpaths_: ?[]const []const u8 = null,
    imports_: ?imports_mod.ImportTable = null,
    exports_: ?imports_mod.ExportTable = null,
    signature_: ?struct { v: ?blobs_mod.Signature } = null,
    verification_: ?struct { v: ?hashes_mod.Verification } = null,
    requirements_: ?struct { v: ?requirements_mod.RequirementSet } = null,
    entitlements_: ?entitlements_mod.Entitlements = null,
    cms_: ?struct { v: ?cms_mod.Cms } = null,
    security_: ?security_mod.Verdict = null,
    xattrs_: ?xattr_mod.Xattrs = null,
    resolutions_: ?[]const dylib_resolve_mod.Resolution = null,
    objc_: ?objc_mod.ObjcInfo = null,
    strings_: ?strings_mod.StringsResult = null,
    strings_opts_: ?strings_mod.Options = null,
    entropy_: ?entropy_mod.EntropyReport = null,
    functions_: ?functions_mod.FunctionTable = null,
    stubs_: ?symbolize_mod.StubTable = null,
    engine_: ?engine_mod.Engine = null,

    pub fn init(gpa: Allocator, arena: Allocator, io: Io, file: *const LoadedFile, img: *const Image, limits: *const Limits, diags: *Diagnostics, options: Options) Analysis {
        return .{ .gpa = gpa, .arena = arena, .io = io, .file = file, .img = img, .limits = limits, .diags = diags, .options = options };
    }
    pub fn deinit(a: *Analysis) void {
        if (a.engine_) |*e| e.deinit();
        a.engine_ = null;
    }
    pub fn symbols(a: *Analysis) Allocator.Error!*const symbols_mod.SymbolTable {
        if (a.symbols_ == null) a.symbols_ = try symbols_mod.parse(a.arena, a.img, a.limits, a.diags);
        return &a.symbols_.?;
    }
    pub fn addressIndex(a: *Analysis) Allocator.Error!*const symbols_mod.AddressIndex {
        if (a.addr_index_ == null) a.addr_index_ = try symbols_mod.AddressIndex.build(a.arena, try a.symbols());
        return &a.addr_index_.?;
    }
    pub fn chained(a: *Analysis) Allocator.Error!?*const dyld_chained_mod.ChainedFixups {
        if (a.chained_ == null) a.chained_ = .{ .v = try dyld_chained_mod.parse(a.arena, a.img, a.limits, a.diags) };
        return if (a.chained_.?.v) |*v| v else null;
    }
    pub fn legacy(a: *Analysis) Allocator.Error!?*const dyld_legacy_mod.DyldInfo {
        if (a.legacy_ == null) a.legacy_ = .{ .v = try dyld_legacy_mod.parse(a.arena, a.img, a.limits, a.diags) };
        return if (a.legacy_.?.v) |*v| v else null;
    }
    pub fn exportsTrie(a: *Analysis) Allocator.Error!?*const dyld_exports_mod.ExportTrie {
        if (a.exports_trie_ == null) a.exports_trie_ = .{ .v = try dyld_exports_mod.parse(a.arena, a.img, a.limits, a.diags) };
        return if (a.exports_trie_.?.v) |*v| v else null;
    }
    pub fn functionStarts(a: *Analysis) Allocator.Error!?*const function_starts_mod.FunctionStarts {
        if (a.function_starts_ == null) a.function_starts_ = .{ .v = try function_starts_mod.parseFunctionStarts(a.arena, a.img, a.limits, a.diags) };
        return if (a.function_starts_.?.v) |*v| v else null;
    }
    pub fn dataInCode(a: *Analysis) Allocator.Error!?*const function_starts_mod.DataInCode {
        if (a.data_in_code_ == null) a.data_in_code_ = .{ .v = try function_starts_mod.parseDataInCode(a.arena, a.img, a.limits, a.diags) };
        return if (a.data_in_code_.?.v) |*v| v else null;
    }
    pub fn fixups(a: *Analysis) Allocator.Error!*const fixups_mod.FixupTable {
        if (a.fixups_ == null) {
            const ch = try a.chained();
            const lg = try a.legacy();
            a.fixups_ = try fixups_mod.build(a.arena, a.img, ch, lg, a.limits, a.diags);
        }
        return &a.fixups_.?;
    }
    pub fn dylibs(a: *Analysis) Allocator.Error![]const imports_mod.DylibRef {
        if (a.dylibs_ == null) a.dylibs_ = try imports_mod.dylibs(a.arena, a.img, a.limits, a.diags);
        return a.dylibs_.?;
    }
    pub fn rpaths(a: *Analysis) Allocator.Error![]const []const u8 {
        if (a.rpaths_ == null) a.rpaths_ = try imports_mod.rpaths(a.arena, a.img, a.limits, a.diags);
        return a.rpaths_.?;
    }
    pub fn imports(a: *Analysis) Allocator.Error!*const imports_mod.ImportTable {
        if (a.imports_ == null) {
            const syms = try a.symbols();
            const fix = try a.fixups();
            const dl = try a.dylibs();
            a.imports_ = try imports_mod.imports(a.arena, a.img, syms, fix, dl, a.limits, a.diags);
        }
        return &a.imports_.?;
    }
    pub fn exports(a: *Analysis) Allocator.Error!*const imports_mod.ExportTable {
        if (a.exports_ == null) {
            const syms = try a.symbols();
            const trie = try a.exportsTrie();
            a.exports_ = try imports_mod.exports(a.arena, a.img, syms, trie, a.limits, a.diags);
        }
        return &a.exports_.?;
    }
    pub fn signature(a: *Analysis) Allocator.Error!?*const blobs_mod.Signature {
        if (a.signature_ == null) a.signature_ = .{ .v = try blobs_mod.parse(a.arena, a.img, a.limits, a.diags) };
        return if (a.signature_.?.v) |*v| v else null;
    }
    pub fn verification(a: *Analysis) Allocator.Error!?*const hashes_mod.Verification {
        if (a.verification_ == null) {
            var v: ?hashes_mod.Verification = null;
            if (try a.signature()) |sig| if (sig.cd()) |cd| {
                v = hashes_mod.verify(a.img, sig, cd, a.limits, a.diags);
                if (a.options.bundle_path) |bp| {
                    const files = try bundle_mod.sealedFiles(a.arena, a.io, bp, a.limits);
                    hashes_mod.verifyBundleSlots(&v.?, cd, files, a.diags);
                }
            };
            a.verification_ = .{ .v = v };
        }
        return if (a.verification_.?.v) |*v| v else null;
    }
    pub fn requirements(a: *Analysis) Allocator.Error!?*const requirements_mod.RequirementSet {
        if (a.requirements_ == null) {
            var v: ?requirements_mod.RequirementSet = null;
            if (try a.signature()) |sig| if (sig.requirements) |bytes| {
                v = try requirements_mod.parseSet(a.arena, bytes, a.limits, a.diags);
            };
            a.requirements_ = .{ .v = v };
        }
        return if (a.requirements_.?.v) |*v| v else null;
    }
    pub fn entitlements(a: *Analysis) Allocator.Error!*const entitlements_mod.Entitlements {
        if (a.entitlements_ == null) {
            if (try a.signature()) |sig| {
                a.entitlements_ = try entitlements_mod.parse(a.arena, sig, a.limits, a.diags);
            } else a.entitlements_ = .empty;
        }
        return &a.entitlements_.?;
    }
    pub fn cms(a: *Analysis) Allocator.Error!?*const cms_mod.Cms {
        if (a.cms_ == null) {
            var v: ?cms_mod.Cms = null;
            if (try a.signature()) |sig| if (sig.cms) |bytes| {
                v = try cms_mod.parse(a.arena, bytes, a.limits, a.diags);
            };
            a.cms_ = .{ .v = v };
        }
        return if (a.cms_.?.v) |*v| v else null;
    }
    /// `.available=false` when options.security is false or the build lacks Security.
    pub fn security(a: *Analysis) Allocator.Error!*const security_mod.Verdict {
        if (a.security_ == null) {
            if (!build_options.have_security) {
                a.security_ = security_mod.unavailable("built without Security.framework (-Dsecurity=false)", a.file.path);
            } else if (!a.options.security) {
                a.security_ = security_mod.unavailable("--no-security", a.file.path);
            } else {
                a.security_ = try security_mod.evaluate(a.arena, a.file.path_z, .{ .revocation = a.options.network, .network = a.options.network, .all_archs = true, .is_directory = a.file.is_dir }, a.diags);
            }
        }
        return &a.security_.?;
    }
    pub fn xattrs(a: *Analysis) Allocator.Error!*const xattr_mod.Xattrs {
        if (a.xattrs_ == null) a.xattrs_ = try xattr_mod.read(a.arena, a.file.path_z, a.diags);
        return &a.xattrs_.?;
    }
    pub fn resolutions(a: *Analysis) Allocator.Error![]const dylib_resolve_mod.Resolution {
        if (a.resolutions_ == null) {
            if (!a.options.resolve_deps) {
                a.resolutions_ = &.{};
            } else {
                // Rebuild the core Dylib records from the load commands (imports_mod.DylibRef is the analyst view).
                var list: std.ArrayList(loadcmds.Dylib) = .empty;
                var ordinal: u16 = 0;
                for (a.img.cmds) |c| if (loadcmds.isDylibLoadCmd(c.cmd) and ordinal < a.limits.max_dylibs) {
                    ordinal += 1;
                    if (try loadcmds.decodeDylib(a.arena, c, ordinal, a.diags)) |d| try list.append(a.arena, d);
                };
                a.resolutions_ = try dylib_resolve_mod.resolveAll(a.arena, a.io, a.file.path, list.items, try a.rpaths(), a.diags);
            }
        }
        return a.resolutions_.?;
    }
    pub fn objc(a: *Analysis) Allocator.Error!?*const objc_mod.ObjcInfo {
        if (a.objc_ == null) {
            if (!objc_mod.hasObjc(a.img)) return null;
            const fix = try a.fixups();
            const syms = try a.symbols();
            a.objc_ = try objc_mod.parse(a.arena, a.img, fix, syms, a.limits, a.diags);
        }
        return &a.objc_.?;
    }
    /// Re-runs when `opts` differ from the memoized options.
    pub fn strings(a: *Analysis, opts: strings_mod.Options) Allocator.Error!*const strings_mod.StringsResult {
        if (a.strings_ == null or !std.meta.eql(a.strings_opts_.?, opts)) {
            const fix = try a.fixups();
            a.strings_ = try strings_mod.extract(a.arena, a.img, fix, opts, a.limits, a.diags);
            a.strings_opts_ = opts;
        }
        return &a.strings_.?;
    }
    pub fn entropy(a: *Analysis) Allocator.Error!*const entropy_mod.EntropyReport {
        if (a.entropy_ == null) {
            var enc: ?loadcmds.EncryptionInfo = null;
            for (a.img.cmds) |c| if (c.lc() == .ENCRYPTION_INFO or c.lc() == .ENCRYPTION_INFO_64) {
                enc = loadcmds.decodeEncryptionInfo(c);
            };
            const syms = try a.symbols();
            const imp = try a.imports();
            a.entropy_ = try entropy_mod.analyze(a.arena, a.img, .{ .symbol_count = @intCast(syms.symbols.len), .import_count = @intCast(imp.imports.len), .encryption = enc, .entry_vm = a.img.entryVm() });
        }
        return &a.entropy_.?;
    }
    pub fn functions(a: *Analysis) Allocator.Error!*const functions_mod.FunctionTable {
        if (a.functions_ == null) {
            const syms = try a.symbols();
            const index = try a.addressIndex();
            const starts = try a.functionStarts();
            const trie = try a.exportsTrie();
            const oc = try a.objc();
            a.functions_ = try functions_mod.discover(a.arena, a.img, .{ .syms = syms, .index = index, .starts = starts, .trie = trie, .objc = oc }, a.limits, a.diags);
        }
        return &a.functions_.?;
    }
    pub fn stubs(a: *Analysis) Allocator.Error!*const symbolize_mod.StubTable {
        if (a.stubs_ == null) {
            const syms = try a.symbols();
            const fix = try a.fixups();
            const oc = try a.objc();
            a.stubs_ = try symbolize_mod.resolveStubs(a.arena, a.img, syms, fix, oc, a.limits, a.diags);
        }
        return &a.stubs_.?;
    }
    pub fn annotateCtx(a: *Analysis) Allocator.Error!symbolize_mod.AnnotateCtx {
        return .{
            .img = a.img,
            .syms = try a.symbols(),
            .index = try a.addressIndex(),
            .fix = try a.fixups(),
            .stubs = try a.stubs(),
            .funcs = try a.functions(),
            .objc = try a.objc(),
            .strings = try a.strings(.{}),
            .otool_compat = a.options.engine.otool_compat,
        };
    }
    /// gpa-owned Capstone handle (when available); freed in deinit.
    pub fn engine(a: *Analysis) engine_mod.OpenError!*engine_mod.Engine {
        if (a.engine_ == null) a.engine_ = try engine_mod.Engine.init(a.img.arch.name, a.options.engine);
        return &a.engine_.?;
    }
};
