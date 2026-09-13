//! tests/golden/dyld.rows.zig — golden rows contributed by WP2 (imported by tests/golden_tests.zig).
//! The `--otool-compat` rows ARE the analyst-output contract: they diff machre's text against the
//! `nm -m`, `nm -a` and `dyld_info -fixups/-fixup_chains/-exports/-imports/-function_starts` sections of
//! tests/corpus/truth/<fixture>.txt.
const golden = @import("../golden_tests.zig");

const nm_m = "/usr/bin/nm -m";
const nm_a = "/usr/bin/nm -a";
const di_fixups = "/usr/bin/dyld_info -fixups";
const di_chains = "/usr/bin/dyld_info -fixup_chains";
const di_exports = "/usr/bin/dyld_info -exports";
const di_imports = "/usr/bin/dyld_info -imports";
const di_fstarts = "/usr/bin/dyld_info -function_starts";

/// `nm` shows a single slice for a fat file that contains the host architecture exactly, so the nm rows
/// never pass --all-archs unless the tool printed per-arch banners (bin-ls: arm64e != host arm64).
fn nmRows(comptime fixture: []const u8, comptime extra: []const []const u8) [2]golden.Row {
    const m = [_][]const u8{ "symbols", "--mode=nm-m", "--otool-compat" } ++ extra[0..extra.len].*;
    const a = [_][]const u8{ "symbols", "--mode=nm-a", "--otool-compat" } ++ extra[0..extra.len].*;
    return .{
        .{ .fixture = fixture, .argv = &m, .truth_cmd = nm_m, .compare = .same_lines },
        .{ .fixture = fixture, .argv = &a, .truth_cmd = nm_a, .compare = .same_lines },
    };
}

/// `dyld_info` always prints every slice of a fat file, so these rows pass --all-archs for fat fixtures.
fn dyldRows(comptime fixture: []const u8, comptime extra: []const []const u8) [5]golden.Row {
    const chains = [_][]const u8{ "dyld", "--chains", "--otool-compat" } ++ extra[0..extra.len].*;
    const fixups = [_][]const u8{ "dyld", "--fixups", "--otool-compat" } ++ extra[0..extra.len].*;
    const fstarts = [_][]const u8{ "dyld", "--function-starts", "--otool-compat" } ++ extra[0..extra.len].*;
    const exports = [_][]const u8{ "exports", "--otool-compat" } ++ extra[0..extra.len].*;
    const imports = [_][]const u8{ "imports", "--otool-compat" } ++ extra[0..extra.len].*;
    return .{
        .{ .fixture = fixture, .argv = &chains, .truth_cmd = di_chains, .compare = .same_lines },
        .{ .fixture = fixture, .argv = &fixups, .truth_cmd = di_fixups, .compare = .same_line_set },
        .{ .fixture = fixture, .argv = &fstarts, .truth_cmd = di_fstarts, .compare = .same_lines },
        .{ .fixture = fixture, .argv = &exports, .truth_cmd = di_exports, .compare = .same_line_set },
        .{ .fixture = fixture, .argv = &imports, .truth_cmd = di_imports, .compare = .same_line_set },
    };
}

/// Same as `dyldRows` minus the `-fixups` row (hello-zig: `dyld_info` mislabels the 2nd and 3rd bind of a
/// BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB run in __thread_vars — the opcode stream names
/// `__tlv_bootstrap` three times; the tool prints the first lazy-stream symbol instead).
fn dyldRowsNoFixups(comptime fixture: []const u8) [4]golden.Row {
    const all = dyldRows(fixture, &.{});
    return .{ all[0], all[2], all[3], all[4] };
}

const thin = [_][]const u8{};
const all_archs = [_][]const u8{"--all-archs"};

pub const rows: []const golden.Row = &(
// ---- otool-compat parity, thin fixtures ----
nmRows("hello-c", &thin) ++ dyldRows("hello-c", &thin) ++
    nmRows("hello-x86_64", &thin) ++ dyldRows("hello-x86_64", &thin) ++
    nmRows("hello-objc", &thin) ++ dyldRows("hello-objc", &thin) ++
    nmRows("libhello.dylib", &thin) ++ dyldRows("libhello.dylib", &thin) ++
    nmRows("hello-usedylib", &thin) ++ dyldRows("hello-usedylib", &thin) ++
    nmRows("hello-adhoc", &thin) ++ dyldRows("hello-adhoc", &thin) ++
    nmRows("hello-entitled", &thin) ++ dyldRows("hello-entitled", &thin) ++
    nmRows("hello-unsigned", &thin) ++ dyldRows("hello-unsigned", &thin) ++
    nmRows("high-entropy", &thin) ++ dyldRows("high-entropy", &thin) ++
    nmRows("fake-packed", &thin) ++ dyldRows("fake-packed", &thin) ++
    nmRows("fake-upx", &thin) ++ dyldRows("fake-upx", &thin) ++
    nmRows("hello-quarantined", &thin) ++ dyldRows("hello-quarantined", &thin) ++
    nmRows("legacy-bind", &thin) ++ dyldRows("legacy-bind", &thin) ++
    nmRows("hello-zig", &thin) ++ dyldRowsNoFixups("hello-zig") ++
    nmRows("Hello.app", &thin) ++ dyldRows("Hello.app", &thin) ++
    // ---- fat fixtures: nm picks the host slice, dyld_info prints both ----
    nmRows("hello-fat", &thin) ++ dyldRows("hello-fat", &all_archs) ++
    nmRows("bin-ls", &all_archs) ++ dyldRows("bin-ls", &all_archs) ++
    [_]golden.Row{
        // ---- reviewed byte-exact snapshots of machre's own rendering ----
        .{ .fixture = "hello-c", .argv = &.{ "symbols", "--mode=machre", "--limit=0" }, .golden_file = "hello-c.symbols.txt" },
        .{ .fixture = "legacy-bind", .argv = &.{ "symbols", "--mode=machre", "--limit=0", "--indirect" }, .golden_file = "legacy-bind.symbols.txt" },
        .{ .fixture = "hello-usedylib", .argv = &.{ "symbols", "--mode=machre", "--limit=0" }, .golden_file = "hello-usedylib.symbols.txt" },
        .{ .fixture = "hello-c", .argv = &.{ "dyld", "--fixups", "--limit=0" }, .golden_file = "hello-c.dyld.fixups.txt" },
        .{ .fixture = "legacy-bind", .argv = &.{ "dyld", "--fixups", "--limit=0" }, .golden_file = "legacy-bind.dyld.fixups.txt" },
        .{ .fixture = "hello-usedylib", .argv = &.{ "dyld", "--fixups", "--limit=0" }, .golden_file = "hello-usedylib.dyld.fixups.txt" },
        .{ .fixture = "hello-c", .argv = &.{ "imports", "--no-resolve" }, .golden_file = "hello-c.imports.txt" },
        .{ .fixture = "legacy-bind", .argv = &.{ "imports", "--no-resolve" }, .golden_file = "legacy-bind.imports.txt" },
        .{ .fixture = "hello-usedylib", .argv = &.{ "imports", "--no-resolve", "--by-dylib" }, .golden_file = "hello-usedylib.imports.txt" },
        .{ .fixture = "hello-c", .argv = &.{"exports"}, .golden_file = "hello-c.exports.txt" },
        .{ .fixture = "legacy-bind", .argv = &.{"exports"}, .golden_file = "legacy-bind.exports.txt" },
        .{ .fixture = "hello-usedylib", .argv = &.{"exports"}, .golden_file = "hello-usedylib.exports.txt" },
        // ---- JSON key inventory (DESIGN §6.3) ----
        .{ .fixture = "hello-c", .argv = &.{ "symbols", "--json" }, .compare = .json_keys, .json_keys = &.{
            "symbols.symtab.nsyms",        "symbols.symtab.stroff",      "symbols.dysymtab.nindirectsyms", "symbols.counts.defined",
            "symbols.counts.undefined",    "symbols.symbols.0.index",    "symbols.symbols.0.name",         "symbols.symbols.0.nm",
            "symbols.symbols.0.type",      "symbols.symbols.0.type_raw", "symbols.symbols.0.sect",         "symbols.symbols.0.desc",
            "symbols.symbols.0.value",     "symbols.symbols.0.external", "symbols.symbols.0.weak_ref",     "symbols.symbols.0.library_ordinal",
            "symbols.indirect.0.index",    "symbols.indirect.0.symbol",  "symbols.indirect.0.section",     "symbols.lossy_strings",
        } },
        .{ .fixture = "hello-c", .argv = &.{ "dyld", "--json" }, .compare = .json_keys, .json_keys = &.{
            "dyld.chained_fixups.header.fixups_version", "dyld.chained_fixups.header.imports_count", "dyld.chained_fixups.imports.0.name",
            "dyld.chained_fixups.imports.0.library",     "dyld.chained_fixups.starts.0.seg_index",   "dyld.chained_fixups.starts.0.pointer_format_name",
            "dyld.chained_fixups.starts.0.page_starts",  "dyld.chained_fixups.fixups.0.address",     "dyld.chained_fixups.fixups.0.kind",
            "dyld.chained_fixups.fixups.0.symbol",       "dyld.chained_fixups.fixups.0.raw",         "dyld.exports_trie.count",
            "dyld.function_starts.addresses",            "dyld.data_in_code.dataoff",
        } },
        .{ .fixture = "legacy-bind", .argv = &.{ "dyld", "--json" }, .compare = .json_keys, .json_keys = &.{
            "dyld.dyld_info.cmd.rebase_off",   "dyld.dyld_info.cmd.lazy_bind_size", "dyld.dyld_info.rebases.0.address",
            "dyld.dyld_info.binds.0.symbol",   "dyld.dyld_info.binds.0.library",    "dyld.dyld_info.lazy_binds.0.symbol",
            "dyld.dyld_info.weak_binds",       "dyld.dyld_info.threaded",           "dyld.function_starts.addresses",
        } },
        .{ .fixture = "hello-c", .argv = &.{ "imports", "--json" }, .compare = .json_keys, .json_keys = &.{
            "imports.imports.0.symbol",   "imports.imports.0.library", "imports.imports.0.ordinal", "imports.imports.0.weak",
            "imports.imports.0.lazy",     "imports.imports.0.locations", "imports.imports.0.first_location", "imports.imports.0.source",
            "imports.dylibs.0.path",      "imports.dylibs.0.short_name", "imports.rpaths",           "imports.resolution",
        } },
        .{ .fixture = "hello-c", .argv = &.{ "exports", "--json" }, .compare = .json_keys, .json_keys = &.{
            "exports.exports.0.name", "exports.exports.0.address", "exports.exports.0.offset", "exports.exports.0.kind",
            "exports.exports.0.weak", "exports.exports.0.reexport", "exports.exports.0.resolver", "exports.source",
        } },
        .{ .fixture = "hello-usedylib", .argv = &.{ "imports", "--json" }, .compare = .json_keys, .json_keys = &.{ "imports.rpaths.0", "imports.dylibs.0.short_name" } },
        .{ .fixture = "hello-zig", .argv = &.{ "dyld", "--json", "--opcodes" }, .compare = .json_keys, .json_keys = &.{ "dyld.dyld_info.binds.0.stream_offset", "dyld.dyld_info.lazy_binds.0.stream_offset" } },
    });
