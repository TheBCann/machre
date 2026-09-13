//! tests/facts/dyld.zig — corpus fact tests for WP2 (symbols, chained fixups, export trie, legacy opcode
//! streams, function starts, imports/exports) asserted against truth/summary.json and truth/*.txt sections.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const truth = @import("../truth.zig");
const Summary = helpers.Summary;

const Analysis = machre.analysis.analysis.Analysis;
const symbols_mod = machre.macho.symbols;
const imports_mod = machre.macho.imports;

const Ctx = struct {
    arena: std.mem.Allocator,
    name: []const u8,
    slice: usize,
    fn fail(c: *const Ctx, comptime what: []const u8, args: anytype) error{FactMismatch} {
        std.debug.print("[{s} slice {d}] " ++ what ++ "\n", .{ c.name, c.slice } ++ args);
        return error.FactMismatch;
    }
};

fn expectInt(c: *const Ctx, what: []const u8, want: ?i64, got: i64) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected {d}, got {d}", .{ what, w, got });
}
fn expectStr(c: *const Ctx, what: []const u8, want: ?[]const u8, got: []const u8) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (!std.mem.eql(u8, w, got)) return c.fail("{s}: expected '{s}', got '{s}'", .{ what, w, got });
}
fn expectBool(c: *const Ctx, what: []const u8, want: ?bool, got: bool) !void {
    const w = want orelse return c.fail("{s}: summary value missing", .{what});
    if (w != got) return c.fail("{s}: expected {}, got {}", .{ what, w, got });
}
/// Set equality between a summary string array and the first `want.len` entries of `got`.
fn expectSet(c: *const Ctx, what: []const u8, want: []const []const u8, got: []const []const u8) !void {
    if (want.len > got.len) return c.fail("{s}: summary lists {d} names, only {d} produced", .{ what, want.len, got.len });
    for (want) |w| {
        var found = false;
        for (got) |g| if (std.mem.eql(u8, w, g)) {
            found = true;
        };
        if (!found) return c.fail("{s}: '{s}' missing from the parsed set", .{ what, w });
    }
}

fn nameList(arena: std.mem.Allocator, comptime T: type, items: []const T, comptime field: []const u8) ![]const []const u8 {
    const out = try arena.alloc([]const u8, items.len);
    for (items, 0..) |it, i| out[i] = @field(it, field);
    return out;
}

fn lessName(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn checkSlice(c: *const Ctx, an: *Analysis, sl: std.json.Value) !void {
    const a = c.arena;
    const img = an.img;

    // ---- symbols ----
    const t = try an.symbols();
    const want_sym = Summary.object(sl, "symbols") orelse return c.fail("summary has no symbols object", .{});
    try expectInt(c, "symbols.total", Summary.int(want_sym, "total"), @intCast(t.symbols.len));
    try expectInt(c, "symbols.defined", Summary.int(want_sym, "defined"), t.counts.defined);
    try expectInt(c, "symbols.undefined", Summary.int(want_sym, "undefined"), t.counts.undefined);
    try expectInt(c, "symbols.stabs", Summary.int(want_sym, "stabs"), t.counts.stabs);
    try expectInt(c, "symbols.external", Summary.int(want_sym, "external"), t.counts.external);
    try expectInt(c, "symbols.local", Summary.int(want_sym, "local"), t.counts.local);

    var defined: std.ArrayList([]const u8) = .empty;
    var undef: std.ArrayList([]const u8) = .empty;
    for (t.symbols) |s| {
        if (s.isStab() or s.name.len == 0) continue;
        switch (s.kind()) {
            .section, .absolute, .indirect => try defined.append(a, s.name),
            .undefined, .prebound => try undef.append(a, s.name),
            else => {},
        }
    }
    try expectSet(c, "defined_symbols_first20", try Summary.strings(a, sl, "defined_symbols_first20"), defined.items);
    try expectSet(c, "undefined_symbols_first20", try Summary.strings(a, sl, "undefined_symbols_first20"), undef.items);

    // ---- which dyld data the slice carries ----
    const has_chained = img.findCmd(.DYLD_CHAINED_FIXUPS) != null;
    const has_dyld_info = img.findCmd(.DYLD_INFO_ONLY) != null or img.findCmd(.DYLD_INFO) != null;
    const has_trie_cmd = img.findCmd(.DYLD_EXPORTS_TRIE) != null;
    try expectBool(c, "has_chained_fixups", Summary.boolean(sl, "has_chained_fixups"), has_chained);
    try expectBool(c, "has_dyld_info", Summary.boolean(sl, "has_dyld_info"), has_dyld_info);
    try expectBool(c, "has_exports_trie", Summary.boolean(sl, "has_exports_trie"), has_trie_cmd);

    // ---- LC_DYLD_INFO offsets ----
    if (Summary.object(sl, "dyld_info")) |want_di| {
        const lg = (try an.legacy()) orelse return c.fail("summary has dyld_info but the parser returned null", .{});
        try expectInt(c, "dyld_info.rebase_off", Summary.int(want_di, "rebase_off"), lg.cmd.rebase_off);
        try expectInt(c, "dyld_info.rebase_size", Summary.int(want_di, "rebase_size"), lg.cmd.rebase_size);
        try expectInt(c, "dyld_info.bind_off", Summary.int(want_di, "bind_off"), lg.cmd.bind_off);
        try expectInt(c, "dyld_info.bind_size", Summary.int(want_di, "bind_size"), lg.cmd.bind_size);
        try expectInt(c, "dyld_info.weak_bind_off", Summary.int(want_di, "weak_bind_off"), lg.cmd.weak_bind_off);
        try expectInt(c, "dyld_info.weak_bind_size", Summary.int(want_di, "weak_bind_size"), lg.cmd.weak_bind_size);
        try expectInt(c, "dyld_info.lazy_bind_off", Summary.int(want_di, "lazy_bind_off"), lg.cmd.lazy_bind_off);
        try expectInt(c, "dyld_info.lazy_bind_size", Summary.int(want_di, "lazy_bind_size"), lg.cmd.lazy_bind_size);
        try expectInt(c, "dyld_info.export_off", Summary.int(want_di, "export_off"), lg.cmd.export_off);
        try expectInt(c, "dyld_info.export_size", Summary.int(want_di, "export_size"), lg.cmd.export_size);
    } else if (try an.legacy() != null) return c.fail("parser produced dyld_info but the summary has none", .{});

    // ---- chained fixups header + starts ----
    if (Summary.object(sl, "chained_fixups")) |want_cf| {
        const ch = (try an.chained()) orelse return c.fail("summary has chained_fixups but the parser returned null", .{});
        try expectInt(c, "chained.fixups_version", Summary.int(want_cf, "fixups_version"), ch.header.fixups_version);
        try expectInt(c, "chained.starts_offset", Summary.int(want_cf, "starts_offset"), ch.header.starts_offset);
        try expectInt(c, "chained.imports_offset", Summary.int(want_cf, "imports_offset"), ch.header.imports_offset);
        try expectInt(c, "chained.symbols_offset", Summary.int(want_cf, "symbols_offset"), ch.header.symbols_offset);
        try expectInt(c, "chained.imports_count", Summary.int(want_cf, "imports_count"), ch.header.imports_count);
        try expectInt(c, "chained.imports_format", Summary.int(want_cf, "imports_format"), ch.header.imports_format);
        try expectInt(c, "chained.symbols_format", Summary.int(want_cf, "symbols_format"), ch.header.symbols_format);
        try expectInt(c, "chained.seg_count", Summary.int(want_cf, "seg_count"), ch.seg_count_declared);
        const want_starts = Summary.array(want_cf, "starts") orelse &.{};
        if (want_starts.len != ch.starts.len) return c.fail("chained.starts: {d} vs {d}", .{ want_starts.len, ch.starts.len });
        for (want_starts, ch.starts) |ws, s| {
            try expectInt(c, "starts.seg_index", Summary.int(ws, "seg_index"), s.seg_index);
            try expectInt(c, "starts.page_size", Summary.int(ws, "page_size"), s.page_size);
            try expectInt(c, "starts.pointer_format", Summary.int(ws, "pointer_format"), s.pointer_format);
            try expectInt(c, "starts.segment_offset", Summary.int(ws, "segment_offset"), @intCast(s.segment_offset));
            try expectInt(c, "starts.page_count", Summary.int(ws, "page_count"), s.page_count);
            if (s.page_starts.len != s.page_count) return c.fail("starts.page_starts len {d} != page_count {d}", .{ s.page_starts.len, s.page_count });
        }
        if (ch.truncated) return c.fail("chained fixups reported truncated on a healthy fixture", .{});
    } else if (try an.chained() != null) return c.fail("parser produced chained fixups but the summary has none", .{});

    // ---- function starts / data in code ----
    if (Summary.object(sl, "function_starts")) |want_fs| {
        const fs = (try an.functionStarts()) orelse return c.fail("summary has function_starts but the parser returned null", .{});
        try expectInt(c, "function_starts.dataoff", Summary.int(want_fs, "dataoff"), fs.dataoff);
        try expectInt(c, "function_starts.datasize", Summary.int(want_fs, "datasize"), fs.datasize);
        if (fs.truncated) return c.fail("function starts reported truncated", .{});
    }
    if (Summary.object(sl, "data_in_code")) |want_dic| {
        const dic = (try an.dataInCode()) orelse return c.fail("summary has data_in_code but the parser returned null", .{});
        try expectInt(c, "data_in_code.dataoff", Summary.int(want_dic, "dataoff"), dic.dataoff);
        try expectInt(c, "data_in_code.datasize", Summary.int(want_dic, "datasize"), dic.datasize);
    }

    // ---- exports ----
    const trie = try an.exportsTrie();
    const ex = try an.exports();
    try expectInt(c, "exports_count", Summary.int(sl, "exports_count"), @intCast(ex.exports.len));
    try expectSet(c, "exports_first20", try Summary.strings(a, sl, "exports_first20"), try nameList(a, imports_mod.ExportEntry, ex.exports, "name"));
    if (trie) |tr| if (tr.truncated) return c.fail("export trie reported truncated", .{});

    // ---- imports ----
    // summary.json scrapes `dyld_info -imports` with a regex that cannot match the "[weak-import]"
    // annotation, so its counts and name lists omit weak imports; compare against the same subset.
    const im = try an.imports();
    const dl = try an.dylibs();
    var non_weak: u32 = 0;
    for (im.imports) |e| {
        if (!e.weak) non_weak += 1;
    }
    try expectInt(c, "imports_count", Summary.int(sl, "imports_count"), non_weak);
    const want_imports = Summary.array(sl, "imports_first20") orelse &.{};
    for (want_imports) |w| {
        const wsym = Summary.str(w, "symbol") orelse return c.fail("imports_first20 entry without a symbol", .{});
        const wlib = Summary.str(w, "dylib") orelse "";
        var found = false;
        for (im.imports) |got| {
            if (!std.mem.eql(u8, got.symbol, wsym)) continue;
            const lib: []const u8 = if (got.dylib) |d| d.short_name else "";
            if (!std.mem.eql(u8, lib, wlib)) return c.fail("imports_first20: {s} attributed to '{s}', expected '{s}'", .{ wsym, lib, wlib });
            found = true;
        }
        if (!found) return c.fail("imports_first20: '{s}' missing from the import table", .{wsym});
    }

    // ---- nm -m style undefined list (sorted by name) ----
    var und_pairs: std.ArrayList(struct { name: []const u8, lib: []const u8 }) = .empty;
    for (t.symbols) |s| {
        if (s.isStab() or s.name.len == 0) continue;
        if (s.kind() != .undefined and s.kind() != .prebound) continue;
        if (s.isWeakRef()) continue; // `nm -m` prints "weak external"; the generator's regex skips those lines
        const ord = s.libraryOrdinal();
        const lib: []const u8 = if (ord != 0 and ord <= dl.len) dl[ord - 1].short_name else "";
        try und_pairs.append(a, .{ .name = s.name, .lib = lib });
    }
    const Pair = @TypeOf(und_pairs.items[0..1].ptr[0]);
    std.mem.sort(Pair, und_pairs.items, {}, struct {
        fn lt(_: void, x: Pair, y: Pair) bool {
            return std.mem.order(u8, x.name, y.name) == .lt;
        }
    }.lt);
    const want_nm = Summary.array(sl, "nm_undefined_first20") orelse &.{};
    if (want_nm.len > und_pairs.items.len) return c.fail("nm_undefined_first20 lists {d}, parser produced {d}", .{ want_nm.len, und_pairs.items.len });
    for (want_nm, und_pairs.items[0..want_nm.len]) |w, got| {
        try expectStr(c, "nm_undefined_first20.symbol", Summary.str(w, "symbol"), got.name);
        try expectStr(c, "nm_undefined_first20.dylib", Summary.str(w, "dylib"), got.lib);
    }
    if (Summary.int(sl, "nm_undefined_count")) |n| try expectInt(c, "nm_undefined_count", n, @intCast(und_pairs.items.len));
}

fn checkFixture(gpa: std.mem.Allocator, io: std.Io, summary: *const Summary, name: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const fx = summary.fixtureNamed(name) orelse return error.SkipZigTest;
    const path = try helpers.summaryFixturePath(a, name);
    var file = machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer file.deinit(gpa);
    const want_slices = Summary.array(fx, "slices") orelse &.{};
    var failures: usize = 0;
    for (want_slices, 0..) |sl, i| {
        const c: Ctx = .{ .arena = a, .name = name, .slice = i };
        const r = file.sliceReader(i) orelse return c.fail("sliceReader({d})", .{i});
        const img = try machre.Image.parse(a, r, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags);
        var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
        defer an.deinit();
        checkSlice(&c, &an, sl) catch |e| switch (e) {
            error.FactMismatch => failures += 1,
            else => return e,
        };
    }
    if (failures != 0) return error.FactMismatch;
}

test "facts/dyld: symbols, chained fixups, export trie, legacy streams and imports for every summary.json fixture" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var summary = try helpers.loadSummary(gpa, io);
    defer summary.deinit();
    const names = [_][]const u8{ "hello-c", "hello-x86_64", "hello-fat", "hello-objc", "libhello.dylib", "hello-usedylib", "hello-adhoc", "hello-entitled", "hello-unsigned", "high-entropy", "fake-packed", "fake-upx", "hello-zig", "legacy-bind", "hello-quarantined", "Hello.app", "bin-ls" };
    var failures: usize = 0;
    for (names) |n| checkFixture(gpa, io, &summary, n) catch |e| switch (e) {
        error.SkipZigTest => {},
        else => failures += 1,
    };
    if (failures != 0) return error.FactsFailed;
}

test "facts/dyld: hello-c fixups, function starts and import attribution (DESIGN 10.3)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const path = try helpers.fixturePath(a, "hello-c");
    var file = try machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags);
    defer file.deinit(gpa);
    const img = try machre.Image.parse(a, file.sliceReader(0).?, 0, 0, &machre.Limits.default, &diags);
    var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
    defer an.deinit();

    const ch = (try an.chained()).?;
    try std.testing.expectEqual(@as(u32, 0), ch.header.fixups_version);
    try std.testing.expectEqual(@as(u32, 32), ch.header.starts_offset);
    try std.testing.expectEqual(@as(u32, 104), ch.header.imports_offset);
    try std.testing.expectEqual(@as(u32, 128), ch.header.symbols_offset);
    try std.testing.expectEqual(@as(u32, 6), ch.header.imports_count);
    try std.testing.expectEqual(@as(u32, 1), ch.header.imports_format);
    try std.testing.expectEqual(@as(u32, 0), ch.header.symbols_format);
    try std.testing.expectEqual(@as(usize, 2), ch.starts.len);
    try std.testing.expectEqual(@as(u32, 2), ch.starts[0].seg_index);
    try std.testing.expectEqual(@as(u32, 3), ch.starts[1].seg_index);
    try std.testing.expectEqual(@as(u16, 16384), ch.starts[0].page_size);
    try std.testing.expectEqual(@as(u16, 6), ch.starts[0].pointer_format);

    const fix = try an.fixups();
    try std.testing.expectEqual(machre.macho.fixups.Source.chained, fix.source);
    try std.testing.expectEqual(@as(u32, 6), fix.counts.binds);
    try std.testing.expectEqual(@as(u32, 1), fix.counts.rebases);
    try std.testing.expectEqual(@as(u32, 0), fix.counts.auth_binds);
    const rebase = fix.at(0x100008008).?;
    try std.testing.expectEqual(@as(u64, 0x100000668), rebase.target);
    try std.testing.expectEqualStrings("___snprintf_chk", fix.bindName(0x100004000).?);
    try std.testing.expectEqualStrings("_strcmp", fix.bindName(0x100004028).?);

    const fs = (try an.functionStarts()).?;
    try std.testing.expectEqual(@as(u32, 49472), fs.dataoff);
    try std.testing.expectEqual(@as(u32, 8), fs.datasize);
    try std.testing.expectEqualSlices(u64, &.{ 0x1000004F8, 0x100000524, 0x10000060C }, fs.addrs);

    const dic = (try an.dataInCode()).?;
    try std.testing.expectEqual(@as(u32, 0), dic.datasize);
    try std.testing.expectEqual(@as(usize, 0), dic.entries.len);

    const im = try an.imports();
    try std.testing.expectEqual(@as(usize, 6), im.imports.len);
    for (im.imports) |e| {
        try std.testing.expectEqualStrings("libSystem", e.dylib.?.short_name);
        try std.testing.expectEqual(@as(i32, 1), e.ordinal);
        try std.testing.expectEqual(imports_mod.ImportSource.chained, e.source);
        try std.testing.expectEqual(@as(u32, 1), e.locations);
    }
    const ix = try an.addressIndex();
    const syms = try an.symbols();
    try std.testing.expectEqualStrings("_main", ix.at(syms, 0x100000524).?.name);
    try std.testing.expectEqual(@as(u64, 4), ix.nearest(syms, 0x100000528).?.delta);
    try std.testing.expectEqual(@as(u32, 0), syms.lossy_names);
    try std.testing.expectEqual(@as(usize, 11), syms.indirect.len);
}

test "facts/dyld: legacy-bind opcode streams (4 non-lazy binds, lazy binds past DONE, dyld_stub_binder)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var diags = machre.Diagnostics.init(a, 64);
    const path = try helpers.fixturePath(a, "legacy-bind");
    var file = try machre.LoadedFile.load(gpa, a, io, path, &machre.Limits.default, &diags);
    defer file.deinit(gpa);
    const img = try machre.Image.parse(a, file.sliceReader(0).?, 0, 0, &machre.Limits.default, &diags);
    var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
    defer an.deinit();
    const lg = (try an.legacy()).?;
    try std.testing.expect((try an.chained()) == null);
    // non-lazy binds: _puts _printf _malloc _free + ___stack_chk_guard + dyld_stub_binder
    var non_lazy: usize = 0;
    var lazy: usize = 0;
    var saw_binder = false;
    for (lg.binds) |b| {
        switch (b.kind) {
            .lazy => lazy += 1,
            else => non_lazy += 1,
        }
        if (std.mem.eql(u8, b.symbol, "dyld_stub_binder")) saw_binder = true;
    }
    try std.testing.expect(saw_binder);
    try std.testing.expectEqual(@as(usize, 6), non_lazy);
    try std.testing.expectEqual(@as(usize, 4), lazy);
    try std.testing.expect(lg.rebases.len >= 10);
    for ([_][]const u8{ "_puts", "_printf", "_malloc", "_free", "___stack_chk_guard" }) |want| {
        var found = false;
        for (lg.binds) |b| if (std.mem.eql(u8, b.symbol, want)) {
            found = true;
        };
        if (!found) {
            std.debug.print("legacy-bind: bind for {s} not found\n", .{want});
            return error.TestUnexpectedResult;
        }
    }
    // lazy entries keep their stream offset (what __stub_helper pushes) and are strictly increasing
    var last: u32 = 0;
    for (lg.binds) |b| if (b.kind == .lazy) {
        try std.testing.expect(b.stream_offset >= last);
        last = b.stream_offset;
    };
    const fix = try an.fixups();
    try std.testing.expectEqual(machre.macho.fixups.Source.legacy, fix.source);
    try std.testing.expectEqual(@as(u32, 4), fix.counts.lazy);
    // a lazy bind and a rebase share __la_symbol_ptr slot 0; the bind wins in resolveSlot
    switch (fix.resolveSlot(&img, 0x100008000).?) {
        .bind => |f| try std.testing.expectEqualStrings("___stack_chk_fail", f.symbol),
        else => return error.TestUnexpectedResult,
    }
}

test "facts/dyld: bin-ls arm64e has 23 rebases and 90 binds (84 authenticated)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    std.Io.Dir.cwd().access(io, "/bin/ls", .{}) catch return error.SkipZigTest;
    var diags = machre.Diagnostics.init(a, 64);
    var file = machre.LoadedFile.load(gpa, a, io, "/bin/ls", &machre.Limits.default, &diags) catch return error.SkipZigTest;
    defer file.deinit(gpa);
    if (file.sliceCount() < 2) return error.SkipZigTest;
    var found = false;
    for (0..file.sliceCount()) |i| {
        const arch = file.sliceArch(i) orelse continue;
        if (arch.name != .arm64e) continue;
        found = true;
        const img = try machre.Image.parse(a, file.sliceReader(i).?, file.sliceOffset(i).?, @intCast(i), &machre.Limits.default, &diags);
        var an = Analysis.init(gpa, a, io, &file, &img, &machre.Limits.default, &diags, .{ .security = false, .resolve_deps = false });
        defer an.deinit();
        const fix = try an.fixups();
        try std.testing.expectEqual(@as(u32, 23), fix.counts.rebases);
        try std.testing.expectEqual(@as(u32, 90), fix.counts.binds);
        try std.testing.expectEqual(@as(u32, 84), fix.counts.auth_binds);
        try std.testing.expectEqual(machre.macho.dyld_chained.PointerFormat.arm64e, fix.pointer_format.?);
        try std.testing.expectEqualStrings("_humanize_number", fix.bindName(0x100008000).?);
        try std.testing.expectEqualStrings("_tgetent", fix.at(0x100008008).?.symbol);
        try std.testing.expect(fix.at(0x100008008).?.auth != null);
        const fs = (try an.functionStarts()).?;
        try std.testing.expectEqual(@as(usize, 50), fs.addrs.len);
    }
    if (!found) return error.SkipZigTest;
}

test "facts/dyld: nm -m, nm -a and dyld_info sections diff clean against the truth files" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fixtures = [_][]const u8{ "hello-c", "hello-objc", "libhello.dylib", "hello-usedylib", "legacy-bind", "hello-zig" };
    for (fixtures) |name| {
        const secs = try truth.load(a, io, name);
        const path = try helpers.fixturePath(a, name);
        const nm_m = try helpers.runMachre(a, io, &.{ "symbols", "--mode=nm-m", "--otool-compat", path });
        try truth.expectSameLines(truth.find(secs, "/usr/bin/nm -m").?.body, nm_m.out);
        const nm_a = try helpers.runMachre(a, io, &.{ "symbols", "--mode=nm-a", "--otool-compat", path });
        try truth.expectSameLines(truth.find(secs, "/usr/bin/nm -a").?.body, nm_a.out);
        const ex = try helpers.runMachre(a, io, &.{ "exports", "--otool-compat", path });
        try truth.expectSameLineSet(gpa, truth.find(secs, "/usr/bin/dyld_info -exports").?.body, ex.out);
        const im = try helpers.runMachre(a, io, &.{ "imports", "--otool-compat", path });
        try truth.expectSameLineSet(gpa, truth.find(secs, "/usr/bin/dyld_info -imports").?.body, im.out);
        const fs = try helpers.runMachre(a, io, &.{ "dyld", "--function-starts", "--otool-compat", path });
        try truth.expectSameLines(truth.find(secs, "/usr/bin/dyld_info -function_starts").?.body, fs.out);
        const ch = try helpers.runMachre(a, io, &.{ "dyld", "--chains", "--otool-compat", path });
        try truth.expectSameLines(truth.find(secs, "/usr/bin/dyld_info -fixup_chains").?.body, ch.out);
    }
}

test "facts/dyld: symbol names never reach JSON unsanitised" {
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for ([_][]const u8{ "hello-c", "hello-objc", "hello-zig", "legacy-bind" }) |name| {
        const path = try helpers.fixturePath(a, name);
        const r = try helpers.runMachre(a, io, &.{ "symbols", "--json", path });
        try std.testing.expectEqual(@as(u8, 0), r.code);
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, r.out, .{});
        defer parsed.deinit();
        const arch0 = parsed.value.object.get("arches").?.array.items[0];
        const payload = arch0.object.get("symbols").?;
        try std.testing.expect(payload.object.get("lossy_strings").?.integer == 0);
        for (payload.object.get("symbols").?.array.items) |s| {
            const n = s.object.get("name").?;
            try std.testing.expect(n == .string); // never the number-array form
            try std.testing.expect(std.unicode.utf8ValidateSlice(n.string));
        }
    }
}
