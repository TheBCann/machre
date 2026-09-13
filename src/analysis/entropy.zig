//! analysis/entropy.zig — Shannon entropy per segment/section/file + packer/encryption tells.
//! Imports: core/image, core/loadcmds (EncryptionInfo).
const std = @import("std");
const Allocator = std.mem.Allocator;
const image_mod = @import("../core/image.zig");
const Image = image_mod.Image;
const loadcmds = @import("../core/loadcmds.zig");
const EncryptionInfo = loadcmds.EncryptionInfo;

pub const Region = struct { name: []const u8, sectname: ?[]const u8, file_offset: u64, size: u64, entropy: f64, file_fraction: f64 };
pub const TellCode = enum { high_entropy_segment, packer_segment_name, packer_section_name, no_imports_no_symbols, protected_segment, encryption_info, tiny_text_huge_data, entry_outside_text, rwx_segment, rwx_maxprot, nonstandard_segment_order };
pub const PackerTell = struct { code: TellCode, detail: []const u8, weight: u8 };
pub const EntropyReport = struct {
    file: f64,
    segments: []const Region,
    sections: []const Region,
    tells: []const PackerTell,
    pub const empty: EntropyReport = .{ .file = 0, .segments = &.{}, .sections = &.{}, .tells = &.{} };
};
pub const Inputs = struct { symbol_count: u32, import_count: u32, encryption: ?EncryptionInfo, entry_vm: ?u64 };

/// Segment entropy at or above this, covering at least `high_entropy_fraction` of the slice, is a packer tell.
pub const high_entropy_threshold: f64 = 7.0;
pub const high_entropy_fraction: f64 = 0.20;
/// Weight each tell contributes to triage (§4.23); comptime-asserted below 50 like every triage rule.
pub fn tellWeight(code: TellCode) u8 {
    return switch (code) {
        .high_entropy_segment => 30,
        .packer_segment_name => 35,
        .packer_section_name => 30,
        .no_imports_no_symbols => 25,
        .protected_segment => 40,
        .encryption_info => 40,
        .tiny_text_huge_data => 15,
        .entry_outside_text => 20,
        .rwx_segment => 30,
        .rwx_maxprot => 15,
        .nonstandard_segment_order => 10,
    };
}
comptime {
    for (std.enums.values(TellCode)) |c| std.debug.assert(tellWeight(c) < 50);
}

/// Segment names a linker emits; anything else between __TEXT and __LINKEDIT is a layout tell.
const known_segments: []const []const u8 = &.{
    "__PAGEZERO",     "__TEXT",       "__TEXT_EXEC",  "__DATA_CONST", "__DATA",   "__DATA_DIRTY",
    "__AUTH",         "__AUTH_CONST", "__OBJC",       "__OBJC_CONST", "__IMPORT", "__LINKEDIT",
    "__LINKINFO",     "__LLVM",       "__RESTRICT",   "__HIB",        "__KLD",    "__CTF",
    "__PRELINK_TEXT", "__UNICODE",    "__TEXT_CONST",
};

fn isKnownSegment(name: []const u8) bool {
    for (known_segments) |k| if (std.mem.eql(u8, k, name)) return true;
    return false;
}

/// Analyzes file bytes per segment and section and derives the packer/encryption tells.
/// Never fails on malformed input: every range is clamped to the slice through `Reader.subClamped`.
pub fn analyze(arena: Allocator, img: *const Image, in: Inputs) Allocator.Error!EntropyReport {
    const slice_len: u64 = img.r.len();
    const denom: f64 = if (slice_len == 0) 1 else @floatFromInt(slice_len);

    var segs: std.ArrayList(Region) = .empty;
    try segs.ensureTotalCapacity(arena, img.segments.len);
    for (img.segments) |*s| {
        const bytes = regionBytes(img, s.fileoff, s.filesize);
        segs.appendAssumeCapacity(.{
            .name = s.name,
            .sectname = null,
            .file_offset = s.fileoff,
            .size = bytes.len,
            .entropy = shannon(bytes),
            .file_fraction = @as(f64, @floatFromInt(bytes.len)) / denom,
        });
    }
    var sects: std.ArrayList(Region) = .empty;
    try sects.ensureTotalCapacity(arena, img.sections.len);
    for (img.sections) |*s| {
        if (s.isZerofill()) continue;
        const bytes = regionBytes(img, s.offset, s.size);
        sects.appendAssumeCapacity(.{
            .name = s.segname,
            .sectname = s.sectname,
            .file_offset = s.offset,
            .size = bytes.len,
            .entropy = shannon(bytes),
            .file_fraction = @as(f64, @floatFromInt(bytes.len)) / denom,
        });
    }

    var tells: std.ArrayList(PackerTell) = .empty;
    try collectTells(arena, img, in, segs.items, sects.items, &tells);

    return .{
        .file = shannon(img.r.bytes),
        .segments = try segs.toOwnedSlice(arena),
        .sections = try sects.toOwnedSlice(arena),
        .tells = try tells.toOwnedSlice(arena),
    };
}

fn regionBytes(img: *const Image, off: u64, size: u64) []const u8 {
    if (size == 0) return &.{};
    const c = img.r.subClamped(off, size) orelse return &.{};
    return c.r.bytes;
}

fn add(arena: Allocator, list: *std.ArrayList(PackerTell), code: TellCode, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
    try list.append(arena, .{ .code = code, .detail = try std.fmt.allocPrint(arena, fmt, args), .weight = tellWeight(code) });
}

fn collectTells(arena: Allocator, img: *const Image, in: Inputs, segs: []const Region, sects: []const Region, out: *std.ArrayList(PackerTell)) Allocator.Error!void {
    // 1. a high-entropy segment covering a meaningful part of the slice
    for (segs) |r| {
        if (r.entropy >= high_entropy_threshold and r.file_fraction > high_entropy_fraction) {
            try add(arena, out, .high_entropy_segment, "segment {s} entropy {d:.3} bits/byte over {d:.1}% of the slice ({d} bytes)", .{ r.name, r.entropy, r.file_fraction * 100, r.size });
        }
    }
    // 2./3. known packer segment / section names
    for (img.segments) |*s| {
        if (packerName(s.name)) |p| try add(arena, out, .packer_segment_name, "segment named {s} ({s} marker) at LC index {d}", .{ s.name, p, s.index });
    }
    for (img.sections) |*s| {
        if (packerName(s.sectname)) |p| try add(arena, out, .packer_section_name, "section {s},{s} ({s} marker)", .{ s.segname, s.sectname, p });
    }
    // 4. nothing to link against and nothing to name: a stripped, dependency-free image
    if (in.symbol_count == 0 and in.import_count == 0 and declaredSymbolCount(img) == 0 and dylibCount(img) == 0) {
        try add(arena, out, .no_imports_no_symbols, "no symbol table entries, no imports and no LC_LOAD_DYLIB", .{});
    }
    // 5. SG_PROTECTED_VERSION_1
    for (img.segments) |*s| {
        if (s.isProtected()) try add(arena, out, .protected_segment, "segment {s} has SG_PROTECTED_VERSION_1 (encrypted)", .{s.name});
    }
    // 6. LC_ENCRYPTION_INFO(_64) with cryptid != 0
    if (in.encryption orelse encryptionFromImage(img)) |e| {
        if (e.cryptid != 0) try add(arena, out, .encryption_info, "LC_ENCRYPTION_INFO cryptid {d} over {d} bytes at offset {d}", .{ e.cryptid, e.cryptsize, e.cryptoff });
    }
    // 7. a token __TEXT in front of a large writable payload
    var text_size: u64 = 0;
    var writable: u64 = 0;
    for (img.segments, 0..) |*s, i| {
        const r = segs[i];
        if (std.mem.eql(u8, s.name, "__TEXT")) text_size += r.size;
        if (s.initprot & 2 != 0) writable += r.size;
    }
    if (writable >= (1 << 20) and text_size *| 8 < writable) {
        try add(arena, out, .tiny_text_huge_data, "__TEXT is {d} bytes but {d} bytes of writable segments follow", .{ text_size, writable });
    }
    // 8. entry point outside __TEXT
    if (in.entry_vm orelse img.entryVm()) |vm| {
        const seg = img.segmentForVm(vm);
        const name = if (seg) |s| s.name else "";
        if (seg == null or !std.mem.eql(u8, name, "__TEXT")) {
            try add(arena, out, .entry_outside_text, "entry 0x{x} is in {s}, not __TEXT", .{ vm, if (seg == null) "no segment" else name });
        }
    }
    // 9. rwx segment — mapped rwx now, and the quieter case of "may become rwx later"
    for (img.segments) |*s| {
        if (s.initprot & 7 == 7) {
            try add(arena, out, .rwx_segment, "segment {s} is mapped rwx", .{s.name});
        } else if (s.maxprot & 7 == 7 and s.initprot & 5 == 5) {
            // initprot r-x but maxprot rwx: the process may `mprotect` its own code to writable at
            // any time and rewrite it, which is how an unpacking stub reveals a packed __TEXT.
            // Measured rarity: 2 of 1178 system/app binaries (/bin, /usr/bin, /usr/libexec,
            // /Applications, /System/Applications) carry it, so it is signal rather than noise —
            // but it is capability, not action, hence half the weight of an actually-rwx segment.
            try add(arena, out, .rwx_maxprot, "segment {s} is r-x but may be re-protected rwx (maxprot)", .{s.name});
        }
    }
    // 10. an unknown segment wedged between __TEXT and __LINKEDIT, or __LINKEDIT not last
    var linkedit_at: ?u16 = null;
    for (img.segments, 0..) |*s, i| {
        if (std.mem.eql(u8, s.name, "__LINKEDIT")) linkedit_at = @intCast(i);
    }
    for (img.segments, 0..) |*s, i| {
        if (isKnownSegment(s.name)) continue;
        if (linkedit_at != null and i > linkedit_at.?) continue;
        try add(arena, out, .nonstandard_segment_order, "unexpected segment {s} at index {d} before __LINKEDIT", .{ s.name, i });
    }
    if (linkedit_at) |i| {
        if (img.segments.len > 0 and i != img.segments.len - 1) {
            try add(arena, out, .nonstandard_segment_order, "__LINKEDIT is segment {d} of {d}, not the last one", .{ i, img.segments.len });
        }
    }
    _ = sects;
}

/// Name of the packer whose marker `name` carries, or null.
pub fn packerName(name: []const u8) ?[]const u8 {
    for (packer_names) |p| {
        if (std.mem.startsWith(u8, name, p)) return if (std.mem.startsWith(u8, p, "__MPRESS")) "MPRESS" else if (std.mem.eql(u8, p, "__XHDR")) "XHDR" else "UPX";
    }
    return null;
}

fn declaredSymbolCount(img: *const Image) u32 {
    var it = img.cmdIterator(.SYMTAB);
    while (it.next()) |c| {
        const st = loadcmds.decodeSymtab(c) orelse continue;
        if (st.nsyms != 0) return st.nsyms;
    }
    return 0;
}

fn dylibCount(img: *const Image) u32 {
    var n: u32 = 0;
    for (img.cmds) |c| {
        if (loadcmds.isDylibLoadCmd(c.cmd)) n += 1;
    }
    return n;
}

fn encryptionFromImage(img: *const Image) ?EncryptionInfo {
    for (img.cmds) |c| {
        switch (c.lc()) {
            .ENCRYPTION_INFO, .ENCRYPTION_INFO_64 => if (loadcmds.decodeEncryptionInfo(c)) |e| return e,
            else => {},
        }
    }
    return null;
}

/// Single pass, 256-bucket histogram, bits/byte; 0 for empty input.
pub fn shannon(bytes: []const u8) f64 {
    if (bytes.len == 0) return 0;
    var counts: [256]u64 = @splat(0);
    for (bytes) |b| counts[b] += 1;
    const n: f64 = @floatFromInt(bytes.len);
    var h: f64 = 0;
    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / n;
        h -= p * @log2(p);
    }
    return if (h < 0) 0 else h;
}
pub const packer_names: []const []const u8 = &.{ "__XHDR", "UPX_DATA", "upxTEXT", "__MPRESS__" };

// ---------------------------------------------------------------------------------------------
// tests — hermetic: Images are built as struct literals, so this file's import set stays {image, loadcmds}.
// ---------------------------------------------------------------------------------------------
const testing = std.testing;

test "entropy: shannon reference values" {
    try testing.expectEqual(@as(f64, 0), shannon(""));
    try testing.expectEqual(@as(f64, 0), shannon("aaaaaaaa"));
    try testing.expectApproxEqAbs(@as(f64, 1), shannon("abab"), 1e-12);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    try testing.expectApproxEqAbs(@as(f64, 8), shannon(&all), 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.811278124459133), shannon("aaab"), 1e-9); // 1/4 vs 3/4
}

test "entropy: packer names" {
    try testing.expectEqualStrings("UPX", packerName("UPX_DATA").?);
    try testing.expectEqualStrings("UPX", packerName("upxTEXT").?);
    try testing.expectEqualStrings("XHDR", packerName("__XHDR").?);
    try testing.expectEqualStrings("MPRESS", packerName("__MPRESS__").?);
    try testing.expect(packerName("__TEXT") == null);
    try testing.expect(packerName("__DATA_CONST") == null);
}

const SegSpec = struct { name: []const u8, prot: u32 = 5, size: u64 = 0x100, random: bool = false, flags: u32 = 0 };

/// Builds an Image value (no parser involved) plus its backing bytes: one `size`-byte region per segment.
fn synth(arena: Allocator, specs: []const SegSpec) !*Image {
    var total: u64 = 0x20;
    for (specs) |s| total += s.size;
    const bytes = try arena.alloc(u8, @intCast(total));
    @memset(bytes, 0);
    const segs = try arena.alloc(image_mod.Segment, specs.len);
    var off: u64 = 0x20;
    var vm: u64 = 0x100000000;
    for (specs, 0..) |s, i| {
        if (s.random) {
            var prng = std.Random.DefaultPrng.init(0x5eed +% i);
            prng.random().bytes(bytes[@intCast(off)..][0..@intCast(s.size)]);
        } else @memset(bytes[@intCast(off)..][0..@intCast(s.size)], 'A');
        segs[i] = .{
            .index = @intCast(i),
            .name = s.name,
            .vmaddr = vm,
            .vmsize = @max(s.size, 0x1000),
            .fileoff = if (s.size == 0) 0 else off,
            .filesize = s.size,
            .maxprot = s.prot,
            .initprot = s.prot,
            .nsects = 0,
            .flags = s.flags,
            .cmd_offset = 0,
            .first_section = 0,
            .section_count = 0,
            .file_range_truncated = false,
        };
        off += s.size;
        vm += @max(s.size, 0x1000);
    }
    const img = try arena.create(Image);
    img.* = .{
        .r = .{ .bytes = bytes, .base = 0 },
        .slice_offset = 0,
        .index = 0,
        .arch = .{ .cputype = 0x0100000c, .cpusubtype = 0, .name = .arm64, .ptr_size = 8, .is_64 = true, .is_arm64e = false, .ptrauth_version = 0, .caps = 0 },
        .hdr = .{ .magic = std.macho.MH_MAGIC_64, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = std.macho.MH_EXECUTE, .ncmds = 0, .sizeofcmds = 0, .flags = 0, .header_size = 32 },
        .cmds = &.{},
        .segments = segs,
        .sections = &.{},
        .image_base = 0x100000000,
        .text_seg = null,
        .linkedit_seg = null,
        .cmds_truncated = false,
        .ncmds_parsed = 0,
    };
    return img;
}

fn hasTell(rep: EntropyReport, code: TellCode) bool {
    for (rep.tells) |t| if (t.code == code) return true;
    return false;
}

const clean_inputs: Inputs = .{ .symbol_count = 12, .import_count = 6, .encryption = null, .entry_vm = null };

test "entropy: a clean layout produces no tells" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try synth(arena, &.{
        .{ .name = "__PAGEZERO", .prot = 0, .size = 0 },
        .{ .name = "__TEXT", .prot = 5 },
        .{ .name = "__DATA_CONST", .prot = 3 },
        .{ .name = "__LINKEDIT", .prot = 1 },
    });
    const rep = try analyze(arena, img, clean_inputs);
    try testing.expectEqual(@as(usize, 0), rep.tells.len);
    try testing.expectEqual(@as(usize, 4), rep.segments.len);
    try testing.expectEqual(@as(f64, 0), rep.segments[1].entropy); // all 'A'
    try testing.expect(rep.segments[0].size == 0 and rep.segments[0].file_fraction == 0);
    try testing.expectEqualStrings("__TEXT", rep.segments[1].name);
    try testing.expect(rep.segments[1].sectname == null);
}

test "entropy: high entropy, packer name, rwx and layout tells" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try synth(arena, &.{
        .{ .name = "__PAGEZERO", .prot = 0, .size = 0 },
        .{ .name = "__TEXT", .prot = 5, .size = 0x40 },
        .{ .name = "UPX_DATA", .prot = 7, .size = 0x400, .random = true },
        .{ .name = "__LINKEDIT", .prot = 1, .size = 0x40 },
    });
    const rep = try analyze(arena, img, clean_inputs);
    try testing.expect(hasTell(rep, .packer_segment_name));
    try testing.expect(hasTell(rep, .rwx_segment));
    try testing.expect(hasTell(rep, .nonstandard_segment_order));
    try testing.expect(hasTell(rep, .high_entropy_segment));
    try testing.expect(!hasTell(rep, .no_imports_no_symbols));
    for (rep.tells) |t| try testing.expect(t.weight == tellWeight(t.code) and t.weight < 50 and t.detail.len > 0);
}

test "entropy: structural tells (protected, encrypted, stripped, entry outside __TEXT, __LINKEDIT not last)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try synth(arena, &.{
        .{ .name = "__TEXT", .prot = 5 },
        .{ .name = "__LINKEDIT", .prot = 1 },
        .{ .name = "__DATA", .prot = 3, .flags = std.macho.SG_PROTECTED_VERSION_1 },
    });
    const rep = try analyze(arena, img, .{
        .symbol_count = 0,
        .import_count = 0,
        .encryption = .{ .cmd = @intFromEnum(std.macho.LC.ENCRYPTION_INFO_64), .cryptoff = 16384, .cryptsize = 4096, .cryptid = 1 },
        .entry_vm = 0xdeadbeef,
    });
    try testing.expect(hasTell(rep, .protected_segment));
    try testing.expect(hasTell(rep, .encryption_info));
    try testing.expect(hasTell(rep, .no_imports_no_symbols));
    try testing.expect(hasTell(rep, .entry_outside_text));
    try testing.expect(hasTell(rep, .nonstandard_segment_order)); // __LINKEDIT is not last
}

test "entropy: every prefix of the backing bytes analyzes without error" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try synth(arena, &.{
        .{ .name = "__TEXT", .prot = 5, .size = 0x40 },
        .{ .name = "__DATA", .prot = 3, .size = 0x40, .random = true },
        .{ .name = "__LINKEDIT", .prot = 1, .size = 0x40 },
    });
    var n: u64 = 0;
    while (n <= img.r.len()) : (n += 1) {
        const cut = try arena.create(Image);
        cut.* = img.*;
        cut.r = img.r.sub(0, n) orelse continue;
        const rep = try analyze(arena, cut, clean_inputs);
        try testing.expect(rep.file >= 0 and rep.file <= 8.0001);
        var covered: u64 = 0;
        for (rep.segments) |r| {
            try testing.expect(r.size <= n and r.entropy >= 0 and r.entropy <= 8.0001);
            covered += r.size;
        }
        try testing.expect(covered <= n);
    }
}

test "entropy: ranges outside the slice are clamped, never trapped" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try synth(arena, &.{.{ .name = "__TEXT" }});
    const segs = try arena.alloc(image_mod.Segment, 2);
    segs[0] = img.segments[0];
    segs[1] = img.segments[0];
    segs[1].name = "__WILD";
    segs[1].fileoff = std.math.maxInt(u64) - 3;
    segs[1].filesize = std.math.maxInt(u64);
    img.segments = segs;
    const rep = try analyze(arena, img, clean_inputs);
    try testing.expectEqual(@as(u64, 0), rep.segments[1].size);
    try testing.expectEqual(@as(f64, 0), rep.segments[1].entropy);
    try testing.expect(hasTell(rep, .nonstandard_segment_order));
}
