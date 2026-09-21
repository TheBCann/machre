//! codesign/hashes.zig — recompute code-page and special-slot hashes and compare.
//! Imports: core/image, core/diag, core/limits, codesign/blobs.
const std = @import("std");
const Image = @import("../core/image.zig").Image;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const blobs = @import("blobs.zig");

/// Special slots this module can check on its own (Info.plist / CodeResources come from bundle.zig).
pub const slot_info_plist: u32 = 1;
pub const slot_requirements: u32 = 2;
pub const slot_resources: u32 = 3;
pub const slot_entitlements_xml: u32 = 5;
pub const slot_entitlements_der: u32 = 7;
pub const slot_launch_constraint_first: u32 = 8;
pub const slot_launch_constraint_last: u32 = 11;

pub const SpecialCheck = struct { requirements: ?bool, entitlements_xml: ?bool, entitlements_der: ?bool, info_plist: ?bool, resources: ?bool, launch_constraints: ?bool };
pub const Verification = struct {
    pages_checked: u32,
    pages_ok: u32,
    mismatches: u32,
    first_bad_page: ?u32,
    special: SpecialCheck,
    special_mismatches: u32,
    code_limit_within_slice: bool,
    hash_type_supported: bool,

    pub const none: Verification = .{
        .pages_checked = 0,
        .pages_ok = 0,
        .mismatches = 0,
        .first_bad_page = null,
        .special = .{ .requirements = null, .entitlements_xml = null, .entitlements_der = null, .info_plist = null, .resources = null, .launch_constraints = null },
        .special_mismatches = 0,
        .code_limit_within_slice = false,
        .hash_type_supported = false,
    };

    pub fn ok(v: Verification) bool {
        return v.hash_type_supported and v.code_limit_within_slice and v.mismatches == 0 and v.special_mismatches == 0 and v.pages_checked != 0;
    }
};

/// Recomputes every code slot over `img.r.bytes[0..code_limit]` with the CD's hash type and compares; also hashes the
/// requirements/entitlements(XML,DER)/launch-constraint blobs against special slots -2/-5/-7/-8..; Info.plist/CodeResources
/// (slots -1/-3) are sealed by path, not by a blob in this file, so `verifyBundleSlots` fills them
/// from the bundle's files on disk -- call it whenever a bundle path is known, or `ok()` cannot
/// see a tampered Info.plist or CodeResources.
pub fn verify(img: *const Image, sig: *const blobs.Signature, cd: *const blobs.CodeDirectory, limits: *const Limits, diags: *Diagnostics) Verification {
    var v: Verification = .none;
    v.hash_type_supported = cd.hash_type.digestLen() != 0 and cd.hash_size == cd.hash_type.digestLen();
    v.code_limit_within_slice = cd.code_limit <= img.r.len();
    if (!v.hash_type_supported) {
        if (!diags.has(.codesign, .version_unsupported))
            diags.warn(.codesign, .version_unsupported, null, "cannot verify page hashes: hash type {d} size {d}", .{ @intFromEnum(cd.hash_type), cd.hash_size });
        return v;
    }
    if (!v.code_limit_within_slice and !diags.has(.codesign, .offset_past_eof))
        diags.warn(.codesign, .offset_past_eof, null, "CodeDirectory codeLimit {d} exceeds the {d}-byte slice; only the present pages are checked", .{ cd.code_limit, img.r.len() });

    const covered: u64 = @min(cd.code_limit, img.r.len());
    var page: u64 = cd.pageSize();
    if (page == 0) page = @max(covered, 1); // pageSize 0 == a single page over everything
    const hs: usize = cd.hash_size;

    var k: usize = 0;
    while (k < cd.code_hashes.len and k < limits.max_code_slots) : (k += 1) {
        const start: u64 = @as(u64, k) * page;
        if (start >= covered) break;
        const end: u64 = @min(start + page, covered);
        const bytes = img.r.sliceAt(start, end - start) orelse break;
        const want = cd.code_hashes[k];
        if (want.len < hs) break;
        var got: [48]u8 = undefined;
        const n = blobs.cdhashOf(cd.hash_type, bytes, &got) orelse break;
        v.pages_checked += 1;
        if (std.mem.eql(u8, want[0..hs], got[0..@min(n, hs)])) {
            v.pages_ok += 1;
        } else {
            v.mismatches += 1;
            if (v.first_bad_page == null) {
                v.first_bad_page = @intCast(k);
                diags.err(.codesign, .hash_mismatch, start, "code page {d} hash does not match the file (offset 0x{x})", .{ k, start });
            }
        }
    }
    if (v.pages_checked < cd.n_code_slots and !diags.has(.codesign, .truncated))
        diags.warn(.codesign, .truncated, null, "checked {d} of {d} declared code slots", .{ v.pages_checked, cd.n_code_slots });

    v.special.requirements = checkSlot(cd, sig, slot_requirements);
    v.special.entitlements_xml = checkSlot(cd, sig, slot_entitlements_xml);
    v.special.entitlements_der = checkSlot(cd, sig, slot_entitlements_der);
    var lc: ?bool = null;
    var n: u32 = slot_launch_constraint_first;
    while (n <= slot_launch_constraint_last) : (n += 1) {
        if (checkSlot(cd, sig, n)) |r| lc = (lc orelse true) and r;
    }
    v.special.launch_constraints = lc;

    inline for (.{ v.special.requirements, v.special.entitlements_xml, v.special.entitlements_der, v.special.launch_constraints }) |r| {
        if (r) |b| if (!b) {
            v.special_mismatches += 1;
        };
    }
    if (v.special_mismatches != 0 and !diags.has(.codesign, .hash_mismatch))
        diags.err(.codesign, .hash_mismatch, null, "{d} special slot hashes do not match their blobs", .{v.special_mismatches});
    return v;
}

/// Fills special slots -1 (Info.plist) and -3 (CodeResources) from the bundle's files on disk and
/// folds any mismatch into `special_mismatches`, so `ok()` -- and the `verdict.valid` it backs --
/// finally accounts for them. `verify` cannot: those two are sealed by path, and nothing in the
/// Mach-O carries their contents. Until this ran, their `null` read as "no mismatch" and a signed
/// bundle with a tampered Info.plist or CodeResources was still reported valid.
pub fn verifyBundleSlots(v: *Verification, cd: *const blobs.CodeDirectory, files: anytype, diags: *Diagnostics) void {
    v.special.info_plist = checkPathSlot(cd, slot_info_plist, files.info_plist);
    v.special.resources = checkPathSlot(cd, slot_resources, files.code_resources);
    var added: u32 = 0;
    inline for (.{ v.special.info_plist, v.special.resources }) |r| {
        if (r) |b| if (!b) {
            added += 1;
        };
    }
    v.special_mismatches += added;
    if (added != 0 and !diags.has(.codesign, .hash_mismatch))
        diags.err(.codesign, .hash_mismatch, null, "{d} bundle special slot hashes do not match the files on disk", .{added});
}

/// `checkSlot` for a slot sealed by path: `bytes` is the file's contents, or null when absent.
fn checkPathSlot(cd: *const blobs.CodeDirectory, n: u32, bytes: ?[]const u8) ?bool {
    const bound = cd.isSpecialSlotBound(n);
    if (bytes == null) return if (bound) false else null; // sealed but the file is gone
    if (!bound) return null; // present but not sealed (codesign tolerates this)
    return verifySpecialSlot(cd, n, bytes.?);
}

/// null when the slot is unbound and the blob absent; false when one of the two is missing.
fn checkSlot(cd: *const blobs.CodeDirectory, sig: *const blobs.Signature, n: u32) ?bool {
    const bound = cd.isSpecialSlotBound(n);
    const b = sig.blob(n);
    if (!bound and b == null) return null;
    if (b == null) return false; // sealed but the blob is gone
    if (!bound) return null; // blob present but not sealed (codesign tolerates this)
    return verifySpecialSlot(cd, n, b.?.bytes);
}

/// Hash `bytes` with the CD's hash type and compare with special slot `n` (1-based; -n in codesign terms).
pub fn verifySpecialSlot(cd: *const blobs.CodeDirectory, n: u32, bytes: []const u8) ?bool {
    if (n == 0 or n > cd.special_hashes.len) return null;
    const want = cd.special_hashes[n - 1];
    const hs: usize = cd.hash_size;
    if (want.len < hs or hs == 0) return null;
    var got: [48]u8 = undefined;
    const got_len = hashBytes(cd.hash_type, bytes, &got) orelse return null;
    return std.mem.eql(u8, want[0..hs], got[0..@min(got_len, hs)]);
}
pub fn hashBytes(hash_type: blobs.HashType, bytes: []const u8, out: *[48]u8) ?u8 {
    return blobs.cdhashOf(hash_type, bytes, out);
}

// ---------------------------------------------------------------------------------------------
// tests

/// The Reader/Arch types without importing them: codesign/hashes.zig may only import
/// core/image, core/diag, core/limits and codesign/blobs (DESIGN.md §4 dependency table).
const ImageReader = @FieldType(Image, "r");
const ImageArch = @FieldType(Image, "arch");

/// Minimal in-memory Mach-O whose bytes are `code`, so `verify` has a slice to hash.
fn fakeImage(bytes: []const u8) Image {
    return .{
        .r = ImageReader.init(bytes, 0),
        .slice_offset = 0,
        .index = 0,
        .arch = ImageArch.fromCpu(0x0100000c, 0),
        .hdr = .{ .magic = 0xfeedfacf, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = 2, .ncmds = 0, .sizeofcmds = 0, .flags = 0, .header_size = 32 },
        .cmds = &.{},
        .segments = &.{},
        .sections = &.{},
        .image_base = 0,
        .text_seg = null,
        .linkedit_seg = null,
        .cmds_truncated = false,
        .ncmds_parsed = 0,
    };
}

test "hashes: page hashes match, then one flipped byte is caught" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = @import("../core/diag.zig").Diagnostics.init(arena, 64);
    var file: [5000]u8 = undefined;
    for (&file, 0..) |*b, i| b.* = @truncate(i *% 7);
    const code_limit: usize = 4500;

    // Hand-build a CodeDirectory over file[0..code_limit] with 4096-byte pages.
    const hs: usize = 32;
    const page: usize = 4096;
    const n_code = (code_limit + page - 1) / page;
    var cdbuf: [512]u8 = @splat(0);
    const ident = "pagehash";
    const ident_off: usize = 88;
    const n_special: usize = 2;
    const hash_off = ident_off + ident.len + 1 + n_special * hs;
    const total = hash_off + n_code * hs;
    std.mem.writeInt(u32, cdbuf[0..4], blobs.CSMAGIC_CODEDIRECTORY, .big);
    std.mem.writeInt(u32, cdbuf[4..8], @intCast(total), .big);
    std.mem.writeInt(u32, cdbuf[8..12], 0x20400, .big);
    std.mem.writeInt(u32, cdbuf[16..20], @intCast(hash_off), .big);
    std.mem.writeInt(u32, cdbuf[20..24], @intCast(ident_off), .big);
    std.mem.writeInt(u32, cdbuf[24..28], @intCast(n_special), .big);
    std.mem.writeInt(u32, cdbuf[28..32], @intCast(n_code), .big);
    std.mem.writeInt(u32, cdbuf[32..36], @intCast(code_limit), .big);
    cdbuf[36] = @intCast(hs);
    cdbuf[37] = 2;
    cdbuf[39] = 12;
    @memcpy(cdbuf[ident_off..][0..ident.len], ident);
    for (0..n_code) |k| {
        const start = k * page;
        const end = @min(start + page, code_limit);
        var dg: [48]u8 = undefined;
        _ = blobs.cdhashOf(.sha256, file[start..end], &dg).?;
        @memcpy(cdbuf[hash_off + k * hs ..][0..hs], dg[0..hs]);
    }
    // Seal the requirements blob in special slot -2.
    const req = [_]u8{ 0xfa, 0xde, 0x0c, 0x01, 0, 0, 0, 12, 0, 0, 0, 0 };
    var dg: [48]u8 = undefined;
    _ = blobs.cdhashOf(.sha256, &req, &dg).?;
    @memcpy(cdbuf[hash_off - 2 * hs ..][0..hs], dg[0..hs]);

    const cd = (try blobs.parseCodeDirectory(arena, 0, cdbuf[0..total], &Limits.default, &d)).?;
    var sig: blobs.Signature = .empty;
    sig.blobs = &[_]blobs.BlobRef{.{ .slot = 2, .offset = 0, .magic = blobs.CSMAGIC_REQUIREMENTS, .length = 12, .bytes = &req, .truncated = false }};
    sig.requirements = &req;

    const img = fakeImage(&file);
    const v = verify(&img, &sig, &cd, &Limits.default, &d);
    try std.testing.expectEqual(@as(u32, 2), v.pages_checked);
    try std.testing.expectEqual(@as(u32, 2), v.pages_ok);
    try std.testing.expectEqual(@as(u32, 0), v.mismatches);
    try std.testing.expectEqual(@as(?bool, true), v.special.requirements);
    try std.testing.expectEqual(@as(?bool, null), v.special.entitlements_xml);
    try std.testing.expect(v.ok());

    // Flip a byte on page 1 -> exactly one mismatch, first_bad_page 1.
    var broken = file;
    broken[4100] ^= 0xff;
    const img2 = fakeImage(&broken);
    const v2 = verify(&img2, &sig, &cd, &Limits.default, &d);
    try std.testing.expectEqual(@as(u32, 1), v2.mismatches);
    try std.testing.expectEqual(@as(?u32, 1), v2.first_bad_page);
    try std.testing.expect(!v2.ok());
    try std.testing.expect(d.has(.codesign, .hash_mismatch));

    // A truncated file verifies only the pages that are present and never traps.
    const img3 = fakeImage(file[0..1000]);
    const v3 = verify(&img3, &sig, &cd, &Limits.default, &d);
    try std.testing.expect(!v3.code_limit_within_slice);
    try std.testing.expectEqual(@as(u32, 1), v3.pages_checked);
}

test "hashes: a tampered Info.plist or CodeResources is no longer reported as valid" {
    // Regression: slots -1/-3 are sealed by path, so `verify` never filled them, and `ok()` read
    // their `null` as "no mismatch" -- a signed bundle whose Info.plist had been edited still
    // reported verdict.valid = true. `verifyBundleSlots` supplies them from the files on disk.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = @import("../core/diag.zig").Diagnostics.init(arena, 64);

    const info_plist = "<plist><dict><key>CFBundleIdentifier</key><string>x</string></dict></plist>";
    const code_resources = "<plist><dict><key>files</key><dict/></dict></plist>";

    var file: [1000]u8 = undefined;
    for (&file, 0..) |*b, i| b.* = @truncate(i *% 13);
    const hs: usize = 32;
    const code_limit: usize = file.len;
    var cdbuf: [512]u8 = @splat(0);
    const ident = "bundleslots";
    const ident_off: usize = 88;
    const n_special: usize = 3; // slots -1, -2, -3
    const hash_off = ident_off + ident.len + 1 + n_special * hs;
    const total = hash_off + 1 * hs;
    std.mem.writeInt(u32, cdbuf[0..4], blobs.CSMAGIC_CODEDIRECTORY, .big);
    std.mem.writeInt(u32, cdbuf[4..8], @intCast(total), .big);
    std.mem.writeInt(u32, cdbuf[8..12], 0x20400, .big);
    std.mem.writeInt(u32, cdbuf[16..20], @intCast(hash_off), .big);
    std.mem.writeInt(u32, cdbuf[20..24], @intCast(ident_off), .big);
    std.mem.writeInt(u32, cdbuf[24..28], @intCast(n_special), .big);
    std.mem.writeInt(u32, cdbuf[28..32], 1, .big);
    std.mem.writeInt(u32, cdbuf[32..36], @intCast(code_limit), .big);
    cdbuf[36] = @intCast(hs);
    cdbuf[37] = 2;
    cdbuf[39] = 12;
    @memcpy(cdbuf[ident_off..][0..ident.len], ident);
    var dg: [48]u8 = undefined;
    _ = blobs.cdhashOf(.sha256, file[0..code_limit], &dg).?;
    @memcpy(cdbuf[hash_off..][0..hs], dg[0..hs]);
    _ = blobs.cdhashOf(.sha256, info_plist, &dg).?;
    @memcpy(cdbuf[hash_off - 1 * hs ..][0..hs], dg[0..hs]); // slot -1
    _ = blobs.cdhashOf(.sha256, code_resources, &dg).?;
    @memcpy(cdbuf[hash_off - 3 * hs ..][0..hs], dg[0..hs]); // slot -3

    const cd = (try blobs.parseCodeDirectory(arena, 0, cdbuf[0..total], &Limits.default, &d)).?;
    var sig: blobs.Signature = .empty;
    const img = fakeImage(&file);

    // Without the bundle's files the two slots stay unknown -- and `ok()` used to stop there.
    const bare = verify(&img, &sig, &cd, &Limits.default, &d);
    try std.testing.expectEqual(@as(?bool, null), bare.special.info_plist);
    try std.testing.expectEqual(@as(?bool, null), bare.special.resources);

    // Both files intact: verified, and the verdict still holds.
    var good = verify(&img, &sig, &cd, &Limits.default, &d);
    verifyBundleSlots(&good, &cd, .{ .info_plist = @as(?[]const u8, info_plist), .code_resources = @as(?[]const u8, code_resources) }, &d);
    try std.testing.expectEqual(@as(?bool, true), good.special.info_plist);
    try std.testing.expectEqual(@as(?bool, true), good.special.resources);
    try std.testing.expectEqual(@as(u32, 0), good.special_mismatches);
    try std.testing.expect(good.ok());

    // One edited byte in Info.plist: MISMATCH, and the verdict must now be false.
    var bad = verify(&img, &sig, &cd, &Limits.default, &d);
    verifyBundleSlots(&bad, &cd, .{ .info_plist = @as(?[]const u8, info_plist ++ " "), .code_resources = @as(?[]const u8, code_resources) }, &d);
    try std.testing.expectEqual(@as(?bool, false), bad.special.info_plist);
    try std.testing.expectEqual(@as(u32, 1), bad.special_mismatches);
    try std.testing.expect(!bad.ok());

    // Sealed but the file is gone counts as a mismatch too.
    var gone = verify(&img, &sig, &cd, &Limits.default, &d);
    verifyBundleSlots(&gone, &cd, .{ .info_plist = @as(?[]const u8, null), .code_resources = @as(?[]const u8, code_resources) }, &d);
    try std.testing.expectEqual(@as(?bool, false), gone.special.info_plist);
    try std.testing.expect(!gone.ok());
}
