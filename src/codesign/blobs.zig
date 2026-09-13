//! codesign/blobs.zig — SuperBlob, slot table, CodeDirectory (v0x20100..0x20600), cdhash, special slots.
//! Imports: core/image, core/reader, core/diag, core/limits, core/version, core/macho_extra.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Reader = @import("../core/reader.zig").Reader;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const version = @import("../core/version.zig");
const extra = @import("../core/macho_extra.zig");

pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

pub const BlobRef = struct { slot: u32, offset: u32, magic: u32, length: u32, bytes: []const u8, truncated: bool };
pub const HashType = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    sha256_truncated = 3,
    sha384 = 4,
    _,

    /// Digest length in bytes (0 for an unsupported type).
    pub fn digestLen(t: HashType) u8 {
        return switch (t) {
            .sha1 => 20,
            .sha256 => 32,
            .sha256_truncated => 20,
            .sha384 => 48,
            _ => 0,
        };
    }
    /// codesign's spelling ("sha256"), or "unknown" for a type we do not know.
    pub fn name(t: HashType) []const u8 {
        return version.csHashTypeName(@intFromEnum(t)) orelse "unknown";
    }
};
pub const ExecSeg = struct { base: u64, limit: u64, flags: u64 };
pub const Linkage = struct { hash_type: u8, app_type: u8, app_subtype: u16, offset: u32, size: u32 };

pub const CodeDirectory = struct {
    slot: u32, // 0 or CSSLOT_ALTERNATE_CODEDIRECTORIES + n
    blob: []const u8,
    version: u32,
    flags: u32,
    hash_offset: u32,
    ident_offset: u32,
    n_special_slots: u32,
    n_code_slots: u32,
    code_limit: u64, // codeLimit64 when set
    hash_size: u8,
    hash_type: HashType,
    platform: u8,
    page_size_log2: u8,
    scatter_offset: ?u32,
    team_offset: ?u32,
    exec_seg: ?ExecSeg,
    runtime: ?u32,
    pre_encrypt_offset: ?u32,
    linkage: ?Linkage,
    identifier: []const u8,
    team_id: ?[]const u8,
    cdhash: [20]u8,
    cdhash_full: []const u8, // hash_size bytes, arena
    /// code_hashes[i] = slot i; special_hashes[k] = slot -(k+1); each hash_size bytes; clamped.
    code_hashes: []const []const u8,
    special_hashes: []const []const u8,
    hashes_truncated: bool,

    /// Bytes covered by one code slot; 0 means "one page covering everything up to code_limit".
    pub fn pageSize(cd: *const CodeDirectory) u64 {
        if (cd.page_size_log2 == 0 or cd.page_size_log2 > 40) return 0;
        return @as(u64, 1) << @intCast(cd.page_size_log2);
    }
    /// All-zero special slot == not bound (codesign: "Info.plist=not bound").
    pub fn isSpecialSlotBound(cd: *const CodeDirectory, n: u32) bool {
        if (n == 0 or n > cd.special_hashes.len) return false;
        for (cd.special_hashes[n - 1]) |b| if (b != 0) return true;
        return false;
    }
    pub fn isAdhoc(cd: *const CodeDirectory) bool {
        return cd.flags & 0x2 != 0;
    }
    pub fn isLinkerSigned(cd: *const CodeDirectory) bool {
        return cd.flags & extra.CS_LINKER_SIGNED != 0;
    }
    pub fn hasHardenedRuntime(cd: *const CodeDirectory) bool {
        return cd.flags & extra.CS_RUNTIME != 0;
    }
};

pub const Signature = struct {
    dataoff: u32,
    datasize: u32,
    superblob_magic: u32,
    superblob_length: u32,
    count_declared: u32,
    blobs: []const BlobRef,
    /// slot 0 first, then 0x1000..0x1004 in slot order.
    code_directories: []const CodeDirectory,
    /// Index into code_directories of the CD codesign presents as "the" CDHash (sha256 > sha384 > sha1).
    best: ?u8,
    /// Whole CSMAGIC_REQUIREMENTS blob (header included: the slot offsets are relative to it).
    requirements: ?[]const u8,
    /// Payloads (the 8-byte blob header removed).
    entitlements_xml: ?[]const u8,
    entitlements_der: ?[]const u8,
    cms: ?[]const u8,
    ticket: ?[]const u8,
    launch_constraints: [4]?[]const u8, // slots 8..11
    truncated: bool,

    pub const empty: Signature = .{
        .dataoff = 0,
        .datasize = 0,
        .superblob_magic = 0,
        .superblob_length = 0,
        .count_declared = 0,
        .blobs = &.{},
        .code_directories = &.{},
        .best = null,
        .requirements = null,
        .entitlements_xml = null,
        .entitlements_der = null,
        .cms = null,
        .ticket = null,
        .launch_constraints = .{ null, null, null, null },
        .truncated = false,
    };

    /// The CodeDirectory codesign presents as "the" one (`best`, else the first parsed).
    pub fn cd(s: *const Signature) ?*const CodeDirectory {
        if (s.code_directories.len == 0) return null;
        const i: usize = if (s.best) |b| @min(b, s.code_directories.len - 1) else 0;
        return &s.code_directories[i];
    }
    pub fn blob(s: *const Signature, slot: u32) ?*const BlobRef {
        for (s.blobs) |*b| if (b.slot == slot) return b;
        return null;
    }
    /// True when a CodeDirectory says the signature is ad hoc.
    pub fn isAdhoc(s: *const Signature) bool {
        const c = s.cd() orelse return false;
        return c.isAdhoc();
    }
};

fn hashTypeRank(t: HashType) u8 {
    return switch (t) {
        .sha256 => 4,
        .sha384 => 3,
        .sha256_truncated => 2,
        .sha1 => 1,
        _ => 0,
    };
}

/// Null when no LC_CODE_SIGNATURE.
pub fn parse(arena: Allocator, img: *const Image, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Signature {
    const c = img.findCmd(.CODE_SIGNATURE) orelse return null;
    const cr = c.reader();
    const dataoff = cr.u32At(8, c.endian) orelse {
        diags.err(.codesign, .truncated, c.offset, "LC_CODE_SIGNATURE is shorter than 16 bytes", .{});
        return null;
    };
    const datasize = cr.u32At(12, c.endian) orelse {
        diags.err(.codesign, .truncated, c.offset, "LC_CODE_SIGNATURE is shorter than 16 bytes", .{});
        return null;
    };
    const lr = img.linkeditReader(dataoff, datasize, diags, .codesign) orelse return null;
    return parseSuperBlob(arena, lr, dataoff, datasize, limits, diags);
}

/// Parse a SuperBlob from bytes (nested code, detached signatures, tests). `dataoff`/`datasize` are recorded only.
pub fn parseSuperBlob(arena: Allocator, r: Reader, dataoff: u32, datasize: u32, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Signature {
    if (r.len() < 8) {
        if (r.len() != 0) diags.err(.codesign, .truncated, dataoff, "signature data is {d} bytes, too small for a blob header", .{r.len()});
        return null;
    }
    var sig: Signature = .empty;
    sig.dataoff = dataoff;
    sig.datasize = datasize;
    sig.superblob_magic = r.u32At(0, .big).?;
    sig.superblob_length = r.u32At(4, .big).?;

    var refs: std.ArrayList(BlobRef) = .empty;
    var cds: std.ArrayList(CodeDirectory) = .empty;

    switch (sig.superblob_magic) {
        CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE_OLD, CSMAGIC_DETACHED_SIGNATURE => {},
        CSMAGIC_CODEDIRECTORY => {
            // A bare CodeDirectory where a SuperBlob was expected (linker-signed stubs seen in the wild).
            diags.warn(.codesign, .blob_malformed, dataoff, "signature starts with a bare CodeDirectory (magic 0x{x}), not a SuperBlob", .{sig.superblob_magic});
            const len = @min(@as(u64, sig.superblob_length), r.len());
            const bytes = r.sliceAt(0, len) orelse r.bytes;
            try refs.append(arena, .{ .slot = 0, .offset = 0, .magic = sig.superblob_magic, .length = sig.superblob_length, .bytes = bytes, .truncated = sig.superblob_length > r.len() });
            if (try parseCodeDirectory(arena, 0, bytes, limits, diags)) |cd| try cds.append(arena, cd);
            sig.truncated = true;
            sig.blobs = try refs.toOwnedSlice(arena);
            sig.code_directories = try cds.toOwnedSlice(arena);
            sig.best = pickBest(sig.code_directories);
            return sig;
        },
        else => {
            diags.err(.codesign, .blob_malformed, dataoff, "signature magic 0x{x} is not CSMAGIC_EMBEDDED_SIGNATURE", .{sig.superblob_magic});
            sig.truncated = true;
            return sig;
        },
    }

    var total: u64 = sig.superblob_length;
    if (total > r.len()) {
        diags.warn(.codesign, .truncated, dataoff, "SuperBlob declares {d} bytes but only {d} are present", .{ total, r.len() });
        total = r.len();
        sig.truncated = true;
    }
    if (total < 12) {
        diags.err(.codesign, .blob_malformed, dataoff, "SuperBlob length {d} is smaller than its header", .{total});
        sig.truncated = true;
        return sig;
    }
    sig.count_declared = r.u32At(8, .big) orelse 0;
    var count: u64 = sig.count_declared;
    const room: u64 = (total - 12) / 8;
    if (count > room or count > limits.max_superblob_slots) {
        const clamped = @min(count, @min(room, @as(u64, limits.max_superblob_slots)));
        diags.warn(.codesign, .count_clamped, dataoff, "SuperBlob declares {d} slots, using {d}", .{ count, clamped });
        count = clamped;
        sig.truncated = true;
    }

    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const slot = r.u32At(12 + i * 8, .big) orelse break;
        const off = r.u32At(16 + i * 8, .big) orelse break;
        if (off + 8 > total) {
            diags.warn(.codesign, .blob_malformed, dataoff + off, "blob for slot 0x{x} at offset {d} lies outside the SuperBlob", .{ slot, off });
            sig.truncated = true;
            continue;
        }
        const magic = r.u32At(off, .big) orelse continue;
        const blen = r.u32At(off + 4, .big) orelse continue;
        var avail: u64 = total - off;
        var trunc = false;
        if (blen > avail or blen < 8) {
            if (blen < 8) {
                diags.warn(.codesign, .blob_malformed, dataoff + off, "blob for slot 0x{x} declares length {d} (< 8)", .{ slot, blen });
            } else {
                diags.warn(.codesign, .truncated, dataoff + off, "blob for slot 0x{x} declares {d} bytes, only {d} present", .{ slot, blen, avail });
            }
            trunc = true;
            sig.truncated = true;
        } else avail = blen;
        if (avail > limits.max_blob_len) {
            avail = limits.max_blob_len;
            trunc = true;
        }
        const bytes = r.sliceAt(off, avail) orelse continue;
        try refs.append(arena, .{ .slot = slot, .offset = off, .magic = magic, .length = blen, .bytes = bytes, .truncated = trunc });

        const payload: []const u8 = if (bytes.len > 8) bytes[8..] else &.{};
        switch (slot) {
            extra.CSSLOT_REQUIREMENTS => if (magic == CSMAGIC_REQUIREMENTS) {
                sig.requirements = bytes;
            },
            extra.CSSLOT_ENTITLEMENTS => if (magic == CSMAGIC_EMBEDDED_ENTITLEMENTS) {
                sig.entitlements_xml = payload;
            },
            extra.CSSLOT_DER_ENTITLEMENTS => if (magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) {
                sig.entitlements_der = payload;
            },
            extra.CSSLOT_SIGNATURESLOT => if (magic == CSMAGIC_BLOBWRAPPER and payload.len != 0) {
                sig.cms = payload;
            },
            extra.CSSLOT_TICKETSLOT => sig.ticket = payload,
            extra.CSSLOT_LAUNCH_CONSTRAINT_SELF...extra.CSSLOT_LIBRARY_CONSTRAINT => {
                sig.launch_constraints[slot - extra.CSSLOT_LAUNCH_CONSTRAINT_SELF] = payload;
            },
            else => {},
        }
        const is_cd_slot = slot == 0 or (slot >= extra.CSSLOT_ALTERNATE_CODEDIRECTORIES and slot < extra.CSSLOT_ALTERNATE_CODEDIRECTORIES + extra.CSSLOT_ALTERNATE_CODEDIRECTORY_MAX);
        if (is_cd_slot and magic == CSMAGIC_CODEDIRECTORY) {
            if (try parseCodeDirectory(arena, slot, bytes, limits, diags)) |cd| try cds.append(arena, cd);
        }
    }
    sig.blobs = try refs.toOwnedSlice(arena);
    sig.code_directories = try cds.toOwnedSlice(arena);
    sig.best = pickBest(sig.code_directories);
    return sig;
}

fn pickBest(cds: []const CodeDirectory) ?u8 {
    var best: ?u8 = null;
    var best_rank: u8 = 0;
    for (cds, 0..) |cd, i| {
        if (i > 255) break;
        const rank = hashTypeRank(cd.hash_type);
        if (best == null or rank > best_rank) {
            best = @intCast(i);
            best_rank = rank;
        }
    }
    return best;
}

pub fn parseCodeDirectory(arena: Allocator, slot: u32, blob: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?CodeDirectory {
    const r = Reader.init(blob, 0);
    if (r.len() < 44) {
        diags.err(.codesign, .truncated, null, "CodeDirectory in slot 0x{x} is {d} bytes (minimum 44)", .{ slot, r.len() });
        return null;
    }
    const magic = r.u32At(0, .big).?;
    if (magic != CSMAGIC_CODEDIRECTORY) {
        diags.err(.codesign, .blob_malformed, null, "CodeDirectory in slot 0x{x} has magic 0x{x}", .{ slot, magic });
        return null;
    }
    const declared_len = r.u32At(4, .big).?;
    var cd: CodeDirectory = .{
        .slot = slot,
        .blob = blob,
        .version = r.u32At(8, .big).?,
        .flags = r.u32At(12, .big).?,
        .hash_offset = r.u32At(16, .big).?,
        .ident_offset = r.u32At(20, .big).?,
        .n_special_slots = r.u32At(24, .big).?,
        .n_code_slots = r.u32At(28, .big).?,
        .code_limit = r.u32At(32, .big).?,
        .hash_size = r.u8At(36).?,
        .hash_type = @enumFromInt(r.u8At(37).?),
        .platform = r.u8At(38).?,
        .page_size_log2 = r.u8At(39).?,
        .scatter_offset = null,
        .team_offset = null,
        .exec_seg = null,
        .runtime = null,
        .pre_encrypt_offset = null,
        .linkage = null,
        .identifier = "",
        .team_id = null,
        .cdhash = @splat(0),
        .cdhash_full = &.{},
        .code_hashes = &.{},
        .special_hashes = &.{},
        .hashes_truncated = false,
    };
    if (declared_len > blob.len) {
        diags.warn(.codesign, .truncated, null, "CodeDirectory declares {d} bytes, {d} present", .{ declared_len, blob.len });
        cd.hashes_truncated = true;
    }
    if (cd.version >= extra.CS_SUPPORTSSCATTER) cd.scatter_offset = r.u32At(44, .big);
    if (cd.version >= extra.CS_SUPPORTSTEAMID) cd.team_offset = r.u32At(48, .big);
    if (cd.version >= extra.CS_SUPPORTSCODELIMIT64) {
        if (r.u64At(56, .big)) |cl64| if (cl64 != 0) {
            cd.code_limit = cl64;
        };
    }
    if (cd.version >= extra.CS_SUPPORTSEXECSEG) {
        if (r.u64At(64, .big)) |base| if (r.u64At(72, .big)) |limit| if (r.u64At(80, .big)) |flags| {
            cd.exec_seg = .{ .base = base, .limit = limit, .flags = flags };
        };
    }
    if (cd.version >= extra.CS_SUPPORTSRUNTIME) {
        cd.runtime = r.u32At(88, .big);
        cd.pre_encrypt_offset = r.u32At(92, .big);
    }
    if (cd.version >= extra.CS_SUPPORTSLINKAGE) {
        if (r.u8At(96)) |ht| if (r.u8At(97)) |at| if (r.u16At(98, .big)) |ast| if (r.u32At(100, .big)) |loff| if (r.u32At(104, .big)) |lsize| {
            cd.linkage = .{ .hash_type = ht, .app_type = at, .app_subtype = ast, .offset = loff, .size = lsize };
        };
    }
    if (cd.version > extra.CS_SUPPORTSLINKAGE and !diags.has(.codesign, .version_unsupported))
        diags.info(.codesign, .version_unsupported, null, "CodeDirectory version 0x{x} is newer than 0x{x}; trailing fields ignored", .{ cd.version, extra.CS_SUPPORTSLINKAGE });

    if (r.cstrAt(cd.ident_offset, limits.max_symbol_name)) |s| {
        cd.identifier = s.bytes;
        if (!s.terminated and !diags.has(.codesign, .string_unterminated))
            diags.warn(.codesign, .string_unterminated, null, "CodeDirectory identifier is not NUL-terminated", .{});
    } else diags.warn(.codesign, .blob_malformed, null, "CodeDirectory identOffset {d} lies outside the blob", .{cd.ident_offset});
    if (cd.team_offset) |to| if (to != 0) {
        if (r.cstrAt(to, limits.max_symbol_name)) |s| {
            cd.team_id = s.bytes;
        } else diags.warn(.codesign, .blob_malformed, null, "CodeDirectory teamOffset {d} lies outside the blob", .{to});
    };

    // cdhash over the whole blob as declared (clamped to what is present).
    const hashed_len = @min(@as(u64, declared_len), blob.len);
    var digest: [48]u8 = @splat(0);
    if (cdhashOf(cd.hash_type, blob[0..@intCast(hashed_len)], &digest)) |n| {
        const full = try arena.dupe(u8, digest[0..n]);
        cd.cdhash_full = full;
        @memcpy(cd.cdhash[0..@min(20, n)], full[0..@min(20, n)]);
    } else if (!diags.has(.codesign, .version_unsupported)) {
        diags.warn(.codesign, .version_unsupported, null, "CodeDirectory hash type {d} is not supported", .{@intFromEnum(cd.hash_type)});
    }

    const hs: u64 = cd.hash_size;
    if (hs == 0 or hs > 48) {
        diags.err(.codesign, .blob_malformed, null, "CodeDirectory hashSize {d} is out of range", .{hs});
        return cd;
    }
    if (cd.hash_offset > blob.len) {
        diags.err(.codesign, .blob_malformed, null, "CodeDirectory hashOffset {d} lies outside the {d}-byte blob", .{ cd.hash_offset, blob.len });
        cd.hashes_truncated = true;
        return cd;
    }
    // Special slots grow downwards from hashOffset.
    var n_special: u64 = @min(cd.n_special_slots, limits.max_special_slots);
    if (n_special * hs > cd.hash_offset) {
        const fit = cd.hash_offset / hs;
        diags.warn(.codesign, .blob_malformed, null, "{d} special slots do not fit below hashOffset {d}; using {d}", .{ cd.n_special_slots, cd.hash_offset, fit });
        n_special = fit;
        cd.hashes_truncated = true;
    }
    if (n_special != 0) {
        const out = try arena.alloc([]const u8, @intCast(n_special));
        for (out, 0..) |*slotp, k| {
            const off = cd.hash_offset - (@as(u64, k) + 1) * hs;
            slotp.* = r.sliceAt(off, hs) orelse &.{};
        }
        cd.special_hashes = out;
    }
    // Code slots grow upwards from hashOffset.
    const room: u64 = (blob.len - cd.hash_offset) / hs;
    var n_code: u64 = cd.n_code_slots;
    if (n_code > room or n_code > limits.max_code_slots) {
        const clamped = @min(n_code, @min(room, @as(u64, limits.max_code_slots)));
        diags.warn(.codesign, .count_clamped, null, "CodeDirectory declares {d} code slots, {d} fit in the blob", .{ n_code, clamped });
        n_code = clamped;
        cd.hashes_truncated = true;
    }
    if (n_code != 0) {
        const out = try arena.alloc([]const u8, @intCast(n_code));
        for (out, 0..) |*slotp, k| {
            const off = @as(u64, cd.hash_offset) + @as(u64, k) * hs;
            slotp.* = r.sliceAt(off, hs) orelse &.{};
        }
        cd.code_hashes = out;
    }
    return cd;
}

/// hash_type(whole CD blob); returns the digest length written into `out` (null for unknown hash types).
pub fn cdhashOf(hash_type: HashType, cd_blob: []const u8, out: *[48]u8) ?u8 {
    switch (hash_type) {
        .sha1 => {
            var d: [20]u8 = undefined;
            std.crypto.hash.Sha1.hash(cd_blob, &d, .{});
            @memcpy(out[0..20], &d);
            return 20;
        },
        .sha256, .sha256_truncated => {
            var d: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(cd_blob, &d, .{});
            const n: u8 = if (hash_type == .sha256_truncated) 20 else 32;
            @memcpy(out[0..n], d[0..n]);
            return n;
        },
        .sha384 => {
            var d: [48]u8 = undefined;
            std.crypto.hash.sha2.Sha384.hash(cd_blob, &d, .{});
            @memcpy(out[0..48], &d);
            return 48;
        },
        _ => return null,
    }
}

// ---------------------------------------------------------------------------------------------
// tests

/// Builds a minimal but structurally valid CodeDirectory blob (version 0x20400) over `code`.
fn buildCd(buf: []u8, hash_type: HashType, page_log2: u8, code: []const u8, ident: []const u8, n_special: u32) []u8 {
    const hs: usize = hash_type.digestLen();
    const page: usize = @as(usize, 1) << @intCast(page_log2);
    const n_code: usize = (code.len + page - 1) / page;
    const header: usize = 88;
    const ident_off = header;
    const hash_off = ident_off + ident.len + 1 + n_special * hs;
    const total = hash_off + n_code * hs;
    @memset(buf[0..total], 0);
    std.mem.writeInt(u32, buf[0..4], CSMAGIC_CODEDIRECTORY, .big);
    std.mem.writeInt(u32, buf[4..8], @intCast(total), .big);
    std.mem.writeInt(u32, buf[8..12], 0x20400, .big);
    std.mem.writeInt(u32, buf[12..16], 0x2, .big); // adhoc
    std.mem.writeInt(u32, buf[16..20], @intCast(hash_off), .big);
    std.mem.writeInt(u32, buf[20..24], @intCast(ident_off), .big);
    std.mem.writeInt(u32, buf[24..28], n_special, .big);
    std.mem.writeInt(u32, buf[28..32], @intCast(n_code), .big);
    std.mem.writeInt(u32, buf[32..36], @intCast(code.len), .big);
    buf[36] = @intCast(hs);
    buf[37] = @intFromEnum(hash_type);
    buf[38] = 0;
    buf[39] = page_log2;
    @memcpy(buf[ident_off..][0..ident.len], ident);
    for (0..n_code) |k| {
        const start = k * page;
        const end = @min(start + page, code.len);
        var d: [48]u8 = undefined;
        _ = cdhashOf(hash_type, code[start..end], &d).?;
        @memcpy(buf[hash_off + k * hs ..][0..hs], d[0..hs]);
    }
    return buf[0..total];
}

/// Wraps blobs into a SuperBlob. `slots` is a list of (slot, blob bytes).
fn buildSuperBlob(buf: []u8, slots: []const struct { u32, []const u8 }) []u8 {
    const index_len = 12 + slots.len * 8;
    var pos = index_len;
    for (slots, 0..) |s, i| {
        std.mem.writeInt(u32, buf[12 + i * 8 ..][0..4], s[0], .big);
        std.mem.writeInt(u32, buf[16 + i * 8 ..][0..4], @intCast(pos), .big);
        @memcpy(buf[pos..][0..s[1].len], s[1]);
        pos += s[1].len;
    }
    std.mem.writeInt(u32, buf[0..4], CSMAGIC_EMBEDDED_SIGNATURE, .big);
    std.mem.writeInt(u32, buf[4..8], @intCast(pos), .big);
    std.mem.writeInt(u32, buf[8..12], @intCast(slots.len), .big);
    return buf[0..pos];
}

test "blobs: synthetic SuperBlob with a v0x20400 CodeDirectory" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 64);
    var code_buf: [1800]u8 = undefined;
    for (&code_buf, 0..) |*b, i| b.* = @intCast('a' + (i % 26));
    const code: []const u8 = &code_buf;
    var cdbuf: [4096]u8 = undefined;
    const cd_blob = buildCd(&cdbuf, .sha256, 12, code, "com.machre.test", 2);
    var sbbuf: [8192]u8 = undefined;
    const sb = buildSuperBlob(&sbbuf, &.{.{ 0, cd_blob }});
    const sig = (try parseSuperBlob(arena, Reader.init(sb, 0), 100, @intCast(sb.len), &Limits.default, &d)).?;
    try std.testing.expectEqual(@as(usize, 1), sig.blobs.len);
    try std.testing.expectEqual(@as(u32, 1), sig.count_declared);
    const cd = sig.cd().?;
    try std.testing.expectEqualStrings("com.machre.test", cd.identifier);
    try std.testing.expectEqual(@as(u32, 0x20400), cd.version);
    try std.testing.expectEqual(@as(u64, 4096), cd.pageSize());
    try std.testing.expectEqual(@as(usize, 1), cd.code_hashes.len);
    try std.testing.expectEqual(@as(usize, 2), cd.special_hashes.len);
    try std.testing.expect(!cd.isSpecialSlotBound(1) and !cd.isSpecialSlotBound(3));
    try std.testing.expect(cd.isAdhoc() and !cd.isLinkerSigned());
    var digest: [48]u8 = undefined;
    const n = cdhashOf(.sha256, cd_blob, &digest).?;
    try std.testing.expectEqualSlices(u8, digest[0..20], &cd.cdhash);
    try std.testing.expectEqualSlices(u8, digest[0..n], cd.cdhash_full);
    try std.testing.expect(!d.hasErrors());
}

test "blobs: dual CodeDirectories pick sha256" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 64);
    var code_buf: [100]u8 = @splat('x');
    const code: []const u8 = &code_buf;
    var b1: [2048]u8 = undefined;
    var b2: [2048]u8 = undefined;
    const cd1 = buildCd(&b1, .sha1, 12, code, "dual", 0);
    const cd2 = buildCd(&b2, .sha256, 12, code, "dual", 0);
    var sbbuf: [8192]u8 = undefined;
    const sb = buildSuperBlob(&sbbuf, &.{ .{ 0, cd1 }, .{ extra.CSSLOT_ALTERNATE_CODEDIRECTORIES, cd2 } });
    const sig = (try parseSuperBlob(arena, Reader.init(sb, 0), 0, @intCast(sb.len), &Limits.default, &d)).?;
    try std.testing.expectEqual(@as(usize, 2), sig.code_directories.len);
    try std.testing.expectEqual(@as(?u8, 1), sig.best);
    try std.testing.expectEqual(HashType.sha256, sig.cd().?.hash_type);
    try std.testing.expectEqual(@as(u8, 20), @as(u8, @intCast(sig.code_directories[0].cdhash_full.len)));
}

test "blobs: every prefix of a valid SuperBlob parses without error" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var cdbuf: [4096]u8 = undefined;
    const cd_blob = buildCd(&cdbuf, .sha256, 12, "hello world", "trunc", 2);
    var sbbuf: [8192]u8 = undefined;
    const sb = buildSuperBlob(&sbbuf, &.{ .{ 0, cd_blob }, .{ extra.CSSLOT_REQUIREMENTS, &[_]u8{ 0xfa, 0xde, 0x0c, 0x01, 0, 0, 0, 12, 0, 0, 0, 0 } } });
    for (0..sb.len + 1) |n| {
        var d = Diagnostics.init(arena, 64);
        _ = try parseSuperBlob(arena, Reader.init(sb[0..n], 0), 0, @intCast(n), &Limits.default, &d);
    }
    // Paranoid limits clamp instead of looping.
    var d2 = Diagnostics.init(arena, 64);
    const sig = (try parseSuperBlob(arena, Reader.init(sb, 0), 0, @intCast(sb.len), &Limits.paranoid, &d2)).?;
    try std.testing.expectEqual(@as(usize, 2), sig.blobs.len);
    try std.testing.expect(sig.requirements != null);
}

test "blobs: absurd header fields are clamped, not trusted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 64);
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], CSMAGIC_EMBEDDED_SIGNATURE, .big);
    std.mem.writeInt(u32, buf[4..8], 0xffff_ffff, .big);
    std.mem.writeInt(u32, buf[8..12], 0xffff_ffff, .big);
    const sig = (try parseSuperBlob(arena, Reader.init(&buf, 0), 0, buf.len, &Limits.default, &d)).?;
    try std.testing.expect(sig.truncated);
    try std.testing.expectEqual(@as(usize, 0), sig.code_directories.len);
    try std.testing.expect(d.has(.codesign, .count_clamped));
    // CodeDirectory with an out-of-range hashOffset.
    var cdbuf: [128]u8 = undefined;
    @memset(&cdbuf, 0);
    std.mem.writeInt(u32, cdbuf[0..4], CSMAGIC_CODEDIRECTORY, .big);
    std.mem.writeInt(u32, cdbuf[4..8], 128, .big);
    std.mem.writeInt(u32, cdbuf[8..12], 0x20400, .big);
    std.mem.writeInt(u32, cdbuf[16..20], 0xffff_fff0, .big); // hashOffset
    std.mem.writeInt(u32, cdbuf[24..28], 0xffff_fff0, .big); // nSpecialSlots
    std.mem.writeInt(u32, cdbuf[28..32], 0xffff_fff0, .big); // nCodeSlots
    cdbuf[36] = 32;
    cdbuf[37] = 2;
    cdbuf[39] = 12;
    const cd = (try parseCodeDirectory(arena, 0, &cdbuf, &Limits.default, &d)).?;
    try std.testing.expectEqual(@as(usize, 0), cd.code_hashes.len);
    try std.testing.expect(cd.hashes_truncated);
}
