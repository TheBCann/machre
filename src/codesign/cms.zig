//! codesign/cms.zig — CMS SignedData walker: certificate chain names, marker OIDs, signing time.
//! Imports: core/diag, core/limits, core/sanitize, codesign/asn1.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");
const asn1 = @import("asn1.zig");

pub const oid_signed_data = "1.2.840.113549.1.7.2";
pub const oid_signing_time = "1.2.840.113549.1.9.5";
pub const oid_timestamp_token = "1.2.840.113549.1.9.16.2.14";
pub const oid_cn = "2.5.4.3";
pub const oid_ou = "2.5.4.11";
pub const oid_o = "2.5.4.10";
pub const oid_c = "2.5.4.6";
pub const oid_uid = "0.9.2342.19200300.100.1.1";
/// Apple marker OIDs (`certificate leaf[field.<oid>]` in designated requirements).
pub const oid_apple_prefix = "1.2.840.113635.100";
pub const oid_marker_developer_id_app = "1.2.840.113635.100.6.1.13";
pub const oid_marker_mac_app_store = "1.2.840.113635.100.6.1.9";
pub const oid_marker_developer_id_installer = "1.2.840.113635.100.6.1.14";
pub const oid_marker_developer_id_ca = "1.2.840.113635.100.6.2.6";
pub const oid_marker_mac_developer = "1.2.840.113635.100.6.1.12";
pub const oid_marker_apple_software_signing = "1.2.840.113635.100.6.22";

pub const CertName = struct {
    cn: ?[]const u8,
    ou: ?[]const u8,
    o: ?[]const u8,
    c: ?[]const u8,
    uid: ?[]const u8,

    pub const empty: CertName = .{ .cn = null, .ou = null, .o = null, .c = null, .uid = null };
    /// The name codesign shows on an `Authority=` line.
    pub fn display(n: CertName) []const u8 {
        return n.cn orelse n.o orelse n.ou orelse "(unnamed)";
    }
    pub fn eql(a: CertName, b: CertName) bool {
        return optEql(a.cn, b.cn) and optEql(a.ou, b.ou) and optEql(a.o, b.o) and optEql(a.c, b.c) and optEql(a.uid, b.uid);
    }
    fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        return std.mem.eql(u8, a.?, b.?);
    }
    pub fn isEmpty(n: CertName) bool {
        return n.cn == null and n.ou == null and n.o == null and n.c == null and n.uid == null;
    }
};
pub const Certificate = struct {
    subject: CertName,
    issuer: CertName,
    serial_hex: []const u8,
    not_before: ?i64,
    not_after: ?i64,
    is_self_signed: bool,
    sha256: [32]u8,
    der: []const u8,
    /// Apple marker OIDs present as extensions: 1.2.840.113635.100.6.1.13 Developer ID Application,
    /// .6.1.9 Mac App Store, .6.1.14 Developer ID Installer, .6.2.6 Developer ID CA, .6.1.12 Mac Developer,
    /// .6.22 Apple Software Signing.
    marker_oids: []const []const u8,

    pub fn hasMarker(c: *const Certificate, oid: []const u8) bool {
        for (c.marker_oids) |m| if (std.mem.eql(u8, m, oid)) return true;
        return false;
    }
};
pub const Cms = struct {
    certificates: []const Certificate,
    chain: []const u32, // leaf -> root indices (codesign Authority= order)
    signing_time: ?i64,
    has_timestamp_token: bool,
    digest_algorithm: ?[]const u8,
    signer_count: u32,
    ber_indefinite: bool,
    truncated: bool,
    pub const empty: Cms = .{ .certificates = &.{}, .chain = &.{}, .signing_time = null, .has_timestamp_token = false, .digest_algorithm = null, .signer_count = 0, .ber_indefinite = false, .truncated = false };
    pub fn leaf(c: *const Cms) ?*const Certificate {
        if (c.chain.len != 0 and c.chain[0] < c.certificates.len) return &c.certificates[c.chain[0]];
        if (c.certificates.len != 0) return &c.certificates[0];
        return null;
    }
    pub fn authorityNames(c: *const Cms, arena: Allocator) Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (c.chain) |i| if (i < c.certificates.len) try out.append(arena, c.certificates[i].subject.display());
        return out.toOwnedSlice(arena);
    }
    pub fn hasMarker(c: *const Cms, oid: []const u8) bool {
        for (c.certificates) |cert| if (cert.hasMarker(oid)) return true;
        return false;
    }
};

fn digestName(oid_content: []const u8) ?[]const u8 {
    if (asn1.oidEquals(oid_content, "1.3.14.3.2.26")) return "sha1";
    if (asn1.oidEquals(oid_content, "2.16.840.1.101.3.4.2.1")) return "sha256";
    if (asn1.oidEquals(oid_content, "2.16.840.1.101.3.4.2.2")) return "sha384";
    if (asn1.oidEquals(oid_content, "2.16.840.1.101.3.4.2.3")) return "sha512";
    return null;
}

pub fn parse(arena: Allocator, bytes: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Cms {
    var out: Cms = .empty;
    if (bytes.len == 0) return out;
    var certs: std.ArrayList(Certificate) = .empty;
    var w = asn1.Walker.init(bytes, limits);
    var cert_end: usize = 0;
    while (true) {
        const node = w.next() catch |e| {
            if (!diags.has(.cms, .der_malformed))
                diags.warn(.cms, .der_malformed, null, "CMS blob is malformed ({t}); parsed {d} certificates", .{ e, certs.items.len });
            out.truncated = true;
            break;
        } orelse break;
        const t = node.tlv;
        if (t.indefinite) out.ber_indefinite = true;
        if (t.class == .universal and t.tag == asn1.tag_oid and !t.constructed) {
            if (asn1.oidEquals(t.content, oid_timestamp_token)) out.has_timestamp_token = true;
            if (out.digest_algorithm == null) {
                if (digestName(t.content)) |n| out.digest_algorithm = n;
            }
        }
        if (t.constructed and t.class == .universal and t.tag == asn1.tag_sequence) {
            if (out.signing_time == null) out.signing_time = readSigningTime(t);
            if (node.offset >= cert_end and certs.items.len < limits.max_cms_certs and looksLikeCertificate(t)) {
                const end = node.offset + t.total_len;
                if (end <= bytes.len) {
                    if (try parseCertificate(arena, bytes[node.offset..end], limits, diags)) |c| {
                        try certs.append(arena, c);
                        cert_end = end;
                    }
                }
            }
        }
    }
    out.certificates = try certs.toOwnedSlice(arena);
    out.chain = try buildChain(arena, out.certificates);
    out.signer_count = countSigners(bytes, limits);
    return out;
}

/// SEQUENCE { OID signingTime, SET { UTCTime } }
fn readSigningTime(t: asn1.Tlv) ?i64 {
    var it = asn1.children(t);
    const oid = (it.next() catch null) orelse return null;
    if (oid.tag != asn1.tag_oid or !asn1.oidEquals(oid.content, oid_signing_time)) return null;
    const set = (it.next() catch null) orelse return null;
    if (!set.constructed) return null;
    var sit = asn1.children(set);
    const time = (sit.next() catch null) orelse return null;
    return asn1.readTime(time);
}

/// A definite-length SEQUENCE whose children are SEQUENCE, SEQUENCE, BIT STRING is an X.509 Certificate.
fn looksLikeCertificate(t: asn1.Tlv) bool {
    if (t.indefinite) return false;
    var it = asn1.children(t);
    const tbs = (it.next() catch null) orelse return false;
    if (!tbs.constructed or tbs.tag != asn1.tag_sequence or tbs.class != .universal) return false;
    const alg = (it.next() catch null) orelse return false;
    if (!alg.constructed or alg.tag != asn1.tag_sequence or alg.class != .universal) return false;
    const sig = (it.next() catch null) orelse return false;
    if (sig.constructed or sig.tag != asn1.tag_bit_string or sig.class != .universal) return false;
    return (it.next() catch null) == null;
}

fn parseCertificate(arena: Allocator, der: []const u8, limits: *const Limits, diags: *Diagnostics) Allocator.Error!?Certificate {
    const t = asn1.read(der, 0) catch return null;
    var it = asn1.children(t);
    const tbs = (it.next() catch null) orelse return null;
    var c: Certificate = .{
        .subject = .empty,
        .issuer = .empty,
        .serial_hex = "",
        .not_before = null,
        .not_after = null,
        .is_self_signed = false,
        .sha256 = undefined,
        .der = der,
        .marker_oids = &.{},
    };
    std.crypto.hash.sha2.Sha256.hash(der, &c.sha256, .{});

    var tit = asn1.children(tbs);
    var cur = (tit.next() catch null) orelse return c;
    if (cur.class == .context and cur.tag == 0) cur = (tit.next() catch null) orelse return c;
    if (cur.tag == asn1.tag_integer and cur.class == .universal) {
        var content = cur.content;
        if (content.len > 1 and content[0] == 0) content = content[1..];
        c.serial_hex = try std.fmt.allocPrint(arena, "{x}", .{content});
    }
    const alg = (tit.next() catch null) orelse return c;
    _ = alg;
    const issuer = (tit.next() catch null) orelse return c;
    c.issuer = parseName(issuer);
    const validity = (tit.next() catch null) orelse return c;
    {
        var vit = asn1.children(validity);
        if (vit.next() catch null) |nb| c.not_before = asn1.readTime(nb);
        if (vit.next() catch null) |na| c.not_after = asn1.readTime(na);
    }
    const subject = (tit.next() catch null) orelse return c;
    c.subject = parseName(subject);
    c.is_self_signed = !c.subject.isEmpty() and c.subject.eql(c.issuer);
    _ = (tit.next() catch null) orelse return c; // subjectPublicKeyInfo
    // Optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
    var markers: std.ArrayList([]const u8) = .empty;
    while (tit.next() catch null) |ext| {
        if (ext.class != .context or ext.tag != 3) continue;
        var eit = asn1.children(ext);
        const list = (eit.next() catch null) orelse break;
        var lit = asn1.children(list);
        var n: u32 = 0;
        while (lit.next() catch null) |e| {
            n += 1;
            if (n > limits.max_asn1_nodes) break;
            var oit = asn1.children(e);
            const oid = (oit.next() catch null) orelse continue;
            if (oid.tag != asn1.tag_oid or oid.class != .universal) continue;
            if (!isApple(oid.content)) continue;
            const dotted = try asn1.oidString(arena, oid.content);
            if (markers.items.len < limits.max_cms_certs * 8) try markers.append(arena, dotted);
        }
    }
    c.marker_oids = try markers.toOwnedSlice(arena);
    _ = diags;
    return c;
}

fn isApple(oid_content: []const u8) bool {
    var it: asn1.OidIterator = .{ .content = oid_content };
    const want = [_]u64{ 1, 2, 840, 113635, 100 };
    for (want) |x| {
        const got = it.next() orelse return false;
        if (got != x) return false;
    }
    return true;
}

/// Name = SEQUENCE OF SET OF SEQUENCE { OID type, value }.
fn parseName(t: asn1.Tlv) CertName {
    var n: CertName = .empty;
    var it = asn1.children(t);
    var guard: u32 = 0;
    while (it.next() catch null) |set| {
        guard += 1;
        if (guard > 64) break;
        var sit = asn1.children(set);
        while (sit.next() catch null) |seq| {
            var ait = asn1.children(seq);
            const oid = (ait.next() catch null) orelse continue;
            const val = (ait.next() catch null) orelse continue;
            if (oid.tag != asn1.tag_oid or oid.class != .universal) continue;
            if (!sanitize.isClean(val.content, .json)) continue;
            if (asn1.oidEquals(oid.content, oid_cn)) {
                if (n.cn == null) n.cn = val.content;
            } else if (asn1.oidEquals(oid.content, oid_ou)) {
                if (n.ou == null) n.ou = val.content;
            } else if (asn1.oidEquals(oid.content, oid_o)) {
                if (n.o == null) n.o = val.content;
            } else if (asn1.oidEquals(oid.content, oid_c)) {
                if (n.c == null) n.c = val.content;
            } else if (asn1.oidEquals(oid.content, oid_uid)) {
                if (n.uid == null) n.uid = val.content;
            }
        }
    }
    return n;
}

/// leaf -> root: the certificate nobody issued, then each issuer in turn.
fn buildChain(arena: Allocator, certs: []const Certificate) Allocator.Error![]const u32 {
    if (certs.len == 0) return &.{};
    var leaf: ?usize = null;
    for (certs, 0..) |c, i| {
        if (c.is_self_signed) continue;
        var issued_another = false;
        for (certs, 0..) |o, j| {
            if (i == j) continue;
            if (o.issuer.eql(c.subject)) issued_another = true;
        }
        if (!issued_another) {
            leaf = i;
            break;
        }
    }
    const start = leaf orelse 0;
    var out: std.ArrayList(u32) = .empty;
    var seen: [64]bool = @splat(false);
    var cur: usize = start;
    var steps: usize = 0;
    while (steps <= certs.len and cur < certs.len) : (steps += 1) {
        if (cur < seen.len) {
            if (seen[cur]) break;
            seen[cur] = true;
        }
        try out.append(arena, @intCast(cur));
        if (certs[cur].is_self_signed) break;
        var next: ?usize = null;
        for (certs, 0..) |o, j| {
            if (j == cur) continue;
            if (o.subject.eql(certs[cur].issuer)) {
                next = j;
                break;
            }
        }
        cur = next orelse break;
    }
    return out.toOwnedSlice(arena);
}

/// ContentInfo { OID signedData, [0] { SignedData { .., SET signerInfos } } }; 0 when the shape is unexpected.
fn countSigners(bytes: []const u8, limits: *const Limits) u32 {
    _ = limits;
    const top = asn1.read(bytes, 0) catch return 0;
    var it = asn1.children(top);
    const oid = (it.next() catch null) orelse return 0;
    if (oid.tag != asn1.tag_oid or !asn1.oidEquals(oid.content, oid_signed_data)) return 0;
    const c0 = (it.next() catch null) orelse return 0;
    var cit = asn1.children(c0);
    const sd = (cit.next() catch null) orelse return 0;
    var sit = asn1.children(sd);
    var last_set: ?asn1.Tlv = null;
    var guard: u32 = 0;
    while (sit.next() catch null) |child| {
        guard += 1;
        if (guard > 32) break;
        if (child.class == .universal and child.tag == asn1.tag_set and child.constructed) last_set = child;
    }
    const signers = last_set orelse return 0;
    var n: u32 = 0;
    var nit = asn1.children(signers);
    while (nit.next() catch null) |_| {
        n += 1;
        if (n > 1024) break;
    }
    return n;
}

/// Offline (unverified) trust-ladder approximation from the leaf certificate's marker OIDs; used when
/// Security.framework is unavailable and always labelled "(offline, unverified)".
pub const OfflineTrust = enum {
    platform,
    app_store,
    developer_id,
    other_certificate,
    adhoc,
    unsigned,
    unknown,

    pub fn label(t: OfflineTrust) []const u8 {
        return switch (t) {
            .platform => "PLATFORM (Apple)",
            .app_store => "MAC APP STORE",
            .developer_id => "DEVELOPER ID",
            .other_certificate => "SIGNED (other certificate)",
            .adhoc => "AD HOC",
            .unsigned => "UNSIGNED",
            .unknown => "UNKNOWN",
        };
    }
};
pub fn offlineTrust(c: ?*const Cms, cd_flags: u32, cd_platform: u8) OfflineTrust {
    if (cd_platform != 0) return .platform;
    if (c) |cms| if (cms.certificates.len != 0) {
        if (cms.leaf()) |l| {
            if (l.hasMarker(oid_marker_apple_software_signing)) return .platform;
            if (l.hasMarker(oid_marker_mac_app_store)) return .app_store;
            if (l.hasMarker(oid_marker_developer_id_app) or l.hasMarker(oid_marker_developer_id_installer)) return .developer_id;
        }
        return .other_certificate;
    };
    if (cd_flags & 0x2 != 0) return .adhoc;
    if (cd_flags == 0) return .unsigned;
    return .unknown;
}

// ---------------------------------------------------------------------------------------------
// tests

const TestBuf = struct {
    list: std.ArrayList(u8) = .empty,
    a: Allocator,
    fn tlv(b: *TestBuf, tag: u8, content: []const u8) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try out.append(b.a, tag);
        if (content.len < 0x80) {
            try out.append(b.a, @intCast(content.len));
        } else if (content.len < 0x100) {
            try out.append(b.a, 0x81);
            try out.append(b.a, @intCast(content.len));
        } else {
            try out.append(b.a, 0x82);
            try out.append(b.a, @intCast(content.len >> 8));
            try out.append(b.a, @intCast(content.len & 0xff));
        }
        try out.appendSlice(b.a, content);
        return out.toOwnedSlice(b.a);
    }
    fn cat(b: *TestBuf, parts: []const []const u8) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        for (parts) |p| try out.appendSlice(b.a, p);
        return out.toOwnedSlice(b.a);
    }
    /// SET { SEQUENCE { OID, UTF8String } } — one RDN.
    fn rdn(b: *TestBuf, oid: []const u8, value: []const u8) Allocator.Error![]const u8 {
        const o = try b.tlv(0x06, oid);
        const v = try b.tlv(0x0c, value);
        const seq = try b.tlv(0x30, try b.cat(&.{ o, v }));
        return b.tlv(0x31, seq);
    }
    fn cert(b: *TestBuf, subject_cn: []const u8, issuer_cn: []const u8, marker: ?[]const u8) Allocator.Error![]const u8 {
        const serial = try b.tlv(0x02, &[_]u8{ 0x00, 0x2a });
        const alg = try b.tlv(0x30, "");
        const issuer = try b.tlv(0x30, try b.rdn(&[_]u8{ 0x55, 0x04, 0x03 }, issuer_cn));
        const validity = try b.tlv(0x30, try b.cat(&.{ try b.tlv(0x17, "260116163918Z"), try b.tlv(0x17, "310116163918Z") }));
        const subject = try b.tlv(0x30, try b.rdn(&[_]u8{ 0x55, 0x04, 0x03 }, subject_cn));
        const spki = try b.tlv(0x30, "");
        var tbs_parts: std.ArrayList([]const u8) = .empty;
        try tbs_parts.appendSlice(b.a, &.{ serial, alg, issuer, validity, subject, spki });
        if (marker) |m| {
            const ext = try b.tlv(0x30, try b.tlv(0x06, m));
            const exts = try b.tlv(0x30, ext);
            try tbs_parts.append(b.a, try b.tlv(0xa3, exts));
        }
        const tbs = try b.tlv(0x30, try b.cat(tbs_parts.items));
        const sigalg = try b.tlv(0x30, "");
        const sig = try b.tlv(0x03, &[_]u8{ 0x00, 0x01 });
        return b.tlv(0x30, try b.cat(&.{ tbs, sigalg, sig }));
    }
};

test "cms: certificate chain, markers, signing time, offline ladder" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var b: TestBuf = .{ .a = arena };
    var d = Diagnostics.init(arena, 64);
    // Apple Software Signing marker 1.2.840.113635.100.6.22 = 2a 86 48 86 f7 63 64 06 16
    const marker = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x16 };
    const leaf = try b.cert("Software Signing", "Apple Code Signing Certification Authority", &marker);
    const mid = try b.cert("Apple Code Signing Certification Authority", "Apple Root CA", null);
    const root = try b.cert("Apple Root CA", "Apple Root CA", null);
    const certs_set = try b.tlv(0xa0, try b.cat(&.{ leaf, mid, root }));
    // signed attribute: SEQUENCE { OID signingTime, SET { UTCTime } }
    const st = try b.tlv(0x30, try b.cat(&.{ try b.tlv(0x06, &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05 }), try b.tlv(0x31, try b.tlv(0x17, "260116163918Z")) }));
    const signer = try b.tlv(0x30, try b.cat(&.{ try b.tlv(0x02, &[_]u8{1}), try b.tlv(0xa0, st) }));
    const signers = try b.tlv(0x31, signer);
    const digest_algs = try b.tlv(0x31, try b.tlv(0x30, try b.tlv(0x06, &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 })));
    const encap = try b.tlv(0x30, try b.tlv(0x06, &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 }));
    const sd = try b.tlv(0x30, try b.cat(&.{ try b.tlv(0x02, &[_]u8{1}), digest_algs, encap, certs_set, signers }));
    const content = try b.tlv(0xa0, sd);
    const top = try b.tlv(0x30, try b.cat(&.{ try b.tlv(0x06, &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 }), content }));

    const cms = try parse(arena, top, &Limits.default, &d);
    try std.testing.expectEqual(@as(usize, 3), cms.certificates.len);
    const names = try cms.authorityNames(arena);
    try std.testing.expectEqual(@as(usize, 3), names.len);
    try std.testing.expectEqualStrings("Software Signing", names[0]);
    try std.testing.expectEqualStrings("Apple Code Signing Certification Authority", names[1]);
    try std.testing.expectEqualStrings("Apple Root CA", names[2]);
    try std.testing.expect(cms.hasMarker(oid_marker_apple_software_signing));
    try std.testing.expectEqual(@as(?i64, 1768581558), cms.signing_time);
    try std.testing.expectEqualStrings("sha256", cms.digest_algorithm.?);
    try std.testing.expectEqual(@as(u32, 1), cms.signer_count);
    try std.testing.expect(!cms.has_timestamp_token);
    try std.testing.expectEqualStrings("2a", cms.certificates[0].serial_hex);
    try std.testing.expect(cms.certificates[2].is_self_signed);
    try std.testing.expectEqual(OfflineTrust.platform, offlineTrust(&cms, 0, 0));
    try std.testing.expectEqual(OfflineTrust.platform, offlineTrust(null, 0, 26));
    try std.testing.expectEqual(OfflineTrust.adhoc, offlineTrust(null, 0x20002, 0));
    try std.testing.expectEqual(OfflineTrust.unsigned, offlineTrust(null, 0, 0));
    try std.testing.expect(!d.hasErrors());
}

test "cms: truncation and garbage never trap" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var b: TestBuf = .{ .a = arena };
    const leaf = try b.cert("A", "B", null);
    var d = Diagnostics.init(arena, 64);
    for (0..leaf.len + 1) |n| {
        var dd = Diagnostics.init(arena, 8);
        _ = try parse(arena, leaf[0..n], &Limits.paranoid, &dd);
    }
    var garbage: [512]u8 = undefined;
    for (&garbage, 0..) |*x, i| x.* = @truncate(i *% 251);
    const cms = try parse(arena, &garbage, &Limits.paranoid, &d);
    try std.testing.expectEqual(@as(usize, 0), cms.chain.len);
    try std.testing.expectEqual(@as(usize, 0), (try cms.authorityNames(arena)).len);
    try std.testing.expect(cms.leaf() == null or cms.certificates.len != 0);
}

test "cms: BER indefinite lengths (Apple platform binaries)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Diagnostics.init(arena, 64);
    // SEQUENCE(indefinite) { OID signedData, [0](indefinite) { SEQUENCE(indefinite) { INTEGER 1 } } }
    const bytes = [_]u8{
        0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        0xa0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const cms = try parse(arena, &bytes, &Limits.default, &d);
    try std.testing.expect(cms.ber_indefinite);
    try std.testing.expectEqual(@as(usize, 0), cms.certificates.len);
    try std.testing.expectEqual(@as(u32, 0), cms.signer_count);
}
