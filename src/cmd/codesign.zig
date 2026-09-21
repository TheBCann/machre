//! cmd/codesign.zig — embedded signature parsed in Zig + Security.framework verdict + trust ladder. Owned by WP3 (DESIGN.md §12).
//! Imports: cli/context, output/*, analysis/analysis, codesign/*, darwin/security, core/*, bundle/bundle,
//! plist/plist, cmd/entitlements.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const sanitize = @import("../core/sanitize.zig");
const fmt = @import("../core/fmt.zig");
const version = @import("../core/version.zig");
const fat = @import("../core/fat.zig");
const Image = @import("../core/image.zig").Image;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const blobs = @import("../codesign/blobs.zig");
const hashes = @import("../codesign/hashes.zig");
const requirements = @import("../codesign/requirements.zig");
const ent_mod = @import("../codesign/entitlements.zig");
const cms_mod = @import("../codesign/cms.zig");
const security = @import("../darwin/security.zig");
const cmd_entitlements = @import("entitlements.zig");
const bundle_mod = @import("../bundle/bundle.zig");
const plist = @import("../plist/plist.zig");

pub const command: Command = .{
    .name = "codesign",
    .summary = "embedded signature parsed in Zig + Security.framework verdict + trust ladder",
    .run = run,
    .flags = &.{ "--entitlements", "--requirements", "--hashes", "--cms", "--der", "--no-verify-pages" },
    .aliases = &.{},
    .needs_macho = true,
};

const View = struct {
    sig: ?*const blobs.Signature,
    ver: ?*const hashes.Verification,
    reqs: ?*const requirements.RequirementSet,
    ents: *const ent_mod.Entitlements,
    cms: ?*const cms_mod.Cms,
    verdict: *const security.Verdict,
    /// The CodeDirectory codesign would present (null when unsigned).
    cd: ?*const blobs.CodeDirectory,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const multi = ctx.images.len > 1;
    const verify_pages = !ctx.args.flag("--no-verify-pages");
    for (ctx.images) |*img| {
        var an = Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{ .security = !ctx.no_security, .network = !ctx.no_network, .bundle_path = ctx.bundle_path });
        defer an.deinit();
        const sig = try an.signature();
        const v: View = .{
            .sig = sig,
            .ver = if (verify_pages) try an.verification() else null,
            .reqs = try an.requirements(),
            .ents = try an.entitlements(),
            .cms = try an.cms(),
            .verdict = try an.security(),
            .cd = if (sig) |s| s.cd() else null,
        };
        if (ctx.sink.isJson()) {
            try json.beginArch(&ctx.sink.json, img);
            try writeJson(ctx, &ctx.sink.json, img, v);
            try json.endArch(&ctx.sink.json);
            continue;
        }
        const out = ctx.sink.out;
        if (multi and !ctx.otool_compat) {
            var buf: [32]u8 = undefined;
            try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), true);
        }
        if (ctx.args.flag("--requirements") and ctx.otool_compat) {
            try writeRequirementsCompat(ctx, out, v);
            continue;
        }
        try writeCodesignDvvv(ctx, out, img, v, try analysedBundle(ctx));
        if (ctx.otool_compat) continue;
        try writeMachreSections(ctx, out, img, v);
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------
// `codesign -dvvv --entitlements -` compatible block (lines 1..N of DESIGN.md §5.4)

/// codesign prefixes the Mach-O shape with the bundle shape when the path it was given is a bundle
/// (`Format=app bundle with Mach-O thin (arm64)`), so `bnd` carries the analysed bundle when there is one.
fn formatString(ctx: *Context, img: *const Image, bnd: ?*const bundle_mod.Bundle) ![]const u8 {
    const prefix: []const u8 = if (bnd) |b| switch (b.kind) {
        .app => "app bundle with ",
        .unknown => "",
        else => "bundle with ",
    } else "";
    var buf: [32]u8 = undefined;
    switch (ctx.file.?.container) {
        .fat => |f| {
            var out: std.ArrayList(u8) = .empty;
            try out.appendSlice(ctx.arena, prefix);
            try out.appendSlice(ctx.arena, "Mach-O universal (");
            var first = true;
            for (f.arches) |a| {
                if (!a.valid) continue;
                if (!first) try out.append(ctx.arena, ' ');
                var nb: [32]u8 = undefined;
                try out.appendSlice(ctx.arena, a.arch.displayName(&nb));
                first = false;
            }
            try out.append(ctx.arena, ')');
            return out.toOwnedSlice(ctx.arena);
        },
        else => return std.fmt.allocPrint(ctx.arena, "{s}Mach-O thin ({s})", .{ prefix, img.arch.displayName(&buf) }),
    }
}

/// The bundle this code object belongs to, or null when there is none. `codesign` promotes a path the
/// way `SecStaticCodeCreateWithPath` does, so `Hello.app` and `Hello.app/Contents/MacOS/Hello` both
/// report the bundle. The seal is not re-verified and nothing is hashed here: only the Info.plist and
/// CodeResources counts `codesign -dvvv` prints are needed. The result is arena-owned.
fn analysedBundle(ctx: *Context) !?*const bundle_mod.Bundle {
    const root = ctx.bundle_path orelse
        try bundle_mod.enclosingBundle(ctx.arena, ctx.io, if (ctx.file) |f| f.path else ctx.path, ctx.limits) orelse
        return null;
    const b = try bundle_mod.analyze(ctx.arena, ctx.gpa, ctx.io, root, .{ .verify_resources = false, .hash_nested = false }, ctx.limits, ctx.diags) orelse return null;
    const p = try ctx.arena.create(bundle_mod.Bundle);
    p.* = b;
    return p;
}

fn writeCodesignDvvv(ctx: *Context, out: *Io.Writer, img: *const Image, v: View, bnd: ?*const bundle_mod.Bundle) !void {
    const a = ctx.arena;
    const cd = v.cd orelse {
        try out.print("{s}: code object is not signed at all\n", .{ctx.display_path});
        return;
    };
    const sig = v.sig.?;
    try out.print("Executable={s}\n", .{try ctx.sink.safe(ctx.file.?.path)});
    try out.print("Identifier={s}\n", .{try ctx.sink.safeMax(cd.identifier, ctx.limits.max_symbol_name)});
    try out.print("Format={s}\n", .{try formatString(ctx, img, bnd)});
    const flag_names = try text.flags(a, cd.flags, version.cs_flags, ",");
    try out.print("CodeDirectory v={x} size={d} flags=0x{x}({s}) hashes={d}+{d} location=embedded\n", .{
        cd.version,
        cdBlobLength(sig, cd),
        cd.flags,
        if (flag_names.len == 0) "none" else flag_names,
        cd.n_code_slots,
        cd.n_special_slots,
    });
    if (cd.platform != 0) try out.print("Platform identifier={d}\n", .{cd.platform});
    try out.print("Hash type={s} size={d}\n", .{ cd.hash_type.name(), cd.hash_size });
    for (sig.code_directories) |c| {
        try out.print("CandidateCDHash {s}={x}\n", .{ c.hash_type.name(), &c.cdhash });
        try out.print("CandidateCDHashFull {s}={x}\n", .{ c.hash_type.name(), c.cdhash_full });
    }
    try out.writeAll("Hash choices=");
    for (sig.code_directories, 0..) |c, i| {
        if (i != 0) try out.writeByte(',');
        try out.writeAll(c.hash_type.name());
    }
    try out.writeByte('\n');
    try out.print("CMSDigest={x}\n", .{cd.cdhash_full});
    try out.print("CMSDigestType={d}\n", .{@intFromEnum(cd.hash_type)});
    try out.print("CDHash={x}\n", .{&cd.cdhash});
    // Signature / authorities
    if (sig.blob(0x10000)) |wrapper| {
        if (wrapper.length > 8) {
            try out.print("Signature size={d}\n", .{wrapper.length - 8});
        } else try out.writeAll(if (cd.isAdhoc()) "Signature=adhoc\n" else "Signature=none\n");
    } else try out.writeAll(if (cd.isAdhoc()) "Signature=adhoc\n" else "Signature=none\n");
    if (v.cms) |c| {
        for (try c.authorityNames(a)) |n| try out.print("Authority={s}\n", .{try ctx.sink.safeMax(n, ctx.limits.max_symbol_name)});
        if (c.signing_time) |t| try out.print("Signed Time={f}\n", .{fmt.Iso8601{ .unix_secs = t }});
    }
    // Sealed data
    // codesign prints the entry count when it can see the bundle's Info.plist, "=bound" when the slot
    // is sealed but the plist is not reachable (a bare Mach-O), and "=not bound" when the slot is empty.
    if (bnd != null and bnd.?.info_plist != null and cd.isSpecialSlotBound(1)) {
        const n: usize = switch (bnd.?.info_plist.?) {
            .dict => |d| d.len,
            else => 0,
        };
        try out.print("Info.plist entries={d}\n", .{n});
    } else if (cd.isSpecialSlotBound(1)) try out.writeAll("Info.plist=bound\n") else try out.writeAll("Info.plist=not bound\n");
    if (cd.team_id) |t| {
        try out.print("TeamIdentifier={s}\n", .{try ctx.sink.safeMax(t, ctx.limits.max_symbol_name)});
    } else try out.writeAll("TeamIdentifier=not set\n");
    if (cd.runtime) |rt| if (rt != 0) try out.print("Runtime Version={f}\n", .{fmt.Version{ .v = rt }});
    if (bnd != null and bnd.?.code_resources != null and cd.isSpecialSlotBound(3)) {
        const cr = &bnd.?.code_resources.?;
        try out.print("Sealed Resources version={d} rules={d} files={d}\n", .{ cr.version, cr.activeRules(), cr.activeFiles() });
    } else if (cd.isSpecialSlotBound(3)) try out.writeAll("Sealed Resources=bound\n") else try out.writeAll("Sealed Resources=none\n");
    if (sig.requirements) |req| {
        const count: usize = if (v.reqs) |rs| rs.requirements.len else 0;
        try out.print("Internal requirements count={d} size={d}\n", .{ count, req.len });
    } else try out.writeAll("Internal requirements=none\n");
    if (ctx.otool_compat or ctx.args.flag("--entitlements")) {
        if (v.ents.preferred()) |value| try cmd_entitlements.writeCodesignDict(ctx.sink, value);
    }
}

/// `codesign -d -r -`: one line per requirement, or the synthesized `# designated => cdhash H"…"`.
fn writeRequirementsCompat(ctx: *Context, out: *Io.Writer, v: View) !void {
    try out.print("Executable={s}\n", .{try ctx.sink.safe(ctx.file.?.path)});
    const cd = v.cd orelse {
        try out.print("{s}: code object is not signed at all\n", .{ctx.display_path});
        return;
    };
    var have_designated = false;
    if (v.reqs) |rs| for (rs.requirements) |r| {
        if (r.type == .designated) have_designated = true;
        try out.print("{s} => {s}\n", .{ r.type.label(), try ctx.sink.safe(r.text) });
    };
    if (!have_designated)
        try out.print("# designated => {s}\n", .{try requirements.synthesizedDesignated(ctx.arena, cd.cdhash)});
}

// ---------------------------------------------------------------------------------------------
// machre-only sections

fn slotLabel(slot: u32) []const u8 {
    return switch (slot) {
        0 => "CodeDirectory",
        1 => "Info.plist hash",
        2 => "Requirements",
        3 => "Resource dir",
        4 => "Application",
        5 => "Entitlements",
        7 => "DER entitlements",
        8 => "Launch constr.",
        9 => "Launch constr.P",
        10 => "Launch constr.R",
        11 => "Library constr.",
        0x1000, 0x1001, 0x1002, 0x1003, 0x1004 => "Alt CodeDirectory",
        0x10000 => "CMS signature",
        0x10001 => "Identification",
        0x10002 => "Ticket",
        else => "unknown slot",
    };
}
fn cdBlobLength(sig: *const blobs.Signature, cd: *const blobs.CodeDirectory) u32 {
    if (sig.blob(cd.slot)) |b| return b.length;
    return @intCast(cd.blob.len);
}

fn writeMachreSections(ctx: *Context, out: *Io.Writer, img: *const Image, v: View) !void {
    const a = ctx.arena;
    const sig = v.sig orelse {
        try out.writeAll("--- machre: embedded signature ---\n");
        try out.writeAll("No LC_CODE_SIGNATURE load command.\n");
        try writeSecuritySection(ctx, out, v);
        return;
    };
    try out.print("--- machre: embedded signature (LC_CODE_SIGNATURE dataoff={d} datasize={d}) ---\n", .{ sig.dataoff, sig.datasize });
    try out.print("SuperBlob magic=0x{x} length={d} count={d}{s}\n", .{ sig.superblob_magic, sig.superblob_length, sig.count_declared, if (sig.truncated) "  (truncated or clamped)" else "" });
    for (sig.blobs) |b| {
        try out.print("  slot 0x{x:<5} {s:<17} offset {d:<6} length {d:<6} magic 0x{x}{s}\n", .{
            b.slot,
            slotLabel(b.slot),
            b.offset,
            b.length,
            b.magic,
            if (b.truncated) "  (truncated)" else "",
        });
    }
    if (v.cd) |cd| {
        try out.print("CodeDirectory page size={d} (2^{d})  code limit={d}  code slots={d}  special slots={d}  platform={d}\n", .{
            cd.pageSize(), cd.page_size_log2, cd.code_limit, cd.n_code_slots, cd.n_special_slots, cd.platform,
        });
        if (cd.exec_seg) |es| {
            const names = try text.flags(a, es.flags, version.exec_seg_flags, ",");
            try out.print("  exec segment base=0x{x} limit=0x{x} flags=0x{x} ({s})\n", .{ es.base, es.limit, es.flags, if (names.len == 0) "none" else names });
        }
        if (v.ver) |ver| {
            if (!ver.hash_type_supported) {
                try out.print("  page hashes: not verified (unsupported hash type {d})\n", .{@intFromEnum(cd.hash_type)});
            } else if (ver.mismatches == 0) {
                try out.print("  page hashes: {d}/{d} match the file on disk\n", .{ ver.pages_ok, ver.pages_checked });
            } else {
                const bad = ver.first_bad_page orelse 0;
                try out.print("  page hashes: {d}/{d} match; first mismatch page {d} (file offset 0x{x})\n", .{ ver.pages_ok, ver.pages_checked, bad, @as(u64, bad) * cd.pageSize() });
            }
            if (!ver.code_limit_within_slice)
                try out.print("  code limit {d} exceeds the {d}-byte slice: only the present pages were checked\n", .{ cd.code_limit, img.r.len() });
        } else try out.writeAll("  page hashes: not verified (--no-verify-pages)\n");
        if (ctx.args.flag("--hashes")) try writeHashTable(ctx, out, cd, v);
    } else try out.writeAll("CodeDirectory: none in this signature\n");

    // Requirements
    var have_designated = false;
    if (v.reqs) |rs| {
        if (rs.requirements.len != 0) {
            try out.writeAll("Designated requirement:\n");
            for (rs.requirements) |r| {
                if (r.type == .designated) have_designated = true;
                try out.print("  {s} => {s}{s}\n", .{ r.type.label(), try ctx.sink.safe(r.text), if (r.truncated) "   (truncated)" else "" });
            }
        }
    }
    if (!have_designated) {
        if (v.cd) |cd| {
            try out.print("Designated requirement ({s}):\n", .{if (sig.requirements == null) "synthesized, no requirements blob" else "synthesized, empty requirements blob"});
            try out.print("  designated => {s}\n", .{try requirements.synthesizedDesignated(a, cd.cdhash)});
        }
    }
    // Entitlements
    const e = v.ents;
    if (e.source == .none) {
        try out.writeAll("Entitlements: none (no XML blob, no DER blob)\n");
    } else {
        try out.print("Entitlements: {d} keys (source {t}", .{ e.keys.len, e.source });
        if (e.xml_raw) |raw| try out.print(", XML payload {d} B", .{raw.len});
        if (e.der_len != 0) try out.print(", DER blob {d} B", .{e.der_len});
        if (e.source == .both) {
            if (e.xml != null and e.der != null) {
                try out.print(", DER {s} XML", .{if (e.disagreement) "!=" else "=="});
            } else try out.writeAll(", XML not parsed");
        }
        try out.writeAll(")\n");
        for (e.keys) |k| {
            const key = try ctx.sink.safeMax(k, ctx.limits.max_symbol_name);
            if (ent_mod.isDangerous(k)) |d| {
                try out.print("  {s}   [dangerous: {s}]\n", .{ key, d.why });
            } else try out.print("  {s}\n", .{key});
        }
        if (ctx.args.flag("--der")) {
            if (e.der) |value| try cmd_entitlements.writeCodesignDict(ctx.sink, value);
        }
    }
    // Certificates
    if (v.cms) |c| {
        if (c.certificates.len == 0) {
            try out.print("Certificates: none decoded from the {d}-byte CMS blob{s}\n", .{ if (sig.cms) |b| b.len else 0, if (c.truncated) " (malformed)" else "" });
        } else {
            try out.print("Certificates: {d} (chain leaf -> root, offline/unverified)\n", .{c.certificates.len});
            for (c.chain, 0..) |idx, i| {
                if (idx >= c.certificates.len) continue;
                const cert = c.certificates[idx];
                try out.print("  {d} {s}\n", .{ i + 1, try ctx.sink.safeMax(cert.subject.display(), ctx.limits.max_symbol_name) });
                if (ctx.args.flag("--cms") or ctx.verbose > 0) {
                    try out.print("      issuer  {s}\n", .{try ctx.sink.safeMax(cert.issuer.display(), ctx.limits.max_symbol_name)});
                    try out.print("      serial  {s}\n", .{try ctx.sink.safe(cert.serial_hex)});
                    if (cert.not_before) |nb| try out.print("      valid   {f} .. {f}\n", .{ fmt.Iso8601{ .unix_secs = nb }, fmt.Iso8601{ .unix_secs = cert.not_after orelse nb } });
                    for (cert.marker_oids) |m| try out.print("      marker  {s}\n", .{try ctx.sink.safe(m)});
                    try out.print("      sha256  {x}\n", .{&cert.sha256});
                }
            }
            if (c.signing_time) |t| try out.print("  signing time {f}\n", .{fmt.Iso8601{ .unix_secs = t }});
            if (c.has_timestamp_token) try out.writeAll("  RFC3161 timestamp token present\n");
        }
    } else try out.writeAll("Certificates: none (no CMS blob)\n");
    if (sig.ticket) |t| try out.print("Stapled notarization ticket: {d} bytes\n", .{t.len});
    try writeSecuritySection(ctx, out, v);
}

fn writeHashTable(ctx: *Context, out: *Io.Writer, cd: *const blobs.CodeDirectory, v: View) !void {
    const a = ctx.arena;
    var t = text.Table.init(a, &.{ .{ .name = "slot", .@"align" = .right }, .{ .name = "name" }, .{ .name = "hash" }, .{ .name = "state" } });
    var n: u32 = 1;
    while (n <= cd.special_hashes.len) : (n += 1) {
        const bound = cd.isSpecialSlotBound(n);
        const state: []const u8 = if (!bound) "not bound" else switch (n) {
            2 => stateOf(if (v.ver) |ver| ver.special.requirements else null),
            5 => stateOf(if (v.ver) |ver| ver.special.entitlements_xml else null),
            7 => stateOf(if (v.ver) |ver| ver.special.entitlements_der else null),
            // -1/-3 are sealed by path; they are verified against the bundle's files on disk when
            // the command was handed a bundle, and are genuinely uncheckable from a bare Mach-O.
            1 => stateOf(if (v.ver) |ver| ver.special.info_plist else null),
            3 => stateOf(if (v.ver) |ver| ver.special.resources else null),
            else => "sealed (blob not in this file)",
        };
        try t.rowFmt(&.{ "-{d}", "{s}", "{x}", "{s}" }, .{ n, version.csSpecialSlotName(n) orelse "?", cd.special_hashes[n - 1], state });
    }
    try t.render(out, 2, ctx.sink.opts.limit);
    if (cd.code_hashes.len != 0) {
        var ct = text.Table.init(a, &.{ .{ .name = "page", .@"align" = .right }, .{ .name = "offset" }, .{ .name = "hash" } });
        for (cd.code_hashes, 0..) |h, i| try ct.rowFmt(&.{ "{d}", "0x{x}", "{x}" }, .{ i, @as(u64, i) * cd.pageSize(), h });
        try ct.render(out, 2, ctx.sink.opts.limit);
    }
}
fn stateOf(b: ?bool) []const u8 {
    if (b) |x| return if (x) "verified" else "MISMATCH";
    return "not checked";
}

fn writeSecuritySection(ctx: *Context, out: *Io.Writer, v: View) !void {
    const cd_flags: ?u32 = if (v.cd) |cd| cd.flags else null;
    const cd_platform: u8 = if (v.cd) |cd| cd.platform else 0;
    const offline = cms_mod.offlineTrust(v.cms, cd_flags orelse 0, cd_platform);
    if (!v.verdict.available) {
        try out.print("Security.framework: not evaluated ({s}); offline ladder (unverified): {s}\n", .{ v.verdict.reason orelse "unavailable", offline.label() });
        return;
    }
    try out.writeAll("--- machre: Security.framework ---\n");
    const flags_text = if (v.verdict.revocation_checked) "kSecCSCheckAllArchitectures | kSecCSEnforceRevocationChecks" else "kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess";
    try out.print("SecStaticCodeCheckValidity({s})   = {d} {s}\n", .{ flags_text, v.verdict.validity_status, v.verdict.validity_status_name });
    const rr = v.verdict.requirement_results;
    try out.print("  {s:<64} = {d} {s}\n", .{ "anchor apple", rr.anchor_apple, security.statusName(rr.anchor_apple) });
    try out.print("  {s:<64} = {d} {s}\n", .{ "anchor apple generic", rr.apple_generic, security.statusName(rr.apple_generic) });
    try out.print("  {s:<64} = {d} {s}\n", .{ "Developer ID (certificate leaf[field.1.2.840.113635.100.6.1.13])", rr.developer_id, security.statusName(rr.developer_id) });
    try out.print("  {s:<64} = {d} {s}\n", .{ "Mac App Store (certificate leaf[field.1.2.840.113635.100.6.1.9])", rr.app_store, security.statusName(rr.app_store) });
    try out.print("  {s:<64} = {d} {s}\n", .{ "notarized", rr.notarized, security.statusName(rr.notarized) });
    try out.print("kSecCodeInfoFlags=0x{x}  kSecCodeInfoFormat=\"{s}\"  kSecCodeInfoIdentifier=\"{s}\"\n", .{
        v.verdict.flags orelse 0,
        try ctx.sink.safeOr(v.verdict.format, "?"),
        try ctx.sink.safeOr(v.verdict.identifier, "?"),
    });
    const sentence = security.trustSentence(v.verdict, cd_flags);
    if (sentence.len != 0) {
        try out.print("Trust ladder: {s}\n", .{sentence});
    } else try out.print("Trust ladder: {s} (offline, unverified)\n", .{offline.label()});
}

// ---------------------------------------------------------------------------------------------
// JSON

fn writeJson(ctx: *Context, js: *Stringify, img: *const Image, v: View) !void {
    const a = ctx.arena;
    try js.objectField("codesign");
    try js.beginObject();
    if (v.sig) |sig| {
        try js.objectField("code_signature");
        try js.beginObject();
        try json.boolean(js, "present", true);
        try json.int(js, "dataoff", sig.dataoff);
        try json.int(js, "datasize", sig.datasize);
        try json.boolean(js, "truncated", sig.truncated);
        try js.objectField("superblob");
        try js.beginObject();
        try json.hex(js, "magic", sig.superblob_magic);
        try js.objectField("magic_name");
        try js.write(version.csMagicName(sig.superblob_magic));
        try json.int(js, "length", sig.superblob_length);
        try json.int(js, "count", sig.count_declared);
        try js.objectField("slots");
        try js.beginArray();
        for (sig.blobs) |b| {
            try js.beginObject();
            try json.int(js, "type", b.slot);
            try js.objectField("type_name");
            try js.write(version.csSlotName(b.slot));
            try json.int(js, "offset", b.offset);
            try json.hex(js, "magic", b.magic);
            try js.objectField("magic_name");
            try js.write(version.csMagicName(b.magic));
            try json.int(js, "length", b.length);
            try js.endObject();
        }
        try js.endArray();
        try js.endObject();

        try js.objectField("code_directories");
        try js.beginArray();
        for (sig.code_directories) |cd| {
            try js.beginObject();
            try json.int(js, "slot", cd.slot);
            try json.hex(js, "version", cd.version);
            try json.flags(js, "flags", cd.flags, version.cs_flags);
            try json.flags(js, "flags_full", cd.flags, version.cs_flags_full);
            try json.int(js, "hash_type", @intFromEnum(cd.hash_type));
            try js.objectField("hash_type_name");
            try js.write(cd.hash_type.name());
            try json.int(js, "hash_size", cd.hash_size);
            try json.int(js, "page_size", cd.pageSize());
            try json.int(js, "platform", cd.platform);
            try json.int(js, "n_code_slots", cd.n_code_slots);
            try json.int(js, "n_special_slots", cd.n_special_slots);
            try json.int(js, "code_limit", cd.code_limit);
            try js.objectField("exec_seg");
            if (cd.exec_seg) |es| {
                try js.beginObject();
                try json.hex(js, "base", es.base);
                try json.hex(js, "limit", es.limit);
                try json.flags(js, "flags", es.flags, version.exec_seg_flags);
                try js.endObject();
            } else try js.write(null);
            try js.objectField("runtime");
            if (cd.runtime) |rt| try js.write(rt) else try js.write(null);
            try json.str(js, a, "identifier", cd.identifier);
            try json.strOpt(js, a, "team_id", cd.team_id);
            try json.bytesHex(js, "cdhash", &cd.cdhash);
            try json.bytesHex(js, "cdhash_full", cd.cdhash_full);
            try js.objectField("special_slots");
            try js.beginArray();
            var n: u32 = 1;
            while (n <= cd.special_hashes.len) : (n += 1) {
                try js.beginObject();
                try json.int(js, "slot", -@as(i32, @intCast(n)));
                try js.objectField("name");
                try js.write(version.csSpecialSlotName(n));
                try json.bytesHex(js, "hash", cd.special_hashes[n - 1]);
                try json.boolean(js, "bound", cd.isSpecialSlotBound(n));
                try js.objectField("verified");
                const verified: ?bool = if (v.ver) |ver| switch (n) {
                    2 => ver.special.requirements,
                    5 => ver.special.entitlements_xml,
                    7 => ver.special.entitlements_der,
                    else => null,
                } else null;
                if (verified) |b| try js.write(b) else try js.write(null);
                try js.endObject();
            }
            try js.endArray();
            try js.objectField("pages");
            if (v.ver != null and cd.slot == (if (sig.cd()) |c| c.slot else 0)) {
                const ver = v.ver.?;
                try js.beginObject();
                try json.int(js, "checked", ver.pages_checked);
                try json.int(js, "ok", ver.pages_ok);
                try json.int(js, "mismatches", ver.mismatches);
                try js.objectField("first_bad");
                if (ver.first_bad_page) |p| try js.write(p) else try js.write(null);
                try json.boolean(js, "code_limit_within_slice", ver.code_limit_within_slice);
                try js.endObject();
            } else try js.write(null);
            try js.endObject();
        }
        try js.endArray();
        try js.objectField("best_cdhash");
        if (v.cd) |cd| try js.write(try sanitize.hexLower(a, &cd.cdhash)) else try js.write(null);

        try js.objectField("requirements");
        try js.beginArray();
        if (v.reqs) |rs| for (rs.requirements) |r| {
            try js.beginObject();
            try json.int(js, "type", @intFromEnum(r.type));
            try js.objectField("type_name");
            try js.write(r.type.label());
            try json.str(js, a, "text", r.text);
            try json.int(js, "ops", r.ops);
            try js.endObject();
        };
        try js.endArray();
        try js.objectField("designated_requirement");
        try js.beginObject();
        const designated: ?*const requirements.Requirement = if (v.reqs) |rs| rs.designated() else null;
        if (designated) |r| {
            try json.str(js, a, "text", r.text);
            try json.boolean(js, "synthesized", false);
        } else if (v.cd) |cd| {
            try json.str(js, a, "text", try requirements.synthesizedDesignated(a, cd.cdhash));
            try json.boolean(js, "synthesized", true);
        } else {
            try js.objectField("text");
            try js.write(null);
            try json.boolean(js, "synthesized", false);
        }
        try js.endObject();

        try cmd_entitlements.writeJson(js, a, v.ents);

        try js.objectField("cms");
        if (v.cms) |c| {
            try js.beginObject();
            try js.objectField("certificates");
            try js.beginArray();
            for (c.certificates) |cert| {
                try js.beginObject();
                try js.objectField("subject");
                try writeName(js, a, cert.subject);
                try js.objectField("issuer");
                try writeName(js, a, cert.issuer);
                try json.str(js, a, "serial", cert.serial_hex);
                try json.isoTime(js, "not_before", cert.not_before);
                try json.isoTime(js, "not_after", cert.not_after);
                try json.boolean(js, "self_signed", cert.is_self_signed);
                try json.bytesHex(js, "sha256", &cert.sha256);
                try json.names(js, a, "marker_oids", cert.marker_oids);
                try js.endObject();
            }
            try js.endArray();
            try json.names(js, a, "authority", try c.authorityNames(a));
            try json.isoTime(js, "signing_time", c.signing_time);
            try json.boolean(js, "has_timestamp", c.has_timestamp_token);
            try json.strOpt(js, a, "digest_algorithm", c.digest_algorithm);
            try json.int(js, "signer_count", c.signer_count);
            try json.boolean(js, "ber_indefinite", c.ber_indefinite);
            try js.endObject();
        } else try js.write(null);
        try js.objectField("offline_trust");
        try js.write(@tagName(cms_mod.offlineTrust(v.cms, if (v.cd) |cd| cd.flags else 0, if (v.cd) |cd| cd.platform else 0)));
        try js.endObject();
    } else {
        try js.objectField("code_signature");
        try js.beginObject();
        try json.boolean(js, "present", false);
        try js.endObject();
    }

    // Security.framework verdict
    const vd = v.verdict;
    if (vd.available) {
        try js.objectField("security");
        try js.beginObject();
        try json.boolean(js, "available", true);
        try json.str(js, a, "evaluated_path", vd.evaluated_path);
        try json.int(js, "create_status", vd.create_status);
        try json.int(js, "validity_status", vd.validity_status);
        try js.objectField("validity_status_name");
        try js.write(vd.validity_status_name);
        try json.boolean(js, "revocation_checked", vd.revocation_checked);
        try js.objectField("requirements");
        try js.beginObject();
        try json.int(js, "anchor_apple", vd.requirement_results.anchor_apple);
        try json.int(js, "apple_generic", vd.requirement_results.apple_generic);
        try json.int(js, "developer_id", vd.requirement_results.developer_id);
        try json.int(js, "app_store", vd.requirement_results.app_store);
        try json.int(js, "notarized", vd.requirement_results.notarized);
        try js.endObject();
        try js.objectField("trust");
        try js.write(@tagName(vd.trust));
        try json.strOpt(js, a, "identifier", vd.identifier);
        try json.strOpt(js, a, "team_id", vd.team_id);
        try json.strOpt(js, a, "format", vd.format);
        try json.hexOpt(js, "flags", if (vd.flags) |f| @as(u64, f) else null);
        try json.isoTime(js, "signing_time", vd.signing_time);
        try json.names(js, a, "certificate_chain", vd.certificate_chain);
        try json.strOpt(js, a, "designated_requirement", vd.designated_requirement);
        try js.objectField("stapled_ticket");
        try js.beginObject();
        try json.boolean(js, "present", vd.has_stapled_ticket);
        try json.int(js, "length", vd.ticket_len);
        try js.endObject();
        try json.int(js, "elapsed_ms", vd.elapsed_ms);
        try js.endObject();
    } else try json.unavailable(js, "security", vd.reason orelse "unavailable");

    // machre's own one-line verdict
    try js.objectField("verdict");
    try js.beginObject();
    try json.boolean(js, "signed", v.sig != null);
    const valid: ?bool = if (v.ver) |ver| ver.ok() else null;
    try js.objectField("valid");
    if (valid) |b| try js.write(b) else try js.write(null);
    try js.objectField("trust");
    try js.write(@tagName(cms_mod.offlineTrust(v.cms, if (v.cd) |cd| cd.flags else 0, if (v.cd) |cd| cd.platform else 0)));
    try json.str(js, a, "summary", try summaryLine(ctx, img, v));
    try js.endObject();
    try js.endObject();
}

fn writeName(js: *Stringify, a: Allocator, n: cms_mod.CertName) !void {
    try js.beginObject();
    try json.strOpt(js, a, "cn", n.cn);
    try json.strOpt(js, a, "ou", n.ou);
    try json.strOpt(js, a, "o", n.o);
    try json.strOpt(js, a, "c", n.c);
    try json.strOpt(js, a, "uid", n.uid);
    try js.endObject();
}

fn summaryLine(ctx: *Context, img: *const Image, v: View) ![]const u8 {
    _ = img;
    const cd = v.cd orelse return "unsigned (no LC_CODE_SIGNATURE)";
    const offline = cms_mod.offlineTrust(v.cms, cd.flags, cd.platform);
    const pages: []const u8 = if (v.ver) |ver|
        (if (!ver.hash_type_supported) "page hashes not verified" else if (ver.mismatches == 0) "page hashes ok" else "PAGE HASH MISMATCH")
    else
        "page hashes not checked";
    return std.fmt.allocPrint(ctx.arena, "{s}, identifier \"{s}\", {s}", .{
        offline.label(),
        try ctx.sink.safeMax(cd.identifier, ctx.limits.max_symbol_name),
        pages,
    });
}
