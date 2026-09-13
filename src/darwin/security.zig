//! darwin/security.zig — Security.framework / CoreFoundation externs (DESIGN.md §8) + trust ladder.
//! Whole bodies gated on build_options.have_security. Imports: core/diag, core/sanitize, plist/plist.
const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");
const plist = @import("../plist/plist.zig");

pub const available: bool = build_options.have_security;

pub const Trust = enum { platform, app_store, developer_id_notarized, developer_id, other_certificate, adhoc, unsigned, invalid, revoked, unavailable };
pub const RequirementResults = struct { anchor_apple: i32, apple_generic: i32, developer_id: i32, app_store: i32, notarized: i32 };
pub const Verdict = struct {
    available: bool, // false when compiled without Security or --no-security
    reason: ?[]const u8, // why unavailable
    evaluated_path: []const u8, // what Security actually evaluated (bundle promotion)
    create_status: i32,
    validity_status: i32,
    validity_status_name: []const u8,
    revocation_checked: bool,
    network_used: bool,
    requirement_results: RequirementResults,
    trust: Trust,
    identifier: ?[]const u8,
    team_id: ?[]const u8,
    format: ?[]const u8,
    flags: ?u32,
    platform_identifier: ?u32,
    runtime_version: ?u32,
    cdhash: ?[20]u8,
    cdhashes: []const []const u8,
    digest_algorithms: []const u32,
    signing_time: ?i64,
    secure_timestamp: ?i64,
    certificate_chain: []const []const u8, // subject summaries leaf -> root
    designated_requirement: ?[]const u8,
    main_executable: ?[]const u8,
    has_stapled_ticket: bool,
    ticket_len: u32,
    entitlements: ?plist.Value,
    elapsed_ms: u32,
};
pub const Options = struct { revocation: bool = true, network: bool = true, all_archs: bool = true, is_directory: bool = false, content_info: bool = true };

/// Requirement texts of the trust ladder (zig-api-notes 15.11); the leaf-marker OIDs are Apple's.
pub const req_anchor_apple: [:0]const u8 = "anchor apple";
pub const req_apple_generic: [:0]const u8 = "anchor apple generic";
pub const req_developer_id: [:0]const u8 = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13]";
pub const req_app_store: [:0]const u8 = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9]";
pub const req_notarized: [:0]const u8 = "notarized";

/// CS_ADHOC / CS_LINKER_SIGNED, the only CodeDirectory flags the ladder sentence needs.
pub const cs_adhoc: u32 = 0x0000_0002;
pub const cs_linker_signed: u32 = 0x0002_0000;

/// Caps applied before any allocation (this module may not import core/limits; §4 DAG).
const max_cf_string_bytes: usize = 1 << 16;
const max_cf_data_bytes: usize = 1 << 20;
const max_children: usize = 4096;
const max_chain_length: usize = 64;
pub const convert_max_depth: usize = 16;
pub const convert_max_nodes: usize = 8192;

/// Returns `.available=false, .trust=.unavailable` when !build_options.have_security.
pub fn evaluate(arena: Allocator, path_z: [:0]const u8, opts: Options, diags: *Diagnostics) Allocator.Error!Verdict {
    if (!build_options.have_security) return unavailable("built without Security.framework (-Dsecurity=false)", path_z);
    const started = nowMs();
    var v = unavailable("", path_z);
    v.available = true;
    v.reason = null;
    v.network_used = opts.network;
    v.revocation_checked = opts.revocation and opts.network;

    const url = CFURLCreateFromFileSystemRepresentation(null, path_z.ptr, @intCast(path_z.len), if (opts.is_directory) 1 else 0) orelse {
        diags.warn(.security, .os_error, null, "CFURLCreateFromFileSystemRepresentation failed for the analysed path", .{});
        return unavailable("cannot build a CFURL for the path", path_z);
    };
    defer CFRelease(url);

    var code: SecStaticCodeRef = null;
    v.create_status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (v.create_status != errSecSuccess or code == null) {
        v.validity_status = v.create_status;
        v.validity_status_name = try arena.dupe(u8, statusName(v.create_status));
        v.trust = if (v.create_status == errSecCSUnsigned) .unsigned else .unavailable;
        v.reason = try arena.dupe(u8, statusName(v.create_status));
        diags.warn(.security, .os_error, null, "SecStaticCodeCreateWithPath: {s} ({d})", .{ v.validity_status_name, v.create_status });
        v.elapsed_ms = elapsedMs(started);
        return v;
    }
    defer CFRelease(code);

    var check_flags: SecCSFlags = 0;
    if (opts.all_archs) check_flags |= kSecCSCheckAllArchitectures;
    if (opts.network) {
        if (opts.revocation) check_flags |= kSecCSEnforceRevocationChecks;
    } else {
        check_flags |= kSecCSNoNetworkAccess;
    }
    v.validity_status = SecStaticCodeCheckValidity(code, check_flags, null);
    v.validity_status_name = try arena.dupe(u8, statusName(v.validity_status));

    // Requirements are evaluated even when validity failed: the five results are the documented
    // oracle matrix (zig-api-notes 15.11) and reproduce codesign -R for every fixture.
    const req_flags: SecCSFlags = check_flags & ~kSecCSEnforceRevocationChecks;
    v.requirement_results = .{
        .anchor_apple = checkRequirement(code, req_anchor_apple, req_flags),
        .apple_generic = checkRequirement(code, req_apple_generic, req_flags),
        .developer_id = checkRequirement(code, req_developer_id, req_flags),
        .app_store = checkRequirement(code, req_app_store, req_flags),
        .notarized = checkRequirement(code, req_notarized, req_flags),
    };
    v.trust = ladder(v.validity_status, v.requirement_results);

    try copySigningInformation(arena, code, opts, &v, diags);
    if (bundleRootOf(v.main_executable orelse path_z, v.format)) |root| v.evaluated_path = root;
    v.elapsed_ms = elapsedMs(started);
    return v;
}

pub fn unavailable(reason: []const u8, path: []const u8) Verdict {
    return .{ .available = false, .reason = reason, .evaluated_path = path, .create_status = 0, .validity_status = 0, .validity_status_name = "not evaluated", .revocation_checked = false, .network_used = false, .requirement_results = .{ .anchor_apple = 0, .apple_generic = 0, .developer_id = 0, .app_store = 0, .notarized = 0 }, .trust = .unavailable, .identifier = null, .team_id = null, .format = null, .flags = null, .platform_identifier = null, .runtime_version = null, .cdhash = null, .cdhashes = &.{}, .digest_algorithms = &.{}, .signing_time = null, .secure_timestamp = null, .certificate_chain = &.{}, .designated_requirement = null, .main_executable = null, .has_stapled_ticket = false, .ticket_len = 0, .entitlements = null, .elapsed_ms = 0 };
}

/// Pure trust ladder (DESIGN §4.14): validity first, then the five requirement results.
pub fn ladder(validity: i32, r: RequirementResults) Trust {
    if (validity != errSecSuccess) {
        return switch (validity) {
            errSecCSUnsigned => .unsigned,
            errSecCSRevokedNotarization, errSecCertificateRevoked, CSSMERR_TP_CERT_REVOKED => .revoked,
            else => .invalid,
        };
    }
    if (r.anchor_apple == errSecSuccess) return .platform;
    if (r.app_store == errSecSuccess) return .app_store;
    if (r.developer_id == errSecSuccess) return if (r.notarized == errSecSuccess) .developer_id_notarized else .developer_id;
    if (r.apple_generic == errSecSuccess) return .other_certificate;
    return .adhoc;
}

pub const StatusInfo = struct { code: i32, name: []const u8, detail: []const u8 };
/// 83 errSecCS* codes (two of them are duplicate spellings of the same value, so 81 rows) plus
/// errSecSuccess, errSecCertificateRevoked and CSSMERR_TP_CERT_REVOKED.
pub const status_table: []const StatusInfo = &.{
    .{ .code = 0, .name = "errSecSuccess", .detail = "no error" },
    .{ .code = -67072, .name = "errSecCSUnimplemented", .detail = "unimplemented code signing feature" },
    .{ .code = -67071, .name = "errSecCSInvalidObjectRef", .detail = "invalid API object reference" },
    .{ .code = -67070, .name = "errSecCSInvalidFlags", .detail = "invalid or inappropriate API flag(s) specified" },
    .{ .code = -67069, .name = "errSecCSObjectRequired", .detail = "a required pointer argument was NULL" },
    .{ .code = -67068, .name = "errSecCSStaticCodeNotFound", .detail = "cannot find code object on disk" },
    .{ .code = -67067, .name = "errSecCSUnsupportedGuestAttributes", .detail = "cannot locate guests using this attribute set" },
    .{ .code = -67066, .name = "errSecCSInvalidAttributeValues", .detail = "given attribute values are invalid" },
    .{ .code = -67065, .name = "errSecCSNoSuchCode", .detail = "host has no guest with the requested attributes" },
    .{ .code = -67064, .name = "errSecCSMultipleGuests", .detail = "ambiguous guest specification (host has multiple guests with these attribute values)" },
    .{ .code = -67063, .name = "errSecCSGuestInvalid", .detail = "code identity has been invalidated" },
    .{ .code = -67062, .name = "errSecCSUnsigned", .detail = "code object is not signed at all" },
    .{ .code = -67061, .name = "errSecCSSignatureFailed", .detail = "invalid signature (code or signature have been modified)" },
    .{ .code = -67060, .name = "errSecCSSignatureNotVerifiable", .detail = "the code cannot be read by the verifier (file system permissions etc.)" },
    .{ .code = -67059, .name = "errSecCSSignatureUnsupported", .detail = "unsupported type or version of signature" },
    .{ .code = -67058, .name = "errSecCSBadDictionaryFormat", .detail = "a required plist file or resource is malformed" },
    .{ .code = -67057, .name = "errSecCSResourcesNotSealed", .detail = "resources are present but not sealed by signature" },
    .{ .code = -67056, .name = "errSecCSResourcesNotFound", .detail = "code has no resources but signature indicates they must be present" },
    .{ .code = -67055, .name = "errSecCSResourcesInvalid", .detail = "the sealed resource directory is invalid" },
    .{ .code = -67054, .name = "errSecCSBadResource", .detail = "a sealed resource is missing or invalid" },
    .{ .code = -67053, .name = "errSecCSResourceRulesInvalid", .detail = "invalid resource specification rule(s)" },
    .{ .code = -67052, .name = "errSecCSReqInvalid", .detail = "invalid or corrupted code requirement(s)" },
    .{ .code = -67051, .name = "errSecCSReqUnsupported", .detail = "unsupported type or version of code requirement(s)" },
    .{ .code = -67050, .name = "errSecCSReqFailed", .detail = "code failed to satisfy specified code requirement(s)" },
    .{ .code = -67049, .name = "errSecCSBadObjectFormat", .detail = "object file format unrecognized, invalid, or unsuitable" },
    .{ .code = -67048, .name = "errSecCSInternalError", .detail = "internal error in Code Signing subsystem" },
    .{ .code = -67047, .name = "errSecCSHostReject", .detail = "code rejected its host" },
    .{ .code = -67046, .name = "errSecCSNotAHost", .detail = "attempt to specify guest of code that is not a host" },
    .{ .code = -67045, .name = "errSecCSSignatureInvalid", .detail = "invalid or unsupported format for signature" },
    .{ .code = -67044, .name = "errSecCSHostProtocolRelativePath", .detail = "host protocol violation - absolute guest path required" },
    .{ .code = -67043, .name = "errSecCSHostProtocolContradiction", .detail = "host protocol violation - contradictory hosting modes" },
    .{ .code = -67042, .name = "errSecCSHostProtocolDedicationError", .detail = "host protocol violation - operation not allowed with/for a dedicated guest" },
    .{ .code = -67041, .name = "errSecCSHostProtocolNotProxy", .detail = "host protocol violation - proxy hosting not engaged" },
    .{ .code = -67040, .name = "errSecCSHostProtocolStateError", .detail = "host protocol violation - invalid guest state change request" },
    .{ .code = -67039, .name = "errSecCSHostProtocolUnrelated", .detail = "host protocol violation - the given guest is not a guest of the given host" },
    .{ .code = -67037, .name = "errSecCSNotSupported", .detail = "operation inapplicable or not supported for this type of code" },
    .{ .code = -67036, .name = "errSecCSCMSTooLarge", .detail = "signature too large to embed (size limitation of on-disk representation)" },
    .{ .code = -67035, .name = "errSecCSHostProtocolInvalidHash", .detail = "host protocol violation - invalid guest hash" },
    .{ .code = -67034, .name = "errSecCSStaticCodeChanged", .detail = "the code on disk does not match what is running" },
    .{ .code = -67033, .name = "errSecCSDBDenied", .detail = "permission to use a database denied" },
    .{ .code = -67032, .name = "errSecCSDBAccess", .detail = "cannot access a database" },
    .{ .code = -67031, .name = "errSecCSHostProtocolInvalidAttribute", .detail = "host returned invalid or inconsistent guest attributes" },
    .{ .code = -67030, .name = "errSecCSInfoPlistFailed", .detail = "invalid Info.plist (plist or signature have been modified)" },
    .{ .code = -67029, .name = "errSecCSNoMainExecutable", .detail = "the code has no main executable file" },
    .{ .code = -67028, .name = "errSecCSBadBundleFormat", .detail = "bundle format unrecognized, invalid, or unsuitable" },
    .{ .code = -67027, .name = "errSecCSNoMatches", .detail = "no matches for search or update operation" },
    .{ .code = -67026, .name = "errSecCSFileHardQuarantined", .detail = "File created by an AppSandbox, exec/open not allowed" },
    .{ .code = -67025, .name = "errSecCSOutdated", .detail = "presented data is out of date" },
    .{ .code = -67024, .name = "errSecCSDbCorrupt", .detail = "a system database or file is corrupt" },
    .{ .code = -67023, .name = "errSecCSResourceDirectoryFailed", .detail = "invalid resource directory (directory or signature have been modified)" },
    .{ .code = -67022, .name = "errSecCSUnsignedNestedCode", .detail = "nested code is unsigned" },
    .{ .code = -67021, .name = "errSecCSBadNestedCode", .detail = "nested code is modified or invalid" },
    .{ .code = -67020, .name = "errSecCSBadCallbackValue", .detail = "monitor callback returned invalid value" },
    .{ .code = -67019, .name = "errSecCSHelperFailed", .detail = "the codesign_allocate helper tool cannot be found or used" },
    .{ .code = -67018, .name = "errSecCSVetoed", .detail = "" },
    .{ .code = -67017, .name = "errSecCSBadLVArch", .detail = "library validation flag cannot be used with an i386 binary" },
    .{ .code = -67016, .name = "errSecCSResourceNotSupported", .detail = "unsupported resource found (something not a directory, file or symlink)" },
    .{ .code = -67015, .name = "errSecCSRegularFile", .detail = "the main executable or Info.plist must be a regular file (no symlinks, etc.)" },
    .{ .code = -67014, .name = "errSecCSUnsealedAppRoot", .detail = "unsealed contents present in the bundle root" },
    .{ .code = -67013, .name = "errSecCSWeakResourceRules", .detail = "resource envelope is obsolete (custom omit rules)" },
    .{ .code = -67012, .name = "errSecCSDSStoreSymlink", .detail = ".DS_Store files cannot be a symlink" },
    .{ .code = -67011, .name = "errSecCSAmbiguousBundleFormat", .detail = "bundle format is ambiguous (could be app or framework)" },
    .{ .code = -67010, .name = "errSecCSBadMainExecutable", .detail = "main executable failed strict validation" },
    .{ .code = -67009, .name = "errSecCSBadFrameworkVersion", .detail = "embedded framework contains modified or invalid version" },
    .{ .code = -67008, .name = "errSecCSUnsealedFrameworkRoot", .detail = "unsealed contents present in the root directory of an embedded framework" },
    .{ .code = -67007, .name = "errSecCSWeakResourceEnvelope", .detail = "resource envelope is obsolete (version 1 signature)" },
    .{ .code = -67006, .name = "errSecCSCancelled", .detail = "operation was terminated by explicit cancelation" },
    .{ .code = -67005, .name = "errSecCSInvalidPlatform", .detail = "invalid platform identifier or platform mismatch" },
    .{ .code = -67004, .name = "errSecCSTooBig", .detail = "code is too big for current signing format" },
    .{ .code = -67003, .name = "errSecCSInvalidSymlink", .detail = "invalid destination for symbolic link in bundle" },
    .{ .code = -67002, .name = "errSecCSNotAppLike", .detail = "the code is valid but does not seem to be an app" },
    .{ .code = -67001, .name = "errSecCSBadDiskImageFormat", .detail = "disk image format unrecognized, invalid, or unsuitable" },
    .{ .code = -67000, .name = "errSecCSUnsupportedDigestAlgorithm", .detail = "a requested signature digest algorithm is not supported" },
    .{ .code = -66999, .name = "errSecCSInvalidAssociatedFileData", .detail = "resource fork, Finder information, or similar detritus not allowed" },
    .{ .code = -66998, .name = "errSecCSInvalidTeamIdentifier", .detail = "a Team Identifier string is invalid" },
    .{ .code = -66997, .name = "errSecCSBadTeamIdentifier", .detail = "a Team Identifier is wrong or inappropriate" },
    .{ .code = -66996, .name = "errSecCSSignatureUntrusted", .detail = "signature is valid but signer is not trusted" },
    .{ .code = -66994, .name = "errSecCSInvalidEntitlements", .detail = "invalid entitlement plist" },
    .{ .code = -66993, .name = "errSecCSInvalidRuntimeVersion", .detail = "an invalid runtime version was explicitly set" },
    .{ .code = -66992, .name = "errSecCSRevokedNotarization", .detail = "notarization indicates this code has been revoked" },
    .{ .code = -66991, .name = "errSecCSCMSConstructionFailed", .detail = "CMS construction failed, see logs for deeper error" },
    .{ .code = -66990, .name = "errSecCSRemoteSignerFailed", .detail = "remote signing block did not return a signature" },
    .{ .code = -67820, .name = "errSecCertificateRevoked", .detail = "the signing certificate was revoked" },
    .{ .code = -2147409652, .name = "CSSMERR_TP_CERT_REVOKED", .detail = "certificate revoked (CSSM trust policy)" },
};

/// Fallback buffer for `statusName` on a code outside `status_table`: the returned slice is valid
/// until the next unknown-status call on the same thread, so callers that keep it must copy.
threadlocal var unknown_status_buf: [32]u8 = undefined;

/// 83 errSecCS* names + errSecCertificateRevoked + CSSMERR_TP_CERT_REVOKED; "OSStatus(N)" otherwise.
pub fn statusName(status: i32) []const u8 {
    for (status_table) |e| if (e.code == status) return e.name;
    return std.fmt.bufPrint(&unknown_status_buf, "OSStatus({d})", .{status}) catch "OSStatus";
}
/// Apple's one-line explanation of a known status, null otherwise.
pub fn statusDetail(status: i32) ?[]const u8 {
    for (status_table) |e| if (e.code == status) return e.detail;
    return null;
}
pub fn trustName(t: Trust) []const u8 {
    return @tagName(t);
}
/// Human sentence for the trust ladder line ("ad hoc (linker-signed) -- integrity only, not identity").
pub fn trustSentence(v: *const Verdict, cd_flags: ?u32) []const u8 {
    if (!v.available) return "not evaluated";
    return switch (v.trust) {
        .platform => "PLATFORM BINARY (Apple) -- signed by Apple's own Software Signing authority",
        .app_store => "MAC APP STORE -- signed by Apple for App Store distribution",
        .developer_id_notarized => if (v.has_stapled_ticket)
            "DEVELOPER ID, notarized (stapled ticket present)"
        else
            "DEVELOPER ID, notarized (ticket checked online, not stapled)",
        .developer_id => "DEVELOPER ID, NOT notarized -- signed but never accepted by Apple's notary service",
        .other_certificate => "SIGNED by a non-Apple certificate chain -- identity is not vouched for by Apple",
        .adhoc => if (cd_flags != null and cd_flags.? & cs_linker_signed != 0)
            "AD HOC (linker-signed) -- signature proves integrity only, not identity"
        else
            "AD HOC -- signature proves integrity only, not identity",
        .unsigned => statusPhrase("UNSIGNED", errSecCSUnsigned),
        .invalid => statusPhrase("INVALID", v.validity_status),
        .revoked => statusPhrase("REVOKED", v.validity_status),
        .unavailable => "not evaluated",
    };
}

/// The five ladder requirements in the order `cmd/codesign.zig` prints them (DESIGN §5.4), with the
/// label codesign uses and the requirement text handed to SecRequirementCreateWithString.
pub const RequirementLabel = struct { label: []const u8, text: []const u8 };
pub const requirement_labels: []const RequirementLabel = &.{
    .{ .label = "anchor apple", .text = req_anchor_apple },
    .{ .label = "anchor apple generic", .text = req_apple_generic },
    .{ .label = "Developer ID (certificate leaf[field.1.2.840.113635.100.6.1.13])", .text = req_developer_id },
    .{ .label = "Mac App Store (certificate leaf[field.1.2.840.113635.100.6.1.9])", .text = req_app_store },
    .{ .label = "notarized", .text = req_notarized },
};
/// Parallel to `requirement_labels`.
pub fn requirementValues(r: RequirementResults) [5]i32 {
    return .{ r.anchor_apple, r.apple_generic, r.developer_id, r.app_store, r.notarized };
}
/// The flag expression that produced `Verdict.validity_status`, for the §5.4 codesign header line.
pub fn checkFlagsText(v: *const Verdict) []const u8 {
    if (v.revocation_checked) return "kSecCSCheckAllArchitectures | kSecCSEnforceRevocationChecks";
    if (!v.network_used) return "kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess";
    return "kSecCSCheckAllArchitectures";
}

/// `prefix (errSecCSName -67061)` built at comptime from `status_table`, so no allocator is needed.
fn statusPhrase(comptime prefix: []const u8, status: i32) []const u8 {
    const table = comptime blk: {
        @setEvalBranchQuota(200_000);
        var out: [status_table.len][]const u8 = undefined;
        for (status_table, 0..) |e, i| out[i] = prefix ++ " (" ++ e.name ++ " " ++ std.fmt.comptimePrint("{d}", .{e.code}) ++ ")";
        const final = out;
        break :blk final;
    };
    for (status_table, 0..) |e, i| if (e.code == status) return table[i];
    return prefix;
}

/// The bundle Security promoted the path to ("…/X.app" for "…/X.app/Contents/MacOS/X"), null when the
/// reported format is not a bundle format.
pub fn bundleRootOf(path: []const u8, format: ?[]const u8) ?[]const u8 {
    const f = format orelse return null;
    if (std.mem.find(u8, f, "bundle with ") == null) return null;
    if (std.mem.findLast(u8, path, "/Contents/MacOS/")) |i| return path[0..i];
    if (std.mem.findLast(u8, path, "/Versions/")) |i| return path[0..i];
    if (std.mem.findLast(u8, path, "/MacOS/")) |i| return path[0..i];
    return null;
}

// ---- generic (testable, portable) container walk used for kSecCodeInfoEntitlementsDict ----

pub const NodeKind = enum { scalar, dict, array };
/// One level of a container: `keys` is empty for arrays, otherwise parallel to `nodes`.
pub fn Children(comptime Node: type) type {
    return struct { keys: []const []const u8, nodes: []const Node };
}

/// Converts a CoreFoundation-shaped tree into `plist.Value` with an explicit stack (DESIGN §7 item 5):
/// depth is capped at `convert_max_depth` and the total slot count at `convert_max_nodes`, so a cyclic
/// or bomb-shaped tree terminates with `.null` placeholders instead of recursing.
/// `Backend` must provide `pub const Node`, `kind(node)`, `open(node) !Children(Node)` and `scalar(node) !Value`.
pub fn convertTree(comptime Backend: type, backend: Backend, arena: Allocator, root: Backend.Node) Allocator.Error!plist.Value {
    const Node = Backend.Node;
    const Frame = struct { is_dict: bool, keys: []const []const u8, nodes: []const Node, out: []plist.Value, i: usize };
    const root_kind = backend.kind(root);
    if (root_kind == .scalar) return backend.scalar(root);
    var seen: usize = 0;
    var stack: std.ArrayList(Frame) = .empty;
    const rc = try backend.open(root);
    seen += rc.nodes.len + 1;
    try stack.append(arena, .{ .is_dict = root_kind == .dict, .keys = rc.keys, .nodes = rc.nodes, .out = try arena.alloc(plist.Value, rc.nodes.len), .i = 0 });
    while (true) {
        const depth = stack.items.len;
        const top = &stack.items[depth - 1];
        if (top.i < top.out.len) {
            const child = top.nodes[top.i];
            const k = backend.kind(child);
            if (k != .scalar and depth < convert_max_depth and seen < convert_max_nodes) {
                const cc = try backend.open(child);
                seen += cc.nodes.len + 1;
                try stack.append(arena, .{ .is_dict = k == .dict, .keys = cc.keys, .nodes = cc.nodes, .out = try arena.alloc(plist.Value, cc.nodes.len), .i = 0 });
                continue;
            }
            top.out[top.i] = if (k == .scalar) try backend.scalar(child) else .null;
            top.i += 1;
            continue;
        }
        const done = try closeFrame(arena, top.is_dict, top.keys, top.out);
        _ = stack.pop();
        if (stack.items.len == 0) return done;
        const parent = &stack.items[stack.items.len - 1];
        parent.out[parent.i] = done;
        parent.i += 1;
    }
}

fn closeFrame(arena: Allocator, is_dict: bool, keys: []const []const u8, out: []plist.Value) Allocator.Error!plist.Value {
    if (!is_dict) return .{ .array = out };
    const n = @min(keys.len, out.len);
    const entries = try arena.alloc(plist.Value.Entry, n);
    for (entries, 0..) |*e, i| e.* = .{ .key = keys[i], .value = out[i] };
    return .{ .dict = entries };
}

// ---- Security.framework plumbing (referenced only inside `if (build_options.have_security)` bodies) ----

fn nowMs() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    const s: i128 = ts.sec;
    const n: i128 = ts.nsec;
    const ms = @divTrunc(s * 1000 * 1000 * 1000 + n, 1000 * 1000);
    if (ms < 0) return 0;
    return @intCast(@min(ms, @as(i128, std.math.maxInt(u32))));
}
fn elapsedMs(started: u64) u32 {
    const now = nowMs();
    return if (now > started) @intCast(@min(now - started, std.math.maxInt(u32))) else 0;
}

fn checkRequirement(code: SecStaticCodeRef, text: [:0]const u8, flags: SecCSFlags) i32 {
    const s = CFStringCreateWithCString(null, text.ptr, kCFStringEncodingUTF8) orelse return errSecCSReqInvalid;
    defer CFRelease(s);
    var req: SecRequirementRef = null;
    const rc = SecRequirementCreateWithString(s, kSecCSDefaultFlags, &req);
    if (rc != errSecSuccess or req == null) return if (rc == errSecSuccess) errSecCSReqInvalid else rc;
    defer CFRelease(req);
    return SecStaticCodeCheckValidity(code, flags, req);
}

fn copySigningInformation(arena: Allocator, code: SecStaticCodeRef, opts: Options, v: *Verdict, diags: *Diagnostics) Allocator.Error!void {
    var info_flags: SecCSFlags = kSecCSSigningInformation | kSecCSRequirementInformation;
    if (opts.content_info) info_flags |= kSecCSContentInformation;
    var dict: CFDictionaryRef = null;
    const rc = SecCodeCopySigningInformation(code, info_flags, &dict);
    if (rc != errSecSuccess or dict == null) {
        if (rc != errSecSuccess)
            diags.warn(.security, .os_error, null, "SecCodeCopySigningInformation: {s} ({d})", .{ statusName(rc), rc });
        return;
    }
    defer CFRelease(dict);

    v.identifier = try cfStringUtf8(arena, CFDictionaryGetValue(dict, kSecCodeInfoIdentifier));
    v.team_id = try cfStringUtf8(arena, CFDictionaryGetValue(dict, kSecCodeInfoTeamIdentifier));
    v.format = try cfStringUtf8(arena, CFDictionaryGetValue(dict, kSecCodeInfoFormat));
    v.flags = cfNumberU32(CFDictionaryGetValue(dict, kSecCodeInfoFlags));
    v.platform_identifier = cfNumberU32(CFDictionaryGetValue(dict, kSecCodeInfoPlatformIdentifier));
    v.runtime_version = cfNumberU32(CFDictionaryGetValue(dict, kSecCodeInfoRuntimeVersion));
    v.signing_time = cfDateUnix(CFDictionaryGetValue(dict, kSecCodeInfoTime));
    v.secure_timestamp = cfDateUnix(CFDictionaryGetValue(dict, kSecCodeInfoTimestamp));

    if (try cfDataBytes(arena, CFDictionaryGetValue(dict, kSecCodeInfoUnique))) |u| {
        if (u.len >= 20) {
            var h: [20]u8 = undefined;
            @memcpy(&h, u[0..20]);
            v.cdhash = h;
        }
    }
    v.cdhashes = try cfDataArray(arena, CFDictionaryGetValue(dict, kSecCodeInfoCdHashes));
    v.digest_algorithms = try cfNumberArray(arena, CFDictionaryGetValue(dict, kSecCodeInfoDigestAlgorithms));
    v.certificate_chain = try certificateSummaries(arena, CFDictionaryGetValue(dict, kSecCodeInfoCertificates));

    if (try cfDataBytes(arena, CFDictionaryGetValue(dict, kSecCodeInfoStapledNotarizationTicket))) |t| {
        v.has_stapled_ticket = true;
        v.ticket_len = @intCast(@min(t.len, std.math.maxInt(u32)));
    }
    v.designated_requirement = try requirementText(arena, CFDictionaryGetValue(dict, kSecCodeInfoDesignatedRequirement));
    v.main_executable = try urlPath(arena, CFDictionaryGetValue(dict, kSecCodeInfoMainExecutable));

    const ent = CFDictionaryGetValue(dict, kSecCodeInfoEntitlementsDict);
    if (cfKind(ent) == .dict) {
        const backend: CfBackend = .{ .arena = arena, .diags = diags };
        v.entitlements = try convertTree(CfBackend, backend, arena, ent);
    }
}

const CfKind = enum { string, number, boolean, data, date, array, dict, other };
fn cfKind(v: ?*const anyopaque) CfKind {
    if (v == null) return .other;
    const t = CFGetTypeID(v);
    if (t == CFStringGetTypeID()) return .string;
    if (t == CFNumberGetTypeID()) return .number;
    if (t == CFBooleanGetTypeID()) return .boolean;
    if (t == CFDataGetTypeID()) return .data;
    if (t == CFDateGetTypeID()) return .date;
    if (t == CFArrayGetTypeID()) return .array;
    if (t == CFDictionaryGetTypeID()) return .dict;
    return .other;
}

fn cfStringUtf8(arena: Allocator, v: ?*const anyopaque) Allocator.Error!?[]const u8 {
    if (cfKind(v) != .string) return null;
    const len = CFStringGetLength(v);
    if (len < 0) return null;
    const max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    if (max <= 0) return "";
    const cap: usize = @intCast(max);
    if (cap > max_cf_string_bytes) return null;
    const buf = try arena.alloc(u8, cap + 1);
    if (CFStringGetCString(v, buf.ptr, @intCast(buf.len), kCFStringEncodingUTF8) == 0) return null;
    return (try sanitize.string(arena, std.mem.sliceTo(buf, 0), .json, max_cf_string_bytes)).text;
}

fn cfNumberI64(v: ?*const anyopaque) ?i64 {
    if (cfKind(v) != .number) return null;
    var out: i64 = 0;
    if (CFNumberGetValue(v, kCFNumberSInt64Type, &out) == 0) return null;
    return out;
}
fn cfNumberU32(v: ?*const anyopaque) ?u32 {
    const n = cfNumberI64(v) orelse return null;
    if (n < 0 or n > std.math.maxInt(u32)) return null;
    return @intCast(n);
}
fn cfDateUnix(v: ?*const anyopaque) ?i64 {
    if (cfKind(v) != .date) return null;
    const unix = CFDateGetAbsoluteTime(v) + kCFAbsoluteTimeIntervalSince1970;
    if (!std.math.isFinite(unix) or unix < -62135596800.0 or unix > 253402300799.0) return null;
    return @intFromFloat(unix);
}
fn cfDataBytes(arena: Allocator, v: ?*const anyopaque) Allocator.Error!?[]const u8 {
    if (cfKind(v) != .data) return null;
    const n = CFDataGetLength(v);
    if (n <= 0) return "";
    const len: usize = @intCast(n);
    if (len > max_cf_data_bytes) return null;
    const p = CFDataGetBytePtr(v);
    return try arena.dupe(u8, p[0..len]);
}
fn cfCount(v: ?*const anyopaque) usize {
    const n = switch (cfKind(v)) {
        .array => CFArrayGetCount(v),
        .dict => CFDictionaryGetCount(v),
        else => return 0,
    };
    if (n <= 0) return 0;
    const c: usize = @intCast(n);
    return @min(c, max_children);
}

fn cfDataArray(arena: Allocator, v: ?*const anyopaque) Allocator.Error![]const []const u8 {
    if (cfKind(v) != .array) return &.{};
    const n = @min(cfCount(v), max_chain_length);
    var list: std.ArrayList([]const u8) = .empty;
    for (0..n) |i| {
        if (try cfDataBytes(arena, CFArrayGetValueAtIndex(v, @intCast(i)))) |b| try list.append(arena, b);
    }
    return list.toOwnedSlice(arena);
}
fn cfNumberArray(arena: Allocator, v: ?*const anyopaque) Allocator.Error![]const u32 {
    if (cfKind(v) != .array) return &.{};
    const n = @min(cfCount(v), max_chain_length);
    var list: std.ArrayList(u32) = .empty;
    for (0..n) |i| {
        if (cfNumberU32(CFArrayGetValueAtIndex(v, @intCast(i)))) |x| try list.append(arena, x);
    }
    return list.toOwnedSlice(arena);
}
/// Subject summaries leaf -> root. Every element is type-checked against SecCertificateGetTypeID()
/// first: calling SecCertificateCopySubjectSummary on a CFData crashes inside Security.framework.
fn certificateSummaries(arena: Allocator, v: ?*const anyopaque) Allocator.Error![]const []const u8 {
    if (cfKind(v) != .array) return &.{};
    const n = @min(cfCount(v), max_chain_length);
    var list: std.ArrayList([]const u8) = .empty;
    for (0..n) |i| {
        const e = CFArrayGetValueAtIndex(v, @intCast(i));
        if (e == null or CFGetTypeID(e) != SecCertificateGetTypeID()) continue;
        const cn = SecCertificateCopySubjectSummary(e) orelse continue;
        defer CFRelease(cn);
        if (try cfStringUtf8(arena, cn)) |s| try list.append(arena, s);
    }
    return list.toOwnedSlice(arena);
}
/// kSecCodeInfoDesignatedRequirement is a SecRequirementRef; it has no public CFTypeID accessor, so
/// the guard is "not any of the plain CF types" before handing it to SecRequirementCopyString.
fn requirementText(arena: Allocator, v: ?*const anyopaque) Allocator.Error!?[]const u8 {
    if (v == null or cfKind(v) != .other) return null;
    var s: CFStringRef = null;
    if (SecRequirementCopyString(v, kSecCSDefaultFlags, &s) != errSecSuccess or s == null) return null;
    defer CFRelease(s);
    return cfStringUtf8(arena, s);
}
/// kSecCodeInfoMainExecutable is a CFURL (also not a plain CF type).
///
/// The scratch buffer MUST be arena-allocated, never a stack array: `sanitize.string`
/// returns its input slice unchanged when nothing needs escaping (the common case for a
/// path), so a stack buffer would leave the returned slice dangling into a dead frame —
/// it printed stale pointer bytes in place of the first 16 characters of the path.
fn urlPath(arena: Allocator, v: ?*const anyopaque) Allocator.Error!?[]const u8 {
    if (v == null or cfKind(v) != .other) return null;
    const buf = try arena.alloc(u8, url_path_max);
    if (CFURLGetFileSystemRepresentation(v, 1, buf.ptr, @intCast(buf.len)) == 0) return null;
    return (try sanitize.string(arena, std.mem.sliceTo(buf, 0), .json, max_cf_string_bytes)).text;
}
/// Upper bound for a file-system path produced by CoreFoundation (PATH_MAX is 1024).
const url_path_max = 4096;

/// `convertTree` backend over CoreFoundation containers.
const CfBackend = struct {
    arena: Allocator,
    diags: *Diagnostics,
    pub const Node = ?*const anyopaque;

    pub fn kind(_: CfBackend, n: Node) NodeKind {
        return switch (cfKind(n)) {
            .dict => .dict,
            .array => .array,
            else => .scalar,
        };
    }
    pub fn open(self: CfBackend, n: Node) Allocator.Error!Children(Node) {
        switch (cfKind(n)) {
            .dict => {
                const raw = CFDictionaryGetCount(n);
                if (raw <= 0) return .{ .keys = &.{}, .nodes = &.{} };
                const cnt: usize = @intCast(raw);
                // CFDictionaryGetKeysAndValues writes every entry, so a clamp here would overflow.
                if (cnt > max_children) {
                    if (!self.diags.has(.security, .count_clamped))
                        self.diags.warn(.security, .count_clamped, null, "entitlements dictionary has {d} keys (cap {d}); skipped", .{ cnt, max_children });
                    return .{ .keys = &.{}, .nodes = &.{} };
                }
                const kbuf = try self.arena.alloc(?*const anyopaque, cnt);
                const vbuf = try self.arena.alloc(?*const anyopaque, cnt);
                CFDictionaryGetKeysAndValues(n, kbuf.ptr, vbuf.ptr);
                const keys = try self.arena.alloc([]const u8, cnt);
                for (kbuf, 0..) |k, i| keys[i] = (try cfStringUtf8(self.arena, k)) orelse "";
                return .{ .keys = keys, .nodes = vbuf };
            },
            .array => {
                const cnt = cfCount(n);
                if (cnt == 0) return .{ .keys = &.{}, .nodes = &.{} };
                const vbuf = try self.arena.alloc(?*const anyopaque, cnt);
                for (vbuf, 0..) |*slot, i| slot.* = CFArrayGetValueAtIndex(n, @intCast(i));
                return .{ .keys = &.{}, .nodes = vbuf };
            },
            else => return .{ .keys = &.{}, .nodes = &.{} },
        }
    }
    pub fn scalar(self: CfBackend, n: Node) Allocator.Error!plist.Value {
        return switch (cfKind(n)) {
            .string => .{ .string = (try cfStringUtf8(self.arena, n)) orelse "" },
            .number => if (cfNumberI64(n)) |i| .{ .integer = i } else .null,
            .boolean => .{ .bool = CFBooleanGetValue(n) != 0 },
            .data => .{ .data = (try cfDataBytes(self.arena, n)) orelse "" },
            .date => .{ .date = CFDateGetAbsoluteTime(n) },
            else => .null,
        };
    }
};

// ---- externs (only referenced inside `if (build_options.have_security)` bodies) ----
const CFTypeRef = ?*const anyopaque;
const CFAllocatorRef = ?*const anyopaque;
const CFStringRef = ?*const anyopaque;
const CFURLRef = ?*const anyopaque;
const CFDictionaryRef = ?*const anyopaque;
const CFArrayRef = ?*const anyopaque;
const CFDataRef = ?*const anyopaque;
const CFDateRef = ?*const anyopaque;
const CFErrorRef = ?*const anyopaque;
const CFNumberRef = ?*const anyopaque;
const CFBooleanRef = ?*const anyopaque;
const SecStaticCodeRef = ?*const anyopaque;
const SecRequirementRef = ?*const anyopaque;
const SecCertificateRef = ?*const anyopaque;
const CFIndex = c_long;
const CFTypeID = c_ulong;
const Boolean = u8;
const OSStatus = i32;
const SecCSFlags = u32;
const CFStringEncoding = u32;
const CFNumberType = CFIndex;
const CFAbsoluteTime = f64;
const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
const kCFNumberSInt64Type: CFNumberType = 4;
const kCFAbsoluteTimeIntervalSince1970: f64 = 978307200.0;
const kSecCSDefaultFlags: SecCSFlags = 0;
const kSecCSConsiderExpiration: SecCSFlags = 1 << 31;
const kSecCSEnforceRevocationChecks: SecCSFlags = 1 << 30;
const kSecCSNoNetworkAccess: SecCSFlags = 1 << 29;
const kSecCSCheckAllArchitectures: SecCSFlags = 1 << 0;
const kSecCSDoNotValidateExecutable: SecCSFlags = 1 << 1;
const kSecCSDoNotValidateResources: SecCSFlags = 1 << 2;
const kSecCSCheckNestedCode: SecCSFlags = 1 << 3;
const kSecCSStrictValidate: SecCSFlags = 1 << 4;
const kSecCSInternalInformation: SecCSFlags = 1 << 0;
const kSecCSSigningInformation: SecCSFlags = 1 << 1;
const kSecCSRequirementInformation: SecCSFlags = 1 << 2;
const kSecCSDynamicInformation: SecCSFlags = 1 << 3;
const kSecCSContentInformation: SecCSFlags = 1 << 4;
const errSecSuccess: OSStatus = 0;
const errSecCSUnsigned: OSStatus = -67062;
const errSecCSSignatureFailed: OSStatus = -67061;
const errSecCSSignatureInvalid: OSStatus = -67045;
const errSecCSReqInvalid: OSStatus = -67052;
const errSecCSReqFailed: OSStatus = -67050;
const errSecCSBadResource: OSStatus = -67054;
const errSecCSUnsignedNestedCode: OSStatus = -67022;
const errSecCSRevokedNotarization: OSStatus = -66992;
const errSecCertificateRevoked: OSStatus = -67820;
const CSSMERR_TP_CERT_REVOKED: OSStatus = -2147409652;
extern fn CFURLCreateFromFileSystemRepresentation(allocator: CFAllocatorRef, buffer: [*]const u8, bufLen: CFIndex, isDirectory: Boolean) CFURLRef;
extern fn CFURLGetFileSystemRepresentation(url: CFURLRef, resolveAgainstBase: Boolean, buffer: [*]u8, maxBufLen: CFIndex) Boolean;
extern fn CFStringCreateWithCString(alloc: CFAllocatorRef, cStr: [*:0]const u8, encoding: CFStringEncoding) CFStringRef;
extern fn CFRelease(cf: CFTypeRef) void;
extern fn CFGetTypeID(cf: CFTypeRef) CFTypeID;
extern fn CFStringGetTypeID() CFTypeID;
extern fn CFNumberGetTypeID() CFTypeID;
extern fn CFDateGetTypeID() CFTypeID;
extern fn CFDataGetTypeID() CFTypeID;
extern fn CFArrayGetTypeID() CFTypeID;
extern fn CFDictionaryGetTypeID() CFTypeID;
extern fn CFBooleanGetTypeID() CFTypeID;
extern fn CFBooleanGetValue(b: CFBooleanRef) Boolean;
extern fn CFStringGetLength(theString: CFStringRef) CFIndex;
extern fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: CFStringEncoding) CFIndex;
extern fn CFStringGetCString(theString: CFStringRef, buffer: [*]u8, bufferSize: CFIndex, encoding: CFStringEncoding) Boolean;
extern fn CFDictionaryGetValue(theDict: CFDictionaryRef, key: ?*const anyopaque) ?*const anyopaque;
extern fn CFDictionaryGetCount(theDict: CFDictionaryRef) CFIndex;
extern fn CFDictionaryGetKeysAndValues(theDict: CFDictionaryRef, keys: ?[*]?*const anyopaque, values: ?[*]?*const anyopaque) void;
extern fn CFNumberGetValue(number: CFNumberRef, theType: CFNumberType, valuePtr: *anyopaque) Boolean;
extern fn CFArrayGetCount(theArray: CFArrayRef) CFIndex;
extern fn CFArrayGetValueAtIndex(theArray: CFArrayRef, idx: CFIndex) ?*const anyopaque;
extern fn CFDateGetAbsoluteTime(theDate: CFDateRef) CFAbsoluteTime;
extern fn CFDataGetLength(theData: CFDataRef) CFIndex;
extern fn CFDataGetBytePtr(theData: CFDataRef) [*]const u8;
extern fn CFErrorCopyDescription(err: CFErrorRef) CFStringRef;
extern fn CFErrorGetCode(err: CFErrorRef) CFIndex;
extern fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: SecCSFlags, staticCode: *SecStaticCodeRef) OSStatus;
extern fn SecStaticCodeCheckValidity(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef) OSStatus;
extern fn SecStaticCodeCheckValidityWithErrors(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef, errors: *CFErrorRef) OSStatus;
extern fn SecRequirementCreateWithString(text: CFStringRef, flags: SecCSFlags, requirement: *SecRequirementRef) OSStatus;
extern fn SecRequirementCopyString(requirement: SecRequirementRef, flags: SecCSFlags, text: *CFStringRef) OSStatus;
extern fn SecCodeCopySigningInformation(code: SecStaticCodeRef, flags: SecCSFlags, information: *CFDictionaryRef) OSStatus;
extern fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) CFStringRef;
extern fn SecCertificateGetTypeID() CFTypeID;
extern const kSecCodeInfoIdentifier: CFStringRef;
extern const kSecCodeInfoTeamIdentifier: CFStringRef;
extern const kSecCodeInfoFlags: CFStringRef;
extern const kSecCodeInfoFormat: CFStringRef;
extern const kSecCodeInfoCertificates: CFStringRef;
extern const kSecCodeInfoTime: CFStringRef;
extern const kSecCodeInfoTimestamp: CFStringRef;
extern const kSecCodeInfoCdHashes: CFStringRef;
extern const kSecCodeInfoUnique: CFStringRef;
extern const kSecCodeInfoDigestAlgorithms: CFStringRef;
extern const kSecCodeInfoRuntimeVersion: CFStringRef;
extern const kSecCodeInfoEntitlementsDict: CFStringRef;
extern const kSecCodeInfoDesignatedRequirement: CFStringRef;
extern const kSecCodeInfoStapledNotarizationTicket: CFStringRef;
extern const kSecCodeInfoMainExecutable: CFStringRef;
extern const kSecCodeInfoPlatformIdentifier: CFStringRef;

// ---- tests (pure; the corpus oracle matrix lives in tests/facts/darwin.zig) ----

test "security: status table is complete and lookup is total" {
    try std.testing.expectEqual(@as(usize, 84), status_table.len);
    try std.testing.expectEqualStrings("errSecSuccess", statusName(0));
    try std.testing.expectEqualStrings("errSecCSUnsigned", statusName(-67062));
    try std.testing.expectEqualStrings("errSecCSSignatureFailed", statusName(-67061));
    try std.testing.expectEqualStrings("errSecCSReqFailed", statusName(-67050));
    try std.testing.expectEqualStrings("errSecCSRevokedNotarization", statusName(-66992));
    try std.testing.expectEqualStrings("errSecCertificateRevoked", statusName(-67820));
    try std.testing.expectEqualStrings("CSSMERR_TP_CERT_REVOKED", statusName(-2147409652));
    try std.testing.expectEqualStrings("OSStatus(12345)", statusName(12345));
    try std.testing.expect(statusDetail(-67062) != null);
    try std.testing.expect(statusDetail(12345) == null);
    // No duplicate codes: statusName must be deterministic.
    for (status_table, 0..) |a, i| for (status_table[i + 1 ..]) |b| try std.testing.expect(a.code != b.code);
}

test "security: trust ladder" {
    const none: RequirementResults = .{ .anchor_apple = -67050, .apple_generic = -67050, .developer_id = -67050, .app_store = -67050, .notarized = -67050 };
    try std.testing.expectEqual(Trust.unsigned, ladder(-67062, none));
    try std.testing.expectEqual(Trust.invalid, ladder(-67061, none));
    try std.testing.expectEqual(Trust.invalid, ladder(-67045, none));
    try std.testing.expectEqual(Trust.revoked, ladder(-66992, none));
    try std.testing.expectEqual(Trust.revoked, ladder(-67820, none));
    try std.testing.expectEqual(Trust.revoked, ladder(-2147409652, none));
    try std.testing.expectEqual(Trust.adhoc, ladder(0, none));
    var r = none;
    r.anchor_apple = 0;
    r.apple_generic = 0;
    try std.testing.expectEqual(Trust.platform, ladder(0, r)); // /bin/ls
    r = none;
    r.apple_generic = 0;
    r.app_store = 0;
    try std.testing.expectEqual(Trust.app_store, ladder(0, r)); // Sketch.app
    r = none;
    r.apple_generic = 0;
    r.developer_id = 0;
    r.notarized = 0;
    try std.testing.expectEqual(Trust.developer_id_notarized, ladder(0, r)); // Discord.app
    r.notarized = -67050;
    try std.testing.expectEqual(Trust.developer_id, ladder(0, r));
    r = none;
    r.apple_generic = 0;
    try std.testing.expectEqual(Trust.other_certificate, ladder(0, r));
}

test "security: trust sentences" {
    var v = unavailable("--no-security", "/x");
    try std.testing.expectEqualStrings("not evaluated", trustSentence(&v, null));
    v.available = true;
    v.trust = .adhoc;
    try std.testing.expectEqualStrings("AD HOC (linker-signed) -- signature proves integrity only, not identity", trustSentence(&v, 0x20002));
    try std.testing.expectEqualStrings("AD HOC -- signature proves integrity only, not identity", trustSentence(&v, 0x2));
    try std.testing.expectEqualStrings("AD HOC -- signature proves integrity only, not identity", trustSentence(&v, null));
    v.trust = .invalid;
    v.validity_status = -67061;
    try std.testing.expectEqualStrings("INVALID (errSecCSSignatureFailed -67061)", trustSentence(&v, null));
    v.validity_status = 4242;
    try std.testing.expectEqualStrings("INVALID", trustSentence(&v, null));
    v.trust = .unsigned;
    try std.testing.expectEqualStrings("UNSIGNED (errSecCSUnsigned -67062)", trustSentence(&v, null));
    v.trust = .revoked;
    v.validity_status = -66992;
    try std.testing.expectEqualStrings("REVOKED (errSecCSRevokedNotarization -66992)", trustSentence(&v, null));
    v.trust = .developer_id_notarized;
    v.has_stapled_ticket = true;
    try std.testing.expectEqualStrings("DEVELOPER ID, notarized (stapled ticket present)", trustSentence(&v, null));
    v.trust = .platform;
    try std.testing.expect(std.mem.startsWith(u8, trustSentence(&v, null), "PLATFORM BINARY"));
    try std.testing.expectEqualStrings("adhoc", trustName(.adhoc));
}

test "security: the §5.4 codesign Security block renders from the verdict alone" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var v = unavailable("", "/x/hello-c");
    v.available = true;
    v.reason = null;
    v.revocation_checked = true;
    v.network_used = true;
    v.validity_status = 0;
    v.validity_status_name = statusName(0);
    v.requirement_results = .{ .anchor_apple = -67050, .apple_generic = -67050, .developer_id = -67050, .app_store = -67050, .notarized = -67050 };
    v.trust = ladder(v.validity_status, v.requirement_results);
    v.flags = 0x20002;
    v.format = "Mach-O thin (arm64)";
    v.identifier = "hello-c";

    const w = &out.writer;
    try w.print("SecStaticCodeCheckValidity({s})   = {d} {s}\n", .{ checkFlagsText(&v), v.validity_status, v.validity_status_name });
    const values = requirementValues(v.requirement_results);
    for (requirement_labels, values) |rl, value| try w.print("  {s:<64} = {d} {s}\n", .{ rl.label, value, statusName(value) });
    try w.print("kSecCodeInfoFlags=0x{x}  kSecCodeInfoFormat=\"{s}\"  kSecCodeInfoIdentifier=\"{s}\"\n", .{ v.flags.?, v.format.?, v.identifier.? });
    try w.print("Trust ladder: {s}\n", .{trustSentence(&v, v.flags)});
    try std.testing.expectEqualStrings(
        \\SecStaticCodeCheckValidity(kSecCSCheckAllArchitectures | kSecCSEnforceRevocationChecks)   = 0 errSecSuccess
        \\  anchor apple                                                     = -67050 errSecCSReqFailed
        \\  anchor apple generic                                             = -67050 errSecCSReqFailed
        \\  Developer ID (certificate leaf[field.1.2.840.113635.100.6.1.13]) = -67050 errSecCSReqFailed
        \\  Mac App Store (certificate leaf[field.1.2.840.113635.100.6.1.9]) = -67050 errSecCSReqFailed
        \\  notarized                                                        = -67050 errSecCSReqFailed
        \\kSecCodeInfoFlags=0x20002  kSecCodeInfoFormat="Mach-O thin (arm64)"  kSecCodeInfoIdentifier="hello-c"
        \\Trust ladder: AD HOC (linker-signed) -- signature proves integrity only, not identity
        \\
    , out.written());
}

test "security: bundle promotion path" {
    try std.testing.expectEqualStrings("/A/Hello.app", bundleRootOf("/A/Hello.app/Contents/MacOS/Hello", "app bundle with Mach-O thin (arm64)").?);
    try std.testing.expectEqualStrings("/A/X.framework", bundleRootOf("/A/X.framework/Versions/A/X", "bundle with Mach-O universal (x86_64 arm64)").?);
    try std.testing.expect(bundleRootOf("/A/hello-objc", "Mach-O thin (arm64)") == null);
    try std.testing.expect(bundleRootOf("/A/hello-objc", null) == null);
    try std.testing.expect(bundleRootOf("/A/bare", "app bundle with Mach-O thin (arm64)") == null);
}

test "security: unavailable verdict shape" {
    const v = unavailable("--no-security", "/x/y");
    try std.testing.expect(!v.available);
    try std.testing.expectEqual(Trust.unavailable, v.trust);
    try std.testing.expectEqualStrings("--no-security", v.reason.?);
    try std.testing.expectEqualStrings("/x/y", v.evaluated_path);
    try std.testing.expectEqualStrings("not evaluated", v.validity_status_name);
    try std.testing.expectEqual(@as(usize, 0), v.certificate_chain.len);
}

/// Synthetic backend used by the conversion tests (and by tests/fuzz/darwin.zig).
pub const TestNode = struct {
    kind: NodeKind,
    scalar: plist.Value = .null,
    keys: []const []const u8 = &.{},
    kids: []const *const TestNode = &.{},
};
pub const TestBackend = struct {
    arena: Allocator,
    pub const Node = *const TestNode;
    pub fn kind(_: TestBackend, n: Node) NodeKind {
        return n.kind;
    }
    pub fn open(self: TestBackend, n: Node) Allocator.Error!Children(Node) {
        if (n.kind == .scalar) return .{ .keys = &.{}, .nodes = &.{} };
        const nodes = try self.arena.alloc(Node, n.kids.len);
        for (n.kids, 0..) |k, i| nodes[i] = k;
        return .{ .keys = n.keys, .nodes = nodes };
    }
    pub fn scalar(_: TestBackend, n: Node) Allocator.Error!plist.Value {
        return n.scalar;
    }
};

test "security: convertTree builds dicts and arrays" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const jit: TestNode = .{ .kind = .scalar, .scalar = .{ .bool = true } };
    const s1: TestNode = .{ .kind = .scalar, .scalar = .{ .string = "group.one" } };
    const arr: TestNode = .{ .kind = .array, .kids = &.{&s1} };
    const root: TestNode = .{ .kind = .dict, .keys = &.{ "com.apple.security.cs.allow-jit", "com.apple.security.application-groups" }, .kids = &.{ &jit, &arr } };
    const v = try convertTree(TestBackend, .{ .arena = a }, a, &root);
    try std.testing.expectEqual(@as(usize, 2), v.dict.len);
    try std.testing.expectEqualStrings("com.apple.security.cs.allow-jit", v.dict[0].key);
    try std.testing.expect(v.dict[0].value.bool);
    try std.testing.expectEqual(@as(usize, 1), v.dict[1].value.array.len);
    try std.testing.expectEqualStrings("group.one", v.dict[1].value.array[0].string);
}

test "security: convertTree terminates on a cyclic tree" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var loop: TestNode = .{ .kind = .array, .kids = &.{} };
    const kids = try a.alloc(*const TestNode, 1);
    kids[0] = &loop;
    loop.kids = kids;
    const v = try convertTree(TestBackend, .{ .arena = a }, a, &loop);
    // convert_max_depth levels of arrays, then a `.null` placeholder.
    var cur = v;
    var depth: usize = 0;
    while (cur == .array and cur.array.len == 1) : (depth += 1) cur = cur.array[0];
    try std.testing.expect(depth <= convert_max_depth);
    try std.testing.expect(cur == .null);
}

test "security: convertTree on a scalar root and empty containers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s: TestNode = .{ .kind = .scalar, .scalar = .{ .integer = 7 } };
    try std.testing.expectEqual(@as(i64, 7), (try convertTree(TestBackend, .{ .arena = a }, a, &s)).integer);
    const d: TestNode = .{ .kind = .dict };
    try std.testing.expectEqual(@as(usize, 0), (try convertTree(TestBackend, .{ .arena = a }, a, &d)).dict.len);
    const arr: TestNode = .{ .kind = .array };
    try std.testing.expectEqual(@as(usize, 0), (try convertTree(TestBackend, .{ .arena = a }, a, &arr)).array.len);
    // Fewer keys than children: extra values are dropped, never read out of bounds.
    const k: TestNode = .{ .kind = .dict, .keys = &.{"only"}, .kids = &.{ &s, &s } };
    try std.testing.expectEqual(@as(usize, 1), (try convertTree(TestBackend, .{ .arena = a }, a, &k)).dict.len);
}

test "security: evaluate reports unavailable without the framework" {
    if (build_options.have_security) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 8);
    const v = try evaluate(a, "/bin/ls", .{}, &diags);
    try std.testing.expect(!v.available);
    try std.testing.expectEqual(Trust.unavailable, v.trust);
}

test "security: evaluate on a nonexistent path returns, never traps" {
    if (!build_options.have_security) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var diags = Diagnostics.init(a, 8);
    const v = try evaluate(a, "/nonexistent/machre/security/probe", .{}, &diags);
    try std.testing.expect(v.create_status != 0);
    try std.testing.expect(v.trust == .unavailable or v.trust == .unsigned);
    try std.testing.expect(diags.items().len > 0);
}
