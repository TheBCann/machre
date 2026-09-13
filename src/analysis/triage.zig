//! analysis/triage.zig — Wardle-style scored anomaly report: table-driven rules, categories, the ">= 2
//! categories" gate for suspicious+, positives that subtract, KnockKnock-style text.
//! Imports: analysis/analysis, bundle/bundle, output/sink, output/json, output/text, every module's types.
//!
//! Never a single tell: every weight is < 50 (comptime-asserted), `suspicious` and above additionally
//! require findings in at least two categories, and positive evidence (platform binary, notarization,
//! hardened runtime) subtracts. Absent inputs are "unknown", never "clean": a parser that is not
//! implemented, a signature that was not evaluated and an unreadable xattr all produce either an
//! info-severity finding or nothing at all — never a credit.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Analysis = @import("analysis.zig").Analysis;
const Bundle = @import("../bundle/bundle.zig").Bundle;
const Sink = @import("../output/sink.zig").Sink;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const version = @import("../core/version.zig");
const extra = @import("../core/macho_extra.zig");
const loadcmds = @import("../core/loadcmds.zig");
const security_mod = @import("../darwin/security.zig");
const cms_mod = @import("../codesign/cms.zig");
const blobs_mod = @import("../codesign/blobs.zig");
const entitlements_mod = @import("../codesign/entitlements.zig");
const strings_mod = @import("../strings/strings.zig");
const sanitize = @import("../core/sanitize.zig");

pub const Category = enum { signature, packing, dependencies, header, entitlements, strings, objc, bundle, quarantine, symbols, structure };
pub const Severity = enum(u8) { info, low, medium, high };
pub const Level = enum { clean, notable, suspicious, likely_malicious };

pub const Rule = struct {
    id: []const u8, // stable: "sig.unsigned", "pack.entropy", "deps.missing_dylib", "ent.get_task_allow", ...
    category: Category,
    severity: Severity,
    weight: u8, // < 50 always (comptime-asserted): no single tell is a verdict
    title: []const u8,
    doc: []const u8,
};
/// The rule table (DESIGN.md §4.23 lists every id/category/weight).
pub const rules: []const Rule = &.{
    // ---- signature ------------------------------------------------------------------------
    .{ .id = "sig.unsigned", .category = .signature, .severity = .high, .weight = 25, .title = "no code signature", .doc = "The file carries no LC_CODE_SIGNATURE. macOS cannot attribute it to anyone and Gatekeeper will refuse it on first launch; legitimate distributed software is always signed." },
    .{ .id = "sig.adhoc", .category = .signature, .severity = .low, .weight = 10, .title = "ad hoc signature", .doc = "An ad hoc signature has no certificate chain: it proves the file has not changed since it was signed, but says nothing about who produced it. Linker-signed ad hoc (the default for a locally built binary) is weaker evidence still, so it scores 3 instead of 10, and 0 when the signature is already known to be broken." },
    .{ .id = "sig.invalid", .category = .signature, .severity = .high, .weight = 35, .title = "signature does not match the file", .doc = "A recomputed page hash or a Security.framework validation disagrees with the embedded CodeDirectory: the file was modified after it was signed." },
    .{ .id = "sig.revoked", .category = .signature, .severity = .high, .weight = 45, .title = "revoked certificate or notarization", .doc = "Apple revoked the signing certificate or the notarization ticket. This is the strongest single signal in the table and still cannot reach a verdict on its own." },
    .{ .id = "sig.devid_not_notarized", .category = .signature, .severity = .medium, .weight = 15, .title = "Developer ID without notarization", .doc = "A Developer ID signature that Apple's notary service never accepted. Distributed software is notarized; an un-notarized Developer ID binary either predates notarization or was never submitted." },
    .{ .id = "sig.not_evaluated", .category = .signature, .severity = .info, .weight = 0, .title = "signature not evaluated by Security.framework", .doc = "--no-security or a build without Security.framework: the trust ladder comes from the embedded CMS chain only. Recorded so \"not checked\" is never mistaken for \"checked and fine\"." },
    .{ .id = "sig.sha1_only", .category = .signature, .severity = .medium, .weight = 8, .title = "SHA-1 code directory only", .doc = "The signature carries no SHA-256 CodeDirectory. SHA-1 has been deprecated for code signing since macOS 10.12; a modern toolchain always emits a SHA-256 directory." },
    .{ .id = "sig.hardened_runtime_missing", .category = .signature, .severity = .low, .weight = 8, .title = "certificate-signed without the hardened runtime", .doc = "A certificate-signed binary without CS_RUNTIME can be injected into with DYLD_INSERT_LIBRARIES and unsigned libraries. Not applicable to ad hoc or Apple platform binaries." },
    // ---- packing --------------------------------------------------------------------------
    .{ .id = "pack.entropy", .category = .packing, .severity = .medium, .weight = 25, .title = "high-entropy segment", .doc = "A segment with more than 7.0 bits/byte covering more than 20% of the slice: compressed, encrypted or packed data rather than code." },
    .{ .id = "pack.names", .category = .packing, .severity = .medium, .weight = 25, .title = "packer segment/section name", .doc = "A segment or section name used by a known packer (__XHDR, UPX_DATA, upxTEXT, __MPRESS__)." },
    .{ .id = "pack.no_imports_no_symbols", .category = .packing, .severity = .medium, .weight = 25, .title = "no imports and no symbols", .doc = "An executable that imports nothing and exports no symbols resolves its own dependencies at runtime — the classic shape of an unpacking stub." },
    .{ .id = "pack.protected_segment", .category = .packing, .severity = .medium, .weight = 20, .title = "SG_PROTECTED_VERSION_1 segment", .doc = "The segment is encrypted with Apple's binary protection. On a third-party binary this is unusual: only Apple can produce a loadable protected segment." },
    .{ .id = "pack.encryption_info", .category = .packing, .severity = .medium, .weight = 20, .title = "LC_ENCRYPTION_INFO with cryptid != 0", .doc = "The load command says part of __TEXT is encrypted and will be decrypted by the kernel at load time. Static analysis of that range is impossible." },
    .{ .id = "pack.tiny_text_large_data", .category = .packing, .severity = .low, .weight = 8, .title = "tiny __TEXT, large data", .doc = "Far more data than code: the payload may be carried as data and executed after unpacking." },
    // ---- dependencies ---------------------------------------------------------------------
    .{ .id = "deps.missing_dylib", .category = .dependencies, .severity = .high, .weight = 20, .title = "dependency cannot be resolved", .doc = "A non-weak LC_LOAD_DYLIB names a library that is neither on disk nor in the dyld shared cache. Either the sample is incomplete or the library is expected to be planted at run time (dylib hijacking)." },
    .{ .id = "deps.rpath_frameworks", .category = .dependencies, .severity = .low, .weight = 5, .title = "run-path outside the bundle", .doc = "An LC_RPATH entry is an absolute path outside the system frameworks, so a library search resolves into a directory the sample does not own." },
    .{ .id = "deps.reexport", .category = .dependencies, .severity = .medium, .weight = 10, .title = "LC_REEXPORT_DYLIB", .doc = "The image re-exports another library's symbols. In a loaded dylib this is the shape of a proxy/shim that forwards to the original library while running its own code." },
    .{ .id = "deps.dyld_environment", .category = .dependencies, .severity = .high, .weight = 20, .title = "LC_DYLD_ENVIRONMENT", .doc = "The binary ships its own DYLD_* environment settings, which dyld applies before main(). A standard way to force an extra library into the process." },
    .{ .id = "deps.weak_unusual", .category = .dependencies, .severity = .low, .weight = 3, .title = "weak dependency outside the system", .doc = "LC_LOAD_WEAK_DYLIB on a non-system library: the process starts even when the library is absent, which is what a planted-library loader wants." },
    // ---- header ---------------------------------------------------------------------------
    .{ .id = "hdr.rwx_segment", .category = .header, .severity = .high, .weight = 30, .title = "writable and executable segment", .doc = "A segment mapped rwx lets the process rewrite its own code. No compiler emits this." },
    .{ .id = "hdr.rwx_maxprot", .category = .header, .severity = .medium, .weight = 15, .title = "segment may be re-protected writable and executable", .doc = "initprot is r-x but maxprot allows rwx, so the process may mprotect its own code writable and rewrite it in place. Compilers emit maxprot == initprot; 2 of 1178 system and application binaries carry this. It is the latent form of hdr.rwx_segment and the shape an unpacking stub needs." },
    .{ .id = "hdr.allow_stack_execution", .category = .header, .severity = .high, .weight = 20, .title = "MH_ALLOW_STACK_EXECUTION", .doc = "The stack is executable: shellcode written to the stack can be jumped to." },
    .{ .id = "hdr.no_pie", .category = .header, .severity = .low, .weight = 8, .title = "not position independent", .doc = "MH_PIE is clear on an executable, so it always loads at the same address and ASLR does not apply." },
    .{ .id = "hdr.unknown_lc_req_dyld", .category = .header, .severity = .high, .weight = 20, .title = "unknown load command with LC_REQ_DYLD", .doc = "A load command this tool does not know that dyld is required to understand. Either a newer OS format or a deliberately malformed header." },
    .{ .id = "hdr.unknown_lc", .category = .header, .severity = .low, .weight = 5, .title = "unknown load command", .doc = "A load command outside the documented set; dyld may ignore it, but so does every analysis tool." },
    .{ .id = "hdr.segment_order", .category = .header, .severity = .low, .weight = 5, .title = "__LINKEDIT is not the last segment", .doc = "The code signature covers the file up to the end of __LINKEDIT; a segment after it is outside everything the signature and the linker expect." },
    .{ .id = "hdr.text_not_at_zero", .category = .header, .severity = .low, .weight = 5, .title = "__TEXT does not start at file offset 0", .doc = "The Mach header must live inside __TEXT at file offset 0; anything else is a hand-edited or generated layout." },
    .{ .id = "hdr.unixthread_entry", .category = .header, .severity = .low, .weight = 8, .title = "LC_UNIXTHREAD entry point", .doc = "A pre-10.8 entry point that names a raw register state instead of LC_MAIN. Modern toolchains do not emit it; hand-built binaries and some packers do." },
    .{ .id = "hdr.entry_outside_text", .category = .header, .severity = .medium, .weight = 20, .title = "entry point outside __TEXT", .doc = "Execution starts outside the executable segment the linker produced — typical of an appended or patched-in stage." },
    // ---- entitlements ---------------------------------------------------------------------
    .{ .id = "ent.get_task_allow", .category = .entitlements, .severity = .medium, .weight = 10, .title = "com.apple.security.get-task-allow", .doc = "Any process may attach to this one, read and write its memory. Present in debug builds; in shipped software it is an open door." },
    .{ .id = "ent.disable_library_validation", .category = .entitlements, .severity = .medium, .weight = 12, .title = "com.apple.security.cs.disable-library-validation", .doc = "Any signed library, from any team, may be loaded into the process — the entitlement that makes plug-in based injection possible." },
    .{ .id = "ent.allow_jit", .category = .entitlements, .severity = .low, .weight = 8, .title = "com.apple.security.cs.allow-jit", .doc = "The process may map writable+executable memory. Legitimate for JavaScript engines; otherwise a way to run code that no signature covers." },
    .{ .id = "ent.allow_unsigned_memory", .category = .entitlements, .severity = .medium, .weight = 12, .title = "com.apple.security.cs.allow-unsigned-executable-memory", .doc = "Unsigned code may be executed from memory: the hardened runtime's core protection is switched off." },
    .{ .id = "ent.allow_dyld_env", .category = .entitlements, .severity = .medium, .weight = 12, .title = "com.apple.security.cs.allow-dyld-environment-variables", .doc = "DYLD_* environment variables are honoured, so a parent process can insert a library into this one." },
    .{ .id = "ent.debugger", .category = .entitlements, .severity = .medium, .weight = 10, .title = "com.apple.security.cs.debugger", .doc = "The process may debug other processes: read and write their memory and install code in them." },
    .{ .id = "ent.xml_der_mismatch", .category = .entitlements, .severity = .high, .weight = 20, .title = "XML and DER entitlements disagree", .doc = "The two entitlement encodings in the same signature carry different dictionaries. Only one is enforced, so the other is there to mislead whoever reads it." },
    // ---- strings --------------------------------------------------------------------------
    .{ .id = "str.script_interpreters", .category = .strings, .severity = .medium, .weight = 8, .title = "script interpreter strings", .doc = "Strings naming /bin/sh, osascript, python or similar: the binary is likely to shell out." },
    .{ .id = "str.persistence_paths", .category = .strings, .severity = .medium, .weight = 10, .title = "persistence paths", .doc = "LaunchAgents/LaunchDaemons, login items or cron paths: the classic macOS persistence locations." },
    .{ .id = "str.network_indicators", .category = .strings, .severity = .low, .weight = 5, .title = "network indicators", .doc = "Embedded URLs or literal IP addresses — where the binary talks to." },
    .{ .id = "str.base64_blobs", .category = .strings, .severity = .low, .weight = 5, .title = "base64 blobs", .doc = "Long base64-looking strings: encoded configuration, a second stage, or an exfiltration key." },
    .{ .id = "str.anti_analysis", .category = .strings, .severity = .medium, .weight = 10, .title = "anti-analysis strings", .doc = "Names of debuggers, VMs or analysis tools: the sample checks whether it is being watched." },
    // ---- objc / symbols / stubs ------------------------------------------------------------
    .{ .id = "objc.suspicious_selectors", .category = .objc, .severity = .medium, .weight = 8, .title = "suspicious Objective-C selectors", .doc = "Selectors for keychain access, screen capture, AppleScript, task spawning or accessibility control." },
    .{ .id = "sym.stripped", .category = .symbols, .severity = .info, .weight = 0, .title = "symbol table stripped", .doc = "No local symbols survive. Normal for release builds, and worth stating next to the other findings." },
    .{ .id = "stubs.mismatch", .category = .structure, .severity = .medium, .weight = 15, .title = "stub table disagrees with the indirect symbol table", .doc = "The symbol a stub actually loads differs from the one the indirect symbol table names: an edited import table redirects a call somewhere else." },
    // ---- bundle ---------------------------------------------------------------------------
    .{ .id = "bundle.no_info_plist", .category = .bundle, .severity = .high, .weight = 20, .title = "bundle without Info.plist", .doc = "A bundle directory with no Info.plist: nothing identifies it, and the code signature has no Info.plist to seal." },
    .{ .id = "bundle.executable_mismatch", .category = .bundle, .severity = .high, .weight = 20, .title = "CFBundleExecutable does not match the main executable", .doc = "The Info.plist names an executable that is missing or different from the one actually present." },
    .{ .id = "bundle.nested_unsigned", .category = .bundle, .severity = .medium, .weight = 15, .title = "unsigned nested code", .doc = "A framework, helper, XPC service or dylib inside the bundle carries no signature, so the bundle's own signature does not vouch for it." },
    .{ .id = "bundle.resource_mismatch", .category = .bundle, .severity = .high, .weight = 25, .title = "sealed resource does not match", .doc = "A file's hash disagrees with the CodeResources seal: the bundle was modified after it was signed." },
    .{ .id = "bundle.unsealed", .category = .bundle, .severity = .medium, .weight = 10, .title = "unsealed files in the bundle", .doc = "Files inside the bundle that the CodeResources seal does not cover: they can be replaced without breaking the signature." },
    .{ .id = "bundle.ui_element", .category = .bundle, .severity = .low, .weight = 3, .title = "LSUIElement / LSBackgroundOnly", .doc = "The app runs without a Dock icon or user interface. Legitimate for agents; also how an unwanted app stays out of sight." },
    .{ .id = "bundle.ats_insecure", .category = .bundle, .severity = .low, .weight = 5, .title = "NSAllowsArbitraryLoads", .doc = "App Transport Security is disabled, so the app may talk plain HTTP to anywhere." },
    // ---- quarantine / structure ------------------------------------------------------------
    .{ .id = "quarantine.present", .category = .quarantine, .severity = .info, .weight = 0, .title = "quarantine xattr present", .doc = "The file was downloaded: com.apple.quarantine records which agent fetched it and when. Provenance, not a defect." },
    .{ .id = "quarantine.translocated", .category = .quarantine, .severity = .info, .weight = 0, .title = "app translocation path", .doc = "The path is inside /private/var/folders/.../AppTranslocation: macOS is running a quarantined app from a read-only copy." },
    .{ .id = "diag.malformed", .category = .structure, .severity = .medium, .weight = 10, .title = "malformed structure", .doc = "At least one parser recorded an error-severity diagnostic: the file's structure does not match its own declarations." },
};
comptime {
    @setEvalBranchQuota(200_000);
    for (rules) |r| std.debug.assert(r.weight < 50);
    // Ids are unique, so `byId` is a stable contract and a finding can be looked up by id.
    for (rules, 0..) |r, i| for (rules[i + 1 ..]) |o| std.debug.assert(!std.mem.eql(u8, r.id, o.id));
}
pub fn byId(id: []const u8) ?*const Rule {
    for (rules) |*r| if (std.mem.eql(u8, r.id, id)) return r;
    return null;
}

pub const Finding = struct { rule: *const Rule, score: u8, title: []const u8, detail: []const u8, evidence: []const []const u8, corroborates: ?[]const u8 };
pub const Positive = struct { id: []const u8, text: []const u8, credit: u8 };
pub const Summary = struct { signed: bool, trust: []const u8, notarized: ?bool, hardened_runtime: bool, quarantined: bool, packed_hint: bool, encrypted: bool, imports: u32, exports: u32, symbols: u32, dylibs: u32, objc_classes: u32, arch: []const u8 };
pub const Report = struct {
    score: u32,
    level: Level,
    findings: []const Finding, // severity desc, then weight desc
    positives: []const Positive,
    categories_hit: []const Category,
    corroboration: []const []const u8, // human sentences
    not_flagged: []const []const u8, // "Not flagged:" facts (entropy max, imports present, ...)
    summary: Summary,
    per_arch: bool,
    exit_code: u8,
};
pub const Options = struct { fail_on: ?Level = null, explain: bool = false };

/// score = sum(weights) - sum(positive credits), floored at 0 (four credits: platform 20, notarized 15,
/// app_store 15, hardened_runtime 3). Bands: < 20 clean, < 50 notable, < 100 suspicious, >= 100 likely
/// malicious. Fewer than 2 of the 11 `Category` values hit demotes the top two bands by exactly one rung,
/// so one category caps at `.notable` below 100 but still reaches `.suspicious` at 100 and above — a
/// single-category score never returns `.likely_malicious`, and never falls back below `.suspicious`.
pub fn levelFor(score: u32, categories_hit: usize) Level {
    if (score < 20) return .clean;
    if (score < 50) return .notable;
    if (score < 100) return if (categories_hit >= 2) .suspicious else .notable;
    return if (categories_hit >= 2) .likely_malicious else .suspicious;
}

pub fn levelName(l: Level) []const u8 {
    return @tagName(l);
}
/// Upper-case spelling used by the text verdict line (DESIGN §5.5).
pub fn levelDisplay(l: Level) []const u8 {
    return switch (l) {
        .clean => "CLEAN",
        .notable => "NOTABLE",
        .suspicious => "SUSPICIOUS",
        .likely_malicious => "LIKELY MALICIOUS",
    };
}
pub fn categoryName(c: Category) []const u8 {
    return @tagName(c);
}
/// Left column of the finding rows.
pub fn categoryDisplay(c: Category) []const u8 {
    return switch (c) {
        .signature => "Signing",
        .packing => "Packing",
        .dependencies => "Dependencies",
        .header => "Header",
        .entitlements => "Entitlements",
        .strings => "Strings",
        .objc => "ObjC",
        .bundle => "Bundle",
        .quarantine => "Quarantine",
        .symbols => "Symbols",
        .structure => "Structure",
    };
}
pub fn severityDisplay(s: Severity) []const u8 {
    return switch (s) {
        .info => "[INFO]",
        .low => "[LOW]",
        .medium => "[MEDIUM]",
        .high => "[HIGH]",
    };
}
/// Short uppercase trust word for the verdict line.
pub fn trustDisplay(t: security_mod.Trust) []const u8 {
    return switch (t) {
        .platform => "PLATFORM (Apple)",
        .app_store => "APP STORE",
        .developer_id_notarized => "DEVELOPER ID, NOTARIZED",
        .developer_id => "DEVELOPER ID",
        .other_certificate => "SIGNED (other certificate)",
        .adhoc => "AD HOC",
        .unsigned => "UNSIGNED",
        .invalid => "INVALID SIGNATURE",
        .revoked => "REVOKED",
        .unavailable => "NOT EVALUATED",
    };
}

// ---------------------------------------------------------------------------------------------
// rule evaluation
// ---------------------------------------------------------------------------------------------

/// Longest detail/evidence string kept in a finding (they are one-liners by construction).
const max_detail: u32 = 4096;

const errSecCSUnsigned: i32 = -67062;
const errSecCSSignatureFailed: i32 = -67061;
const errSecCSSignatureInvalid: i32 = -67030;
const errSecCSRevokedNotarization: i32 = -66992;
const CSSMERR_TP_CERT_REVOKED: i32 = -2147409652;

const Builder = struct {
    arena: Allocator,
    findings: std.ArrayList(Finding) = .empty,
    positives: std.ArrayList(Positive) = .empty,
    corroboration: std.ArrayList([]const u8) = .empty,
    not_flagged: std.ArrayList([]const u8) = .empty,

    /// Every stored string is sanitised here, so the JSON and text renderers need no allocator and
    /// a 16-byte segment name full of random bytes can never reach `std.json.Stringify` as a string
    /// or the analyst's terminal as an escape sequence. `.text` (not `.json`) because a `Report` is
    /// rendered to both channels from the same stored bytes.
    fn clean(b: *Builder, s: []const u8) Allocator.Error![]const u8 {
        return (try sanitize.string(b.arena, s, .text, max_detail)).text;
    }
    fn add(b: *Builder, id: []const u8, detail: []const u8) Allocator.Error!void {
        const r = byId(id) orelse return;
        try b.addScored(id, r.weight, detail, &.{});
    }
    fn addFmt(b: *Builder, id: []const u8, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try b.add(id, try std.fmt.allocPrint(b.arena, fmt, args));
    }
    fn addScored(b: *Builder, id: []const u8, score: u8, detail: []const u8, evidence: []const []const u8) Allocator.Error!void {
        const r = byId(id) orelse return;
        if (b.fired(id)) return; // one finding per rule per slice
        const ev = try b.arena.alloc([]const u8, evidence.len);
        for (evidence, 0..) |e, i| ev[i] = try b.clean(e);
        try b.findings.append(b.arena, .{ .rule = r, .score = score, .title = r.title, .detail = try b.clean(detail), .evidence = ev, .corroborates = null });
    }
    fn fired(b: *const Builder, id: []const u8) bool {
        for (b.findings.items) |f| if (std.mem.eql(u8, f.rule.id, id)) return true;
        return false;
    }
    fn firedCategory(b: *const Builder, c: Category) bool {
        for (b.findings.items) |f| if (f.rule.category == c) return true;
        return false;
    }
    fn firedPrefix(b: *const Builder, prefix: []const u8) bool {
        for (b.findings.items) |f| if (std.mem.startsWith(u8, f.rule.id, prefix)) return true;
        return false;
    }
    fn detailOf(b: *const Builder, id: []const u8) ?[]const u8 {
        for (b.findings.items) |f| if (std.mem.eql(u8, f.rule.id, id)) return f.detail;
        return null;
    }
    fn corroborate(b: *Builder, id: []const u8, other: []const u8, sentence: []const u8) Allocator.Error!void {
        for (b.findings.items) |*f| if (std.mem.eql(u8, f.rule.id, id)) {
            f.corroborates = other;
        };
        try b.corroboration.append(b.arena, sentence);
    }
    fn positive(b: *Builder, id: []const u8, text: []const u8, credit: u8) Allocator.Error!void {
        try b.positives.append(b.arena, .{ .id = id, .text = text, .credit = credit });
    }
    fn note(b: *Builder, s: []const u8) Allocator.Error!void {
        try b.not_flagged.append(b.arena, try b.clean(s));
    }
    fn noteFmt(b: *Builder, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try b.note(try std.fmt.allocPrint(b.arena, fmt, args));
    }
};

fn lessFinding(_: void, a: Finding, c: Finding) bool {
    if (a.rule.severity != c.rule.severity) return @intFromEnum(a.rule.severity) > @intFromEnum(c.rule.severity);
    if (a.rule.weight != c.rule.weight) return a.rule.weight > c.rule.weight;
    return std.mem.order(u8, a.rule.id, c.rule.id) == .lt;
}

/// Selectors whose presence is worth a line in a triage report.
const suspicious_selectors: []const []const u8 = &.{
    "eychain",    "LaunchAgent", "LaunchDaemon", "AppleScript",        "screenCapture", "CGWindowList",
    "SMJobBless", "NSTask",      "posix_spawn",  "AXIsProcessTrusted", "CGEventTap",    "TCC",
};

fn selectorIsSuspicious(name: []const u8) ?[]const u8 {
    for (suspicious_selectors) |needle| if (std.mem.find(u8, name, needle) != null) return needle;
    return null;
}

/// System locations a dylib search path may legitimately point at.
fn systemPath(p: []const u8) bool {
    const roots = [_][]const u8{ "/System/", "/usr/lib/", "/Library/Apple/", "/usr/local/lib/" };
    for (roots) |r| if (std.mem.startsWith(u8, p, r)) return true;
    return false;
}

pub fn run(arena: Allocator, a: *Analysis, bundle: ?*const Bundle, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!Report {
    // Every cap that matters here is applied by the parsers behind `Analysis` (which hold the same
    // `*const Limits`): triage itself only walks already-clamped tables, so it has no loop of its own
    // to bound. The parameter stays in the signature so a future rule can reach for a cap.
    _ = limits;
    var b: Builder = .{ .arena = arena };
    const img = a.img;

    // ---------------------------------------------------------------- signature ----
    const sig = try a.signature();
    const cd: ?*const blobs_mod.CodeDirectory = if (sig) |s| s.cd() else null;
    const ver = try a.verification();
    const sec = try a.security();
    const cms = try a.cms();
    const cd_flags: u32 = if (cd) |c| c.flags else 0;
    const hardened = cd != null and cd.?.hasHardenedRuntime();
    const offline = cms_mod.offlineTrust(cms, cd_flags, if (cd) |c| c.platform else 0);

    const revoked = sec.trust == .revoked or sec.validity_status == errSecCSRevokedNotarization or sec.validity_status == CSSMERR_TP_CERT_REVOKED;
    const pages_bad = if (ver) |v| (v.mismatches != 0 or v.special_mismatches != 0) else false;
    const sec_invalid = sec.available and sec.validity_status != 0 and sec.validity_status != errSecCSUnsigned and !revoked;

    if (sig == null) {
        try b.add("sig.unsigned", "no LC_CODE_SIGNATURE: nothing attests to the contents of this file");
    } else {
        if (revoked) {
            try b.addFmt("sig.revoked", "Apple revoked the signing certificate or the notarization ticket: {s} ({d})", .{ security_mod.statusName(sec.validity_status), sec.validity_status });
        }
        if (pages_bad or sec_invalid) {
            const detail = if (pages_bad and ver.?.pages_checked != 0) blk: {
                const page = ver.?.first_bad_page orelse 0;
                const page_size = if (cd) |c| c.pageSize() else 0;
                const at = @as(u64, page) *| page_size;
                break :blk if (sec.available and sec.validity_status != 0)
                    try std.fmt.allocPrint(arena, "embedded CodeDirectory does not match the file: {d}/{d} page hashes mismatch (first page {d} @ 0x{x}); Security: {s} ({d})", .{ ver.?.mismatches, ver.?.pages_checked, page, at, security_mod.statusName(sec.validity_status), sec.validity_status })
                else
                    try std.fmt.allocPrint(arena, "embedded CodeDirectory does not match the file: {d}/{d} page hashes mismatch (first page {d} @ 0x{x})", .{ ver.?.mismatches, ver.?.pages_checked, page, at });
            } else if (pages_bad)
                try std.fmt.allocPrint(arena, "{d} special slot hash(es) do not match the blobs they seal", .{ver.?.special_mismatches})
            else
                try std.fmt.allocPrint(arena, "Security.framework rejected the signature: {s} ({d})", .{ security_mod.statusName(sec.validity_status), sec.validity_status });
            try b.add("sig.invalid", detail);
        }
        if (cd) |c| if (c.isAdhoc()) {
            // Ad hoc identity is only worth scoring while the signature itself still holds.
            const base: u8 = if (c.isLinkerSigned()) 3 else 10;
            const score: u8 = if (b.fired("sig.invalid") or b.fired("sig.revoked")) 0 else base;
            try b.addScored("sig.adhoc", score, if (c.isLinkerSigned())
                "ad hoc, linker-signed; no certificate chain, not notarized"
            else
                "ad hoc; no certificate chain, not notarized", &.{});
        };
        if (sec.trust == .developer_id) {
            try b.add("sig.devid_not_notarized", "Developer ID certificate, but Apple's notary service never accepted this build");
        }
        if (cd) |c| if (c.hash_type == .sha1) {
            var only_sha1 = true;
            for (sig.?.code_directories) |o| if (o.hash_type != .sha1) {
                only_sha1 = false;
            };
            if (only_sha1) try b.add("sig.sha1_only", "the only CodeDirectory uses SHA-1 (deprecated for code signing since macOS 10.12)");
        };
        const certificate_signed = cms != null and cms.?.certificates.len != 0;
        if (certificate_signed and !hardened and sec.trust != .platform and offline != .platform) {
            try b.add("sig.hardened_runtime_missing", "certificate-signed but CS_RUNTIME is clear: DYLD_INSERT_LIBRARIES and unsigned libraries are not blocked");
        }
    }
    if (!sec.available) {
        try b.addScored("sig.not_evaluated", 0, sec.reason orelse "Security.framework was not consulted", &.{});
    }

    // ---------------------------------------------------------------- packing ----
    const ent_report = try a.entropy();
    for (ent_report.tells) |t| switch (t.code) {
        .high_entropy_segment => try b.add("pack.entropy", t.detail),
        .packer_segment_name, .packer_section_name => try b.add("pack.names", t.detail),
        .no_imports_no_symbols => try b.add("pack.no_imports_no_symbols", t.detail),
        .protected_segment => try b.add("pack.protected_segment", t.detail),
        .encryption_info => try b.add("pack.encryption_info", t.detail),
        .tiny_text_huge_data => try b.add("pack.tiny_text_large_data", t.detail),
        .rwx_segment => try b.add("hdr.rwx_segment", t.detail),
        .rwx_maxprot => try b.add("hdr.rwx_maxprot", t.detail),
        .entry_outside_text => try b.add("hdr.entry_outside_text", t.detail),
        // Reported as evidence on the packing/header findings rather than scored on its own:
        // an unknown segment name before __LINKEDIT is exactly what `pack.names`/`pack.entropy` saw.
        .nonstandard_segment_order => {},
    };

    // ---------------------------------------------------------------- header ----
    const flags = img.hdr.flags;
    if (flags & 0x20000 != 0) try b.add("hdr.allow_stack_execution", "MH_ALLOW_STACK_EXECUTION is set: the stack is mapped executable");
    if (flags & 0x200000 == 0 and img.hdr.filetype == 2) {
        try b.add("hdr.no_pie", "MH_PIE is clear on an MH_EXECUTE: the image always loads at the same address");
    }
    for (img.cmds) |c| {
        if (version.lcName(c.cmd) != null) continue;
        if (c.cmd & extra.LC_REQ_DYLD != 0) {
            try b.addFmt("hdr.unknown_lc_req_dyld", "load command {d} is 0x{x} (LC_REQ_DYLD) and is not a documented command", .{ c.index, c.cmd });
        } else {
            try b.addFmt("hdr.unknown_lc", "load command {d} is 0x{x} and is not a documented command", .{ c.index, c.cmd });
        }
    }
    if (img.linkedit_seg) |le| {
        if (le + 1 != img.segments.len) try b.addFmt("hdr.segment_order", "__LINKEDIT is segment {d} of {d}: another segment follows it", .{ le, img.segments.len });
    }
    if (img.text_seg) |ti| {
        const t = img.segments[ti];
        if (t.fileoff != 0) try b.addFmt("hdr.text_not_at_zero", "__TEXT starts at file offset {d}, not 0", .{t.fileoff});
    }
    for (img.cmds) |c| if (c.lc() == .UNIXTHREAD) {
        try b.add("hdr.unixthread_entry", "LC_UNIXTHREAD entry point (pre-10.8 form) instead of LC_MAIN");
    };

    // ---------------------------------------------------------------- dependencies ----
    const dylibs = try a.dylibs();
    for (img.cmds) |c| switch (c.lc()) {
        .REEXPORT_DYLIB => try b.add("deps.reexport", "LC_REEXPORT_DYLIB: this image forwards another library's symbols"),
        .DYLD_ENVIRONMENT => try b.add("deps.dyld_environment", "LC_DYLD_ENVIRONMENT: the image sets DYLD_* variables for its own process"),
        else => {},
    };
    for (dylibs) |d| if (d.weak and !systemPath(d.path) and !std.mem.startsWith(u8, d.path, "@")) {
        try b.addFmt("deps.weak_unusual", "LC_LOAD_WEAK_DYLIB {s}: the process starts even when this library is absent", .{d.short_name});
    };
    for (try a.rpaths()) |rp| if (rp.len != 0 and rp[0] == '/' and !systemPath(rp)) {
        try b.addFmt("deps.rpath_frameworks", "LC_RPATH {s} is an absolute path outside the system frameworks", .{rp});
    };
    for (try a.resolutions()) |res| switch (res.status) {
        .missing, .unresolvable_rpath => try b.addFmt("deps.missing_dylib", "{s} is neither on disk nor in the dyld shared cache ({t})", .{ res.path, res.status }),
        else => {},
    };

    // ---------------------------------------------------------------- entitlements ----
    const ents = try a.entitlements();
    if (ents.disagreement) try b.add("ent.xml_der_mismatch", "the XML and DER entitlement blobs in this signature carry different dictionaries");
    for (ents.keys) |k| {
        const id: ?[]const u8 = if (std.mem.eql(u8, k, "com.apple.security.get-task-allow"))
            "ent.get_task_allow"
        else if (std.mem.eql(u8, k, "com.apple.security.cs.disable-library-validation"))
            "ent.disable_library_validation"
        else if (std.mem.eql(u8, k, "com.apple.security.cs.allow-jit"))
            "ent.allow_jit"
        else if (std.mem.eql(u8, k, "com.apple.security.cs.allow-unsigned-executable-memory"))
            "ent.allow_unsigned_memory"
        else if (std.mem.eql(u8, k, "com.apple.security.cs.allow-dyld-environment-variables"))
            "ent.allow_dyld_env"
        else if (std.mem.eql(u8, k, "com.apple.security.cs.debugger"))
            "ent.debugger"
        else
            null;
        // Only a TRUE value grants anything: `get-task-allow = false` is the hardened default, not a tell.
        if (id) |i| if (ents.isTrue(k)) {
            const why = if (entitlements_mod.isDangerous(k)) |d| d.why else "";
            try b.addFmt(i, "{s} = true: {s}", .{ k, why });
        };
    }

    // ---------------------------------------------------------------- strings ----
    const strs = try a.strings(.{ .min_len = 6, .dedupe = true, .classify = true });
    var class_counts: [@typeInfo(strings_mod.Class).@"enum".field_names.len]u32 = @splat(0);
    var first_of_class: [@typeInfo(strings_mod.Class).@"enum".field_names.len]?[]const u8 = @splat(null);
    for (strs.strings) |s| {
        const i = @intFromEnum(s.class);
        class_counts[i] +|= 1;
        if (first_of_class[i] == null) first_of_class[i] = s.text;
    }
    const StrRule = struct { class: strings_mod.Class, id: []const u8 };
    const str_rules = [_]StrRule{
        .{ .class = .script, .id = "str.script_interpreters" },
        .{ .class = .shell, .id = "str.script_interpreters" },
        .{ .class = .launch_agent, .id = "str.persistence_paths" },
        .{ .class = .persistence, .id = "str.persistence_paths" },
        .{ .class = .keychain, .id = "str.persistence_paths" },
        .{ .class = .url, .id = "str.network_indicators" },
        .{ .class = .ip, .id = "str.network_indicators" },
        .{ .class = .base64, .id = "str.base64_blobs" },
        .{ .class = .anti_analysis, .id = "str.anti_analysis" },
    };
    for (str_rules) |sr| {
        const i = @intFromEnum(sr.class);
        if (class_counts[i] == 0) continue;
        try b.addFmt(sr.id, "{d} {t} string(s), first: {s}", .{ class_counts[i], sr.class, firstLine(first_of_class[i].?) });
    }

    // ---------------------------------------------------------------- objc ----
    const oc = try a.objc();
    var objc_classes: u32 = 0;
    if (oc) |o| {
        objc_classes = @intCast(o.classes.len);
        for (o.selectors) |s| if (selectorIsSuspicious(s.name)) |needle| {
            try b.addFmt("objc.suspicious_selectors", "selector {s} (matched \"{s}\")", .{ s.name, needle });
        };
    }

    // ---------------------------------------------------------------- symbols / stubs ----
    const syms = try a.symbols();
    const imports = try a.imports();
    const exports = try a.exports();
    if (syms.present and syms.counts.local == 0 and syms.counts.stabs == 0) {
        try b.addScored("sym.stripped", 0, "no local symbols in LC_SYMTAB", &.{});
    }
    const stubs = try a.stubs();
    if (stubs.mismatches != 0) {
        try b.addFmt("stubs.mismatch", "{d} stub(s) load a symbol the indirect symbol table does not name", .{stubs.mismatches});
    }

    // ---------------------------------------------------------------- bundle ----
    if (bundle) |bun| {
        if (bun.info_plist_path == null) try b.add("bundle.no_info_plist", "no Contents/Info.plist, Versions/*/Resources/Info.plist or Info.plist");
        if (bun.info_plist_path != null and bun.executable_path == null) {
            try b.addFmt("bundle.executable_mismatch", "CFBundleExecutable {s} is not present in the bundle", .{bun.executable_rel orelse "(missing)"});
        }
        const nested = try bun.nestedAll(arena);
        for (nested) |n| if (n.signed != null and !n.signed.?) {
            try b.addFmt("bundle.nested_unsigned", "{s} carries no code signature", .{n.rel_path});
        };
        for (nested) |n| if (n.cdhash_match != null and !n.cdhash_match.?) {
            try b.addFmt("bundle.resource_mismatch", "nested code {s}: the actual cdhash differs from the sealed one", .{n.rel_path});
        };
        if (bun.resource_verify) |rv| {
            if (rv.mismatched.len != 0) try b.addFmt("bundle.resource_mismatch", "{d} sealed resource(s) do not match, first: {s}", .{ rv.mismatched.len, rv.mismatched[0] });
            if (rv.unsealed.len != 0) try b.addFmt("bundle.unsealed", "{d} file(s) inside the bundle are not covered by CodeResources, first: {s}", .{ rv.unsealed.len, rv.unsealed[0] });
        }
        if (bun.ui_element or bun.background_only) try b.add("bundle.ui_element", "LSUIElement/LSBackgroundOnly: the app runs with no Dock icon and no window");
        if (bun.ats_arbitrary_loads) try b.add("bundle.ats_insecure", "NSAppTransportSecurity.NSAllowsArbitraryLoads is true");
    }

    // ---------------------------------------------------------------- quarantine ----
    const xa = try a.xattrs();
    if (xa.quarantine) |q| {
        try b.addScored("quarantine.present", 0, try std.fmt.allocPrint(arena, "downloaded by {s}{s}", .{
            q.agent orelse "(unknown agent)",
            if (q.well_formed) "" else " (malformed xattr value)",
        }), &.{});
    }
    if (xa.is_translocated) try b.addScored("quarantine.translocated", 0, "running from an App Translocation copy", &.{});

    // ---------------------------------------------------------------- structure ----
    var structural: u32 = 0;
    var first_structural: []const u8 = "";
    for (diags.items()) |d| {
        if (!structuralDiag(d)) continue;
        if (structural == 0) first_structural = d.message;
        structural += 1;
    }
    if (structural != 0) {
        try b.addFmt("diag.malformed", "{d} error-severity diagnostic(s), first: {s}", .{ structural, firstLine(first_structural) });
    }

    // ---------------------------------------------------------------- positives ----
    if (sec.trust == .platform or offline == .platform) try b.positive("platform", "Apple platform binary (anchor apple)", 20);
    if (sec.trust == .developer_id_notarized) try b.positive("notarized", "notarized Developer ID", 15);
    if (sec.trust == .app_store or offline == .app_store) try b.positive("app_store", "Mac App Store distribution", 15);
    if (hardened) try b.positive("hardened_runtime", "hardened runtime (CS_RUNTIME)", 3);

    // ---------------------------------------------------------------- corroboration ----
    if (b.firedCategory(.packing) and (b.fired("sig.invalid") or b.fired("sig.revoked"))) {
        const marker = try b.clean(packMarker(&b));
        try b.corroborate("sig.invalid", "pack.names", try std.fmt.allocPrint(arena, "packing tell ({s}) is corroborated by a broken signature -> file was modified after linking.", .{marker}));
    } else if (b.firedCategory(.packing) and b.fired("sig.unsigned")) {
        try b.corroboration.append(arena, try std.fmt.allocPrint(arena, "packing tell ({s}) on an unsigned file -> nothing attests to the packed payload.", .{try b.clean(packMarker(&b))}));
    }
    if (b.fired("deps.dyld_environment") and b.fired("ent.allow_dyld_env")) {
        try b.corroboration.append(arena, "the load command and the entitlement both enable DYLD_* injection -> library insertion is intended, not accidental.");
    }
    if (b.fired("ent.disable_library_validation") and (b.fired("sig.adhoc") or b.fired("sig.unsigned"))) {
        try b.corroboration.append(arena, "library validation is disabled on a signature that proves no identity -> any signed library may be injected.");
    }
    if (b.fired("bundle.resource_mismatch") and !b.fired("sig.invalid")) {
        try b.corroboration.append(arena, "the executable's own signature is intact but a sealed resource is not -> the bundle was edited after signing.");
    }
    if (b.fired("stubs.mismatch") and b.fired("sig.invalid")) {
        try b.corroboration.append(arena, "an edited import table and a broken signature agree -> calls were redirected after linking.");
    }

    // ---------------------------------------------------------------- not flagged ----
    if (!b.fired("pack.entropy")) {
        var max: f64 = 0;
        var max_name: []const u8 = "-";
        for (ent_report.segments) |r| if (r.entropy > max) {
            max = r.entropy;
            max_name = r.name;
        };
        try b.noteFmt("entropy (max {d:.2} {s})", .{ max, max_name });
    }
    if (imports.imports.len != 0) try b.noteFmt("imports present ({d})", .{imports.imports.len});
    if (syms.symbols.len != 0) try b.noteFmt("symbols present ({d})", .{syms.symbols.len});
    if (xa.available and xa.quarantine == null) try b.note("no quarantine xattr");
    if (flags & 0x200000 != 0) try b.note("PIE");
    // "no RWX segment" is about initprot. Saying it on a report that ALSO flags hdr.rwx_maxprot
    // reads as a contradiction, so the corroboration is withheld once the latent form has fired —
    // the reader has already been told the segment can become rwx.
    if (!b.fired("hdr.rwx_segment") and !b.fired("hdr.rwx_maxprot")) try b.note("no RWX segment");

    // ---------------------------------------------------------------- scoring ----
    std.mem.sort(Finding, b.findings.items, {}, lessFinding);
    var total: u32 = 0;
    for (b.findings.items) |f| total +|= f.score;
    var credit: u32 = 0;
    for (b.positives.items) |p| credit +|= p.credit;
    const score: u32 = total -| credit;

    const cats = try categoriesOf(arena, b.findings.items);
    const level = levelFor(score, cats.len);

    var enc: bool = false;
    for (img.cmds) |c| if (c.lc() == .ENCRYPTION_INFO or c.lc() == .ENCRYPTION_INFO_64) {
        if (loadcmds.decodeEncryptionInfo(c)) |e| {
            if (e.cryptid != 0) enc = true;
        }
    };
    var arch_buf: [32]u8 = undefined;
    const arch_name = try arena.dupe(u8, img.arch.displayName(&arch_buf));

    // Security.framework evaluates the whole FILE (kSecCSCheckAllArchitectures): on a fat file whose
    // other slice is unsigned it answers errSecCSUnsigned even for a slice that carries a signature.
    // Fall back to the embedded (offline) ladder in exactly that case, so the per-slice line is honest.
    const verdict_is_about_another_slice = sig != null and sec.trust == .unsigned;
    const trust_text = if (sec.available and !verdict_is_about_another_slice) trustDisplay(sec.trust) else offline.label();
    const summary: Summary = .{
        .signed = sig != null,
        .trust = trust_text,
        .notarized = if (sec.available) sec.requirement_results.notarized == 0 else null,
        .hardened_runtime = hardened,
        .quarantined = xa.quarantine != null,
        .packed_hint = b.firedCategory(.packing),
        .encrypted = enc,
        .imports = @intCast(imports.imports.len),
        .exports = @intCast(exports.exports.len),
        .symbols = @intCast(syms.symbols.len),
        .dylibs = @intCast(dylibs.len),
        .objc_classes = objc_classes,
        .arch = arch_name,
    };
    _ = opts.explain;
    return .{
        .score = score,
        .level = level,
        .findings = try b.findings.toOwnedSlice(arena),
        .positives = try b.positives.toOwnedSlice(arena),
        .categories_hit = cats,
        .corroboration = try b.corroboration.toOwnedSlice(arena),
        .not_flagged = try b.not_flagged.toOwnedSlice(arena),
        .summary = summary,
        .per_arch = true,
        .exit_code = exitCodeFor(level, opts.fail_on),
    };
}

/// Distinct categories of the findings that actually SCORE. An informational, weight-0 finding
/// (`quarantine.present`, `sym.stripped`, `sig.not_evaluated`) is reported but must never help a file
/// across the ">= 2 categories" gate: "we noticed something" is not corroborating evidence.
fn categoriesOf(arena: Allocator, findings: []const Finding) Allocator.Error![]const Category {
    var cats: std.ArrayList(Category) = .empty;
    for (findings) |f| {
        if (f.score == 0) continue;
        var seen = false;
        for (cats.items) |c| if (c == f.rule.category) {
            seen = true;
        };
        if (!seen) try cats.append(arena, f.rule.category);
    }
    return cats.toOwnedSlice(arena);
}

/// The exit code a report produces: 20 once `--fail-on` is reached, 0 otherwise.
pub fn exitCodeFor(level: Level, fail_on: ?Level) u8 {
    const want = fail_on orelse return 0;
    return if (@intFromEnum(level) >= @intFromEnum(want)) 20 else 0;
}

/// The parenthetical of the corroboration sentence: the packer marker when there is one, else the segment.
fn packMarker(b: *const Builder) []const u8 {
    if (b.detailOf("pack.names")) |d| {
        if (std.mem.find(u8, d, "named ")) |i| {
            const rest = d[i + 6 ..];
            const end = std.mem.findScalar(u8, rest, ' ') orelse rest.len;
            return rest[0..end];
        }
        return d;
    }
    if (b.detailOf("pack.entropy")) |d| {
        if (std.mem.find(u8, d, "segment ")) |i| {
            const rest = d[i + 8 ..];
            const end = std.mem.findScalar(u8, rest, ' ') orelse rest.len;
            return rest[0..end];
        }
        return d;
    }
    return "packed";
}

/// Error-severity diagnostics that say the MACH-O FILE is malformed, and only those: the score must
/// not depend on which other commands happened to run first (`machre triage X` and the `triage`
/// section of `machre report X` have to agree). `hash_mismatch` is excluded because `sig.invalid`
/// already scores it — double counting would push fake-upx past its documented 60 — and
/// `os_error`/`not_available`/`not_implemented` describe this machine or this build, never the input.
fn structuralDiag(d: @import("../core/diag.zig").Diag) bool {
    if (d.severity != .@"error") return false;
    switch (d.module) {
        .file, .fat, .header, .loadcmds, .segments, .symbols, .chained, .exports, .legacy, .function_starts, .fixups, .imports, .codesign, .requirements, .objc => {},
        else => return false,
    }
    return switch (d.code) {
        .hash_mismatch, .os_error, .not_available, .not_implemented, .heuristic, .backend_disagree => false,
        else => true,
    };
}

/// First line of a possibly multi-line message, cut at 120 bytes (details are single-line).
fn firstLine(s: []const u8) []const u8 {
    const nl = std.mem.findScalar(u8, s, '\n') orelse s.len;
    return s[0..@min(nl, 120)];
}

/// Merge per-arch reports of a fat file into one (max level, union of findings).
pub fn merge(arena: Allocator, reports: []const Report) Allocator.Error!Report {
    if (reports.len == 1) {
        var one = reports[0];
        one.per_arch = false;
        return one;
    }
    var findings: std.ArrayList(Finding) = .empty;
    var positives: std.ArrayList(Positive) = .empty;
    var corro: std.ArrayList([]const u8) = .empty;
    var notf: std.ArrayList([]const u8) = .empty;
    var cats: std.ArrayList(Category) = .empty;
    var summary: Summary = .{ .signed = false, .trust = "unknown", .notarized = null, .hardened_runtime = false, .quarantined = false, .packed_hint = false, .encrypted = false, .imports = 0, .exports = 0, .symbols = 0, .dylibs = 0, .objc_classes = 0, .arch = "" };
    var arch_names: std.ArrayList([]const u8) = .empty;
    var exit_code: u8 = 0;
    for (reports, 0..) |r, i| {
        for (r.findings) |f| {
            var seen = false;
            for (findings.items) |*g| if (g.rule == f.rule) {
                seen = true;
                if (f.score > g.score) g.score = f.score;
            };
            if (!seen) try findings.append(arena, f);
        }
        for (r.positives) |p| {
            var seen = false;
            for (positives.items) |q| if (std.mem.eql(u8, q.id, p.id)) {
                seen = true;
            };
            if (!seen) try positives.append(arena, p);
        }
        for (r.corroboration) |s| {
            var seen = false;
            for (corro.items) |t| if (std.mem.eql(u8, t, s)) {
                seen = true;
            };
            if (!seen) try corro.append(arena, s);
        }
        if (i == 0) {
            for (r.not_flagged) |s| try notf.append(arena, s);
            summary = r.summary;
        } else {
            // "Not flagged" survives only when every slice agrees.
            var keep: std.ArrayList([]const u8) = .empty;
            for (notf.items) |s| {
                for (r.not_flagged) |t| if (std.mem.eql(u8, t, s)) {
                    try keep.append(arena, s);
                    break;
                };
            }
            notf = keep;
            summary.signed = summary.signed and r.summary.signed;
            summary.hardened_runtime = summary.hardened_runtime and r.summary.hardened_runtime;
            summary.quarantined = summary.quarantined or r.summary.quarantined;
            summary.packed_hint = summary.packed_hint or r.summary.packed_hint;
            summary.encrypted = summary.encrypted or r.summary.encrypted;
            summary.imports = @max(summary.imports, r.summary.imports);
            summary.exports = @max(summary.exports, r.summary.exports);
            summary.symbols = @max(summary.symbols, r.summary.symbols);
            summary.dylibs = @max(summary.dylibs, r.summary.dylibs);
            summary.objc_classes = @max(summary.objc_classes, r.summary.objc_classes);
            if (r.summary.notarized) |n| summary.notarized = (summary.notarized orelse true) and n;
        }
        try arch_names.append(arena, r.summary.arch);
        exit_code = @max(exit_code, r.exit_code);
    }
    std.mem.sort(Finding, findings.items, {}, lessFinding);
    var total: u32 = 0;
    for (findings.items) |f| total +|= f.score;
    var credit: u32 = 0;
    for (positives.items) |p| credit +|= p.credit;
    const score = total -| credit;
    cats = .empty;
    for (try categoriesOf(arena, findings.items)) |c| try cats.append(arena, c);
    var level = levelFor(score, cats.items.len);
    for (reports) |r| if (@intFromEnum(r.level) > @intFromEnum(level)) {
        level = r.level;
    };
    summary.arch = try std.mem.join(arena, "+", arch_names.items);
    return .{
        .score = score,
        .level = level,
        .findings = findings.items,
        .positives = positives.items,
        .categories_hit = cats.items,
        .corroboration = corro.items,
        .not_flagged = notf.items,
        .summary = summary,
        .per_arch = false,
        .exit_code = exit_code,
    };
}

// ---------------------------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------------------------

/// Column of `width` characters, always followed by at least one space so a cell that fills the
/// column ("Entitlements", "quarantine.present") still separates from the next one.
fn pad(out: *Io.Writer, s: []const u8, width: usize) Io.Writer.Error!void {
    try out.writeAll(s);
    try out.splatByteAll(' ', @max(width -| s.len, 1));
}

pub fn writeText(r: *const Report, path: []const u8, sink: *Sink) Io.Writer.Error!void {
    const out = sink.out;
    try out.print("machre triage: {s} [{s}]\n", .{ path, r.summary.arch });
    var buf: [160]u8 = undefined;
    const head = std.fmt.bufPrint(&buf, "LEVEL: {s} (score {d}, {d} categor{s})", .{
        levelDisplay(r.level),
        r.score,
        r.categories_hit.len,
        if (r.categories_hit.len == 1) "y" else "ies",
    }) catch "LEVEL:";
    try pad(out, head, 54);
    try out.print("trust: {s}\n", .{r.summary.trust});
    for (r.findings) |f| {
        try pad(out, categoryDisplay(f.rule.category), 12);
        try pad(out, severityDisplay(f.rule.severity), 9);
        try pad(out, f.rule.id, 18);
        try out.writeAll(f.detail);
        try out.writeByte('\n');
        if (sink.opts.verbose > 0) {
            try out.print("                                       why: {s}\n", .{f.rule.doc});
        }
        for (f.evidence) |e| try out.print("                                       {s}\n", .{e});
    }
    if (r.positives.len != 0) {
        try out.writeAll("Positives:");
        for (r.positives, 0..) |p, i| try out.print("{s} {s} (-{d})", .{ if (i == 0) "" else ",", p.text, p.credit });
        try out.writeAll(".\n");
    }
    for (r.corroboration) |c| try out.print("Corroboration: {s}\n", .{c});
    if (r.not_flagged.len != 0) {
        try out.writeAll("Not flagged: ");
        for (r.not_flagged, 0..) |n, i| {
            if (i != 0) try out.writeAll(", ");
            try out.writeAll(n);
        }
        try out.writeAll(".\n");
    }
}

// ---------------------------------------------------------------------------------------------
// json
// ---------------------------------------------------------------------------------------------

/// `Stringify.Error` only: every string in a Report was sanitised when it was built (Builder.clean),
/// so nothing here needs an allocator and no invalid UTF-8 can reach `std.json.Stringify`.
const Stringify = std.json.Stringify;
fn jfield(js: *Stringify, key: []const u8, v: anytype) Stringify.Error!void {
    try js.objectField(key);
    try js.write(v);
}

pub fn writeJson(r: *const Report, sink: *Sink) Stringify.Error!void {
    const js = &sink.json;
    try js.beginObject();
    try jfield(js, "score", r.score);
    try jfield(js, "level", levelName(r.level));
    try js.objectField("categories_hit");
    try js.beginArray();
    for (r.categories_hit) |c| try js.write(categoryName(c));
    try js.endArray();
    try js.objectField("findings");
    try js.beginArray();
    for (r.findings) |f| {
        try js.beginObject();
        try jfield(js, "id", f.rule.id);
        try jfield(js, "category", categoryName(f.rule.category));
        try jfield(js, "severity", @tagName(f.rule.severity));
        try jfield(js, "weight", f.rule.weight);
        try jfield(js, "score", f.score);
        try jfield(js, "title", f.title);
        try jfield(js, "detail", f.detail);
        try js.objectField("evidence");
        try js.beginArray();
        for (f.evidence) |e| try js.write(e);
        try js.endArray();
        try js.objectField("corroborates");
        if (f.corroborates) |c| try js.write(c) else try js.write(null);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("positives");
    try js.beginArray();
    for (r.positives) |p| {
        try js.beginObject();
        try jfield(js, "id", p.id);
        try jfield(js, "text", p.text);
        try jfield(js, "credit", p.credit);
        try js.endObject();
    }
    try js.endArray();
    try js.objectField("corroboration");
    try js.beginArray();
    for (r.corroboration) |c| try js.write(c);
    try js.endArray();
    try js.objectField("not_flagged");
    try js.beginArray();
    for (r.not_flagged) |n| try js.write(n);
    try js.endArray();
    try js.objectField("summary");
    try js.beginObject();
    try jfield(js, "signed", r.summary.signed);
    try jfield(js, "trust", r.summary.trust);
    try js.objectField("notarized");
    if (r.summary.notarized) |n| try js.write(n) else try js.write(null);
    try jfield(js, "hardened_runtime", r.summary.hardened_runtime);
    try jfield(js, "quarantined", r.summary.quarantined);
    try jfield(js, "packed_hint", r.summary.packed_hint);
    try jfield(js, "encrypted", r.summary.encrypted);
    try jfield(js, "imports", r.summary.imports);
    try jfield(js, "exports", r.summary.exports);
    try jfield(js, "symbols", r.summary.symbols);
    try jfield(js, "dylibs", r.summary.dylibs);
    try jfield(js, "objc_classes", r.summary.objc_classes);
    try jfield(js, "arch", r.summary.arch);
    try js.endObject();
    try jfield(js, "exit_code", r.exit_code);
    try js.endObject();
}

// ---------------------------------------------------------------------------------------------
// tests

const testing = std.testing;

test "triage: no single tell is a verdict" {
    // A comptime assert already refuses a weight >= 50; this pins the consequence.
    var worst: u8 = 0;
    for (rules) |r| worst = @max(worst, r.weight);
    try testing.expect(worst < 50);
    try testing.expectEqual(Level.notable, levelFor(worst, 1));
    try testing.expectEqual(Level.notable, levelFor(49, 1));
    try testing.expectEqual(Level.clean, levelFor(19, 3));
    try testing.expectEqual(Level.notable, levelFor(20, 1));
    // the >= 2 categories gate
    try testing.expectEqual(Level.notable, levelFor(60, 1));
    try testing.expectEqual(Level.suspicious, levelFor(60, 2));
    try testing.expectEqual(Level.suspicious, levelFor(120, 1));
    try testing.expectEqual(Level.likely_malicious, levelFor(120, 2));
}

test "triage: rule table lookup and display spellings" {
    try testing.expect(byId("sig.unsigned") != null);
    try testing.expect(byId("nope.nope") == null);
    try testing.expectEqual(@as(u8, 25), byId("sig.unsigned").?.weight);
    try testing.expectEqual(@as(u8, 45), byId("sig.revoked").?.weight);
    try testing.expectEqual(@as(u8, 35), byId("sig.invalid").?.weight);
    try testing.expectEqual(@as(u8, 30), byId("hdr.rwx_segment").?.weight);
    try testing.expectEqualStrings("SUSPICIOUS", levelDisplay(.suspicious));
    try testing.expectEqualStrings("Dependencies", categoryDisplay(.dependencies));
    try testing.expectEqualStrings("[MEDIUM]", severityDisplay(.medium));
    try testing.expectEqualStrings("INVALID SIGNATURE", trustDisplay(.invalid));
    // every rule has a title and an explanation, and every category has a display name
    for (rules) |r| {
        try testing.expect(r.title.len > 0 and r.doc.len > 16);
        try testing.expect(categoryDisplay(r.category).len <= 12);
        try testing.expect(std.mem.findScalar(u8, r.id, '.') != null);
    }
    inline for (@typeInfo(Category).@"enum".field_names) |n| try testing.expect(categoryDisplay(@field(Category, n)).len > 0);
}

test "triage: exit code follows --fail-on" {
    try testing.expectEqual(@as(u8, 0), exitCodeFor(.notable, null));
    try testing.expectEqual(@as(u8, 20), exitCodeFor(.notable, .notable));
    try testing.expectEqual(@as(u8, 0), exitCodeFor(.notable, .suspicious));
    try testing.expectEqual(@as(u8, 20), exitCodeFor(.suspicious, .suspicious));
    try testing.expectEqual(@as(u8, 20), exitCodeFor(.likely_malicious, .suspicious));
}

/// Builds a report out of rule ids so the scoring/level/text paths are testable without a file.
fn syntheticReport(arena: Allocator, ids: []const []const u8, credits: u32) Allocator.Error!Report {
    var b: Builder = .{ .arena = arena };
    for (ids) |id| try b.add(id, "synthetic");
    if (credits != 0) try b.positive("platform", "Apple platform binary (anchor apple)", @intCast(credits));
    std.mem.sort(Finding, b.findings.items, {}, lessFinding);
    var total: u32 = 0;
    for (b.findings.items) |f| total +|= f.score;
    const score = total -| credits;
    const cats = try categoriesOf(arena, b.findings.items);
    return .{
        .score = score,
        .level = levelFor(score, cats.len),
        .findings = b.findings.items,
        .positives = b.positives.items,
        .categories_hit = cats,
        .corroboration = &.{},
        .not_flagged = &.{"PIE"},
        .summary = .{ .signed = true, .trust = "AD HOC", .notarized = false, .hardened_runtime = false, .quarantined = false, .packed_hint = false, .encrypted = false, .imports = 6, .exports = 5, .symbols = 12, .dylibs = 1, .objc_classes = 0, .arch = "arm64" },
        .per_arch = true,
        .exit_code = 0,
    };
}

test "triage: a single category never exceeds notable, two categories do" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // every signature rule at once is still one category
    const one = try syntheticReport(a, &.{ "sig.revoked", "sig.invalid", "sig.unsigned", "sig.devid_not_notarized", "sig.sha1_only" }, 0);
    try testing.expectEqual(@as(u32, 128), one.score);
    try testing.expectEqual(@as(usize, 1), one.categories_hit.len);
    try testing.expectEqual(Level.suspicious, one.level); // >= 100 with one category
    const two = try syntheticReport(a, &.{ "sig.invalid", "pack.names" }, 0);
    try testing.expectEqual(@as(u32, 60), two.score);
    try testing.expectEqual(Level.suspicious, two.level);
    const revoked_only = try syntheticReport(a, &.{"sig.revoked"}, 0);
    try testing.expectEqual(@as(u32, 45), revoked_only.score);
    try testing.expectEqual(Level.notable, revoked_only.level);
    // positives subtract and the score floors at 0
    const platform = try syntheticReport(a, &.{"sig.hardened_runtime_missing"}, 20);
    try testing.expectEqual(@as(u32, 0), platform.score);
    try testing.expectEqual(Level.clean, platform.level);
}

test "triage: text rows use the DESIGN §5.5 column layout" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var r = try syntheticReport(a, &.{ "sig.invalid", "pack.names", "sig.adhoc" }, 0);
    r.summary.trust = "INVALID SIGNATURE";
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var sink = Sink.init(.text, &w, .{}, a);
    try writeText(&r, "tests/corpus/fake-upx", &sink);
    var it = std.mem.splitScalar(u8, w.buffered(), '\n');
    try testing.expectEqualStrings("machre triage: tests/corpus/fake-upx [arm64]", it.next().?);
    try testing.expectEqualStrings("LEVEL: SUSPICIOUS (score 70, 2 categories)            trust: INVALID SIGNATURE", it.next().?);
    try testing.expectEqualStrings("Signing     [HIGH]   sig.invalid       synthetic", it.next().?);
    try testing.expectEqualStrings("Packing     [MEDIUM] pack.names        synthetic", it.next().?);
    try testing.expectEqualStrings("Signing     [LOW]    sig.adhoc         synthetic", it.next().?);
    try testing.expectEqualStrings("Not flagged: PIE.", it.next().?);
}

test "triage: json payload carries every §6.3 key" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const r = try syntheticReport(a, &.{ "sig.adhoc", "quarantine.present" }, 0);
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sink = Sink.init(.json, &out.writer, .{ .pretty_json = false }, a);
    try writeJson(&r, &sink);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    for ([_][]const u8{ "score", "level", "categories_hit", "findings", "positives", "corroboration", "not_flagged", "summary", "exit_code" }) |k| {
        try testing.expect(o.get(k) != null);
    }
    try testing.expectEqualStrings("clean", o.get("level").?.string);
    const f0 = o.get("findings").?.array.items[0].object;
    for ([_][]const u8{ "id", "category", "severity", "weight", "score", "title", "detail", "evidence", "corroborates" }) |k| {
        try testing.expect(f0.get(k) != null);
    }
    const s = o.get("summary").?.object;
    for ([_][]const u8{ "signed", "trust", "notarized", "hardened_runtime", "quarantined", "packed_hint", "encrypted", "imports", "exports", "symbols", "dylibs", "objc_classes", "arch" }) |k| {
        try testing.expect(s.get(k) != null);
    }
}

test "triage: merge takes the union of findings and the worst level" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var x = try syntheticReport(a, &.{"sig.unsigned"}, 0);
    x.summary.arch = "x86_64";
    x.not_flagged = &.{ "PIE", "no RWX segment" };
    var y = try syntheticReport(a, &.{ "sig.adhoc", "pack.names" }, 0);
    y.summary.arch = "arm64";
    y.not_flagged = &.{"PIE"};
    const m = try merge(a, &.{ x, y });
    try testing.expectEqual(@as(u32, 60), m.score); // 25 + 10 + 25
    try testing.expectEqual(@as(usize, 3), m.findings.len);
    try testing.expectEqual(@as(usize, 2), m.categories_hit.len);
    try testing.expectEqual(Level.suspicious, m.level);
    try testing.expectEqualStrings("x86_64+arm64", m.summary.arch);
    try testing.expectEqual(@as(usize, 1), m.not_flagged.len); // only facts both slices agree on
    try testing.expect(!m.per_arch);
    const single = try merge(a, &.{y});
    try testing.expectEqual(@as(u32, 35), single.score);
    try testing.expect(!single.per_arch);
}

test "triage: packMarker names the packer segment" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b: Builder = .{ .arena = arena_state.allocator() };
    try b.add("pack.names", "segment named UPX_DATA (UPX marker) at LC index 2");
    try testing.expectEqualStrings("UPX_DATA", packMarker(&b));
    var c: Builder = .{ .arena = arena_state.allocator() };
    try c.add("pack.entropy", "segment __RANDOM entropy 7.997 bits/byte over 65.8% of the slice (65536 bytes)");
    try testing.expectEqualStrings("__RANDOM", packMarker(&c));
    var d: Builder = .{ .arena = arena_state.allocator() };
    try testing.expectEqualStrings("packed", packMarker(&d));
}

test "triage: suspicious selector table ignores the ordinary NSObject protocol" {
    const ordinary = [_][]const u8{ "init", "bark", "performSelector:withObject:", "isKindOfClass:", "描述", "hash", "zone", "class", "copy" };
    for (ordinary) |s| try testing.expect(selectorIsSuspicious(s) == null);
    try testing.expect(selectorIsSuspicious("SecKeychainFindGenericPassword") != null);
    try testing.expect(selectorIsSuspicious("installLaunchAgent:") != null);
    try testing.expect(selectorIsSuspicious("runAppleScript:") != null);
    try testing.expect(systemPath("/usr/lib/libSystem.B.dylib"));
    try testing.expect(!systemPath("/Users/x/evil.dylib"));
}
