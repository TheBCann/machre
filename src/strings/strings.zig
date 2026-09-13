//! strings/strings.zig — sectioned string extraction + classification.
//! Imports: core/image, core/reader, core/limits, core/sanitize, core/macho_extra, macho/fixups.
const std = @import("std");
const Allocator = std.mem.Allocator;
const image_mod = @import("../core/image.zig");
const Image = image_mod.Image;
const Section = image_mod.Section;
const Reader = @import("../core/reader.zig").Reader;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");
const extra = @import("../core/macho_extra.zig");
const FixupTable = @import("../macho/fixups.zig").FixupTable;

pub const Kind = enum { cstring, ustring, cfstring, objc_methname, objc_classname, objc_methtype, info_plist, generic_ascii, generic_utf16 };
/// Analyst classification (triage `str.*` rules and `strings --class`).
pub const Class = enum { plain, url, ip, path, shell, launch_agent, keychain, base64, format, user_agent, crypto_wallet, anti_analysis, persistence, script };
pub const Str = struct {
    addr: u64,
    file_offset: u64,
    kind: Kind,
    class: Class,
    section: ?u16,
    /// The string's own bytes, cut at `max_string_len`. Decoded UTF-8 for `ustring`/UTF-16 `cfstring`,
    /// raw file bytes otherwise: renderers sanitize (`--bare` writes them verbatim so the output
    /// diffs empty against `strings(1)`, whose alphabet includes bytes no JSON string may carry).
    text: []const u8,
    raw_len: u32,
    cut: bool,
    lossy: bool,
};
pub const StringsResult = struct {
    strings: []const Str,
    truncated: bool,
    lossy_count: u32,
    pub const empty: StringsResult = .{ .strings = &.{}, .truncated = false, .lossy_count = 0 };
};
pub const Options = struct {
    min_len: u32 = 4,
    kinds: std.EnumSet(Kind) = .full,
    generic_scan: bool = true,
    dedupe: bool = false,
    classify: bool = true,
};

/// The byte alphabet cctools `strings(1)` treats as printable: ASCII 0x20..0x7e plus form feed.
/// Verified by probing /usr/bin/strings with every byte value (96 accepted).
pub fn isPrintable(b: u8) bool {
    return (b >= 0x20 and b < 0x7f) or b == 0x0c;
}

/// Kind implied by a section's class; null = "no typed kind" (candidate for the generic scan).
fn kindForSection(s: *const Section) ?Kind {
    return switch (s.class) {
        .cstring => .cstring,
        .ustring => .ustring,
        .cfstring => .cfstring,
        .objc_methname => .objc_methname,
        .objc_classname => .objc_classname,
        .objc_methtype => .objc_methtype,
        .info_plist => .info_plist,
        else => null,
    };
}

const Ctx = struct {
    arena: Allocator,
    img: *const Image,
    fix: *const FixupTable,
    opts: Options,
    limits: *const Limits,
    diags: *Diagnostics,
    out: std.ArrayList(Str) = .empty,
    seen: std.StringHashMapUnmanaged(void) = .empty,
    truncated: bool = false,
    lossy_count: u32 = 0,

    fn minLen(c: *const Ctx) usize {
        return @max(@as(usize, c.opts.min_len), 1);
    }
    fn full(c: *const Ctx) bool {
        return c.out.items.len >= c.limits.max_strings;
    }
    fn want(c: *const Ctx, k: Kind) bool {
        return c.opts.kinds.contains(k);
    }
    /// Appends one string; applies `max_string_len`, dedupe and classification.
    fn push(c: *Ctx, kind: Kind, addr: u64, file_offset: u64, section: ?u16, bytes: []const u8, raw_len: u64) Allocator.Error!void {
        if (c.full()) {
            c.truncated = true;
            return;
        }
        const cut = bytes.len > c.limits.max_string_len;
        const text = if (cut) bytes[0..c.limits.max_string_len] else bytes;
        if (c.opts.dedupe) {
            const g = try c.seen.getOrPut(c.arena, text);
            if (g.found_existing) return;
        }
        const lossy = !sanitize.isClean(text, .json);
        if (lossy) c.lossy_count += 1;
        try c.out.append(c.arena, .{
            .addr = addr,
            .file_offset = file_offset,
            .kind = kind,
            .class = if (c.opts.classify) classify(text) else .plain,
            .section = section,
            .text = text,
            .raw_len = @intCast(@min(raw_len, std.math.maxInt(u32))),
            .cut = cut,
            .lossy = lossy,
        });
    }
};

/// Extracts strings from every mapped, non-zerofill section of `img`, in load-command order and
/// then by offset — the same walk `strings(1)` performs, so `--bare` output is directly comparable.
/// Typed sections (`__cstring`, `__ustring`, `__cfstring`, `__objc_*`, `__info_plist`) are decoded
/// according to their format; every other section contributes generic printable runs when
/// `opts.generic_scan` (code sections are skipped, exactly like `strings(1)`).
pub fn extract(arena: Allocator, img: *const Image, fix: *const FixupTable, opts: Options, limits: *const Limits, diags: *Diagnostics) Allocator.Error!StringsResult {
    var c: Ctx = .{ .arena = arena, .img = img, .fix = fix, .opts = opts, .limits = limits, .diags = diags };
    for (img.sections) |*s| {
        if (c.full()) break;
        if (s.isZerofill() or s.size == 0) continue;
        const r = img.sectionReader(s) orelse continue;
        if (r.len() == 0) continue;
        const kind = kindForSection(s);
        if (kind) |k| {
            if (!c.want(k)) continue;
            switch (k) {
                .cstring, .objc_methname, .objc_classname, .objc_methtype => try cstringSection(&c, s, r, k),
                .ustring => try ustringSection(&c, s, r),
                .cfstring => try cfstringSection(&c, s, r),
                .info_plist => try infoPlistSection(&c, s, r),
                else => unreachable,
            }
            continue;
        }
        if (!opts.generic_scan or s.isCode()) continue;
        if (c.want(.generic_ascii)) try asciiRuns(&c, s.addr, s.offset, s.index, r.bytes, .generic_ascii);
        if (c.want(.generic_utf16)) try utf16Runs(&c, s.addr, s.offset, s.index, r.bytes);
    }
    if (c.truncated) c.diags.info(.strings, .limit_reached, null, "string list cut at {d} entries", .{limits.max_strings});
    return .{ .strings = try c.out.toOwnedSlice(arena), .truncated = c.truncated, .lossy_count = c.lossy_count };
}

/// NUL-separated C strings (`S_CSTRING_LITERALS` and the ObjC name/type sections).
fn cstringSection(c: *Ctx, s: *const Section, r: Reader, kind: Kind) Allocator.Error!void {
    const len: u64 = r.len();
    var i: u64 = 0;
    while (i < len) {
        if (c.full()) {
            c.truncated = true;
            return;
        }
        const e = r.cstrAt(i, len - i) orelse return;
        if (e.bytes.len >= c.minLen()) try c.push(kind, s.addr +| i, s.offset +| i, s.index, e.bytes, e.bytes.len);
        if (!e.terminated) return; // the last entry runs to the end of the section
        i += @as(u64, e.bytes.len) + 1;
    }
}

/// `__TEXT,__ustring`: NUL-terminated UTF-16LE runs.
fn ustringSection(c: *Ctx, s: *const Section, r: Reader) Allocator.Error!void {
    var i: u64 = 0;
    while (i + 2 <= r.len()) {
        if (c.full()) {
            c.truncated = true;
            return;
        }
        var n: u64 = 0;
        while (true) {
            const unit = r.u16At(i + 2 * n, .little) orelse break;
            if (unit == 0) break;
            n += 1;
        }
        if (n >= c.minLen()) {
            if (r.sliceAt(i, 2 * n)) |raw| {
                if (try decodeUtf16(c, raw)) |t| try c.push(.ustring, s.addr +| i, s.offset +| i, s.index, t, 2 * n);
            }
        }
        i += 2 * n + 2;
    }
}

/// `__DATA_CONST,__cfstring`: 32-byte `__CFConstantString` records (format-notes 12.1).
fn cfstringSection(c: *Ctx, s: *const Section, r: Reader) Allocator.Error!void {
    const stride: u64 = extra.objc.cfstring_size;
    var i: u64 = 0;
    while (i + stride <= r.len()) : (i += stride) {
        if (c.full()) {
            c.truncated = true;
            return;
        }
        const entry_vm = s.addr +| i;
        const flags = c.img.u64AtVm(entry_vm +| 8) orelse continue;
        const data = slotPointer(c, entry_vm +| 16) orelse continue;
        const length = c.img.u64AtVm(entry_vm +| 24) orelse continue;
        if (length > c.limits.max_string_len) {
            if (!c.diags.has(.strings, .limit_reached)) c.diags.info(.strings, .limit_reached, s.offset +| i, "__cfstring entry length {d} exceeds max_string_len", .{length});
            continue;
        }
        if (flags == extra.objc.cfstring_flags_utf16) {
            const vb = c.img.bytesAtVm(data, length *| 2) orelse continue;
            if (try decodeUtf16(c, vb.bytes)) |text| {
                if (text.len >= c.minLen()) try c.push(.cfstring, entry_vm, s.offset +| i, s.index, text, vb.bytes.len);
            }
            continue;
        }
        if (flags != extra.objc.cfstring_flags_utf8 and !c.diags.has(.strings, .unknown_value)) {
            c.diags.info(.strings, .unknown_value, s.offset +| i, "__cfstring flags 0x{x} not 0x7c8/0x7d0; decoded as 8-bit", .{flags});
        }
        const vb = c.img.bytesAtVm(data, length) orelse continue;
        if (vb.bytes.len >= c.minLen()) try c.push(.cfstring, entry_vm, s.offset +| i, s.index, vb.bytes, vb.bytes.len);
    }
}

/// `__TEXT,__info_plist` is one document, not a list; trailing NUL padding is trimmed.
fn infoPlistSection(c: *Ctx, s: *const Section, r: Reader) Allocator.Error!void {
    const body = std.mem.trimEnd(u8, r.sliceAt(0, r.len()).?, "\x00");
    if (body.len >= c.minLen()) try c.push(.info_plist, s.addr, s.offset, s.index, body, body.len);
}

/// Maximal runs of `strings(1)`-printable bytes.
fn asciiRuns(c: *Ctx, addr: u64, offset: u64, section: u16, bytes: []const u8, kind: Kind) Allocator.Error!void {
    var i: usize = 0;
    while (i < bytes.len) {
        if (!isPrintable(bytes[i])) {
            i += 1;
            continue;
        }
        var n: usize = 0;
        while (i + n < bytes.len and isPrintable(bytes[i + n])) : (n += 1) {}
        if (n >= c.minLen()) {
            if (c.full()) {
                c.truncated = true;
                return;
            }
            try c.push(kind, addr +| i, offset +| i, section, bytes[i..][0..n], n);
        }
        i += n;
    }
}

/// UTF-16LE runs of printable BMP characters (what `strings(1)` misses entirely).
fn utf16Runs(c: *Ctx, addr: u64, offset: u64, section: u16, bytes: []const u8) Allocator.Error!void {
    var i: usize = 0;
    while (i + 1 < bytes.len) {
        if (bytes[i + 1] != 0 or !isPrintable(bytes[i])) {
            i += 1;
            continue;
        }
        var n: usize = 0;
        while (i + 2 * n + 1 < bytes.len and bytes[i + 2 * n + 1] == 0 and isPrintable(bytes[i + 2 * n])) : (n += 1) {}
        if (n >= c.minLen()) {
            if (c.full()) {
                c.truncated = true;
                return;
            }
            if (try decodeUtf16(c, bytes[i..][0 .. 2 * n])) |text| {
                try c.push(.generic_utf16, addr +| i, offset +| i, section, text, 2 * n);
            }
        }
        i += @max(2 * n, 1);
    }
}

/// UTF-16LE bytes -> arena UTF-8; null (with one diagnostic) when the units are not valid UTF-16.
fn decodeUtf16(c: *Ctx, bytes: []const u8) Allocator.Error!?[]const u8 {
    const units_len = bytes.len / 2;
    if (units_len == 0) return null;
    if (units_len > c.limits.max_string_len) return null;
    const units = try c.arena.alloc(u16, units_len);
    for (units, 0..) |*u, i| u.* = std.mem.readInt(u16, bytes[2 * i ..][0..2], .little);
    return std.unicode.utf16LeToUtf8Alloc(c.arena, units) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => {
            if (!c.diags.has(.strings, .invalid_utf8)) c.diags.info(.strings, .invalid_utf8, null, "UTF-16 run is not valid UTF-16", .{});
            return null;
        },
    };
}

/// Pointer-sized slot read through the fixup table (the only component that knows pointer formats).
/// A slot with no fixup entry falls back to the raw word with PAC/high bits stripped, which is what
/// legacy (`LC_DYLD_INFO`) images store; `null` when the slot is unmapped or bound to an import.
fn slotPointer(c: *Ctx, vmaddr: u64) ?u64 {
    if (c.fix.resolveSlot(c.img, vmaddr)) |slot| return switch (slot) {
        .bind => null,
        .rebase => |t| t & extra.objc.PTR_MASK,
        .raw => |v| v & extra.objc.PTR_MASK,
    };
    const raw = c.img.u64AtVm(vmaddr) orelse return null;
    if (raw == 0) return null;
    if (c.fix.source == .none and c.img.dyldStyle() == .chained) {
        // The fixup table has not been built yet (macho/fixups still a stub). Decode the
        // DYLD_CHAINED_PTR_64(_OFFSET) rebase field directly so __cfstring stays readable;
        // dead code as soon as FixupTable.source is .chained.
        if (c.img.arch.is_arm64e) return null; // authenticated formats need the real decoder
        if (raw >> 63 != 0) return null; // bind entry: the target is an import, not an address
        const target = raw & 0xf_ffff_ffff;
        if (target == 0) return null;
        return if (target < c.img.image_base) c.img.image_base +% target else target;
    }
    return raw & extra.objc.PTR_MASK;
}

/// For non-Mach-O files (generic printable runs only).
pub fn extractRaw(arena: Allocator, bytes: []const u8, base_offset: u64, opts: Options, limits: *const Limits) Allocator.Error!StringsResult {
    var dummy = Diagnostics.init(arena, 1);
    var c: Ctx = .{ .arena = arena, .img = undefined, .fix = undefined, .opts = opts, .limits = limits, .diags = &dummy };
    if (opts.kinds.contains(.generic_ascii)) try asciiRuns(&c, base_offset, base_offset, 0, bytes, .generic_ascii);
    if (opts.kinds.contains(.generic_utf16)) try utf16Runs(&c, base_offset, base_offset, 0, bytes);
    return .{ .strings = try c.out.toOwnedSlice(arena), .truncated = c.truncated, .lossy_count = c.lossy_count };
}

// ---------------------------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------------------------

fn containsAny(s: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.mem.indexOf(u8, s, n) != null) return true;
    return false;
}
fn startsAny(s: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.mem.startsWith(u8, s, n)) return true;
    return false;
}

/// True when `s` is exactly a dotted quad (each octet 0-255), optionally with a `:port` suffix.
fn isDottedQuad(s: []const u8) bool {
    const host = if (std.mem.findScalar(u8, s, ':')) |i| s[0..i] else s;
    var parts: usize = 0;
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |p| {
        parts += 1;
        if (parts > 4 or p.len == 0 or p.len > 3) return false;
        for (p) |ch| if (!std.ascii.isDigit(ch)) return false;
        const v = std.fmt.parseInt(u16, p, 10) catch return false;
        if (v > 255) return false;
    }
    return parts == 4;
}

fn isBase64Blob(s: []const u8) bool {
    if (s.len < 32) return false;
    var pad: usize = 0;
    for (s, 0..) |ch, i| {
        if (ch == '=') {
            pad += 1;
            if (i + pad < s.len) continue;
            continue;
        }
        if (pad != 0) return false; // padding may only trail
        if (!(std.ascii.isAlphanumeric(ch) or ch == '+' or ch == '/')) return false;
    }
    return pad != 0 and pad <= 2 and s.len % 4 == 0;
}

/// True for printf/NSLog-style format strings ("%s (%d args)", "%@ has %ld legs").
fn hasFormatSpecifier(s: []const u8) bool {
    var i: usize = 0;
    while (i + 1 < s.len) : (i += 1) {
        if (s[i] != '%') continue;
        var j = i + 1;
        if (j < s.len and s[j] == '%') {
            i = j;
            continue;
        }
        while (j < s.len and (std.ascii.isDigit(s[j]) or s[j] == '.' or s[j] == '-' or s[j] == '+' or s[j] == '#' or s[j] == ' ' or s[j] == 'l' or s[j] == 'h' or s[j] == 'z' or s[j] == 'q')) j += 1;
        if (j < s.len and containsAny(&.{s[j]}, &.{ "d", "i", "u", "x", "X", "o", "f", "g", "e", "s", "c", "p", "@" })) return true;
    }
    return false;
}

/// Analyst class of one string; the first matching rule wins (most specific first).
pub fn classify(text: []const u8) Class {
    const s = text;
    if (s.len == 0) return .plain;
    if (containsAny(s, &.{ "http://", "https://", "ftp://", "ftps://", "ws://", "wss://" })) return .url;
    if (isDottedQuad(s)) return .ip;
    if (containsAny(s, &.{ "LaunchAgents", "LaunchDaemons", "launchd.plist" })) return .launch_agent;
    if (containsAny(s, &.{ "launchctl", "crontab", "LoginItems", "StartupItems", "com.apple.loginitems" })) return .persistence;
    if (containsAny(s, &.{ "security find-", "SecKeychain", "login.keychain", "kSecClassGenericPassword" })) return .keychain;
    if (containsAny(s, &.{ "sysctl hw.model", "hw.model", "VMware", "VirtualBox", "Parallels", "ptrace", "P_TRACED", "isDebuggerActive", "PT_DENY_ATTACH" })) return .anti_analysis;
    if (containsAny(s, &.{ "xpub", "Electrum", "Exodus/exodus.wallet", "wallet.dat", "MetaMask" })) return .crypto_wallet;
    if (startsAny(s, &.{"#!/"}) or containsAny(s, &.{ "python -c", "ruby -e", "perl -e" })) return .script;
    if (containsAny(s, &.{ "/bin/sh", "/bin/bash", "/bin/zsh", "osascript", "curl ", "chmod +x", "nohup", "/usr/bin/env " })) return .shell;
    if (containsAny(s, &.{ "Mozilla/", "curl/", "User-Agent" })) return .user_agent;
    if (isBase64Blob(s)) return .base64;
    if (startsAny(s, &.{ "/", "~/", "./", "../", "@rpath/", "@executable_path/", "@loader_path/" })) return .path;
    if (hasFormatSpecifier(s)) return .format;
    return .plain;
}

// ---------------------------------------------------------------------------------------------
// tests — hermetic: Images are built as struct literals so this file's import set does not grow.
// ---------------------------------------------------------------------------------------------
const testing = std.testing;

test "strings: classifier" {
    try testing.expectEqual(Class.url, classify("https://evil.example/payload"));
    try testing.expectEqual(Class.ip, classify("192.168.1.14"));
    try testing.expectEqual(Class.ip, classify("10.0.0.1:4444"));
    try testing.expectEqual(Class.plain, classify("1.2.3"));
    try testing.expectEqual(Class.plain, classify("999.1.1.1"));
    try testing.expectEqual(Class.launch_agent, classify("/Library/LaunchAgents/com.evil.plist"));
    try testing.expectEqual(Class.persistence, classify("launchctl load -w"));
    try testing.expectEqual(Class.keychain, classify("security find-generic-password"));
    try testing.expectEqual(Class.anti_analysis, classify("sysctl hw.model"));
    try testing.expectEqual(Class.script, classify("#!/bin/sh"));
    try testing.expectEqual(Class.shell, classify("/bin/sh -c"));
    try testing.expectEqual(Class.shell, classify("osascript -e"));
    try testing.expectEqual(Class.user_agent, classify("Mozilla/5.0 (Macintosh)"));
    try testing.expectEqual(Class.base64, classify("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY="));
    try testing.expectEqual(Class.path, classify("/Users/bob/Library/Application Support"));
    try testing.expectEqual(Class.path, classify("@rpath/libhello.dylib"));
    try testing.expectEqual(Class.format, classify("%s (%d args)"));
    try testing.expectEqual(Class.format, classify("%@ has %ld legs"));
    try testing.expectEqual(Class.plain, classify("hello from machre corpus"));
    try testing.expectEqual(Class.plain, classify("100%"));
    try testing.expectEqual(Class.plain, classify(""));
}

test "strings: printable alphabet matches cctools strings(1)" {
    var n: usize = 0;
    for (0..256) |i| {
        if (isPrintable(@intCast(i))) n += 1;
    }
    try testing.expectEqual(@as(usize, 96), n); // 0x20..0x7e plus 0x0c
    try testing.expect(isPrintable(0x0c) and !isPrintable('\t') and !isPrintable('\n'));
}

const SectionClass = @FieldType(image_mod.Section, "class");
const SectSpec = struct { seg: []const u8, name: []const u8, class: SectionClass = .other, flags: u32 = 0, body: []const u8 };

fn synth(arena: Allocator, specs: []const SectSpec) !*Image {
    var total: u64 = 0x40;
    for (specs) |s| total += s.body.len;
    const bytes = try arena.alloc(u8, @intCast(total));
    @memset(bytes, 0);
    const sects = try arena.alloc(image_mod.Section, specs.len);
    var off: u64 = 0x40;
    const base: u64 = 0x100000000;
    for (specs, 0..) |s, i| {
        @memcpy(bytes[@intCast(off)..][0..s.body.len], s.body);
        sects[i] = .{
            .index = @intCast(i + 1),
            .segment = 0,
            .sectname = s.name,
            .segname = s.seg,
            .addr = base + off,
            .size = s.body.len,
            .offset = @intCast(off),
            .@"align" = 0,
            .reloff = 0,
            .nreloc = 0,
            .flags = s.flags,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
            .class = s.class,
        };
        off += s.body.len;
    }
    const segs = try arena.alloc(image_mod.Segment, 1);
    segs[0] = .{
        .index = 0,
        .name = "__TEXT",
        .vmaddr = base,
        .vmsize = total,
        .fileoff = 0,
        .filesize = total,
        .maxprot = 5,
        .initprot = 5,
        .nsects = @intCast(specs.len),
        .flags = 0,
        .cmd_offset = 0,
        .first_section = 0,
        .section_count = @intCast(specs.len),
        .file_range_truncated = false,
    };
    const img = try arena.create(Image);
    img.* = .{
        .r = .{ .bytes = bytes, .base = 0 },
        .slice_offset = 0,
        .index = 0,
        .arch = .{ .cputype = 0x0100000c, .cpusubtype = 0, .name = .arm64, .ptr_size = 8, .is_64 = true, .is_arm64e = false, .ptrauth_version = 0, .caps = 0 },
        .hdr = .{ .magic = std.macho.MH_MAGIC_64, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = std.macho.MH_EXECUTE, .ncmds = 0, .sizeofcmds = 0, .flags = 0, .header_size = 32 },
        .cmds = &.{},
        .segments = segs,
        .sections = sects,
        .image_base = base,
        .text_seg = 0,
        .linkedit_seg = null,
        .cmds_truncated = false,
        .ncmds_parsed = 0,
    };
    return img;
}

fn extractSynth(arena: Allocator, specs: []const SectSpec, opts: Options) !StringsResult {
    const img = try synth(arena, specs);
    var diags = Diagnostics.init(arena, 32);
    return extract(arena, img, &FixupTable.empty, opts, &Limits.default, &diags);
}

test "strings: cstring, objc name sections and generic runs in section order" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const res = try extractSynth(arena, &.{
        .{ .seg = "__TEXT", .name = "__text", .class = .text, .flags = std.macho.S_ATTR_PURE_INSTRUCTIONS, .body = "ignore-me-code" },
        .{ .seg = "__TEXT", .name = "__objc_methname", .class = .objc_methname, .body = "init\x00describe\x00" },
        .{ .seg = "__TEXT", .name = "__cstring", .class = .cstring, .body = "hello from machre corpus\x00%s (%d args)\x00exit\x00" },
        .{ .seg = "__DATA", .name = "__data", .class = .data, .body = "\x00\x00padded-run\x00\x00" },
    }, .{ .min_len = 4 });
    try testing.expectEqual(@as(usize, 6), res.strings.len);
    try testing.expectEqualStrings("init", res.strings[0].text);
    try testing.expectEqual(Kind.objc_methname, res.strings[0].kind);
    try testing.expectEqualStrings("describe", res.strings[1].text);
    try testing.expectEqualStrings("hello from machre corpus", res.strings[2].text);
    try testing.expectEqual(Kind.cstring, res.strings[2].kind);
    try testing.expectEqual(Class.format, res.strings[3].class);
    try testing.expectEqualStrings("exit", res.strings[4].text);
    try testing.expectEqualStrings("padded-run", res.strings[5].text);
    try testing.expectEqual(Kind.generic_ascii, res.strings[5].kind);
    // addresses and offsets point at the string, not the section
    try testing.expectEqual(res.strings[2].addr + 25, res.strings[3].addr);
    try testing.expect(res.strings[2].file_offset + 25 == res.strings[3].file_offset);
    try testing.expectEqual(@as(u32, 0), res.lossy_count);
}

test "strings: min_len, kinds filter, no-generic and dedupe" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const specs: []const SectSpec = &.{
        .{ .seg = "__TEXT", .name = "__cstring", .class = .cstring, .body = "abcdef\x00abc\x00abcdef\x00" },
        .{ .seg = "__DATA", .name = "__data", .class = .data, .body = "generic-one\x00" },
    };
    const all = try extractSynth(arena, specs, .{ .min_len = 4 });
    try testing.expectEqual(@as(usize, 3), all.strings.len);
    const min6 = try extractSynth(arena, specs, .{ .min_len = 7 });
    try testing.expectEqual(@as(usize, 1), min6.strings.len);
    const no_generic = try extractSynth(arena, specs, .{ .min_len = 4, .generic_scan = false });
    try testing.expectEqual(@as(usize, 2), no_generic.strings.len);
    const only_c = try extractSynth(arena, specs, .{ .min_len = 4, .kinds = .initOne(.cstring) });
    try testing.expectEqual(@as(usize, 2), only_c.strings.len);
    const deduped = try extractSynth(arena, specs, .{ .min_len = 4, .dedupe = true });
    try testing.expectEqual(@as(usize, 2), deduped.strings.len);
}

test "strings: __ustring decodes UTF-16LE (héllo)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const body = "h\x00\xe9\x00l\x00l\x00o\x00\x00\x00";
    const res = try extractSynth(arena, &.{.{ .seg = "__TEXT", .name = "__ustring", .class = .ustring, .body = body }}, .{ .min_len = 4 });
    try testing.expectEqual(@as(usize, 1), res.strings.len);
    try testing.expectEqualStrings("h\u{e9}llo", res.strings[0].text);
    try testing.expectEqual(Kind.ustring, res.strings[0].kind);
    try testing.expectEqual(@as(u32, 10), res.strings[0].raw_len);
    // strings(1) cannot see it: the generic ASCII scan of the same bytes yields nothing at min 4
    const as_generic = try extractSynth(arena, &.{.{ .seg = "__DATA", .name = "__data", .class = .data, .body = body }}, .{ .min_len = 4, .kinds = .initOne(.generic_ascii) });
    try testing.expectEqual(@as(usize, 0), as_generic.strings.len);
    const utf16_generic = try extractSynth(arena, &.{.{ .seg = "__DATA", .name = "__data", .class = .data, .body = "w\x00i\x00d\x00e\x00!\x00" }}, .{ .min_len = 4, .kinds = .initOne(.generic_utf16) });
    try testing.expectEqual(@as(usize, 1), utf16_generic.strings.len);
    try testing.expectEqualStrings("wide!", utf16_generic.strings[0].text);
}

test "strings: __cfstring entries resolve through the raw slot on legacy images" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // __cstring first so its address is known, then a 32-byte CFString record pointing at it.
    const text_body = "cf target\x00";
    const target_vm: u64 = 0x100000000 + 0x40;
    var rec: [32]u8 = @splat(0);
    std.mem.writeInt(u64, rec[8..16], 0x7c8, .little);
    std.mem.writeInt(u64, rec[16..24], target_vm, .little);
    std.mem.writeInt(u64, rec[24..32], 9, .little);
    const res = try extractSynth(arena, &.{
        .{ .seg = "__TEXT", .name = "__cstring", .class = .cstring, .body = text_body },
        .{ .seg = "__DATA_CONST", .name = "__cfstring", .class = .cfstring, .body = &rec },
    }, .{ .min_len = 4 });
    try testing.expectEqual(@as(usize, 2), res.strings.len);
    try testing.expectEqual(Kind.cfstring, res.strings[1].kind);
    try testing.expectEqualStrings("cf target", res.strings[1].text);
    try testing.expectEqual(target_vm + 10, res.strings[1].addr); // the record's own address
}

test "strings: lossy bytes are kept raw and flagged, long strings are cut" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var limits = Limits.default;
    limits.max_string_len = 8;
    const img = try synth(arena, &.{.{ .seg = "__TEXT", .name = "__cstring", .class = .cstring, .body = "bad\xffutf8\x00aaaaaaaaaaaaaaaa\x00" }});
    var diags = Diagnostics.init(arena, 32);
    const res = try extract(arena, img, &FixupTable.empty, .{ .min_len = 4 }, &limits, &diags);
    try testing.expectEqual(@as(usize, 2), res.strings.len);
    try testing.expectEqualStrings("bad\xffutf8", res.strings[0].text);
    try testing.expect(res.strings[0].lossy);
    try testing.expectEqual(@as(u32, 1), res.lossy_count);
    try testing.expect(res.strings[1].cut and res.strings[1].text.len == 8 and res.strings[1].raw_len == 16);
}

test "strings: extractRaw over arbitrary bytes" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const res = try extractRaw(a.allocator(), "\x00\x01hello world\x00\x02ab", 0x1000, .{ .min_len = 4 }, &Limits.default);
    try testing.expectEqual(@as(usize, 1), res.strings.len);
    try testing.expectEqualStrings("hello world", res.strings[0].text);
    try testing.expectEqual(@as(u64, 0x1002), res.strings[0].file_offset);
}

test "strings: max_strings clamps and records limit_reached" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var limits = Limits.default;
    limits.max_strings = 2;
    const img = try synth(arena, &.{.{ .seg = "__TEXT", .name = "__cstring", .class = .cstring, .body = "aaaa\x00bbbb\x00cccc\x00dddd\x00" }});
    var diags = Diagnostics.init(arena, 32);
    const res = try extract(arena, img, &FixupTable.empty, .{ .min_len = 4 }, &limits, &diags);
    try testing.expectEqual(@as(usize, 2), res.strings.len);
    try testing.expect(res.truncated);
    try testing.expect(diags.has(.strings, .limit_reached));
}

test "strings: every prefix of a section body extracts without error" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const body = "abcdef\x00\xff\xfe\x00h\x00i\x00\x00\x00zzzzzz";
    var n: usize = 0;
    while (n <= body.len) : (n += 1) {
        for ([_]SectionClass{ .cstring, .ustring, .cfstring, .info_plist, .data }) |cl| {
            const img = try synth(arena, &.{.{ .seg = "__TEXT", .name = "__x", .class = cl, .body = body[0..n] }});
            var diags = Diagnostics.init(arena, 8);
            const res = try extract(arena, img, &FixupTable.empty, .{ .min_len = 1 }, &Limits.paranoid, &diags);
            for (res.strings) |s| try testing.expect(s.text.len <= Limits.paranoid.max_string_len);
        }
    }
}
