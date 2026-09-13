//! disasm/symbolize.zig — stub resolution (A: indirect table, B: pointer slot), ADRP/ADD/LDR folding,
//! otool-style ';' annotations, xref table (incl. fixup-derived pointer_slot xrefs).
//! Imports: core/image, core/limits, core/diag, core/sanitize, macho/symbols, macho/fixups, objc/objc, strings/strings, disasm/insn, disasm/functions.
//!
//! Two independent stub algorithms run whenever both can (DESIGN §9, disasm-notes D.2): A reads the
//! indirect symbol table, B decodes the stub body down to its pointer slot and resolves that slot through
//! the fixup table. They agree on healthy binaries; when they disagree B wins and `Stub.mismatch` is set,
//! which is a cheap "edited indirect table" tell.
//!
//! The annotator owns otool's `;` vocabulary. Under `AnnotateCtx.otool_compat` it prints exactly what
//! `otool -tV` prints and nothing else: machre-only comments are dropped, a branch whose target carries a
//! symbol has the symbol as its OPERAND, and ObjC metadata is resolved the way otool resolves it (raw
//! pointer, no chained-fixup interpretation) so its `bad cfstring ref` / `bad class ref` placeholders are
//! reproduced instead of silently disagreeing. Outside that flag machre resolves the fixup properly and
//! prints the real string.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Image = @import("../core/image.zig").Image;
const Section = @import("../core/image.zig").Section;
const Limits = @import("../core/limits.zig").Limits;
const Diagnostics = @import("../core/diag.zig").Diagnostics;
const sanitize = @import("../core/sanitize.zig");
const symbols = @import("../macho/symbols.zig");
const fixups_mod = @import("../macho/fixups.zig");
const FixupTable = fixups_mod.FixupTable;
const ObjcInfo = @import("../objc/objc.zig").ObjcInfo;
const StringsResult = @import("../strings/strings.zig").StringsResult;
const x86len = @import("x86len.zig");
const insn = @import("insn.zig");
const functions_mod = @import("functions.zig");
const FunctionTable = functions_mod.FunctionTable;

// ---------------------------------------------------------------------------------------------
// minimal arm64 field decoding (symbolize may not import the arm64 decoder; §4 import table)
// ---------------------------------------------------------------------------------------------

const a64 = struct {
    fn rd(w: u32) u5 {
        return @truncate(w & 0x1f);
    }
    fn rn(w: u32) u5 {
        return @truncate((w >> 5) & 0x1f);
    }
    fn isAdrp(w: u32) bool {
        return w & 0x9f00_0000 == 0x9000_0000;
    }
    /// Resolved page address of an `adrp`.
    fn adrpPage(w: u32, pc: u64) u64 {
        const imm_hi: u64 = (w >> 5) & 0x7ffff;
        const imm_lo: u64 = (w >> 29) & 3;
        const imm21: u64 = (imm_hi << 2) | imm_lo;
        const signed: i64 = @as(i64, @bitCast(imm21 << 43)) >> 43;
        return (pc & ~@as(u64, 0xfff)) +% (@as(u64, @bitCast(signed)) *% 4096);
    }
    /// 64-bit `add Xd, Xn, #imm{, lsl #12}` (no flags).
    fn isAddImm(w: u32) bool {
        return w & 0xff80_0000 == 0x9100_0000;
    }
    fn addImm(w: u32) u64 {
        const imm12: u64 = (w >> 10) & 0xfff;
        return if ((w >> 22) & 1 != 0) imm12 << 12 else imm12;
    }
    /// 64-bit `ldr Xt, [Xn, #imm12*8]`.
    fn isLdr64(w: u32) bool {
        return w & 0xffc0_0000 == 0xf940_0000;
    }
    fn ldrOff(w: u32) u64 {
        return (@as(u64, (w >> 10) & 0xfff)) * 8;
    }
};

// ---------------------------------------------------------------------------------------------
// stubs
// ---------------------------------------------------------------------------------------------

pub const StubKind = enum { arm64_stubs, arm64e_auth_stubs, x86_64_stubs, objc_stubs, stub_helper, lazy_pointer, non_lazy_pointer };
pub const ResolvedBy = enum { indirect_table, pointer_slot, symbol, none };
pub const Stub = struct {
    addr: u64,
    size: u8,
    kind: StubKind,
    symbol: ?[]const u8, // "_puts" or "_objc_msgSend$sel"
    slot: ?u64, // GOT / la_symbol_ptr / selref slot the stub loads
    dylib: ?[]const u8,
    resolved_by: ResolvedBy,
    /// Algorithms A and B both ran and disagreed (tampered/stripped indirect table) -> triage tell `stubs.mismatch`.
    mismatch: bool,
};
pub const StubTable = struct {
    stubs: []const Stub, // sorted by addr
    mismatches: u32,
    pub const empty: StubTable = .{ .stubs = &.{}, .mismatches = 0 };
    pub fn at(t: *const StubTable, addr: u64) ?*const Stub {
        var lo: usize = 0;
        var hi: usize = t.stubs.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.stubs[mid].addr < addr) lo = mid + 1 else hi = mid;
        }
        if (lo >= t.stubs.len or t.stubs[lo].addr != addr) return null;
        return &t.stubs[lo];
    }
    /// The stub that loads `slot_vmaddr`, if any.
    pub fn slotName(t: *const StubTable, slot_vmaddr: u64) ?[]const u8 {
        for (t.stubs) |*s| if (s.slot == slot_vmaddr) return s.symbol;
        return null;
    }
    pub fn byName(t: *const StubTable, name: []const u8) ?*const Stub {
        for (t.stubs) |*s| if (s.symbol) |n| if (std.mem.eql(u8, n, name)) return s;
        return null;
    }
    /// Stub covering `addr` (its entry range, not only its first byte).
    pub fn covering(t: *const StubTable, addr: u64) ?*const Stub {
        for (t.stubs) |*s| if (addr >= s.addr and addr - s.addr < s.size) return s;
        return null;
    }
};

fn stubKindOf(img: *const Image, s: *const Section) ?StubKind {
    if (s.isSymbolStubs()) {
        if (std.mem.eql(u8, s.sectname, "__auth_stubs")) return .arm64e_auth_stubs;
        return switch (img.arch.name) {
            .x86_64, .x86_64h => .x86_64_stubs,
            else => .arm64_stubs,
        };
    }
    if (s.class == .objc_stubs) return .objc_stubs;
    return null;
}

/// Entry stride of a stub section; null (with one diagnostic) when the section cannot be walked.
fn stubEntrySize(s: *const Section, kind: StubKind, diags: *Diagnostics) ?u8 {
    switch (kind) {
        .objc_stubs => {
            if (s.size % 32 == 0) return 32;
            if (s.size % 16 == 0) {
                if (!diags.has(.symbolize, .unknown_value))
                    diags.info(.symbolize, .unknown_value, s.offset, "__objc_stubs size {d} is not a multiple of 32 (-objc_stubs_small?); using a 16-byte stride", .{s.size});
                return 16;
            }
            diags.warn(.symbolize, .unknown_value, s.offset, "__objc_stubs size {d} matches no known stride; section skipped", .{s.size});
            return null;
        },
        else => {
            if (s.reserved2 == 0 or s.reserved2 > 64) {
                diags.warn(.symbolize, .unknown_value, s.offset, "{s},{s} reserved2 (stub size) is {d}; section skipped", .{ s.segname, s.sectname, s.reserved2 });
                return null;
            }
            return @intCast(s.reserved2);
        },
    }
}

/// True for the pointer sections whose slots the indirect symbol table describes.
fn isPointerSection(s: *const Section) bool {
    return switch (s.sectType()) {
        std.macho.S_NON_LAZY_SYMBOL_POINTERS, std.macho.S_LAZY_SYMBOL_POINTERS => true,
        else => false,
    };
}

/// Symbol a pointer-sized slot resolves to THROUGH THE FIXUPS ONLY — this is stub algorithm B, so it
/// must not consult the indirect symbol table that algorithm A reads, or the two could never disagree.
fn slotSymbol(img: *const Image, fix: *const FixupTable, slot: u64) ?[]const u8 {
    _ = img;
    const f = fix.at(slot) orelse return null;
    if (!f.isBind() or f.symbol.len == 0) return null;
    return f.symbol;
}

/// cctools' `guess_indirect_symbol`: any address inside an `S_SYMBOL_STUBS` /
/// `S_LAZY_SYMBOL_POINTERS` / `S_NON_LAZY_SYMBOL_POINTERS` section names an indirect-table entry.
/// This is the rule behind otool's "literal pool symbol address: _name" comments.
fn indirectSymbolAt(img: *const Image, syms: *const symbols.SymbolTable, addr: u64) ?[]const u8 {
    const sect = img.sectionForVm(addr) orelse return null;
    const stride: u64 = switch (sect.sectType()) {
        std.macho.S_SYMBOL_STUBS => sect.reserved2,
        std.macho.S_LAZY_SYMBOL_POINTERS, std.macho.S_NON_LAZY_SYMBOL_POINTERS => if (img.hdr.is_64) 8 else 4,
        else => return null,
    };
    if (stride == 0) return null;
    const idx = (addr - sect.addr) / stride;
    const entry = std.math.add(u64, sect.reserved1, idx) catch return null;
    if (entry > std.math.maxInt(u32)) return null;
    const sym = syms.indirectSymbol(@intCast(entry)) orelse return null;
    if (sym.name.len == 0) return null;
    return sym.name;
}

/// Folds the `adrp (+add) + ldr` pair inside a stub body down to the pointer slot it loads.
fn foldStubSlot(img: *const Image, addr: u64, size: u8) ?u64 {
    var page: [32]?u64 = @splat(null);
    var i: u8 = 0;
    while (i + 4 <= size) : (i += 4) {
        const w = img.u32AtVm(addr + i) orelse return null;
        if (a64.isAdrp(w)) {
            page[a64.rd(w)] = a64.adrpPage(w, addr + i);
        } else if (a64.isLdr64(w)) {
            const base = page[a64.rn(w)] orelse continue;
            return base +% a64.ldrOff(w);
        } else if (a64.isAddImm(w)) {
            const base = page[a64.rn(w)] orelse continue;
            page[a64.rd(w)] = base +% a64.addImm(w);
        }
    }
    return null;
}

/// x86_64 stub body: `FF 25 disp32` = `jmpq *disp(%rip)`.
fn x86StubSlot(img: *const Image, addr: u64) ?u64 {
    const head = img.u32AtVm(addr) orelse return null;
    if (head & 0xffff != 0x25ff) return null;
    const disp = img.u32AtVm(addr + 2) orelse return null;
    const rel: i64 = @as(i32, @bitCast(disp));
    return @bitCast(@as(i64, @bitCast(addr +% 6)) +% rel);
}

pub fn resolveStubs(arena: Allocator, img: *const Image, syms: *const symbols.SymbolTable, fix: *const FixupTable, objc: ?*const ObjcInfo, limits: *const Limits, diags: *Diagnostics) Allocator.Error!StubTable {
    var list: std.ArrayList(Stub) = .empty;
    var mismatches: u32 = 0;

    // Defined symbols by address — algorithm A for __objc_stubs and the otool operand rule.
    var sym_at: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
    for (syms.symbols) |s| {
        if (s.isStab() or s.kind() != .section or s.name.len == 0) continue;
        const g = try sym_at.getOrPut(arena, s.n_value);
        if (!g.found_existing or s.isExternal()) g.value_ptr.* = s.name;
    }

    for (img.sections) |*s| {
        const kind = stubKindOf(img, s) orelse continue;
        const entry = stubEntrySize(s, kind, diags) orelse continue;
        const n_max: u64 = s.size / entry;
        var n = n_max;
        if (n > limits.max_imports) {
            if (!diags.has(.symbolize, .count_clamped))
                diags.warn(.symbolize, .count_clamped, s.offset, "{s},{s} has {d} stubs; clamped to limits.max_imports {d}", .{ s.segname, s.sectname, n_max, limits.max_imports });
            n = limits.max_imports;
        }
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const addr = s.addr +| (i * entry);
            var name_a: ?[]const u8 = null;
            var resolved_a: ResolvedBy = .none;
            if (kind == .objc_stubs) {
                if (sym_at.get(addr)) |nm| {
                    name_a = nm;
                    resolved_a = .symbol;
                }
            } else {
                const entry_index = std.math.add(u64, s.reserved1, i) catch continue;
                if (entry_index <= std.math.maxInt(u32)) {
                    if (syms.indirectSymbol(@intCast(entry_index))) |sym| {
                        if (sym.name.len != 0) {
                            name_a = sym.name;
                            resolved_a = .indirect_table;
                        }
                    }
                }
            }

            const slot: ?u64 = switch (kind) {
                .x86_64_stubs => x86StubSlot(img, addr),
                else => foldStubSlot(img, addr, entry),
            };
            var name_b: ?[]const u8 = null;
            if (slot) |sl| {
                if (kind == .objc_stubs) {
                    name_b = try objcStubName(arena, img, objc, sl, limits);
                } else {
                    name_b = slotSymbol(img, fix, sl);
                }
            }

            var symbol = name_a;
            var resolved_by = resolved_a;
            var mismatch = false;
            if (name_a) |a| {
                if (name_b) |b| if (!std.mem.eql(u8, a, b)) {
                    // B (the real pointer) wins: a rewritten indirect table cannot fool it.
                    symbol = b;
                    resolved_by = .pointer_slot;
                    mismatch = true;
                    mismatches += 1;
                };
            } else if (name_b != null) {
                symbol = name_b;
                resolved_by = .pointer_slot;
            }
            try list.append(arena, .{
                .addr = addr,
                .size = entry,
                .kind = kind,
                .symbol = symbol,
                .slot = slot,
                .dylib = null,
                .resolved_by = resolved_by,
                .mismatch = mismatch,
            });
        }
    }
    if (mismatches != 0 and !diags.has(.symbolize, .stub_mismatch))
        diags.warn(.symbolize, .stub_mismatch, null, "{d} stub(s) name a different symbol in the indirect table than the pointer they load; the pointer wins", .{mismatches});

    const stubs = try list.toOwnedSlice(arena);
    std.mem.sort(Stub, stubs, {}, struct {
        fn less(_: void, x: Stub, y: Stub) bool {
            return x.addr < y.addr;
        }
    }.less);
    return .{ .stubs = stubs, .mismatches = mismatches };
}

/// `_objc_msgSend$<selector>` from the `__objc_selrefs` slot a stub loads.
fn objcStubName(arena: Allocator, img: *const Image, objc: ?*const ObjcInfo, selref: u64, limits: *const Limits) Allocator.Error!?[]const u8 {
    var sel: ?[]const u8 = null;
    if (objc) |o| {
        for (o.selectors) |s| if (s.selref_addr == selref) {
            sel = s.name;
            break;
        };
    }
    if (sel == null) {
        // No ObjC metadata: follow the slot ourselves (rebase target -> __objc_methname cstring).
        const target = img.u64AtVm(selref) orelse return null;
        const masked = target & fixups_mod.pointer_mask;
        sel = img.cstrAtVm(masked, @min(limits.max_symbol_name, 1024));
    }
    const name = sel orelse return null;
    if (name.len == 0) return null;
    return try std.fmt.allocPrint(arena, "_objc_msgSend${s}", .{name});
}

// ---------------------------------------------------------------------------------------------
// annotations
// ---------------------------------------------------------------------------------------------

pub const AnnotateCtx = struct {
    img: *const Image,
    syms: *const symbols.SymbolTable,
    index: *const symbols.AddressIndex,
    fix: *const FixupTable,
    stubs: *const StubTable,
    funcs: *const FunctionTable,
    objc: ?*const ObjcInfo,
    strings: ?*const StringsResult,
    /// Suppress machre-only comments (data symbols, one-level pointer follow) and print `bl _name`
    /// for direct calls so the listing diffs empty against `otool -tV`.
    otool_compat: bool = false,
};
pub const AnnKind = enum { page, literal_string, cfstring, selector_ref, class_ref, got_symbol, stub, objc_msgsend, function, data_symbol, pointer, literal_value, jump_table, trap };
pub const Annotation = struct { kind: AnnKind, text: []const u8, otool_compatible: bool };

/// Name of a defined symbol exactly at `addr` (external preferred), or null.
fn symbolAt(ctx: AnnotateCtx, addr: u64) ?[]const u8 {
    const s = ctx.index.at(ctx.syms, addr) orelse return null;
    if (s.name.len == 0) return null;
    return s.name;
}

/// otool quotes a symbol operand as soon as it leaves the C-identifier alphabet (`$` and `.` included).
fn needsQuotes(name: []const u8) bool {
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '$' or c == '.' or c == '@') continue;
        return true;
    }
    return false;
}
/// A symbol name being substituted INTO `Insn.operands` (the `--otool-compat` spellings `bl _name` and
/// `movq _name(%rip), %r9`) is file-derived text on its way to a terminal, and the operand column — unlike
/// labels and comments — is printed by `cmd/disasm.zig` without `Sink.safe`. Every such substitution is
/// therefore made inert HERE, at the single point where a name enters the operand string, so `disasm`,
/// `xrefs` and `functions` are all covered by construction.
///
/// This cannot break the `--otool-compat` diff contract (DESIGN.md §5.6): `sanitize.forText` returns its
/// input unchanged for every clean name, so the rewrite is a no-op on healthy input and fires only where
/// otool would emit a raw control character — exactly the divergence DESIGN.md:4374 already sanctions.
fn safeName(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    return sanitize.forText(arena, name, null);
}
fn quoteName(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    const safe = try safeName(arena, name);
    if (!needsQuotes(safe)) return safe;
    return std.fmt.allocPrint(arena, "\"{s}\"", .{safe});
}

/// cctools' `print_cstring_char`: printable bytes verbatim (only `\` doubled), the seven C escapes,
/// everything else as a three-digit OCTAL escape. Matching it exactly is what keeps `--otool-compat`
/// listings byte-identical for strings like "\033[0m".
fn escaped(arena: Allocator, bytes: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (bytes) |b| {
        if (b == '\\') {
            try out.appendSlice(arena, "\\\\");
        } else if (b >= 0x20 and b < 0x7f) {
            try out.append(arena, b);
        } else switch (b) {
            '\n' => try out.appendSlice(arena, "\\n"),
            '\t' => try out.appendSlice(arena, "\\t"),
            0x0c => try out.appendSlice(arena, "\\f"),
            '\r' => try out.appendSlice(arena, "\\r"),
            0x0b => try out.appendSlice(arena, "\\v"),
            0x08 => try out.appendSlice(arena, "\\b"),
            0x07 => try out.appendSlice(arena, "\\a"),
            else => try out.print(arena, "\\{o:0>3}", .{b}),
        }
    }
    return out.toOwnedSlice(arena);
}

/// `__cfstring` payload: {isa, flags, data, length}; `data` points at a cstring (or UTF-16 when
/// flags == 0x7d0). Under otool_compat the raw slot word is used, exactly like otool.
fn cfstringText(arena: Allocator, ctx: AnnotateCtx, addr: u64, limits: *const Limits) Allocator.Error!?[]const u8 {
    const data_slot = addr +% 16;
    var data: ?u64 = null;
    if (ctx.otool_compat) {
        const raw = ctx.img.u64AtVm(data_slot) orelse return null;
        data = raw;
    } else switch (ctx.fix.resolveSlot(ctx.img, data_slot) orelse return null) {
        .bind => return null,
        .rebase => |v| data = v,
        .raw => |v| data = v,
    }
    const p = data orelse return null;
    if (p == 0) return null;
    const text = ctx.img.cstrAtVm(p, @min(limits.max_string_len, 4096)) orelse return null;
    if (text.len == 0) return null;
    return try escaped(arena, text);
}

/// Class name a `__objc_classrefs` / `__objc_superrefs` slot points at.
fn classRefName(ctx: AnnotateCtx, slot: u64) ?[]const u8 {
    if (!ctx.otool_compat) {
        if (ctx.objc) |o| for (o.classrefs) |c| if (c.ref_addr == slot) return c.name;
        if (ctx.fix.at(slot)) |f| if (f.isBind() and f.symbol.len != 0) return f.symbol;
        if (ctx.fix.pointerAt(ctx.img, slot)) |target| {
            if (ctx.objc) |o| for (o.classes) |c| if (c.address == target) return c.name;
            return symbolAt(ctx, target);
        }
        return null;
    }
    // otool reads the raw word and gives up when it does not name a class.
    const raw = ctx.img.u64AtVm(slot) orelse return null;
    if (ctx.objc) |o| for (o.classes) |c| if (c.address == raw) return c.name;
    return null;
}

/// Selector string a `__objc_selrefs` slot points at.
fn selectorName(ctx: AnnotateCtx, slot: u64, limits: *const Limits) ?[]const u8 {
    if (ctx.objc) |o| for (o.selectors) |s| if (s.selref_addr == slot) return s.name;
    const target = ctx.fix.pointerAt(ctx.img, slot) orelse return null;
    return ctx.img.cstrAtVm(target, @min(limits.max_symbol_name, 1024));
}

const string_classes = [_]@FieldType(Section, "class"){ .cstring, .ustring, .objc_methname, .objc_classname, .objc_methtype };
fn isStringSection(s: *const Section) bool {
    for (string_classes) |c| if (s.class == c) return true;
    return false;
}
fn isGotSection(s: *const Section) bool {
    return switch (s.class) {
        .got, .auth_got, .la_symbol_ptr, .nl_symbol_ptr => true,
        else => false,
    };
}

/// Annotation for an address computed by `adrp`+`add` / `adr` (a value, not a slot).
fn describeAddress(arena: Allocator, ctx: AnnotateCtx, addr: u64, limits: *const Limits) Allocator.Error!?Annotation {
    const sect = ctx.img.sectionForVm(addr) orelse return null;
    // An `adrp`+`add` pair landing on a stub or pointer slot (the hand-written thunk shape): otool
    // names it through the indirect symbol table.
    if (indirectSymbolAt(ctx.img, ctx.syms, addr)) |name|
        return .{ .kind = .got_symbol, .text = try std.fmt.allocPrint(arena, "literal pool symbol address: {s}", .{name}), .otool_compatible = true };
    if (isStringSection(sect)) {
        const text = ctx.img.cstrAtVm(addr, @min(limits.max_string_len, 4096)) orelse return null;
        return .{ .kind = .literal_string, .text = try std.fmt.allocPrint(arena, "literal pool for: \"{s}\"", .{try escaped(arena, text)}), .otool_compatible = true };
    }
    if (sect.class == .cfstring) {
        const text = (try cfstringText(arena, ctx, addr, limits)) orelse
            (if (ctx.otool_compat) "bad cfstring ref" else return null);
        if (ctx.otool_compat)
            return .{ .kind = .cfstring, .text = try std.fmt.allocPrint(arena, "Objc cfstring ref: @\"{s}\"", .{text}), .otool_compatible = true };
        return .{ .kind = .cfstring, .text = try std.fmt.allocPrint(arena, "@\"{s}\"", .{text}), .otool_compatible = false };
    }
    if (sect.class == .objc_selrefs) {
        // otool prints nothing for selector refs; this is a machre extra.
        const sel = selectorName(ctx, addr, limits) orelse return null;
        return .{ .kind = .selector_ref, .text = try std.fmt.allocPrint(arena, "Objc selector ref: {s}", .{sel}), .otool_compatible = false };
    }
    if (sect.class == .objc_classrefs or sect.class == .objc_superrefs) {
        const name = classRefName(ctx, addr) orelse (if (ctx.otool_compat) "bad class ref" else return null);
        return .{ .kind = .class_ref, .text = try std.fmt.allocPrint(arena, "Objc class ref: {s}", .{name}), .otool_compatible = true };
    }
    if (sect.isCode()) {
        if (ctx.funcs.byStart(addr)) |f|
            return .{ .kind = .function, .text = f.name, .otool_compatible = false };
        return null;
    }
    // machre extra: a data symbol, else the section-relative spelling.
    if (symbolAt(ctx, addr)) |name|
        return .{ .kind = .data_symbol, .text = name, .otool_compatible = false };
    return .{ .kind = .data_symbol, .text = try std.fmt.allocPrint(arena, "{s},{s}+0x{x}", .{ sect.segname, sect.sectname, addr - sect.addr }), .otool_compatible = false };
}

/// Annotation for a pointer-sized slot loaded by `ldr Xt, [Xn, #off]` / `movq off(%rip), %reg`.
fn describeSlot(arena: Allocator, ctx: AnnotateCtx, slot: u64, limits: *const Limits) Allocator.Error!?Annotation {
    const sect = ctx.img.sectionForVm(slot) orelse return null;
    if (indirectSymbolAt(ctx.img, ctx.syms, slot)) |name|
        return .{ .kind = .got_symbol, .text = try std.fmt.allocPrint(arena, "literal pool symbol address: {s}", .{name}), .otool_compatible = true };
    // A bind on a slot the indirect table does not describe (thread vars, chained-only images):
    // useful, but otool prints nothing there, so it is a machre extra.
    if (slotSymbol(ctx.img, ctx.fix, slot)) |name|
        return .{ .kind = .got_symbol, .text = try std.fmt.allocPrint(arena, "literal pool symbol address: {s}", .{name}), .otool_compatible = false };
    if (sect.class == .objc_selrefs) {
        const sel = selectorName(ctx, slot, limits) orelse return null;
        return .{ .kind = .selector_ref, .text = try std.fmt.allocPrint(arena, "Objc selector ref: {s}", .{sel}), .otool_compatible = false };
    }
    if (sect.class == .objc_classrefs or sect.class == .objc_superrefs) {
        const name = classRefName(ctx, slot) orelse (if (ctx.otool_compat) "bad class ref" else return null);
        return .{ .kind = .class_ref, .text = try std.fmt.allocPrint(arena, "Objc class ref: {s}", .{name}), .otool_compatible = true };
    }
    if (ctx.otool_compat) return null;
    // machre extra: follow the pointer ONE level and show what it lands on.
    const target = ctx.fix.pointerAt(ctx.img, slot) orelse return null;
    if (target == 0) return null;
    const label: []const u8 = symbolAt(ctx, slot) orelse blk: {
        break :blk try std.fmt.allocPrint(arena, "{s},{s}+0x{x}", .{ sect.segname, sect.sectname, slot - sect.addr });
    };
    if (ctx.img.sectionForVm(target)) |ts| {
        if (isStringSection(ts)) {
            if (ctx.img.cstrAtVm(target, @min(limits.max_string_len, 4096))) |text| {
                if (text.len != 0)
                    return .{ .kind = .pointer, .text = try std.fmt.allocPrint(arena, "{s} -> 0x{x} \"{s}\"", .{ label, target, try escaped(arena, text) }), .otool_compatible = false };
            }
        }
    }
    return .{ .kind = .pointer, .text = try std.fmt.allocPrint(arena, "{s} -> 0x{x}", .{ label, target }), .otool_compatible = false };
}

/// Annotation for a branch/call target.
fn describeTarget(arena: Allocator, ctx: AnnotateCtx, target: u64) Allocator.Error!?Annotation {
    if (ctx.stubs.covering(target)) |st| {
        const name = st.symbol orelse return null;
        if (st.kind == .objc_stubs)
            return .{ .kind = .objc_msgsend, .text = try std.fmt.allocPrint(arena, "\"{s}\"", .{name}), .otool_compatible = false };
        if (std.mem.startsWith(u8, name, "_objc_msgSend"))
            return .{ .kind = .objc_msgsend, .text = try std.fmt.allocPrint(arena, "Objc message: {s}", .{name}), .otool_compatible = true };
        return .{ .kind = .stub, .text = try std.fmt.allocPrint(arena, "symbol stub for: {s}", .{name}), .otool_compatible = true };
    }
    if (ctx.funcs.byStart(target)) |f|
        return .{ .kind = .function, .text = f.name, .otool_compatible = false };
    if (symbolAt(ctx, target)) |name|
        return .{ .kind = .function, .text = name, .otool_compatible = false };
    return null;
}

/// Best name for an address: "_main", "_main+0x1c", "-[Foo bar]", stub symbol, or null.
pub fn nameFor(ctx: AnnotateCtx, addr: u64, buf: []u8) ?[]const u8 {
    if (ctx.funcs.byStart(addr)) |f| return f.name;
    if (ctx.stubs.at(addr)) |s| if (s.symbol) |n| return n;
    if (symbolAt(ctx, addr)) |n| return n;
    if (ctx.funcs.containing(addr)) |f| {
        if (buf.len == 0) return f.name;
        return std.fmt.bufPrint(buf, "{s}+0x{x}", .{ f.name, addr - f.start }) catch f.name;
    }
    const near = ctx.index.nearest(ctx.syms, addr) orelse return null;
    if (near.delta == 0) return near.sym.name;
    if (buf.len == 0) return near.sym.name;
    return std.fmt.bufPrint(buf, "{s}+0x{x}", .{ near.sym.name, near.delta }) catch near.sym.name;
}

// ---------------------------------------------------------------------------------------------
// the shared walk: ADRP/ADD/LDR folding + comment/xref production
// ---------------------------------------------------------------------------------------------

const XrefSink = struct {
    list: std.ArrayList(Xref) = .empty,
    truncated: bool = false,
    cap: u32,
    fn push(s: *XrefSink, arena: Allocator, x: Xref) Allocator.Error!void {
        if (s.list.items.len >= s.cap) {
            s.truncated = true;
            return;
        }
        try s.list.append(arena, x);
    }
};

fn isArm64(img: *const Image) bool {
    return switch (img.arch.name) {
        .arm64, .arm64e, .arm64v8, .arm64_32 => true,
        else => false,
    };
}

/// Invalidates every GPR `i` writes. Register 31 is deliberately NOT tracked (see `walk`), so the
/// bit is masked off rather than special-cased at every call site.
fn clobber(page: *[32]?u64, i: *const insn.Insn) void {
    var m = i.reg_writes & 0x7fff_ffff;
    while (m != 0) : (m &= m - 1) page[@as(u5, @intCast(@ctz(m)))] = null;
}
/// Invalidates every GPR `i` writes, then records `v` for its primary destination.
fn definePage(page: *[32]?u64, i: *const insn.Insn, v: ?u64) void {
    clobber(page, i);
    if (i.reg_write) |rw| if (rw != 31) {
        page[rw] = v;
    };
}

/// One pass over a listing: folds register pages, fills `comments` (when given) and emits xrefs
/// (when given). `comments` and `listing.insns` must have the same length.
fn walk(
    arena: Allocator,
    listing: *const insn.Listing,
    ctx: AnnotateCtx,
    limits: *const Limits,
    comments: ?[]?[]const u8,
    operands: ?[]insn.Insn,
    xrefs: ?*XrefSink,
) Allocator.Error!void {
    const insns = listing.insns;
    if (insns.len == 0) return;
    const arm = isArm64(ctx.img);

    // Branch targets inside the listing invalidate the folded page state (§9).
    var targets: std.AutoHashMapUnmanaged(u64, void) = .empty;
    for (insns) |*i| if (i.target) |t| {
        if (i.kind == .branch or i.kind == .cond_branch) try targets.put(arena, t, {});
    };

    const from_function: ?u32 = blk: {
        for (ctx.funcs.functions, 0..) |*f, fi| if (f.start == listing.start) break :blk @intCast(fi);
        break :blk null;
    };

    // `page[r]` is the address machre believes register r holds. Index 31 is NEVER written: as a
    // DESTINATION register 31 is XZR (the write is discarded) and as a memory base it is SP — two
    // different registers sharing one encoding. Keeping 31 out of the tracked set is what makes the
    // invalidation below a pure DROP: it can remove an annotation, never turn it into a different one.
    var page: [32]?u64 = @splat(null);
    for (insns, 0..) |*i, idx| {
        if (targets.contains(i.addr)) page = @splat(null);
        var ann: ?Annotation = null;
        var folded: ?u64 = null; // address computed by this instruction (not a slot)
        var slot: ?u64 = null; // pointer slot this instruction loads

        switch (i.kind) {
            .adrp => {
                if (i.imm) |p| {
                    definePage(&page, i, p);
                    ann = .{ .kind = .page, .text = try std.fmt.allocPrint(arena, "0x{x}", .{p}), .otool_compatible = true };
                } else clobber(&page, i);
            },
            .adr => {
                if (i.imm) |v| {
                    definePage(&page, i, v);
                    folded = v;
                } else clobber(&page, i);
            },
            .add_imm => {
                if (arm) {
                    const w = word(i);
                    const base = page[a64.rn(w)];
                    if (base != null and i.imm != null) {
                        const a = base.? +% i.imm.?;
                        folded = a;
                        definePage(&page, i, a);
                    } else clobber(&page, i);
                } else clobber(&page, i);
            },
            .ldr_imm => {
                if (i.mem_ref) |m| {
                    if (page[m.base]) |base| {
                        const s: u64 = @bitCast(@as(i64, @bitCast(base)) +% m.offset);
                        if (m.size == 8) slot = s else folded = s;
                    }
                }
                clobber(&page, i);
            },
            .ldr_literal => {
                if (i.target) |t| {
                    if (ctx.img.u64AtVm(t)) |v|
                        ann = .{ .kind = .literal_value, .text = try std.fmt.allocPrint(arena, "0x{x}", .{v}), .otool_compatible = false };
                }
                clobber(&page, i);
            },
            .lea => {
                // x86_64: `leaq disp(%rip), %reg` — the decoder resolved the target already.
                if (i.target) |t| folded = t;
                clobber(&page, i);
            },
            .trap => ann = .{ .kind = .trap, .text = "trap", .otool_compatible = false },
            .call, .indirect_call => {
                // A call clobbers the volatile registers; otool's own folding stops there too
                // (`bl _getenv` then `ldrb w8, [x0]` must not claim to load the argument string).
                var r: usize = 0;
                while (r <= 18) : (r += 1) page[r] = null;
                page[30] = null;
                clobber(&page, i);
            },
            else => {
                clobber(&page, i);
                // x86_64 `movq off(%rip), %reg` / `call *off(%rip)` carry a resolved target.
                if (!arm and i.target != null and (i.kind == .other or i.kind == .indirect_call or i.kind == .indirect_branch)) slot = i.target;
            },
        }

        if (ann == null) {
            if (folded) |a| ann = try describeAddress(arena, ctx, a, limits);
            if (ann == null) if (slot) |s| {
                ann = try describeSlot(arena, ctx, s, limits);
            };
        }
        if (ann == null and (i.kind == .call or i.kind == .branch or i.kind == .cond_branch)) {
            if (i.target) |t| ann = try describeTarget(arena, ctx, t);
        }

        // otool prints the symbol as the OPERAND when one sits exactly on the branch target.
        if (operands) |ops| {
            if (ctx.otool_compat and (i.kind == .call or i.kind == .branch)) {
                if (i.target) |t| if (symbolAt(ctx, t)) |name| {
                    ops[idx].operands = try quoteName(arena, name);
                    ann = null;
                };
            }
            if (ctx.otool_compat and !arm and i.text_from == .capstone) {
                if (try otoolX86Operands(arena, ctx, i)) |rewritten| ops[idx].operands = rewritten;
                if (ann == null) {
                    // LLVM's X86InstComments wins over the generic `imm = ...` note.
                    var sbuf: [96]u8 = undefined;
                    if (x86len.pshufComment(&sbuf, i.mnemonic, ops[idx].operands, i.raw())) |sc| {
                        ann = .{ .kind = .literal_value, .text = try arena.dupe(u8, sc), .otool_compatible = true };
                    } else if (try llvmImmComment(arena, ops[idx].operands)) |t| {
                        ann = .{ .kind = .literal_value, .text = t, .otool_compatible = true };
                    }
                }
            }
        }

        if (comments) |cs| {
            if (ann) |a| {
                if (!ctx.otool_compat or a.otool_compatible) cs[idx] = a.text;
            }
        }

        if (xrefs) |xs| try emitXrefs(arena, xs, ctx, i, folded, slot, from_function);

        // Fail closed. Past `b`/`br`/`ret`/`brk` the next instruction is reached by a path this pass
        // never walked, and an undecodable word may have written any register at all; either way
        // nothing this block computed may be carried across. (A `.cond_branch` falls through, so its
        // state survives; its TARGET is invalidated by the `targets` set above.)
        if (i.endsTracking()) page = @splat(null);
    }
}

/// Capstone's AT&T spelling differs from otool/LLVM's in four mechanical ways: decimal immediates and
/// displacements (`$3`, `-4(%rbp)`) where otool prints hex, a space after the comma inside a memory
/// operand, no symbol substitution for rip-relative references, and an UNSIGNED immediate where LLVM
/// prints the signed MCOperand it decoded (`andl $0xffffffed` vs `andl $-0x13`; x86len.otoolImmOperand
/// owns that last rule, which needs the instruction bytes). `--otool-compat` rewrites all four so an
/// x86_64 listing diffs empty against `otool -tV`; nothing else touches Capstone's text.
fn otoolX86Operands(arena: Allocator, ctx: AnnotateCtx, i: *const insn.Insn) Allocator.Error!?[]const u8 {
    const ops = i.operands;
    if (ops.len == 0) return null;
    var out: std.ArrayList(u8) = .empty;
    var depth: usize = 0;
    var k: usize = 0;
    var at_token_start = true;
    var changed = false;
    while (k < ops.len) {
        const c = ops[k];
        if (c == '(') {
            depth += 1;
            try out.append(arena, c);
            k += 1;
            at_token_start = true;
            continue;
        }
        if (c == ')') {
            if (depth > 0) depth -= 1;
            try out.append(arena, c);
            k += 1;
            at_token_start = false;
            continue;
        }
        if (c == ',' and depth > 0 and k + 1 < ops.len and ops[k + 1] == ' ') {
            try out.append(arena, ',');
            k += 2;
            at_token_start = true;
            changed = true;
            continue;
        }
        if (c == ',' or c == ' ' or c == '$' or c == ':') {
            try out.append(arena, c);
            k += 1;
            at_token_start = true;
            continue;
        }
        if (at_token_start and (c == '-' or std.ascii.isDigit(c))) {
            const neg = c == '-';
            var j = k + if (neg) @as(usize, 1) else 0;
            const num_start = j;
            var is_hex = false;
            if (j + 1 < ops.len and ops[j] == '0' and (ops[j + 1] == 'x' or ops[j + 1] == 'X')) {
                is_hex = true;
                j += 2;
                while (j < ops.len and std.ascii.isHex(ops[j])) j += 1;
            } else {
                while (j < ops.len and std.ascii.isDigit(ops[j])) j += 1;
            }
            if (j == num_start or (is_hex and j == num_start + 2)) {
                try out.append(arena, c);
                k += 1;
                at_token_start = false;
                continue;
            }
            const digits = ops[if (is_hex) num_start + 2 else num_start..j];
            const value = std.fmt.parseInt(u64, digits, if (is_hex) 16 else 10) catch {
                try out.appendSlice(arena, ops[k..j]);
                k = j;
                at_token_start = false;
                continue;
            };
            const rip = std.mem.startsWith(u8, ops[j..], "(%rip)");
            if (rip) {
                const delta: i64 = if (neg) -@as(i64, @intCast(value)) else @intCast(value);
                const target: u64 = @bitCast(@as(i64, @bitCast(i.addr +% i.size)) +% delta);
                if (symbolAt(ctx, target)) |name| {
                    // File-derived: inert before it joins the operand string (see `safeName`).
                    try out.appendSlice(arena, try safeName(arena, name));
                    k = j;
                    at_token_start = false;
                    changed = true;
                    continue;
                }
            }
            // Only immediates (`$3`) and displacements (`3(%rbp)`) are hex in otool; a SIB scale
            // (`(%r13,%rcx,4)`) stays decimal.
            const is_imm = out.items.len != 0 and out.items[out.items.len - 1] == '$';
            const is_disp = j < ops.len and ops[j] == '(';
            if (!is_hex and (is_imm or is_disp)) {
                if (neg) try out.append(arena, '-');
                try out.print(arena, "0x{x}", .{value});
                changed = true;
            } else try out.appendSlice(arena, ops[k..j]);
            k = j;
            at_token_start = false;
            continue;
        }
        try out.append(arena, c);
        k += 1;
        at_token_start = false;
    }
    const rewritten: []const u8 = if (changed) try out.toOwnedSlice(arena) else ops;
    // The immediate's signedness needs the raw bytes (the printed text alone cannot say whether a
    // top bit is a sign bit or a value), so it is applied last, over the hex-normalised text.
    const final = try x86len.otoolImmOperand(arena, rewritten, i.raw());
    if (!changed and final.ptr == ops.ptr and final.len == ops.len) return null;
    return final;
}

/// LLVM (and therefore otool) annotates an x86 immediate outside [-256, 255] with `imm = 0x<HEX>`
/// when the instruction carries no other comment, printing the value at the NARROWEST of 16/32/64 bits
/// that still holds it (`andq $-0x10000` -> `imm = 0xFFFF0000`, not `0xFFFFFFFFFFFF0000`). Reproduced
/// for `--otool-compat` only; the operand text it reads has already been signed by otoolX86Operands.
fn llvmImmComment(arena: Allocator, ops: []const u8) Allocator.Error!?[]const u8 {
    var k: usize = 0;
    while (std.mem.findScalarPos(u8, ops, k, '$')) |p| {
        k = p + 1;
        var j = k;
        const neg = j < ops.len and ops[j] == '-';
        if (neg) j += 1;
        var is_hex = false;
        const num_start = j;
        if (j + 1 < ops.len and ops[j] == '0' and (ops[j + 1] == 'x' or ops[j + 1] == 'X')) {
            is_hex = true;
            j += 2;
            while (j < ops.len and std.ascii.isHex(ops[j])) j += 1;
        } else while (j < ops.len and std.ascii.isDigit(ops[j])) j += 1;
        const digits = ops[if (is_hex) num_start + 2 else num_start..j];
        if (digits.len == 0) continue;
        const mag = std.fmt.parseInt(u64, digits, if (is_hex) 16 else 10) catch continue;
        // Two's complement without negating through i64: `movabsq $-0x8000000000000000` really occurs.
        const value: u64 = if (neg) ~mag +% 1 else mag;
        const signed: i64 = @bitCast(value);
        if (signed <= 255 and signed >= -256) continue;
        if (signed == @as(i64, @as(i16, @truncate(signed))))
            return try std.fmt.allocPrint(arena, "imm = 0x{X}", .{@as(u16, @bitCast(@as(i16, @truncate(signed))))});
        if (signed == @as(i64, @as(i32, @truncate(signed))))
            return try std.fmt.allocPrint(arena, "imm = 0x{X}", .{@as(u32, @bitCast(@as(i32, @truncate(signed))))});
        return try std.fmt.allocPrint(arena, "imm = 0x{X}", .{value});
    }
    return null;
}

/// The raw 32-bit word of an arm64 instruction record.
fn word(i: *const insn.Insn) u32 {
    const raw = i.raw();
    if (raw.len < 4) return 0;
    return std.mem.readInt(u32, raw[0..4], .little);
}

/// Name shown next to an xref target: the string itself for a literal, the selector/class for ObjC
/// metadata, otherwise a defined symbol at the address.
fn xrefName(arena: Allocator, ctx: AnnotateCtx, kind: XrefKind, addr: u64) Allocator.Error!?[]const u8 {
    switch (kind) {
        .string_ref => {
            const text = ctx.img.cstrAtVm(addr, 128) orelse return symbolAt(ctx, addr);
            if (text.len == 0) return symbolAt(ctx, addr);
            return try std.fmt.allocPrint(arena, "\"{s}\"", .{try escaped(arena, text)});
        },
        .objc_selector => return selectorName(ctx, addr, &.{}) orelse symbolAt(ctx, addr),
        .objc_class => return classRefName(ctx, addr) orelse symbolAt(ctx, addr),
        else => return symbolAt(ctx, addr),
    }
}

fn emitXrefs(arena: Allocator, xs: *XrefSink, ctx: AnnotateCtx, i: *const insn.Insn, folded: ?u64, slot: ?u64, from_function: ?u32) Allocator.Error!void {
    if (i.target) |t| {
        const kind: ?XrefKind = switch (i.kind) {
            .call, .indirect_call => .call,
            .branch => .jump,
            .cond_branch => .cond_jump,
            else => null,
        };
        if (kind) |k| {
            var name: ?[]const u8 = null;
            var via_stub = false;
            if (ctx.stubs.covering(t)) |st| {
                name = st.symbol;
                via_stub = true;
            } else if (ctx.funcs.byStart(t)) |f| {
                name = f.name;
            } else name = symbolAt(ctx, t);
            try xs.push(arena, .{ .from = i.addr, .to = t, .kind = k, .target_name = name, .from_function = from_function, .via_stub = via_stub });
        }
    }
    if (folded) |a| {
        if (ctx.img.sectionForVm(a)) |sect| {
            const k: XrefKind = if (isStringSection(sect))
                .string_ref
            else if (sect.class == .objc_selrefs)
                .objc_selector
            else if (sect.class == .objc_classrefs or sect.class == .objc_superrefs)
                .objc_class
            else
                .data_ref;
            try xs.push(arena, .{ .from = i.addr, .to = a, .kind = k, .target_name = try xrefName(arena, ctx, k, a), .from_function = from_function, .via_stub = false });
        }
    }
    if (slot) |s| {
        if (ctx.img.sectionForVm(s)) |sect| {
            const k: XrefKind = if (isGotSection(sect))
                .got_load
            else if (sect.class == .objc_selrefs)
                .objc_selector
            else if (sect.class == .objc_classrefs or sect.class == .objc_superrefs)
                .objc_class
            else
                .data_ref;
            const name = indirectSymbolAt(ctx.img, ctx.syms, s) orelse slotSymbol(ctx.img, ctx.fix, s) orelse try xrefName(arena, ctx, k, s);
            try xs.push(arena, .{ .from = i.addr, .to = s, .kind = k, .target_name = name, .from_function = from_function, .via_stub = false });
        }
    }
}

/// Fills listing.comments in place (one optional annotation per instruction; page[reg] state reset at
/// function entry and at every branch target).
pub fn annotate(arena: Allocator, listing: *insn.Listing, ctx: AnnotateCtx, limits: *const Limits) Allocator.Error!void {
    if (listing.insns.len == 0) return;
    const comments = try arena.alloc(?[]const u8, listing.insns.len);
    @memset(comments, null);
    // The engine owns the instruction storage; operand rewriting is confined to --otool-compat.
    const ops: ?[]insn.Insn = if (ctx.otool_compat) @constCast(listing.insns) else null;
    try walk(arena, listing, ctx, limits, comments, ops, null);
    listing.comments = comments;
}

// ---------------------------------------------------------------------------------------------
// xrefs
// ---------------------------------------------------------------------------------------------

pub const XrefKind = enum { call, jump, cond_jump, data_ref, string_ref, got_load, objc_selector, objc_class, pointer_slot };
pub const Xref = struct { from: u64, to: u64, kind: XrefKind, target_name: ?[]const u8, from_function: ?u32, via_stub: bool };
pub const XrefTable = struct {
    by_to: []const Xref, // sorted by (to, from)
    by_from: []const Xref, // sorted by (from, to)
    truncated: bool,
    pub const empty: XrefTable = .{ .by_to = &.{}, .by_from = &.{}, .truncated = false };
    pub fn to(t: *const XrefTable, addr: u64) []const Xref {
        var lo: usize = 0;
        var hi: usize = t.by_to.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.by_to[mid].to < addr) lo = mid + 1 else hi = mid;
        }
        var end = lo;
        while (end < t.by_to.len and t.by_to[end].to == addr) end += 1;
        return t.by_to[lo..end];
    }
    pub fn from(t: *const XrefTable, addr: u64) []const Xref {
        var lo: usize = 0;
        var hi: usize = t.by_from.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (t.by_from[mid].from < addr) lo = mid + 1 else hi = mid;
        }
        var end = lo;
        while (end < t.by_from.len and t.by_from[end].from == addr) end += 1;
        return t.by_from[lo..end];
    }
};
pub const XrefOptions = struct {
    /// Every rebase fixup whose target lands in a code section becomes a `pointer_slot` xref
    /// (function-pointer tables, blocks, ObjC IMPs, __mod_init_func / __init_offsets).
    include_pointer_slots: bool = true,
};

fn lessByTo(_: void, a: Xref, b: Xref) bool {
    if (a.to != b.to) return a.to < b.to;
    if (a.from != b.from) return a.from < b.from;
    return @intFromEnum(a.kind) < @intFromEnum(b.kind);
}
fn lessByFrom(_: void, a: Xref, b: Xref) bool {
    if (a.from != b.from) return a.from < b.from;
    if (a.to != b.to) return a.to < b.to;
    return @intFromEnum(a.kind) < @intFromEnum(b.kind);
}

pub fn buildXrefs(arena: Allocator, listings: []const insn.Listing, ctx: AnnotateCtx, opts: XrefOptions, limits: *const Limits) Allocator.Error!XrefTable {
    var sink: XrefSink = .{ .cap = limits.max_xrefs };
    for (listings) |*l| try walk(arena, l, ctx, limits, null, null, &sink);
    if (opts.include_pointer_slots) {
        for (ctx.fix.fixups) |*f| {
            if (f.isBind()) continue;
            if (f.target == 0) continue;
            const sect = ctx.img.sectionForVm(f.target) orelse continue;
            if (!sect.isCode()) continue;
            var name: ?[]const u8 = null;
            if (ctx.funcs.byStart(f.target)) |fun| name = fun.name else name = symbolAt(ctx, f.target);
            try sink.push(arena, .{ .from = f.vmaddr, .to = f.target, .kind = .pointer_slot, .target_name = name, .from_function = null, .via_stub = false });
        }
    }
    const by_to = try sink.list.toOwnedSlice(arena);
    const by_from = try arena.dupe(Xref, by_to);
    std.mem.sort(Xref, by_to, {}, lessByTo);
    std.mem.sort(Xref, by_from, {}, lessByFrom);
    return .{ .by_to = by_to, .by_from = by_from, .truncated = sink.truncated };
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------
const testing = std.testing;

test "symbolize: arm64 field helpers reproduce the hello-objc stub shapes" {
    // 1000012c0: adrp x1, 7 ; ldr x1, [x1, #0x380]
    try testing.expect(a64.isAdrp(0xf0000021));
    try testing.expectEqual(@as(u64, 0x100008000), a64.adrpPage(0xf0000021, 0x1000012c0));
    try testing.expect(a64.isLdr64(0xf941c021));
    try testing.expectEqual(@as(u5, 1), a64.rn(0xf941c021));
    try testing.expectEqual(@as(u64, 0x380), a64.ldrOff(0xf941c021));
    // add x17, x17, #0x28
    try testing.expect(a64.isAddImm(0x9100a231));
    try testing.expectEqual(@as(u64, 0x28), a64.addImm(0x9100a231));
    // negative page delta
    try testing.expectEqual(@as(u64, 0x100000000), a64.adrpPage(0xf0fffff0, 0x100001000));
    try testing.expect(!a64.isAdrp(0x10000021)); // adr, not adrp
}

test "symbolize: quoting follows otool's alphabet" {
    try testing.expect(!needsQuotes("_objc_msgSend$copy"));
    try testing.expect(needsQuotes("_objc_msgSend$stringWithFormat:"));
    try testing.expect(needsQuotes("-[Foo bar]"));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("_main", try quoteName(arena.allocator(), "_main"));
    try testing.expectEqualStrings("\"a:b\"", try quoteName(arena.allocator(), "a:b"));
    try testing.expectEqualStrings("%s=%p\\n", try escaped(arena.allocator(), "%s=%p\n"));
    try testing.expectEqualStrings("a\\001b", try escaped(arena.allocator(), "a\x01b"));
    try testing.expectEqualStrings("\\033[0m", try escaped(arena.allocator(), "\x1b[0m"));
    try testing.expectEqualStrings("a\\\\b", try escaped(arena.allocator(), "a\\b"));
}

test "symbolize: empty tables answer every query" {
    const t = StubTable.empty;
    try testing.expect(t.at(0) == null);
    try testing.expect(t.byName("_x") == null);
    try testing.expect(t.slotName(0) == null);
    try testing.expect(t.covering(0x1000) == null);
    const x = XrefTable.empty;
    try testing.expectEqual(@as(usize, 0), x.to(0x100).len);
    try testing.expectEqual(@as(usize, 0), x.from(0x100).len);
}

test "symbolize: xref tables are sorted and searchable in both directions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = [_]Xref{
        .{ .from = 0x30, .to = 0x10, .kind = .call, .target_name = null, .from_function = null, .via_stub = false },
        .{ .from = 0x10, .to = 0x30, .kind = .jump, .target_name = null, .from_function = null, .via_stub = false },
        .{ .from = 0x20, .to = 0x10, .kind = .call, .target_name = null, .from_function = null, .via_stub = false },
    };
    const by_to = try a.dupe(Xref, &raw);
    const by_from = try a.dupe(Xref, &raw);
    std.mem.sort(Xref, by_to, {}, lessByTo);
    std.mem.sort(Xref, by_from, {}, lessByFrom);
    const t: XrefTable = .{ .by_to = by_to, .by_from = by_from, .truncated = false };
    try testing.expectEqual(@as(usize, 2), t.to(0x10).len);
    try testing.expectEqual(@as(u64, 0x20), t.to(0x10)[0].from);
    try testing.expectEqual(@as(usize, 1), t.from(0x30).len);
    try testing.expectEqual(@as(usize, 0), t.to(0x99).len);
}

/// Classifies a rendered comment back into its `AnnKind` (the JSON `comment_kind` field). The producer
/// and this classifier live together so the vocabulary cannot drift.
pub fn commentKind(t: []const u8) AnnKind {
    if (std.mem.startsWith(u8, t, "literal pool for:")) return .literal_string;
    if (std.mem.startsWith(u8, t, "literal pool symbol address:")) return .got_symbol;
    if (std.mem.startsWith(u8, t, "symbol stub for:")) return .stub;
    if (std.mem.startsWith(u8, t, "Objc message:")) return .objc_msgsend;
    if (std.mem.startsWith(u8, t, "Objc cfstring ref:") or std.mem.startsWith(u8, t, "@\"")) return .cfstring;
    if (std.mem.startsWith(u8, t, "Objc selector ref:")) return .selector_ref;
    if (std.mem.startsWith(u8, t, "Objc class ref:")) return .class_ref;
    if (std.mem.eql(u8, t, "trap")) return .trap;
    if (std.mem.startsWith(u8, t, "\"_objc_msgSend$")) return .objc_msgsend;
    if (std.mem.find(u8, t, " -> 0x") != null) return .pointer;
    if (std.mem.startsWith(u8, t, "0x")) return .page;
    return .function;
}

test "symbolize: comment kinds round-trip the vocabulary" {
    try testing.expectEqual(AnnKind.literal_string, commentKind("literal pool for: \"x\""));
    try testing.expectEqual(AnnKind.got_symbol, commentKind("literal pool symbol address: _x"));
    try testing.expectEqual(AnnKind.stub, commentKind("symbol stub for: _puts"));
    try testing.expectEqual(AnnKind.objc_msgsend, commentKind("Objc message: _objc_msgSendSuper2"));
    try testing.expectEqual(AnnKind.cfstring, commentKind("@\"hi\""));
    try testing.expectEqual(AnnKind.class_ref, commentKind("Objc class ref: bad class ref"));
    try testing.expectEqual(AnnKind.page, commentKind("0x100004000"));
    try testing.expectEqual(AnnKind.pointer, commentKind("_greeting -> 0x100000668 \"hi\""));
    try testing.expectEqual(AnnKind.function, commentKind("_add_numbers"));
}
