//! objc/objc.zig — Objective-C runtime metadata (objc4 new ABI, 64-bit).
//! Imports: core/image, core/reader, core/diag, core/limits, core/sanitize, core/macho_extra, macho/fixups, macho/symbols.
const std = @import("std");
const Allocator = std.mem.Allocator;
const image_mod = @import("../core/image.zig");
const Image = image_mod.Image;
const Section = image_mod.Section;
const Limits = @import("../core/limits.zig").Limits;
const diag = @import("../core/diag.zig");
const Diagnostics = diag.Diagnostics;
const extra = @import("../core/macho_extra.zig");
const FixupTable = @import("../macho/fixups.zig").FixupTable;
const SymbolTable = @import("../macho/symbols.zig").SymbolTable;

pub const ImageInfo = struct { version: u32, flags: u32, swift_unstable: u8, swift_stable: u16, has_category_class_properties: bool, is_swift: bool };
pub const Method = struct { name: []const u8, types: []const u8, imp: u64, is_class_method: bool, small: bool };
pub const Ivar = struct { name: []const u8, type: []const u8, offset: ?u32, alignment: u32, size: u32 };
pub const Property = struct { name: []const u8, attributes: []const u8 };
pub const SuperRef = struct { kind: enum { local, external, unresolved, none }, address: u64, name: ?[]const u8 };
pub const Class = struct {
    address: u64,
    name: []const u8,
    superclass: SuperRef, // rebase -> local class name; bind -> external symbol
    is_meta: bool,
    is_swift: bool,
    ro_flags: u32,
    instance_start: u32,
    instance_size: u32,
    methods: []const Method,
    class_methods: []const Method,
    ivars: []const Ivar,
    properties: []const Property,
    protocols: []const []const u8,
};
pub const Category = struct { address: u64, name: []const u8, class_name: []const u8, class_external: bool, instance_methods: []const Method, class_methods: []const Method, protocols: []const []const u8, properties: []const Property };
pub const Protocol = struct { address: u64, name: []const u8, protocols: []const []const u8, instance_methods: []const Method, class_methods: []const Method, optional_instance_methods: []const Method, optional_class_methods: []const Method };
pub const Selector = struct { selref_addr: u64, name: []const u8 };
pub const ClassRef = struct { ref_addr: u64, name: []const u8, external: bool };
pub const Stub = struct { addr: u64, selector: []const u8 };
pub const ObjcInfo = struct {
    present: bool,
    image_info: ?ImageInfo,
    classes: []const Class,
    categories: []const Category,
    protocols: []const Protocol,
    selectors: []const Selector,
    classrefs: []const ClassRef,
    stubs: []const Stub,
    truncated: bool,
    pub const empty: ObjcInfo = .{ .present = false, .image_info = null, .classes = &.{}, .categories = &.{}, .protocols = &.{}, .selectors = &.{}, .classrefs = &.{}, .stubs = &.{}, .truncated = false };
    pub fn classByName(o: *const ObjcInfo, name: []const u8) ?*const Class {
        for (o.classes) |*c| if (std.mem.eql(u8, c.name, name)) return c;
        return null;
    }
};

const objc_section_classes = [_]@FieldType(Section, "class"){
    .objc_classlist, .objc_nlclslist, .objc_catlist,   .objc_nlcatlist, .objc_protolist,
    .objc_imageinfo, .objc_selrefs,   .objc_classrefs, .objc_superrefs, .objc_const,
    .objc_data,      .objc_ivar,      .objc_methlist,  .objc_stubs,
};

/// True when the slice carries any ObjC runtime section (metadata or stubs).
pub fn hasObjc(img: *const Image) bool {
    for (img.sections) |*s| {
        for (objc_section_classes) |c| if (s.class == c) return true;
    }
    return false;
}

/// Strips the runtime's symbol decoration: `_OBJC_CLASS_$_NSObject` -> `NSObject`.
fn stripClassSymbol(sym: []const u8) []const u8 {
    const prefixes = [_][]const u8{ "_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "_OBJC_PROTOCOL_$_", "__OBJC_CLASS_$_", "__OBJC_PROTOCOL_$_" };
    for (prefixes) |p| if (std.mem.startsWith(u8, sym, p)) return sym[p.len..];
    return sym;
}

/// One pointer-sized slot after dyld: an address, an unresolved import, or nothing.
const SlotValue = union(enum) { addr: u64, bind: []const u8, none };

const Ctx = struct {
    arena: Allocator,
    img: *const Image,
    fix: *const FixupTable,
    syms: *const SymbolTable,
    limits: *const Limits,
    diags: *Diagnostics,
    truncated: bool = false,
    total_methods: u32 = 0,
    visited: std.AutoHashMapUnmanaged(u64, void) = .empty,

    /// Reads the slot at `vmaddr`. The fixup table is the only component that knows pointer formats;
    /// the fallbacks below apply when it has nothing to say about this slot:
    ///  * legacy / no dyld data: the raw word is an unslid vmaddr (PAC and high bits stripped);
    ///  * chained data that has not been parsed yet (`FixupTable.empty`, i.e. macho/fixups still a
    ///    stub) on a non-arm64e image: decode the DYLD_CHAINED_PTR_64(_OFFSET) rebase field so ObjC
    ///    metadata stays readable. Dead code as soon as `FixupTable.source == .chained`.
    fn slot(c: *Ctx, vmaddr: u64) SlotValue {
        if (c.fix.resolveSlot(c.img, vmaddr)) |s| return switch (s) {
            .bind => |f| .{ .bind = f.symbol },
            .rebase => |t| if (t == 0) .none else .{ .addr = t & extra.objc.PTR_MASK },
            .raw => |v| if (v & extra.objc.PTR_MASK == 0) .none else .{ .addr = v & extra.objc.PTR_MASK },
        };
        const raw = c.img.u64AtVm(vmaddr) orelse return .none;
        if (raw == 0) return .none;
        if (c.fix.source == .none and c.img.dyldStyle() == .chained) {
            if (c.img.arch.is_arm64e) return .none; // authenticated formats: needs the real decoder
            if (raw >> 63 != 0) return .none; // bind entry; the symbol lives in the imports table
            const target = raw & 0xf_ffff_ffff; // 36-bit target field of formats 2 and 6
            if (target == 0) return .none;
            return .{ .addr = if (target < c.img.image_base) c.img.image_base +% target else target };
        }
        return .{ .addr = raw & extra.objc.PTR_MASK };
    }
    fn pointerAt(c: *Ctx, vmaddr: u64) ?u64 {
        return switch (c.slot(vmaddr)) {
            .addr => |a| a,
            else => null,
        };
    }
    fn cstrAt(c: *Ctx, vmaddr: u64) []const u8 {
        return c.img.cstrAtVm(vmaddr, c.limits.max_symbol_name) orelse "";
    }
    /// Follows a slot that holds a `char *` and returns the string it points at.
    fn stringSlot(c: *Ctx, vmaddr: u64) []const u8 {
        const p = c.pointerAt(vmaddr) orelse return "";
        return c.cstrAt(p);
    }
    fn u32At(c: *Ctx, vmaddr: u64) ?u32 {
        return c.img.u32AtVm(vmaddr);
    }
    fn note(c: *Ctx, code: diag.Code, off: ?u64, comptime fmt: []const u8, args: anytype) void {
        if (!c.diags.has(.objc, code)) c.diags.warn(.objc, code, off, fmt, args);
    }
};

/// Pointer array in a section (`__objc_classlist`, `__objc_catlist`, ...): count = size / 8, clamped.
fn pointerList(c: *Ctx, s: *const Section, cap: u32) Allocator.Error![]const u64 {
    const r = c.img.sectionReader(s) orelse return &.{};
    var n = r.len() / 8;
    if (n > cap) {
        n = cap;
        c.truncated = true;
        c.note(.count_clamped, s.offset, "{s},{s}: {d} entries clamped to {d}", .{ s.segname, s.sectname, r.len() / 8, cap });
    }
    const out = try c.arena.alloc(u64, @intCast(n));
    for (out, 0..) |*e, i| {
        e.* = switch (c.slot(s.addr +| 8 * i)) {
            .addr => |a| a,
            else => 0,
        };
    }
    return out;
}

/// Every pointer read goes FixupTable.resolveSlot -> mask PTR_MASK -> Image.bytesAtVm; counts clamped;
/// visited-address set prevents protocol/superclass cycles.
pub fn parse(arena: Allocator, img: *const Image, fix: *const FixupTable, syms: *const SymbolTable, limits: *const Limits, diags: *Diagnostics) Allocator.Error!ObjcInfo {
    if (!hasObjc(img)) return .empty;
    var c: Ctx = .{ .arena = arena, .img = img, .fix = fix, .syms = syms, .limits = limits, .diags = diags };

    var classes: std.ArrayList(Class) = .empty;
    for (img.sections) |*s| {
        if (s.class != .objc_classlist and s.class != .objc_nlclslist) continue;
        for (try pointerList(&c, s, limits.max_objc_classes)) |addr| {
            if (addr == 0) continue;
            if (classes.items.len >= limits.max_objc_classes) {
                c.truncated = true;
                break;
            }
            if (try parseClass(&c, addr, false)) |cl| try classes.append(arena, cl);
        }
    }
    var categories: std.ArrayList(Category) = .empty;
    for (img.sections) |*s| {
        if (s.class != .objc_catlist and s.class != .objc_nlcatlist) continue;
        for (try pointerList(&c, s, limits.max_objc_classes)) |addr| {
            if (addr == 0) continue;
            if (try parseCategory(&c, addr)) |cat| try categories.append(arena, cat);
        }
    }
    var protocols: std.ArrayList(Protocol) = .empty;
    for (img.sections) |*s| {
        if (s.class != .objc_protolist) continue;
        for (try pointerList(&c, s, limits.max_objc_classes)) |addr| {
            if (addr == 0) continue;
            if (try parseProtocol(&c, addr)) |p| try protocols.append(arena, p);
        }
    }
    var selectors: std.ArrayList(Selector) = .empty;
    for (img.sections) |*s| {
        if (s.class != .objc_selrefs) continue;
        const r = img.sectionReader(s) orelse continue;
        var i: u64 = 0;
        while (i + 8 <= r.len()) : (i += 8) {
            const ref = s.addr +| i;
            const name = c.stringSlot(ref);
            if (name.len == 0) continue;
            try selectors.append(arena, .{ .selref_addr = ref, .name = name });
        }
    }
    var classrefs: std.ArrayList(ClassRef) = .empty;
    for (img.sections) |*s| {
        if (s.class != .objc_classrefs and s.class != .objc_superrefs) continue;
        const r = img.sectionReader(s) orelse continue;
        var i: u64 = 0;
        while (i + 8 <= r.len()) : (i += 8) {
            const ref = s.addr +| i;
            switch (c.slot(ref)) {
                .bind => |sym| try classrefs.append(arena, .{ .ref_addr = ref, .name = stripClassSymbol(sym), .external = true }),
                .addr => |a| try classrefs.append(arena, .{ .ref_addr = ref, .name = classNameAt(&c, a) orelse "", .external = false }),
                .none => {},
            }
        }
    }
    const stubs = try parseStubs(&c);
    const image_info = parseImageInfo(&c);

    return .{
        .present = true,
        .image_info = image_info,
        .classes = try classes.toOwnedSlice(arena),
        .categories = try categories.toOwnedSlice(arena),
        .protocols = try protocols.toOwnedSlice(arena),
        .selectors = try selectors.toOwnedSlice(arena),
        .classrefs = try classrefs.toOwnedSlice(arena),
        .stubs = stubs,
        .truncated = c.truncated,
    };
}

fn parseImageInfo(c: *Ctx) ?ImageInfo {
    const s = c.img.sectionByClass(.objc_imageinfo) orelse return null;
    const version = c.img.u32AtVm(s.addr) orelse return null;
    const flags = c.img.u32AtVm(s.addr +| 4) orelse return null;
    const unstable: u8 = @truncate((flags >> 8) & 0xff);
    const stable: u16 = @truncate(flags >> 16);
    return .{
        .version = version,
        .flags = flags,
        .swift_unstable = unstable,
        .swift_stable = stable,
        .has_category_class_properties = flags & extra.objc.image_info_has_category_class_properties != 0,
        .is_swift = unstable != 0 or stable != 0,
    };
}

/// class_ro_t fields of the class at `addr`, or null when the pointers do not map.
const Ro = struct { addr: u64, flags: u32, instance_start: u32, instance_size: u32, name: []const u8 };

fn readRo(c: *Ctx, class_addr: u64) ?Ro {
    const data = c.pointerAt(class_addr +| extra.objc.class_data) orelse return null;
    const ro = data & extra.objc.FAST_DATA_MASK;
    if (ro == 0) return null;
    const flags = c.img.u32AtVm(ro +| extra.objc.ro_flags) orelse return null;
    const start = c.img.u32AtVm(ro +| extra.objc.ro_instance_start) orelse return null;
    const size = c.img.u32AtVm(ro +| extra.objc.ro_instance_size) orelse return null;
    const name = c.stringSlot(ro +| extra.objc.ro_name);
    if (name.len == 0) return null;
    return .{ .addr = ro, .flags = flags, .instance_start = start, .instance_size = size, .name = name };
}

fn classNameAt(c: *Ctx, class_addr: u64) ?[]const u8 {
    const ro = readRo(c, class_addr) orelse return null;
    return ro.name;
}

fn parseClass(c: *Ctx, addr: u64, is_meta: bool) Allocator.Error!?Class {
    const g = try c.visited.getOrPut(c.arena, addr);
    if (g.found_existing) return null;
    const ro = readRo(c, addr) orelse {
        c.note(.truncated, null, "class at 0x{x}: class_ro_t not readable", .{addr});
        return null;
    };
    const data = c.pointerAt(addr +| extra.objc.class_data) orelse 0;
    const methods = try methodList(c, c.pointerAt(ro.addr +| extra.objc.ro_base_methods), false);
    const ivars = try ivarList(c, c.pointerAt(ro.addr +| extra.objc.ro_ivars));
    const properties = try propertyList(c, c.pointerAt(ro.addr +| extra.objc.ro_base_properties));
    const protocols = try protocolNames(c, c.pointerAt(ro.addr +| extra.objc.ro_base_protocols), 0);

    // The metaclass (`isa`) carries the class methods; it is never reported as a class of its own.
    var class_methods: []const Method = &.{};
    if (!is_meta) {
        if (c.pointerAt(addr +| extra.objc.class_isa)) |meta| {
            if (readRo(c, meta)) |mro| class_methods = try methodList(c, c.pointerAt(mro.addr +| extra.objc.ro_base_methods), true);
        }
    }
    return .{
        .address = addr,
        .name = ro.name,
        .superclass = superRef(c, addr +| extra.objc.class_superclass),
        .is_meta = is_meta or (ro.flags & extra.objc.RO_META != 0),
        .is_swift = data & (extra.objc.FAST_IS_SWIFT_LEGACY | extra.objc.FAST_IS_SWIFT_STABLE) != 0,
        .ro_flags = ro.flags,
        .instance_start = ro.instance_start,
        .instance_size = ro.instance_size,
        .methods = methods,
        .class_methods = class_methods,
        .ivars = ivars,
        .properties = properties,
        .protocols = protocols,
    };
}

fn superRef(c: *Ctx, slot_addr: u64) SuperRef {
    return switch (c.slot(slot_addr)) {
        .bind => |sym| .{ .kind = .external, .address = 0, .name = stripClassSymbol(sym) },
        .addr => |a| if (classNameAt(c, a)) |n| .{ .kind = .local, .address = a, .name = n } else .{ .kind = .unresolved, .address = a, .name = null },
        .none => .{ .kind = .none, .address = 0, .name = null },
    };
}

/// `n = min(declared, limit, mapped bytes / entry size)` — DESIGN.md §7 rule 3. Records one
/// `count_clamped` diagnostic per structure when the declared count does not fit.
fn clampCount(c: *Ctx, list: u64, declared: u32, entsize: u32, cap: u32, what: []const u8) u32 {
    const capped: u64 = @min(declared, cap);
    const avail: u64 = if (c.img.bytesAtVm(list +| 8, capped *| entsize)) |vb| vb.bytes.len else 0;
    const count: u32 = @intCast(@min(avail / entsize, capped));
    if (count < declared) {
        c.truncated = true;
        c.note(.count_clamped, null, "{s} at 0x{x}: {d} entries clamped to {d}", .{ what, list, declared, count });
    }
    return count;
}

/// method_list_t: uint32 entsizeAndFlags, uint32 count, then `count` entries of `entsize` bytes.
fn methodList(c: *Ctx, list_addr_opt: ?u64, is_class_method: bool) Allocator.Error![]const Method {
    const list = list_addr_opt orelse return &.{};
    if (list == 0) return &.{};
    const eaf = c.u32At(list) orelse return &.{};
    const declared = c.u32At(list +| 4) orelse return &.{};
    const small = eaf & extra.objc.method_list_small_flag != 0;
    const entsize = eaf & extra.objc.method_list_entsize_mask;
    if (entsize == 0) {
        c.note(.unknown_value, null, "method_list_t at 0x{x} has entsize 0", .{list});
        return &.{};
    }
    var count = clampCount(c, list, declared, entsize, c.limits.max_objc_methods_per_list, "method_list_t");
    if (c.total_methods +| count > c.limits.max_objc_total_methods) {
        count = c.limits.max_objc_total_methods -| c.total_methods;
        c.truncated = true;
    }
    var out: std.ArrayList(Method) = .empty;
    try out.ensureTotalCapacity(c.arena, count);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const base = list +| 8 +| @as(u64, i) *| entsize;
        if (c.img.bytesAtVm(base, entsize) == null) {
            c.truncated = true;
            c.note(.truncated, null, "method_list_t at 0x{x}: entry {d} is not mapped", .{ list, i });
            break;
        }
        const imp_delta = if (small) c.img.u32AtVm(base +| 8) orelse 0 else 0;
        const m: Method = if (small) .{
            .name = smallName(c, base),
            .types = c.cstrAt(relative(base +| 4, c.img.u32AtVm(base +| 4) orelse 0)),
            // a zero delta means "no implementation" (protocol method lists), not "points at itself"
            .imp = if (imp_delta == 0) 0 else relative(base +| 8, imp_delta),
            .is_class_method = is_class_method,
            .small = true,
        } else .{
            .name = c.stringSlot(base),
            .types = c.stringSlot(base +| 8),
            .imp = c.pointerAt(base +| 16) orelse 0,
            .is_class_method = is_class_method,
            .small = false,
        };
        out.appendAssumeCapacity(m);
        c.total_methods +|= 1;
    }
    return out.toOwnedSlice(c.arena);
}

/// Small method lists store signed 32-bit deltas relative to the field's own address.
fn relative(field_addr: u64, delta_u32: u32) u64 {
    const d: i64 = @as(i32, @bitCast(delta_u32));
    return @bitCast(@as(i64, @bitCast(field_addr)) +% d);
}

/// `nameOffset` points at a selector-reference slot; older linkers point straight at the string.
fn smallName(c: *Ctx, base: u64) []const u8 {
    const target = relative(base, c.img.u32AtVm(base) orelse return "");
    if (c.img.sectionForVm(target)) |s| {
        switch (s.class) {
            .objc_methname, .objc_classname, .objc_methtype, .cstring => return c.cstrAt(target),
            else => {},
        }
    }
    return c.stringSlot(target);
}

/// ivar_list_t: uint32 entsize, uint32 count, then `count` ivar_t.
fn ivarList(c: *Ctx, list_addr_opt: ?u64) Allocator.Error![]const Ivar {
    const list = list_addr_opt orelse return &.{};
    if (list == 0) return &.{};
    const entsize = c.u32At(list) orelse return &.{};
    const declared = c.u32At(list +| 4) orelse return &.{};
    if (entsize == 0) return &.{};
    const count = clampCount(c, list, declared, entsize, c.limits.max_objc_methods_per_list, "ivar_list_t");
    var out: std.ArrayList(Ivar) = .empty;
    try out.ensureTotalCapacity(c.arena, count);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const base = list +| 8 +| @as(u64, i) *| entsize;
        if (c.img.bytesAtVm(base, entsize) == null) {
            c.truncated = true;
            break;
        }
        const off_ptr = c.pointerAt(base);
        out.appendAssumeCapacity(.{
            .name = c.stringSlot(base +| 8),
            .type = c.stringSlot(base +| 16),
            .offset = if (off_ptr) |p| c.img.u32AtVm(p) else null,
            .alignment = c.u32At(base +| 24) orelse 0,
            .size = c.u32At(base +| 28) orelse 0,
        });
    }
    return out.toOwnedSlice(c.arena);
}

/// property_list_t: uint32 entsize, uint32 count, then `count` property_t (name, attributes).
fn propertyList(c: *Ctx, list_addr_opt: ?u64) Allocator.Error![]const Property {
    const list = list_addr_opt orelse return &.{};
    if (list == 0) return &.{};
    const entsize = c.u32At(list) orelse return &.{};
    const declared = c.u32At(list +| 4) orelse return &.{};
    if (entsize == 0) return &.{};
    const count = clampCount(c, list, declared, entsize, c.limits.max_objc_methods_per_list, "property_list_t");
    var out: std.ArrayList(Property) = .empty;
    try out.ensureTotalCapacity(c.arena, count);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const base = list +| 8 +| @as(u64, i) *| entsize;
        if (c.img.bytesAtVm(base, entsize) == null) {
            c.truncated = true;
            break;
        }
        out.appendAssumeCapacity(.{ .name = c.stringSlot(base), .attributes = c.stringSlot(base +| 8) });
    }
    return out.toOwnedSlice(c.arena);
}

/// protocol_list_t: uintptr count, then `count` protocol_t pointers. `depth` bounds nesting.
fn protocolNames(c: *Ctx, list_addr_opt: ?u64, depth: u32) Allocator.Error![]const []const u8 {
    const list = list_addr_opt orelse return &.{};
    if (list == 0 or depth > c.limits.max_objc_protocol_depth) return &.{};
    const declared64 = c.img.u64AtVm(list) orelse return &.{};
    const declared: u32 = @intCast(@min(declared64, std.math.maxInt(u32)));
    const count = clampCount(c, list, declared, 8, c.limits.max_objc_methods_per_list, "protocol_list_t");
    var out: std.ArrayList([]const u8) = .empty;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const slot_addr = list +| 8 +| i *| 8;
        const name = switch (c.slot(slot_addr)) {
            .bind => |sym| stripClassSymbol(sym),
            .addr => |a| protocolName(c, a),
            .none => "",
        };
        if (name.len != 0) try out.append(c.arena, name);
    }
    return out.toOwnedSlice(c.arena);
}

fn protocolName(c: *Ctx, addr: u64) []const u8 {
    return c.stringSlot(addr +| 8); // protocol_t.mangledName
}

fn parseProtocol(c: *Ctx, addr: u64) Allocator.Error!?Protocol {
    const g = try c.visited.getOrPut(c.arena, addr);
    if (g.found_existing) return null;
    const name = protocolName(c, addr);
    if (name.len == 0) return null;
    return .{
        .address = addr,
        .name = name,
        .protocols = try protocolNames(c, c.pointerAt(addr +| 16), 1),
        .instance_methods = try methodList(c, c.pointerAt(addr +| 24), false),
        .class_methods = try methodList(c, c.pointerAt(addr +| 32), true),
        .optional_instance_methods = try methodList(c, c.pointerAt(addr +| 40), false),
        .optional_class_methods = try methodList(c, c.pointerAt(addr +| 48), true),
    };
}

/// category_t: name, cls, instanceMethods, classMethods, protocols, instanceProperties.
fn parseCategory(c: *Ctx, addr: u64) Allocator.Error!?Category {
    const name = c.stringSlot(addr);
    if (name.len == 0) return null;
    var class_name: []const u8 = "";
    var external = false;
    switch (c.slot(addr +| 8)) {
        .bind => |sym| {
            class_name = stripClassSymbol(sym);
            external = true;
        },
        .addr => |a| class_name = classNameAt(c, a) orelse "",
        .none => {},
    }
    return .{
        .address = addr,
        .name = name,
        .class_name = class_name,
        .class_external = external,
        .instance_methods = try methodList(c, c.pointerAt(addr +| 16), false),
        .class_methods = try methodList(c, c.pointerAt(addr +| 24), true),
        .protocols = try protocolNames(c, c.pointerAt(addr +| 32), 1),
        .properties = try propertyList(c, c.pointerAt(addr +| 40)),
    };
}

/// `__TEXT,__objc_stubs`: fixed-stride `objc_msgSend` trampolines whose first two instructions are
/// `adrp xN, <selref>@PAGE` / `ldr xN, [xN, <selref>@PAGEOFF]`. The selref slot names the selector.
fn parseStubs(c: *Ctx) Allocator.Error![]const Stub {
    const s = c.img.sectionByClass(.objc_stubs) orelse return &.{};
    const stride: u64 = extra.objc.objc_stub_size;
    if (s.size % stride != 0) {
        c.note(.unknown_value, s.offset, "__objc_stubs size {d} is not a multiple of {d} (-objc_stubs_small?)", .{ s.size, stride });
    }
    const r = c.img.sectionReader(s) orelse return &.{};
    var out: std.ArrayList(Stub) = .empty;
    var i: u64 = 0;
    while (i + stride <= r.len()) : (i += stride) {
        const addr = s.addr +| i;
        const head = r.sliceAt(i, stride) orelse continue;
        const selref = adrpLdrTarget(head, addr) orelse continue;
        const name = c.stringSlot(selref);
        if (name.len == 0) continue;
        try out.append(c.arena, .{ .addr = addr, .selector = name });
    }
    return out.toOwnedSlice(c.arena);
}

/// Decodes `adrp Xd, page` + `ldr Xt, [Xd, #imm12]` at the head of a stub -> the addressed slot.
fn adrpLdrTarget(bytes: []const u8, addr: u64) ?u64 {
    if (bytes.len < 8) return null;
    const w0 = std.mem.readInt(u32, bytes[0..4], .little);
    const w1 = std.mem.readInt(u32, bytes[4..8], .little);
    if (w0 & 0x9f00_0000 != 0x9000_0000) return null; // ADRP Xd, #imm21<<12
    if (w1 & 0xffc0_0000 != 0xf940_0000) return null; // LDR Xt, [Xn, #imm12] (64-bit, unsigned offset)
    if ((w1 >> 5) & 0x1f != w0 & 0x1f) return null; // the ldr must use the adrp's destination as base
    const immlo: u64 = (w0 >> 29) & 0x3;
    const immhi: u64 = (w0 >> 5) & 0x7ffff;
    const page_delta = signExtend((immhi << 2) | immlo, 21) *% 0x1000;
    const page: u64 = @bitCast(@as(i64, @bitCast(addr & ~@as(u64, 0xfff))) +% page_delta);
    const imm12: u64 = (w1 >> 10) & 0xfff;
    return page +% imm12 *% 8;
}

fn signExtend(value: u64, comptime bits: u6) i64 {
    const shift: u6 = @intCast(64 - @as(u7, bits));
    return @as(i64, @bitCast(value << shift)) >> shift;
}

pub const Imp = struct { imp: u64, name: []const u8 }; // "-[Class sel]" / "+[Class sel]"
/// Every method implementation address paired with its `-[Class selector]` display name.
pub fn methodImps(arena: Allocator, info: *const ObjcInfo) Allocator.Error![]const Imp {
    var out: std.ArrayList(Imp) = .empty;
    for (info.classes) |cl| {
        for (cl.methods) |m| try appendImp(arena, &out, m, cl.name);
        for (cl.class_methods) |m| try appendImp(arena, &out, m, cl.name);
    }
    for (info.categories) |cat| {
        for (cat.instance_methods) |m| try appendImp(arena, &out, m, cat.class_name);
        for (cat.class_methods) |m| try appendImp(arena, &out, m, cat.class_name);
    }
    return out.toOwnedSlice(arena);
}

fn appendImp(arena: Allocator, out: *std.ArrayList(Imp), m: Method, class_name: []const u8) Allocator.Error!void {
    if (m.imp == 0 or m.name.len == 0) return;
    try out.append(arena, .{ .imp = m.imp, .name = try std.fmt.allocPrint(arena, "{c}[{s} {s}]", .{ @as(u8, if (m.is_class_method) '+' else '-'), class_name, m.name }) });
}

// ---------------------------------------------------------------------------------------------
// tests — hermetic: a hand-built image whose slots hold plain vmaddrs (legacy layout), so the
// parser is exercised end to end without any dyld data. Corpus checks live in tests/facts.
// ---------------------------------------------------------------------------------------------
const testing = std.testing;

test "objc: class symbol decoration is stripped" {
    try testing.expectEqualStrings("NSObject", stripClassSymbol("_OBJC_CLASS_$_NSObject"));
    try testing.expectEqualStrings("NSDocument", stripClassSymbol("_OBJC_METACLASS_$_NSDocument"));
    try testing.expectEqualStrings("NSCopying", stripClassSymbol("__OBJC_PROTOCOL_$_NSCopying"));
    try testing.expectEqualStrings("_plain", stripClassSymbol("_plain"));
}

test "objc: adrp/ldr stub decoding reproduces hello-objc's first stub" {
    // 00000001000012c0  f0000021 f941c021  =  adrp x1, 7 ; 0x100008000 / ldr x1, [x1, #0x380]
    const bytes = [_]u8{ 0x21, 0x00, 0x00, 0xf0, 0x21, 0xc0, 0x41, 0xf9 };
    try testing.expectEqual(@as(?u64, 0x100008380), adrpLdrTarget(&bytes, 0x1000012c0));
    // negative page delta: adrp x16, -1 page
    const back = [_]u8{ 0xf0, 0xff, 0xff, 0xf0, 0x10, 0x02, 0x40, 0xf9 };
    try testing.expectEqual(@as(?u64, 0x100000000 + 0x00), adrpLdrTarget(&back, 0x100001000).?);
    try testing.expect(adrpLdrTarget(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, 0x1000) == null); // not an adrp
    try testing.expect(adrpLdrTarget(&[_]u8{ 0x21, 0x00, 0x00, 0xf0 }, 0x1000) == null); // truncated
    // ldr whose base register is not the adrp destination
    const mismatch = [_]u8{ 0x21, 0x00, 0x00, 0xf0, 0x42, 0xc0, 0x41, 0xf9 };
    try testing.expect(adrpLdrTarget(&mismatch, 0x1000012c0) == null);
}

/// Little-endian buffer builder for the synthetic ObjC image (vm address == 0x100000000 + offset).
const TB = struct {
    arena: Allocator,
    d: std.ArrayList(u8) = .empty,
    const base: u64 = 0x100000000;
    fn addr(t: *TB) u64 {
        return base + t.d.items.len;
    }
    fn pad8(t: *TB) !void {
        while (t.d.items.len % 8 != 0) try t.d.append(t.arena, 0);
    }
    fn cstr(t: *TB, s: []const u8) !u64 {
        const a = t.addr();
        try t.d.appendSlice(t.arena, s);
        try t.d.append(t.arena, 0);
        return a;
    }
    fn p(t: *TB, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try t.d.appendSlice(t.arena, &b);
    }
    fn w(t: *TB, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try t.d.appendSlice(t.arena, &b);
    }
    fn methodList(t: *TB, entries: []const [3]u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.w(24);
        try t.w(@intCast(entries.len));
        for (entries) |e| {
            try t.p(e[0]);
            try t.p(e[1]);
            try t.p(e[2]);
        }
        return a;
    }
    fn ivarList(t: *TB, entries: []const [3]u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.w(32);
        try t.w(@intCast(entries.len));
        for (entries) |e| {
            try t.p(e[0]); // offset variable
            try t.p(e[1]); // name
            try t.p(e[2]); // type
            try t.w(3); // alignment (log2)
            try t.w(8); // size
        }
        return a;
    }
    fn propertyList(t: *TB, entries: []const [2]u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.w(16);
        try t.w(@intCast(entries.len));
        for (entries) |e| {
            try t.p(e[0]);
            try t.p(e[1]);
        }
        return a;
    }
    fn protocolList(t: *TB, entries: []const u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.p(entries.len);
        for (entries) |e| try t.p(e);
        return a;
    }
    fn ro(t: *TB, flags: u32, name: u64, methods: u64, protocols: u64, ivars: u64, properties: u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.w(flags);
        try t.w(8); // instanceStart
        try t.w(24); // instanceSize
        try t.w(0); // reserved
        try t.p(0); // ivarLayout
        try t.p(name);
        try t.p(methods);
        try t.p(protocols);
        try t.p(ivars);
        try t.p(0); // weakIvarLayout
        try t.p(properties);
        return a;
    }
    fn class(t: *TB, isa: u64, superclass: u64, data: u64) !u64 {
        try t.pad8();
        const a = t.addr();
        try t.p(isa);
        try t.p(superclass);
        try t.p(0); // cache
        try t.p(0); // vtable
        try t.p(data);
        return a;
    }
};

fn section(arena: Allocator, index: u16, seg: []const u8, name: []const u8, cls: @FieldType(Section, "class"), from: u64, to: u64) !Section {
    _ = arena;
    return .{
        .index = index,
        .segment = 0,
        .sectname = name,
        .segname = seg,
        .addr = TB.base + from,
        .size = to - from,
        .offset = @intCast(from),
        .@"align" = 3,
        .reloff = 0,
        .nreloc = 0,
        .flags = if (cls == .objc_methname) 2 else 0,
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
        .class = cls,
    };
}

fn finish(arena: Allocator, t: *TB, sects: []const Section) !*Image {
    const segs = try arena.alloc(image_mod.Segment, 1);
    segs[0] = .{
        .index = 0,
        .name = "__DATA",
        .vmaddr = TB.base,
        .vmsize = t.d.items.len,
        .fileoff = 0,
        .filesize = t.d.items.len,
        .maxprot = 3,
        .initprot = 3,
        .nsects = @intCast(sects.len),
        .flags = 0,
        .cmd_offset = 0,
        .first_section = 0,
        .section_count = @intCast(sects.len),
        .file_range_truncated = false,
    };
    const img = try arena.create(Image);
    img.* = .{
        .r = .{ .bytes = t.d.items, .base = 0 },
        .slice_offset = 0,
        .index = 0,
        .arch = .{ .cputype = 0x0100000c, .cpusubtype = 0, .name = .arm64, .ptr_size = 8, .is_64 = true, .is_arm64e = false, .ptrauth_version = 0, .caps = 0 },
        .hdr = .{ .magic = std.macho.MH_MAGIC_64, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = std.macho.MH_EXECUTE, .ncmds = 0, .sizeofcmds = 0, .flags = 0, .header_size = 32 },
        .cmds = &.{},
        .segments = segs,
        .sections = sects,
        .image_base = TB.base,
        .text_seg = null,
        .linkedit_seg = null,
        .cmds_truncated = false,
        .ncmds_parsed = 0,
    };
    return img;
}

/// MachreAnimal (1 method + 1 class method, 1 ivar, 1 property, protocol MachreGreeter),
/// MachreDog : MachreAnimal, category MachreAnimal(MachreExtras), 2 selrefs, 1 classref, 1 stub.
fn buildTestImage(arena: Allocator) !*Image {
    var t: TB = .{ .arena = arena };
    var sects: std.ArrayList(Section) = .empty;

    // --- __TEXT,__objc_methname: every name string ---------------------------------------------
    const str_from: u64 = 0;
    const s_describe = try t.cstr("describe");
    const s_population = try t.cstr("population");
    const s_greet = try t.cstr("greet:");
    const s_shout = try t.cstr("shout");
    const s_animal = try t.cstr("MachreAnimal");
    const s_dog = try t.cstr("MachreDog");
    const s_extras = try t.cstr("MachreExtras");
    const s_greeter = try t.cstr("MachreGreeter");
    const s_ivar = try t.cstr("_name");
    const s_ivar_type = try t.cstr("@\"NSString\"");
    const s_prop = try t.cstr("name");
    const s_prop_attr = try t.cstr("T@\"NSString\",C,N,V_name");
    const s_type_obj = try t.cstr("@16@0:8");
    const s_type_void = try t.cstr("v16@0:8");
    try t.pad8();
    try sects.append(arena, try section(arena, 1, "__TEXT", "__objc_methname", .objc_methname, str_from, t.d.items.len));

    // --- __DATA,__objc_ivar: the ivar offset variable ------------------------------------------
    const ivar_from = t.d.items.len;
    const ivar_off_var = t.addr();
    try t.w(8);
    try t.pad8();
    try sects.append(arena, try section(arena, 2, "__DATA", "__objc_ivar", .objc_ivar, ivar_from, t.d.items.len));

    // --- __DATA,__objc_const: lists, class_ro_t, protocol_t ------------------------------------
    const const_from = t.d.items.len;
    const animal_methods = try t.methodList(&.{.{ s_describe, s_type_obj, 0x100000cbc }});
    const animal_class_methods = try t.methodList(&.{.{ s_population, s_type_obj, 0x100000d58 }});
    const animal_ivars = try t.ivarList(&.{.{ ivar_off_var, s_ivar, s_ivar_type }});
    const animal_props = try t.propertyList(&.{.{ s_prop, s_prop_attr }});
    const greeter_methods = try t.methodList(&.{.{ s_greet, s_type_void, 0 }});
    const proto_greeter = blk: {
        try t.pad8();
        const a = t.addr();
        try t.p(0); // isa
        try t.p(s_greeter); // mangledName
        try t.p(0); // protocols
        try t.p(greeter_methods); // instanceMethods
        try t.p(0); // classMethods
        try t.p(0); // optionalInstanceMethods
        try t.p(0); // optionalClassMethods
        try t.p(0); // instanceProperties
        try t.w(96); // size
        try t.w(0); // flags
        try t.p(0); // extendedMethodTypes
        try t.p(0); // demangledName
        try t.p(0); // classProperties
        break :blk a;
    };
    const animal_protos = try t.protocolList(&.{proto_greeter});
    const animal_ro = try t.ro(0, s_animal, animal_methods, animal_protos, animal_ivars, animal_props);
    const animal_meta_ro = try t.ro(extra.objc.RO_META, s_animal, animal_class_methods, 0, 0, 0);
    const dog_ro = try t.ro(0, s_dog, 0, 0, 0, 0);
    const dog_meta_ro = try t.ro(extra.objc.RO_META, s_dog, 0, 0, 0, 0);
    const cat_methods = try t.methodList(&.{.{ s_shout, s_type_void, 0x100001080 }});
    try sects.append(arena, try section(arena, 3, "__DATA", "__objc_const", .objc_const, const_from, t.d.items.len));

    // --- __DATA,__objc_data: objc_class records ------------------------------------------------
    const data_from = t.d.items.len;
    const animal_meta = try t.class(0, 0, animal_meta_ro);
    const animal = try t.class(animal_meta, 0, animal_ro);
    const dog_meta = try t.class(0, animal_meta, dog_meta_ro);
    const dog = try t.class(dog_meta, animal, dog_ro);
    const category = blk: {
        try t.pad8();
        const a = t.addr();
        try t.p(s_extras); // name
        try t.p(animal); // cls
        try t.p(cat_methods); // instanceMethods
        try t.p(0); // classMethods
        try t.p(0); // protocols
        try t.p(0); // instanceProperties
        break :blk a;
    };
    try sects.append(arena, try section(arena, 4, "__DATA", "__objc_data", .objc_data, data_from, t.d.items.len));

    // --- __DATA_CONST list sections ------------------------------------------------------------
    const classlist_from = t.d.items.len;
    try t.p(animal);
    try t.p(dog);
    try sects.append(arena, try section(arena, 5, "__DATA_CONST", "__objc_classlist", .objc_classlist, classlist_from, t.d.items.len));
    const catlist_from = t.d.items.len;
    try t.p(category);
    try sects.append(arena, try section(arena, 6, "__DATA_CONST", "__objc_catlist", .objc_catlist, catlist_from, t.d.items.len));
    const protolist_from = t.d.items.len;
    try t.p(proto_greeter);
    try sects.append(arena, try section(arena, 7, "__DATA_CONST", "__objc_protolist", .objc_protolist, protolist_from, t.d.items.len));
    const imageinfo_from = t.d.items.len;
    try t.w(0);
    try t.w(extra.objc.image_info_has_category_class_properties);
    try sects.append(arena, try section(arena, 8, "__DATA_CONST", "__objc_imageinfo", .objc_imageinfo, imageinfo_from, t.d.items.len));

    // --- __DATA,__objc_selrefs / __objc_classrefs ----------------------------------------------
    const selrefs_from = t.d.items.len;
    const selref0 = t.addr();
    try t.p(s_describe);
    try t.p(s_population);
    try sects.append(arena, try section(arena, 9, "__DATA", "__objc_selrefs", .objc_selrefs, selrefs_from, t.d.items.len));
    const classrefs_from = t.d.items.len;
    try t.p(animal);
    try sects.append(arena, try section(arena, 10, "__DATA", "__objc_classrefs", .objc_classrefs, classrefs_from, t.d.items.len));

    // --- __TEXT,__objc_stubs: adrp/ldr pointing at selref[0] -----------------------------------
    while ((TB.base + t.d.items.len) % 0x1000 != 0) try t.d.append(arena, 0); // page-align the stub
    const stubs_from = t.d.items.len;
    const stub_addr = t.addr();
    const page_delta: i64 = @as(i64, @bitCast(selref0 & ~@as(u64, 0xfff))) - @as(i64, @bitCast(stub_addr & ~@as(u64, 0xfff)));
    const imm21: u32 = @truncate(@as(u64, @bitCast(@divExact(page_delta, 0x1000))) & 0x1fffff);
    try t.w(0x9000_0001 | ((imm21 & 0x3) << 29) | ((imm21 >> 2) << 5)); // adrp x1, page
    try t.w(0xf940_0021 | (@as(u32, @intCast((selref0 & 0xfff) / 8)) << 10)); // ldr x1, [x1, #off]
    var k: usize = 0;
    while (k < 6) : (k += 1) try t.w(0xd4200020); // brk #1 padding to 32 bytes
    try sects.append(arena, try section(arena, 11, "__TEXT", "__objc_stubs", .objc_stubs, stubs_from, t.d.items.len));

    return finish(arena, &t, try sects.toOwnedSlice(arena));
}

test "objc: hand-built image yields classes, methods, ivars, properties, protocols and stubs" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try buildTestImage(arena);
    var diags = Diagnostics.init(arena, 64);
    const info = try parse(arena, img, &FixupTable.empty, &SymbolTable.empty, &Limits.default, &diags);

    try testing.expect(info.present and !info.truncated);
    try testing.expectEqual(@as(usize, 2), info.classes.len);
    const animal = info.classByName("MachreAnimal").?;
    try testing.expectEqual(@as(usize, 1), animal.methods.len);
    try testing.expectEqualStrings("describe", animal.methods[0].name);
    try testing.expectEqualStrings("@16@0:8", animal.methods[0].types);
    try testing.expectEqual(@as(u64, 0x100000cbc), animal.methods[0].imp);
    try testing.expect(!animal.methods[0].is_class_method and !animal.methods[0].small);
    try testing.expectEqual(@as(usize, 1), animal.class_methods.len);
    try testing.expectEqualStrings("population", animal.class_methods[0].name);
    try testing.expect(animal.class_methods[0].is_class_method);
    try testing.expectEqual(@as(usize, 1), animal.ivars.len);
    try testing.expectEqualStrings("_name", animal.ivars[0].name);
    try testing.expectEqualStrings("@\"NSString\"", animal.ivars[0].type);
    try testing.expectEqual(@as(?u32, 8), animal.ivars[0].offset);
    try testing.expectEqual(@as(u32, 3), animal.ivars[0].alignment);
    try testing.expectEqual(@as(usize, 1), animal.properties.len);
    try testing.expectEqualStrings("name", animal.properties[0].name);
    try testing.expectEqualStrings("T@\"NSString\",C,N,V_name", animal.properties[0].attributes);
    try testing.expectEqual(@as(usize, 1), animal.protocols.len);
    try testing.expectEqualStrings("MachreGreeter", animal.protocols[0]);
    try testing.expect(animal.superclass.kind == .none and !animal.is_meta and !animal.is_swift);

    const dog = info.classByName("MachreDog").?;
    try testing.expect(dog.superclass.kind == .local);
    try testing.expectEqualStrings("MachreAnimal", dog.superclass.name.?);

    try testing.expectEqual(@as(usize, 1), info.categories.len);
    try testing.expectEqualStrings("MachreExtras", info.categories[0].name);
    try testing.expectEqualStrings("MachreAnimal", info.categories[0].class_name);
    try testing.expect(!info.categories[0].class_external);
    try testing.expectEqual(@as(usize, 1), info.categories[0].instance_methods.len);
    try testing.expectEqualStrings("shout", info.categories[0].instance_methods[0].name);

    try testing.expectEqual(@as(usize, 1), info.protocols.len);
    try testing.expectEqualStrings("MachreGreeter", info.protocols[0].name);
    try testing.expectEqual(@as(usize, 1), info.protocols[0].instance_methods.len);
    try testing.expectEqualStrings("greet:", info.protocols[0].instance_methods[0].name);

    try testing.expectEqual(@as(usize, 2), info.selectors.len);
    try testing.expectEqualStrings("describe", info.selectors[0].name);
    try testing.expectEqualStrings("population", info.selectors[1].name);
    try testing.expectEqual(@as(usize, 1), info.classrefs.len);
    try testing.expectEqualStrings("MachreAnimal", info.classrefs[0].name);
    try testing.expect(!info.classrefs[0].external);
    try testing.expectEqual(@as(usize, 1), info.stubs.len);
    try testing.expectEqualStrings("describe", info.stubs[0].selector);

    const ii = info.image_info.?;
    try testing.expectEqual(@as(u32, 0), ii.version);
    try testing.expect(ii.has_category_class_properties and !ii.is_swift);

    const imps = try methodImps(arena, &info);
    var names: std.ArrayList([]const u8) = .empty;
    for (imps) |i| try names.append(arena, i.name);
    try testing.expectEqual(@as(usize, 3), names.items.len);
    try testing.expectEqualStrings("-[MachreAnimal describe]", names.items[0]);
    try testing.expectEqualStrings("+[MachreAnimal population]", names.items[1]);
    try testing.expectEqualStrings("-[MachreAnimal shout]", names.items[2]);
}

test "objc: small (relative) method lists decode" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var t: TB = .{ .arena = arena };
    var sects: std.ArrayList(Section) = .empty;
    const s_sel = try t.cstr("wave");
    const s_types = try t.cstr("v16@0:8");
    const s_name = try t.cstr("Small");
    try t.pad8();
    try sects.append(arena, try section(arena, 1, "__TEXT", "__objc_methname", .objc_methname, 0, t.d.items.len));
    const const_from = t.d.items.len;
    const selref = t.addr();
    try t.p(s_sel);
    try sects.append(arena, try section(arena, 2, "__DATA", "__objc_selrefs", .objc_selrefs, const_from, t.d.items.len));
    const rest_from = t.d.items.len;
    try t.pad8();
    const list = t.addr();
    try t.w(12 | extra.objc.method_list_small_flag);
    try t.w(1);
    const e0 = t.addr();
    try t.w(@bitCast(@as(i32, @intCast(@as(i64, @bitCast(selref)) - @as(i64, @bitCast(e0))))));
    try t.w(@bitCast(@as(i32, @intCast(@as(i64, @bitCast(s_types)) - @as(i64, @bitCast(e0 + 4))))));
    try t.w(@bitCast(@as(i32, -0x40)));
    const ro_addr = try t.ro(0, s_name, list, 0, 0, 0);
    const cls = try t.class(0, 0, ro_addr);
    try sects.append(arena, try section(arena, 3, "__DATA", "__objc_const", .objc_const, rest_from, t.d.items.len));
    const cl_from = t.d.items.len;
    try t.p(cls);
    try sects.append(arena, try section(arena, 4, "__DATA_CONST", "__objc_classlist", .objc_classlist, cl_from, t.d.items.len));
    const img = try finish(arena, &t, try sects.toOwnedSlice(arena));

    var diags = Diagnostics.init(arena, 16);
    const info = try parse(arena, img, &FixupTable.empty, &SymbolTable.empty, &Limits.default, &diags);
    try testing.expectEqual(@as(usize, 1), info.classes.len);
    const m = info.classes[0].methods;
    try testing.expectEqual(@as(usize, 1), m.len);
    try testing.expect(m[0].small);
    try testing.expectEqualStrings("wave", m[0].name);
    try testing.expectEqualStrings("v16@0:8", m[0].types);
    try testing.expectEqual(e0 + 8 - 0x40, m[0].imp);
}

test "objc: hasObjc is false without ObjC sections" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try buildTestImage(arena);
    const bare = try arena.create(Image);
    bare.* = img.*;
    bare.sections = &.{};
    try testing.expect(!hasObjc(bare));
    var diags = Diagnostics.init(arena, 8);
    const info = try parse(arena, bare, &FixupTable.empty, &SymbolTable.empty, &Limits.default, &diags);
    try testing.expect(!info.present);
    try testing.expectEqual(@as(usize, 0), info.classes.len);
}

test "objc: paranoid limits clamp and every truncation of the image still parses" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try buildTestImage(arena);
    var tiny = Limits.paranoid;
    tiny.max_objc_total_methods = 1;
    var diags = Diagnostics.init(arena, 64);
    const info = try parse(arena, img, &FixupTable.empty, &SymbolTable.empty, &tiny, &diags);
    try testing.expect(info.truncated);

    var n: usize = 0;
    while (n <= img.r.len()) : (n += 1) {
        const cut = try arena.create(Image);
        cut.* = img.*;
        cut.r = img.r.sub(0, n) orelse continue;
        var d2 = Diagnostics.init(arena, 16);
        const res = try parse(arena, cut, &FixupTable.empty, &SymbolTable.empty, &Limits.paranoid, &d2);
        for (res.classes) |cl| try testing.expect(cl.name.len <= Limits.paranoid.max_symbol_name);
    }
}

test "objc: a class list that points at itself terminates" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var t: TB = .{ .arena = arena };
    var sects: std.ArrayList(Section) = .empty;
    const s_name = try t.cstr("Loop");
    try t.pad8();
    try sects.append(arena, try section(arena, 1, "__TEXT", "__objc_methname", .objc_methname, 0, t.d.items.len));
    const from = t.d.items.len;
    const ro_addr = try t.ro(0, s_name, 0, 0, 0, 0);
    const cls = try t.class(0, 0, ro_addr);
    // isa and superclass point at the class itself
    const cls_off: usize = @intCast(cls - TB.base);
    std.mem.writeInt(u64, t.d.items[cls_off..][0..8], cls, .little);
    std.mem.writeInt(u64, t.d.items[cls_off + 8 ..][0..8], cls, .little);
    try sects.append(arena, try section(arena, 2, "__DATA", "__objc_const", .objc_const, from, t.d.items.len));
    const cl_from = t.d.items.len;
    try t.p(cls);
    try t.p(cls); // listed twice: the visited set must drop the duplicate
    try sects.append(arena, try section(arena, 3, "__DATA_CONST", "__objc_classlist", .objc_classlist, cl_from, t.d.items.len));
    const img = try finish(arena, &t, try sects.toOwnedSlice(arena));

    var diags = Diagnostics.init(arena, 16);
    const info = try parse(arena, img, &FixupTable.empty, &SymbolTable.empty, &Limits.default, &diags);
    try testing.expectEqual(@as(usize, 1), info.classes.len);
    try testing.expectEqualStrings("Loop", info.classes[0].name);
    try testing.expect(info.classes[0].superclass.kind == .local);
}
