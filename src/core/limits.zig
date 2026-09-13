//! core/limits.zig — every cap in one place + the byte-budgeted allocator wrapper.
//! Imports: std only.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Limits = struct {
    max_file_size: u64 = 1 << 31,
    max_fat_arches: u32 = 32,
    max_load_commands: u32 = 4096,
    max_sizeofcmds: u32 = 1 << 20,
    max_sections: u32 = 4096,
    max_symbols: u32 = 1 << 22,
    max_strtab: u32 = 1 << 28,
    max_indirect_symbols: u32 = 1 << 22,
    max_symbol_name: u32 = 4096,
    max_dylibs: u32 = 1024,
    max_rpaths: u32 = 256,
    max_fixups: u32 = 1 << 22,
    max_chain_steps_per_page: u32 = 1 << 16,
    max_imports: u32 = 1 << 20,
    max_exports: u32 = 1 << 20,
    max_trie_nodes: u32 = 1 << 20,
    max_trie_depth: u32 = 512,
    max_opcode_bytes: u32 = 1 << 26,
    max_function_starts: u32 = 1 << 20,
    max_data_in_code: u32 = 1 << 20,
    max_superblob_slots: u32 = 64,
    max_blob_len: u32 = 1 << 24,
    max_code_slots: u32 = 1 << 20,
    max_special_slots: u32 = 16,
    max_requirement_ops: u32 = 4096,
    max_requirement_depth: u32 = 64,
    max_der_depth: u32 = 32,
    max_der_nodes: u32 = 1 << 16,
    max_asn1_depth: u32 = 32,
    max_asn1_nodes: u32 = 1 << 16,
    max_cms_certs: u32 = 32,
    max_entitlement_keys: u32 = 4096,
    max_objc_classes: u32 = 1 << 16,
    max_objc_methods_per_list: u32 = 1 << 14,
    max_objc_total_methods: u32 = 1 << 20,
    max_objc_protocol_depth: u32 = 16,
    max_strings: u32 = 1 << 20,
    max_string_len: u32 = 1 << 16,
    min_string_len: u32 = 4,
    max_plist_objects: u32 = 1 << 20,
    max_plist_depth: u32 = 64,
    max_plist_bytes: u32 = 1 << 26,
    max_xml_bytes: u32 = 1 << 26,
    max_bundle_entries: u32 = 1 << 16,
    max_bundle_depth: u32 = 16,
    max_nested_code: u32 = 1024,
    max_disasm_bytes: u32 = 1 << 26,
    max_instructions: u32 = 1 << 22,
    max_functions: u32 = 1 << 20,
    max_xrefs: u32 = 1 << 22,
    max_diagnostics: u32 = 512,
    max_arena_bytes: u64 = 1 << 31,

    pub const default: Limits = .{};
    /// Tiny caps so pathological loops terminate instantly (fuzzers, --paranoid).
    pub const paranoid: Limits = .{
        .max_file_size = 1 << 24,
        .max_load_commands = 256,
        .max_sections = 256,
        .max_symbols = 1 << 12,
        .max_fixups = 1 << 12,
        .max_imports = 1 << 12,
        .max_exports = 1 << 12,
        .max_trie_nodes = 1 << 10,
        .max_code_slots = 1 << 12,
        .max_objc_classes = 1 << 10,
        .max_strings = 1 << 12,
        .max_plist_objects = 1 << 12,
        .max_instructions = 1 << 12,
        .max_functions = 1 << 12,
        .max_xrefs = 1 << 12,
        .max_arena_bytes = 1 << 26,
    };
};

/// std.mem.Allocator wrapper that fails with OutOfMemory once `used` would exceed `budget`.
pub const BudgetAllocator = struct {
    child: Allocator,
    budget: u64,
    used: u64 = 0,
    peak: u64 = 0,
    failures: u32 = 0,

    pub fn init(child: Allocator, budget: u64) BudgetAllocator {
        return .{ .child = child, .budget = budget };
    }
    pub fn allocator(b: *BudgetAllocator) Allocator {
        return .{ .ptr = b, .vtable = &vtable };
    }
    pub fn remaining(b: *const BudgetAllocator) u64 {
        return b.budget -| b.used;
    }
    fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (n > b.remaining()) {
            b.failures += 1;
            return null;
        }
        const p = b.child.rawAlloc(n, alignment, ret_addr) orelse {
            b.failures += 1;
            return null;
        };
        b.used += n;
        b.peak = @max(b.peak, b.used);
        return p;
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > b.remaining()) {
            b.failures += 1;
            return false;
        }
        if (!b.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        b.used = b.used - memory.len + new_len;
        b.peak = @max(b.peak, b.used);
        return true;
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > b.remaining()) {
            b.failures += 1;
            return null;
        }
        const p = b.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        b.used = b.used - memory.len + new_len;
        b.peak = @max(b.peak, b.used);
        return p;
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const b: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        b.child.rawFree(memory, alignment, ret_addr);
        b.used -|= memory.len;
    }
    pub const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
};

test "limits: budget allocator enforces the cap and tracks usage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var budget = BudgetAllocator.init(arena.allocator(), 1024);
    const a = budget.allocator();
    const first = try a.alloc(u8, 600);
    try std.testing.expectEqual(@as(u64, 600), budget.used);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 600));
    try std.testing.expectEqual(@as(u32, 1), budget.failures);
    const second = try a.alloc(u8, 400);
    try std.testing.expectEqual(@as(u64, 1000), budget.peak);
    a.free(second);
    a.free(first);
    try std.testing.expect(budget.used <= 1000);
    try std.testing.expect(Limits.default.max_symbols > Limits.paranoid.max_symbols);
}
