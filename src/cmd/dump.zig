//! cmd/dump.zig — hexdump of a section or vm/file range. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;

pub const command: Command = .{
    .name = "dump",
    .summary = "hexdump of a section or vm/file range",
    .run = run,
    .flags = &.{ "--section=", "--addr=", "--offset=", "--length=" },
    .aliases = &.{},
    .needs_macho = true,
};

/// `vm_size` is the section size in memory; for a zero-fill section `bytes` is empty and only
/// `vm_size` is meaningful.
const Range = struct { segname: ?[]const u8, sectname: ?[]const u8, address: ?u64, offset: u64, bytes: []const u8, zerofill: bool = false, vm_size: u64 = 0 };

/// Parses "<start>[+<len>]" (base 0).
fn parseRange(s: []const u8) ?struct { start: u64, len: ?u64 } {
    if (std.mem.findScalar(u8, s, '+')) |p| {
        const start = std.fmt.parseInt(u64, s[0..p], 0) catch return null;
        const len = std.fmt.parseInt(u64, s[p + 1 ..], 0) catch return null;
        return .{ .start = start, .len = len };
    }
    const start = std.fmt.parseInt(u64, s, 0) catch return null;
    return .{ .start = start, .len = null };
}

fn resolve(ctx: *Context, img: *const Image) !?Range {
    const length: u64 = (ctx.args.valueInt(u64, "--length") catch null) orelse 256;
    if (ctx.args.value("--section")) |spec| {
        const comma = std.mem.findScalar(u8, spec, ',') orelse {
            ctx.diags.err(.cli, .unknown_value, null, "--section expects <segname>,<sectname>", .{});
            return null;
        };
        const sect = img.sectionByName(spec[0..comma], spec[comma + 1 ..]) orelse {
            ctx.diags.err(.cli, .not_available, null, "section {s} not found", .{spec});
            return null;
        };
        const r = img.sectionReader(sect) orelse {
            ctx.diags.err(.segments, .offset_past_eof, sect.offset, "section {s} lies outside the slice", .{spec});
            return null;
        };
        const n = if (ctx.args.value("--length") != null) @min(length, r.len()) else r.len();
        return .{ .segname = sect.segname, .sectname = sect.sectname, .address = sect.addr, .offset = sect.offset, .bytes = r.sliceAt(0, n).?, .zerofill = sect.isZerofill(), .vm_size = sect.size };
    }
    if (ctx.args.value("--addr")) |spec| {
        const pr = parseRange(spec) orelse {
            ctx.diags.err(.cli, .unknown_value, null, "--addr: invalid range '{s}'", .{spec});
            return null;
        };
        const want = pr.len orelse length;
        const vb = img.bytesAtVm(pr.start, want) orelse {
            ctx.diags.err(.cli, .not_available, null, "address 0x{x} is not mapped by any segment", .{pr.start});
            return null;
        };
        if (vb.bytes.len == 0) {
            ctx.diags.err(.cli, .not_available, null, "address 0x{x} has no bytes in the file (zero-fill or __PAGEZERO)", .{pr.start});
            return null;
        }
        if (vb.truncated) ctx.diags.warn(.cli, .truncated, null, "range clamped to {d} of {d} requested bytes at the end of the mapped segment", .{ vb.bytes.len, want });
        const s = img.sectionForVm(pr.start);
        return .{ .segname = if (s) |x| x.segname else null, .sectname = if (s) |x| x.sectname else null, .address = pr.start, .offset = img.vmToOff(pr.start) orelse 0, .bytes = vb.bytes, .vm_size = vb.bytes.len };
    }
    if (ctx.args.value("--offset")) |spec| {
        const pr = parseRange(spec) orelse {
            ctx.diags.err(.cli, .unknown_value, null, "--offset: invalid range '{s}'", .{spec});
            return null;
        };
        const want = pr.len orelse length;
        const sub = img.r.subClamped(pr.start, want) orelse {
            ctx.diags.err(.cli, .offset_past_eof, pr.start, "file offset {d} is past the slice end", .{pr.start});
            return null;
        };
        if (sub.truncated) ctx.diags.warn(.cli, .truncated, pr.start, "range clamped to {d} of {d} requested bytes at the slice end", .{ sub.r.bytes.len, want });
        return .{ .segname = null, .sectname = null, .address = img.offToVm(pr.start), .offset = pr.start, .bytes = sub.r.bytes, .vm_size = sub.r.bytes.len };
    }
    // No range given: the start of the slice (Mach-O header + load commands).
    const sub = img.r.subClamped(0, length) orelse return null;
    return .{ .segname = null, .sectname = null, .address = img.offToVm(0), .offset = 0, .bytes = sub.r.bytes };
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    var code: u8 = 0;
    for (ctx.images) |*img| {
        const rg = try resolve(ctx, img);
        if (rg == null) code = 1;
        if (ctx.sink.isJson()) {
            const js = &ctx.sink.json;
            try json.beginArch(js, img);
            if (rg) |x| {
                try js.objectField("dump");
                try js.beginObject();
                try json.strOpt(js, ctx.arena, "segment", x.segname);
                try json.strOpt(js, ctx.arena, "section", x.sectname);
                try json.hexOpt(js, "address", x.address);
                try json.int(js, "offset", x.offset);
                try json.int(js, "length", x.bytes.len);
                try json.boolean(js, "zerofill", x.zerofill);
                try json.int(js, "vm_size", x.vm_size);
                try json.bytesHex(js, "hex", x.bytes);
                const ascii = try ctx.arena.alloc(u8, x.bytes.len);
                for (x.bytes, 0..) |b, i| ascii[i] = if (b >= 0x20 and b < 0x7f) b else '.';
                try json.str(js, ctx.arena, "ascii", ascii);
                try js.endObject();
            } else try json.unavailable(js, "dump", "range not resolved");
            try json.endArch(js);
        } else if (rg) |x| {
            const out = ctx.sink.out;
            var buf: [32]u8 = undefined;
            if (ctx.images.len > 1) try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), true);
            if (x.sectname) |sn| {
                if (x.zerofill) {
                    try out.print("({s},{s}) section, {d} bytes in memory, zero-fill (no file bytes)\n", .{ try ctx.sink.safe(x.segname.?), try ctx.sink.safe(sn), x.vm_size });
                } else try out.print("({s},{s}) section, {d} bytes at file offset {d}\n", .{ try ctx.sink.safe(x.segname.?), try ctx.sink.safe(sn), x.bytes.len, x.offset });
            } else try out.print("{d} bytes at file offset {d}\n", .{ x.bytes.len, x.offset });
            try text.hexdump(out, x.bytes, x.address orelse x.offset, 0);
        }
    }
    return code;
}

test "dump: range parsing" {
    try std.testing.expectEqual(@as(u64, 0x1000), parseRange("0x1000").?.start);
    try std.testing.expect(parseRange("0x1000").?.len == null);
    const r = parseRange("0x100000668+16").?;
    try std.testing.expectEqual(@as(u64, 0x100000668), r.start);
    try std.testing.expectEqual(@as(u64, 16), r.len.?);
    try std.testing.expectEqual(@as(u64, 4096), parseRange("4096").?.start);
    try std.testing.expect(parseRange("nope") == null);
    try std.testing.expect(parseRange("0x10+") == null);
    try std.testing.expect(parseRange("") == null);
    // No wrap-around and no trap on a huge start+len.
    const huge = parseRange("0xffffffffffffffff+0xffffffffffffffff").?;
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), huge.start);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), huge.len.?);
}
