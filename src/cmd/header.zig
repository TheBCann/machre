//! cmd/header.zig — Mach header (and fat table) only, otool -hv layout. Owned by one WP (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, the modules it renders.
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const version = @import("../core/version.zig");
const Image = @import("../core/image.zig").Image;
const Header = @import("../core/loadcmds.zig").Header;

pub const command: Command = .{
    .name = "header",
    .summary = "Mach header (and fat table) only, otool -hv layout",
    .run = run,
    .flags = &.{"--fat"},
    .aliases = &.{},
    .needs_macho = true,
};

pub const column_header = "      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags";

/// otool -hv verbose header row (llvm-objdump PrintMachHeader spelling).
pub fn writeVerboseRow(out: *Io.Writer, hdr: Header) Io.Writer.Error!void {
    switch (hdr.magic) {
        std.macho.MH_MAGIC => try out.writeAll("   MH_MAGIC"),
        std.macho.MH_MAGIC_64 => try out.writeAll("MH_MAGIC_64"),
        else => try out.print(" 0x{x:0>8}", .{hdr.magic}),
    }
    const sub: u32 = @bitCast(hdr.cpusubtype);
    const low: u32 = sub & 0x00ff_ffff;
    const caps: u32 = sub >> 24;
    switch (hdr.cputype) {
        7 => {
            try out.writeAll("     I386");
            if (low == 3) try out.writeAll("        ALL") else try out.print(" {d:>10}", .{low});
        },
        0x01000007 => {
            try out.writeAll("   X86_64");
            switch (low) {
                3 => try out.writeAll("        ALL"),
                8 => try out.writeAll("    Haswell"),
                else => try out.print(" {d:>10}", .{low}),
            }
        },
        12 => {
            try out.writeAll("      ARM");
            switch (low) {
                0 => try out.writeAll("        ALL"),
                5 => try out.writeAll("        V4T"),
                6 => try out.writeAll("         V6"),
                7 => try out.writeAll("      V5TEJ"),
                8 => try out.writeAll("     XSCALE"),
                9 => try out.writeAll("         V7"),
                11 => try out.writeAll("        V7S"),
                12 => try out.writeAll("        V7K"),
                14 => try out.writeAll("        V6M"),
                15 => try out.writeAll("        V7M"),
                16 => try out.writeAll("       V7EM"),
                else => try out.print(" {d:>10}", .{low}),
            }
        },
        0x0100000c => {
            try out.writeAll("    ARM64");
            switch (low) {
                0 => try out.writeAll("        ALL"),
                1 => try out.writeAll("         V8"),
                2 => try out.writeAll("          E"),
                else => try out.print(" {d:>10}", .{low}),
            }
        },
        0x0200000c => {
            try out.writeAll(" ARM64_32");
            if (low == 1) try out.writeAll("         V8") else try out.print(" {d:>10}", .{low});
        },
        18 => {
            try out.writeAll("      PPC");
            if (low == 0) try out.writeAll("        ALL") else try out.print(" {d:>10}", .{low});
        },
        0x01000012 => {
            try out.writeAll("    PPC64");
            if (low == 0) try out.writeAll("        ALL") else try out.print(" {d:>10}", .{low});
        },
        else => {
            var cb: [24]u8 = undefined;
            try out.print(" {s:>8}", .{dec(&cb, hdr.cputype)});
            try out.print(" {d:>10}", .{low});
        },
    }
    if (hdr.cputype == 0x0100000c and low == 2) {
        try out.print(" {s}{d:0>2}", .{ if (caps & 0x80 != 0) "USR" else "KER", (sub & 0x0f00_0000) >> 24 });
    } else if (caps == 0x80) {
        try out.writeAll(" LIB64");
    } else {
        try out.print("  0x{x:0>2}", .{caps});
    }
    switch (hdr.filetype) {
        1 => try out.writeAll("      OBJECT"),
        2 => try out.writeAll("     EXECUTE"),
        3 => try out.writeAll("      FVMLIB"),
        4 => try out.writeAll("        CORE"),
        5 => try out.writeAll("     PRELOAD"),
        6 => try out.writeAll("       DYLIB"),
        7 => try out.writeAll("    DYLINKER"),
        8 => try out.writeAll("      BUNDLE"),
        9 => try out.writeAll("  DYLIB_STUB"),
        10 => try out.writeAll("        DSYM"),
        11 => try out.writeAll("  KEXTBUNDLE"),
        12 => try out.writeAll("     FILESET"),
        else => try out.print("  {d:>10}", .{hdr.filetype}),
    }
    try out.print(" {d:>5}", .{hdr.ncmds});
    try out.print(" {d:>10}", .{hdr.sizeofcmds});
    var f = hdr.flags;
    for (version.mh_flags) |e| {
        if (f & e.bit != 0) {
            if (e.bit == 0x1) try out.writeAll("   NOUNDEFS") else try out.print(" {s}", .{e.name});
            f &= ~@as(u32, @truncate(e.bit));
        }
    }
    if (f != 0 or hdr.flags == 0) try out.print(" 0x{x:0>8}", .{f});
    try out.writeByte('\n');
}

/// Signed decimal without the "+" that `{d:>N}` adds to signed integers on this nightly.
fn dec(buf: []u8, v: i64) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{v}) catch "?";
}

/// `lipo -detailed_info` spelling of a fat entry's cputype ("CPU_TYPE_ARM64"), or the number.
fn lipoCpuType(buf: []u8, cputype: i32) []const u8 {
    return switch (cputype) {
        7 => "CPU_TYPE_I386",
        0x01000007 => "CPU_TYPE_X86_64",
        12 => "CPU_TYPE_ARM",
        0x0100000c => "CPU_TYPE_ARM64",
        0x0200000c => "CPU_TYPE_ARM64_32",
        18 => "CPU_TYPE_POWERPC",
        0x01000012 => "CPU_TYPE_POWERPC64",
        else => dec(buf, cputype),
    };
}

/// `lipo -detailed_info` spelling of a fat entry's cpusubtype ("CPU_SUBTYPE_ARM64E"), or the number.
fn lipoCpuSubtype(buf: []u8, cputype: i32, low: u32) []const u8 {
    const name: ?[]const u8 = switch (cputype) {
        7 => switch (low) {
            3 => "CPU_SUBTYPE_I386_ALL",
            else => null,
        },
        0x01000007 => switch (low) {
            3 => "CPU_SUBTYPE_X86_64_ALL",
            8 => "CPU_SUBTYPE_X86_64_H",
            else => null,
        },
        12 => switch (low) {
            0 => "CPU_SUBTYPE_ARM_ALL",
            5 => "CPU_SUBTYPE_ARM_V4T",
            6 => "CPU_SUBTYPE_ARM_V6",
            7 => "CPU_SUBTYPE_ARM_V5TEJ",
            8 => "CPU_SUBTYPE_ARM_XSCALE",
            9 => "CPU_SUBTYPE_ARM_V7",
            10 => "CPU_SUBTYPE_ARM_V7F",
            11 => "CPU_SUBTYPE_ARM_V7S",
            12 => "CPU_SUBTYPE_ARM_V7K",
            13 => "CPU_SUBTYPE_ARM_V8",
            14 => "CPU_SUBTYPE_ARM_V6M",
            15 => "CPU_SUBTYPE_ARM_V7M",
            16 => "CPU_SUBTYPE_ARM_V7EM",
            else => null,
        },
        0x0100000c => switch (low) {
            0 => "CPU_SUBTYPE_ARM64_ALL",
            1 => "CPU_SUBTYPE_ARM64_V8",
            2 => "CPU_SUBTYPE_ARM64E",
            else => null,
        },
        0x0200000c => switch (low) {
            1 => "CPU_SUBTYPE_ARM64_32_V8",
            else => null,
        },
        18, 0x01000012 => switch (low) {
            0 => "CPU_SUBTYPE_POWERPC_ALL",
            else => null,
        },
        else => null,
    };
    return name orelse dec(buf, @as(i32, @bitCast(low)));
}

/// The `lipo -detailed_info` table (`--fat`); with `--otool-compat` it is the whole output.
fn writeFatTable(out: *Io.Writer, path: []const u8, f: @import("../core/fat.zig").Fat) Io.Writer.Error!void {
    try out.print("Fat header in: {s}\n", .{path});
    try out.print("fat_magic 0x{x}\nnfat_arch {d}\n", .{ @as(u32, if (f.is_64) std.macho.FAT_MAGIC_64 else std.macho.FAT_MAGIC), f.nfat_arch_declared });
    for (f.arches) |a| {
        var nb: [32]u8 = undefined;
        var cb: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        const low = a.arch.subtypeLow();
        try out.print("architecture {s}{s}\n", .{ a.arch.displayName(&nb), if (a.valid) "" else " (invalid)" });
        try out.print("    cputype {s}\n    cpusubtype {s}\n", .{ lipoCpuType(&cb, a.arch.cputype), lipoCpuSubtype(&sb, a.arch.cputype, low) });
        if (a.arch.cputype == 0x0100000c and low == 2) {
            try out.print("    capabilities PTR_AUTH_VERSION {s} {d}\n", .{ if (a.arch.caps & 0x80 != 0) "USERSPACE" else "KERNEL", a.arch.caps & 0x0f });
        } else try out.print("    capabilities 0x{x}\n", .{a.arch.caps});
        try out.print("    offset {d}\n    size {d}\n    align 2^{d} ({d})\n", .{ a.offset, a.size, a.@"align", @as(u64, 1) << @intCast(@min(a.@"align", 63)) });
    }
}

/// otool -h (non-verbose) header row.
pub fn writeRawRow(out: *Io.Writer, hdr: Header) Io.Writer.Error!void {
    const sub: u32 = @bitCast(hdr.cpusubtype);
    var cb: [24]u8 = undefined;
    var sb: [24]u8 = undefined;
    try out.print(" 0x{x:0>8} {s:>7} {s:>10}  0x{x:0>2}  {d:>10} {d:>5} {d:>10} 0x{x:0>8}\n", .{ hdr.magic, dec(&cb, hdr.cputype), dec(&sb, @as(i32, @bitCast(sub & 0x00ff_ffff))), sub >> 24, hdr.filetype, hdr.ncmds, hdr.sizeofcmds, hdr.flags });
}

/// JSON `header{...}` object shared with `info`.
pub fn writeHeaderJson(js: *std.json.Stringify, img: *const Image) json.Error!void {
    const hdr = img.hdr;
    try js.objectField("header");
    try js.beginObject();
    try json.hex(js, "magic", hdr.magic);
    try js.objectField("magic_name");
    if (version.magicName(hdr.magic)) |n| try js.write(n) else try js.write(null);
    try json.hex(js, "cputype", @as(u32, @bitCast(hdr.cputype)));
    try js.objectField("cputype_name");
    if (version.cpuTypeName(hdr.cputype)) |n| try js.write(n) else try js.write(null);
    try json.hex(js, "cpusubtype", @as(u32, @bitCast(hdr.cpusubtype)));
    try json.int(js, "cpusubtype_low", img.arch.subtypeLow());
    try json.hex(js, "caps", img.arch.caps);
    try json.int(js, "filetype", hdr.filetype);
    try js.objectField("filetype_name");
    if (version.filetypeName(hdr.filetype)) |n| try js.write(n) else try js.write(null);
    try json.int(js, "ncmds", hdr.ncmds);
    try json.int(js, "sizeofcmds", hdr.sizeofcmds);
    try json.flags(js, "flags", hdr.flags, version.mh_flags);
    try json.flags(js, "flags_full", hdr.flags, version.mh_flags_full);
    try json.boolean(js, "is_64", hdr.is_64);
    try js.objectField("endian");
    try js.write(@tagName(hdr.endian));
    try js.endObject();
}

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    const file = ctx.file.?;
    if (ctx.sink.isJson()) {
        const js = &ctx.sink.json;
        for (ctx.images) |*img| {
            try json.beginArch(js, img);
            try js.objectField("header");
            try js.beginObject();
            try writeHeaderJson(js, img);
            try js.objectField("fat");
            switch (file.container) {
                .fat => |f| {
                    try js.beginObject();
                    try json.int(js, "nfat_arch", f.nfat_arch_declared);
                    try json.int(js, "slices", f.arches.len);
                    try js.endObject();
                },
                else => try js.write(null),
            }
            try js.endObject();
            try json.endArch(js);
        }
        return 0;
    }
    const out = ctx.sink.out;
    if (ctx.args.flag("--fat")) {
        switch (file.container) {
            .fat => |f| try writeFatTable(out, ctx.display_path, f),
            else => if (!ctx.otool_compat) try out.print("{s}: not a fat file\n", .{ctx.display_path}),
        }
        // `--fat --otool-compat` diffs against `lipo -detailed_info`, which prints no Mach header.
        if (ctx.otool_compat) return 0;
    }
    const multi = ctx.images.len > 1;
    for (ctx.images) |*img| {
        var buf: [32]u8 = undefined;
        try text.archBanner(out, ctx.display_path, img.arch.displayName(&buf), multi);
        try out.writeAll("Mach header\n");
        try out.writeAll(column_header ++ "\n");
        try writeVerboseRow(out, img.hdr);
    }
    return 0;
}

test "header: verbose row spelling for the corpus headers" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const h: Header = .{ .magic = std.macho.MH_MAGIC_64, .is_64 = true, .endian = .little, .cputype = 0x0100000c, .cpusubtype = 0, .filetype = 2, .ncmds = 18, .sizeofcmds = 1208, .flags = 0x200085, .header_size = 32 };
    try writeVerboseRow(&w, h);
    try std.testing.expectEqualStrings("MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    18       1208   NOUNDEFS DYLDLINK TWOLEVEL PIE\n", w.buffered());
    w = .fixed(&buf);
    var e = h;
    e.cpusubtype = @bitCast(@as(u32, 0x80000002));
    e.ncmds = 20;
    e.sizeofcmds = 1712;
    try writeVerboseRow(&w, e);
    try std.testing.expectEqualStrings("MH_MAGIC_64    ARM64          E USR00     EXECUTE    20       1712   NOUNDEFS DYLDLINK TWOLEVEL PIE\n", w.buffered());
    w = .fixed(&buf);
    try writeRawRow(&w, h);
    try std.testing.expectEqualStrings(" 0xfeedfacf 16777228          0  0x00           2    18       1208 0x00200085\n", w.buffered());
    w = .fixed(&buf);
    var z = h;
    z.flags = 0xb00085;
    z.sizeofcmds = 1864;
    z.ncmds = 17;
    try writeVerboseRow(&w, z);
    try std.testing.expectEqualStrings("MH_MAGIC_64    ARM64        ALL  0x00     EXECUTE    17       1864   NOUNDEFS DYLDLINK TWOLEVEL NO_REEXPORTED_DYLIBS PIE MH_HAS_TLV_DESCRIPTORS\n", w.buffered());
}
