//! core/arch.zig — cputype/cpusubtype decoding. Imports: std only.
const std = @import("std");
const builtin = @import("builtin");

pub const CpuType = enum(i32) {
    any = -1,
    x86 = 7,
    arm = 12,
    powerpc = 18,
    x86_64 = 0x01000007,
    arm64 = 0x0100000c,
    arm64_32 = 0x0200000c,
    powerpc64 = 0x01000012,
    _,
};

pub const ArchName = enum {
    x86_64,
    x86_64h,
    i386,
    arm64,
    arm64v8,
    arm64e,
    arm64_32,
    armv7,
    armv7s,
    armv7k,
    armv8,
    ppc,
    ppc64,
    unknown,
    pub fn parse(s: []const u8) ?ArchName {
        return std.meta.stringToEnum(ArchName, s);
    }
    pub fn str(n: ArchName) []const u8 {
        return @tagName(n);
    }
};
pub const Arch = struct {
    cputype: i32,
    cpusubtype: i32,
    name: ArchName,
    ptr_size: u8,
    is_64: bool,
    is_arm64e: bool,
    ptrauth_version: u8,
    caps: u8,

    pub fn fromCpu(cputype: i32, cpusubtype: i32) Arch {
        const sub: u32 = @bitCast(cpusubtype);
        const low = sub & 0x00ff_ffff;
        const caps: u8 = @truncate(sub >> 24);
        const name: ArchName = switch (cputype) {
            0x01000007 => if (low == 8) .x86_64h else .x86_64,
            7 => .i386,
            0x0100000c => switch (low) {
                1 => .arm64v8,
                2 => .arm64e,
                else => .arm64,
            },
            0x0200000c => .arm64_32,
            12 => switch (low) {
                9 => .armv7,
                11 => .armv7s,
                12 => .armv7k,
                13 => .armv8,
                else => .unknown,
            },
            18 => .ppc,
            0x01000012 => .ppc64,
            else => .unknown,
        };
        const is_64 = (cputype & 0x01000000) != 0;
        return .{
            .cputype = cputype,
            .cpusubtype = cpusubtype,
            .name = name,
            .ptr_size = if (is_64) 8 else 4,
            .is_64 = is_64,
            .is_arm64e = name == .arm64e,
            .ptrauth_version = @truncate((sub & 0x0f000000) >> 24),
            .caps = caps,
        };
    }
    pub fn subtypeLow(a: Arch) u32 {
        return @as(u32, @bitCast(a.cpusubtype)) & 0x00ff_ffff;
    }
    pub fn matches(a: Arch, wanted: ArchName) bool {
        return a.name == wanted;
    }
    pub fn host() Arch {
        return switch (builtin.cpu.arch) {
            .aarch64 => fromCpu(0x0100000c, 0),
            .x86_64 => fromCpu(0x01000007, 3),
            else => fromCpu(0, 0),
        };
    }
    pub fn preferenceRank(a: Arch, host_arch: Arch) u8 {
        if (a.name == host_arch.name) return 0;
        if (a.cputype == host_arch.cputype) return 1;
        return 2;
    }
    /// "arm64e" or "unknown(0x1000012/0x0)" for unrecognised pairs.
    pub fn displayName(a: Arch, buf: *[32]u8) []const u8 {
        if (a.name != .unknown) return @tagName(a.name);
        return std.fmt.bufPrint(buf, "unknown(0x{x}/0x{x})", .{ @as(u32, @bitCast(a.cputype)), @as(u32, @bitCast(a.cpusubtype)) }) catch "unknown";
    }
};

test "arch: /bin/ls slices and --arch parsing" {
    const e = Arch.fromCpu(0x0100000c, @bitCast(@as(u32, 0x80000002)));
    try std.testing.expectEqual(ArchName.arm64e, e.name);
    try std.testing.expectEqual(@as(u8, 0x80), e.caps);
    try std.testing.expectEqual(@as(u32, 2), e.subtypeLow());
    try std.testing.expect(e.is_arm64e and e.is_64 and e.ptr_size == 8);
    try std.testing.expectEqual(ArchName.x86_64, Arch.fromCpu(0x01000007, 3).name);
    try std.testing.expectEqual(ArchName.x86_64h, Arch.fromCpu(0x01000007, 8).name);
    try std.testing.expectEqual(ArchName.arm64e, ArchName.parse("arm64e").?);
    try std.testing.expect(ArchName.parse("mips") == null);
    try std.testing.expectEqual(@as(u8, 1), e.preferenceRank(Arch.fromCpu(0x0100000c, 0)));
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("arm64e", e.displayName(&buf));
    try std.testing.expectEqualStrings("unknown(0x1000013/0x0)", Arch.fromCpu(0x01000013, 0).displayName(&buf));
}
