//! tests/fuzz/codesign.zig — Smith fuzzers for the code-signing parsers (DESIGN.md §10.5).
//! Every fuzzer mutates a real corpus seed and asserts only that the parser returned: under
//! `Limits.paranoid` no input may trap, hang or allocate without bound.
const std = @import("std");
const machre = @import("machre");
const helpers = @import("../helpers.zig");
const Limits = machre.Limits;
const Reader = machre.Reader;
const Diagnostics = machre.Diagnostics;
const blobs = machre.codesign.blobs;
const hashes = machre.codesign.hashes;
const requirements = machre.codesign.requirements;
const entitlements = machre.codesign.entitlements;
const cms = machre.codesign.cms;
const asn1 = machre.codesign.asn1;

const Seeds = struct {
    /// Whole files (owned by the caller).
    files: [][]u8,
    /// Signature-relevant blobs sliced out of those files.
    blob_seeds: [][]const u8,
};

/// Loads hello-c / hello-entitled / /bin/ls and slices out their signature blobs with the real parser.
fn collectSeeds(gpa: std.mem.Allocator, io: std.Io, arena: std.mem.Allocator) !Seeds {
    var files: std.ArrayList([]u8) = .empty;
    var seeds: std.ArrayList([]const u8) = .empty;
    var diags = Diagnostics.init(arena, 64);
    for ([_][]const u8{ "hello-c", "hello-entitled", "hello-adhoc" }) |name| {
        const bytes = helpers.readFixture(io, gpa, name) catch continue;
        try files.append(arena, bytes);
        var file = machre.LoadedFile.fromBytes(arena, name, bytes, &Limits.default, &diags) catch continue;
        const r = file.sliceReader(0) orelse continue;
        const img = machre.Image.parse(arena, r, 0, 0, &Limits.default, &diags) catch continue;
        const sig = (blobs.parse(arena, &img, &Limits.default, &diags) catch continue) orelse continue;
        // the whole signature area, and every interesting blob inside it
        if (img.findCmd(.CODE_SIGNATURE)) |c| {
            const off = c.reader().u32At(8, c.endian) orelse 0;
            const size = c.reader().u32At(12, c.endian) orelse 0;
            if (r.sliceAt(off, size)) |all| try seeds.append(arena, all);
        }
        for (sig.blobs) |b| try seeds.append(arena, b.bytes);
        if (sig.requirements) |x| try seeds.append(arena, x);
        if (sig.entitlements_der) |x| try seeds.append(arena, x);
        if (sig.cms) |x| try seeds.append(arena, x);
    }
    return .{ .files = try files.toOwnedSlice(arena), .blob_seeds = try seeds.toOwnedSlice(arena) };
}

const BlobCtx = struct {
    gpa: std.mem.Allocator,
    seeds: [][]const u8,

    fn testOne(ctx: BlobCtx, smith: *std.testing.Smith) anyerror!void {
        var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        var diags = Diagnostics.init(a, 32);

        // Either a mutated corpus blob or a purely synthetic one.
        var random_buf: [512]u8 = undefined;
        var input: []u8 = undefined;
        if (ctx.seeds.len != 0 and smith.boolWeighted(1, 3)) {
            const seed = ctx.seeds[smith.index(ctx.seeds.len)];
            const copy = try a.dupe(u8, seed);
            const muts = smith.valueRangeAtMost(u8, 0, 8);
            var i: u8 = 0;
            while (i < muts and copy.len != 0) : (i += 1) copy[smith.index(copy.len)] = @truncate(smith.value(u32));
            input = copy[0..smith.index(copy.len + 1)];
        } else {
            const n = smith.slice(&random_buf);
            input = random_buf[0..n];
        }

        _ = try blobs.parseSuperBlob(a, Reader.init(input, 0), 0, @intCast(input.len), &Limits.paranoid, &diags);
        if (try blobs.parseCodeDirectory(a, 0, input, &Limits.paranoid, &diags)) |cd| {
            _ = cd.pageSize();
            _ = cd.isSpecialSlotBound(smith.valueRangeAtMost(u32, 0, 20));
            _ = hashes.verifySpecialSlot(&cd, 2, input);
            var out: [48]u8 = undefined;
            _ = hashes.hashBytes(cd.hash_type, input, &out);
        }
        _ = try requirements.parseSet(a, input, &Limits.paranoid, &diags);
        _ = try requirements.prettyPrint(a, input, &Limits.paranoid, &diags);
        _ = try entitlements.parseDer(a, input, &Limits.paranoid, &diags);
        _ = try cms.parse(a, input, &Limits.paranoid, &diags);
        // The raw ASN.1 walker must terminate on any byte string.
        var w = asn1.Walker.init(input, &Limits.paranoid);
        var nodes: u32 = 0;
        while (w.next() catch null) |_| {
            nodes += 1;
            if (nodes > 1 << 16) return error.WalkerDidNotTerminate;
        }
    }
};

test "fuzz/codesign: SuperBlob, CodeDirectory, requirements, DER entitlements and CMS parsers" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const seeds = try collectSeeds(gpa, std.testing.io, a);
    defer for (seeds.files) |f| gpa.free(f);
    if (seeds.blob_seeds.len == 0) return error.SkipZigTest;
    // Corpus entries drive Smith; the seeds themselves are reached through the context.
    try std.testing.fuzz(BlobCtx{ .gpa = gpa, .seeds = seeds.blob_seeds }, BlobCtx.testOne, .{
        .corpus = &.{ "\xfa\xde\x0c\xc0", "\xfa\xde\x0c\x02", "\x30\x80\x02\x01\x01\x00\x00", "\x70\x0a\x02\x01\x01\xb0\x05\x30\x03\x0c\x01a" },
    });
}

const ImageCtx = struct {
    gpa: std.mem.Allocator,
    file_bytes: []const u8,

    fn testOne(ctx: ImageCtx, smith: *std.testing.Smith) anyerror!void {
        var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        var diags = Diagnostics.init(a, 32);
        const copy = try a.dupe(u8, ctx.file_bytes);
        const muts = smith.valueRangeAtMost(u8, 0, 8);
        var i: u8 = 0;
        while (i < muts and copy.len != 0) : (i += 1) copy[smith.index(copy.len)] = @truncate(smith.value(u32));
        const cut = if (smith.boolWeighted(4, 1)) copy.len else smith.index(copy.len + 1);
        const input = copy[0..cut];

        var file = machre.LoadedFile.fromBytes(a, "fuzz", input, &Limits.paranoid, &diags) catch return;
        const r = file.sliceReader(0) orelse return;
        const img = machre.Image.parse(a, r, 0, 0, &Limits.paranoid, &diags) catch return;
        const sig = (try blobs.parse(a, &img, &Limits.paranoid, &diags)) orelse return;
        if (sig.cd()) |cd| {
            const v = hashes.verify(&img, &sig, cd, &Limits.paranoid, &diags);
            _ = v.ok();
        }
        _ = try entitlements.parse(a, &sig, &Limits.paranoid, &diags);
        if (sig.requirements) |req| _ = try requirements.parseSet(a, req, &Limits.paranoid, &diags);
        if (sig.cms) |c| _ = try cms.parse(a, c, &Limits.paranoid, &diags);
    }
};

test "fuzz/codesign: mutated Mach-O images through signature parse + page verification" {
    const gpa = std.testing.allocator;
    const bytes = helpers.readFixture(std.testing.io, gpa, "hello-entitled") catch return error.SkipZigTest;
    defer gpa.free(bytes);
    try std.testing.fuzz(ImageCtx{ .gpa = gpa, .file_bytes = bytes }, ImageCtx.testOne, .{
        .corpus = &.{ "\xcf\xfa\xed\xfe", "machre" },
    });
}
