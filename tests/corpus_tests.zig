//! tests/corpus_tests.zig — root of the corpus fact tests (one import per WP file). Owned by WP0.
const std = @import("std");
pub const helpers = @import("helpers.zig");
pub const truth = @import("truth.zig");
test {
    _ = @import("facts/core.zig");
    _ = @import("facts/dyld.zig");
    _ = @import("facts/codesign.zig");
    _ = @import("facts/darwin.zig");
    _ = @import("facts/plist_bundle.zig");
    _ = @import("facts/objc_strings.zig");
    _ = @import("facts/decoders.zig");
    _ = @import("facts/disasm.zig");
    _ = @import("facts/triage.zig");
    std.testing.refAllDecls(@This());
}
test "corpus: manifest resolves and hello-c is readable" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const data = try helpers.readFixture(io, gpa, "hello-c");
    defer gpa.free(data);
    try std.testing.expectEqual(@as(usize, 50424), data.len);
}
