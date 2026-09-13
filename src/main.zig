//! machre entry point. Owned by WP0.
const std = @import("std");
const machre = @import("machre");

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main(init: std.process.Init) u8 {
    return machre.cli.run(init);
}

test "cli smoke" {
    try std.testing.expect(machre.cli.version_string.len > 0);
}
