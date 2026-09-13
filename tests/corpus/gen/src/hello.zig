const std = @import("std");
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var buf: [256]u8 = undefined;
    var w: std.Io.File.Writer = .init(.stdout(), io, &buf);
    try w.interface.print("hello from zig {s}\n", .{"machre"});
    try w.interface.flush();
}
