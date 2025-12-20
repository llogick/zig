const std = @import("std");

var static_single_threaded_io: std.Io.Threaded = .init_single_threaded;
const io = static_single_threaded_io.ioBasic();

pub fn main() !void {
    try std.Io.File.stdout().writeStreamingAll(io, "Hello, World!\n");
}
