const std = @import("std");

pub fn main() !void {
    try std.Io.File.stdout().writeAll("Hello, World!\n");
}
