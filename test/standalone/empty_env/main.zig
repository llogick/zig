const std = @import("std");

pub fn main(init: std.process.Init) !void {
    try std.testing.expectEqual(0, init.env_map.count());
}
