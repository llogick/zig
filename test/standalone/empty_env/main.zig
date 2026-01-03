const std = @import("std");

pub fn main(init: std.process.Init) !void {
    try std.testing.expect(init.env_map.count() == 0);
}
