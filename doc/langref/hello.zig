const std = @import("std");

// See https://github.com/ziglang/zig/issues/24510
// for the plan to simplify this code.
pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.Io.File.stdout().writeStreamingAll(io, "Hello, World!\n");
}

// exe=succeed
