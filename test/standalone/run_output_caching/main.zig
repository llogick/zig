const std = @import("std");

pub fn main() !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var args = try std.process.argsWithAllocator(std.heap.page_allocator);
    _ = args.skip();
    const filename = args.next().?;
    const file = try std.Io.Dir.cwd().createFile(io, filename, .{});
    defer file.close(io);
    try file.writeAll(io, filename);
}
