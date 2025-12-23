const std = @import("std");

pub fn main() !void {
    const io = std.Io.Threaded.global_single_threaded.ioBasic();
    var args = try std.process.argsWithAllocator(std.heap.page_allocator);
    _ = args.skip();
    const filename = args.next().?;
    const file = try std.Io.Dir.cwd().createFile(io, filename, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, filename);
}
