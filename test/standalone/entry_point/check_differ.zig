pub fn main() !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len != 3) return error.BadUsage; // usage: 'check_differ <path a> <path b>'

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const contents_1 = try std.Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(1024 * 1024 * 64)); // 64 MiB ought to be plenty
    const contents_2 = try std.Io.Dir.cwd().readFileAlloc(io, args[2], arena, .limited(1024 * 1024 * 64)); // 64 MiB ought to be plenty

    if (std.mem.eql(u8, contents_1, contents_2)) {
        return error.FilesMatch;
    }
    // success, files differ
}
const std = @import("std");
