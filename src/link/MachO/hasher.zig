const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const trace = @import("../../tracy.zig").trace;

pub fn ParallelHasher(comptime Hasher: type) type {
    const hash_size = Hasher.digest_length;

    return struct {
        allocator: Allocator,
        io: std.Io,

        pub fn hash(self: Self, file: Io.File, out: [][hash_size]u8, opts: struct {
            chunk_size: u64 = 0x4000,
            max_file_size: ?u64 = null,
        }) !void {
            const tracy = trace(@src());
            defer tracy.end();

            const io = self.io;

            const file_size = blk: {
                const file_size = opts.max_file_size orelse try file.getEndPos();
                break :blk std.math.cast(usize, file_size) orelse return error.Overflow;
            };
            const chunk_size = std.math.cast(usize, opts.chunk_size) orelse return error.Overflow;

            const buffer = try self.allocator.alloc(u8, chunk_size * out.len);
            defer self.allocator.free(buffer);

            const results = try self.allocator.alloc(Io.File.PReadError!usize, out.len);
            defer self.allocator.free(results);

            {
                var group: std.Io.Group = .init;
                errdefer group.cancel(io);

                for (out, results, 0..) |*out_buf, *result, i| {
                    const fstart = i * chunk_size;
                    const fsize = if (fstart + chunk_size > file_size)
                        file_size - fstart
                    else
                        chunk_size;
                    group.async(io, worker, .{
                        file,
                        fstart,
                        buffer[fstart..][0..fsize],
                        &(out_buf.*),
                        &(result.*),
                    });
                }

                group.wait(io);
            }
            for (results) |result| _ = try result;
        }

        fn worker(
            file: Io.File,
            fstart: usize,
            buffer: []u8,
            out: *[hash_size]u8,
            err: *Io.File.PReadError!usize,
        ) void {
            const tracy = trace(@src());
            defer tracy.end();
            err.* = file.preadAll(buffer, fstart);
            Hasher.hash(buffer, out, .{});
        }

        const Self = @This();
    };
}
