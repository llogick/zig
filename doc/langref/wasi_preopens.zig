const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const preopens = try std.fs.wasi.preopensAlloc(init.arena.allocator());

    for (preopens.names, 0..) |preopen, i| {
        std.debug.print("{d}: {s}\n", .{ i, preopen });
    }
}

// exe=succeed
// target=wasm32-wasi
