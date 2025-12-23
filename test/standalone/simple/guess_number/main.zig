const builtin = @import("builtin");
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

    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &.{});
    const out = &stdout_writer.interface;
    const stdin: std.Io.File = .stdin();

    try out.writeAll("Welcome to the Guess Number Game in Zig.\n");

    const answer = std.crypto.random.intRangeLessThan(u8, 0, 100) + 1;

    while (true) {
        try out.writeAll("\nGuess a number between 1 and 100: ");
        var line_buf: [20]u8 = undefined;
        const amt = try stdin.read(&line_buf);
        if (amt == line_buf.len) {
            try out.writeAll("Input too long.\n");
            continue;
        }
        const line = std.mem.trimEnd(u8, line_buf[0..amt], "\r\n");

        const guess = std.fmt.parseUnsigned(u8, line, 10) catch {
            try out.writeAll("Invalid number.\n");
            continue;
        };
        if (guess > answer) {
            try out.writeAll("Guess lower.\n");
        } else if (guess < answer) {
            try out.writeAll("Guess higher.\n");
        } else {
            try out.writeAll("You win!\n");
            return;
        }
    }
}
