const builtin = @import("builtin");
const std = @import("std");

pub const linkage: std.builtin.GlobalLinkage = if (builtin.is_test)
    .internal
else
    .strong;

/// Determines the symbol's visibility to other objects.
/// For WebAssembly this allows the symbol to be resolved to other modules, but will not
/// export it to the host runtime.
pub const visibility: std.builtin.SymbolVisibility = if (linkage != .internal)
    .hidden
else
    .default;

/// Checks whether the syscall has had an error, storing it in `std.c.errno` and returning -1.
/// Otherwise returns the result.
pub fn linuxErrno(r: usize) isize {
    const linux = std.os.linux;

    return switch (linux.errno(r)) {
        .SUCCESS => @bitCast(r),
        else => |err| blk: {
            std.c._errno().* = @intFromEnum(err);
            break :blk -1;
        },
    };
}
