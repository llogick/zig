const std = @import("std");
const common = @import("common.zig");
const builtin = @import("builtin");

comptime {
    if (builtin.target.isMuslLibC() or builtin.target.isWasiLibC()) {
        // Functions specific to musl and wasi-libc.
        @export(&abs, .{ .name = "abs", .linkage = common.linkage, .visibility = common.visibility });
        @export(&labs, .{ .name = "labs", .linkage = common.linkage, .visibility = common.visibility });
        @export(&llabs, .{ .name = "llabs", .linkage = common.linkage, .visibility = common.visibility });

        @export(&qsort_r, .{ .name = "qsort_r", .linkage = common.linkage, .visibility = common.visibility });
        @export(&qsort, .{ .name = "qsort", .linkage = common.linkage, .visibility = common.visibility });
    }
}

fn abs(a: c_int) callconv(.c) c_int {
    return @intCast(@abs(a));
}

fn labs(a: c_long) callconv(.c) c_long {
    return @intCast(@abs(a));
}

fn llabs(a: c_longlong) callconv(.c) c_longlong {
    return @intCast(@abs(a));
}

// NOTE: Despite its name, `qsort` doesn't have to use quicksort or make any complexity or stability guarantee.
fn qsort_r(base: *anyopaque, n: usize, size: usize, compare: *const fn (a: *const anyopaque, b: *const anyopaque, arg: ?*anyopaque) callconv(.c) c_int, arg: ?*anyopaque) callconv(.c) void {
    const Context = struct {
        base: [*]u8,
        size: usize,
        compare: *const fn (a: *const anyopaque, b: *const anyopaque, arg: ?*anyopaque) callconv(.c) c_int,
        arg: ?*anyopaque,

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return ctx.compare(&ctx.base[a * ctx.size], &ctx.base[b * ctx.size], ctx.arg) < 0;
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            const a_bytes: []u8 = ctx.base[a * ctx.size ..][0..ctx.size];
            const b_bytes: []u8 = ctx.base[b * ctx.size ..][0..ctx.size];

            for (a_bytes, b_bytes) |*ab, *bb| {
                const tmp = ab.*;
                ab.* = bb.*;
                bb.* = tmp;
            }
        }
    };

    std.mem.sortUnstableContext(0, n, Context{
        .base = @ptrCast(base),
        .size = size,
        .compare = compare,
        .arg = arg,
    });
}

fn qsort(base: *anyopaque, n: usize, size: usize, compare: *const fn (a: *const anyopaque, b: *const anyopaque) callconv(.c) c_int) callconv(.c) void {
    return qsort_r(base, n, size, (struct {
        fn wrap(a: *const anyopaque, b: *const anyopaque, arg: ?*anyopaque) callconv(.c) c_int {
            const cmp: *const fn (a: *const anyopaque, b: *const anyopaque) callconv(.c) c_int = @ptrCast(@alignCast(arg.?));
            return cmp(a, b);
        }
    }).wrap, @constCast(compare));
}

test abs {
    const val: c_int = -10;
    try std.testing.expectEqual(10, abs(val));
}

test labs {
    const val: c_long = -10;
    try std.testing.expectEqual(10, labs(val));
}

test llabs {
    const val: c_longlong = -10;
    try std.testing.expectEqual(10, llabs(val));
}
