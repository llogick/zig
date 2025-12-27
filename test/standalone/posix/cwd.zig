const builtin = @import("builtin");

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const path_max = std.fs.max_path_bytes;

pub fn main() !void {
    switch (builtin.target.os.tag) {
        .wasi => return, // WASI doesn't support changing the working directory at all.
        .windows => return, // POSIX is not implemented by Windows
        else => {},
    }

    var debug_allocator: std.heap.DebugAllocator(.{}) = .{};
    defer assert(debug_allocator.deinit() == .ok);
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try test_chdir_self();
    try test_chdir_absolute();
    try test_chdir_relative(gpa, io);
}

// get current working directory and expect it to match given path
fn expect_cwd(expected_cwd: []const u8) !void {
    var cwd_buf: [path_max]u8 = undefined;
    const actual_cwd = try std.posix.getcwd(cwd_buf[0..]);
    try std.testing.expectEqualStrings(actual_cwd, expected_cwd);
}

fn test_chdir_self() !void {
    var old_cwd_buf: [path_max]u8 = undefined;
    const old_cwd = try std.posix.getcwd(old_cwd_buf[0..]);

    // Try changing to the current directory
    try std.posix.chdir(old_cwd);
    try expect_cwd(old_cwd);
}

fn test_chdir_absolute() !void {
    var old_cwd_buf: [path_max]u8 = undefined;
    const old_cwd = try std.posix.getcwd(old_cwd_buf[0..]);

    const parent = std.fs.path.dirname(old_cwd) orelse unreachable; // old_cwd should be absolute

    // Try changing to the parent via a full path
    try std.posix.chdir(parent);

    try expect_cwd(parent);
}

fn test_chdir_relative(gpa: Allocator, io: Io) !void {
    var tmp = tmpDir(io, .{});
    defer tmp.cleanup(io);

    // Use the tmpDir parent_dir as the "base" for the test. Then cd into the child
    try std.process.setCurrentDir(io, tmp.parent_dir);

    // Capture base working directory path, to build expected full path
    var base_cwd_buf: [path_max]u8 = undefined;
    const base_cwd = try std.posix.getcwd(base_cwd_buf[0..]);

    const relative_dir_name = &tmp.sub_path;
    const expected_path = try std.fs.path.resolve(gpa, &.{ base_cwd, relative_dir_name });
    defer gpa.free(expected_path);

    // change current working directory to new test directory
    try std.posix.chdir(relative_dir_name);

    var new_cwd_buf: [path_max]u8 = undefined;
    const new_cwd = try std.posix.getcwd(new_cwd_buf[0..]);

    // On Windows, fs.path.resolve returns an uppercase drive letter, but the drive letter returned by getcwd may be lowercase
    const resolved_cwd = try std.fs.path.resolve(gpa, &.{new_cwd});
    defer gpa.free(resolved_cwd);

    try std.testing.expectEqualStrings(expected_path, resolved_cwd);
}

pub fn tmpDir(io: Io, opts: Io.Dir.OpenOptions) TmpDir {
    var random_bytes: [TmpDir.random_bytes_count]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [TmpDir.sub_path_len]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);

    const cwd = Io.Dir.cwd();
    var cache_dir = cwd.createDirPathOpen(io, ".zig-cache", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache dir");
    defer cache_dir.close(io);
    const parent_dir = cache_dir.createDirPathOpen(io, "tmp", .{}) catch
        @panic("unable to make tmp dir for testing: unable to make and open .zig-cache/tmp dir");
    const dir = parent_dir.createDirPathOpen(io, &sub_path, .{ .open_options = opts }) catch
        @panic("unable to make tmp dir for testing: unable to make and open the tmp dir");

    return .{
        .dir = dir,
        .parent_dir = parent_dir,
        .sub_path = sub_path,
    };
}

pub const TmpDir = struct {
    dir: Io.Dir,
    parent_dir: Io.Dir,
    sub_path: [sub_path_len]u8,

    const random_bytes_count = 12;
    const sub_path_len = std.fs.base64_encoder.calcSize(random_bytes_count);

    pub fn cleanup(self: *TmpDir, io: Io) void {
        self.dir.close(io);
        self.parent_dir.deleteTree(io, &self.sub_path) catch {};
        self.parent_dir.close(io);
        self.* = undefined;
    }
};
