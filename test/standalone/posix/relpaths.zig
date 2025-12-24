// Test relative paths through POSIX APIS.  These tests have to change the cwd, so
// they shouldn't be Zig unit tests.

const builtin = @import("builtin");

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main() !void {
    if (builtin.target.os.tag == .wasi) return; // Can link, but can't change into tmpDir

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_allocator.allocator();
    defer std.debug.assert(debug_allocator.deinit() == .ok);

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = tmpDir(io, .{});
    defer tmp.cleanup(io);

    // Want to test relative paths, so cd into the tmpdir for these tests
    try std.process.setCurrentDir(io, tmp.dir);

    try test_symlink(gpa, io, tmp);
    try test_link(io, tmp);
}

fn test_symlink(gpa: Allocator, io: Io, tmp: TmpDir) !void {
    const target_name = "symlink-target";
    const symlink_name = "symlinker";

    // Create the target file
    try tmp.dir.writeFile(io, .{ .sub_path = target_name, .data = "nonsense" });

    if (builtin.target.os.tag == .windows) {
        const wtarget_name = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, target_name);
        const wsymlink_name = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, symlink_name);
        defer gpa.free(wtarget_name);
        defer gpa.free(wsymlink_name);

        std.os.windows.CreateSymbolicLink(tmp.dir.fd, wsymlink_name, wtarget_name, false) catch |err| switch (err) {
            // Symlink requires admin privileges on windows, so this test can legitimately fail.
            error.AccessDenied => return,
            else => return err,
        };
    } else {
        try Io.Dir.cwd().symLink(io, target_name, symlink_name, .{});
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const given = buffer[0..try Io.Dir.cwd().readLink(io, symlink_name, &buffer)];
    try std.testing.expectEqualStrings(target_name, given);
}

fn test_link(io: Io, tmp: TmpDir) !void {
    switch (builtin.target.os.tag) {
        .linux, .illumos => {},
        else => return,
    }

    const target_name = "link-target";
    const link_name = "newlink";

    try tmp.dir.writeFile(io, .{ .sub_path = target_name, .data = "example" });

    // Test 1: create the relative link from inside tmp
    try Io.Dir.hardLink(.cwd(), target_name, .cwd(), link_name, io, .{});

    // Verify
    const efd = try tmp.dir.openFile(io, target_name, .{});
    defer efd.close(io);

    const nfd = try tmp.dir.openFile(io, link_name, .{});
    defer nfd.close(io);

    {
        const e_stat = try efd.stat(io);
        const n_stat = try nfd.stat(io);
        try std.testing.expectEqual(e_stat.inode, n_stat.inode);
        try std.testing.expectEqual(2, n_stat.nlink);
    }

    // Test 2: Remove the link and see the stats update
    try Io.Dir.cwd().deleteFile(io, link_name);
    {
        const e_stat = try efd.stat(io);
        try std.testing.expectEqual(1, e_stat.nlink);
    }
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
