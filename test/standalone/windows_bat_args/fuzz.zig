const builtin = @import("builtin");

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var it = try init.minimal.argsAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_exe_path_orig = it.next() orelse unreachable;

    const iterations: u64 = iterations: {
        const arg = it.next() orelse "0";
        break :iterations try std.fmt.parseUnsigned(u64, arg, 10);
    };

    var rand_seed = false;
    const seed: u64 = seed: {
        const seed_arg = it.next() orelse {
            rand_seed = true;
            var buf: [8]u8 = undefined;
            try std.posix.getrandom(&buf);
            break :seed std.mem.readInt(u64, &buf, builtin.cpu.arch.endian());
        };
        break :seed try std.fmt.parseUnsigned(u64, seed_arg, 10);
    };
    var random = std.Random.DefaultPrng.init(seed);
    const rand = random.random();

    // If the seed was not given via the CLI, then output the
    // randomly chosen seed so that this run can be reproduced
    if (rand_seed) {
        std.debug.print("rand seed: {}\n", .{seed});
    }

    var tmp = tmpDir(io, .{});
    defer tmp.cleanup(io);

    try std.process.setCurrentDir(io, tmp.dir);
    defer std.process.setCurrentDir(io, tmp.parent_dir) catch {};

    // `child_exe_path_orig` might be relative; make it relative to our new cwd.
    const child_exe_path = try std.fs.path.resolve(gpa, &.{ "..\\..\\..", child_exe_path_orig });
    defer gpa.free(child_exe_path);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.print(gpa,
        \\@echo off
        \\"{s}"
    , .{child_exe_path});
    // Trailing newline intentionally omitted above so we can add args.
    const preamble_len = buf.items.len;

    try buf.appendSlice(gpa, " %*");
    try tmp.dir.writeFile(io, .{ .sub_path = "args1.bat", .data = buf.items });
    buf.shrinkRetainingCapacity(preamble_len);

    try buf.appendSlice(gpa, " %1 %2 %3 %4 %5 %6 %7 %8 %9");
    try tmp.dir.writeFile(io, .{ .sub_path = "args2.bat", .data = buf.items });
    buf.shrinkRetainingCapacity(preamble_len);

    try buf.appendSlice(gpa, " \"%~1\" \"%~2\" \"%~3\" \"%~4\" \"%~5\" \"%~6\" \"%~7\" \"%~8\" \"%~9\"");
    try tmp.dir.writeFile(io, .{ .sub_path = "args3.bat", .data = buf.items });
    buf.shrinkRetainingCapacity(preamble_len);

    var i: u64 = 0;
    while (iterations == 0 or i < iterations) {
        const rand_arg = try randomArg(gpa, rand);
        defer gpa.free(rand_arg);

        try testExec(gpa, io, &.{rand_arg}, null);

        i += 1;
    }
}

fn testExec(gpa: Allocator, io: Io, args: []const []const u8, env: ?*std.process.Environ.Map) !void {
    try testExecBat(gpa, io, "args1.bat", args, env);
    try testExecBat(gpa, io, "args2.bat", args, env);
    try testExecBat(gpa, io, "args3.bat", args, env);
}

fn testExecBat(gpa: Allocator, io: Io, bat: []const u8, args: []const []const u8, env: ?*std.process.Environ.Map) !void {
    const argv = try gpa.alloc([]const u8, 1 + args.len);
    defer gpa.free(argv);
    argv[0] = bat;
    @memcpy(argv[1..], args);

    const can_have_trailing_empty_args = std.mem.eql(u8, bat, "args3.bat");

    const result = try std.process.run(gpa, io, .{
        .environ_map = env,
        .argv = argv,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    try std.testing.expectEqualStrings("", result.stderr);
    var it = std.mem.splitScalar(u8, result.stdout, '\x00');
    var i: usize = 0;
    while (it.next()) |actual_arg| {
        if (i >= args.len and can_have_trailing_empty_args) {
            try std.testing.expectEqualStrings("", actual_arg);
            continue;
        }
        const expected_arg = args[i];
        try std.testing.expectEqualSlices(u8, expected_arg, actual_arg);
        i += 1;
    }
}

fn randomArg(gpa: Allocator, rand: std.Random) ![]const u8 {
    const Choice = enum {
        backslash,
        quote,
        space,
        control,
        printable,
        surrogate_half,
        non_ascii,
    };

    const choices = rand.uintAtMostBiased(u16, 256);
    var buf: std.ArrayList(u8) = try .initCapacity(gpa, choices);
    errdefer buf.deinit(gpa);

    var last_codepoint: u21 = 0;
    for (0..choices) |_| {
        const choice = rand.enumValue(Choice);
        const codepoint: u21 = switch (choice) {
            .backslash => '\\',
            .quote => '"',
            .space => ' ',
            .control => switch (rand.uintAtMostBiased(u8, 0x21)) {
                // NUL/CR/LF can't roundtrip
                '\x00', '\r', '\n' => ' ',
                0x21 => '\x7F',
                else => |b| b,
            },
            .printable => '!' + rand.uintAtMostBiased(u8, '~' - '!'),
            .surrogate_half => rand.intRangeAtMostBiased(u16, 0xD800, 0xDFFF),
            .non_ascii => rand.intRangeAtMostBiased(u21, 0x80, 0x10FFFF),
        };
        // Ensure that we always return well-formed WTF-8.
        // Instead of concatenating to ensure well-formed WTF-8,
        // we just skip encoding the low surrogate.
        if (std.unicode.isSurrogateCodepoint(last_codepoint) and std.unicode.isSurrogateCodepoint(codepoint)) {
            if (std.unicode.utf16IsHighSurrogate(@intCast(last_codepoint)) and std.unicode.utf16IsLowSurrogate(@intCast(codepoint))) {
                continue;
            }
        }
        try buf.ensureUnusedCapacity(gpa, 4);
        const unused_slice = buf.unusedCapacitySlice();
        const len = std.unicode.wtf8Encode(codepoint, unused_slice) catch unreachable;
        buf.items.len += len;
        last_codepoint = codepoint;
    }

    return buf.toOwnedSlice(gpa);
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
