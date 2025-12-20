const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const windows = std.os.windows;
const utf16Literal = std.unicode.utf8ToUtf16LeStringLiteral;

pub fn main() anyerror!void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) @panic("found memory leaks");
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const hello_exe_cache_path = it.next() orelse unreachable;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_absolute_path = try tmp.dir.realpathAlloc(gpa, ".");
    defer gpa.free(tmp_absolute_path);
    const tmp_absolute_path_w = try std.unicode.utf8ToUtf16LeAllocZ(gpa, tmp_absolute_path);
    defer gpa.free(tmp_absolute_path_w);
    const cwd_absolute_path = try Io.Dir.cwd().realpathAlloc(gpa, ".");
    defer gpa.free(cwd_absolute_path);
    const tmp_relative_path = try std.fs.path.relative(gpa, cwd_absolute_path, tmp_absolute_path);
    defer gpa.free(tmp_relative_path);

    // Clear PATH
    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        null,
    ) == windows.TRUE);

    // Set PATHEXT to something predictable
    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATHEXT"),
        utf16Literal(".COM;.EXE;.BAT;.CMD;.JS"),
    ) == windows.TRUE);

    // No PATH, so it should fail to find anything not in the cwd
    try testExecError(error.FileNotFound, gpa, "something_missing");

    // make sure we don't get error.BadPath traversing out of cwd with a relative path
    try testExecError(error.FileNotFound, gpa, "..\\.\\.\\.\\\\..\\more_missing");

    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        tmp_absolute_path_w,
    ) == windows.TRUE);

    // Move hello.exe into the tmp dir which is now added to the path
    try Io.Dir.cwd().copyFile(hello_exe_cache_path, tmp.dir, "hello.exe", .{});

    // with extension should find the .exe (case insensitive)
    try testExec(gpa, "HeLLo.exe", "hello from exe\n");
    // without extension should find the .exe (case insensitive)
    try testExec(gpa, "heLLo", "hello from exe\n");
    // with invalid cwd
    try std.testing.expectError(error.FileNotFound, testExecWithCwd(gpa, io, "hello.exe", "missing_dir", ""));

    // now add a .bat
    try tmp.dir.writeFile(io, .{ .sub_path = "hello.bat", .data = "@echo hello from bat" });
    // and a .cmd
    try tmp.dir.writeFile(io, .{ .sub_path = "hello.cmd", .data = "@echo hello from cmd" });

    // with extension should find the .bat (case insensitive)
    try testExec(gpa, "heLLo.bat", "hello from bat\r\n");
    // with extension should find the .cmd (case insensitive)
    try testExec(gpa, "heLLo.cmd", "hello from cmd\r\n");
    // without extension should find the .exe (since its first in PATHEXT)
    try testExec(gpa, "heLLo", "hello from exe\n");

    // now rename the exe to not have an extension
    try renameExe(tmp.dir, "hello.exe", "hello");

    // with extension should now fail
    try testExecError(error.FileNotFound, gpa, "hello.exe");
    // without extension should succeed (case insensitive)
    try testExec(gpa, "heLLo", "hello from exe\n");

    try tmp.dir.createDir(io, "something", .default_dir);
    try renameExe(tmp.dir, "hello", "something/hello.exe");

    const relative_path_no_ext = try std.fs.path.join(gpa, &.{ tmp_relative_path, "something/hello" });
    defer gpa.free(relative_path_no_ext);

    // Giving a full relative path to something/hello should work
    try testExec(gpa, relative_path_no_ext, "hello from exe\n");
    // But commands with path separators get excluded from PATH searching, so this will fail
    try testExecError(error.FileNotFound, gpa, "something/hello");

    // Now that .BAT is the first PATHEXT that should be found, this should succeed
    try testExec(gpa, "heLLo", "hello from bat\r\n");

    // Add a hello.exe that is not a valid executable
    try tmp.dir.writeFile(io, .{ .sub_path = "hello.exe", .data = "invalid" });

    // Trying to execute it with extension will give InvalidExe. This is a special
    // case for .EXE extensions, where if they ever try to get executed but they are
    // invalid, that gets treated as a fatal error wherever they are found and InvalidExe
    // is returned immediately.
    try testExecError(error.InvalidExe, gpa, "hello.exe");
    // Same thing applies to the command with no extension--even though there is a
    // hello.bat that could be executed, it should stop after it tries executing
    // hello.exe and getting InvalidExe.
    try testExecError(error.InvalidExe, gpa, "hello");

    // If we now rename hello.exe to have no extension, it will behave differently
    try renameExe(tmp.dir, "hello.exe", "hello");

    // Now, trying to execute it without an extension should treat InvalidExe as recoverable
    // and skip over it and find hello.bat and execute that
    try testExec(gpa, "hello", "hello from bat\r\n");

    // If we rename the invalid exe to something else
    try renameExe(tmp.dir, "hello", "goodbye");
    // Then we should now get FileNotFound when trying to execute 'goodbye',
    // since that is what the original error will be after searching for 'goodbye'
    // in the cwd. It will try to execute 'goodbye' from the PATH but the InvalidExe error
    // should be ignored in this case.
    try testExecError(error.FileNotFound, gpa, "goodbye");

    // Now let's set the tmp dir as the cwd and set the path only include the "something" sub dir
    try tmp.dir.setAsCwd();
    defer tmp.parent_dir.setAsCwd() catch {};
    const something_subdir_abs_path = try std.mem.concatWithSentinel(gpa, u16, &.{ tmp_absolute_path_w, utf16Literal("\\something") }, 0);
    defer gpa.free(something_subdir_abs_path);

    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        something_subdir_abs_path,
    ) == windows.TRUE);

    // Now trying to execute goodbye should give error.InvalidExe since it's the original
    // error that we got when trying within the cwd
    try testExecError(error.InvalidExe, gpa, "goodbye");

    // hello should still find the .bat
    try testExec(gpa, "hello", "hello from bat\r\n");

    // If we rename something/hello.exe to something/goodbye.exe
    try renameExe(tmp.dir, "something/hello.exe", "something/goodbye.exe");
    // And try to execute goodbye, then the one in something should be found
    // since the one in cwd is an invalid executable
    try testExec(gpa, "goodbye", "hello from exe\n");

    // If we use an absolute path to execute the invalid goodbye
    const goodbye_abs_path = try std.mem.join(gpa, "\\", &.{ tmp_absolute_path, "goodbye" });
    defer gpa.free(goodbye_abs_path);
    // then the PATH should not be searched and we should get InvalidExe
    try testExecError(error.InvalidExe, gpa, goodbye_abs_path);

    // If we try to exec but provide a cwd that is an absolute path, the PATH
    // should still be searched and the goodbye.exe in something should be found.
    try testExecWithCwd(gpa, "goodbye", tmp_absolute_path, "hello from exe\n");

    // introduce some extra path separators into the path which is dealt with inside the spawn call.
    const denormed_something_subdir_size = std.mem.replacementSize(u16, something_subdir_abs_path, utf16Literal("\\"), utf16Literal("\\\\\\\\"));

    const denormed_something_subdir_abs_path = try gpa.allocSentinel(u16, denormed_something_subdir_size, 0);
    defer gpa.free(denormed_something_subdir_abs_path);

    _ = std.mem.replace(u16, something_subdir_abs_path, utf16Literal("\\"), utf16Literal("\\\\\\\\"), denormed_something_subdir_abs_path);

    const denormed_something_subdir_wtf8 = try std.unicode.wtf16LeToWtf8Alloc(gpa, denormed_something_subdir_abs_path);
    defer gpa.free(denormed_something_subdir_wtf8);

    // clear the path to ensure that the match comes from the cwd
    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        null,
    ) == windows.TRUE);

    try testExecWithCwd(gpa, "goodbye", denormed_something_subdir_wtf8, "hello from exe\n");

    // normalization should also work if the non-normalized path is found in the PATH var.
    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        denormed_something_subdir_abs_path,
    ) == windows.TRUE);
    try testExec(gpa, "goodbye", "hello from exe\n");

    // now make sure we can launch executables "outside" of the cwd
    var subdir_cwd = try tmp.dir.openDir(denormed_something_subdir_wtf8, .{});
    defer subdir_cwd.close(io);

    try renameExe(tmp.dir, "something/goodbye.exe", "hello.exe");
    try subdir_cwd.setAsCwd();

    // clear the PATH again
    std.debug.assert(windows.kernel32.SetEnvironmentVariableW(
        utf16Literal("PATH"),
        null,
    ) == windows.TRUE);

    // while we're at it make sure non-windows separators work fine
    try testExec(gpa, "../hello", "hello from exe\n");
}

fn testExecError(err: anyerror, gpa: Allocator, command: []const u8) !void {
    return std.testing.expectError(err, testExec(gpa, command, ""));
}

fn testExec(gpa: Allocator, command: []const u8, expected_stdout: []const u8) !void {
    return testExecWithCwd(gpa, command, null, expected_stdout);
}

fn testExecWithCwd(gpa: Allocator, io: Io, command: []const u8, cwd: ?[]const u8, expected_stdout: []const u8) !void {
    const result = try std.process.Child.run(gpa, io, .{
        .argv = &[_][]const u8{command},
        .cwd = cwd,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    try std.testing.expectEqualStrings("", result.stderr);
    try std.testing.expectEqualStrings(expected_stdout, result.stdout);
}

fn renameExe(dir: Io.Dir, old_sub_path: []const u8, new_sub_path: []const u8) !void {
    var attempt: u5 = 0;
    while (true) break dir.rename(old_sub_path, new_sub_path) catch |err| switch (err) {
        error.AccessDenied => {
            if (attempt == 13) return error.AccessDenied;
            // give the kernel a chance to finish closing the executable handle
            _ = std.os.windows.kernel32.SleepEx(@as(u32, 1) << attempt >> 1, std.os.windows.FALSE);
            attempt += 1;
            continue;
        },
        else => |e| return e,
    };
}
