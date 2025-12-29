const builtin = @import("builtin");
const native_os = builtin.os.tag;

const std = @import("std.zig");
const Io = std.Io;
const File = std.Io.File;
const fs = std.fs;
const mem = std.mem;
const math = std.math;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;
const posix = std.posix;
const windows = std.os.windows;
const unicode = std.unicode;
const max_path_bytes = std.fs.max_path_bytes;

pub const Child = @import("process/Child.zig");
pub const Args = @import("process/Args.zig");
pub const Environ = @import("process/Environ.zig");

/// This is the global, process-wide protection to coordinate stderr writes.
///
/// The primary motivation for recursive mutex here is so that a panic while
/// stderr mutex is held still dumps the stack trace and other debug
/// information.
pub var stderr_thread_mutex: std.Thread.Mutex.Recursive = .init;

/// A standard set of pre-initialized useful APIs for programs to take
/// advantage of. This is the type of the first parameter of the main function.
/// Applications wanting more flexibility can accept `Init.Minimal` instead.
///
/// Completion of https://github.com/ziglang/zig/issues/24510 will also allow
/// the second parameter of the main function to be a custom struct that
/// contain auto-parsed CLI arguments.
pub const Init = struct {
    /// `Init` is a superset of `Minimal`; the latter is included here.
    minimal: Minimal,
    /// Permanent storage for the entire process, cleaned automatically on
    /// exit. Not threadsafe.
    arena: *std.heap.ArenaAllocator,
    /// A default-selected general purpose allocator for temporary heap
    /// allocations. Debug mode will set up leak checking. Threadsafe.
    gpa: Allocator,
    /// An appropriate default Io implementation based on the target
    /// configuration. Debug mode will set up leak checking.
    io: Io,
    /// Environment variables, initialized with `gpa`. Not threadsafe.
    env_map: *Environ.Map,

    /// Alternative to `Init` as the first parameter of the main function.
    pub const Minimal = struct {
        /// Environment variables.
        environ: Environ,
        /// Command line arguments.
        args: Args,
    };
};

pub const GetCwdError = posix.GetCwdError;

/// The result is a slice of `out_buffer`, from index `0`.
/// On Windows, the result is encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn getCwd(out_buffer: []u8) GetCwdError![]u8 {
    return posix.getcwd(out_buffer);
}

// Same as GetCwdError, minus error.NameTooLong + Allocator.Error
pub const GetCwdAllocError = Allocator.Error || error{CurrentWorkingDirectoryUnlinked} || posix.UnexpectedError;

/// Caller must free the returned memory.
/// On Windows, the result is encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn getCwdAlloc(allocator: Allocator) GetCwdAllocError![]u8 {
    // The use of max_path_bytes here is just a heuristic: most paths will fit
    // in stack_buf, avoiding an extra allocation in the common case.
    var stack_buf: [max_path_bytes]u8 = undefined;
    var heap_buf: ?[]u8 = null;
    defer if (heap_buf) |buf| allocator.free(buf);

    var current_buf: []u8 = &stack_buf;
    while (true) {
        if (posix.getcwd(current_buf)) |slice| {
            return allocator.dupe(u8, slice);
        } else |err| switch (err) {
            error.NameTooLong => {
                // The path is too long to fit in stack_buf. Allocate geometrically
                // increasing buffers until we find one that works
                const new_capacity = current_buf.len * 2;
                if (heap_buf) |buf| allocator.free(buf);
                current_buf = try allocator.alloc(u8, new_capacity);
                heap_buf = current_buf;
            },
            else => |e| return e,
        }
    }
}

test getCwdAlloc {
    if (native_os == .wasi) return error.SkipZigTest;

    const cwd = try getCwdAlloc(testing.allocator);
    testing.allocator.free(cwd);
}

pub const UserInfo = struct {
    uid: posix.uid_t,
    gid: posix.gid_t,
};

/// POSIX function which gets a uid from username.
pub fn getUserInfo(name: []const u8) !UserInfo {
    return switch (native_os) {
        .linux,
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        .freebsd,
        .netbsd,
        .openbsd,
        .haiku,
        .illumos,
        .serenity,
        => posixGetUserInfo(name),
        else => @compileError("Unsupported OS"),
    };
}

/// TODO this reads /etc/passwd. But sometimes the user/id mapping is in something else
/// like NIS, AD, etc. See `man nss` or look at an strace for `id myuser`.
pub fn posixGetUserInfo(io: Io, name: []const u8) !UserInfo {
    const file = try Io.Dir.openFileAbsolute(io, "/etc/passwd", .{});
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var file_reader = file.reader(&buffer);
    return posixGetUserInfoPasswdStream(name, &file_reader.interface) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.EndOfStream => return error.UserNotFound,
        error.CorruptPasswordFile => return error.CorruptPasswordFile,
    };
}

fn posixGetUserInfoPasswdStream(name: []const u8, reader: *std.Io.Reader) !UserInfo {
    const State = enum {
        start,
        wait_for_next_line,
        skip_password,
        read_user_id,
        read_group_id,
    };

    var name_index: usize = 0;
    var uid: posix.uid_t = 0;
    var gid: posix.gid_t = 0;

    sw: switch (State.start) {
        .start => switch (try reader.takeByte()) {
            ':' => {
                if (name_index == name.len) {
                    continue :sw .skip_password;
                } else {
                    continue :sw .wait_for_next_line;
                }
            },
            '\n' => return error.CorruptPasswordFile,
            else => |byte| {
                if (name_index == name.len or name[name_index] != byte) {
                    continue :sw .wait_for_next_line;
                }
                name_index += 1;
                continue :sw .start;
            },
        },
        .wait_for_next_line => switch (try reader.takeByte()) {
            '\n' => {
                name_index = 0;
                continue :sw .start;
            },
            else => continue :sw .wait_for_next_line,
        },
        .skip_password => switch (try reader.takeByte()) {
            '\n' => return error.CorruptPasswordFile,
            ':' => {
                continue :sw .read_user_id;
            },
            else => continue :sw .skip_password,
        },
        .read_user_id => switch (try reader.takeByte()) {
            ':' => {
                continue :sw .read_group_id;
            },
            '\n' => return error.CorruptPasswordFile,
            else => |byte| {
                const digit = switch (byte) {
                    '0'...'9' => byte - '0',
                    else => return error.CorruptPasswordFile,
                };
                {
                    const ov = @mulWithOverflow(uid, 10);
                    if (ov[1] != 0) return error.CorruptPasswordFile;
                    uid = ov[0];
                }
                {
                    const ov = @addWithOverflow(uid, digit);
                    if (ov[1] != 0) return error.CorruptPasswordFile;
                    uid = ov[0];
                }
                continue :sw .read_user_id;
            },
        },
        .read_group_id => switch (try reader.takeByte()) {
            '\n', ':' => return .{
                .uid = uid,
                .gid = gid,
            },
            else => |byte| {
                const digit = switch (byte) {
                    '0'...'9' => byte - '0',
                    else => return error.CorruptPasswordFile,
                };
                {
                    const ov = @mulWithOverflow(gid, 10);
                    if (ov[1] != 0) return error.CorruptPasswordFile;
                    gid = ov[0];
                }
                {
                    const ov = @addWithOverflow(gid, digit);
                    if (ov[1] != 0) return error.CorruptPasswordFile;
                    gid = ov[0];
                }
                continue :sw .read_group_id;
            },
        },
    }
    comptime unreachable;
}

pub fn getBaseAddress() usize {
    switch (native_os) {
        .linux => {
            const phdrs = std.posix.getSelfPhdrs();
            var base: usize = 0;
            for (phdrs) |phdr| switch (phdr.type) {
                .LOAD => return base + phdr.vaddr,
                .PHDR => base = @intFromPtr(phdrs.ptr) - phdr.vaddr,
                else => {},
            } else unreachable;
        },
        .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
            return @intFromPtr(&std.c._mh_execute_header);
        },
        .windows => return @intFromPtr(windows.kernel32.GetModuleHandleW(null)),
        else => @compileError("Unsupported OS"),
    }
}

/// Deprecated in favor of `Child.can_spawn`.
pub const can_spawn = Child.can_spawn;
/// Deprecated in favor of `can_replace`.
pub const can_execv = can_replace;

/// Tells whether the target operating system supports replacing the current
/// process image. If this is `false` then calling `execv` or `replace`
/// functions will cause compilation to fail.
pub const can_replace = switch (native_os) {
    .windows, .haiku, .wasi => false,
    else => true,
};

pub const ReplaceError = std.posix.ExecveError || error{OutOfMemory};

/// Replaces the current process image with the executed process. If this
/// function succeeds, it does not return.
///
/// `argv[0]` is the name of the process to replace the current one with. If it
/// is not already a file path (i.e. it contains '/'), it is resolved into a
/// file path based on PATH from the parent environment.
///
/// This operation is not available on targets for which `can_replace` is
/// `false`.
///
/// This function must allocate memory to add a null terminating bytes on path
/// and each arg.
///
/// Due to the heap allocation, it is illegal to call this function in a fork()
/// child.
pub fn replace(io: Io, gpa: Allocator, argv: []const []const u8, env: Environ.Block) ReplaceError {
    if (!can_replace) @compileError("unsupported operation: replace");

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

    return posix.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, env);
}

/// Replaces the current process image with the executed process. If this
/// function succeeds, it does not return.
///
/// `argv[0]` is the file path of the process to replace the current one with,
/// relative to `dir`. It is *always* treated as a file path, even if it does
/// not contain '/'.
///
/// This operation is not available on targets for which `can_replace` is
/// `false`.
///
/// This function must allocate memory to add a null terminating bytes on path
/// and each arg.
///
/// Due to the heap allocation, it is illegal to call this
/// function in a fork() child. For that use case, use the `std.posix`
/// functions directly.
pub fn replaceFile(io: Io, gpa: Allocator, argv: []const []const u8, env: Environ.Block) ReplaceError {
    if (!can_replace) @compileError("unsupported operation: replaceFile");

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

    return posix.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, env);
}

pub const Arg0Expand = enum { expand, no_expand };

/// Replaces the current process image with the executed process. If this
/// function succeeds, it does not return.
///
/// This operation is not available on all targets. `can_execv`
///
/// This function also uses the PATH environment variable to get the full path to the executable.
/// If `file` is an absolute path, this is the same as `execveZ`.
///
/// Like `execvpeZ` except if `arg0_expand` is `.expand`, then `argv` is mutable,
/// and `argv[0]` is expanded to be the same absolute path that is passed to the execve syscall.
/// If this function returns with an error, `argv[0]` will be restored to the value it was when it was passed in.
pub fn replace(
    comptime arg0_expand: Arg0Expand,
    file: [*:0]const u8,
    child_argv: switch (arg0_expand) {
        .expand => [*:null]?[*:0]const u8,
        .no_expand => [*:null]const ?[*:0]const u8,
    },
    envp: [*:null]const ?[*:0]const u8,
    optional_PATH: ?[]const u8,
) ExecveError {
    const file_slice = mem.sliceTo(file, 0);
    if (mem.findScalar(u8, file_slice, '/') != null) return execveZ(file, child_argv, envp);

    const PATH = optional_PATH orelse "/usr/local/bin:/bin/:/usr/bin";
    // Use of PATH_MAX here is valid as the path_buf will be passed
    // directly to the operating system in execveZ.
    var path_buf: [PATH_MAX]u8 = undefined;
    var it = mem.tokenizeScalar(u8, PATH, ':');
    var seen_eacces = false;
    var err: ExecveError = error.FileNotFound;

    // In case of expanding arg0 we must put it back if we return with an error.
    const prev_arg0 = child_argv[0];
    defer switch (arg0_expand) {
        .expand => child_argv[0] = prev_arg0,
        .no_expand => {},
    };

    while (it.next()) |search_path| {
        const path_len = search_path.len + file_slice.len + 1;
        if (path_buf.len < path_len + 1) return error.NameTooLong;
        @memcpy(path_buf[0..search_path.len], search_path);
        path_buf[search_path.len] = '/';
        @memcpy(path_buf[search_path.len + 1 ..][0..file_slice.len], file_slice);
        path_buf[path_len] = 0;
        const full_path = path_buf[0..path_len :0].ptr;
        switch (arg0_expand) {
            .expand => child_argv[0] = full_path,
            .no_expand => {},
        }
        err = execveZ(full_path, child_argv, envp);
        switch (err) {
            error.AccessDenied => seen_eacces = true,
            error.FileNotFound, error.NotDir => {},
            else => |e| return e,
        }
    }
    if (seen_eacces) return error.AccessDenied;
    return err;
}


pub const TotalSystemMemoryError = error{
    UnknownTotalSystemMemory,
};

/// Returns the total system memory, in bytes as a u64.
/// We return a u64 instead of usize due to PAE on ARM
/// and Linux's /proc/meminfo reporting more memory when
/// using QEMU user mode emulation.
pub fn totalSystemMemory() TotalSystemMemoryError!u64 {
    switch (native_os) {
        .linux => {
            var info: std.os.linux.Sysinfo = undefined;
            const result: usize = std.os.linux.sysinfo(&info);
            if (std.os.linux.errno(result) != .SUCCESS) {
                return error.UnknownTotalSystemMemory;
            }
            // Promote to u64 to avoid overflow on systems where info.totalram is a 32-bit usize
            return @as(u64, info.totalram) * info.mem_unit;
        },
        .freebsd => {
            var physmem: c_ulong = undefined;
            var len: usize = @sizeOf(c_ulong);
            posix.sysctlbynameZ("hw.physmem", &physmem, &len, null, 0) catch |err| switch (err) {
                error.UnknownName => unreachable,
                else => return error.UnknownTotalSystemMemory,
            };
            return @as(u64, @intCast(physmem));
        },
        // whole Darwin family
        .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
            // "hw.memsize" returns uint64_t
            var physmem: u64 = undefined;
            var len: usize = @sizeOf(u64);
            posix.sysctlbynameZ("hw.memsize", &physmem, &len, null, 0) catch |err| switch (err) {
                error.PermissionDenied => unreachable, // only when setting values,
                error.SystemResources => unreachable, // memory already on the stack
                error.UnknownName => unreachable, // constant, known good value
                else => return error.UnknownTotalSystemMemory,
            };
            return physmem;
        },
        .openbsd => {
            const mib: [2]c_int = [_]c_int{
                posix.CTL.HW,
                posix.HW.PHYSMEM64,
            };
            var physmem: i64 = undefined;
            var len: usize = @sizeOf(@TypeOf(physmem));
            posix.sysctl(&mib, &physmem, &len, null, 0) catch |err| switch (err) {
                error.NameTooLong => unreachable, // constant, known good value
                error.PermissionDenied => unreachable, // only when setting values,
                error.SystemResources => unreachable, // memory already on the stack
                error.UnknownName => unreachable, // constant, known good value
                else => return error.UnknownTotalSystemMemory,
            };
            assert(physmem >= 0);
            return @as(u64, @bitCast(physmem));
        },
        .windows => {
            var sbi: windows.SYSTEM_BASIC_INFORMATION = undefined;
            const rc = windows.ntdll.NtQuerySystemInformation(
                .SystemBasicInformation,
                &sbi,
                @sizeOf(windows.SYSTEM_BASIC_INFORMATION),
                null,
            );
            if (rc != .SUCCESS) {
                return error.UnknownTotalSystemMemory;
            }
            return @as(u64, sbi.NumberOfPhysicalPages) * sbi.PageSize;
        },
        else => return error.UnknownTotalSystemMemory,
    }
}

/// Indicate intent to terminate with a successful exit code.
///
/// In debug builds, this is a no-op, so that the calling code's cleanup
/// mechanisms are tested and so that external tools checking for resource
/// leaks can be accurate. In release builds, this calls `exit` with code zero,
/// and does not return.
pub fn cleanExit(io: Io) void {
    if (builtin.mode == .Debug) return;
    _ = io.lockStderr(&.{}, .no_color) catch {};
    exit(0);
}

/// Request ability to have more open file descriptors simultaneously.
///
/// On some systems, this raises the limit before seeing ProcessFdQuotaExceeded
/// errors. On other systems, this does nothing.
pub fn raiseFileDescriptorLimit() void {
    const have_rlimit = posix.rlimit_resource != void;
    if (!have_rlimit) return;

    var lim = posix.getrlimit(.NOFILE) catch return; // Oh well; we tried.
    if (native_os.isDarwin()) {
        // On Darwin, `NOFILE` is bounded by a hardcoded value `OPEN_MAX`.
        // According to the man pages for setrlimit():
        //   setrlimit() now returns with errno set to EINVAL in places that historically succeeded.
        //   It no longer accepts "rlim_cur = RLIM.INFINITY" for RLIM.NOFILE.
        //   Use "rlim_cur = min(OPEN_MAX, rlim_max)".
        lim.max = @min(std.c.OPEN_MAX, lim.max);
    }
    if (lim.cur == lim.max) return;

    // Do a binary search for the limit.
    var min: posix.rlim_t = lim.cur;
    var max: posix.rlim_t = 1 << 20;
    // But if there's a defined upper bound, don't search, just set it.
    if (lim.max != posix.RLIM.INFINITY) {
        min = lim.max;
        max = lim.max;
    }

    while (true) {
        lim.cur = min + @divTrunc(max - min, 2); // on freebsd rlim_t is signed
        if (posix.setrlimit(.NOFILE, lim)) |_| {
            min = lim.cur;
        } else |_| {
            max = lim.cur;
        }
        if (min + 1 >= max) break;
    }
}

test raiseFileDescriptorLimit {
    raiseFileDescriptorLimit();
}

/// Logs an error and then terminates the process with exit code 1.
pub fn fatal(comptime format: []const u8, format_arguments: anytype) noreturn {
    std.log.err(format, format_arguments);
    exit(1);
}

pub const ExecutablePathBaseError = error{
    FileNotFound,
    AccessDenied,
    /// The operating system does not support an executable learning its own
    /// path.
    OperationUnsupported,
    NotDir,
    SymLinkLoop,
    InputOutput,
    FileTooBig,
    IsDir,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    NoSpaceLeft,
    FileSystem,
    BadPathName,
    DeviceBusy,
    SharingViolation,
    PipeBusy,
    NotLink,
    PathAlreadyExists,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    ProcessNotFound,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
    /// On Windows, the volume does not contain a recognized file system. File
    /// system drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
    PermissionDenied,
} || Io.Cancelable || Io.UnexpectedError;

pub const ExecutablePathAllocError = ExecutablePathBaseError || Allocator.Error;

pub fn executablePathAlloc(io: Io, allocator: Allocator) ExecutablePathAllocError![:0]u8 {
    var buffer: [max_path_bytes]u8 = undefined;
    const n = executablePath(io, &buffer) catch |err| switch (err) {
        error.NameTooLong => unreachable,
        else => |e| return e,
    };
    return allocator.dupeZ(u8, buffer[0..n]);
}

pub const ExecutablePathError = ExecutablePathBaseError || error{NameTooLong};

/// Get the path to the current executable, following symlinks.
///
/// This function may return an error if the current executable
/// was deleted after spawning.
///
/// Returned value is a slice of out_buffer.
///
/// On Windows, the result is encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
///
/// On Linux, depends on procfs being mounted. If the currently executing binary has
/// been deleted, the file path looks something like "/a/b/c/exe (deleted)".
///
/// See also:
/// * `executableDirPath` - to obtain only the directory
/// * `openExecutable` - to obtain only an open file handle
pub fn executablePath(io: Io, out_buffer: []u8) ExecutablePathError!usize {
    return io.vtable.processExecutablePath(io.userdata, out_buffer);
}

/// Get the directory path that contains the current executable.
///
/// Returns index into `out_buffer`.
///
/// On Windows, the result is encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn executableDirPath(io: Io, out_buffer: []u8) ExecutablePathError!usize {
    const n = try executablePath(io, out_buffer);
    // Assert that the OS APIs return absolute paths, and therefore dirname
    // will not return null.
    return std.fs.path.dirname(out_buffer[0..n]).?.len;
}

/// Same as `executableDirPath` except allocates the result.
pub fn executableDirPathAlloc(io: Io, allocator: Allocator) ExecutablePathAllocError![]u8 {
    var buffer: [max_path_bytes]u8 = undefined;
    const dir_path_len = executableDirPath(io, &buffer) catch |err| switch (err) {
        error.NameTooLong => unreachable,
        else => |e| return e,
    };
    return allocator.dupe(u8, buffer[0..dir_path_len]);
}

pub const OpenExecutableError = File.OpenError || ExecutablePathError || File.LockError;

pub fn openExecutable(io: Io, flags: File.OpenFlags) OpenExecutableError!File {
    return io.vtable.processExecutableOpen(io.userdata, flags);
}

/// Causes abnormal process termination.
///
/// If linking against libc, this calls `std.c.abort`. Otherwise it raises
/// SIGABRT followed by SIGKILL.
///
/// Invokes the current signal handler for SIGABRT, if any.
pub fn abort() noreturn {
    @branchHint(.cold);
    // MSVCRT abort() sometimes opens a popup window which is undesirable, so
    // even when linking libc on Windows we use our own abort implementation.
    // See https://github.com/ziglang/zig/issues/2071 for more details.
    if (native_os == .windows) {
        if (builtin.mode == .Debug and windows.peb().BeingDebugged != 0) {
            @breakpoint();
        }
        windows.ntdll.RtlExitUserProcess(3);
    }
    if (!builtin.link_libc and native_os == .linux) {
        // The Linux man page says that the libc abort() function
        // "first unblocks the SIGABRT signal", but this is a footgun
        // for user-defined signal handlers that want to restore some state in
        // some program sections and crash in others.
        // So, the user-installed SIGABRT handler is run, if present.
        posix.raise(.ABRT) catch {};

        // Disable all signal handlers.
        const filledset = std.os.linux.sigfillset();
        posix.sigprocmask(posix.SIG.BLOCK, &filledset, null);

        // Only one thread may proceed to the rest of abort().
        if (!builtin.single_threaded) {
            const global = struct {
                var abort_entered: bool = false;
            };
            while (@cmpxchgWeak(bool, &global.abort_entered, false, true, .seq_cst, .seq_cst)) |_| {}
        }

        // Install default handler so that the tkill below will terminate.
        const sigact: posix.Sigaction = .{
            .handler = .{ .handler = posix.SIG.DFL },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(.ABRT, &sigact, null);

        _ = std.os.linux.tkill(std.os.linux.gettid(), .ABRT);

        var sigabrtmask = posix.sigemptyset();
        posix.sigaddset(&sigabrtmask, .ABRT);
        posix.sigprocmask(posix.SIG.UNBLOCK, &sigabrtmask, null);

        // Beyond this point should be unreachable.
        @as(*allowzero volatile u8, @ptrFromInt(0)).* = 0;
        posix.raise(.KILL) catch {};
        exit(127); // Pid 1 might not be signalled in some containers.
    }
    switch (native_os) {
        .uefi, .wasi, .emscripten, .cuda, .amdhsa => @trap(),
        else => posix.system.abort(),
    }
}

/// Exits all threads of the program with the specified status code.
pub fn exit(status: u8) noreturn {
    if (builtin.link_libc) {
        std.c.exit(status);
    } else switch (native_os) {
        .windows => windows.ntdll.RtlExitUserProcess(status),
        .wasi => std.os.wasi.proc_exit(status),
        .linux => {
            if (!builtin.single_threaded) std.os.linux.exit_group(status);
            posix.system.exit(status);
        },
        .uefi => {
            const uefi = std.os.uefi;
            // exit() is only available if exitBootServices() has not been called yet.
            // This call to exit should not fail, so we catch-ignore errors.
            if (uefi.system_table.boot_services) |bs| {
                bs.exit(uefi.handle, @enumFromInt(status), null) catch {};
            }
            // If we can't exit, reboot the system instead.
            uefi.system_table.runtime_services.resetSystem(.cold, @enumFromInt(status), null);
        },
        else => posix.system.exit(status),
    }
}

pub const SetCurrentDirError = error{
    AccessDenied,
    BadPathName,
    FileNotFound,
    FileSystem,
    NameTooLong,
    NoDevice,
    NotDir,
    OperationUnsupported,
    UnrecognizedVolume,
} || Io.Cancelable || Io.UnexpectedError;

/// Changes the current working directory to the open directory handle.
/// Corresponds to "fchdir" in libc.
///
/// This modifies global process state and can have surprising effects in
/// multithreaded applications. Most applications and especially libraries
/// should not call this function as a general rule, however it can have use
/// cases in, for example, implementing a shell, or child process execution.
///
/// Calling this function makes code less portable and less reusable.
pub fn setCurrentDir(io: Io, dir: Io.Dir) !void {
    return io.vtable.processSetCurrentDir(io.userdata, dir);
}
