const Dir = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;

const std = @import("../std.zig");
const Io = std.Io;
const File = Io.File;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

handle: Handle,

pub const Entry = struct {
    name: []const u8,
    kind: File.Kind,
    inode: File.INode,
};

/// Returns a handle to the current working directory.
///
/// It is not opened with iteration capability. Iterating over the result is
/// illegal behavior.
///
/// Closing the returned `Dir` is checked illegal behavior.
///
/// On POSIX targets, this function is comptime-callable.
///
/// On WASI, the value this returns is application-configurable.
pub fn cwd() Dir {
    return switch (native_os) {
        .windows => .{ .handle = std.os.windows.peb().ProcessParameters.CurrentDirectory.Handle },
        .wasi => .{ .handle = std.options.wasiCwd() },
        else => .{ .handle = std.posix.AT.FDCWD },
    };
}

pub const Reader = struct {
    dir: Dir,
    state: State,
    /// Stores I/O implementation specific data.
    buffer: [2048]u8 align(@alignOf(usize)),
    index: usize,

    pub const State = enum {
        /// Indicates the next call to `read` should rewind and start over the
        /// directory listing.
        reset,
        reading,
        finished,
    };

    pub const Error = error{
        AccessDenied,
        PermissionDenied,
        SystemResources,
    } || Io.UnexpectedError || Io.Cancelable;

    pub fn init(dir: Dir) Reader {
        return .{
            .dir = dir,
            .state = .reset,
            .index = 0,
            .buffer = undefined,
        };
    }

    pub fn read(r: *Reader, io: Io, buffer: []Entry) Error!usize {
        return io.vtable.dirRead(io.userdata, r, buffer);
    }
};

pub const Iterator = struct {
    reader: Reader,
    buffer: [32]Entry,
    /// Index of next entry in `buffer`.
    index: usize,
    /// Fill position of `buffer`.
    end: usize,

    pub const Error = Reader.Error;

    pub fn init(dir: Dir, reader_state: Reader.State) Iterator {
        return .{
            .reader = .{
                .dir = dir,
                .state = reader_state,
                .index = 0,
                .buffer = undefined,
            },
            .buffer = undefined,
            .index = 0,
            .end = 0,
        };
    }

    pub fn next(it: *Iterator, io: Io) Error!?Entry {
        if (it.end - it.index == 0) {
            if (it.reader.state == .finished) return null;
            it.end = try it.reader.read(io, &it.buffer);
            it.index = 0;
            if (it.end - it.index == 0) {
                assert(it.reader.state == .finished);
                return null;
            }
        }
        const index = it.index;
        it.index = index + 1;
        return it.buffer[index];
    }
};

pub fn iterate(dir: Dir) Iterator {
    return .init(dir, .reset);
}

/// Like `iterate`, but will not reset the directory cursor before the first
/// iteration. This should only be used in cases where it is known that the
/// `Dir` has not had its cursor modified yet (e.g. it was just opened).
pub fn iterateAssumeFirstIteration(dir: Dir) Iterator {
    return .init(dir, .reading);
}

pub const SelectiveWalker = struct {
    stack: std.ArrayList(Walker.StackItem),
    name_buffer: std.ArrayList(u8),
    allocator: Allocator,

    pub const Error = Io.Dir.Iterator.Error || Allocator.Error;

    /// After each call to this function, and on deinit(), the memory returned
    /// from this function becomes invalid. A copy must be made in order to keep
    /// a reference to the path.
    pub fn next(self: *SelectiveWalker, io: Io) Error!?Walker.Entry {
        while (self.stack.items.len > 0) {
            const top = &self.stack.items[self.stack.items.len - 1];
            var dirname_len = top.dirname_len;
            if (top.iter.next() catch |err| {
                // If we get an error, then we want the user to be able to continue
                // walking if they want, which means that we need to pop the directory
                // that errored from the stack. Otherwise, all future `next` calls would
                // likely just fail with the same error.
                var item = self.stack.pop().?;
                if (self.stack.items.len != 0) {
                    item.iter.dir.close(io);
                }
                return err;
            }) |entry| {
                self.name_buffer.shrinkRetainingCapacity(dirname_len);
                if (self.name_buffer.items.len != 0) {
                    try self.name_buffer.append(self.allocator, std.fs.path.sep);
                    dirname_len += 1;
                }
                try self.name_buffer.ensureUnusedCapacity(self.allocator, entry.name.len + 1);
                self.name_buffer.appendSliceAssumeCapacity(entry.name);
                self.name_buffer.appendAssumeCapacity(0);
                const walker_entry: Walker.Entry = .{
                    .dir = top.iter.dir,
                    .basename = self.name_buffer.items[dirname_len .. self.name_buffer.items.len - 1 :0],
                    .path = self.name_buffer.items[0 .. self.name_buffer.items.len - 1 :0],
                    .kind = entry.kind,
                };
                return walker_entry;
            } else {
                var item = self.stack.pop().?;
                if (self.stack.items.len != 0) {
                    item.iter.dir.close(io);
                }
            }
        }
        return null;
    }

    /// Traverses into the directory, continuing walking one level down.
    pub fn enter(self: *SelectiveWalker, io: Io, entry: Walker.Entry) !void {
        if (entry.kind != .directory) {
            @branchHint(.cold);
            return;
        }

        var new_dir = entry.dir.openDir(entry.basename, .{ .iterate = true }) catch |err| {
            switch (err) {
                error.NameTooLong => unreachable,
                else => |e| return e,
            }
        };
        errdefer new_dir.close(io);

        try self.stack.append(self.allocator, .{
            .iter = new_dir.iterateAssumeFirstIteration(),
            .dirname_len = self.name_buffer.items.len - 1,
        });
    }

    pub fn deinit(self: *SelectiveWalker) void {
        self.name_buffer.deinit(self.allocator);
        self.stack.deinit(self.allocator);
    }

    /// Leaves the current directory, continuing walking one level up.
    /// If the current entry is a directory entry, then the "current directory"
    /// will pertain to that entry if `enter` is called before `leave`.
    pub fn leave(self: *SelectiveWalker, io: Io) void {
        var item = self.stack.pop().?;
        if (self.stack.items.len != 0) {
            @branchHint(.likely);
            item.iter.dir.close(io);
        }
    }
};

/// Recursively iterates over a directory, but requires the user to
/// opt-in to recursing into each directory entry.
///
/// `dir` must have been opened with `OpenOptions{.iterate = true}`.
///
/// `Walker.deinit` releases allocated memory and directory handles.
///
/// The order of returned file system entries is undefined.
///
/// `dir` will not be closed after walking it.
///
/// See also `walk`.
pub fn walkSelectively(dir: Dir, allocator: Allocator) !SelectiveWalker {
    var stack: std.ArrayList(Walker.StackItem) = .empty;

    try stack.append(allocator, .{
        .iter = dir.iterate(),
        .dirname_len = 0,
    });

    return .{
        .stack = stack,
        .name_buffer = .{},
        .allocator = allocator,
    };
}

pub const Walker = struct {
    inner: SelectiveWalker,

    pub const Entry = struct {
        /// The containing directory. This can be used to operate directly on `basename`
        /// rather than `path`, avoiding `error.NameTooLong` for deeply nested paths.
        /// The directory remains open until `next` or `deinit` is called.
        dir: Dir,
        basename: [:0]const u8,
        path: [:0]const u8,
        kind: Dir.Entry.Kind,

        /// Returns the depth of the entry relative to the initial directory.
        /// Returns 1 for a direct child of the initial directory, 2 for an entry
        /// within a direct child of the initial directory, etc.
        pub fn depth(self: Walker.Entry) usize {
            return std.mem.countScalar(u8, self.path, std.fs.path.sep) + 1;
        }
    };

    const StackItem = struct {
        iter: Dir.Iterator,
        dirname_len: usize,
    };

    /// After each call to this function, and on deinit(), the memory returned
    /// from this function becomes invalid. A copy must be made in order to keep
    /// a reference to the path.
    pub fn next(self: *Walker) !?Walker.Entry {
        const entry = try self.inner.next();
        if (entry != null and entry.?.kind == .directory) {
            try self.inner.enter(entry.?);
        }
        return entry;
    }

    pub fn deinit(self: *Walker) void {
        self.inner.deinit();
    }

    /// Leaves the current directory, continuing walking one level up.
    /// If the current entry is a directory entry, then the "current directory"
    /// is the directory pertaining to the current entry.
    pub fn leave(self: *Walker) void {
        self.inner.leave();
    }
};

/// Recursively iterates over a directory.
///
/// `dir` must have been opened with `OpenOptions{.iterate = true}`.
///
/// `Walker.deinit` releases allocated memory and directory handles.
///
/// The order of returned file system entries is undefined.
///
/// `dir` will not be closed after walking it.
///
/// See also `walkSelectively`.
pub fn walk(dir: Dir, allocator: Allocator) Allocator.Error!Walker {
    return .{ .inner = try walkSelectively(dir, allocator) };
}

pub const Handle = std.posix.fd_t;

pub const PathNameError = error{
    NameTooLong,
    /// File system cannot encode the requested file name bytes.
    /// Could be due to invalid WTF-8 on Windows, invalid UTF-8 on WASI,
    /// invalid characters on Windows, etc. Filesystem and operating specific.
    BadPathName,
};

pub const AccessError = error{
    AccessDenied,
    PermissionDenied,
    FileNotFound,
    InputOutput,
    SystemResources,
    FileBusy,
    SymLinkLoop,
    ReadOnlyFileSystem,
} || PathNameError || Io.Cancelable || Io.UnexpectedError;

pub const AccessOptions = packed struct {
    follow_symlinks: bool = true,
    read: bool = false,
    write: bool = false,
    execute: bool = false,
};

/// Test accessing `sub_path`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
///
/// Be careful of Time-Of-Check-Time-Of-Use race conditions when using this
/// function. For example, instead of testing if a file exists and then opening
/// it, just open it and handle the error for file not found.
pub fn access(dir: Dir, io: Io, sub_path: []const u8, options: AccessOptions) AccessError!void {
    return io.vtable.dirAccess(io.userdata, dir, sub_path, options);
}

pub const OpenError = error{
    FileNotFound,
    NotDir,
    AccessDenied,
    PermissionDenied,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    DeviceBusy,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || PathNameError || Io.Cancelable || Io.UnexpectedError;

pub const OpenOptions = struct {
    /// `true` means the opened directory can be used as the `Dir` parameter
    /// for functions which operate based on an open directory handle. When `false`,
    /// such operations are Illegal Behavior.
    access_sub_paths: bool = true,
    /// `true` means the opened directory can be scanned for the files and sub-directories
    /// of the result. It means the `iterate` function can be called.
    iterate: bool = false,
    /// `false` means it won't dereference the symlinks.
    follow_symlinks: bool = true,
};

/// Opens a directory at the given path. The directory is a system resource that remains
/// open until `close` is called on the result.
///
/// The directory cannot be iterated unless the `iterate` option is set to `true`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn openDir(dir: Dir, io: Io, sub_path: []const u8, options: OpenOptions) OpenError!Dir {
    return io.vtable.dirOpenDir(io.userdata, dir, sub_path, options);
}

pub fn close(dir: Dir, io: Io) void {
    return io.vtable.dirClose(io.userdata, dir);
}

/// Opens a file for reading or writing, without attempting to create a new file.
///
/// To create a new file, see `createFile`.
///
/// Allocates a resource to be released with `File.close`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn openFile(dir: Dir, io: Io, sub_path: []const u8, flags: File.OpenFlags) File.OpenError!File {
    return io.vtable.dirOpenFile(io.userdata, dir, sub_path, flags);
}

/// Creates, opens, or overwrites a file with write access.
///
/// Allocates a resource to be dellocated with `File.close`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn createFile(dir: Dir, io: Io, sub_path: []const u8, flags: File.CreateFlags) File.OpenError!File {
    return io.vtable.dirCreateFile(io.userdata, dir, sub_path, flags);
}

pub const WriteFileOptions = struct {
    /// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
    /// On WASI, `sub_path` should be encoded as valid UTF-8.
    /// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
    sub_path: []const u8,
    data: []const u8,
    flags: File.CreateFlags = .{},
};

pub const WriteFileError = File.WriteError || File.OpenError;

/// Writes content to the file system, using the file creation flags provided.
pub fn writeFile(dir: Dir, io: Io, options: WriteFileOptions) WriteFileError!void {
    var file = try dir.createFile(io, options.sub_path, options.flags);
    defer file.close(io);
    try file.writeAll(io, options.data);
}

pub const PrevStatus = enum {
    stale,
    fresh,
};

pub const UpdateFileError = File.OpenError;

/// Check the file size, mtime, and permissions of `source_path` and `dest_path`. If
/// they are equal, does nothing. Otherwise, atomically copies `source_path` to
/// `dest_path`, creating the parent directory hierarchy as needed. The
/// destination file gains the mtime, atime, and permissions of the source file so
/// that the next call to `updateFile` will not need a copy.
///
/// Returns the previous status of the file before updating.
///
/// * On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// * On WASI, both paths should be encoded as valid UTF-8.
/// * On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn updateFile(
    source_dir: Dir,
    io: Io,
    source_path: []const u8,
    dest_dir: Dir,
    /// If directories in this path do not exist, they are created.
    dest_path: []const u8,
    options: CopyFileOptions,
) !PrevStatus {
    var src_file = try source_dir.openFile(io, source_path, .{});
    defer src_file.close(io);

    const src_stat = try src_file.stat(io);
    const actual_permissions = options.override_permissions orelse src_stat.permissions;
    check_dest_stat: {
        const dest_stat = blk: {
            var dest_file = dest_dir.openFile(io, dest_path, .{}) catch |err| switch (err) {
                error.FileNotFound => break :check_dest_stat,
                else => |e| return e,
            };
            defer dest_file.close(io);

            break :blk try dest_file.stat(io);
        };

        if (src_stat.size == dest_stat.size and
            src_stat.mtime.nanoseconds == dest_stat.mtime.nanoseconds and
            actual_permissions == dest_stat.permissions)
        {
            return .fresh;
        }
    }

    if (std.fs.path.dirname(dest_path)) |dirname| {
        try dest_dir.makePath(io, dirname, .default_dir);
    }

    var buffer: [1000]u8 = undefined; // Used only when direct fd-to-fd is not available.
    var atomic_file = try Dir.atomicFile(dest_dir, dest_path, .{
        .permissions = actual_permissions,
        .write_buffer = &buffer,
    });
    defer atomic_file.deinit();

    var src_reader: File.Reader = .initSize(src_file, io, &.{}, src_stat.size);
    const dest_writer = &atomic_file.file_writer.interface;

    _ = dest_writer.sendFileAll(&src_reader, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return src_reader.err.?,
        error.WriteFailed => return atomic_file.file_writer.err.?,
    };
    try atomic_file.flush();
    try atomic_file.file_writer.file.updateTimes(src_stat.atime, src_stat.mtime);
    try atomic_file.renameIntoPlace();
    return .stale;
}

pub const ReadFileError = File.OpenError || File.Reader.Error;

/// Read all of file contents using a preallocated buffer.
///
/// The returned slice has the same pointer as `buffer`. If the length matches `buffer.len`
/// the situation is ambiguous. It could either mean that the entire file was read, and
/// it exactly fits the buffer, or it could mean the buffer was not big enough for the
/// entire file.
///
/// * On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, `file_path` should be encoded as valid UTF-8.
/// * On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
pub fn readFile(dir: Dir, io: Io, file_path: []const u8, buffer: []u8) ReadFileError![]u8 {
    var file = try dir.openFile(io, file_path, .{});
    defer file.close(io);

    var reader = file.reader(io, &.{});
    const n = reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
    };

    return buffer[0..n];
}

pub const MakeError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to create a new directory relative to it.
    AccessDenied,
    PermissionDenied,
    DiskQuota,
    PathAlreadyExists,
    SymLinkLoop,
    LinkQuotaExceeded,
    FileNotFound,
    SystemResources,
    NoSpaceLeft,
    NotDir,
    ReadOnlyFileSystem,
    NoDevice,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || PathNameError || Io.Cancelable || Io.UnexpectedError;

/// Creates a single directory with a relative or absolute path.
///
/// * On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, `sub_path` should be encoded as valid UTF-8.
/// * On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
///
/// Related:
/// * `makePath`
/// * `makeDirAbsolute`
pub fn makeDir(dir: Dir, io: Io, sub_path: []const u8, permissions: Permissions) MakeError!void {
    return io.vtable.dirMake(io.userdata, dir, sub_path, permissions);
}

pub const MakePathError = MakeError || StatPathError;

/// Creates parent directories with default permissions as necessary to ensure
/// `sub_path` exists as a directory.
///
/// Returns success if the path already exists and is a directory.
///
/// This function may not be atomic. If it returns an error, the file system
/// may have been modified.
///
/// Fails on an empty path with `error.BadPathName` as that is not a path that
/// can be created.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
///
/// Paths containing `..` components are handled differently depending on the platform:
/// - On Windows, `..` are resolved before the path is passed to NtCreateFile, meaning
///   a `sub_path` like "first/../second" will resolve to "second" and only a
///   `./second` directory will be created.
/// - On other platforms, `..` are not resolved before the path is passed to `mkdirat`,
///   meaning a `sub_path` like "first/../second" will create both a `./first`
///   and a `./second` directory.
///
/// See also:
/// * `makePathStatus`
pub fn makePath(dir: Dir, io: Io, sub_path: []const u8) MakePathError!void {
    _ = try io.vtable.dirMakePath(io.userdata, dir, sub_path, .default_dir);
}

pub const MakePathStatus = enum { existed, created };

/// Same as `makePath` except returns whether the path already existed or was
/// successfully created.
pub fn makePathStatus(dir: Dir, io: Io, sub_path: []const u8, permissions: Permissions) MakePathError!MakePathStatus {
    return io.vtable.dirMakePath(io.userdata, dir, sub_path, permissions);
}

pub const MakeOpenPathError = MakeError || OpenError || StatPathError;

pub const MakeOpenPathOptions = struct {
    open_options: OpenOptions = .{},
    permissions: Permissions = .default_dir,
};

/// Performs the equivalent of `makePath` followed by `openDir`, atomically if possible.
///
/// When this operation is canceled, it may leave the file system in a
/// partially modified state.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn makeOpenPath(dir: Dir, io: Io, sub_path: []const u8, options: MakeOpenPathOptions) MakeOpenPathError!Dir {
    return io.vtable.dirMakeOpenPath(io.userdata, dir, sub_path, options.permissions, options.open_options);
}

pub const Stat = File.Stat;
pub const StatError = File.StatError;

pub fn stat(dir: Dir, io: Io) StatError!Stat {
    return io.vtable.dirStat(io.userdata, dir);
}

pub const StatPathError = File.OpenError || File.StatError;

pub const StatPathOptions = struct {
    follow_symlinks: bool = true,
};

/// Returns metadata for a file inside the directory.
///
/// On Windows, this requires three syscalls. On other operating systems, it
/// only takes one.
///
/// Symlinks are followed.
///
/// `sub_path` may be absolute, in which case `self` is ignored.
///
/// * On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On WASI, `sub_path` should be encoded as valid UTF-8.
/// * On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn statPath(dir: Dir, io: Io, sub_path: []const u8, options: StatPathOptions) StatPathError!Stat {
    return io.vtable.dirStatPath(io.userdata, dir, sub_path, options);
}

pub const RealPathError = error{
    FileNotFound,
    AccessDenied,
    PermissionDenied,
    NameTooLong,
    NotSupported,
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
    DeviceBusy,
    SharingViolation,
    PipeBusy,
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    PathAlreadyExists,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
    /// On Windows, the volume does not contain a recognized file system. File
    /// system drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
} || Io.Cancelable || Io.UnexpectedError;

///  This function returns the canonicalized absolute pathname of `pathname`
///  relative to this `Dir`. If `pathname` is absolute, ignores this `Dir`
///  handle and returns the canonicalized absolute pathname of `pathname`
///  argument.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// On Windows, the result is encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
///
/// This function is not universally supported by all platforms. Currently
/// supported hosts are: Linux, macOS, and Windows.
///
/// See also:
/// * `realpathAlloc`.
pub fn realPath(dir: Dir, io: Io, sub_path: []const u8, out_buffer: []u8) RealPathError!usize {
    return io.vtable.dirRealPath(io.userdata, dir, sub_path, out_buffer);
}

pub const RealPathAllocError = RealPathError || Allocator.Error;

/// Same as `Dir.realpath` except caller must free the returned memory.
/// See also `Dir.realpath`.
pub fn realpathAlloc(self: Dir, allocator: Allocator, pathname: []const u8) RealPathAllocError![]u8 {
    // Use of max_path_bytes here is valid as the realpath function does not
    // have a variant that takes an arbitrary-size buffer.
    // TODO(#4812): Consider reimplementing realpath or using the POSIX.1-2008
    // NULL out parameter (GNU's canonicalize_file_name) to handle overelong
    // paths. musl supports passing NULL but restricts the output to PATH_MAX
    // anyway.
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try self.realpath(pathname, &buf));
}

pub const DeleteFileError = error{
    FileNotFound,
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to unlink a resource by path relative to it.
    AccessDenied,
    PermissionDenied,
    FileBusy,
    FileSystem,
    IsDir,
    SymLinkLoop,
    NameTooLong,
    NotDir,
    SystemResources,
    ReadOnlyFileSystem,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    /// Windows: file paths cannot contain these characters:
    /// '/', '*', '?', '"', '<', '>', '|'
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || Io.Cancelable || Io.UnexpectedError;

/// Delete a file name and possibly the file it refers to, based on an open directory handle.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
///
/// Asserts that the path parameter has no null bytes.
pub fn deleteFile(dir: Dir, io: Io, sub_path: []const u8) DeleteFileError!void {
    return io.vtable.dirDeleteFile(io.userdata, dir, sub_path);
}

pub const DeleteDirError = error{
    DirNotEmpty,
    FileNotFound,
    AccessDenied,
    PermissionDenied,
    FileBusy,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    NotDir,
    SystemResources,
    ReadOnlyFileSystem,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || Io.Cancelable || Io.UnexpectedError;

/// Returns `error.DirNotEmpty` if the directory is not empty.
///
/// To delete a directory recursively, see `deleteTree`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteDir(dir: Dir, io: Io, sub_path: []const u8) DeleteDirError!void {
    return io.vtable.dirDeleteDir(io.userdata, dir, sub_path);
}

pub const RenameError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to rename a resource by path relative to it.
    ///
    /// On Windows, this error may be returned instead of PathAlreadyExists when
    /// renaming a directory over an existing directory.
    AccessDenied,
    PermissionDenied,
    FileBusy,
    DiskQuota,
    IsDir,
    SymLinkLoop,
    LinkQuotaExceeded,
    NameTooLong,
    FileNotFound,
    NotDir,
    SystemResources,
    NoSpaceLeft,
    PathAlreadyExists,
    ReadOnlyFileSystem,
    RenameAcrossMountPoints,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    BadPathName,
    NoDevice,
    SharingViolation,
    PipeBusy,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
} || Io.Cancelable || Io.UnexpectedError;

/// Change the name or location of a file or directory.
///
/// If `new_sub_path` already exists, it will be replaced.
///
/// Renaming a file over an existing directory or a directory over an existing
/// file will fail with `error.IsDir` or `error.NotDir`
///
/// On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn rename(
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
    io: Io,
) RenameError!void {
    return io.vtable.dirRename(io.userdata, old_dir, old_sub_path, new_dir, new_sub_path);
}

/// Use with `Dir.symLink`, `Dir.symLinkAtomic`, and `symLinkAbsolute` to
/// specify whether the symlink will point to a file or a directory. This value
/// is ignored on all hosts except Windows where creating symlinks to different
/// resource types, requires different flags. By default, `symLinkAbsolute` is
/// assumed to point to a file.
pub const SymLinkFlags = struct {
    is_directory: bool = false,
};

pub const SymLinkError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to create a new symbolic link relative to it.
    AccessDenied,
    PermissionDenied,
    DiskQuota,
    PathAlreadyExists,
    FileSystem,
    SymLinkLoop,
    FileNotFound,
    SystemResources,
    NoSpaceLeft,
    ReadOnlyFileSystem,
    NotDir,
    NameTooLong,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    BadPathName,
} || Io.Cancelable || Io.UnexpectedError;

/// Creates a symbolic link named `sym_link_path` which contains the string `target_path`.
///
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
///
/// If `sym_link_path` exists, it will not be overwritten.
///
/// On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn symLink(
    dir: Dir,
    io: Io,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: SymLinkFlags,
) SymLinkError!void {
    return io.vtable.dirSymLink(io.userdata, dir, target_path, sym_link_path, flags);
}

/// Same as `symLink`, except tries to create the symbolic link until it
/// succeeds or encounters an error other than `error.PathAlreadyExists`.
///
/// * On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// * On WASI, both paths should be encoded as valid UTF-8.
/// * On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn symLinkAtomic(
    dir: Dir,
    io: Io,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: SymLinkFlags,
) !void {
    if (dir.symLink(io, target_path, sym_link_path, flags)) {
        return;
    } else |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    }

    const dirname = std.fs.path.dirname(sym_link_path) orelse ".";

    const rand_len = @sizeOf(u64) * 2;
    const temp_path_len = dirname.len + 1 + rand_len;
    var temp_path_buf: [std.fs.max_path_bytes]u8 = undefined;

    if (temp_path_len > temp_path_buf.len) return error.NameTooLong;
    @memcpy(temp_path_buf[0..dirname.len], dirname);
    temp_path_buf[dirname.len] = std.fs.path.sep;

    const temp_path = temp_path_buf[0..temp_path_len];

    while (true) {
        const random_integer = std.crypto.random.int(u64);
        temp_path[dirname.len + 1 ..][0..rand_len].* = std.fmt.hex(random_integer);

        if (dir.symLink(io, target_path, temp_path, flags)) {
            return dir.rename(temp_path, dir, io, sym_link_path);
        } else |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        }
    }
}

pub const ReadLinkError = error{
    /// In WASI, this error may occur when the file descriptor does
    /// not hold the required rights to read value of a symbolic link relative to it.
    AccessDenied,
    PermissionDenied,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotLink,
    NotDir,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    BadPathName,
    /// Windows-only. This error may occur if the opened reparse point is
    /// of unsupported type.
    UnsupportedReparsePointType,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
} || Io.Cancelable || Io.UnexpectedError;

/// Obtain target of a symbolic link.
///
/// Returns how many bytes of `buffer` are populated.
///
/// Asserts that the path parameter has no null bytes.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn readLink(dir: Dir, io: Io, sub_path: []const u8, buffer: []u8) ReadLinkError!usize {
    return io.vtable.dirReadLink(io.userdata, dir, sub_path, buffer);
}

pub const ReadFileAllocError = File.OpenError || File.ReadError || Allocator.Error || error{
    /// File size reached or exceeded the provided limit.
    StreamTooLong,
};

/// Reads all the bytes from the named file. On success, caller owns returned
/// buffer.
///
/// If the file size is already known, a better alternative is to initialize a
/// `File.Reader`.
///
/// If the file size cannot be obtained, an error is returned. If
/// this is a realistic possibility, a better alternative is to initialize a
/// `File.Reader` which handles this seamlessly.
pub fn readFileAlloc(
    dir: Dir,
    io: Io,
    /// On Windows, should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
    /// On WASI, should be encoded as valid UTF-8.
    /// On other platforms, an opaque sequence of bytes with no particular encoding.
    sub_path: []const u8,
    /// Used to allocate the result.
    gpa: Allocator,
    /// If reached or exceeded, `error.StreamTooLong` is returned instead.
    limit: Io.Limit,
) ReadFileAllocError![]u8 {
    return readFileAllocOptions(dir, io, sub_path, gpa, limit, .of(u8), null);
}

/// Reads all the bytes from the named file. On success, caller owns returned
/// buffer.
///
/// If the file size is already known, a better alternative is to initialize a
/// `File.Reader`.
pub fn readFileAllocOptions(
    dir: Dir,
    io: Io,
    /// On Windows, should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
    /// On WASI, should be encoded as valid UTF-8.
    /// On other platforms, an opaque sequence of bytes with no particular encoding.
    sub_path: []const u8,
    /// Used to allocate the result.
    gpa: Allocator,
    /// If reached or exceeded, `error.StreamTooLong` is returned instead.
    limit: Io.Limit,
    comptime alignment: std.mem.Alignment,
    comptime sentinel: ?u8,
) ReadFileAllocError!(if (sentinel) |s| [:s]align(alignment.toByteUnits()) u8 else []align(alignment.toByteUnits()) u8) {
    var file = try dir.openFile(io, sub_path, .{});
    defer file.close(io);
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.allocRemainingAlignedSentinel(gpa, limit, alignment, sentinel) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.OutOfMemory, error.StreamTooLong => |e| return e,
    };
}

pub const DeleteTreeError = error{
    AccessDenied,
    PermissionDenied,
    FileTooBig,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    NameTooLong,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    ReadOnlyFileSystem,
    FileSystem,
    FileBusy,
    DeviceBusy,
    /// One of the path components was not a directory.
    /// This error is unreachable if `sub_path` does not contain a path separator.
    NotDir,
    /// WASI: file paths must be valid UTF-8.
    /// Windows: file paths provided by the user must be valid WTF-8.
    /// https://wtf-8.codeberg.page/
    /// On Windows, file paths cannot contain these characters:
    /// '/', '*', '?', '"', '<', '>', '|'
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || Io.Cancelable || Io.UnexpectedError;

/// Whether `sub_path` describes a symlink, file, or directory, this function
/// removes it. If it cannot be removed because it is a non-empty directory,
/// this function recursively removes its entries and then tries again.
///
/// This operation is not atomic on most file systems.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTree(dir: Dir, io: Io, sub_path: []const u8) DeleteTreeError!void {
    var initial_iterable_dir = (try dir.deleteTreeOpenInitialSubpath(io, sub_path, .file)) orelse return;

    const StackItem = struct {
        name: []const u8,
        parent_dir: Dir,
        iter: Dir.Iterator,

        fn closeAll(inner_io: Io, items: []@This()) void {
            for (items) |*item| item.iter.dir.close(inner_io);
        }
    };

    var stack_buffer: [16]StackItem = undefined;
    var stack = std.ArrayList(StackItem).initBuffer(&stack_buffer);
    defer StackItem.closeAll(io, stack.items);

    stack.appendAssumeCapacity(.{
        .name = sub_path,
        .parent_dir = dir,
        .iter = initial_iterable_dir.iterateAssumeFirstIteration(),
    });

    process_stack: while (stack.items.len != 0) {
        var top = &stack.items[stack.items.len - 1];
        while (try top.iter.next()) |entry| {
            var treat_as_dir = entry.kind == .directory;
            handle_entry: while (true) {
                if (treat_as_dir) {
                    if (stack.unusedCapacitySlice().len >= 1) {
                        var iterable_dir = top.iter.dir.openDir(io, entry.name, .{
                            .follow_symlinks = false,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                break :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessFdQuotaExceeded,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            error.Canceled,
                            => |e| return e,
                        };
                        stack.appendAssumeCapacity(.{
                            .name = entry.name,
                            .parent_dir = top.iter.dir,
                            .iter = iterable_dir.iterateAssumeFirstIteration(),
                        });
                        continue :process_stack;
                    } else {
                        try top.iter.dir.deleteTreeMinStackSizeWithKindHint(io, entry.name, entry.kind);
                        break :handle_entry;
                    }
                } else {
                    if (top.iter.dir.deleteFile(io, entry.name)) {
                        break :handle_entry;
                    } else |err| switch (err) {
                        error.FileNotFound => break :handle_entry,

                        // Impossible because we do not pass any path separators.
                        error.NotDir => unreachable,

                        error.IsDir => {
                            treat_as_dir = true;
                            continue :handle_entry;
                        },

                        error.AccessDenied,
                        error.PermissionDenied,
                        error.SymLinkLoop,
                        error.NameTooLong,
                        error.SystemResources,
                        error.ReadOnlyFileSystem,
                        error.FileSystem,
                        error.FileBusy,
                        error.BadPathName,
                        error.NetworkNotFound,
                        error.Unexpected,
                        => |e| return e,
                    }
                }
            }
        }

        // On Windows, we can't delete until the dir's handle has been closed, so
        // close it before we try to delete.
        top.iter.dir.close(io);

        // In order to avoid double-closing the directory when cleaning up
        // the stack in the case of an error, we save the relevant portions and
        // pop the value from the stack.
        const parent_dir = top.parent_dir;
        const name = top.name;
        stack.items.len -= 1;

        var need_to_retry: bool = false;
        parent_dir.deleteDir(name) catch |err| switch (err) {
            error.FileNotFound => {},
            error.DirNotEmpty => need_to_retry = true,
            else => |e| return e,
        };

        if (need_to_retry) {
            // Since we closed the handle that the previous iterator used, we
            // need to re-open the dir and re-create the iterator.
            var iterable_dir = iterable_dir: {
                var treat_as_dir = true;
                handle_entry: while (true) {
                    if (treat_as_dir) {
                        break :iterable_dir parent_dir.openDir(name, .{
                            .follow_symlinks = false,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                continue :process_stack;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessFdQuotaExceeded,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            error.Canceled,
                            => |e| return e,
                        };
                    } else {
                        if (parent_dir.deleteFile(name)) {
                            continue :process_stack;
                        } else |err| switch (err) {
                            error.FileNotFound => continue :process_stack,

                            // Impossible because we do not pass any path separators.
                            error.NotDir => unreachable,

                            error.IsDir => {
                                treat_as_dir = true;
                                continue :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.NameTooLong,
                            error.SystemResources,
                            error.ReadOnlyFileSystem,
                            error.FileSystem,
                            error.FileBusy,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.Unexpected,
                            => |e| return e,
                        }
                    }
                }
            };
            // We know there is room on the stack since we are just re-adding
            // the StackItem that we previously popped.
            stack.appendAssumeCapacity(.{
                .name = name,
                .parent_dir = parent_dir,
                .iter = iterable_dir.iterateAssumeFirstIteration(),
            });
            continue :process_stack;
        }
    }
}

/// Like `deleteTree`, but only keeps one `Iterator` active at a time to minimize the function's stack size.
/// This is slower than `deleteTree` but uses less stack space.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTreeMinStackSize(dir: Dir, io: Io, sub_path: []const u8) DeleteTreeError!void {
    return dir.deleteTreeMinStackSizeWithKindHint(io, sub_path, .file);
}

fn deleteTreeMinStackSizeWithKindHint(parent: Dir, io: Io, sub_path: []const u8, kind_hint: File.Kind) DeleteTreeError!void {
    start_over: while (true) {
        var dir = (try parent.deleteTreeOpenInitialSubpath(io, sub_path, kind_hint)) orelse return;
        var cleanup_dir_parent: ?Dir = null;
        defer if (cleanup_dir_parent) |*d| d.close(io);

        var cleanup_dir = true;
        defer if (cleanup_dir) dir.close(io);

        // Valid use of max_path_bytes because dir_name_buf will only
        // ever store a single path component that was returned from the
        // filesystem.
        var dir_name_buf: [std.fs.max_path_bytes]u8 = undefined;
        var dir_name: []const u8 = sub_path;

        // Here we must avoid recursion, in order to provide O(1) memory guarantee of this function.
        // Go through each entry and if it is not a directory, delete it. If it is a directory,
        // open it, and close the original directory. Repeat. Then start the entire operation over.

        scan_dir: while (true) {
            var dir_it = dir.iterateAssumeFirstIteration();
            dir_it: while (try dir_it.next()) |entry| {
                var treat_as_dir = entry.kind == .directory;
                handle_entry: while (true) {
                    if (treat_as_dir) {
                        const new_dir = dir.openDir(entry.name, .{
                            .follow_symlinks = false,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                continue :dir_it;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessFdQuotaExceeded,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            error.Canceled,
                            => |e| return e,
                        };
                        if (cleanup_dir_parent) |*d| d.close(io);
                        cleanup_dir_parent = dir;
                        dir = new_dir;
                        const result = dir_name_buf[0..entry.name.len];
                        @memcpy(result, entry.name);
                        dir_name = result;
                        continue :scan_dir;
                    } else {
                        if (dir.deleteFile(entry.name)) {
                            continue :dir_it;
                        } else |err| switch (err) {
                            error.FileNotFound => continue :dir_it,

                            // Impossible because we do not pass any path separators.
                            error.NotDir => unreachable,

                            error.IsDir => {
                                treat_as_dir = true;
                                continue :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.NameTooLong,
                            error.SystemResources,
                            error.ReadOnlyFileSystem,
                            error.FileSystem,
                            error.FileBusy,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.Unexpected,
                            => |e| return e,
                        }
                    }
                }
            }
            // Reached the end of the directory entries, which means we successfully deleted all of them.
            // Now to remove the directory itself.
            dir.close(io);
            cleanup_dir = false;

            if (cleanup_dir_parent) |d| {
                d.deleteDir(io, dir_name) catch |err| switch (err) {
                    // These two things can happen due to file system race conditions.
                    error.FileNotFound, error.DirNotEmpty => continue :start_over,
                    else => |e| return e,
                };
                continue :start_over;
            } else {
                parent.deleteDir(io, sub_path) catch |err| switch (err) {
                    error.FileNotFound => return,
                    error.DirNotEmpty => continue :start_over,
                    else => |e| return e,
                };
                return;
            }
        }
    }
}

/// On successful delete, returns null.
fn deleteTreeOpenInitialSubpath(dir: Dir, sub_path: []const u8, kind_hint: File.Kind) !?Dir {
    return iterable_dir: {
        // Treat as a file by default
        var treat_as_dir = kind_hint == .directory;

        handle_entry: while (true) {
            if (treat_as_dir) {
                break :iterable_dir dir.openDir(sub_path, .{
                    .follow_symlinks = false,
                    .iterate = true,
                }) catch |err| switch (err) {
                    error.NotDir => {
                        treat_as_dir = false;
                        continue :handle_entry;
                    },
                    error.FileNotFound => {
                        // That's fine, we were trying to remove this directory anyway.
                        return null;
                    },

                    error.AccessDenied,
                    error.PermissionDenied,
                    error.SymLinkLoop,
                    error.ProcessFdQuotaExceeded,
                    error.NameTooLong,
                    error.SystemFdQuotaExceeded,
                    error.NoDevice,
                    error.SystemResources,
                    error.Unexpected,
                    error.BadPathName,
                    error.DeviceBusy,
                    error.NetworkNotFound,
                    error.Canceled,
                    => |e| return e,
                };
            } else {
                if (dir.deleteFile(sub_path)) {
                    return null;
                } else |err| switch (err) {
                    error.FileNotFound => return null,

                    error.IsDir => {
                        treat_as_dir = true;
                        continue :handle_entry;
                    },

                    error.AccessDenied,
                    error.PermissionDenied,
                    error.SymLinkLoop,
                    error.NameTooLong,
                    error.SystemResources,
                    error.ReadOnlyFileSystem,
                    error.NotDir,
                    error.FileSystem,
                    error.FileBusy,
                    error.BadPathName,
                    error.NetworkNotFound,
                    error.Unexpected,
                    => |e| return e,
                }
            }
        }
    };
}

pub const CopyFileOptions = struct {
    /// When this is `null` the permissions are copied from the source file.
    override_permissions: ?File.Permissions = null,
};

pub const CopyFileError = File.OpenError || File.StatError ||
    File.Atomic.InitError || File.Atomic.FinishError ||
    File.ReadError || File.WriteError || error{InvalidFileName};

/// Atomically creates a new file at `dest_path` within `dest_dir` with the
/// same contents as `source_path` within `source_dir`, overwriting any already
/// existing file.
///
/// On Linux, until https://patchwork.kernel.org/patch/9636735/ is merged and
/// readily available, there is a possibility of power loss or application
/// termination leaving temporary files present in the same directory as
/// dest_path.
///
/// On Windows, both paths should be encoded as
/// [WTF-8](https://wtf-8.codeberg.page/). On WASI, both paths should be
/// encoded as valid UTF-8. On other platforms, both paths are an opaque
/// sequence of bytes with no particular encoding.
pub fn copyFile(
    source_dir: Dir,
    source_path: []const u8,
    dest_dir: Dir,
    dest_path: []const u8,
    io: Io,
    options: CopyFileOptions,
) CopyFileError!void {
    const file = try source_dir.openFile(io, source_path, .{});
    var file_reader: File.Reader = .init(.{ .handle = file.handle }, io, &.{});
    defer file_reader.file.close(io);

    const permissions = options.override_permissions orelse blk: {
        const st = try file_reader.file.stat(io);
        file_reader.size = st.size;
        break :blk st.permissions;
    };

    var buffer: [1024]u8 = undefined; // Used only when direct fd-to-fd is not available.
    var atomic_file = try dest_dir.atomicFile(io, dest_path, .{
        .permissions = permissions,
        .write_buffer = &buffer,
    });
    defer atomic_file.deinit(io);

    _ = atomic_file.file_writer.interface.sendFileAll(&file_reader, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.WriteFailed => return atomic_file.file_writer.err.?,
    };

    try atomic_file.finish();
}

pub const AtomicFileOptions = struct {
    permissions: File.Permissions = .default_file,
    make_path: bool = false,
    write_buffer: []u8,
};

/// Directly access the `.file` field, and then call `File.Atomic.finish` to
/// atomically replace `dest_path` with contents.
///
/// Always call `File.Atomic.deinit` to clean up, regardless of whether
/// `File.Atomic.finish` succeeded. `dest_path` must remain valid until
/// `File.Atomic.deinit` is called.
///
/// On Windows, `dest_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `dest_path` should be encoded as valid UTF-8.
/// On other platforms, `dest_path` is an opaque sequence of bytes with no particular encoding.
pub fn atomicFile(parent: Dir, io: Io, dest_path: []const u8, options: AtomicFileOptions) !File.Atomic {
    if (std.fs.path.dirname(dest_path)) |dirname| {
        const dir = if (options.make_path)
            try parent.makeOpenPath(io, dirname, .{})
        else
            try parent.openDir(io, dirname, .{});

        return .init(std.fs.path.basename(dest_path), options.permissions, dir, true, options.write_buffer);
    } else {
        return .init(dest_path, options.permissions, parent, false, options.write_buffer);
    }
}

pub const SetPermissionsError = File.SetPermissionsError;
pub const Permissions = File.Permissions;

/// Also known as "chmod".
///
/// The process must have the correct privileges in order to do this
/// successfully, or must have the effective user ID matching the owner
/// of the directory. Additionally, the directory must have been opened
/// with `OpenOptions.iterate` set to `true`.
pub fn setPermissions(dir: Dir, io: Io, new_permissions: File.Permissions) SetPermissionsError!void {
    return io.vtable.dirSetPermissions(io.userdata, dir, new_permissions);
}

pub const SetOwnerError = File.SetOwnerError;

/// Also known as "chown".
///
/// The process must have the correct privileges in order to do this
/// successfully. The group may be changed by the owner of the directory to
/// any group of which the owner is a member. Additionally, the directory
/// must have been opened with `OpenOptions.iterate` set to `true`. If the
/// owner or group is specified as `null`, the ID is not changed.
pub fn setOwner(dir: Dir, io: Io, owner: ?File.Uid, group: ?File.Gid) SetOwnerError!void {
    return io.vtable.dirSetOwner(io.userdata, dir, owner, group);
}

pub const SetTimestampsError = File.SetTimestampsError;

pub const SetTimestampsOptions = struct {
    follow_symlinks: bool = true,
};

/// The granularity that ultimately is stored depends on the combination of
/// operating system and file system. When a value as provided that exceeds
/// this range, the value is clamped to the maximum.
pub fn setTimestamps(
    dir: Dir,
    io: Io,
    sub_path: []const u8,
    last_accessed: Io.Timestamp,
    last_modified: Io.Timestamp,
    options: SetTimestampsOptions,
) SetTimestampsError!void {
    return io.vtable.dirSetTimestamps(io.userdata, dir, sub_path, last_accessed, last_modified, options);
}

/// Sets the accessed and modification timestamps of the provided path to the
/// current wall clock time.
///
/// The granularity that ultimately is stored depends on the combination of
/// operating system and file system.
pub fn setTimestampsNow(dir: Dir, io: Io, sub_path: []const u8, options: SetTimestampsOptions) SetTimestampsError!void {
    return io.vtable.fileSetTimestampsNow(io.userdata, dir, sub_path, options);
}
