//! File System.
const builtin = @import("builtin");
const native_os = builtin.os.tag;

const std = @import("std.zig");
const Io = std.Io;
const root = @import("root");
const mem = std.mem;
const base64 = std.base64;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const posix = std.posix;
const windows = std.os.windows;

const is_darwin = native_os.isDarwin();

/// Deprecated.
pub const AtomicFile = std.Io.File.Atomic;
/// Deprecated.
pub const Dir = std.Io.Dir;
/// Deprecated.
pub const File = std.Io.File;

pub const path = @import("fs/path.zig");
pub const wasi = @import("fs/wasi.zig");

pub const getAppDataDir = @import("fs/get_app_data_dir.zig").getAppDataDir;
pub const GetAppDataDirError = @import("fs/get_app_data_dir.zig").GetAppDataDirError;

/// The maximum length of a file path that the operating system will accept.
///
/// Paths, including those returned from file system operations, may be longer
/// than this length, but such paths cannot be successfully passed back in
/// other file system operations. However, all path components returned by file
/// system operations are assumed to fit into a `u8` array of this length.
///
/// The byte count includes room for a null sentinel byte.
///
/// * On Windows, `[]u8` file paths are encoded as
///   [WTF-8](https://wtf-8.codeberg.page/).
/// * On WASI, `[]u8` file paths are encoded as valid UTF-8.
/// * On other platforms, `[]u8` file paths are opaque sequences of bytes with
///   no particular encoding.
pub const max_path_bytes = switch (native_os) {
    .linux, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .freebsd, .openbsd, .netbsd, .dragonfly, .haiku, .illumos, .plan9, .emscripten, .wasi, .serenity => posix.PATH_MAX,
    // Each WTF-16LE code unit may be expanded to 3 WTF-8 bytes.
    // If it would require 4 WTF-8 bytes, then there would be a surrogate
    // pair in the WTF-16LE, and we (over)account 3 bytes for it that way.
    // +1 for the null byte at the end, which can be encoded in 1 byte.
    .windows => windows.PATH_MAX_WIDE * 3 + 1,
    else => if (@hasDecl(root, "os") and @hasDecl(root.os, "PATH_MAX"))
        root.os.PATH_MAX
    else
        @compileError("PATH_MAX not implemented for " ++ @tagName(native_os)),
};

/// This represents the maximum size of a `[]u8` file name component that
/// the platform's common file systems support. File name components returned by file system
/// operations are likely to fit into a `u8` array of this length, but
/// (depending on the platform) this assumption may not hold for every configuration.
/// The byte count does not include a null sentinel byte.
/// On Windows, `[]u8` file name components are encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, file name components are encoded as valid UTF-8.
/// On other platforms, `[]u8` components are an opaque sequence of bytes with no particular encoding.
pub const max_name_bytes = switch (native_os) {
    .linux, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .freebsd, .openbsd, .netbsd, .dragonfly, .illumos, .serenity => posix.NAME_MAX,
    // Haiku's NAME_MAX includes the null terminator, so subtract one.
    .haiku => posix.NAME_MAX - 1,
    // Each WTF-16LE character may be expanded to 3 WTF-8 bytes.
    // If it would require 4 WTF-8 bytes, then there would be a surrogate
    // pair in the WTF-16LE, and we (over)account 3 bytes for it that way.
    .windows => windows.NAME_MAX * 3,
    // For WASI, the MAX_NAME will depend on the host OS, so it needs to be
    // as large as the largest max_name_bytes (Windows) in order to work on any host OS.
    // TODO determine if this is a reasonable approach
    .wasi => windows.NAME_MAX * 3,
    else => if (@hasDecl(root, "os") and @hasDecl(root.os, "NAME_MAX"))
        root.os.NAME_MAX
    else
        @compileError("NAME_MAX not implemented for " ++ @tagName(native_os)),
};

pub const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".*;

/// Base64 encoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_encoder = base64.Base64Encoder.init(base64_alphabet, null);

/// Base64 decoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_decoder = base64.Base64Decoder.init(base64_alphabet, null);

/// Same as `Dir.copyFile`, except asserts that both `source_path` and `dest_path`
/// are absolute. See `Dir.copyFile` for a function that operates on both
/// absolute and relative paths.
/// On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn copyFileAbsolute(
    source_path: []const u8,
    dest_path: []const u8,
    args: Dir.CopyFileOptions,
) !void {
    assert(path.isAbsolute(source_path));
    assert(path.isAbsolute(dest_path));
    const my_cwd = cwd();
    return Dir.copyFile(my_cwd, source_path, my_cwd, dest_path, args);
}

test copyFileAbsolute {}

/// Create a new directory, based on an absolute path.
/// Asserts that the path is absolute. See `Dir.makeDir` for a function that operates
/// on both absolute and relative paths.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn makeDirAbsolute(absolute_path: []const u8) !void {
    assert(path.isAbsolute(absolute_path));
    return posix.mkdir(absolute_path, Dir.default_mode);
}

test makeDirAbsolute {}

/// Same as `makeDirAbsolute` except the parameter is null-terminated.
pub fn makeDirAbsoluteZ(absolute_path_z: [*:0]const u8) !void {
    assert(path.isAbsoluteZ(absolute_path_z));
    return posix.mkdirZ(absolute_path_z, Dir.default_mode);
}

test makeDirAbsoluteZ {}

/// Same as `Dir.deleteDir` except the path is absolute.
/// On Windows, `dir_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `dir_path` should be encoded as valid UTF-8.
/// On other platforms, `dir_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteDirAbsolute(dir_path: []const u8) !void {
    assert(path.isAbsolute(dir_path));
    return posix.rmdir(dir_path);
}

/// Same as `deleteDirAbsolute` except the path parameter is null-terminated.
pub fn deleteDirAbsoluteZ(dir_path: [*:0]const u8) !void {
    assert(path.isAbsoluteZ(dir_path));
    return posix.rmdirZ(dir_path);
}

/// Deprecated in favor of `Io.Dir.cwd`.
pub fn cwd() Io.Dir {
    return .cwd();
}

pub fn defaultWasiCwd() std.os.wasi.fd_t {
    // Expect the first preopen to be current working directory.
    return 3;
}

/// Opens a directory at the given path. The directory is a system resource that remains
/// open until `close` is called on the result.
/// See `openDirAbsoluteZ` for a function that accepts a null-terminated path.
///
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn openDirAbsolute(absolute_path: []const u8, flags: Dir.OpenOptions) File.OpenError!Dir {
    assert(path.isAbsolute(absolute_path));
    return cwd().openDir(absolute_path, flags);
}

/// Deprecated in favor of `Io.File.openAbsolute`.
pub fn openFileAbsolute(absolute_path: []const u8, flags: File.OpenFlags) Io.File.OpenError!Io.File {
    var threaded: Io.Threaded = .init_single_threaded;
    const io = threaded.ioBasic();
    return Io.File.openAbsolute(io, absolute_path, flags);
}

/// Test accessing `path`.
/// Be careful of Time-Of-Check-Time-Of-Use race conditions when using this function.
/// For example, instead of testing if a file exists and then opening it, just
/// open it and handle the error for file not found.
/// See `accessAbsoluteZ` for a function that accepts a null-terminated path.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn accessAbsolute(absolute_path: []const u8, flags: Io.Dir.AccessOptions) Dir.AccessError!void {
    assert(path.isAbsolute(absolute_path));
    try cwd().access(absolute_path, flags);
}
/// Creates, opens, or overwrites a file with write access, based on an absolute path.
/// Call `File.close` to release the resource.
/// Asserts that the path is absolute. See `Dir.createFile` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes. See `createFileAbsoluteC` for a function
/// that accepts a null-terminated path.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn createFileAbsolute(absolute_path: []const u8, flags: File.CreateFlags) File.OpenError!File {
    assert(path.isAbsolute(absolute_path));
    return cwd().createFile(absolute_path, flags);
}

/// Delete a file name and possibly the file it refers to, based on an absolute path.
/// Asserts that the path is absolute. See `Dir.deleteFile` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteFileAbsolute(absolute_path: []const u8) Dir.DeleteFileError!void {
    assert(path.isAbsolute(absolute_path));
    return cwd().deleteFile(absolute_path);
}

/// Removes a symlink, file, or directory.
/// This is equivalent to `Dir.deleteTree` with the base directory.
/// Asserts that the path is absolute. See `Dir.deleteTree` for a function that
/// operates on both absolute and relative paths.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `absolute_path` should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, `absolute_path` should be encoded as valid UTF-8.
/// On other platforms, `absolute_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTreeAbsolute(io: Io, absolute_path: []const u8) !void {
    assert(path.isAbsolute(absolute_path));
    const dirname = path.dirname(absolute_path) orelse return error{
        /// Attempt to remove the root file system path.
        /// This error is unreachable if `absolute_path` is relative.
        CannotDeleteRootDirectory,
    }.CannotDeleteRootDirectory;

    var dir = try cwd().openDir(dirname, .{});
    defer dir.close(io);

    return dir.deleteTree(path.basename(absolute_path));
}

/// Creates a symbolic link named `sym_link_path` which contains the string `target_path`.
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
/// If `sym_link_path` exists, it will not be overwritten.
/// See also `symLinkAbsoluteZ` and `symLinkAbsoluteW`.
/// On Windows, both paths should be encoded as [WTF-8](https://wtf-8.codeberg.page/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn symLinkAbsolute(
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) !void {
    assert(path.isAbsolute(target_path));
    assert(path.isAbsolute(sym_link_path));
    if (native_os == .windows) {
        const target_path_w = try windows.sliceToPrefixedFileW(null, target_path);
        const sym_link_path_w = try windows.sliceToPrefixedFileW(null, sym_link_path);
        return windows.CreateSymbolicLink(null, sym_link_path_w.span(), target_path_w.span(), flags.is_directory);
    }
    return posix.symlink(target_path, sym_link_path);
}

/// Windows-only. Same as `symLinkAbsolute` except the parameters are null-terminated, WTF16 LE encoded.
/// Note that this function will by default try creating a symbolic link to a file. If you would
/// like to create a symbolic link to a directory, specify this with `SymLinkFlags{ .is_directory = true }`.
/// See also `symLinkAbsolute`, `symLinkAbsoluteZ`.
pub fn symLinkAbsoluteW(
    target_path_w: [*:0]const u16,
    sym_link_path_w: [*:0]const u16,
    flags: Dir.SymLinkFlags,
) !void {
    assert(path.isAbsoluteWindowsW(target_path_w));
    assert(path.isAbsoluteWindowsW(sym_link_path_w));
    return windows.CreateSymbolicLink(null, mem.span(sym_link_path_w), mem.span(target_path_w), flags.is_directory);
}

test {
    _ = AtomicFile;
    _ = Dir;
    _ = File;
    _ = path;
    _ = @import("fs/test.zig");
    _ = @import("fs/get_app_data_dir.zig");
}
