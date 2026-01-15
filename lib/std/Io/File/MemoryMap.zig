const MemoryMap = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;
const is_windows = native_os == .windows;

const std = @import("../../std.zig");
const Io = std.Io;
const File = Io.File;
const Allocator = std.mem.Allocator;

file: File,
/// Byte index inside `file` where `memory` starts. Page-aligned.
offset: u64,
/// Memory that may or may not remain consistent with file contents. Use `read`
/// and `write` to ensure synchronization points. No minimum alignment on the
/// pointer is guaranteed, but the length is page-aligned.
memory: []u8,
/// Tells whether it is memory-mapped or file operations. On Windows this also
/// has a section handle.
section: ?Section,

pub const Section = if (is_windows) std.os.windows.HANDLE else void;

pub const CreateError = error{
    /// One of the following:
    /// * The `File.Kind` is not `file`.
    /// * The file is not open for reading and read access protections enabled.
    /// * The file is not open for writing and write access protections enabled.
    AccessDenied,
    /// The `prot` argument asks for `PROT_EXEC` but the mapped area belongs to a file on
    /// a filesystem that was mounted no-exec.
    PermissionDenied,
    LockedMemoryLimitExceeded,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
} || Allocator.Error || File.ReadPositionalError;

pub const CreateOptions = struct {
    /// Size of the mapping, in bytes. If this is longer than the file size, it
    /// will be filled with zeroes.
    ///
    /// Asserted to be a multiple of page size which can be obtained via
    /// `std.heap.pageSize`.
    len: usize,
    /// When this has read set to false, bytes that are not modified before a
    /// sync may have the original file contents, or may be set to zero.
    protection: std.process.MemoryProtection = .{ .read = true, .write = true },
    /// If set to `true`, allows bytes observed before calling `read` to be
    /// undefined, and bytes unwritten before calling `write` to write
    /// undefined memory to the file.
    undefined_contents: bool = false,
    /// Prefault the pages.
    populate: bool = true,
    /// Asserted to be a multiple of page size which can be obtained via
    /// `std.heap.pageSize`.
    offset: u64 = 0,
};

/// To release the resources associated with the returned `MemoryMap`, call
/// `destroy`.
pub fn create(io: Io, file: File, options: CreateOptions) CreateError!MemoryMap {
    return io.vtable.fileMemoryMapCreate(io.userdata, file, options);
}

/// If `write` is not called before this function, changes to `memory` may or may
/// not be synchronized to `file`.
pub fn destroy(mm: *MemoryMap, io: Io) void {
    io.vtable.fileMemoryMapDestroy(io.userdata, mm);
}

pub const SetLengthError = error{
    LockedMemoryLimitExceeded,
} || Allocator.Error || File.SetLengthError;

/// Change the size of the mapping. This does not sync the contents. The size
/// of the file after calling this is unspecified until `write` is called.
///
/// May change the pointer address of `memory`.
pub fn setLength(
    mm: *MemoryMap,
    io: Io,
    /// New size of the mapping, in bytes. If this is longer than the file
    /// size, it will be filled with zeroes. Asserted to be a multiple of page
    /// size which can be obtained with `std.heap.pageSize`.
    new_length: usize,
) File.SetLengthError!void {
    return io.vtable.fileMemoryMapSetLength(io.userdata, mm, new_length);
}

/// Synchronizes the contents of `memory` from `file`.
pub fn read(mm: *MemoryMap, io: Io) File.ReadPositionalError!void {
    return io.vtable.fileMemoryMapRead(io.userdata, mm);
}

/// Synchronizes the contents of `memory` to `file`.
///
/// Size of the mapping may be longer than the file size, so the `file_size`
/// argument is used to avoid writing too many bytes. If `file_size` is not
/// handy, use `File.length` to get it.
pub fn write(mm: *MemoryMap, io: Io, file_size: u64) File.WritePositionalError!void {
    return io.vtable.fileMemoryMapWrite(io.userdata, mm, file_size);
}
