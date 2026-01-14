const MemoryMap = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;
const is_windows = native_os == .windows;

const std = @import("../../std.zig");
const Io = std.Io;
const File = Io.File;
const Allocator = std.mem.Allocator;

file: File,
/// Byte index inside `file` where `memory` starts.
offset: usize,
/// Memory that may or may not remain consistent with file contents. Use `read`
/// and `write` to ensure synchronization points.
memory: []u8,
/// Tells whether it is memory-mapped or file operations. On Windows this also
/// has a section handle.
section: ?Section,

pub const Section = if (is_windows) std.os.windows.HANDLE else void;

pub const CreateError = error{
    /// A file descriptor refers to a non-regular file. Or a file mapping was requested,
    /// but the file descriptor is not open for reading. Or `MAP.SHARED` was requested
    /// and `PROT_WRITE` is set, but the file descriptor is not open in `RDWR` mode.
    /// Or `PROT_WRITE` is set, but the file is append-only.
    AccessDenied,
    /// The `prot` argument asks for `PROT_EXEC` but the mapped area belongs to a file on
    /// a filesystem that was mounted no-exec.
    PermissionDenied,
    LockedMemoryLimitExceeded,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
} || Allocator.Error || File.ReadPositionalError;

pub const CreateOptions = struct {
    protection: std.process.MemoryProtection = .{ .read = true, .write = true },
    populate: bool = true,
    /// Byte index of file to start from.
    offset: u64 = 0,
    /// `null` indicates to map the entire file. If mapping the entire file is
    /// desired and the file size is known, it is more efficient to populate
    /// the value here.
    len: ?usize = null,
};

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
pub fn setLength(mm: *MemoryMap, io: Io, n: usize) File.SetLengthError!void {
    return io.vtable.fileMemoryMapSetLength(io.userdata, mm, n);
}

/// Synchronizes the contents of `memory` from `file`.
pub fn read(mm: *MemoryMap, io: Io) File.ReadPositionalError!void {
    return io.vtable.fileMemoryMapRead(io.userdata, mm);
}

/// Synchronizes the contents of `memory` to `file`.
pub fn write(mm: *MemoryMap, io: Io) File.WritePositionalError!void {
    return io.vtable.fileMemoryMapWrite(io.userdata, mm);
}
