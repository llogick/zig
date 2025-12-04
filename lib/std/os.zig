//! This file contains thin wrappers around OS-specific APIs, with these
//! specific goals in mind:
//! * Convert "errno"-style error codes into Zig errors.
//! * When null-terminated byte buffers are required, provide APIs which accept
//!   slices as well as APIs which accept null-terminated byte buffers. Same goes
//!   for WTF-16LE encoding.
//! * Where operating systems share APIs, e.g. POSIX, these thin wrappers provide
//!   cross platform abstracting.
//! * When there exists a corresponding libc function and linking libc, the libc
//!   implementation is used. Exceptions are made for known buggy areas of libc.
//!   On Linux libc can be side-stepped by using `std.os.linux` directly.
//! * For Windows, this file represents the API that libc would provide for
//!   Windows. For thin wrappers around Windows-specific APIs, see `std.os.windows`.

const root = @import("root");
const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const elf = std.elf;
const fs = std.fs;
const dl = @import("dynamic_library.zig");
const posix = std.posix;
const native_os = builtin.os.tag;

pub const linux = @import("os/linux.zig");
pub const plan9 = @import("os/plan9.zig");
pub const uefi = @import("os/uefi.zig");
pub const wasi = @import("os/wasi.zig");
pub const emscripten = @import("os/emscripten.zig");
pub const windows = @import("os/windows.zig");
pub const freebsd = @import("os/freebsd.zig");

test {
    _ = linux;
    if (native_os == .uefi) {
        _ = uefi;
    }
    _ = wasi;
    _ = windows;
}

/// See also `getenv`. Populated by startup code before main().
/// TODO this is a footgun because the value will be undefined when using `zig build-lib`.
/// https://github.com/ziglang/zig/issues/4524
pub var environ: [][*:0]u8 = undefined;

/// Populated by startup code before main().
/// Not available on WASI or Windows without libc. See `std.process.argsAlloc`
/// or `std.process.argsWithAllocator` for a cross-platform alternative.
pub var argv: [][*:0]u8 = if (builtin.link_libc) undefined else switch (native_os) {
    .windows => @compileError("argv isn't supported on Windows: use std.process.argsAlloc instead"),
    .wasi => @compileError("argv isn't supported on WASI: use std.process.argsAlloc instead"),
    else => undefined,
};

pub const FstatError = error{
    SystemResources,
    AccessDenied,
    Unexpected,
};

pub fn fstat_wasi(fd: posix.fd_t) FstatError!wasi.filestat_t {
    var stat: wasi.filestat_t = undefined;
    switch (wasi.fd_filestat_get(fd, &stat)) {
        .SUCCESS => return stat,
        .INVAL => unreachable,
        .BADF => unreachable, // Always a race condition.
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .NOTCAPABLE => return error.AccessDenied,
        else => |err| return posix.unexpectedErrno(err),
    }
}
