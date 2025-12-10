const Writer = @This();
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const std = @import("../../std.zig");
const Io = std.Io;
const File = std.Io.File;
const assert = std.debug.assert;

io: Io,
file: File,
err: ?Error = null,
mode: Mode = .positional,
/// Tracks the true seek position in the file. To obtain the logical
/// position, add the buffer size to this value.
pos: u64 = 0,
write_file_err: ?WriteFileError = null,
seek_err: ?SeekError = null,
interface: Io.Writer,

pub const Mode = union(enum) {
    /// Uses `Io.VTable.fileWriteFileStreaming` if possible. Not a terminal.
    /// `setColor` does nothing.
    streaming,
    /// Uses `Io.VTable.fileWriteFilePositional` if possible. Not a terminal.
    /// `setColor` does nothing.
    positional,
    /// Avoids `Io.VTable.fileWriteFileStreaming`. Not a terminal. `setColor`
    /// does nothing.
    streaming_simple,
    /// Avoids `Io.VTable.fileWriteFilePositional`. Not a terminal. `setColor`
    /// does nothing.
    positional_simple,
    /// It's a terminal. Writes are escaped so as to strip escape sequences.
    /// Color is enabled.
    terminal_escaped,
    /// It's a terminal. Colors are enabled via calling
    /// SetConsoleTextAttribute. Writes are not escaped.
    terminal_winapi: TerminalWinapi,
    /// Indicates writing cannot continue because of a seek failure.
    failure,

    pub fn toStreaming(m: @This()) @This() {
        return switch (m) {
            .positional, .streaming => .streaming,
            .positional_simple, .streaming_simple => .streaming_simple,
            inline else => |_, x| x,
        };
    }

    pub fn toSimple(m: @This()) @This() {
        return switch (m) {
            .positional, .positional_simple => .positional_simple,
            .streaming, .streaming_simple => .streaming_simple,
            inline else => |x| x,
        };
    }

    pub fn toUnescaped(m: @This()) @This() {
        return switch (m) {
            .terminal_escaped => .streaming_simple,
            inline else => |x| x,
        };
    }

    pub const TerminalWinapi = if (!is_windows) noreturn else struct {
        handle: File.Handle,
        reset_attributes: u16,
    };

    /// Detect suitable TTY configuration options for the given file (commonly
    /// stdout/stderr).
    ///
    /// Will attempt to enable ANSI escape code support if necessary/possible.
    pub fn detect(io: Io, file: File, want_color: bool, fallback: Mode) Io.Cancelable!Mode {
        if (!want_color) return if (try file.isTty(io)) .terminal_escaped else fallback;

        if (file.enableAnsiEscapeCodes(io)) |_| {
            return .terminal_escaped;
        } else |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.NotTerminalDevice, error.Unexpected => {},
        }

        if (is_windows and file.isTty(io)) {
            const windows = std.os.windows;
            var info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
            if (windows.kernel32.GetConsoleScreenBufferInfo(file.handle, &info) != windows.FALSE) {
                return .{ .terminal_winapi = .{
                    .handle = file.handle,
                    .reset_attributes = info.wAttributes,
                } };
            }
            return .terminal_escaped;
        }

        return fallback;
    }

    pub const SetColorError = std.os.windows.SetConsoleTextAttributeError || Io.Writer.Error;

    pub fn setColor(mode: Mode, io_w: *Io.Writer, color: Color) Mode.SetColorError!void {
        switch (mode) {
            .streaming, .positional, .streaming_simple, .positional_simple, .failure => return,
            .terminal_escaped => {
                const color_string = switch (color) {
                    .black => "\x1b[30m",
                    .red => "\x1b[31m",
                    .green => "\x1b[32m",
                    .yellow => "\x1b[33m",
                    .blue => "\x1b[34m",
                    .magenta => "\x1b[35m",
                    .cyan => "\x1b[36m",
                    .white => "\x1b[37m",
                    .bright_black => "\x1b[90m",
                    .bright_red => "\x1b[91m",
                    .bright_green => "\x1b[92m",
                    .bright_yellow => "\x1b[93m",
                    .bright_blue => "\x1b[94m",
                    .bright_magenta => "\x1b[95m",
                    .bright_cyan => "\x1b[96m",
                    .bright_white => "\x1b[97m",
                    .bold => "\x1b[1m",
                    .dim => "\x1b[2m",
                    .reset => "\x1b[0m",
                };
                try io_w.writeAll(color_string);
            },
            .terminal_winapi => |ctx| {
                const windows = std.os.windows;
                const attributes: windows.WORD = switch (color) {
                    .black => 0,
                    .red => windows.FOREGROUND_RED,
                    .green => windows.FOREGROUND_GREEN,
                    .yellow => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN,
                    .blue => windows.FOREGROUND_BLUE,
                    .magenta => windows.FOREGROUND_RED | windows.FOREGROUND_BLUE,
                    .cyan => windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE,
                    .white => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE,
                    .bright_black => windows.FOREGROUND_INTENSITY,
                    .bright_red => windows.FOREGROUND_RED | windows.FOREGROUND_INTENSITY,
                    .bright_green => windows.FOREGROUND_GREEN | windows.FOREGROUND_INTENSITY,
                    .bright_yellow => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_INTENSITY,
                    .bright_blue => windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_magenta => windows.FOREGROUND_RED | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_cyan => windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_white, .bold => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    // "dim" is not supported using basic character attributes, but let's still make it do *something*.
                    // This matches the old behavior of TTY.Color before the bright variants were added.
                    .dim => windows.FOREGROUND_INTENSITY,
                    .reset => ctx.reset_attributes,
                };
                try io_w.flush();
                try windows.SetConsoleTextAttribute(ctx.handle, attributes);
            },
        }
    }
};

pub const Error = error{
    DiskQuota,
    FileTooBig,
    InputOutput,
    NoSpaceLeft,
    DeviceBusy,
    InvalidArgument,
    /// File descriptor does not hold the required rights to write to it.
    AccessDenied,
    PermissionDenied,
    /// File is an unconnected socket, or closed its read end.
    BrokenPipe,
    /// Insufficient kernel memory to read from in_fd.
    SystemResources,
    NotOpenForWriting,
    /// The process cannot access the file because another process has locked
    /// a portion of the file. Windows-only.
    LockViolation,
    /// Non-blocking has been enabled and this operation would block.
    WouldBlock,
    /// This error occurs when a device gets disconnected before or mid-flush
    /// while it's being written to - errno(6): No such device or address.
    NoDevice,
    FileBusy,
} || Io.Cancelable || Io.UnexpectedError;

pub const WriteFileError = Error || error{
    /// Descriptor is not valid or locked, or an mmap(2)-like operation is not available for in_fd.
    Unimplemented,
    EndOfStream,
    ReadFailed,
};

pub const SeekError = Io.File.SeekError;

pub fn init(file: File, io: Io, buffer: []u8) Writer {
    return .{
        .io = io,
        .file = file,
        .interface = initInterface(buffer),
        .mode = .positional,
    };
}

/// Positional is more threadsafe, since the global seek position is not
/// affected, but when such syscalls are not available, preemptively
/// initializing in streaming mode will skip a failed syscall.
pub fn initStreaming(file: File, io: Io, buffer: []u8) Writer {
    return .{
        .io = io,
        .file = file,
        .interface = initInterface(buffer),
        .mode = .streaming,
    };
}

/// Detects if `file` is terminal and sets the mode accordingly.
pub fn initDetect(file: File, io: Io, buffer: []u8) Io.Cancelable!Writer {
    return .{
        .io = io,
        .file = file,
        .interface = initInterface(buffer),
        .mode = try .detect(io, file, true, .positional),
    };
}

pub fn initInterface(buffer: []u8) Io.Writer {
    return .{
        .vtable = &.{
            .drain = drain,
            .sendFile = sendFile,
        },
        .buffer = buffer,
    };
}

pub fn moveToReader(w: *Writer) File.Reader {
    defer w.* = undefined;
    return .{
        .io = w.io,
        .file = .{ .handle = w.file.handle },
        .mode = w.mode,
        .pos = w.pos,
        .interface = File.Reader.initInterface(w.interface.buffer),
        .seek_err = w.seek_err,
    };
}

pub fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
    switch (w.mode) {
        .positional, .positional_simple => return drainPositional(w, data, splat),
        .streaming, .streaming_simple, .terminal_winapi => return drainStreaming(w, data, splat),
        .terminal_escaped => return drainEscaping(w, data, splat),
        .failure => return error.WriteFailed,
    }
}

fn drainPositional(w: *Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const io = w.io;
    const header = w.interface.buffered();
    const n = io.vtable.fileWritePositional(io.userdata, w.file, header, data, splat, w.pos) catch |err| switch (err) {
        error.Unseekable => {
            w.mode = w.mode.toStreaming();
            const pos = w.pos;
            if (pos != 0) {
                w.pos = 0;
                w.seekTo(@intCast(pos)) catch {
                    w.mode = .failure;
                    return error.WriteFailed;
                };
            }
            return 0;
        },
        else => |e| {
            w.err = e;
            return error.WriteFailed;
        },
    };
    w.pos += n;
    return w.interface.consume(n);
}

fn drainStreaming(w: *Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const io = w.io;
    const header = w.interface.buffered();
    const n = io.vtable.fileWriteStreaming(io.userdata, w.file, header, data, splat) catch |err| {
        w.err = err;
        return error.WriteFailed;
    };
    w.pos += n;
    return w.interface.consume(n);
}

fn findTerminalEscape(buffer: []const u8) ?usize {
    return std.mem.findScalar(u8, buffer, 0x1b);
}

fn drainEscaping(w: *Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const io = w.io;
    const header = w.interface.buffered();
    if (findTerminalEscape(header)) |i| {
        _ = i;
        @panic("TODO strip terminal escape sequence");
    }
    for (data) |d| {
        if (findTerminalEscape(d)) |i| {
            _ = i;
            @panic("TODO strip terminal escape sequence");
        }
    }
    const n = io.vtable.fileWriteStreaming(io.userdata, w.file, header, data, splat) catch |err| {
        w.err = err;
        return error.WriteFailed;
    };
    w.pos += n;
    return w.interface.consume(n);
}

pub fn sendFile(io_w: *Io.Writer, file_reader: *Io.File.Reader, limit: Io.Limit) Io.Writer.FileError!usize {
    const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
    switch (w.mode) {
        .positional => return sendFilePositional(w, file_reader, limit),
        .positional_simple => return error.Unimplemented,
        .streaming => return sendFileStreaming(w, file_reader, limit),
        .streaming_simple, .terminal_escaped, .terminal_winapi => return error.Unimplemented,
        .failure => return error.WriteFailed,
    }
}

fn sendFilePositional(w: *Writer, file_reader: *Io.File.Reader, limit: Io.Limit) Io.Writer.FileError!usize {
    const io = w.io;
    const header = w.interface.buffered();
    const n = io.vtable.fileWriteFilePositional(io.userdata, w.file, header, file_reader, limit, w.pos) catch |err| switch (err) {
        error.Unseekable => {
            w.mode = w.mode.toStreaming();
            const pos = w.pos;
            if (pos != 0) {
                w.pos = 0;
                w.seekTo(@intCast(pos)) catch {
                    w.mode = .failure;
                    return error.WriteFailed;
                };
            }
            return 0;
        },
        error.Canceled => {
            w.err = error.Canceled;
            return error.WriteFailed;
        },
        error.EndOfStream => return error.EndOfStream,
        error.Unimplemented => return error.Unimplemented,
        error.ReadFailed => return error.ReadFailed,
        else => |e| {
            w.write_file_err = e;
            return error.WriteFailed;
        },
    };
    w.pos += n;
    return w.interface.consume(n);
}

fn sendFileStreaming(w: *Writer, file_reader: *Io.File.Reader, limit: Io.Limit) Io.Writer.FileError!usize {
    const io = w.io;
    const header = w.interface.buffered();
    const n = io.vtable.fileWriteFileStreaming(io.userdata, w.file, header, file_reader, limit) catch |err| switch (err) {
        error.Canceled => {
            w.err = error.Canceled;
            return error.WriteFailed;
        },
        error.EndOfStream => return error.EndOfStream,
        error.Unimplemented => return error.Unimplemented,
        error.ReadFailed => return error.ReadFailed,
        else => |e| {
            w.write_file_err = e;
            return error.WriteFailed;
        },
    };
    w.pos += n;
    return w.interface.consume(n);
}

pub fn seekTo(w: *Writer, offset: u64) (SeekError || Io.Writer.Error)!void {
    try w.interface.flush();
    try seekToUnbuffered(w, offset);
}

/// Asserts that no data is currently buffered.
pub fn seekToUnbuffered(w: *Writer, offset: u64) SeekError!void {
    assert(w.interface.buffered().len == 0);
    const io = w.io;
    switch (w.mode) {
        .positional, .positional_simple => {
            w.pos = offset;
        },
        .streaming, .streaming_simple, .terminal_escaped, .terminal_winapi => {
            if (w.seek_err) |err| return err;
            io.vtable.fileSeekTo(io.userdata, w.file, offset) catch |err| {
                w.seek_err = err;
                return err;
            };
            w.pos = offset;
        },
        .failure => return w.seek_err.?,
    }
}

pub const EndError = File.SetLengthError || Io.Writer.Error;

/// Flushes any buffered data and sets the end position of the file.
///
/// If not overwriting existing contents, then calling `interface.flush`
/// directly is sufficient.
///
/// Flush failure is handled by setting `err` so that it can be handled
/// along with other write failures.
pub fn end(w: *Writer) EndError!void {
    const io = w.io;
    try w.interface.flush();
    switch (w.mode) {
        .positional,
        .positional_simple,
        => w.file.setLength(io, w.pos) catch |err| switch (err) {
            error.NonResizable => return,
            else => |e| return e,
        },

        .streaming,
        .streaming_simple,
        .failure,
        => {},
    }
}

pub const Color = enum {
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_cyan,
    bright_white,
    dim,
    bold,
    reset,
};

pub const SetColorError = Mode.SetColorError;

pub fn setColor(w: *Writer, color: Color) SetColorError!void {
    return w.mode.setColor(&w.interface, color);
}

pub fn disableEscape(w: *Writer) Mode {
    const prev = w.mode;
    w.mode = w.mode.toUnescaped();
    return prev;
}

pub fn restoreEscape(w: *Writer, mode: Mode) void {
    w.mode = mode;
}

pub fn writeAllUnescaped(w: *Writer, bytes: []const u8) Io.Error!void {
    const prev_mode = w.disableEscape();
    defer w.restoreEscape(prev_mode);
    return w.interface.writeAll(bytes);
}

pub fn printUnescaped(w: *Writer, comptime fmt: []const u8, args: anytype) Io.Error!void {
    const prev_mode = w.disableEscape();
    defer w.restoreEscape(prev_mode);
    return w.interface.print(fmt, args);
}
