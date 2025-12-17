/// Abstraction for writing to a stream that might support terminal escape
/// codes.
const Terminal = @This();

const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const std = @import("std");
const Io = std.Io;
const File = std.Io.File;

writer: *Io.Writer,
mode: Mode,

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

pub const Mode = union(enum) {
    no_color,
    escape_codes,
    windows_api: WindowsApi,

    pub const WindowsApi = if (!is_windows) noreturn else struct {
        handle: File.Handle,
        reset_attributes: u16,
    };

    /// Detect suitable TTY configuration options for the given file (commonly
    /// stdout/stderr).
    ///
    /// Will attempt to enable ANSI escape code support if necessary/possible.
    pub fn detect(io: Io, file: File) Io.Cancelable!Mode {
        if (file.enableAnsiEscapeCodes(io)) |_| {
            return .escape_codes;
        } else |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.NotTerminalDevice, error.Unexpected => {},
        }

        if (is_windows and file.isTty(io)) {
            const windows = std.os.windows;
            var info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
            if (windows.kernel32.GetConsoleScreenBufferInfo(file.handle, &info) != 0) {
                return .{ .terminal_winapi = .{
                    .handle = file.handle,
                    .reset_attributes = info.wAttributes,
                } };
            }
            return .escape_codes;
        }

        return .no_color;
    }
};

pub const SetColorError = std.os.windows.SetConsoleTextAttributeError || Io.Writer.Error;

pub fn setColor(t: Terminal, color: Color) Io.Writer.Error!void {
    switch (t.mode) {
        .no_color => return,
        .escape_codes => {
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
            try t.writer.writeAll(color_string);
        },
        .windows_api => |wa| {
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
                .reset => wa.reset_attributes,
            };
            try t.writer.flush();
            try windows.SetConsoleTextAttribute(wa.handle, attributes);
        },
    }
}

pub fn disableEscape(t: *Terminal) Mode {
    const prev = t.mode;
    t.mode = t.mode.toUnescaped();
    return prev;
}

pub fn restoreEscape(t: *Terminal, mode: Mode) void {
    t.mode = mode;
}

pub fn writeAllUnescaped(t: *Terminal, bytes: []const u8) Io.Writer.Error!void {
    const prev_mode = t.disableEscape();
    defer t.restoreEscape(prev_mode);
    return t.interface.writeAll(bytes);
}

pub fn printUnescaped(t: *Terminal, comptime fmt: []const u8, args: anytype) Io.Writer.Error!void {
    const prev_mode = t.disableEscape();
    defer t.restoreEscape(prev_mode);
    return t.interface.print(fmt, args);
}
