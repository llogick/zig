const Writer = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;
const is_windows = native_os == .windows;

const std = @import("../../std.zig");
const Io = std.Io;
const File = std.Io.File;
const assert = std.debug.assert;
const windows = std.os.windows;
const posix = std.posix;

file: File,
err: ?File.WriteError = null,
mode: Writer.Mode = .positional,
/// Tracks the true seek position in the file. To obtain the logical
/// position, add the buffer size to this value.
pos: u64 = 0,
sendfile_err: ?SendfileError = null,
copy_file_range_err: ?CopyFileRangeError = null,
fcopyfile_err: ?FcopyfileError = null,
seek_err: ?Writer.SeekError = null,
interface: Io.Writer,

pub const Mode = File.Reader.Mode;

pub const SendfileError = error{
    UnsupportedOperation,
    SystemResources,
    InputOutput,
    BrokenPipe,
    WouldBlock,
    Unexpected,
};

pub const CopyFileRangeError = std.os.freebsd.CopyFileRangeError || std.os.linux.wrapped.CopyFileRangeError;

pub const FcopyfileError = error{
    OperationNotSupported,
    OutOfMemory,
    Unexpected,
};

pub const SeekError = Io.File.SeekError;

/// Number of slices to store on the stack, when trying to send as many byte
/// vectors through the underlying write calls as possible.
const max_buffers_len = 16;

pub fn init(file: File, buffer: []u8) Writer {
    return .{
        .file = file,
        .interface = initInterface(buffer),
        .mode = .positional,
    };
}

/// Positional is more threadsafe, since the global seek position is not
/// affected, but when such syscalls are not available, preemptively
/// initializing in streaming mode will skip a failed syscall.
pub fn initStreaming(file: File, buffer: []u8) Writer {
    return .{
        .file = file,
        .interface = initInterface(buffer),
        .mode = .streaming,
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
    const handle = w.file.handle;
    const buffered = io_w.buffered();
    if (is_windows) switch (w.mode) {
        .positional, .positional_reading => {
            if (buffered.len != 0) {
                const n = windows.WriteFile(handle, buffered, w.pos) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                w.pos += n;
                return io_w.consume(n);
            }
            for (data[0 .. data.len - 1]) |buf| {
                if (buf.len == 0) continue;
                const n = windows.WriteFile(handle, buf, w.pos) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                w.pos += n;
                return io_w.consume(n);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            const n = windows.WriteFile(handle, pattern, w.pos) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            w.pos += n;
            return io_w.consume(n);
        },
        .streaming, .streaming_reading => {
            if (buffered.len != 0) {
                const n = windows.WriteFile(handle, buffered, null) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                w.pos += n;
                return io_w.consume(n);
            }
            for (data[0 .. data.len - 1]) |buf| {
                if (buf.len == 0) continue;
                const n = windows.WriteFile(handle, buf, null) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                w.pos += n;
                return io_w.consume(n);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            const n = windows.WriteFile(handle, pattern, null) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            w.pos += n;
            return io_w.consume(n);
        },
        .failure => return error.WriteFailed,
    };
    var iovecs: [max_buffers_len]posix.iovec_const = undefined;
    var len: usize = 0;
    if (buffered.len > 0) {
        iovecs[len] = .{ .base = buffered.ptr, .len = buffered.len };
        len += 1;
    }
    for (data[0 .. data.len - 1]) |d| {
        if (d.len == 0) continue;
        iovecs[len] = .{ .base = d.ptr, .len = d.len };
        len += 1;
        if (iovecs.len - len == 0) break;
    }
    const pattern = data[data.len - 1];
    if (iovecs.len - len != 0) switch (splat) {
        0 => {},
        1 => if (pattern.len != 0) {
            iovecs[len] = .{ .base = pattern.ptr, .len = pattern.len };
            len += 1;
        },
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer_candidate = io_w.buffer[io_w.end..];
                var backup_buffer: [64]u8 = undefined;
                const splat_buffer = if (splat_buffer_candidate.len >= backup_buffer.len)
                    splat_buffer_candidate
                else
                    &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                iovecs[len] = .{ .base = buf.ptr, .len = buf.len };
                len += 1;
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - len != 0) {
                    assert(buf.len == splat_buffer.len);
                    iovecs[len] = .{ .base = splat_buffer.ptr, .len = splat_buffer.len };
                    len += 1;
                    remaining_splat -= splat_buffer.len;
                }
                if (remaining_splat > 0 and iovecs.len - len != 0) {
                    iovecs[len] = .{ .base = splat_buffer.ptr, .len = remaining_splat };
                    len += 1;
                }
            },
            else => for (0..splat) |_| {
                iovecs[len] = .{ .base = pattern.ptr, .len = pattern.len };
                len += 1;
                if (iovecs.len - len == 0) break;
            },
        },
    };
    if (len == 0) return 0;
    switch (w.mode) {
        .positional, .positional_reading => {
            const n = posix.pwritev(handle, iovecs[0..len], w.pos) catch |err| switch (err) {
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
            return io_w.consume(n);
        },
        .streaming, .streaming_reading => {
            const n = posix.writev(handle, iovecs[0..len]) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            w.pos += n;
            return io_w.consume(n);
        },
        .failure => return error.WriteFailed,
    }
}

pub fn sendFile(
    io_w: *Io.Writer,
    file_reader: *Io.File.Reader,
    limit: Io.Limit,
) Io.Writer.FileError!usize {
    const reader_buffered = file_reader.interface.buffered();
    if (reader_buffered.len >= @intFromEnum(limit))
        return sendFileBuffered(io_w, file_reader, limit.slice(reader_buffered));
    const writer_buffered = io_w.buffered();
    const file_limit = @intFromEnum(limit) - reader_buffered.len;
    const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
    const out_fd = w.file.handle;
    const in_fd = file_reader.file.handle;

    if (file_reader.size) |size| {
        if (size - file_reader.pos == 0) {
            if (reader_buffered.len != 0) {
                return sendFileBuffered(io_w, file_reader, reader_buffered);
            } else {
                return error.EndOfStream;
            }
        }
    }

    if (native_os == .freebsd and w.mode == .streaming) sf: {
        // Try using sendfile on FreeBSD.
        if (w.sendfile_err != null) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (writer_buffered.len != 0) {
            headers[headers_i] = .{ .base = writer_buffered.ptr, .len = writer_buffered.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        var sbytes: std.c.off_t = undefined;
        const nbytes: usize = @min(file_limit, std.math.maxInt(usize));
        const flags = 0;
        switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, nbytes, hdtr, &sbytes, flags))) {
            .SUCCESS, .INTR => {},
            .INVAL, .OPNOTSUPP, .NOTSOCK, .NOSYS => w.sendfile_err = error.UnsupportedOperation,
            .BADF => if (builtin.mode == .Debug) @panic("race condition") else {
                w.sendfile_err = error.Unexpected;
            },
            .FAULT => if (builtin.mode == .Debug) @panic("segmentation fault") else {
                w.sendfile_err = error.Unexpected;
            },
            .NOTCONN => w.sendfile_err = error.BrokenPipe,
            .AGAIN, .BUSY => if (sbytes == 0) {
                w.sendfile_err = error.WouldBlock;
            },
            .IO => w.sendfile_err = error.InputOutput,
            .PIPE => w.sendfile_err = error.BrokenPipe,
            .NOBUFS => w.sendfile_err = error.SystemResources,
            else => |err| w.sendfile_err = posix.unexpectedErrno(err),
        }
        if (w.sendfile_err != null) {
            // Give calling code chance to observe the error before trying
            // something else.
            return 0;
        }
        if (sbytes == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const consumed = io_w.consume(@intCast(sbytes));
        file_reader.seekBy(@intCast(consumed)) catch return error.ReadFailed;
        return consumed;
    }

    if (native_os.isDarwin() and w.mode == .streaming) sf: {
        // Try using sendfile on macOS.
        if (w.sendfile_err != null) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (writer_buffered.len != 0) {
            headers[headers_i] = .{ .base = writer_buffered.ptr, .len = writer_buffered.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        const max_count = std.math.maxInt(i32); // Avoid EINVAL.
        var len: std.c.off_t = @min(file_limit, max_count);
        const flags = 0;
        switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, &len, hdtr, flags))) {
            .SUCCESS, .INTR => {},
            .OPNOTSUPP, .NOTSOCK, .NOSYS => w.sendfile_err = error.UnsupportedOperation,
            .BADF => if (builtin.mode == .Debug) @panic("race condition") else {
                w.sendfile_err = error.Unexpected;
            },
            .FAULT => if (builtin.mode == .Debug) @panic("segmentation fault") else {
                w.sendfile_err = error.Unexpected;
            },
            .INVAL => if (builtin.mode == .Debug) @panic("invalid API usage") else {
                w.sendfile_err = error.Unexpected;
            },
            .NOTCONN => w.sendfile_err = error.BrokenPipe,
            .AGAIN => if (len == 0) {
                w.sendfile_err = error.WouldBlock;
            },
            .IO => w.sendfile_err = error.InputOutput,
            .PIPE => w.sendfile_err = error.BrokenPipe,
            else => |err| w.sendfile_err = posix.unexpectedErrno(err),
        }
        if (w.sendfile_err != null) {
            // Give calling code chance to observe the error before trying
            // something else.
            return 0;
        }
        if (len == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const consumed = io_w.consume(@bitCast(len));
        file_reader.seekBy(@intCast(consumed)) catch return error.ReadFailed;
        return consumed;
    }

    if (native_os == .linux and w.mode == .streaming) sf: {
        // Try using sendfile on Linux.
        if (w.sendfile_err != null) break :sf;
        // Linux sendfile does not support headers.
        if (writer_buffered.len != 0 or reader_buffered.len != 0)
            return sendFileBuffered(io_w, file_reader, reader_buffered);
        const max_count = 0x7ffff000; // Avoid EINVAL.
        var off: std.os.linux.off_t = undefined;
        const off_ptr: ?*std.os.linux.off_t, const count: usize = switch (file_reader.mode) {
            .positional => o: {
                const size = file_reader.getSize() catch return 0;
                off = std.math.cast(std.os.linux.off_t, file_reader.pos) orelse return error.ReadFailed;
                break :o .{ &off, @min(@intFromEnum(limit), size - file_reader.pos, max_count) };
            },
            .streaming => .{ null, limit.minInt(max_count) },
            .streaming_reading, .positional_reading => break :sf,
            .failure => return error.ReadFailed,
        };
        const n = std.os.linux.wrapped.sendfile(out_fd, in_fd, off_ptr, count) catch |err| switch (err) {
            error.Unseekable => {
                file_reader.mode = file_reader.mode.toStreaming();
                const pos = file_reader.pos;
                if (pos != 0) {
                    file_reader.pos = 0;
                    file_reader.seekBy(@intCast(pos)) catch {
                        file_reader.mode = .failure;
                        return error.ReadFailed;
                    };
                }
                return 0;
            },
            else => |e| {
                w.sendfile_err = e;
                return 0;
            },
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        w.pos += n;
        return n;
    }

    const copy_file_range = switch (native_os) {
        .freebsd => std.os.freebsd.copy_file_range,
        .linux => std.os.linux.wrapped.copy_file_range,
        else => {},
    };
    if (@TypeOf(copy_file_range) != void) cfr: {
        if (w.copy_file_range_err != null) break :cfr;
        if (writer_buffered.len != 0 or reader_buffered.len != 0)
            return sendFileBuffered(io_w, file_reader, reader_buffered);
        var off_in: i64 = undefined;
        var off_out: i64 = undefined;
        const off_in_ptr: ?*i64 = switch (file_reader.mode) {
            .positional_reading, .streaming_reading => return error.Unimplemented,
            .positional => p: {
                off_in = @intCast(file_reader.pos);
                break :p &off_in;
            },
            .streaming => null,
            .failure => return error.WriteFailed,
        };
        const off_out_ptr: ?*i64 = switch (w.mode) {
            .positional_reading, .streaming_reading => return error.Unimplemented,
            .positional => p: {
                off_out = @intCast(w.pos);
                break :p &off_out;
            },
            .streaming => null,
            .failure => return error.WriteFailed,
        };
        const n = copy_file_range(in_fd, off_in_ptr, out_fd, off_out_ptr, @intFromEnum(limit), 0) catch |err| {
            w.copy_file_range_err = err;
            return 0;
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        w.pos += n;
        return n;
    }

    if (builtin.os.tag.isDarwin()) fcf: {
        if (w.fcopyfile_err != null) break :fcf;
        if (file_reader.pos != 0) break :fcf;
        if (w.pos != 0) break :fcf;
        if (limit != .unlimited) break :fcf;
        const size = file_reader.getSize() catch break :fcf;
        if (writer_buffered.len != 0 or reader_buffered.len != 0)
            return sendFileBuffered(io_w, file_reader, reader_buffered);
        const rc = std.c.fcopyfile(in_fd, out_fd, null, .{ .DATA = true });
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INVAL => if (builtin.mode == .Debug) @panic("invalid API usage") else {
                w.fcopyfile_err = error.Unexpected;
                return 0;
            },
            .NOMEM => {
                w.fcopyfile_err = error.OutOfMemory;
                return 0;
            },
            .OPNOTSUPP => {
                w.fcopyfile_err = error.OperationNotSupported;
                return 0;
            },
            else => |err| {
                w.fcopyfile_err = posix.unexpectedErrno(err);
                return 0;
            },
        }
        file_reader.pos = size;
        w.pos = size;
        return size;
    }

    return error.Unimplemented;
}

fn sendFileBuffered(
    io_w: *Io.Writer,
    file_reader: *Io.File.Reader,
    reader_buffered: []const u8,
) Io.Writer.FileError!usize {
    const n = try drain(io_w, &.{reader_buffered}, 1);
    file_reader.seekBy(@intCast(n)) catch return error.ReadFailed;
    return n;
}

pub fn seekTo(w: *Writer, offset: u64) (Writer.SeekError || Io.Writer.Error)!void {
    try w.interface.flush();
    try seekToUnbuffered(w, offset);
}

/// Asserts that no data is currently buffered.
pub fn seekToUnbuffered(w: *Writer, offset: u64) Writer.SeekError!void {
    assert(w.interface.buffered().len == 0);
    switch (w.mode) {
        .positional, .positional_reading => {
            w.pos = offset;
        },
        .streaming, .streaming_reading => {
            if (w.seek_err) |err| return err;
            posix.lseek_SET(w.file.handle, offset) catch |err| {
                w.seek_err = err;
                return err;
            };
            w.pos = offset;
        },
        .failure => return w.seek_err.?,
    }
}

pub const EndError = File.SetEndPosError || Io.Writer.Error;

/// Flushes any buffered data and sets the end position of the file.
///
/// If not overwriting existing contents, then calling `interface.flush`
/// directly is sufficient.
///
/// Flush failure is handled by setting `err` so that it can be handled
/// along with other write failures.
pub fn end(w: *Writer) EndError!void {
    try w.interface.flush();
    switch (w.mode) {
        .positional,
        .positional_reading,
        => w.file.setEndPos(w.pos) catch |err| switch (err) {
            error.NonResizable => return,
            else => |e| return e,
        },

        .streaming,
        .streaming_reading,
        .failure,
        => {},
    }
}
