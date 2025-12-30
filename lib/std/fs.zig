//! File System.

const std = @import("std.zig");

/// Deprecated, use `std.Io.Dir.path`.
pub const path = @import("fs/path.zig");
pub const wasi = @import("fs/wasi.zig");

pub const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".*;

/// Base64 encoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_encoder = std.base64.Base64Encoder.init(base64_alphabet, null);

/// Base64 decoder, replacing the standard `+/` with `-_` so that it can be used in a file name on any filesystem.
pub const base64_decoder = std.base64.Base64Decoder.init(base64_alphabet, null);

/// Deprecated, use `std.Io.Dir.max_path_bytes`.
pub const max_path_bytes = std.Io.Dir.max_path_bytes;
/// Deprecated, use `std.Io.Dir.max_name_bytes`.
pub const max_name_bytes = std.Io.Dir.max_name_bytes;

test {
    _ = path;
    _ = @import("fs/test.zig");
}
