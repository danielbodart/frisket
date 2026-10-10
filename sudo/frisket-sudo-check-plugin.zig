//! frisket-sudo-check-plugin SO SYMBOL SUDO_VERSION, at build time: loads the
//! plugin as sudo would and fails unless SYMBOL is an audit plugin of this
//! sudo_plugin.h's API major, built for SUDO_VERSION. sudo loads a plugin
//! of the wrong type without complaint and every sudo then segfaults.

const std = @import("std");
const abi = @import("abi");
const config = @import("config");

pub fn main() u8 {
    const args = std.os.argv;
    if (args.len != 4) return fail("usage: frisket-sudo-check-plugin SO SYMBOL SUDO_VERSION", .{});
    const so, const symbol, const version = .{ args[1], args[2], std.mem.span(args[3]) };
    const lib = std.c.dlopen(so, .{ .NOW = true }) orelse return fail("cannot load {s}: {s}", .{ so, std.c.dlerror() orelse "" });
    const sym = std.c.dlsym(lib, symbol) orelse return fail("{s}: no symbol {s}", .{ so, symbol });
    const plugin: *const abi.c.struct_audit_plugin = @ptrCast(@alignCast(sym));
    if (plugin.type != abi.c.SUDO_AUDIT_PLUGIN)
        return fail("{s}: {s} is plugin type {d}, not {d} (audit)", .{ so, symbol, plugin.type, abi.c.SUDO_AUDIT_PLUGIN });
    if (plugin.version >> 16 != abi.c.SUDO_API_VERSION_MAJOR)
        return fail("{s}: {s} has API major {d}, not {d}", .{ so, symbol, plugin.version >> 16, abi.c.SUDO_API_VERSION_MAJOR });
    if (!std.mem.eql(u8, version, config.sudo_version))
        return fail("{s} is built for sudo {s}, not {s}", .{ so, config.sudo_version, version });
    return 0;
}

fn fail(comptime fmt: []const u8, args: anytype) u8 {
    var buf: [1024]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    w.interface.print("frisket-sudo-check-plugin: " ++ fmt ++ "\n", args) catch return 1;
    w.interface.flush() catch return 1;
    return 1;
}
