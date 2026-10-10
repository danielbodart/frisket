//! A plugin built so its mode test always says -v: open() leaves a
//! no-tty, local sudo of the gated user ungated, and accept() refuses it.

const std = @import("std");
const plugin = @import("plugin");
const c = @import("abi").c;
const testing = std.testing;

var printed: usize = 0;

fn printf(kind: c_int, noalias fmt: [*c]const u8, ...) callconv(.c) c_int {
    _ = .{ kind, fmt };
    printed += 1;
    return 0;
}

test "accept() refuses a no-tty, local sudo of the gated user with no check-in, whatever open() decided" {
    var uid_buf: [32]u8 = undefined;
    const uid = try std.fmt.bufPrintZ(&uid_buf, "uid={d}", .{std.os.linux.getuid()});
    const ui = [_:null]?[*:0]const u8{ "user=tester", uid };
    const opts = [_:null]?[*:0]const u8{"user=tester"};
    const argv = [_:null]?[*:0]const u8{ "sudo", "id" };
    const none = [_:null]?[*:0]const u8{};
    var errstr: [*c]const u8 = null;
    try testing.expectEqual(@as(c_int, 1), plugin.frisket_audit.open.?(c.SUDO_API_VERSION_MAJOR << 16, null, printf, @ptrCast(&none), @ptrCast(&ui), 1, @ptrCast(&argv), @ptrCast(&none), @ptrCast(&opts), &errstr));
    try testing.expectEqual(@as(usize, 0), printed);
    const info = [_:null]?[*:0]const u8{"command=/run/current-system/sw/bin/id"};
    try testing.expectEqual(@as(c_int, 0), plugin.frisket_audit.accept.?("sudoers", c.SUDO_POLICY_PLUGIN, @ptrCast(&info), @ptrCast(&argv), @ptrCast(&none), &errstr));
    try testing.expectEqualStrings("gate not running", std.mem.span(errstr));
    plugin.frisket_audit.close.?(0, 0);
}
