//! frisket-sudo-pam USER: pam_exec's helper in sudo's auth stack,
//! `sufficient`, before pam_unix. Exits 0, so sudo skips the password, only
//! when the gate says its parent sudo checked in.

const std = @import("std");
const fd = @import("fd");
const wire = @import("wire");
const config = @import("config");

pub fn main() u8 {
    const user = if (std.os.argv.len > 1) std.mem.span(std.os.argv[1]) else return 1;
    return if (skip(std.posix.getenv("PAM_TTY"), std.posix.getenv("PAM_SERVICE"), std.posix.getenv("PAM_USER"), user)) 0 else 1;
}

fn skip(tty: ?[]const u8, service: ?[]const u8, pam_user: ?[]const u8, user: []const u8) bool {
    if (tty != null) return false;
    if (!std.mem.eql(u8, service orelse return false, "sudo")) return false;
    if (!std.mem.eql(u8, pam_user orelse return false, user)) return false;
    return checkedIn() catch false;
}

fn checkedIn() !bool {
    const s = try fd.connectUnix(config.gate_path);
    defer s.close();
    if (try s.peerUid() != config.gate_uid) return false;
    var req: [10]u8 = undefined;
    try s.sendAll(wire.empty(&req, .did_check_in));
    var h: [3]u8 = undefined;
    if (try s.recvFull(&h) != h.len) return false;
    const head = wire.head(h, false) orelse return false;
    return head.reply == .yes;
}

test "a tty, another service or another user skips nothing and asks no gate" {
    try std.testing.expect(!skip("/dev/pts/0", "sudo", "dan", "dan"));
    try std.testing.expect(!skip(null, "su", "dan", "dan"));
    try std.testing.expect(!skip(null, null, "dan", "dan"));
    try std.testing.expect(!skip(null, "sudo", "bob", "dan"));
    try std.testing.expect(!skip(null, "sudo", null, "dan"));
}
