//! The drop to the invoking user for remote mode's connect to the forwarded
//! agent, and the exact restore of sudo's ids. Never connect as root: root's
//! CAP_DAC_OVERRIDE passes the socket's modes.

const std = @import("std");
const c = @import("abi").c;
const fd = @import("fd");

pub const max_groups = 65536;

pub const Error = error{ Drop, Restore, Connect };

/// libc's calls, which set the ids of every thread.
pub const Libc = struct {
    pub fn getresuid(out: *[3]u32) bool {
        return c.getresuid(&out[0], &out[1], &out[2]) == 0;
    }

    pub fn getresgid(out: *[3]u32) bool {
        return c.getresgid(&out[0], &out[1], &out[2]) == 0;
    }

    pub fn getgroups(buf: []u32) ?[]u32 {
        const n = c.getgroups(@intCast(buf.len), buf.ptr);
        if (n < 0) return null;
        return buf[0..@intCast(n)];
    }

    pub fn setgroups(groups: []const u32) bool {
        return c.setgroups(groups.len, groups.ptr) == 0;
    }

    pub fn setegid(gid: u32) bool {
        return c.setegid(gid) == 0;
    }

    pub fn seteuid(uid: u32) bool {
        return c.seteuid(uid) == 0;
    }
};

const Ids = struct {
    uid: [3]u32,
    gid: [3]u32,
    groups: []u32,

    fn read(comptime Sys: type, buf: []u32) ?Ids {
        var ids: Ids = undefined;
        if (!Sys.getresuid(&ids.uid) or !Sys.getresgid(&ids.gid)) return null;
        ids.groups = Sys.getgroups(buf) orelse return null;
        return ids;
    }

    fn eql(a: Ids, b: Ids) bool {
        return std.mem.eql(u32, &a.uid, &b.uid) and std.mem.eql(u32, &a.gid, &b.gid) and std.mem.eql(u32, a.groups, b.groups);
    }
};

var saved_groups: [max_groups]u32 = undefined;
var check_groups: [max_groups]u32 = undefined;

/// Connects to `path` with the effective ids and groups of `uid`, `gid` and
/// `groups`, then restores sudo's and checks every id against the saved ones.
pub fn connectAs(comptime Sys: type, path: []const u8, uid: u32, gid: u32, groups: []const u32) Error!fd.Sock {
    const saved = Ids.read(Sys, &saved_groups) orelse return error.Drop;
    const swap = !std.mem.eql(u32, saved.groups, groups);
    if (swap and !Sys.setgroups(groups)) return error.Drop;
    const dropped = Sys.setegid(gid) and Sys.seteuid(uid);
    const s: ?fd.Sock = if (dropped) fd.connectUnix(path, null) catch null else null;
    if (!restore(Sys, saved, swap)) {
        if (s) |x| x.close();
        return error.Restore;
    }
    if (!dropped) return error.Drop;
    return s orelse error.Connect;
}

fn restore(comptime Sys: type, saved: Ids, swap: bool) bool {
    var ok = Sys.seteuid(saved.uid[1]);
    ok = Sys.setegid(saved.gid[1]) and ok;
    if (swap) ok = Sys.setgroups(saved.groups) and ok;
    const now = Ids.read(Sys, &check_groups) orelse return false;
    return ok and now.eql(saved);
}

const testing = std.testing;

/// Ids as a setuid sudo has them, with each set call able to fail or to
/// succeed while setting the wrong id.
const Fake = struct {
    var uid: [3]u32 = .{ 1000, 0, 0 };
    var gid: [3]u32 = .{ 100, 0, 0 };
    var groups_buf: [4]u32 = .{ 100, 1, 0, 0 };
    var groups_len: usize = 2;
    var calls: usize = 0;
    var fail_at: usize = 0;
    var lie_at: usize = 0;
    var connected_as: ?u32 = null;

    fn reset(fail: usize, lie: usize) void {
        uid = .{ 1000, 0, 0 };
        gid = .{ 100, 0, 0 };
        groups_buf = .{ 100, 1, 0, 0 };
        groups_len = 2;
        calls = 0;
        fail_at = fail;
        lie_at = lie;
    }

    fn call() enum { fail, lie, ok } {
        calls += 1;
        if (calls == fail_at) return .fail;
        if (calls == lie_at) return .lie;
        return .ok;
    }

    pub fn getresuid(out: *[3]u32) bool {
        out.* = uid;
        return true;
    }

    pub fn getresgid(out: *[3]u32) bool {
        out.* = gid;
        return true;
    }

    pub fn getgroups(buf: []u32) ?[]u32 {
        @memcpy(buf[0..groups_len], groups_buf[0..groups_len]);
        return buf[0..groups_len];
    }

    pub fn setgroups(g: []const u32) bool {
        switch (call()) {
            .fail => return false,
            .lie => groups_len = 0,
            .ok => {
                @memcpy(groups_buf[0..g.len], g);
                groups_len = g.len;
            },
        }
        return true;
    }

    pub fn setegid(g: u32) bool {
        switch (call()) {
            .fail => return false,
            .lie => gid[1] = g +% 1,
            .ok => gid[1] = g,
        }
        return true;
    }

    pub fn seteuid(u: u32) bool {
        switch (call()) {
            .fail => return false,
            .lie => uid[1] = u +% 1,
            .ok => uid[1] = u,
        }
        return true;
    }
};

fn fakeConnect() Error!fd.Sock {
    return connectAs(Fake, "ids-test-no-such.sock", 1000, 100, &.{ 100, 27 });
}

test "every failed or lying set call refuses, and the ids come back or the restore refuses" {
    Fake.reset(0, 0);
    try testing.expectError(error.Connect, fakeConnect());
    const calls = Fake.calls;
    try testing.expectEqual(@as(usize, 6), calls);
    for (1..calls + 1) |n| {
        Fake.reset(n, 0);
        const drop_stage = n <= 3;
        try testing.expectError(if (drop_stage) error.Drop else error.Restore, fakeConnect());
        if (drop_stage) {
            try testing.expectEqual([3]u32{ 1000, 0, 0 }, Fake.uid);
            try testing.expectEqual([3]u32{ 100, 0, 0 }, Fake.gid);
            try testing.expectEqualSlices(u32, &.{ 100, 1 }, Fake.groups_buf[0..Fake.groups_len]);
        }
        Fake.reset(0, n);
        const lied = fakeConnect();
        if (n <= 3) {
            try testing.expectError(error.Connect, lied);
        } else {
            try testing.expectError(error.Restore, lied);
        }
    }
}

test "the same groups are not set again" {
    Fake.reset(0, 0);
    try testing.expectError(error.Connect, connectAs(Fake, "ids-test-no-such.sock", 1000, 100, &.{ 100, 1 }));
    try testing.expectEqual(@as(usize, 4), Fake.calls);
}

var own_groups: [max_groups]u32 = undefined;

test "a connect as this process's own ids leaves every id as it was" {
    const before = Ids.read(Libc, &own_groups).?;
    std.posix.unlink("ids-test.sock") catch |err| std.debug.assert(err == error.FileNotFound);
    defer std.posix.unlink("ids-test.sock") catch |err| std.debug.panic("unlink: {}", .{err});
    const l = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(l);
    const addr = try std.net.Address.initUnix("ids-test.sock");
    try std.posix.bind(l, &addr.any, addr.getOsSockLen());
    try std.posix.listen(l, 1);
    const s = try connectAs(Libc, "ids-test.sock", before.uid[0], before.gid[0], before.groups);
    s.close();
    var after_buf: [max_groups]u32 = undefined;
    try testing.expect(Ids.read(Libc, &after_buf).?.eql(before));
    if (before.uid[1] != 0) {
        try testing.expectError(error.Drop, connectAs(Libc, "ids-test.sock", before.uid[0], before.gid[0], &.{before.gid[0] +% 12345}));
        try testing.expect(Ids.read(Libc, &after_buf).?.eql(before));
    }
}
