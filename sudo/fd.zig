//! flong's src/fd.zig cut down to the gate connection, as generation-checked
//! handles; readFile's descriptor never leaves it.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{ TableFull, Closed, Sys };

const capacity = 4;
const free: i32 = -1;

const Slot = struct {
    raw: i32 = free,
    gen: u32 = 0,
    deadline: ?u64 = null,
};

var slots: [capacity]Slot = @splat(.{});

fn live(slot: u8, gen: u32) *Slot {
    const s = &slots[slot];
    if (s.raw < 0 or s.gen != gen) @panic("stale descriptor handle");
    return s;
}

fn adopt(raw: i32) Error!Sock {
    for (&slots, 0..) |*s, i| {
        if (s.raw == free) {
            s.raw = raw;
            s.deadline = null;
            return .{ .slot = @intCast(i), .gen = s.gen };
        }
    }
    _ = linux.close(raw);
    return error.TableFull;
}

fn failed(rc: usize) bool {
    return linux.E.init(rc) != .SUCCESS;
}

fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn setTimeouts(raw: i32, tv: linux.timeval) Error!void {
    for ([_]u32{ linux.SO.SNDTIMEO, linux.SO.RCVTIMEO }) |opt| {
        if (failed(linux.setsockopt(raw, linux.SOL.SOCKET, opt, @ptrCast(&tv), @sizeOf(linux.timeval)))) return error.Sys;
    }
}

/// Bounds the next blocking call by what is left until the slot's deadline.
fn bound(s: *Slot) Error!void {
    const end = s.deadline orelse return;
    const t = now();
    if (t >= end) return error.Sys;
    const left = @max(end - t, std.time.ns_per_us);
    try setTimeouts(s.raw, .{ .sec = @intCast(left / std.time.ns_per_s), .usec = @intCast(left % std.time.ns_per_s / std.time.ns_per_us) });
}

/// A connected unix stream socket.
pub const Sock = struct {
    slot: u8,
    gen: u32,

    fn raw(self: Sock) i32 {
        return live(self.slot, self.gen).raw;
    }

    pub fn isLive(self: Sock) bool {
        const s = &slots[self.slot];
        return s.raw >= 0 and s.gen == self.gen;
    }

    pub fn close(self: Sock) void {
        const s = live(self.slot, self.gen);
        _ = linux.close(s.raw);
        s.raw = free;
        s.deadline = null;
        s.gen +%= 1;
    }

    /// Lifts connectUnix's bound from every later call.
    pub fn unbound(self: Sock) Error!void {
        const s = live(self.slot, self.gen);
        s.deadline = null;
        try setTimeouts(s.raw, .{ .sec = 0, .usec = 0 });
    }

    /// Sends all of `bytes`, with MSG_NOSIGNAL: a gate that has gone is an
    /// error here, never a SIGPIPE.
    pub fn sendAll(self: Sock, bytes: []const u8) Error!void {
        var done: usize = 0;
        while (done < bytes.len) {
            try bound(live(self.slot, self.gen));
            const rc = linux.sendto(self.raw(), bytes[done..].ptr, bytes.len - done, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.E.init(rc)) {
                .SUCCESS => done += rc,
                .INTR => {},
                else => return error.Sys,
            }
        }
    }

    /// Reads until `buf` is full or the peer closes; the count read.
    pub fn recvFull(self: Sock, buf: []u8) Error!usize {
        var done: usize = 0;
        while (done < buf.len) {
            try bound(live(self.slot, self.gen));
            const rc = linux.read(self.raw(), buf[done..].ptr, buf.len - done);
            switch (linux.E.init(rc)) {
                .SUCCESS => {
                    if (rc == 0) return done;
                    done += rc;
                },
                .INTR => {},
                else => return error.Sys,
            }
        }
        return done;
    }

    /// SO_PEERCRED's uid: the peer as the kernel recorded it at connect.
    pub fn peerUid(self: Sock) Error!u32 {
        var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
        var len: linux.socklen_t = @sizeOf(@TypeOf(cred));
        if (failed(linux.getsockopt(self.raw(), linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len))) return error.Sys;
        return cred.uid;
    }
};

/// Connects to the unix socket at `path`, SOCK_CLOEXEC. With `within`, the
/// connect and every later send and read end within that many ns in all.
pub fn connectUnix(path: []const u8, within: ?u64) Error!Sock {
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= addr.path.len) return error.Sys;
    @memcpy(addr.path[0..path.len], path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(rc)) return error.Sys;
    const sock = try adopt(@intCast(rc));
    errdefer sock.close();
    const s = live(sock.slot, sock.gen);
    if (within) |ns| s.deadline = now() + ns;
    try bound(s);
    if (failed(linux.connect(s.raw, @ptrCast(&addr), @sizeOf(linux.sockaddr.un)))) return error.Sys;
    return sock;
}

/// The start of the file at `path`, up to `buf.len` bytes, or null when it
/// cannot be read.
pub fn readFile(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOCTTY = true }, 0);
    if (failed(rc)) return null;
    const raw: i32 = @intCast(rc);
    defer _ = linux.close(raw);
    var done: usize = 0;
    while (done < buf.len) {
        const n = linux.read(raw, buf[done..].ptr, buf.len - done);
        switch (linux.E.init(n)) {
            .SUCCESS => {
                if (n == 0) break;
                done += n;
            },
            .INTR => {},
            else => return null,
        }
    }
    return buf[0..done];
}

test "a closed handle is no longer live, and its slot is reused under a new generation" {
    var fds: [2]i32 = undefined;
    try std.testing.expect(!failed(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)));
    defer _ = linux.close(fds[1]);
    const a = try adopt(fds[0]);
    a.close();
    try std.testing.expect(!a.isLive());
    var more: [2]i32 = undefined;
    try std.testing.expect(!failed(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &more)));
    defer _ = linux.close(more[1]);
    const b = try adopt(more[0]);
    defer b.close();
    try std.testing.expectEqual(a.slot, b.slot);
    try std.testing.expect(!a.isLive() and b.isLive());
}

test "a bounded connect, send and read end once the time is up, and unbound lifts it" {
    std.posix.unlink("fd-test.sock") catch |err| std.debug.assert(err == error.FileNotFound);
    defer std.posix.unlink("fd-test.sock") catch |err| std.debug.panic("unlink: {}", .{err});
    const l = try std.posix.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    defer std.posix.close(l);
    const addr = try std.net.Address.initUnix("fd-test.sock");
    try std.posix.bind(l, &addr.any, addr.getOsSockLen());
    try std.posix.listen(l, 1);
    const s = try connectUnix("fd-test.sock", 50 * std.time.ns_per_ms);
    defer s.close();
    const start = now();
    var b: [1]u8 = undefined;
    try std.testing.expectError(error.Sys, s.recvFull(&b));
    try std.testing.expect(now() - start >= 40 * std.time.ns_per_ms);
    try std.testing.expectError(error.Sys, s.sendAll("x"));
    try s.unbound();
    try s.sendAll("x");
}

test "readFile reads a file and says null for one that cannot be read" {
    var buf: [64]u8 = undefined;
    try std.testing.expect(readFile("/proc/self/stat", &buf) != null);
    try std.testing.expect(readFile("/proc/self/no-such-file", &buf) == null);
}
