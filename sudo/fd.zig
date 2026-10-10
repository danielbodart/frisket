//! The descriptors frisket-sudo keeps, as generation-checked handles: flong's
//! src/fd.zig cut down to the one kind the plugin and the PAM helper hold, a
//! connection to the gate. A handle is a slot and a generation, so a copy
//! used after `close` panics instead of reaching whatever reused the number.
//!
//! `readFile` is the one other way a descriptor is opened, and it never
//! leaves the function: open() reads /proc with it before deciding whether
//! to gate, when it may touch no handle.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{ TableFull, Closed, Sys };

const capacity = 4;
const free: i32 = -1;

const Slot = struct {
    raw: i32 = free,
    gen: u32 = 0,
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
            return .{ .slot = @intCast(i), .gen = s.gen };
        }
    }
    _ = linux.close(raw);
    return error.TableFull;
}

fn failed(rc: usize) bool {
    return linux.E.init(rc) != .SUCCESS;
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
        s.gen +%= 1;
    }

    /// Sends all of `bytes`, with MSG_NOSIGNAL: a gate that has gone is an
    /// error here, never a SIGPIPE.
    pub fn sendAll(self: Sock, bytes: []const u8) Error!void {
        var done: usize = 0;
        while (done < bytes.len) {
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

/// Connects to the unix socket at `path`, SOCK_CLOEXEC.
pub fn connectUnix(path: []const u8) Error!Sock {
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= addr.path.len) return error.Sys;
    @memcpy(addr.path[0..path.len], path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(rc)) return error.Sys;
    const raw: i32 = @intCast(rc);
    if (failed(linux.connect(raw, @ptrCast(&addr), @sizeOf(linux.sockaddr.un)))) {
        _ = linux.close(raw);
        return error.Sys;
    }
    return adopt(raw);
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

test "readFile reads a file and says null for one that cannot be read" {
    var buf: [64]u8 = undefined;
    try std.testing.expect(readFile("/proc/self/stat", &buf) != null);
    try std.testing.expect(readFile("/proc/self/no-such-file", &buf) == null);
}
