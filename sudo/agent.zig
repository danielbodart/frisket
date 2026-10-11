//! Remote mode's ssh-agent client: the first identity among the listed keys
//! signs the gate's message with a plain SSH_AGENTC_SIGN_REQUEST.

const std = @import("std");
const fd = @import("fd");

/// OpenSSH's agent message limit.
pub const max_frame = 256 * 1024;

const failure = 5;
const request_identities = 11;
const identities_answer = 12;
const sign_request = 13;
const sign_response = 14;

/// SSH wire encoding: uint32 big-endian, string as uint32 length then bytes.
pub const Reader = struct {
    b: []const u8,

    pub fn byte(r: *Reader) ?u8 {
        if (r.b.len < 1) return null;
        defer r.b = r.b[1..];
        return r.b[0];
    }

    pub fn int(r: *Reader) ?u32 {
        if (r.b.len < 4) return null;
        defer r.b = r.b[4..];
        return std.mem.readInt(u32, r.b[0..4], .big);
    }

    pub fn string(r: *Reader) ?[]const u8 {
        const n = r.int() orelse return null;
        if (n > r.b.len) return null;
        defer r.b = r.b[n..];
        return r.b[0..n];
    }

    pub fn done(r: Reader) bool {
        return r.b.len == 0;
    }
};

/// Whether `keys` is exactly `uint32 n, string blob × n` with n ≥ 1 and no
/// blob empty.
pub fn validKeys(keys: []const u8) bool {
    var r: Reader = .{ .b = keys };
    const n = r.int() orelse return false;
    if (n == 0) return false;
    for (0..n) |_| {
        const k = r.string() orelse return false;
        if (k.len == 0) return false;
    }
    return r.done();
}

/// The listed key byte-equal to `blob`, as a slice of `keys`.
fn listed(keys: []const u8, blob: []const u8) ?[]const u8 {
    var r: Reader = .{ .b = keys };
    const n = r.int() orelse return null;
    for (0..n) |_| {
        const k = r.string() orelse return null;
        if (std.mem.eql(u8, k, blob)) return k;
    }
    return null;
}

pub const Outcome = union(enum) {
    /// `key` is a slice of the listed keys; `signature` is SIGN_RESPONSE's
    /// string format | string blob, a slice of the frame buffer.
    signed: struct { key: []const u8, signature: []const u8 },
    /// Printable ASCII, for the 'f' record.
    failed: []const u8,
};

const hung_up = "the forwarded agent hung up";
const garbage = "the forwarded agent sent garbage";

fn failed(why: []const u8) Outcome {
    return .{ .failed = why };
}

/// One agent frame into `buf`: u32be length, then that many bytes.
fn frame(s: fd.Sock, buf: *[max_frame]u8) error{ HungUp, Garbage }![]u8 {
    var h: [4]u8 = undefined;
    if ((s.recvFull(&h) catch return error.HungUp) != h.len) return error.HungUp;
    const len = std.mem.readInt(u32, &h, .big);
    if (len == 0 or len > max_frame) return error.Garbage;
    const body = buf[0..len];
    if ((s.recvFull(body) catch return error.HungUp) != len) return error.HungUp;
    return body;
}

fn frameFailed(e: error{ HungUp, Garbage }) Outcome {
    return failed(switch (e) {
        error.HungUp => hung_up,
        error.Garbage => garbage,
    });
}

/// Asks the agent on `s` for its identities and has the first one that is
/// among `keys` (validKeys) sign `message`, with flags 0. No timeout: a
/// person answers on the client.
pub fn sign(s: fd.Sock, keys: []const u8, message: []const u8, buf: *[max_frame]u8) Outcome {
    s.sendAll(&.{ 0, 0, 0, 1, request_identities }) catch return failed(hung_up);
    var r: Reader = .{ .b = frame(s, buf) catch |e| return frameFailed(e) };
    switch (r.byte() orelse return failed(garbage)) {
        identities_answer => {},
        failure => return failed("the forwarded agent failed"),
        else => return failed(garbage),
    }
    const n = r.int() orelse return failed(garbage);
    var key: ?[]const u8 = null;
    for (0..n) |_| {
        const blob = r.string() orelse return failed(garbage);
        _ = r.string() orelse return failed(garbage);
        if (key == null) key = listed(keys, blob);
    }
    if (!r.done()) return failed(garbage);
    const k = key orelse return failed("no listed key in the forwarded agent");

    const len = 1 + 4 + k.len + 4 + message.len + 4;
    if (len > max_frame) return failed("message too long for the agent");
    var head: [9]u8 = undefined;
    std.mem.writeInt(u32, head[0..4], @intCast(len), .big);
    head[4] = sign_request;
    std.mem.writeInt(u32, head[5..9], @intCast(k.len), .big);
    var mlen: [4]u8 = undefined;
    std.mem.writeInt(u32, &mlen, @intCast(message.len), .big);
    const flags = [4]u8{ 0, 0, 0, 0 };
    for ([_][]const u8{ &head, k, &mlen, message, &flags }) |part| s.sendAll(part) catch return failed(hung_up);

    r = .{ .b = frame(s, buf) catch |e| return frameFailed(e) };
    switch (r.byte() orelse return failed(garbage)) {
        sign_response => {},
        failure => return failed("the forwarded agent refused"),
        else => return failed(garbage),
    }
    const sig = r.string() orelse return failed(garbage);
    if (!r.done()) return failed(garbage);
    var inner: Reader = .{ .b = sig };
    _ = inner.string() orelse return failed(garbage);
    _ = inner.string() orelse return failed(garbage);
    if (!inner.done()) return failed(garbage);
    return .{ .signed = .{ .key = k, .signature = sig } };
}

const testing = std.testing;

fn put(out: []u8, at: *usize, b: []const u8) void {
    @memcpy(out[at.*..][0..b.len], b);
    at.* += b.len;
}

fn putInt(out: []u8, at: *usize, v: u32) void {
    std.mem.writeInt(u32, out[at.*..][0..4], v, .big);
    at.* += 4;
}

fn putString(out: []u8, at: *usize, b: []const u8) void {
    putInt(out, at, @intCast(b.len));
    put(out, at, b);
}

/// A frame of `kind` and the strings `parts`; an identities answer counts
/// its key and comment pairs first.
fn testFrame(out: []u8, kind: u8, parts: []const []const u8) []u8 {
    var at: usize = 4;
    out[at] = kind;
    at += 1;
    if (kind == identities_answer) putInt(out, &at, @intCast(parts.len / 2));
    for (parts) |p| putString(out, &at, p);
    std.mem.writeInt(u32, out[0..4], @intCast(at - 4), .big);
    return out[0..at];
}

/// A test agent on a unix socket: reads one request, answers with the next
/// canned reply, and records what it was sent.
const TestAgent = struct {
    listener: std.posix.socket_t,
    path: []const u8,
    replies: []const []const u8,
    thread: std.Thread = undefined,
    got: [2][1024]u8 = undefined,
    got_len: [2]usize = .{ 0, 0 },

    fn start(path: []const u8, replies: []const []const u8) !*TestAgent {
        std.posix.unlink(path) catch |err| std.debug.assert(err == error.FileNotFound);
        const l = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
        const addr = try std.net.Address.initUnix(path);
        try std.posix.bind(l, &addr.any, addr.getOsSockLen());
        try std.posix.listen(l, 1);
        const a = try testing.allocator.create(TestAgent);
        a.* = .{ .listener = l, .path = path, .replies = replies };
        a.thread = try std.Thread.spawn(.{}, serve, .{a});
        return a;
    }

    fn serve(a: *TestAgent) void {
        const conn = std.posix.accept(a.listener, null, null, std.posix.SOCK.CLOEXEC) catch return;
        defer std.posix.close(conn);
        for (a.replies, 0..) |reply, i| {
            var h: [4]u8 = undefined;
            if (readFull(conn, &h) != 4) return;
            const len = std.mem.readInt(u32, &h, .big);
            if (len > a.got[i].len or readFull(conn, a.got[i][0..len]) != len) return;
            a.got_len[i] = len;
            _ = std.posix.write(conn, reply) catch return;
        }
    }

    fn readFull(f: std.posix.socket_t, buf: []u8) usize {
        var done: usize = 0;
        while (done < buf.len) {
            const n = std.posix.read(f, buf[done..]) catch return done;
            if (n == 0) return done;
            done += n;
        }
        return done;
    }

    fn stop(a: *TestAgent) void {
        a.thread.join();
        std.posix.close(a.listener);
        std.posix.unlink(a.path) catch |err| std.debug.panic("unlink: {}", .{err});
        testing.allocator.destroy(a);
    }
};

var test_buf: [max_frame]u8 = undefined;

fn listedKeys(out: []u8, keys: []const []const u8) []u8 {
    var at: usize = 0;
    putInt(out, &at, @intCast(keys.len));
    for (keys) |k| putString(out, &at, k);
    return out[0..at];
}

fn signWith(replies: []const []const u8, keys: []const u8) !struct { Outcome, *TestAgent } {
    const a = try TestAgent.start("agent-test.sock", replies);
    const s = try fd.connectUnix("agent-test.sock", null);
    defer s.close();
    return .{ sign(s, keys, "the message", &test_buf), a };
}

test "the first offered identity that is listed signs, with flags 0" {
    var kb: [128]u8 = undefined;
    const keys = listedKeys(&kb, &.{ "key-b", "key-c" });
    var ib: [256]u8 = undefined;
    const ids = testFrame(&ib, identities_answer, &.{ "key-a", "comment a", "key-c", "comment c", "key-b", "comment b" });
    var sb: [256]u8 = undefined;
    var inner: [64]u8 = undefined;
    var at: usize = 0;
    putString(&inner, &at, "ssh-ed25519");
    putString(&inner, &at, "sigbytes");
    const resp = testFrame(&sb, sign_response, &.{inner[0..at]});
    const out, const a = try signWith(&.{ ids, resp }, keys);
    defer a.stop();
    try testing.expectEqualStrings("key-c", out.signed.key);
    try testing.expectEqualSlices(u8, inner[0..at], out.signed.signature);
    try testing.expectEqualSlices(u8, &.{request_identities}, a.got[0][0..a.got_len[0]]);
    try testing.expectEqualSlices(u8, "\x0d\x00\x00\x00\x05key-c\x00\x00\x00\x0bthe message\x00\x00\x00\x00", a.got[1][0..a.got_len[1]]);
}

test "a refusal, a failure, EOF, garbage and no listed identity are each a reason" {
    var kb: [128]u8 = undefined;
    const keys = listedKeys(&kb, &.{"key-b"});
    var ib: [256]u8 = undefined;
    const ids = testFrame(&ib, identities_answer, &.{ "key-b", "" });
    var ib2: [256]u8 = undefined;
    const unlisted = testFrame(&ib2, identities_answer, &.{ "key-a", "" });
    const cases = [_]struct { replies: []const []const u8, want: []const u8 }{
        .{ .replies = &.{ ids, "\x00\x00\x00\x01\x05" }, .want = "the forwarded agent refused" },
        .{ .replies = &.{"\x00\x00\x00\x01\x05"}, .want = "the forwarded agent failed" },
        .{ .replies = &.{}, .want = hung_up },
        .{ .replies = &.{ids}, .want = hung_up },
        .{ .replies = &.{"\x00\x00\x00\x02\x0c"}, .want = hung_up },
        .{ .replies = &.{"\x7f\xff\xff\xff"}, .want = garbage },
        .{ .replies = &.{"\x00\x00\x00\x01\x0e"}, .want = garbage },
        .{ .replies = &.{ ids, "\x00\x00\x00\x05\x0e\x00\x00\x00\x00" }, .want = garbage },
        .{ .replies = &.{unlisted}, .want = "no listed key in the forwarded agent" },
    };
    for (cases) |cs| {
        const out, const a = try signWith(cs.replies, keys);
        a.stop();
        try testing.expectEqualStrings(cs.want, out.failed);
    }
}

test "a message too long for an agent frame is refused before it is sent" {
    var kb: [128]u8 = undefined;
    const keys = listedKeys(&kb, &.{"key-b"});
    var ib: [256]u8 = undefined;
    const ids = testFrame(&ib, identities_answer, &.{ "key-b", "" });
    const a = try TestAgent.start("agent-test.sock", &.{ids});
    defer a.stop();
    const s = try fd.connectUnix("agent-test.sock", null);
    defer s.close();
    const big = try testing.allocator.alloc(u8, max_frame);
    defer testing.allocator.free(big);
    try testing.expectEqualStrings("message too long for the agent", sign(s, keys, big, &test_buf).failed);
}

test "the listed keys parse only as a count of at least one and non-empty blobs" {
    var kb: [128]u8 = undefined;
    try testing.expect(validKeys(listedKeys(&kb, &.{ "a", "b" })));
    try testing.expect(!validKeys(listedKeys(&kb, &.{})));
    try testing.expect(!validKeys(listedKeys(&kb, &.{""})));
    try testing.expect(!validKeys("\x00\x00\x00\x01\x00\x00\x00\x02a"));
    try testing.expect(!validKeys("\x00\x00\x00\x01\x00\x00\x00\x01ab"));
}
