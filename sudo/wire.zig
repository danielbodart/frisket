//! The sudo wire, version 2, between the Zig and the gate.

const std = @import("std");
const chain = @import("chain");
const agent = @import("agent");

pub const magic = "FSUD";
pub const version = 2;
pub const max_request = 1 << 20;
pub const max_message = 512;
pub const max_password = 1023;
/// The one timeout: 'C' and 'G', connect to reply. No person is waited on.
pub const answer_within = 250 * std.time.ns_per_ms;
pub const header_len = 10;
const record_head = 5;
/// An 'S': a key and a signature, each from one agent frame.
pub const max_signature_request = header_len + 2 * (record_head + agent.max_frame);

pub const Kind = enum(u8) {
    check_in = 'C',
    did_check_in = 'G',
    approval = 'A',
    verify = 'V',
    signature = 'S',
};

pub const Tag = enum(u8) {
    link = 'k',
    user_info = 'u',
    settings = 's',
    command_info = 'c',
    run_argv = 'a',
    run_envp = 'e',
    result = 'r',
    truncated = 't',
    remote = 'm',
    key = 'p',
    agent_signature = 'g',
    agent_failed = 'f',
};

/// A NULL-terminated array of C strings, as sudo passes them.
pub const CArray = [*c]const [*c]u8;

pub const Error = error{TooLong};

const Out = struct {
    buf: []u8,
    len: usize = 0,

    fn bytes(self: *Out, b: []const u8) void {
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }

    fn int(self: *Out, comptime T: type, v: T) void {
        std.mem.writeInt(T, self.buf[self.len..][0..@sizeOf(T)], v, .big);
        self.len += @sizeOf(T);
    }

    fn header(self: *Out, kind: Kind) void {
        self.bytes(magic);
        self.int(u8, version);
        self.int(u8, @intFromEnum(kind));
        self.int(u32, 0);
    }

    fn record(self: *Out, tag: Tag, b: []const u8) void {
        self.int(u8, @intFromEnum(tag));
        self.int(u32, @intCast(b.len));
        self.bytes(b);
    }

    fn finish(self: *Out) []u8 {
        std.mem.writeInt(u32, self.buf[6..10], @intCast(self.len - header_len), .big);
        return self.buf[0..self.len];
    }
};

/// 'G', and a local 'C': no body.
pub fn empty(buf: *[header_len]u8, kind: Kind) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(kind);
    return o.finish();
}

/// 'C', with an 'm' record when remote.
pub fn checkIn(buf: *[header_len + record_head]u8, remote: bool) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(.check_in);
    if (remote) o.record(.remote, "");
    return o.finish();
}

/// 'S' with the listed key the agent signed with and its signature.
pub fn signature(buf: *[max_signature_request]u8, key: []const u8, sig: []const u8) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(.signature);
    o.record(.key, key);
    o.record(.agent_signature, sig);
    return o.finish();
}

/// 'S' saying the agent step failed, and why.
pub fn signFailed(buf: *[max_signature_request]u8, why: []const u8) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(.signature);
    o.record(.agent_failed, why[0..@min(why.len, max_message)]);
    return o.finish();
}

/// 'V' with the result of the password check.
pub fn verify(buf: *[header_len + record_head + 1]u8, ok: bool) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(.verify);
    o.record(.result, &.{@intFromBool(ok)});
    return o.finish();
}

fn linkSize(l: *const chain.Link, cmdline: bool) usize {
    return record_head + 4 + 4 + 8 + 4 + 4 + 2 + l.comm().len + 2 + if (cmdline) l.cmdline().len else 0;
}

fn count(a: CArray) usize {
    var n: usize = 0;
    if (a == null) return 0;
    while (a[n] != null) n += 1;
    return n;
}

fn arraySize(a: CArray, n: usize) usize {
    var size: usize = 0;
    for (0..n) |i| size += record_head + std.mem.len(a[i]);
    return size;
}

/// 'A' within max_request, with an 'm' record when remote: over it,
/// run_envp entries go from the end, then cmdlines from the top of the chain,
/// and a 't' record says so.
pub fn approval(buf: *[max_request]u8, links: []const chain.Link, user_info: CArray, settings: CArray, command_info: CArray, run_argv: CArray, run_envp: CArray, remote: bool) Error![]u8 {
    var size: usize = header_len;
    if (remote) size += record_head;
    for (links) |*l| size += linkSize(l, true);
    for ([_]CArray{ user_info, settings, command_info, run_argv }) |a| size += arraySize(a, count(a));
    var envs = count(run_envp);
    size += arraySize(run_envp, envs);

    const truncated = size > max_request;
    var cmdlines = links.len;
    if (truncated) {
        size += record_head;
        while (size > max_request and envs > 0) {
            envs -= 1;
            size -= record_head + std.mem.len(run_envp[envs]);
        }
        while (size > max_request and cmdlines > 0) {
            cmdlines -= 1;
            size -= links[cmdlines].cmdline().len;
        }
        if (size > max_request) return error.TooLong;
    }

    var o: Out = .{ .buf = buf };
    o.header(.approval);
    for (links, 0..) |*l, i| {
        const cmd = if (i < cmdlines) l.cmdline() else "";
        o.int(u8, @intFromEnum(Tag.link));
        o.int(u32, @intCast(linkSize(l, i < cmdlines) - record_head));
        o.int(u32, l.pid);
        o.int(u32, l.ppid);
        o.int(u64, l.start);
        o.int(u32, l.uid);
        o.int(u32, l.tty);
        o.int(u16, @intCast(l.comm().len));
        o.bytes(l.comm());
        o.int(u16, @intCast(cmd.len));
        o.bytes(cmd);
    }
    const arrays = [_]struct { Tag, CArray, usize }{
        .{ .user_info, user_info, count(user_info) },
        .{ .settings, settings, count(settings) },
        .{ .command_info, command_info, count(command_info) },
        .{ .run_argv, run_argv, count(run_argv) },
        .{ .run_envp, run_envp, envs },
    };
    for (arrays) |x| {
        for (0..x[2]) |i| o.record(x[0], std.mem.span(x[1][i]));
    }
    if (remote) o.record(.remote, "");
    if (truncated) o.record(.truncated, "");
    return o.finish();
}

pub const Reply = enum(u8) { yes = 'Y', no = 'N', password = 'W', message = 'M' };

/// What a reply answers: 'C', 'G' or 'S' (yes or no), a local 'A' or 'V'
/// (also 'W'), or a remote 'A' ('M' or 'N').
pub const Expect = enum { yes_no, local, remote };

/// The reply kind in `b`, if `e` allows it.
pub fn replyKind(b: u8, e: Expect) ?Reply {
    const r = std.meta.intToEnum(Reply, b) catch return null;
    const ok = switch (r) {
        .no => true,
        .yes => e != .remote,
        .password => e == .local,
        .message => e == .remote,
    };
    return if (ok) r else null;
}

/// The size of a reply's length field: u32be for 'M', else u16be.
pub fn lengthSize(r: Reply) usize {
    return if (r == .message) 4 else 2;
}

/// Whether `len` is within the limit for a reply of kind `r`.
pub fn lengthOk(r: Reply, len: u32) bool {
    return len <= @as(u32, switch (r) {
        .yes, .no => max_message,
        .password => max_password,
        .message => max_request,
    });
}

/// An 'M' body: the message to sign and the listed keys.
pub const Signing = struct {
    message: []const u8,
    /// uint32 n, string key blob × n, n ≥ 1.
    keys: []const u8,
};

/// `string message | uint32 count | string key blob*`, with at least one key
/// and no trailing bytes, or null.
pub fn signing(body: []const u8) ?Signing {
    var r: agent.Reader = .{ .b = body };
    const message = r.string() orelse return null;
    if (!agent.validKeys(r.b)) return null;
    return .{ .message = message, .keys = r.b };
}

/// Whether a 'Y' or 'N' message is printable ASCII.
pub fn printable(m: []const u8) bool {
    for (m) |ch| {
        if (ch < 0x20 or ch > 0x7e) return false;
    }
    return true;
}

const testing = std.testing;

fn testLink(pid: u32, comm: []const u8, cmd: []const u8) chain.Link {
    var l: chain.Link = .{ .pid = pid, .ppid = pid + 1, .start = 0x0102030405060708, .uid = 1000, .tty = 0 };
    @memcpy(l.comm_buf[0..comm.len], comm);
    l.comm_len = @intCast(comm.len);
    @memcpy(l.cmdline_buf[0..cmd.len], cmd);
    l.cmdline_len = @intCast(cmd.len);
    return l;
}

var test_buf: [max_request]u8 = undefined;

test "'C', 'V' and 'S' frame to their bytes" {
    var c: [header_len]u8 = undefined;
    try testing.expectEqualSlices(u8, "FSUD\x02C\x00\x00\x00\x00", empty(&c, .check_in));
    var cm: [header_len + record_head]u8 = undefined;
    try testing.expectEqualSlices(u8, "FSUD\x02C\x00\x00\x00\x00", checkIn(&cm, false));
    try testing.expectEqualSlices(u8, "FSUD\x02C\x00\x00\x00\x05m\x00\x00\x00\x00", checkIn(&cm, true));
    var v: [header_len + record_head + 1]u8 = undefined;
    try testing.expectEqualSlices(u8, "FSUD\x02V\x00\x00\x00\x06r\x00\x00\x00\x01\x01", verify(&v, true));
    try testing.expectEqualSlices(u8, "FSUD\x02S\x00\x00\x00\x0fp\x00\x00\x00\x02kbg\x00\x00\x00\x03sig", signature(&sig_buf, "kb", "sig"));
    try testing.expectEqualSlices(u8, "FSUD\x02S\x00\x00\x00\x09f\x00\x00\x00\x04why?", signFailed(&sig_buf, "why?"));
}

var sig_buf: [max_signature_request]u8 = undefined;

test "'A' frames a link and one record per entry, and 'm' when remote" {
    const links = [_]chain.Link{testLink(7, "bash", "bash\x00-c\x00x")};
    const ui = [_:null]?[*:0]const u8{ "user=dan", "uid=1000" };
    const none = [_:null]?[*:0]const u8{};
    const argv = [_:null]?[*:0]const u8{"id"};
    const req = try approval(&test_buf, &links, @ptrCast(&ui), @ptrCast(&none), @ptrCast(&none), @ptrCast(&argv), null, false);
    const want = "FSUD\x02A\x00\x00\x00\x4f" ++
        "k\x00\x00\x00\x29\x00\x00\x00\x07\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x04bash\x00\x09bash\x00-c\x00x" ++
        "u\x00\x00\x00\x08user=dan" ++ "u\x00\x00\x00\x08uid=1000" ++ "a\x00\x00\x00\x02id";
    try testing.expectEqualSlices(u8, want, req);
    const remote = try approval(&test_buf, &links, @ptrCast(&ui), @ptrCast(&none), @ptrCast(&none), @ptrCast(&argv), null, true);
    try testing.expectEqualSlices(u8, "FSUD\x02A\x00\x00\x00\x54", remote[0..10]);
    try testing.expectEqualSlices(u8, want[10..] ++ "m\x00\x00\x00\x00", remote[10..]);
}

var big_buf: [max_request + 1]u8 = undefined;

fn big(len: usize) [*:0]const u8 {
    @memset(big_buf[0..len], 'y');
    @memcpy(big_buf[0..2], "X=");
    big_buf[len] = 0;
    return big_buf[0..len :0];
}

test "an 'A' over the limit drops run_envp from its end first and says so" {
    const env = big(600 * 1024);
    const links = [_]chain.Link{testLink(7, "bash", "bash")};
    const envp = [_:null]?[*:0]const u8{ "A=1", env, env };
    const argv = [_:null]?[*:0]const u8{"id"};
    const req = try approval(&test_buf, &links, null, null, null, @ptrCast(&argv), @ptrCast(&envp), true);
    try testing.expect(req.len <= max_request);
    try testing.expect(std.mem.indexOf(u8, req, "e\x00\x00\x00\x03A=1") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, req, "X=yyyy"));
    try testing.expect(std.mem.endsWith(u8, req, "m\x00\x00\x00\x00t\x00\x00\x00\x00"));
    try testing.expectEqual(@as(u32, @intCast(req.len - header_len)), std.mem.readInt(u32, req[6..10], .big));
}

test "an argv that cannot fit is TooLong" {
    const argv = [_:null]?[*:0]const u8{big(max_request)};
    try testing.expectError(error.TooLong, approval(&test_buf, &.{}, null, null, null, @ptrCast(&argv), null, false));
}

test "a reply is refused when its kind, length or place is wrong" {
    try testing.expectEqual(Reply.yes, replyKind('Y', .yes_no).?);
    try testing.expectEqual(Reply.no, replyKind('N', .remote).?);
    try testing.expect(replyKind('Y', .remote) == null);
    try testing.expect(replyKind('W', .yes_no) == null);
    try testing.expect(replyKind('W', .remote) == null);
    try testing.expect(replyKind('M', .local) == null);
    try testing.expect(replyKind('M', .yes_no) == null);
    try testing.expectEqual(Reply.password, replyKind('W', .local).?);
    try testing.expectEqual(Reply.message, replyKind('M', .remote).?);
    try testing.expect(replyKind('X', .local) == null);
    try testing.expectEqual(@as(usize, 4), lengthSize(.message));
    try testing.expectEqual(@as(usize, 2), lengthSize(.no));
    try testing.expect(lengthOk(.yes, 512) and !lengthOk(.yes, 513));
    try testing.expect(lengthOk(.password, 1023) and !lengthOk(.password, 1024));
    try testing.expect(lengthOk(.message, max_request) and !lengthOk(.message, max_request + 1));
    try testing.expect(printable("frisket-sudo: ok ~"));
    try testing.expect(!printable("a\nb"));
}

test "an 'M' body is a message and at least one key, with nothing after" {
    const m = signing("\x00\x00\x00\x03msg\x00\x00\x00\x02\x00\x00\x00\x01a\x00\x00\x00\x02bc").?;
    try testing.expectEqualStrings("msg", m.message);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x02\x00\x00\x00\x01a\x00\x00\x00\x02bc", m.keys);
    try testing.expect(signing("\x00\x00\x00\x03msg\x00\x00\x00\x00") == null);
    try testing.expect(signing("\x00\x00\x00\x03msg\x00\x00\x00\x01\x00\x00\x00\x01ax") == null);
    try testing.expect(signing("\x00\x00\x00\x09msg") == null);
    try testing.expect(signing("") == null);
}
