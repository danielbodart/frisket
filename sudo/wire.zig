//! The sudo wire, version 1, between the Zig and the gate.

const std = @import("std");
const chain = @import("chain");

pub const magic = "FSUD";
pub const version = 1;
pub const max_request = 1 << 20;
pub const max_message = 512;
pub const max_password = 1023;
const header_len = 10;
const record_head = 5;

pub const Kind = enum(u8) {
    check_in = 'C',
    did_check_in = 'G',
    approval = 'A',
    verify = 'V',
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

/// 'C' and 'G': no body.
pub fn empty(buf: *[header_len]u8, kind: Kind) []u8 {
    var o: Out = .{ .buf = buf };
    o.header(kind);
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

/// 'A': the chain and the run info, within max_request. Over it, run_envp
/// loses entries from its end, then the links lose their cmdlines from the
/// top of the chain down, and a 't' record says so; what still does not
/// fit is TooLong.
pub fn approval(buf: *[max_request]u8, links: []const chain.Link, user_info: CArray, settings: CArray, command_info: CArray, run_argv: CArray, run_envp: CArray) Error![]u8 {
    var size: usize = header_len;
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
    if (truncated) o.record(.truncated, "");
    return o.finish();
}

pub const Reply = enum(u8) { yes = 'Y', no = 'N', password = 'W' };

pub const Head = struct { reply: Reply, len: u16 };

/// A reply's kind and length, or null for garbage. 'W' is a reply only to
/// 'A' or 'V'.
pub fn head(b: [3]u8, password_ok: bool) ?Head {
    const len = std.mem.readInt(u16, b[1..3], .big);
    const reply = std.meta.intToEnum(Reply, b[0]) catch return null;
    switch (reply) {
        .yes, .no => if (len > max_message) return null,
        .password => if (!password_ok or len > max_password) return null,
    }
    return .{ .reply = reply, .len = len };
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

test "'C' and 'V' frame to their bytes" {
    var c: [header_len]u8 = undefined;
    try testing.expectEqualSlices(u8, "FSUD\x01C\x00\x00\x00\x00", empty(&c, .check_in));
    var v: [header_len + record_head + 1]u8 = undefined;
    try testing.expectEqualSlices(u8, "FSUD\x01V\x00\x00\x00\x06r\x00\x00\x00\x01\x01", verify(&v, true));
}

test "'A' frames a link and one record per entry" {
    const links = [_]chain.Link{testLink(7, "bash", "bash\x00-c\x00x")};
    const ui = [_:null]?[*:0]const u8{ "user=dan", "uid=1000" };
    const none = [_:null]?[*:0]const u8{};
    const argv = [_:null]?[*:0]const u8{"id"};
    const req = try approval(&test_buf, &links, @ptrCast(&ui), @ptrCast(&none), @ptrCast(&none), @ptrCast(&argv), null);
    const want = "FSUD\x01A\x00\x00\x00\x4f" ++
        "k\x00\x00\x00\x29\x00\x00\x00\x07\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x04bash\x00\x09bash\x00-c\x00x" ++
        "u\x00\x00\x00\x08user=dan" ++ "u\x00\x00\x00\x08uid=1000" ++ "a\x00\x00\x00\x02id";
    try testing.expectEqualSlices(u8, want, req);
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
    const req = try approval(&test_buf, &links, null, null, null, @ptrCast(&argv), @ptrCast(&envp));
    try testing.expect(req.len <= max_request);
    try testing.expect(std.mem.indexOf(u8, req, "e\x00\x00\x00\x03A=1") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, req, "X=yyyy"));
    try testing.expect(std.mem.endsWith(u8, req, "t\x00\x00\x00\x00"));
    try testing.expectEqual(@as(u32, @intCast(req.len - header_len)), std.mem.readInt(u32, req[6..10], .big));
}

test "an argv that cannot fit is TooLong" {
    const argv = [_:null]?[*:0]const u8{big(max_request)};
    try testing.expectError(error.TooLong, approval(&test_buf, &.{}, null, null, null, @ptrCast(&argv), null));
}

test "a reply head is refused when its kind, length or place is wrong" {
    try testing.expectEqual(Head{ .reply = .yes, .len = 512 }, head(.{ 'Y', 2, 0 }, false).?);
    try testing.expect(head(.{ 'Y', 2, 1 }, false) == null);
    try testing.expect(head(.{ 'W', 0, 4 }, false) == null);
    try testing.expectEqual(Head{ .reply = .password, .len = 1023 }, head(.{ 'W', 3, 0xff }, true).?);
    try testing.expect(head(.{ 'W', 4, 0 }, true) == null);
    try testing.expect(head(.{ 'X', 0, 0 }, true) == null);
    try testing.expect(printable("frisket-sudo: ok ~"));
    try testing.expect(!printable("a\nb"));
}
