//! Remote mode from outside, on a plugin built to take every chain for
//! remote: the check-in, the gate's 'M', a test agent on a socket that
//! answers identities and sign requests, and the 'S' the gate gets.

const std = @import("std");
const minish = @import("minish");
const plugin = @import("plugin");
const c = @import("abi").c;
const agent = @import("agent");
const fd = @import("fd");
const testing = std.testing;

const gate_path = "frisket-sudo-test-remote-gate.sock";
const agent_name = "frisket-sudo-test-agent.sock";

// ---- sudo's side ----

var said: [8]struct { buf: [600]u8, len: usize } = undefined;
var said_n: usize = 0;

fn printf(kind: c_int, noalias fmt: [*c]const u8, ...) callconv(.c) c_int {
    _ = .{ kind, fmt };
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const s = std.mem.span(@cVaArg(&ap, [*:0]const u8));
    if (said_n < said.len) {
        const n = @min(s.len, said[said_n].buf.len);
        @memcpy(said[said_n].buf[0..n], s[0..n]);
        said[said_n].len = n;
        said_n += 1;
    }
    return 0;
}

fn saidLine(i: usize) []const u8 {
    return said[i].buf[0..said[i].len];
}

fn arr(a: anytype) [*c]const [*c]u8 {
    return @ptrCast(a);
}

var strings: [8][256]u8 = undefined;

fn z(i: usize, comptime fmt: []const u8, args: anytype) [*:0]const u8 {
    return std.fmt.bufPrintZ(&strings[i], fmt, args) catch unreachable; // proven: each fits in 256
}

var group_buf: [64]u32 = undefined;
var groups_text: [1024]u8 = undefined;

/// user_info for this process as the invoking user, and its options.
const Me = struct {
    user: [*:0]const u8,
    uid: [*:0]const u8,
    gid: [*:0]const u8,
    groups: [*:0]const u8,
    option: [*:0]const u8,
};

fn me() !Me {
    const n = c.getgroups(group_buf.len, &group_buf);
    try testing.expect(n >= 0);
    var len: usize = 0;
    for (group_buf[0..@intCast(n)], 0..) |g, i| {
        len += (try std.fmt.bufPrint(groups_text[len..], "{s}{d}", .{ if (i > 0) "," else "", g })).len;
    }
    const uid = std.os.linux.getuid();
    return .{
        .user = z(0, "user=tester{d}", .{uid}),
        .uid = z(1, "uid={d}", .{uid}),
        .gid = z(2, "gid={d}", .{std.os.linux.getgid()}),
        .groups = z(3, "groups={s}", .{groups_text[0..len]}),
        .option = z(4, "user=tester{d}", .{uid}),
    };
}

var agent_path_buf: [std.fs.max_path_bytes]u8 = undefined;

fn agentPath() ![]const u8 {
    const dir = try std.fs.cwd().realpath(".", &agent_path_buf);
    const tail = "/" ++ agent_name;
    @memcpy(agent_path_buf[dir.len..][0..tail.len], tail);
    return agent_path_buf[0 .. dir.len + tail.len];
}

fn open(user_info: [*c]const [*c]u8, options: [*c]const [*c]u8, envp: [*c]const [*c]u8) c_int {
    var errstr: [*c]const u8 = null;
    const none = [_:null]?[*:0]const u8{};
    const argv = [_:null]?[*:0]const u8{ "sudo", "id" };
    return plugin.frisket_audit.open.?(c.SUDO_API_VERSION_MAJOR << 16, null, printf, arr(&none), user_info, 1, arr(&argv), envp, options, &errstr);
}

fn accept(errstr: *[*c]const u8) c_int {
    const info = [_:null]?[*:0]const u8{"command=/run/current-system/sw/bin/id"};
    const argv = [_:null]?[*:0]const u8{"id"};
    const envp = [_:null]?[*:0]const u8{"PATH=/run/current-system/sw/bin"};
    return plugin.frisket_audit.accept.?("sudoers", c.SUDO_POLICY_PLUGIN, arr(&info), arr(&argv), arr(&envp), errstr);
}

fn close() void {
    plugin.frisket_audit.close.?(0, 0);
}

// ---- the gate's and the agent's sides ----

fn listen(path: []const u8) !std.posix.socket_t {
    std.posix.unlink(path) catch {};
    const s = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    const addr = try std.net.Address.initUnix(path);
    try std.posix.bind(s, &addr.any, addr.getOsSockLen());
    try std.posix.listen(s, 1);
    return s;
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

fn pending(l: std.posix.socket_t) !bool {
    var p = [_]std.posix.pollfd{.{ .fd = l, .events = std.posix.POLL.IN, .revents = 0 }};
    return try std.posix.poll(&p, 0) > 0;
}

/// Answers each request on one connection with the next reply, keeping the
/// kind and body of each.
const Peer = struct {
    listener: std.posix.socket_t,
    path: []const u8,
    replies: []const []const u8,
    /// stream: every reply at once, then EOF, whatever is asked.
    header: enum { gate, agent, stream },
    thread: std.Thread = undefined,
    kinds: [4]u8 = @splat(0),
    bodies: [4][8192]u8 = undefined,
    lens: [4]usize = @splat(0),
    n: usize = 0,

    fn start(p: *Peer) !void {
        p.thread = try std.Thread.spawn(.{}, serve, .{p});
    }

    fn serve(p: *Peer) void {
        const conn = std.posix.accept(p.listener, null, null, std.posix.SOCK.CLOEXEC) catch return;
        defer std.posix.close(conn);
        if (p.header == .stream) {
            for (p.replies) |r| _ = std.posix.write(conn, r) catch return;
            std.posix.shutdown(conn, .send) catch return;
            var b: [256]u8 = undefined;
            while ((std.posix.read(conn, &b) catch 0) > 0) {}
            return;
        }
        for (p.replies, 0..) |r, i| {
            var h: [10]u8 = undefined;
            const hl: usize = if (p.header == .gate) 10 else 4;
            if (readFull(conn, h[0..hl]) != hl) return;
            const len = std.mem.readInt(u32, h[hl - 4 ..][0..4], .big);
            if (len > p.bodies[i].len or readFull(conn, p.bodies[i][0..len]) != len) return;
            p.kinds[i] = if (p.header == .gate) h[5] else p.bodies[i][0];
            p.lens[i] = len;
            p.n = i + 1;
            _ = std.posix.write(conn, r) catch return;
        }
        if (p.header == .agent) return;
        var b: [1]u8 = undefined;
        while ((std.posix.read(conn, &b) catch 0) > 0) {}
    }

    fn body(p: *const Peer, i: usize) []const u8 {
        return p.bodies[i][0..p.lens[i]];
    }

    fn stop(p: *Peer) void {
        p.thread.join();
        std.posix.close(p.listener);
        std.posix.unlink(p.path) catch {};
    }
};

const Wire = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    fn bytes(w: *Wire, b: []const u8) void {
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }

    fn int(w: *Wire, v: u32) void {
        std.mem.writeInt(u32, w.buf[w.len..][0..4], v, .big);
        w.len += 4;
    }

    fn string(w: *Wire, b: []const u8) void {
        w.int(@intCast(b.len));
        w.bytes(b);
    }

    fn out(w: *const Wire) []const u8 {
        return w.buf[0..w.len];
    }
};

const message = "\x00\x00\x00\x0ffrisket-sudo-v1 and the rest";

/// The gate's 'M' with `keys`.
fn mReply(w: *Wire, keys: []const []const u8) []const u8 {
    w.bytes("M");
    w.int(0);
    w.string(message);
    w.int(@intCast(keys.len));
    for (keys) |k| w.string(k);
    std.mem.writeInt(u32, w.buf[1..5], @intCast(w.len - 5), .big);
    return w.out();
}

/// An agent frame of `kind` and strings; an identities answer counts its
/// key and comment pairs first.
fn agentFrame(w: *Wire, kind: u8, parts: []const []const u8) []const u8 {
    w.int(0);
    w.bytes(&.{kind});
    if (kind == 12) w.int(@intCast(parts.len / 2));
    for (parts) |p| w.string(p);
    std.mem.writeInt(u32, w.buf[0..4], @intCast(w.len - 4), .big);
    return w.out();
}

const signature = "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x03sig";

fn identities(w: *Wire) []const u8 {
    return agentFrame(w, 12, &.{ "key-a", "unlisted", "key-c", "listed second", "key-b", "listed first" });
}

fn signResponse(w: *Wire) []const u8 {
    return agentFrame(w, 14, &.{signature});
}

const Ids = struct {
    uid: [3]c.uid_t = undefined,
    gid: [3]c.gid_t = undefined,
    groups: [64]c.gid_t = undefined,
    n: c_int = 0,

    fn now() Ids {
        var i: Ids = .{};
        _ = c.getresuid(&i.uid[0], &i.uid[1], &i.uid[2]);
        _ = c.getresgid(&i.gid[0], &i.gid[1], &i.gid[2]);
        i.n = c.getgroups(i.groups.len, &i.groups);
        return i;
    }

    fn expectEqual(a: Ids, b: Ids) !void {
        try testing.expectEqual(a.uid, b.uid);
        try testing.expectEqual(a.gid, b.gid);
        try testing.expectEqualSlices(c.gid_t, a.groups[0..@intCast(a.n)], b.groups[0..@intCast(b.n)]);
    }
};

fn openFds(buf: *[64]i32) ![]i32 {
    var dir = try std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true });
    defer dir.close();
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |e| {
        const v = try std.fmt.parseInt(i32, e.name, 10);
        if (v == dir.fd) continue;
        buf[n] = v;
        n += 1;
    }
    std.mem.sort(i32, buf[0..n], {}, std.sort.asc(i32));
    return buf[0..n];
}

const Run = struct { rc: c_int, gate: *Peer, agent: ?*Peer, errstr: [*c]const u8 };

var gate_peer: Peer = undefined;
var agent_peer: Peer = undefined;

/// open(), accept() and close() of a remote sudo against a gate and, unless
/// `agent_replies` is null, an agent.
fn run(gate_replies: []const []const u8, agent_replies: ?[]const []const u8, groups: ?[*:0]const u8) !Run {
    gate_peer = .{ .listener = try listen(gate_path), .path = gate_path, .replies = gate_replies, .header = .gate };
    try gate_peer.start();
    const path = try agentPath();
    var with_agent: ?*Peer = null;
    if (agent_replies) |r| {
        agent_peer = .{ .listener = try listen(path), .path = path, .replies = r, .header = .agent };
        try agent_peer.start();
        with_agent = &agent_peer;
    }
    const m = try me();
    const ui = [_:null]?[*:0]const u8{ m.user, m.uid, m.gid, groups orelse m.groups };
    const opts = [_:null]?[*:0]const u8{ m.option, "remote" };
    const envp = [_:null]?[*:0]const u8{ "HOME=/", z(5, "SSH_AUTH_SOCK={s}", .{path}) };
    said_n = 0;
    try testing.expectEqual(@as(c_int, 1), open(arr(&ui), arr(&opts), arr(&envp)));
    var errstr: [*c]const u8 = null;
    const rc = accept(&errstr);
    close();
    gate_peer.stop();
    if (with_agent) |a| a.stop();
    return .{ .rc = rc, .gate = &gate_peer, .agent = with_agent, .errstr = errstr };
}

test "a remote sudo checks in with 'm', the first listed identity signs the gate's message, and it is allowed with sudo's ids as they were" {
    var fds_buf: [64]i32 = undefined;
    const fds = try openFds(&fds_buf);
    const before = Ids.now();
    var mw: Wire = .{};
    var iw: Wire = .{};
    var sw: Wire = .{};
    const r = try run(&.{ "Y\x00\x00", mReply(&mw, &.{ "key-b", "key-c" }), "Y\x00\x00" }, &.{ identities(&iw), signResponse(&sw) }, null);
    try testing.expectEqual(@as(c_int, 1), r.rc);
    try testing.expectEqualSlices(u8, "CAS", r.gate.kinds[0..3]);
    try testing.expectEqualSlices(u8, "m\x00\x00\x00\x00", r.gate.body(0));
    try testing.expect(std.mem.endsWith(u8, r.gate.body(1), "m\x00\x00\x00\x00"));
    var s: Wire = .{};
    s.bytes("p");
    s.string("key-c");
    s.bytes("g");
    s.string(signature);
    try testing.expectEqualSlices(u8, s.out(), r.gate.body(2));
    const a = r.agent.?;
    try testing.expectEqualSlices(u8, &.{11}, a.body(0));
    var want: Wire = .{};
    want.bytes(&.{13});
    want.string("key-c");
    want.string(message);
    want.int(0);
    try testing.expectEqualSlices(u8, want.out(), a.body(1));
    try testing.expectEqual(@as(usize, 0), said_n);
    try Ids.now().expectEqual(before);
    var after_buf: [64]i32 = undefined;
    try testing.expectEqualSlices(i32, fds, try openFds(&after_buf));
}

test "an agent that refuses, fails, hangs up or has no listed key, or no agent at all, is an 'f' and the gate's no refuses" {
    var iw: Wire = .{};
    const ids = identities(&iw);
    var uw: Wire = .{};
    const unlisted = agentFrame(&uw, 12, &.{ "key-a", "" });
    const cases = [_]struct { agent: ?[]const []const u8, why: []const u8 }{
        .{ .agent = &.{ ids, "\x00\x00\x00\x01\x05" }, .why = "the forwarded agent refused" },
        .{ .agent = &.{"\x00\x00\x00\x01\x05"}, .why = "the forwarded agent failed" },
        .{ .agent = &.{}, .why = "the forwarded agent hung up" },
        .{ .agent = &.{ids}, .why = "the forwarded agent hung up" },
        .{ .agent = &.{unlisted}, .why = "no listed key in the forwarded agent" },
        .{ .agent = null, .why = "cannot connect to the forwarded agent" },
    };
    for (cases) |cs| {
        var mw: Wire = .{};
        const r = try run(&.{ "Y\x00\x00", mReply(&mw, &.{ "key-b", "key-c" }), "N\x00\x0dfrisket-sudo." }, cs.agent, null);
        try testing.expectEqual(@as(c_int, 0), r.rc);
        try testing.expectEqualSlices(u8, "CAS", r.gate.kinds[0..3]);
        var want: Wire = .{};
        want.bytes("f");
        want.string(cs.why);
        try testing.expectEqualSlices(u8, want.out(), r.gate.body(2));
        try testing.expectEqualStrings("frisket-sudo.", saidLine(0));
    }
}

test "a no to the remote 'A' refuses with its message, and a yes, a password or a bad 'M' is no answer" {
    var mw: Wire = .{};
    const r = try run(&.{ "Y\x00\x00", "N\x00\x1fremote sudo is off on this host" }, null, null);
    try testing.expectEqual(@as(c_int, 0), r.rc);
    try testing.expectEqualStrings("remote sudo is off on this host", saidLine(0));
    for ([_][]const u8{ "Y\x00\x00", "W\x00\x02pw", mReply(&mw, &.{}), "M\x00\x00\x00\x02ab" }) |reply| {
        const x = try run(&.{ "Y\x00\x00", reply }, null, null);
        try testing.expectEqual(@as(c_int, 0), x.rc);
        try testing.expectEqualStrings("no answer from gate", std.mem.span(x.errstr));
        try testing.expectEqual(@as(usize, 2), x.gate.n);
    }
}

test "a yes or garbage after the 'S' is the gate's answer" {
    var mw: Wire = .{};
    var iw: Wire = .{};
    var sw: Wire = .{};
    const r = try run(&.{ "Y\x00\x00", mReply(&mw, &.{"key-b"}), "Y\x00\x03ok." }, &.{ identities(&iw), signResponse(&sw) }, null);
    try testing.expectEqual(@as(c_int, 1), r.rc);
    try testing.expectEqualStrings("ok.", saidLine(0));
    var mw2: Wire = .{};
    var iw2: Wire = .{};
    var sw2: Wire = .{};
    const g = try run(&.{ "Y\x00\x00", mReply(&mw2, &.{"key-b"}), "W\x00\x02pw" }, &.{ identities(&iw2), signResponse(&sw2) }, null);
    try testing.expectEqual(@as(c_int, 0), g.rc);
    try testing.expectEqualStrings("no answer from gate", std.mem.span(g.errstr));
}

test "a drop that fails refuses before the agent is asked" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    var mw: Wire = .{};
    const r = try run(&.{ "Y\x00\x00", mReply(&mw, &.{"key-b"}) }, null, z(6, "groups={d}", .{std.os.linux.getgid() +% 12345}));
    try testing.expectEqual(@as(c_int, 0), r.rc);
    try testing.expectEqualStrings("cannot drop to the invoking user", std.mem.span(r.errstr));
    try testing.expectEqual(@as(usize, 2), r.gate.n);
}

test "no SSH_AUTH_SOCK, a relative, empty or over-long one, no remote option or a tty is stock: no check-in, accepted" {
    const m = try me();
    const path = try agentPath();
    const good = z(5, "SSH_AUTH_SOCK={s}", .{path});
    var long_buf: [140]u8 = undefined;
    @memset(&long_buf, 'x');
    @memcpy(long_buf[0.."SSH_AUTH_SOCK=/".len], "SSH_AUTH_SOCK=/");
    long_buf[long_buf.len - 1] = 0;
    const long: [*:0]const u8 = long_buf[0 .. long_buf.len - 1 :0];
    const plain = [_:null]?[*:0]const u8{ m.user, m.uid, m.gid, m.groups };
    const tty = [_:null]?[*:0]const u8{ m.user, m.uid, m.gid, m.groups, "tty=/dev/pts/0" };
    const remote = [_:null]?[*:0]const u8{ m.option, "remote" };
    const local = [_:null]?[*:0]const u8{m.option};
    const cases = [_]struct { ui: [*c]const [*c]u8, opts: [*c]const [*c]u8, env: ?[*:0]const u8 }{
        .{ .ui = arr(&plain), .opts = arr(&remote), .env = null },
        .{ .ui = arr(&plain), .opts = arr(&remote), .env = "SSH_AUTH_SOCK=agent.sock" },
        .{ .ui = arr(&plain), .opts = arr(&remote), .env = "SSH_AUTH_SOCK=" },
        .{ .ui = arr(&plain), .opts = arr(&remote), .env = long },
        .{ .ui = arr(&plain), .opts = arr(&local), .env = good },
        .{ .ui = arr(&tty), .opts = arr(&remote), .env = good },
    };
    const l = try listen(gate_path);
    defer {
        std.posix.close(l);
        std.posix.unlink(gate_path) catch {};
    }
    for (cases) |cs| {
        const envp = [_:null]?[*:0]const u8{ "HOME=/", cs.env };
        said_n = 0;
        try testing.expectEqual(@as(c_int, 1), open(cs.ui, cs.opts, arr(&envp)));
        var errstr: [*c]const u8 = null;
        try testing.expectEqual(@as(c_int, 1), accept(&errstr));
        close();
        try testing.expect(!try pending(l));
        try testing.expectEqual(@as(usize, 0), said_n);
    }
}

test "a remote sudo with the gate down is stock, printing nothing" {
    std.posix.unlink(gate_path) catch {};
    const m = try me();
    const ui = [_:null]?[*:0]const u8{ m.user, m.uid, m.gid, m.groups };
    const opts = [_:null]?[*:0]const u8{ m.option, "remote" };
    const envp = [_:null]?[*:0]const u8{z(5, "SSH_AUTH_SOCK={s}", .{try agentPath()})};
    said_n = 0;
    try testing.expectEqual(@as(c_int, 1), open(arr(&ui), arr(&opts), arr(&envp)));
    var errstr: [*c]const u8 = null;
    try testing.expectEqual(@as(c_int, 1), accept(&errstr));
    close();
    try testing.expectEqual(@as(usize, 0), said_n);
}

test "property: open() returns 1 and never panics on a remote chain, whatever it is given" {
    std.posix.unlink(gate_path) catch {};
    try minish.check(testing.allocator, minish.gen.list(u8, minish.gen.int(u8), 0, 24), openAnything, .{ .num_runs = 2_000, .seed = 0x5d1 });
}

var env_buf: [300]u8 = undefined;

fn openAnything(script: []const u8) !void {
    const m = try me();
    const at = struct {
        fn f(s: []const u8, i: usize) u8 {
            return if (s.len > i) s[i] else 0;
        }
    }.f;
    const users = [_]?[*:0]const u8{ m.user, "user=root", "user=", null };
    const options = [_]?[*:0]const u8{ m.option, "remote", "remote=1", "user", null };
    const a = at(script, 0);
    const b = at(script, 1);
    const tail = if (script.len > 2) script[2..] else "";
    const n = @min(tail.len, env_buf.len - "SSH_AUTH_SOCK=".len - 1);
    @memcpy(env_buf[0.."SSH_AUTH_SOCK=".len], "SSH_AUTH_SOCK=");
    for (tail[0..n], 0..) |ch, i| env_buf["SSH_AUTH_SOCK=".len + i] = if (ch == 0) '/' else ch;
    env_buf["SSH_AUTH_SOCK=".len + n] = 0;
    const env: [*:0]const u8 = env_buf[0 .. "SSH_AUTH_SOCK=".len + n :0];
    var ui = [_:null]?[*:0]const u8{ users[a % users.len], m.uid, if (a & 4 != 0) "tty=/dev/pts/0" else m.gid, if (a & 8 != 0) null else m.groups };
    if (ui[0] == null) ui[0] = m.uid;
    const opts = [_:null]?[*:0]const u8{ options[b % options.len], options[(b >> 3) % options.len] };
    const envp = [_:null]?[*:0]const u8{ if (b & 0x40 != 0) env else "HOME=/", null };
    try testing.expectEqual(@as(c_int, 1), open(arr(&ui), arr(&opts), arr(&envp)));
    close();
}

// ---- the agent client on any reply ----

var frame_buf: [agent.max_frame]u8 = undefined;
var replies_buf: [2]Wire = undefined;

/// Two agent replies from a script: raw bytes, or an identities answer and
/// a sign response built from it, each maybe cut short or with a byte
/// changed.
fn agentReplies(script: []const u8) [2][]const u8 {
    const at = struct {
        fn f(s: []const u8, i: usize) u8 {
            return if (s.len > i) s[i] else 0;
        }
    }.f;
    const mode = at(script, 0);
    const rest = if (script.len > 1) script[1..] else "";
    var out: [2][]const u8 = undefined;
    for (&replies_buf, 0..) |*w, i| {
        w.* = .{};
        if (mode & 1 == 0) {
            const half = rest.len / 2;
            w.bytes(if (i == 0) rest[0..half] else rest[half..]);
        } else if (i == 0) {
            const pool = [_][]const u8{ "key-a", "key-b", "key-c", "" };
            var parts: [8][]const u8 = undefined;
            const n: usize = @min(rest.len, 4);
            for (rest[0..n], 0..) |ch, j| {
                parts[2 * j] = pool[ch % pool.len];
                parts[2 * j + 1] = "comment";
            }
            _ = agentFrame(w, if (mode & 2 == 0) 12 else at(script, 2), parts[0 .. 2 * n]);
        } else {
            _ = agentFrame(w, if (mode & 4 == 0) 14 else 5, if (mode & 8 == 0) &.{signature} else &.{rest});
        }
        if (mode & 0x30 == 0x10 and w.len > 0) w.len -= 1 + @as(usize, at(script, 3)) % w.len;
        if (mode & 0x30 == 0x20 and w.len > 0) w.buf[at(script, 4) % w.len] ^= at(script, 5) | 1;
        out[i] = w.out();
    }
    return out;
}

fn signsOrSaysWhy(script: []const u8) !void {
    const replies = agentReplies(script);
    const path = try agentPath();
    agent_peer = .{ .listener = try listen(path), .path = path, .replies = &replies, .header = .stream };
    try agent_peer.start();
    defer agent_peer.stop();
    const s = try fd.connectUnix(path, null);
    defer s.close();
    var kw: Wire = .{};
    kw.int(2);
    kw.string("key-b");
    kw.string("key-c");
    switch (agent.sign(s, kw.out(), message, &frame_buf)) {
        .signed => |x| {
            try testing.expect(std.mem.eql(u8, x.key, "key-b") or std.mem.eql(u8, x.key, "key-c"));
            try testing.expect(x.signature.len >= 8);
        },
        .failed => |why| {
            try testing.expect(why.len > 0 and why.len <= 512);
            for (why) |ch| try testing.expect(ch >= 0x20 and ch <= 0x7e);
        },
    }
}

test "property: any agent replies give a signature by a listed key or a reason, never a panic" {
    try minish.check(testing.allocator, minish.gen.list(u8, minish.gen.int(u8), 0, 40), signsOrSaysWhy, .{ .num_runs = 1_000, .seed = 0xa6e });
}
