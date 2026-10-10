//! The plugin from outside, as sudo calls it: the mode parse held to sudo's
//! own parse_args, open() on any input, and a sudo checked in and answered
//! by a gate on a socket of the test's own.

const std = @import("std");
const minish = @import("minish");
const plugin = @import("plugin");
const c = @import("abi").c;
const oracle = @import("oracle");
const testing = std.testing;

const gate_path = "frisket-sudo-test-gate.sock";

// ---- sudo's side ----

var said: [8]struct { kind: c_int, buf: [600]u8, len: usize } = undefined;
var said_n: usize = 0;

fn printf(kind: c_int, noalias fmt: [*c]const u8, ...) callconv(.c) c_int {
    _ = fmt;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const s = std.mem.span(@cVaArg(&ap, [*:0]const u8));
    if (said_n < said.len) {
        const n = @min(s.len, said[said_n].buf.len);
        said[said_n].kind = kind;
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

var name_buf: [64]u8 = undefined;
var uid_buf: [32]u8 = undefined;
var opt_buf: [64]u8 = undefined;

fn me() struct { user: [*:0]const u8, uid: [*:0]const u8, option: [*:0]const u8 } {
    const uid = std.os.linux.getuid();
    const user = std.fmt.bufPrintZ(&name_buf, "user=tester{d}", .{uid}) catch unreachable; // proven: fits in 64
    return .{
        .user = user,
        .uid = std.fmt.bufPrintZ(&uid_buf, "uid={d}", .{uid}) catch unreachable, // proven: fits in 32
        .option = std.fmt.bufPrintZ(&opt_buf, "{s}", .{user}) catch unreachable, // proven: fits in 64
    };
}

fn open(user_info: [*c]const [*c]u8, options: [*c]const [*c]u8, argv: [*c]const [*c]u8, optind: c_int) c_int {
    var errstr: [*c]const u8 = null;
    const none = [_:null]?[*:0]const u8{};
    return plugin.frisket_audit.open.?(c.SUDO_API_VERSION_MAJOR << 16, null, printf, arr(&none), user_info, optind, argv, arr(&none), options, &errstr);
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

// ---- the gate's side ----

const Gate = struct {
    listener: std.posix.socket_t,
    thread: std.Thread = undefined,
    replies: []const []const u8,
    kinds: [4]u8 = @splat(0),
    approval: [4096]u8 = undefined,
    approval_len: usize = 0,

    fn start(g: *Gate) !void {
        g.thread = try std.Thread.spawn(.{}, serve, .{g});
    }

    fn serve(g: *Gate) void {
        const conn = std.posix.accept(g.listener, null, null, std.posix.SOCK.CLOEXEC) catch return;
        defer std.posix.close(conn);
        for (g.replies, 0..) |r, i| {
            var h: [10]u8 = undefined;
            if (readFull(conn, &h) != h.len) return;
            g.kinds[i] = h[5];
            const len = std.mem.readInt(u32, h[6..10], .big);
            var left: usize = len;
            while (left > 0) {
                var b: [4096]u8 = undefined;
                const n = readFull(conn, b[0..@min(left, b.len)]);
                if (n == 0) return;
                if (h[5] == 'A' and g.approval_len == 0) {
                    @memcpy(g.approval[0..n], b[0..n]);
                    g.approval_len = n;
                }
                left -= n;
            }
            _ = std.posix.write(conn, r) catch return;
        }
        std.posix.shutdown(conn, .send) catch {};
        var b: [1]u8 = undefined;
        while ((std.posix.read(conn, &b) catch 0) > 0) {}
    }

    fn readFull(fd: std.posix.socket_t, buf: []u8) usize {
        var done: usize = 0;
        while (done < buf.len) {
            const n = std.posix.read(fd, buf[done..]) catch return done;
            if (n == 0) return done;
            done += n;
        }
        return done;
    }

    fn stop(g: *Gate) void {
        g.thread.join();
        std.posix.close(g.listener);
        std.posix.unlink(gate_path) catch {};
    }
};

fn listen() !std.posix.socket_t {
    std.posix.unlink(gate_path) catch {};
    const s = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    const addr = try std.net.Address.initUnix(gate_path);
    try std.posix.bind(s, &addr.any, addr.getOsSockLen());
    try std.posix.listen(s, 1);
    return s;
}

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

fn runGated(replies: []const []const u8, errstr: *[*c]const u8) !struct { rc: c_int, gate: Gate } {
    var g: Gate = .{ .listener = try listen(), .replies = replies };
    try g.start();
    const m = me();
    const ui = [_:null]?[*:0]const u8{ m.user, m.uid, "pid=1" };
    const opts = [_:null]?[*:0]const u8{m.option};
    const argv = [_:null]?[*:0]const u8{ "sudo", "id" };
    said_n = 0;
    try testing.expectEqual(@as(c_int, 1), open(arr(&ui), arr(&opts), arr(&argv), 1));
    const rc = accept(errstr);
    close();
    g.stop();
    return .{ .rc = rc, .gate = g };
}

test "a gated sudo checks in, is allowed, and leaves no descriptor open after close()" {
    var before_buf: [64]i32 = undefined;
    const before = try openFds(&before_buf);
    var errstr: [*c]const u8 = null;
    const r = try runGated(&.{ "Y\x00\x00", "Y\x00\x0bfine by me." }, &errstr);
    try testing.expectEqual(@as(c_int, 1), r.rc);
    try testing.expectEqualSlices(u8, "CA", r.gate.kinds[0..2]);
    try testing.expectEqual(@as(u8, 'k'), r.gate.approval[0]);
    try testing.expect(std.mem.indexOf(u8, r.gate.approval[0..r.gate.approval_len], "command=/run/current-system/sw/bin/id") != null);
    try testing.expectEqual(@as(usize, 1), said_n);
    try testing.expectEqual(@as(c_int, c.SUDO_CONV_INFO_MSG), said[0].kind);
    try testing.expectEqualStrings("fine by me.", saidLine(0));
    var after_buf: [64]i32 = undefined;
    try testing.expectEqualSlices(i32, before, try openFds(&after_buf));
}

test "a refusal prints the gate's message and refuses" {
    var errstr: [*c]const u8 = null;
    const r = try runGated(&.{ "Y\x00\x00", "N\x00\x09cancelled" }, &errstr);
    try testing.expectEqual(@as(c_int, 0), r.rc);
    try testing.expectEqual(@as(c_int, c.SUDO_CONV_ERROR_MSG), said[0].kind);
    try testing.expectEqualStrings("cancelled", saidLine(0));
}

test "garbage, a message that is not printable and a password to 'C' are no answer" {
    for ([_][]const []const u8{
        &.{ "Y\x00\x00", "Q\x00\x00" },
        &.{ "Y\x00\x00", "Y\x00\x02a\n" },
        &.{ "Y\x00\x00", "Y\x00\x05ab" },
    }) |replies| {
        var errstr: [*c]const u8 = null;
        const r = try runGated(replies, &errstr);
        try testing.expectEqual(@as(c_int, 0), r.rc);
        try testing.expectEqualStrings("no answer from gate", std.mem.span(errstr));
    }
    var errstr: [*c]const u8 = null;
    const r = try runGated(&.{"W\x00\x02pw"}, &errstr);
    try testing.expectEqual(@as(c_int, 0), r.rc);
    try testing.expectEqualStrings("gate not running", std.mem.span(errstr));
    try testing.expectEqualStrings("frisket-sudo: gate not running (systemctl status frisket-sudo.socket); sudo in a terminal is not gated", saidLine(0));
}

test "an accept on behalf of sudo's front end, after the policy's, passes" {
    var errstr: [*c]const u8 = null;
    const info = [_:null]?[*:0]const u8{"command=/run/current-system/sw/bin/id"};
    try testing.expectEqual(@as(c_int, 1), plugin.frisket_audit.accept.?("sudo", c.SUDO_FRONT_END, arr(&info), arr(&info), arr(&info), &errstr));
}

// ---- open() on any input ----

fn openNeverPanics(script: []const u8) !void {
    const m = me();
    const users = [_]?[*:0]const u8{ m.user, "user=root", "user=", null };
    const options = [_]?[*:0]const u8{ m.option, "user=root", "user", null };
    var argv_buf: [64]?[*:0]const u8 = undefined;
    var words: Words = .{};
    const argv = decode(script, &words, &argv_buf, "sudo");
    const pick = if (script.len > 0) script[0] else 0;
    var ui = [_:null]?[*:0]const u8{ users[pick % users.len], m.uid, if (pick & 4 != 0) "tty=/dev/pts/0" else null, null };
    if (ui[0] == null) ui[0] = m.uid;
    const opts = [_:null]?[*:0]const u8{ options[(pick >> 3) % options.len], null };
    try testing.expectEqual(@as(c_int, 1), open(arr(&ui), arr(&opts), @ptrCast(argv.ptr), @intCast(@min(argv.len, (pick >> 5) + 1))));
    close();
}

test "property: open() returns 1 and never panics, whatever it is given" {
    std.posix.unlink(gate_path) catch {};
    try minish.check(testing.allocator, minish.gen.list(u8, minish.gen.int(u8), 0, 24), openNeverPanics, .{ .num_runs = 2_000, .seed = 0x5d0 });
}

// ---- the mode parse against sudo's parse_args ----

/// Words, and runs of words split at spaces, from sudo's options and the
/// ways an argument or an assignment can sit among them.
const vocab = [_][]const u8{
    "-v",
    "-l",
    "--",
    "-",
    "-gwheel",
    "-g",
    "wheel",
    "-u",
    "lp",
    "-nv",
    "-ll",
    "--validate",
    "--vali",
    "--li",
    "--list",
    "--l",
    "--lis=x",
    "--validate=x",
    "FOO=bar",
    "=x",
    "/x=y",
    "-h",
    "host",
    "-hhost",
    "-E",
    "--preserve-env=FOO",
    "--preserve-env",
    "id",
    "-k",
    "-K",
    "-V",
    "-s",
    "-i",
    "-n",
    "-S",
    "-A",
    "-p",
    "-C",
    "3",
    "-U",
    "--user",
    "--user=lp",
    "--host=x",
    "--help",
    "--host",
    "--non",
    "--lo",
    "--v",
    "--va",
    "-e",
    "-uv",
    "-hv",
    "-nh",
    "-hl",
    "--=x",
    "-:",
    "-x",
    "-vl",
    "-lu",
    "--list=",
    "-h host",
    "-h FOO=bar",
    "-h -v",
    "-h /x=y",
    "-h =x",
    "-u -v",
    "--user -l",
    "-p -l",
    "-- -v",
    "-hhost -l",
    "FOO=bar -v",
    "-n -h host -l",
};

const letters = "AaBbCcDEeghHiKklNnPpRrSsTtUuVv:x-";

const Words = struct {
    buf: [2048]u8 = undefined,
    len: usize = 0,

    fn add(w: *Words, s: []const u8) ?[*:0]const u8 {
        if (w.len + s.len + 1 > w.buf.len) return null;
        const start = w.len;
        @memcpy(w.buf[start..][0..s.len], s);
        w.buf[start + s.len] = 0;
        w.len += s.len + 1;
        return w.buf[start .. start + s.len :0];
    }
};

/// argv from a script of bytes: argv0, then words from the vocabulary,
/// option clusters, and words of any non-NUL bytes.
fn decode(script: []const u8, words: *Words, out: *[64]?[*:0]const u8, argv0: [*:0]const u8) [:null]?[*:0]const u8 {
    var n: usize = 0;
    out[n] = argv0;
    n += 1;
    var i: usize = 0;
    while (i < script.len and n + 1 < out.len) {
        const b = script[i];
        i += 1;
        var word: [17]u8 = undefined;
        var len: usize = 0;
        if (b < 0xc0) {
            var it = std.mem.splitScalar(u8, vocab[b % vocab.len], ' ');
            while (it.next()) |v| {
                if (n + 1 >= out.len) break;
                out[n] = words.add(v) orelse break;
                n += 1;
            }
            continue;
        } else if (b < 0xf0) {
            word[0] = '-';
            len = 1;
            for (0..1 + (b & 3)) |_| {
                if (i >= script.len) break;
                word[len] = letters[script[i] % letters.len];
                len += 1;
                i += 1;
            }
        } else {
            for (0..(b & 0x0f)) |_| {
                if (i >= script.len) break;
                word[len] = if (script[i] == 0) 1 else script[i];
                len += 1;
                i += 1;
            }
        }
        out[n] = words.add(word[0..len]) orelse break;
        n += 1;
    }
    out[n] = null;
    return out[0..n :null];
}

var names_dir: ?[]const u8 = null;
var names_buf: [std.fs.max_path_bytes]u8 = undefined;
const names = [_][]const u8{ "sudo", "sudoedit", "lt-sudoedit", "lt-", "visudo" };

const Oracle = struct { mode: u32, optind: c_int };

fn ask(argv: [:null]?[*:0]const u8) !?Oracle {
    var args: [64][]const u8 = undefined;
    for (argv, 0..) |a, i| args[i] = std.mem.span(a.?);
    var child = std.process.Child.init(args[0..argv.len], testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    var out: [64 * 1024]u8 = undefined;
    var len: usize = 0;
    while (len < out.len) {
        const n = try child.stdout.?.read(out[len..]);
        if (n == 0) break;
        len += n;
    }
    _ = try child.wait();
    const marker = "\noracle mode=";
    const at = std.mem.lastIndexOf(u8, out[0..len], marker) orelse return null;
    var f = std.mem.tokenizeAny(u8, out[at + marker.len .. len], " \n");
    const mode = try std.fmt.parseInt(u32, f.next() orelse return error.Oracle, 10);
    const rest = f.next() orelse return error.Oracle;
    if (!std.mem.startsWith(u8, rest, "optind=")) return error.Oracle;
    return .{ .mode = mode, .optind = try std.fmt.parseInt(c_int, rest["optind=".len..], 10) };
}

fn agrees(script: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes + 32]u8 = undefined;
    const name = names[if (script.len > 1) script[script.len - 1] % names.len else 0];
    const argv0 = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ names_dir.?, name });
    var argv_buf: [64]?[*:0]const u8 = undefined;
    var words: Words = .{};
    const argv = decode(script, &words, &argv_buf, argv0);
    const o = try ask(argv) orelse return;
    const want = o.mode == 0x4 or o.mode == 0x80 or o.mode == 0x100;
    if (plugin.listOrValidate(@ptrCast(argv.ptr), o.optind) != want) {
        std.debug.print("disagree: oracle mode {x} optind {d} argv", .{ o.mode, o.optind });
        for (argv) |a| std.debug.print(" [{s}]", .{a.?});
        std.debug.print("\n", .{});
        return error.Disagree;
    }
}

test "property: the mode parse says -v or -l exactly when sudo's parse_args does" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for (names) |n| try tmp.dir.symLink(oracle.path, n, .{});
    names_dir = try tmp.dir.realpath(".", &names_buf);
    try minish.check(testing.allocator, minish.gen.list(u8, minish.gen.int(u8), 0, 16), agrees, .{ .num_runs = 10_000, .seed = 0x50d0 });
}

test "the plan's spellings of -v and -l, and options whose argument is v or l" {
    const cases = [_]struct { argv: []const [*:0]const u8, optind: c_int, want: bool }{
        .{ .argv = &.{ "sudo", "-v" }, .optind = 2, .want = true },
        .{ .argv = &.{ "sudo", "-nv" }, .optind = 2, .want = true },
        .{ .argv = &.{ "sudo", "--vali" }, .optind = 2, .want = true },
        .{ .argv = &.{ "sudo", "--li" }, .optind = 2, .want = true },
        .{ .argv = &.{ "sudo", "-l", "id" }, .optind = 2, .want = true },
        .{ .argv = &.{ "sudo", "-gwheel", "id" }, .optind = 2, .want = false },
        .{ .argv = &.{ "sudo", "-u", "lp", "id" }, .optind = 3, .want = false },
        .{ .argv = &.{ "sudo", "-uv", "id" }, .optind = 2, .want = false },
        .{ .argv = &.{ "sudo", "-u", "-v", "id" }, .optind = 3, .want = false },
        .{ .argv = &.{ "sudo", "--", "-v" }, .optind = 2, .want = false },
        .{ .argv = &.{ "sudoedit", "-v" }, .optind = 2, .want = false },
    };
    for (cases) |cs| {
        var argv: [8:null]?[*:0]const u8 = @splat(null);
        for (cs.argv, 0..) |a, i| argv[i] = a;
        try testing.expectEqual(cs.want, plugin.listOrValidate(@ptrCast(&argv), cs.optind));
    }
}
