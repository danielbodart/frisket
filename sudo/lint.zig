//! lint: flong's fdlint (tools/fdlint.zig) with the rules frisket-sudo
//! takes, over Zig's own tokens, so comments and strings never match.
//!
//!   lint [--skip DIR]... PATH...
//!
//! Prints "NAME:LINE:COL: RULE: why" per finding and exits 1 when there is
//! any. A name is the path relative to the package root.
//!
//!   extern             extern fn, var or const, extern "lib", @extern,
//!                      @cImport. Not in abi.zig
//!   export             export. Not in frisket_sudo.zig, planted_type.zig
//!   raw-number         .raw, a descriptor's number. Not in fd.zig,
//!                      *_test.zig
//!   handle-guts        .slot, .gen: a handle's fields. Not in fd.zig,
//!                      *_test.zig
//!   catch-unreachable  catch unreachable, unless its line says
//!                      `// proven: ` and why
//!   alloc              GeneralPurposeAllocator, DebugAllocator. Not in
//!                      *_test.zig

const std = @import("std");
const Tag = std.zig.Token.Tag;

const Rule = enum {
    @"extern",
    @"export",
    @"raw-number",
    @"handle-guts",
    @"catch-unreachable",
    alloc,

    fn why(r: Rule) []const u8 {
        return switch (r) {
            .@"extern" => "C headers and symbols belong in abi.zig",
            .@"export" => "the plugin's one export is frisket_audit, in frisket_sudo.zig",
            .@"raw-number" => "a descriptor's number never leaves fd.zig",
            .@"handle-guts" => "a handle's fields are fd.zig's",
            .@"catch-unreachable" => "say why it cannot happen: `// proven: <why>` on the line",
            .alloc => "no general-purpose allocator",
        };
    }
};

fn applies(rule: Rule, name: []const u8) bool {
    const base = std.fs.path.basename(name);
    return switch (rule) {
        .@"extern" => !std.mem.eql(u8, base, "abi.zig"),
        .@"export" => !std.mem.eql(u8, base, "frisket_sudo.zig") and !std.mem.eql(u8, base, "planted_type.zig"),
        .@"raw-number", .@"handle-guts" => !std.mem.eql(u8, base, "fd.zig") and !std.mem.endsWith(u8, base, "_test.zig"),
        .@"catch-unreachable" => true,
        .alloc => !std.mem.endsWith(u8, base, "_test.zig"),
    };
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const args = try std.process.argsAlloc(a);

    var skips: std.ArrayList([]const u8) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--skip") and i + 1 < args.len) {
            i += 1;
            try skips.append(a, std.mem.trimRight(u8, args[i], "/"));
            continue;
        }
        const p = std.mem.trimRight(u8, args[i], "/");
        const st = try std.fs.cwd().statFile(p);
        if (st.kind != .directory) {
            try names.append(a, p);
            continue;
        }
        var dir = try std.fs.cwd().openDir(p, .{ .iterate = true });
        defer dir.close();
        var walk = try dir.walk(a);
        defer walk.deinit();
        while (try walk.next()) |e| {
            if (e.kind != .file or !std.mem.endsWith(u8, e.path, ".zig")) continue;
            if (std.mem.startsWith(u8, e.path, ".zig-cache/") or std.mem.startsWith(u8, e.path, "zig-out/")) continue;
            const skipped = for (skips.items) |s| {
                if (std.mem.startsWith(u8, e.path, s) and e.path.len > s.len and e.path[s.len] == '/') break true;
            } else false;
            if (!skipped) try names.append(a, try a.dupe(u8, e.path));
        }
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);

    var out_buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&out_buf);
    const out = &w.interface;
    var findings: usize = 0;
    for (names.items) |name| {
        const src = try std.fs.cwd().readFileAllocOptions(a, name, 16 << 20, null, .of(u8), 0);
        findings += try lint(a, out, name, src);
    }
    try out.flush();
    if (findings > 0) std.process.exit(1);
}

const Tok = struct { tag: Tag, start: usize, text: []const u8 };

fn lint(a: std.mem.Allocator, out: *std.Io.Writer, name: []const u8, src: [:0]const u8) !usize {
    var toks: std.ArrayList(Tok) = .empty;
    var t = std.zig.Tokenizer.init(src);
    while (true) {
        const tok = t.next();
        if (tok.tag == .eof) break;
        try toks.append(a, .{ .tag = tok.tag, .start = tok.loc.start, .text = src[tok.loc.start..tok.loc.end] });
    }
    const ts = toks.items;

    var found: usize = 0;
    for (ts, 0..) |tok, k| {
        const prev: ?Tok = if (k >= 1) ts[k - 1] else null;
        const next: ?Tok = if (k + 1 < ts.len) ts[k + 1] else null;
        const after_period = prev != null and prev.?.tag == .period;

        var rule: ?Rule = null;
        switch (tok.tag) {
            .identifier => {
                const x = tok.text;
                if (after_period and std.mem.eql(u8, x, "raw")) rule = .@"raw-number";
                if (after_period and (std.mem.eql(u8, x, "slot") or std.mem.eql(u8, x, "gen"))) rule = .@"handle-guts";
                if (std.mem.eql(u8, x, "GeneralPurposeAllocator") or std.mem.eql(u8, x, "DebugAllocator")) rule = .alloc;
            },
            .keyword_extern => {
                const typed = next != null and switch (next.?.tag) {
                    .keyword_struct, .keyword_union, .keyword_enum => true,
                    else => false,
                };
                if (!typed) rule = .@"extern";
            },
            .keyword_export => rule = .@"export",
            .builtin => if (std.mem.eql(u8, tok.text, "@extern") or std.mem.eql(u8, tok.text, "@cImport")) {
                rule = .@"extern";
            },
            .keyword_unreachable => if (prev != null and prev.?.tag == .keyword_catch) {
                const line_end = std.mem.indexOfScalarPos(u8, src, tok.start, '\n') orelse src.len;
                if (std.mem.indexOf(u8, src[tok.start..line_end], "// proven: ") == null)
                    rule = .@"catch-unreachable";
            },
            else => {},
        }
        const r = rule orelse continue;
        if (!applies(r, name)) continue;
        const line = std.mem.count(u8, src[0..tok.start], "\n") + 1;
        const col = tok.start - (if (std.mem.lastIndexOfScalar(u8, src[0..tok.start], '\n')) |n| n + 1 else 0) + 1;
        try out.print("{s}:{d}:{d}: {s}: {s}\n", .{ name, line, col, @tagName(r), r.why() });
        found += 1;
    }
    return found;
}
