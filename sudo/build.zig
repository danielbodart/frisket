//! frisket-sudo's Zig: install, test, lint, fmt and analyze steps.
const std = @import("std");

const gate_path = "/run/frisket-sudo/gate.sock";
const gate_uid = 0;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    const dev = b.option(bool, "dev", "Enable the steps that need lazy dependencies: test, analyze") orelse false;
    const sudo_version = b.option([]const u8, "sudo-version", "The sudo version the plugin is built for");
    const misread = b.option(bool, "misread-mode", "Build a plugin whose mode test always says -v") orelse false;
    const oracle = b.option([]const u8, "oracle", "sudo's parse_args built as a test oracle (sudo/oracle)");

    const install = b.getInstallStep();
    if (sudo_version) |v| {
        const cfg = config(b, gate_path, gate_uid, if (misread) .misread else .stock, v);
        const lib = plugin(b, target, optimize, modules(b, target, optimize), cfg, true);
        install.dependOn(&b.addInstallFileWithDir(lib.getEmittedBin(), .lib, "frisket_sudo.so").step);
        b.installArtifact(pamHelper(b, target, optimize, cfg, true));
        b.installArtifact(checkPlugin(b, target, optimize, cfg, true));
    } else {
        install.dependOn(&b.addFail("install needs -Dsudo-version=VERSION, the sudo the plugin is built for").step);
    }

    const test_step = b.step("test", "Run the unit and property tests");
    if (!dev) {
        test_step.dependOn(&b.addFail("needs -Ddev=true").step);
    } else if (oracle == null) {
        test_step.dependOn(&b.addFail("needs -Doracle=PATH, sudo's parse_args built as a test oracle").step);
    } else if (b.lazyDependency("minish", .{ .target = target, .optimize = optimize })) |minish| {
        const uid = std.os.linux.getuid();
        const cfg = config(b, "frisket-sudo-test-gate.sock", uid, .stock, "test");
        for ([_][]const u8{ "fd", "wire", "chain", "agent", "ids" }) |name| {
            const m = modules(b, target, optimize);
            const t = b.addTest(.{ .name = name, .root_module = m.get(name) });
            test_step.dependOn(&b.addRunArtifact(t).step);
        }
        const pam_cfg = config(b, "frisket-sudo-test-pam.sock", uid, .stock, "test");
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "pam", .root_module = pamHelper(b, target, optimize, pam_cfg, false).root_module })).step);

        const opts = b.addOptions();
        opts.addOption([]const u8, "path", oracle.?);
        const pm = modules(b, target, optimize);
        const pt = b.addTest(.{
            .name = "plugin",
            .root_module = b.createModule(.{
                .root_source_file = b.path("plugin_test.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "minish", .module = minish.module("minish") },
                    .{ .name = "plugin", .module = plugin(b, target, optimize, pm, cfg, false).root_module },
                    .{ .name = "abi", .module = pm.abi },
                    .{ .name = "oracle", .module = opts.createModule() },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(pt).step);

        const misread_cfg = config(b, "frisket-sudo-test-gate.sock", uid, .misread, "test");
        const mm = modules(b, target, optimize);
        const mt = b.addTest(.{
            .name = "misread",
            .root_module = b.createModule(.{
                .root_source_file = b.path("misread_test.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "plugin", .module = plugin(b, target, optimize, mm, misread_cfg, false).root_module },
                    .{ .name = "abi", .module = mm.abi },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(mt).step);

        const remote_cfg = config(b, "frisket-sudo-test-remote-gate.sock", uid, .remote, "test");
        const rm = modules(b, target, optimize);
        const rt = b.addTest(.{
            .name = "remote",
            .root_module = b.createModule(.{
                .root_source_file = b.path("remote_test.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "minish", .module = minish.module("minish") },
                    .{ .name = "plugin", .module = plugin(b, target, optimize, rm, remote_cfg, false).root_module },
                    .{ .name = "abi", .module = rm.abi },
                    .{ .name = "agent", .module = rm.agent },
                    .{ .name = "fd", .module = rm.fd },
                },
            }),
        });
        test_step.dependOn(&b.addRunArtifact(rt).step);

        checkPluginCases(b, target, optimize, test_step);
    }

    const lint_step = b.step("lint", "Run lint.zig over the package");
    {
        const lint = b.addExecutable(.{
            .name = "lint",
            .root_module = b.createModule(.{ .root_source_file = b.path("lint.zig"), .target = b.graph.host }),
        });
        const run = b.addRunArtifact(lint);
        run.setCwd(b.path("."));
        run.has_side_effects = true;
        run.stdio = .inherit;
        run.addArgs(&.{ "--skip", "analyze", "." });
        lint_step.dependOn(&run.step);
    }

    const fmt_step = b.step("fmt", "Check the formatting of the package's Zig");
    fmt_step.dependOn(&b.addFmt(.{ .check = true, .paths = &.{"."} }).step);

    const analyze_step = b.step("analyze", "Run zwanzig over the package, and check it still catches the planted bugs");
    if (!dev) {
        analyze_step.dependOn(&b.addFail("needs -Ddev=true").step);
    } else if (b.lazyDependency("zwanzig", .{ .target = b.graph.host, .optimize = .ReleaseFast })) |zw| {
        const exe = zw.artifact("zwanzig");
        for ([_][]const u8{ "fd.zig", "wire.zig", "chain.zig", "agent.zig", "ids.zig", "frisket_sudo.zig", "frisket-sudo-pam.zig", "frisket-sudo-check-plugin.zig" }) |file| {
            const run = b.addRunArtifact(exe);
            run.addArg("--config");
            run.addFileArg(b.path(".zwanzig.json"));
            run.addFileArg(b.path(file));
            run.has_side_effects = true;
            run.stdio = .inherit;
            analyze_step.dependOn(&run.step);
        }
        const run = b.addRunArtifact(exe);
        run.addArg("--config");
        run.addFileArg(b.path(".zwanzig.json"));
        run.addFileArg(b.path("analyze/bugs.zig"));
        for ([_][]const u8{
            "bugs.zig:10:12: error: [store-violations-engine] double-close",
            "bugs.zig:17:9: error: [store-violations-engine] use after close",
            "bugs.zig:24:12: error: [store-violations-engine] use after close",
        }) |want| run.addCheck(.{ .expect_stdout_match = want });
        run.addCheck(.{ .expect_stdout_match = "Found 3 issue(s):\n" });
        run.addCheck(.{ .expect_term = .{ .Exited = 1 } });
        analyze_step.dependOn(&run.step);
    }
}

/// A test build's misread mode test always says -v; its remote one takes
/// every chain for remote.
const Build = enum { stock, misread, remote };

fn config(b: *std.Build, path: []const u8, uid: u32, kind: Build, sudo_version: []const u8) *std.Build.Module {
    const opts = b.addOptions();
    opts.addOption([]const u8, "gate_path", path);
    opts.addOption(u32, "gate_uid", uid);
    opts.addOption(bool, "misread_mode", kind == .misread);
    opts.addOption(bool, "force_remote", kind == .remote);
    opts.addOption([]const u8, "sudo_version", sudo_version);
    return opts.createModule();
}

const Modules = struct {
    abi: *std.Build.Module,
    fd: *std.Build.Module,
    wire: *std.Build.Module,
    chain: *std.Build.Module,
    agent: *std.Build.Module,
    ids: *std.Build.Module,

    fn get(m: Modules, name: []const u8) *std.Build.Module {
        inline for (@typeInfo(Modules).@"struct".fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return @field(m, f.name);
        }
        unreachable;
    }
};

fn modules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Modules {
    const abi = b.createModule(.{ .root_source_file = b.path("abi.zig"), .target = target, .optimize = optimize, .link_libc = true });
    // A system library is what makes zig read NIX_CFLAGS_COMPILE's include
    // paths for the @cImport.
    abi.linkSystemLibrary("pam", .{});
    const fd = b.createModule(.{ .root_source_file = b.path("fd.zig"), .target = target, .optimize = optimize });
    const chain = b.createModule(.{
        .root_source_file = b.path("chain.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "fd", .module = fd }},
    });
    const agent = b.createModule(.{
        .root_source_file = b.path("agent.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "fd", .module = fd }},
    });
    const wire = b.createModule(.{
        .root_source_file = b.path("wire.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "chain", .module = chain }, .{ .name = "agent", .module = agent } },
    });
    const ids = b.createModule(.{
        .root_source_file = b.path("ids.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{ .{ .name = "abi", .module = abi }, .{ .name = "fd", .module = fd } },
    });
    return .{ .abi = abi, .fd = fd, .wire = wire, .chain = chain, .agent = agent, .ids = ids };
}

fn plugin(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, m: Modules, cfg: *std.Build.Module, strip: bool) *std.Build.Step.Compile {
    return b.addLibrary(.{
        .name = "frisket_sudo",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("frisket_sudo.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .imports = &.{
                .{ .name = "abi", .module = m.abi },
                .{ .name = "fd", .module = m.fd },
                .{ .name = "wire", .module = m.wire },
                .{ .name = "chain", .module = m.chain },
                .{ .name = "agent", .module = m.agent },
                .{ .name = "ids", .module = m.ids },
                .{ .name = "config", .module = cfg },
            },
        }),
    });
}

fn pamHelper(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, cfg: *std.Build.Module, strip: bool) *std.Build.Step.Compile {
    const m = modules(b, target, optimize);
    return b.addExecutable(.{
        .name = "frisket-sudo-pam",
        .root_module = b.createModule(.{
            .root_source_file = b.path("frisket-sudo-pam.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "fd", .module = m.fd },
                .{ .name = "wire", .module = m.wire },
                .{ .name = "config", .module = cfg },
            },
        }),
    });
}

fn checkPlugin(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, cfg: *std.Build.Module, strip: bool) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = "frisket-sudo-check-plugin",
        .root_module = b.createModule(.{
            .root_source_file = b.path("frisket-sudo-check-plugin.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .imports = &.{
                .{ .name = "abi", .module = modules(b, target, optimize).abi },
                .{ .name = "config", .module = cfg },
            },
        }),
    });
}

/// The check-plugin passes the plugin built for its sudo, and fails a wrong
/// symbol, a wrong sudo version, a file that is no library and a plugin of
/// the wrong type (planted_type.zig).
fn checkPluginCases(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, step: *std.Build.Step) void {
    const cfg = config(b, gate_path, gate_uid, .stock, "1.2.3");
    const check = checkPlugin(b, target, optimize, cfg, false);
    const so = plugin(b, target, optimize, modules(b, target, optimize), cfg, false).getEmittedBin();
    const planted = b.addLibrary(.{
        .name = "planted_type",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("planted_type.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "abi", .module = modules(b, target, optimize).abi }},
        }),
    }).getEmittedBin();
    const cases = [_]struct { so: std.Build.LazyPath, symbol: []const u8, version: []const u8, code: u8, stderr: []const u8 }{
        .{ .so = so, .symbol = "frisket_audit", .version = "1.2.3", .code = 0, .stderr = "" },
        .{ .so = so, .symbol = "frisket_approval", .version = "1.2.3", .code = 1, .stderr = "no symbol frisket_approval" },
        .{ .so = so, .symbol = "frisket_audit", .version = "1.2.4", .code = 1, .stderr = "is built for sudo 1.2.3, not 1.2.4" },
        .{ .so = b.path("build.zig"), .symbol = "frisket_audit", .version = "1.2.3", .code = 1, .stderr = "cannot load" },
        .{ .so = planted, .symbol = "frisket_audit", .version = "1.2.3", .code = 1, .stderr = "is plugin type 1, not 3 (audit)" },
    };
    for (cases) |c| {
        const run = b.addRunArtifact(check);
        run.addFileArg(c.so);
        run.addArgs(&.{ c.symbol, c.version });
        if (c.code == 0) run.addCheck(.{ .expect_stderr_exact = "" }) else run.addCheck(.{ .expect_stderr_match = c.stderr });
        run.addCheck(.{ .expect_term = .{ .Exited = c.code } });
        step.dependOn(&run.step);
    }
}
