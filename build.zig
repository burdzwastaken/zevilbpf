const std = @import("std");

var vmlinux_bin_path: ?[]const u8 = null;
var debugging = false;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    vmlinux_bin_path = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    if (b.option(bool, "debug", "enable debugging log")) |v| debugging = v;

    const zbpf_dep = b.dependency("zbpf", .{
        .target = target,
        .optimize = optimize,
    });

    const bpf_prog = createBpfProg(b, target, optimize, zbpf_dep);

    const exe = b.addExecutable(.{
        .name = "zevilbpf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    exe.root_module.addAnonymousImport("@bpf_prog", .{
        .root_source_file = bpf_prog,
    });

    const libbpf_dep = zbpf_dep.builder.dependency("libbpf", .{
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libbpf_dep.artifact("bpf"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the filter");
    run_step.dependOn(&run_cmd.step);
}

fn createBpfProg(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zbpf_dep: *std.Build.Dependency,
) std.Build.LazyPath {
    const host = std.Build.resolveTargetQuery(b, .{});

    const prog = b.addObject(.{
        .name = "evilbit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/evilbit.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = switch (target.result.cpu.arch.endian()) {
                    .big => .bpfeb,
                    .little => .bpfel,
                },
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseFast,
            .strip = false,
            .omit_frame_pointer = true,
        }),
    });

    // disable .eh_frame generation for cleaner output?
    prog.root_module.unwind_tables = .none;

    prog.root_module.addImport("bpf", zbpf_dep.module("bpf"));
    prog.root_module.addImport("vmlinux", zbpf_dep.module("vmlinux"));

    const btf_sanitizer_dep = zbpf_dep.builder.dependency("btf_sanitizer", .{
        .target = host,
        .optimize = optimize,
    });
    const run_btf_sanitizer = b.addRunArtifact(btf_sanitizer_dep.artifact("btf_sanitizer"));
    run_btf_sanitizer.addFileArg(prog.getEmittedBin());
    if (vmlinux_bin_path) |vmlinux| {
        run_btf_sanitizer.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    }
    if (debugging) run_btf_sanitizer.addArg("-debug");

    return run_btf_sanitizer.addPrefixedOutputFileArg("-o", "evilbit_sanitized.o");
}
