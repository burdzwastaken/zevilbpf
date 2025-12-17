const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
    @cInclude("net/if.h");
    @cInclude("linux/if_link.h");
});

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    var interface: []const u8 = "lo";
    var detach_only = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-i") or std.mem.eql(u8, args[i], "--interface")) {
            i += 1;
            if (i < args.len) {
                interface = args[i];
            }
        } else if (std.mem.eql(u8, args[i], "-d") or std.mem.eql(u8, args[i], "--detach")) {
            detach_only = true;
        } else if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            printUsage();
            return;
        }
    }

    const if_name = try allocator.dupeZ(u8, interface);
    const idx = libbpf.if_nametoindex(if_name.ptr);
    if (idx == 0) {
        print("failed to get index of interface '{s}': {}\n", .{ interface, std.posix.errno(-1) });
        return error.DEV;
    }

    if (detach_only) {
        const ret = libbpf.bpf_xdp_detach(@intCast(idx), libbpf.XDP_FLAGS_UPDATE_IF_NOEXIST, null);
        if (ret < 0) {
            print("failed to detach XDP program from {s}: {}\n", .{ interface, std.posix.errno(-1) });
            return error.DETACH;
        }
        print("successfully detached XDP program from {s}\n", .{interface});
        return;
    }

    // aligned for libbpf I found and the ELF is embedded at comptime
    const bytes align(64) = @embedFile("@bpf_prog").*;

    const obj = libbpf.bpf_object__open_mem(&bytes, bytes.len, null);
    if (obj == null) {
        print("failed to open BPF object: {}\n", .{std.posix.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load BPF object: {}\n", .{std.posix.errno(-1)});
        return error.LOAD;
    }

    const prog = libbpf.bpf_object__find_program_by_name(obj, "evil_bit_filter") orelse {
        print("failed to find evil_bit_filter BPF program\n", .{});
        return error.PROG_NOT_FOUND;
    };

    const dropped_map = libbpf.bpf_object__find_map_by_name(obj, "dropped_packets");
    const passed_map = libbpf.bpf_object__find_map_by_name(obj, "passed_packets");

    const prog_fd = libbpf.bpf_program__fd(prog);
    ret = libbpf.bpf_xdp_attach(@intCast(idx), prog_fd, libbpf.XDP_FLAGS_UPDATE_IF_NOEXIST, null);
    if (ret < 0) {
        print("failed to attach XDP program to {s}: {}\n", .{ interface, std.posix.errno(-1) });
        return error.ATTACH;
    }

    print(
        \\
        \\  ╔═══════════════════════════════════════════════════════════════╗
        \\  ║              ZEVILBPF - RFC 3514 XDP Filter                   ║
        \\  ╚═══════════════════════════════════════════════════════════════╝
        \\
        \\running on interface: {s} (index {})
        \\ctrl+c to detach/exit...
        \\
    , .{ interface, idx });

    const mask = std.posix.sigemptyset();
    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    var last_dropped: u64 = 0;
    var last_passed: u64 = 0;

    while (!should_exit.load(.acquire)) {
        std.Thread.sleep(1 * std.time.ns_per_s);

        var dropped: u64 = 0;
        var passed: u64 = 0;
        const key: u32 = 0;

        if (dropped_map) |dm| {
            _ = libbpf.bpf_map__lookup_elem(dm, &key, @sizeOf(@TypeOf(key)), &dropped, @sizeOf(@TypeOf(dropped)), 0);
        }
        if (passed_map) |pm| {
            _ = libbpf.bpf_map__lookup_elem(pm, &key, @sizeOf(@TypeOf(key)), &passed, @sizeOf(@TypeOf(passed)), 0);
        }

        const dropped_delta = dropped - last_dropped;
        const passed_delta = passed - last_passed;
        last_dropped = dropped;
        last_passed = passed;

        if (dropped_delta > 0 or passed_delta > 0) {
            print("stats: dropped={} (+{}) passed={} (+{})\n", .{ dropped, dropped_delta, passed, passed_delta });
        }
    }

    _ = libbpf.bpf_xdp_detach(@intCast(idx), libbpf.XDP_FLAGS_UPDATE_IF_NOEXIST, null);
    print("\ndetached XDP program from {s}\n", .{interface});
}

var should_exit = std.atomic.Value(bool).init(false);

fn handleSignal(_: c_int) callconv(.c) void {
    should_exit.store(true, .release);
}

fn printUsage() void {
    print(
        \\zevilbpf - RFC 3514 XDP Filter
        \\
        \\Usage: zevilbpf [OPTIONS]
        \\
        \\Options:
        \\  -i, --interface <name>  Network interface to attach to (default: lo)
        \\  -d, --detach            Detach any existing XDP program and exit
        \\  -h, --help              Show this help message
        \\
        \\Example:
        \\  sudo ./zevilbpf -i eth0
        \\
    , .{});
}
