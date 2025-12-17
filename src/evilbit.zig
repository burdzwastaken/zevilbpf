const std = @import("std");
const bpf = @import("bpf");
const Xdp = bpf.Xdp;

const EthHdr = extern struct {
    dest: [6]u8,
    src: [6]u8,
    proto: u16,
};

const IPv4Hdr = extern struct {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src: u32,
    dst: u32,
};

const EVIL_BIT_MASK: u16 = 0x8000;
const PROTO_IPV4: u16 = 0x0800;

var dropped_packets = bpf.Map.HashMap("dropped_packets", u32, u64, 1, 0).init();
var passed_packets = bpf.Map.HashMap("passed_packets", u32, u64, 1, 0).init();

inline fn incrementCounter(comptime map: anytype) void {
    const key: u32 = 0;
    const new_count = if (map.lookup(key)) |count| count.* + 1 else 1;
    map.update(.any, key, new_count);
}

export fn evil_bit_filter(ctx: *Xdp.Meta) linksection("xdp") c_int {
    // pass if packet too small
    const eth_hdr: *const EthHdr = ctx.get_ptr(EthHdr, 0) orelse return @intFromEnum(Xdp.RET.pass);

    // byte order comparison
    if (eth_hdr.proto != std.mem.nativeTo(u16, PROTO_IPV4, .big)) {
        return @intFromEnum(Xdp.RET.pass);
    }

    const ip_hdr: *const IPv4Hdr = ctx.get_ptr(IPv4Hdr, @sizeOf(EthHdr)) orelse return @intFromEnum(Xdp.RET.pass);

    if (ip_hdr.frag_off & std.mem.nativeTo(u16, EVIL_BIT_MASK, .big) == 0) {
        incrementCounter(&dropped_packets);
        return @intFromEnum(Xdp.RET.drop);
    }

    incrementCounter(&passed_packets);
    return @intFromEnum(Xdp.RET.pass);
}
