# ZEvilBPF - RFC 3514 XDP Filter

XDP-based packet filter written in Zig using [zbpf](https://github.com/tw4452852/zbpf) that filters [RFC 3514](https://www.rfc-editor.org/rfc/rfc3514)

> **Warning**: This is a silly XDP filter for learning more about Zig/eBPF. May the evil be with you!

## Usage

### Prerequisites

- Zig compiler
- Linux kernel with `CONFIG_DEBUG_INFO_BTF=y`
- Privileges (sudo!) for loading XDP programs

### Commands

build:
```bash
zig build
```

run:
```bash
sudo ./zig-out/bin/zevilbpf -i eth0
```

detach:
```bash
sudo ./zig-out/bin/zevilbpf -i eth0 --detach
```
