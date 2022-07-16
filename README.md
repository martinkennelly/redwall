Linux firewall using eBPF written in rust

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

Create a yaml to define the source IP CIDRs you wish to block.
```yaml
ingress:
- fromCIDRS:
     - 1.1.1.0/24
     - 2.2.2.0/24
     ...
```

```bash
cargo xtask run -- --filename /tmp/blocklist.yaml --iface eth0
```


# Demo
[![asciicast](https://asciinema.org/a/WZyahQwVoO6GbZWG8QDgcdbRK.svg)](https://asciinema.org/a/WZyahQwVoO6GbZWG8QDgcdbRK)

