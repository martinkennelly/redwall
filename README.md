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
Create a yaml to define the source IP CIDRs you wish to allow or deny.
Also, you must define rules for any `fromCIDRS` defined. Rules contain order with lower order integers taking precidence over higher order integers.
A rule for ports is optional, and if not defined, all ports are selected.

```yaml
interfaces:
- eth0
- eth2
ingress:
- fromCIDRS:
     - 1.1.1.0/24
     - 2.2.2.0/24
  rules:
    - order: 10
      protocol: tcp
      ports: [800,8000]
      action: allow
    - order: 20
      protocol: udp      
      action: deny
    - order: 30
      protocol: tcp
      action: deny
    - order: 40
      protocol: icmp
      action: deny
```

```bash
cargo xtask run -- --filename /tmp/blocklist.yaml
```