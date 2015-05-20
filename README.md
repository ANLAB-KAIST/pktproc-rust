# pktproc-rust
A small pilot project to evaluate [Rust](http://rust-lang.org) for packet processing

This program is based on [our packet generator project](https://github.com/anlab-kaist/pspgen-dpdk).

## Goals

 * Test if the raw forwarding performance of "bare-metal" Rust can keep up with multi-10 Gbps setups.
 * Compare the algorithmic performance with NBA (e.g., IPv4 lookup).
 * Explore possible "packet" abstractions for Rust

## How to compile

### The sample packet processing library written in Rust

```
cd libpktproc
cargo build --release
```

### The C-based main program

```
export RTE_SDK=$HOME/dpdk/x86_64-native-linuxapp-gcc
cd c-main
make
```

### The DPDK bindings for Rust (TODO)

```
cd libdpdk
./bindgen.sh
```

### The Rust-based main program (TODO)

```
cd rust-main
cargo build --release
```

