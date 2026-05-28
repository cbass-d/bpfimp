#!/bin/bash
# Build and run bpfimp attached to the test veth. Run setup_netns.sh first.
#
# veth supports native XDP on recent kernels but some configurations require
# generic/skb mode -- if `XdpFlags::default()` fails to attach, edit
# bpfimp/src/main.rs to use XdpFlags::SKB_MODE.

set -euo pipefail
IFS=$'\n\t'

VETH_HOST="${VETH_HOST:-vbpfimp0}"
PEERS_CONFIG="${PEERS_CONFIG:-bpfimp.toml}"
RUST_LOG="${RUST_LOG:-info}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

echo "[run] cargo build --release"
cargo build --release

echo "[run] attaching bpfimp to $VETH_HOST (peers=$PEERS_CONFIG)"
sudo RUST_LOG="$RUST_LOG" ./target/release/bpfimp \
    run \
    --iface "$VETH_HOST" \
    --config "$PEERS_CONFIG"
