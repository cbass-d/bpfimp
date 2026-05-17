#!/bin/bash
# Create a test network namespace + veth pair for exercising the XDP program.
#
# Topology:
#
#   host  vbpfimp0 (10.200.0.1/24)  <--veth-->  vbpfimp1 (10.200.0.2/24)  ns bpfimp-test
#
# Attach the XDP program to vbpfimp0 on the host; traffic generated from inside
# the ns (e.g. via gen_traffic.sh) will arrive on vbpfimp0 and hit the program.

set -euo pipefail
IFS=$'\n\t'

NS_NAME="${NS_NAME:-bpfimp-test}"
VETH_HOST="${VETH_HOST:-vbpfimp0}"
VETH_NS="${VETH_NS:-vbpfimp1}"
HOST_IP="${HOST_IP:-10.200.0.1/24}"
NS_IP="${NS_IP:-10.200.0.2/24}"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

log() { printf '[setup] %s\n' "$*"; }

if ip netns list | awk '{print $1}' | grep -qx "$NS_NAME"; then
    log "netns $NS_NAME already exists"
else
    log "creating netns $NS_NAME"
    ip netns add "$NS_NAME"
fi

if ip link show "$VETH_HOST" &>/dev/null; then
    log "$VETH_HOST already exists (assuming pair is set up)"
else
    log "creating veth pair $VETH_HOST <-> $VETH_NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS_NAME"
fi

log "configuring $HOST_IP on $VETH_HOST"
ip addr replace "$HOST_IP" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

log "configuring $NS_IP on $VETH_NS (inside $NS_NAME)"
ip -n "$NS_NAME" addr replace "$NS_IP" dev "$VETH_NS"
ip -n "$NS_NAME" link set lo up
ip -n "$NS_NAME" link set "$VETH_NS" up

# Disable IPv6 on the veth pair so the program (IPv4-only) doesn't see RA/NDP chatter.
sysctl -qw "net.ipv6.conf.${VETH_HOST}.disable_ipv6=1" || true
ip netns exec "$NS_NAME" sysctl -qw "net.ipv6.conf.${VETH_NS}.disable_ipv6=1" || true

log "done"
log ""
log "  attach XDP:    sudo ./target/release/bpfimp --iface $VETH_HOST"
log "  send traffic:  ./scripts/gen_traffic.sh"
log "  teardown:      ./scripts/teardown_netns.sh"
