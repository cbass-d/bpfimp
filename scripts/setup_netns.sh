#!/bin/bash
# Create a test network namespace + veth pair for exercising the XDP program.
#
# Topology:
#
#   host           vbpfimp0 (10.200.0.1/24, fd00:200::1/64)
#                            <--veth-->
#   ns bpfimp-test vbpfimp1 (10.200.0.2/24, fd00:200::2/64)
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
HOST_IP6="${HOST_IP6:-fd00:200::1/64}"
NS_IP6="${NS_IP6:-fd00:200::2/64}"

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

# Make sure v6 is enabled on the veth pair (an earlier teardown/setup cycle
# may have left disable_ipv6=1 in place).
sysctl -qw "net.ipv6.conf.${VETH_HOST}.disable_ipv6=0" >/dev/null
ip netns exec "$NS_NAME" sysctl -qw "net.ipv6.conf.${VETH_NS}.disable_ipv6=0" >/dev/null

# We don't run a router in the harness, so no RAs arrive; turn off autoconf
# anyway to keep the address state predictable across reboots and kernels.
sysctl -qw "net.ipv6.conf.${VETH_HOST}.accept_ra=0" >/dev/null
sysctl -qw "net.ipv6.conf.${VETH_HOST}.autoconf=0" >/dev/null
ip netns exec "$NS_NAME" sysctl -qw "net.ipv6.conf.${VETH_NS}.accept_ra=0" >/dev/null
ip netns exec "$NS_NAME" sysctl -qw "net.ipv6.conf.${VETH_NS}.autoconf=0" >/dev/null

log "configuring $HOST_IP / $HOST_IP6 on $VETH_HOST"
ip addr replace "$HOST_IP" dev "$VETH_HOST"
ip -6 addr replace "$HOST_IP6" dev "$VETH_HOST" nodad
ip link set "$VETH_HOST" up

log "configuring $NS_IP / $NS_IP6 on $VETH_NS (inside $NS_NAME)"
ip -n "$NS_NAME" addr replace "$NS_IP" dev "$VETH_NS"
ip -n "$NS_NAME" -6 addr replace "$NS_IP6" dev "$VETH_NS" nodad
ip -n "$NS_NAME" link set lo up
ip -n "$NS_NAME" link set "$VETH_NS" up

log "done"
log ""
log "  attach XDP:    sudo ./target/release/bpfimp --iface $VETH_HOST"
log "  send traffic:  ./scripts/gen_traffic.sh"
log "  teardown:      ./scripts/teardown_netns.sh"
