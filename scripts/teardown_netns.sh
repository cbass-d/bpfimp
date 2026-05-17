#!/bin/bash
# Tear down the test netns + veth pair created by setup_netns.sh. Idempotent.

set -euo pipefail
IFS=$'\n\t'

NS_NAME="${NS_NAME:-bpfimp-test}"
VETH_HOST="${VETH_HOST:-vbpfimp0}"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

log() { printf '[teardown] %s\n' "$*"; }

# Removing the host-side veth removes the peer too; do this first so the link is
# gone even if the netns delete fails for some reason.
if ip link show "$VETH_HOST" &>/dev/null; then
    log "deleting veth $VETH_HOST (peer goes with it)"
    ip link del "$VETH_HOST"
else
    log "$VETH_HOST not present"
fi

if ip netns list | awk '{print $1}' | grep -qx "$NS_NAME"; then
    log "deleting netns $NS_NAME"
    ip netns del "$NS_NAME"
else
    log "netns $NS_NAME not present"
fi

log "done"
