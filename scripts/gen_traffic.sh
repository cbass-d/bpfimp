#!/bin/bash
# Generate test traffic from inside the netns toward the host's veth IP.
#
# Usage:
#   ./scripts/gen_traffic.sh                # 20 pings at 1/s (under the limit)
#   ./scripts/gen_traffic.sh burst          # flood to trigger the rate limiter
#   ./scripts/gen_traffic.sh ping <count>   # custom ping count, 1/s
#
# MAX_TOKENS=100 and REFILL_PER_SEC=10 in bpfimp-common, so a sustained rate
# above ~10 pkt/s will eventually drain the bucket and start getting XDP_DROP.

set -euo pipefail
IFS=$'\n\t'

NS_NAME="${NS_NAME:-bpfimp-test}"
TARGET="${TARGET:-10.200.0.1}"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

mode="${1:-ping}"

case "$mode" in
    ping)
        count="${2:-20}"
        echo "[traffic] $count pings (1/s) from $NS_NAME -> $TARGET"
        ip netns exec "$NS_NAME" ping -c "$count" -i 1 "$TARGET"
        ;;
    burst)
        count="${2:-500}"
        # -f floods (needs root); -c bounds the run.
        echo "[traffic] flood $count pings from $NS_NAME -> $TARGET (expect drops)"
        ip netns exec "$NS_NAME" ping -f -c "$count" "$TARGET"
        ;;
    *)
        echo "usage: $0 [ping <count> | burst <count>]" >&2
        exit 2
        ;;
esac
