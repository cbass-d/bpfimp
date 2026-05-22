#!/bin/bash
# Generate test traffic from inside the netns toward the host's veth IP.
#
# Usage:
#   ./scripts/gen_traffic.sh                 # 20 v4 pings at 1/s (under the limit)
#   ./scripts/gen_traffic.sh burst           # v4 flood to trigger the rate limiter
#   ./scripts/gen_traffic.sh ping <count>    # custom v4 ping count, 1/s
#   ./scripts/gen_traffic.sh ping6 <count>   # custom v6 ping count, 1/s
#   ./scripts/gen_traffic.sh burst6 <count>  # v6 flood
#
# MAX_TOKENS=100 and REFILL_PER_SEC=10 in bpfimp-common, so a sustained rate
# above ~10 pkt/s will eventually drain the bucket and start getting XDP_DROP.

set -euo pipefail
IFS=$'\n\t'

NS_NAME="${NS_NAME:-bpfimp-test}"
TARGET="${TARGET:-10.200.0.1}"
TARGET6="${TARGET6:-fd00:200::1}"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0)" >&2
    exit 1
fi

mode="${1:-ping}"

case "$mode" in
    ping)
        count="${2:-20}"
        echo "[traffic] $count v4 pings (1/s) from $NS_NAME -> $TARGET"
        ip netns exec "$NS_NAME" ping -4 -c "$count" -i 1 "$TARGET"
        ;;
    burst)
        count="${2:-500}"
        # -f floods (needs root); -c bounds the run.
        echo "[traffic] v4 flood $count pings from $NS_NAME -> $TARGET (expect drops)"
        ip netns exec "$NS_NAME" ping -4 -f -c "$count" "$TARGET"
        ;;
    ping6)
        count="${2:-20}"
        echo "[traffic] $count v6 pings (1/s) from $NS_NAME -> $TARGET6"
        ip netns exec "$NS_NAME" ping -6 -c "$count" -i 1 "$TARGET6"
        ;;
    burst6)
        count="${2:-500}"
        echo "[traffic] v6 flood $count pings from $NS_NAME -> $TARGET6 (expect drops)"
        ip netns exec "$NS_NAME" ping -6 -f -c "$count" "$TARGET6"
        ;;
    *)
        echo "usage: $0 [ping|burst|ping6|burst6] [<count>]" >&2
        exit 2
        ;;
esac
