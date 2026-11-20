#!/usr/bin/env bash
# On-site baseline: delay + bandwidth on one clock, no privileges needed.
#
#   ./examples/run_baseline.sh                       # self-contained, loopback
#   TARGET=192.168.1.20 ./examples/run_baseline.sh   # remote host running `netprobe server`
#   SNIFF=eth0 sudo -E ./examples/run_baseline.sh    # add packet capture (CAP_NET_RAW)
set -euo pipefail

NETPROBE=${NETPROBE:-netprobe}
TARGET=${TARGET:-127.0.0.1}
DURATION=${DURATION:-20}
OUT=${OUT:-runs/baseline-$(date +%Y%m%dT%H%M%S)}

if [[ $TARGET == 127.0.0.1 ]]; then
    $NETPROBE server --bind 127.0.0.1 &
    SRV=$!
    trap 'kill $SRV 2>/dev/null || true' EXIT
    sleep 0.5
fi

args=(run "$TARGET" --duration "$DURATION" --out "$OUT" --label baseline)
if [[ -n ${SNIFF:-} ]]; then
    args+=(--sniff "$SNIFF" --sniff-host "$TARGET")
fi
$NETPROBE "${args[@]}"
echo "report: $OUT/report.html"
