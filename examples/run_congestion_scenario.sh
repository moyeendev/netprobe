#!/usr/bin/env bash
# Controlled congestion scenario (requires root; see examples/netns.sh):
#
#   bottleneck: tc netem delay 10ms rate 50mbit limit 200 on the router (see netns.sh)
#   t = 0..35 s   delay probes every 50 ms + one TCP flow paced at 20 Mbit/s
#   t = 10..25 s  unresponsive UDP load at 40 Mbit/s (NetProbe stress probe)
#   whole run     packet capture on the client interface np0
#
# NetProbe records all of it on one clock and reports the congestion onset,
# its latency after the load started, and the pcap frames behind it.
set -euo pipefail
cd "$(dirname "$0")/.."
source examples/netns.sh
np_require_root

OUT=${OUT:-runs/congestion-$(date +%Y%m%dT%H%M%S)}
RATE=${RATE:-50mbit}
LOAD=${LOAD:-40M}

trap np_teardown EXIT
np_setup
np_netem delay 10ms rate "$RATE" limit 200
np_start_servers

$NETPROBE run "$NP_SRV_IP" \
    --duration 35 --delay-interval 0.05 --bw-rate 20M \
    --stress-rate "$LOAD" --stress-start 10 --stress-duration 15 \
    --i-understand-this-sends-traffic \
    --sniff "$NP_CLI_IF" --sniff-host "$NP_SRV_IP" \
    --out "$OUT" --label "congestion netem rate=$RATE load=$LOAD" --no-elevate

$NETPROBE analyze "$OUT" | head -n 40
echo "report: $OUT/report.html"
