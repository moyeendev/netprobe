#!/usr/bin/env bash
# Runs the full evaluation: delay/throughput accuracy against ping and iperf3
# under tc netem, and repeated congestion-onset runs; then builds the tables
# and the correlation-timeline figure.
#
# Requires root on Linux with iproute2, iputils-ping, iperf3 and ethtool, or
# use the bundled container (recommended; pins the userland):
#
#   docker build -t netprobe-repro .
#   docker run --rm --privileged -v "$PWD":/src netprobe-repro \
#       bash examples/run_evaluation.sh
#
# Outputs (under $RESULTS, default evaluation-results/):
#           results.json                 raw measurements
#           runs/...                     NetProbe run directories
#           table_accuracy.md            delay and throughput accuracy
#           table_congestion.md          congestion onset detection
#           figures/fig_correlation.{pdf,png}
#
# QUICK=1 shortens every experiment (smoke test only).
# ONLY=delay|bandwidth|congestion re-runs one experiment into existing results.
set -euo pipefail
cd "$(dirname "$0")/.."
source examples/netns.sh
np_require_root
for t in ping iperf3; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 69; }
done

RESULTS=${RESULTS:-evaluation-results}
mkdir -p "$RESULTS"

trap np_teardown EXIT
np_setup
np_start_servers

python3 examples/evaluation/reproduce.py --out "$RESULTS" ${QUICK:+--quick} ${ONLY:+--only "$ONLY"}
python3 examples/evaluation/make_assets.py --results "$RESULTS" --figures "$RESULTS/figures"
echo "done: $RESULTS"
