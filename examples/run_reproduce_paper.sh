#!/usr/bin/env bash
# Reproduces every number, table and figure in paper/paper.md.
#
# Requires root on Linux with iproute2, iputils-ping, iperf3 and ethtool, or
# use the bundled container (recommended; pins the userland):
#
#   docker build -t netprobe-repro .
#   docker run --rm --privileged -v "$PWD":/src netprobe-repro \
#       bash examples/run_reproduce_paper.sh
#
# Outputs:  paper/results/results.json        raw measurements
#           paper/results/runs/...            NetProbe run directories
#           paper/results/table_accuracy.md   Table 1
#           paper/results/table_congestion.md Table 2
#           paper/figures/fig_correlation.{pdf,png}
#
# QUICK=1 shortens every experiment (smoke test, not for the paper).
# ONLY=delay|bandwidth|congestion re-runs one experiment into existing results.
set -euo pipefail
cd "$(dirname "$0")/.."
source examples/netns.sh
np_require_root
for t in ping iperf3; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 69; }
done

RESULTS=${RESULTS:-paper/results}
mkdir -p "$RESULTS"

trap np_teardown EXIT
np_setup
np_start_servers

python3 examples/paper/reproduce.py --out "$RESULTS" ${QUICK:+--quick} ${ONLY:+--only "$ONLY"}
python3 examples/paper/make_assets.py --results "$RESULTS" --figures paper/figures
echo "done: $RESULTS"
