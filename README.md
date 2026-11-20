# NetProbe

[![ci](https://github.com/moyeendev/netprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/moyeendev/netprobe/actions/workflows/ci.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24398726.svg)](https://doi.org/10.5281/zenodo.24398726)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)

**One clock for delay, bandwidth, congestion, load and packet capture.**

NetProbe runs network measurements concurrently in a single session and writes
every result — RTT samples, lost probes, throughput intervals, kernel TCP
state, offered load, packet-capture summaries, congestion level — into one
record schema stamped by one monotonic clock. The output of a run is directly
correlatable: the report shows when congestion began, how long after the load
started, what happened to RTT, loss and throughput, and which pcap frames hold
the evidence.

The same workflow with separate tools (`iperf3`, `ping`, `tc netem`,
`tcpdump`) means several terminals, several output formats and several time
bases (relative interval times, wall-clock prints, pcap timestamps) that have
to be aligned by hand.

* Linux, Python ≥ 3.10, **no runtime dependencies** (scapy optional).
* Unprivileged for delay, bandwidth and congestion; `CAP_NET_RAW` only for
  capture and raw-socket load ([docs/privileges.md](docs/privileges.md)).
* Python API for scripted experiments ([docs/api.md](docs/api.md)), CLI for
  field use.
* Safety-gated load generator: explicit acknowledgement, 10 Mbit/s default,
  private targets only by default.

## Install

```bash
pip install .            # core, zero dependencies
pip install ".[scapy]"   # BPF-filtered capture backend
pip install ".[plot,dev]"  # evaluation figures, tests, lint
```

## Quickstart

On the far end (or the same host):

```bash
netprobe server                     # UDP echo + TCP sink on port 47001
```

On the measuring host:

```bash
netprobe delay 192.168.1.20 --count 50                 # RTT / jitter / loss
netprobe bandwidth 192.168.1.20 --duration 10          # TCP throughput (+ TCP_INFO)
netprobe run 192.168.1.20 --duration 30                # delay + bandwidth together -> report
```

Integrated congestion experiment (load from t=10 s for 10 s, capture on eth0):

```bash
sudo -E netprobe run 192.168.1.20 --duration 30 --bw-rate 20M \
    --stress-rate 40M --stress-start 10 --stress-duration 10 \
    --i-understand-this-sends-traffic --sniff eth0 --sniff-host 192.168.1.20
```

```
# example output
run 20261120T101500-a1b2c3 -> runs/20261120T101500-a1b2c3
congestion onset: 10.0 s (decided at 12.0 s), recovery: 21.0 s
report: runs/20261120T101500-a1b2c3/report.html
```

Re-analyse a stored run with other detector settings:

```bash
netprobe analyze runs/<id> --window 0.5 --persist 3
netprobe report  runs/<id> --bin 0.25
```

Python:

```python
from netprobe import Session

with Session(target="192.168.1.20") as s:
    s.delay(background=True, count=600, interval=0.05)
    s.bandwidth(background=True, duration=30, rate_bps=20e6)
    s.stress(background=True, isolate=True, rate_bps=40e6, duration=10,
             start_delay=10, i_understand=True)
    s.wait()
    c = s.correlate()
    print(c.onset_s, c.detection_latency_s, c.evidence)
    s.report()
```

## Commands

| command | what it records | privileges |
|---|---|---|
| `server` | UDP echo + TCP bandwidth responder | none |
| `delay TARGET [--mode udp\|tcp\|icmp]` | `rtt`, `jitter` (RFC 3550), `lost`, `loss` | none (icmp: see docs) |
| `bandwidth TARGET [--direction up\|down] [--rate R]` | `throughput` (from `tcpi_bytes_acked`), `tcp_rtt`, `cwnd`, `retrans`, `goodput_total` | none |
| `stress TARGET --i-understand-this-sends-traffic` | `offered_rate`, `packets`, start/stop markers | none (`--raw`: `CAP_NET_RAW`) |
| `sniff --iface IF` | `capture.pcap`, per-bin `pkts`, `bytes`, `tcp_retrans` with frame ranges | `CAP_NET_RAW` |
| `run TARGET ...` | all of the above concurrently, then congestion + report | depends on options |
| `report RUN_DIR` / `analyze RUN_DIR` | rebuild report / print correlation JSON | none |
| `privileges` | show effective capabilities | none |

All results land in `runs/<run_id>/` (`records.jsonl`, `manifest.json`,
optional `records.sqlite`, `capture.pcap`, `report.html`, `report.json`,
`timeline.csv`). See [docs/architecture.md](docs/architecture.md) for the
schema and the correlation pipeline.

## Examples and reproducibility

| script | needs | does |
|---|---|---|
| `examples/run_baseline.sh` | nothing (loopback) | on-site baseline; `TARGET=` for a remote server |
| `examples/run_congestion_scenario.sh` | root | 3-namespace testbed, `tc netem` bottleneck, load + capture, report |
| `examples/run_evaluation.sh` | root or Docker | accuracy vs ping/iperf3, congestion runs, tables and figures |

```bash
docker build -t netprobe-repro .
docker run --rm --privileged -v "$PWD":/src netprobe-repro bash examples/run_evaluation.sh
```

## Tests

```bash
pytest -q          # unit + loopback integration, no root required
ruff check .
```

Raw-socket and capability paths are exercised with mocks/injected backends;
UDP/TCP probes are exercised end-to-end on loopback.

## Why Linux only

NetProbe relies on `CLOCK_MONOTONIC` being shared across processes (isolated
probes rebuild the session clock from its anchor), `TCP_INFO` (`tcpi_bytes_acked`,
sRTT, cwnd, retransmissions), `AF_PACKET` with `SO_TIMESTAMPNS`, Linux
capabilities (`CapEff`) and `tc netem` for the evaluation. The unprivileged
UDP/TCP probes also run on macOS and Windows (the test suite passes on
Windows), but without `TCP_INFO` throughput falls back to bytes handed to the
socket, and capture is unavailable. Native support is future work.

## Limitations

* IPv4 only; IPv6 targets are rejected with an explicit error.
* Python userspace timestamping: the UDP probe reads 0.2–0.55 ms above `ping`
  and ICMP mode up to 0.28 ms (`evaluation-results/table_accuracy.md`); use `--mode icmp` for lower
  overhead.
* The load generator is a Python token bucket; sustained rates above a few
  hundred Mbit/s are CPU-bound.
* The congestion detector is a transparent threshold rule, not a learned
  model; thresholds are configurable and recorded in the report.

## Citation

If you use NetProbe, please cite it using the metadata in [CITATION.cff](CITATION.cff)
(GitHub's "Cite this repository" button). Each release is archived on Zenodo:
concept DOI (all versions) [10.5281/zenodo.24398726](https://doi.org/10.5281/zenodo.24398726),
v0.1.0 [10.5281/zenodo.24398727](https://doi.org/10.5281/zenodo.24398727).

## Authors

M. A. Moyeen (Institute of Information and Communication Technology, KUET) and
Md. Abdul Awal (Department of Computer Science and Engineering, KUET), Khulna, Bangladesh.

## License

MIT, see [LICENSE.txt](LICENSE.txt).
