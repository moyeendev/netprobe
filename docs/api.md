# Python API

```python
from netprobe import Session
```

## `Session(target=None, *, out_dir=None, run_id=None, persist=True, sqlite=False, label=None, clock=None)`

A run. All probes in a session share one clock, one record list and one
run directory. Use as a context manager; on exit it waits for background
probes and writes `manifest.json`. On an exception it stops all probes first.

| method | returns | notes |
|---|---|---|
| `delay(target=None, *, mode="udp", count=100, interval=0.2, size=64, timeout=1.0, port=47001, background=False)` | `DelaySummary` or `ProbeHandle` | modes `udp`, `tcp`, `icmp` |
| `bandwidth(target=None, *, duration=10, direction="up", interval=0.25, rate_bps=None, background=False)` | `BandwidthSummary` / handle | `rate_bps` paces the upload |
| `stress(target=None, *, rate_bps=10e6, duration=10, packet_size=1200, start_delay=0, i_understand=False, allow_public=False, rate_cap_override=False, raw=False, tos=0, background=False, isolate=False)` | `StressSummary` / handle | raises `SafetyError` on policy violations |
| `sniff(*, iface="lo", duration=10, pcap="capture.pcap", bin_s=0.5, bpf=None, host=None, port=None, backend="auto", background=False, isolate=False)` | `SniffSummary` / handle | needs `CAP_NET_RAW` |
| `congestion(emit=True, **CongestionConfig)` | `CongestionResult` | `.onset_s`, `.decision_s`, `.recovery_s`, `.windows`, `.baseline` |
| `correlate(bin_s=0.5, congestion=None, max_lag_s=5)` | `Correlation` | `.phases`, `.lags`, `.evidence`, `.detection_latency_s`, `.timeline` |
| `report(path=None, **correlate_kw)` | `Path` | writes `report.html`, `report.json`, `timeline.csv` |
| `run_probe(fn, *, name=None, background=False, isolate=False, **kw)` | result / handle | run any probe function `fn(sink, **kw)` |
| `emit(probe, metric, value, unit=None, *, target=None, ts_ns=None, **meta)` | `Record` | the only way records are created |
| `query(probe=None, metric=None, target=None)` | `list[Record]` | sorted by time |
| `records` | `list[Record]` | snapshot, sorted |
| `wait()` / `stop()` / `close()` | | lifecycle |

`ProbeHandle.join()` returns the probe's summary or re-raises its exception.
For isolated probes the summary arrives as a `dict`.

## Examples

Concurrent measurements on one clock:

```python
with Session(target="10.0.0.2", out_dir="runs/exp1", label="cabinet A") as s:
    d = s.delay(background=True, count=600, interval=0.05)
    b = s.bandwidth(background=True, duration=30, rate_bps=20e6)
    s.stress(background=True, isolate=True, rate_bps=40e6, duration=10,
             start_delay=10, i_understand=True)
    s.wait()
    c = s.correlate()
    print(c.onset_s, c.detection_latency_s, c.phases["load"]["rtt_median_ms"])
    s.report()
```

A parameter sweep (the pattern used in `examples/evaluation/reproduce.py`):

```python
for rate in (10e6, 20e6, 40e6):
    with Session(target="10.0.0.2", out_dir=f"runs/sweep_{rate:.0f}") as s:
        s.delay(background=True, count=400, interval=0.05)
        s.stress(rate_bps=rate, duration=20, i_understand=True)
        s.wait()
        print(rate, s.correlate().phases["load"]["rtt_p95_ms"])
```

Offline re-analysis with a different detector configuration:

```python
from netprobe.core.storage import load_records, load_manifest
from netprobe.analysis.correlate import correlate

recs = load_records("runs/exp1")
c = correlate(recs, manifest=load_manifest("runs/exp1"),
              congestion={"window_s": 0.5, "persist": 3})
```

A custom probe that joins the unified timeline:

```python
from netprobe.core.session import register_metric

register_metric("radio", "rssi", "dBm")

def run_rssi(sink, *, iface="wlan0", count=100, interval=0.5):
    for _ in range(count):
        sink.emit("radio", "rssi", read_rssi(iface), target=iface)
        if sink.stop_event.wait(interval):
            break

with Session() as s:
    s.run_probe(run_rssi, background=True, iface="wlan0")
    s.delay("10.0.0.2", count=100, interval=0.5)
```

Servers for scripted testbeds:

```python
from netprobe.probes.delay import UdpEchoServer
from netprobe.probes.bandwidth import BandwidthServer

with UdpEchoServer("0.0.0.0", 47001), BandwidthServer("0.0.0.0", 47001):
    ...
```

## Errors

| exception | raised when |
|---|---|
| `netprobe.SchemaError` (`ValueError`) | unknown probe/metric, wrong unit, non-finite value |
| `netprobe.probes.stress.SafetyError` (`ValueError`) | load request violates the safety policy |
| `netprobe.utils.privileges.PrivilegeError` (`PermissionError`) | a capability is missing; `.hint` has remediation |
