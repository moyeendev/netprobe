"""Align all record streams on the unified clock and correlate them.

Because every record already carries session-relative monotonic time, the
alignment step is a deterministic binning — no cross-tool clock matching,
no parsing of heterogeneous text outputs. On top of the aligned timeline
this module derives:

* load phases (baseline / load / after) from ``stress.event`` markers,
* congestion level, onset and recovery (:mod:`netprobe.probes.congestion`),
* detection latency = onset - stress start (when a stress probe ran),
* per-phase statistics for RTT, jitter, loss, throughput, retransmissions,
* lagged Pearson correlation between offered load and RTT / throughput,
* packet-capture evidence: pcap frame ranges behind the onset window.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass, field

from netprobe.probes.congestion import CongestionConfig, CongestionResult, estimate

#: How each time-series metric is aggregated inside a bin. Summary/marker
#: metrics are deliberately absent: they are not time series.
AGGREGATION: dict[tuple[str, str], str] = {
    ("delay", "rtt"): "median",
    ("delay", "jitter"): "last",
    ("delay", "lost"): "sum",
    ("bandwidth", "throughput"): "mean",
    ("bandwidth", "tcp_rtt"): "median",
    ("bandwidth", "cwnd"): "mean",
    ("bandwidth", "retrans"): "sum",
    ("stress", "offered_rate"): "mean",
    ("stress", "packets"): "sum",
    ("sniff", "pkts"): "sum",
    ("sniff", "bytes"): "sum",
    ("sniff", "tcp_retrans"): "sum",
    ("congestion", "level"): "max",
    ("congestion", "index"): "mean",
}


def _agg(kind: str, xs: list[float]) -> float:
    if kind == "median":
        return statistics.median(xs)
    if kind == "mean":
        return statistics.fmean(xs)
    if kind == "sum":
        return float(sum(xs))
    if kind == "max":
        return max(xs)
    if kind == "last":
        return xs[-1]
    raise ValueError(kind)


@dataclass
class Timeline:
    bin_s: float
    t: list[float]  # bin start times (s)
    series: dict[str, list[float | None]]
    units: dict[str, str]

    def get(self, key: str) -> list[float | None]:
        return self.series.get(key, [None] * len(self.t))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_csv(self) -> str:
        keys = sorted(self.series)
        lines = [",".join(["t_s", *keys])]
        for i, t in enumerate(self.t):
            row = [f"{t:.3f}"]
            for k in keys:
                v = self.series[k][i]
                row.append("" if v is None else f"{v:.6g}")
            lines.append(",".join(row))
        return "\n".join(lines) + "\n"


def build_timeline(records, bin_s: float = 0.5) -> Timeline:
    if bin_s <= 0:
        raise ValueError("bin_s must be > 0")
    bin_ns = int(bin_s * 1e9)
    targets: dict[tuple[str, str], set[str]] = {}
    for r in records:
        if (r.probe, r.metric) in AGGREGATION:
            targets.setdefault((r.probe, r.metric), set()).add(r.target)
    buckets: dict[str, dict[int, list[float]]] = {}
    units: dict[str, str] = {}
    t_max = 0
    for r in sorted(records, key=lambda r: r.ts_monotonic):
        pm = (r.probe, r.metric)
        if pm not in AGGREGATION:
            continue
        key = f"{r.probe}.{r.metric}"
        if len(targets[pm]) > 1:
            key += f"@{r.target}"
        units[key] = r.unit
        b = max(r.ts_monotonic, 0) // bin_ns
        t_max = max(t_max, b)
        buckets.setdefault(key, {}).setdefault(b, []).append(r.value)
    n = t_max + 1 if buckets else 0
    series: dict[str, list[float | None]] = {}
    for key, bins in buckets.items():
        probe, metric = key.split("@")[0].split(".", 1)
        kind = AGGREGATION[(probe, metric)]
        series[key] = [(_agg(kind, bins[i]) if i in bins else None) for i in range(n)]
    return Timeline(bin_s, [i * bin_s for i in range(n)], series, units)


def pearson(x: list[float | None], y: list[float | None]) -> float | None:
    pairs = [(a, b) for a, b in zip(x, y, strict=False) if a is not None and b is not None]
    if len(pairs) < 3:
        return None
    xs, ys = zip(*pairs, strict=False)
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((a - mx) ** 2 for a in xs)
    syy = sum((b - my) ** 2 for b in ys)
    if sxx == 0 or syy == 0:
        return None
    return sum((a - mx) * (b - my) for a, b in pairs) / math.sqrt(sxx * syy)


def lagged_correlation(x, y, max_lag: int) -> list[tuple[int, float | None]]:
    """r(x[t], y[t+lag]) for lag in [-max_lag, max_lag]; lag > 0: y follows x."""
    out = []
    n = len(x)
    for lag in range(-max_lag, max_lag + 1):
        if lag >= 0:
            xa, ya = x[: n - lag], y[lag:]
        else:
            xa, ya = x[-lag:], y[: n + lag]
        out.append((lag, pearson(list(xa), list(ya))))
    return out


@dataclass
class StressWindow:
    start_s: float
    stop_s: float | None
    rate_bps: float | None


def stress_windows(records) -> list[StressWindow]:
    evs = sorted((r for r in records if r.probe == "stress" and r.metric == "event"),
                 key=lambda r: r.ts_monotonic)
    out: list[StressWindow] = []
    for r in evs:
        if r.meta.get("event") == "start":
            out.append(StressWindow(r.t_s, None, r.meta.get("rate_bps")))
        elif r.meta.get("event") == "stop" and out and out[-1].stop_s is None:
            out[-1].stop_s = r.t_s
    return out


def _pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def phase_stats(records, t0: float, t1: float) -> dict:
    def sel(probe, metric):
        return [r.value for r in records if r.probe == probe and r.metric == metric
                and t0 <= r.t_s < t1]

    rtt, lost = sel("delay", "rtt"), sel("delay", "lost")
    thr = sel("bandwidth", "throughput")
    return {
        "t0_s": t0,
        "t1_s": t1,
        "rtt_samples": len(rtt),
        "rtt_median_ms": statistics.median(rtt) if rtt else None,
        "rtt_p95_ms": _pct(rtt, 0.95),
        "jitter_ms": statistics.fmean(sel("delay", "jitter")) if rtt else None,
        "loss": (len(lost) / (len(lost) + len(rtt))) if (lost or rtt) else None,
        "throughput_mean_bps": statistics.fmean(thr) if thr else None,
        "tcp_rtt_median_ms": (statistics.median(x) if (x := sel("bandwidth", "tcp_rtt"))
                              else None),
        "tcp_retrans": sum(sel("bandwidth", "retrans")) if sel("bandwidth", "retrans") else None,
        "wire_retrans": (sum(x) if (x := sel("sniff", "tcp_retrans")) else None),
        "offered_load_mean_bps": (statistics.fmean(x) if (x := sel("stress", "offered_rate"))
                                  else None),
    }


def capture_evidence(records, t0: float, t1: float) -> dict | None:
    """pcap frame range and retransmissions recorded in (t0, t1]."""
    rs = [r for r in records if r.probe == "sniff" and r.metric == "tcp_retrans"
          and t0 < r.t_s <= t1 + 1e-9]
    if not rs:
        return None
    firsts = [r.meta["frame_first"] for r in rs if r.meta.get("frame_first")]
    lasts = [r.meta["frame_last"] for r in rs if r.meta.get("frame_last")]
    return {
        "pcap": next((r.meta.get("pcap") for r in rs if r.meta.get("pcap")), None),
        "frame_first": min(firsts) if firsts else None,
        "frame_last": max(lasts) if lasts else None,
        "tcp_retrans": int(sum(r.value for r in rs)),
        "t0_s": t0,
        "t1_s": t1,
    }


@dataclass
class Correlation:
    run_id: str | None
    timeline: Timeline
    congestion: CongestionResult
    stress: list[StressWindow]
    onset_s: float | None
    recovery_s: float | None
    detection_latency_s: float | None  # decision time - load start
    onset_error_s: float | None  # onset window start - load start, in (-window, ...]
    phases: dict
    lags: dict
    evidence: dict | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "onset_s": self.onset_s,
            "recovery_s": self.recovery_s,
            "detection_latency_s": self.detection_latency_s,
            "onset_error_s": self.onset_error_s,
            "decision_s": self.congestion.decision_s,
            "stress": [asdict(s) for s in self.stress],
            "phases": self.phases,
            "lags": self.lags,
            "evidence": self.evidence,
            "congestion": self.congestion.to_dict(),
            "timeline": self.timeline.to_dict(),
            "notes": self.notes,
        }


def correlate(
    records,
    *,
    manifest: dict | None = None,
    bin_s: float = 0.5,
    congestion: CongestionConfig | dict | None = None,
    max_lag_s: float = 5.0,
) -> Correlation:
    records = [r for r in records if r.probe != "congestion"]  # always recompute
    cfg = (CongestionConfig(**congestion) if isinstance(congestion, dict)
           else congestion or CongestionConfig())
    tl = build_timeline(records, bin_s)
    cres = estimate(records, cfg)
    sw = stress_windows(records)
    end_s = max((r.t_s for r in records), default=0.0)
    notes: list[str] = []

    phases: dict = {}
    if sw:
        s0 = sw[0]
        s1 = s0.stop_s if s0.stop_s is not None else end_s
        phases["baseline"] = phase_stats(records, 0.0, s0.start_s)
        phases["load"] = phase_stats(records, s0.start_s, s1)
        if s1 < end_s:
            phases["after"] = phase_stats(records, s1, end_s + 1e-9)
    elif cres.onset_s is not None:
        phases["before_onset"] = phase_stats(records, 0.0, cres.onset_s)
        end = cres.recovery_s if cres.recovery_s is not None else end_s + 1e-9
        phases["congested"] = phase_stats(records, cres.onset_s, end)
    else:
        phases["whole_run"] = phase_stats(records, 0.0, end_s + 1e-9)

    latency = onset_err = None
    if sw and cres.onset_s is not None:
        onset_err = cres.onset_s - sw[0].start_s
        latency = cres.decision_s - sw[0].start_s
    elif sw:
        notes.append("load was applied but no congestion onset met the persistence rule")

    lags: dict = {}
    max_lag = max(1, int(round(max_lag_s / bin_s)))
    load = tl.get("stress.offered_rate")
    if sw:
        load = [v if v is not None else 0.0 for v in load]
        for name, key, pick in (("load->rtt", "delay.rtt", max),
                                ("load->throughput", "bandwidth.throughput", min)):
            if key not in tl.series:
                continue
            lc = [(lag, r) for lag, r in lagged_correlation(load, tl.series[key], max_lag)
                  if r is not None]
            if lc:
                lag, r = pick(lc, key=lambda p: p[1])
                lags[name] = {"lag_s": lag * bin_s, "r": r,
                              "r_at_zero": dict(lc).get(0)}

    evidence = None
    if cres.onset_s is not None:
        onset_end = cres.onset_s + cfg.window_s * cfg.persist
        evidence = capture_evidence(records, cres.onset_s, onset_end)

    return Correlation(
        run_id=(manifest or {}).get("run_id"), timeline=tl, congestion=cres, stress=sw,
        onset_s=cres.onset_s, recovery_s=cres.recovery_s, detection_latency_s=latency,
        onset_error_s=onset_err,
        phases=phases, lags=lags, evidence=evidence, notes=notes,
    )
