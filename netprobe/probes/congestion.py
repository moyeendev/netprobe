"""Congestion-level estimation from delay, loss and throughput records.

This probe sends no traffic: it is a deterministic function of records
already in the session, so it can run live (``Session.congestion()``) or
offline on a stored run.

Method
------
Records are grouped into fixed windows of ``window_s`` aligned at session
time 0. Per window:

* ``rtt``  - median of ``delay.rtt`` (fallback: ``bandwidth.tcp_rtt``),
* ``loss`` - ``delay.lost / (delay.lost + #delay.rtt)``,
* ``thr``  - mean ``bandwidth.throughput``.

The *baseline* is the median of each quantity over windows that end at or
before ``baseline_s`` (and, if a stress probe ran, before it started).
Three binary signals are evaluated per window:

* queuing delay:   ``rtt - base_rtt > max(rtt_rise_ratio * base_rtt, rtt_rise_min_ms)``
* loss:            ``loss - base_loss > loss_threshold``
* throughput drop: ``thr < (1 - thr_drop_ratio) * base_thr``

``level`` is the number of active signals (0..3). A window is *congested*
when ``level >= min(2, available_signals)`` (signals corroborate each other),
or when any single signal reaches twice its threshold (a strong signal, e.g.
loss-free bufferbloat seen by RTT alone). **Onset** is the start of the
first post-baseline window that begins a run of ``persist`` consecutive
congested windows (resolution: one window); the **decision time** is the end
of that run, i.e. when a live detector would first have declared onset;
**recovery** is the start of the first later run of ``persist``
non-congested windows. ``index`` is the mean per-signal
severity, scaled so that 0.5 means "exactly at threshold", clipped to [0,1].
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field


@dataclass
class CongestionConfig:
    window_s: float = 1.0
    baseline_s: float = 5.0
    rtt_rise_ratio: float = 0.5
    rtt_rise_min_ms: float = 2.0
    loss_threshold: float = 0.01
    thr_drop_ratio: float = 0.2
    persist: int = 2


@dataclass
class Window:
    t_start: float
    t_end: float
    rtt_ms: float | None
    loss: float | None
    throughput_bps: float | None
    signals: dict = field(default_factory=dict)
    level: int = 0
    available: int = 0
    index: float = 0.0
    congested: bool = False


@dataclass
class CongestionResult:
    config: CongestionConfig
    baseline: dict
    windows: list[Window]
    onset_s: float | None
    recovery_s: float | None
    decision_s: float | None = None  # end of the persistence run: when an online
    #                                  detector would first have declared onset

    def to_dict(self) -> dict:
        return {
            "config": asdict(self.config),
            "baseline": self.baseline,
            "onset_s": self.onset_s,
            "decision_s": self.decision_s,
            "recovery_s": self.recovery_s,
            "windows": [asdict(w) for w in self.windows],
        }


def _median(xs):
    return statistics.median(xs) if xs else None


def _clip01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def estimate(records, config: CongestionConfig | None = None) -> CongestionResult:
    cfg = config or CongestionConfig()
    if cfg.window_s <= 0 or cfg.persist < 1:
        raise ValueError("window_s > 0 and persist >= 1 required")
    w_ns = int(cfg.window_s * 1e9)

    rtt_d: dict[int, list[float]] = {}
    rtt_t: dict[int, list[float]] = {}
    lost: dict[int, int] = {}
    thr: dict[int, list[float]] = {}
    stress_start: float | None = None
    t_max = 0
    for r in records:
        b = r.ts_monotonic // w_ns
        t_max = max(t_max, r.ts_monotonic)
        key = (r.probe, r.metric)
        if key == ("delay", "rtt"):
            rtt_d.setdefault(b, []).append(r.value)
        elif key == ("delay", "lost"):
            lost[b] = lost.get(b, 0) + 1
        elif key == ("bandwidth", "tcp_rtt"):
            rtt_t.setdefault(b, []).append(r.value)
        elif key == ("bandwidth", "throughput"):
            thr.setdefault(b, []).append(r.value)
        elif key == ("stress", "event") and r.meta.get("event") == "start":
            t = r.ts_monotonic / 1e9
            stress_start = t if stress_start is None else min(stress_start, t)

    rtt_src = rtt_d if rtt_d else rtt_t
    have_loss = bool(rtt_d) or bool(lost)
    n_windows = t_max // w_ns + 1 if records else 0

    windows: list[Window] = []
    for b in range(n_windows):
        rtts = rtt_src.get(b, [])
        n_rx = len(rtt_d.get(b, []))
        n_lost = lost.get(b, 0)
        loss = (n_lost / (n_lost + n_rx)) if have_loss and (n_lost + n_rx) else None
        th = thr.get(b)
        windows.append(Window(
            t_start=b * cfg.window_s, t_end=(b + 1) * cfg.window_s,
            rtt_ms=_median(rtts), loss=loss,
            throughput_bps=statistics.fmean(th) if th else None,
        ))

    base_end = cfg.baseline_s
    if stress_start is not None:
        base_end = min(base_end, stress_start)
    base_w = [w for w in windows if w.t_end <= base_end + 1e-9]
    baseline = {
        "end_s": base_end,
        "windows": len(base_w),
        "rtt_ms": _median([w.rtt_ms for w in base_w if w.rtt_ms is not None]),
        "loss": _median([w.loss for w in base_w if w.loss is not None]),
        "throughput_bps": _median([w.throughput_bps for w in base_w
                                   if w.throughput_bps is not None]),
    }

    for w in windows:
        sev = []
        if w.rtt_ms is not None and baseline["rtt_ms"] is not None:
            thr_ms = max(cfg.rtt_rise_ratio * baseline["rtt_ms"], cfg.rtt_rise_min_ms)
            excess = w.rtt_ms - baseline["rtt_ms"]
            w.signals["rtt"] = excess > thr_ms
            sev.append(_clip01(0.5 * excess / thr_ms))
        if w.loss is not None and baseline["loss"] is not None:
            excess = w.loss - baseline["loss"]
            w.signals["loss"] = excess > cfg.loss_threshold
            sev.append(_clip01(0.5 * excess / cfg.loss_threshold))
        if w.throughput_bps is not None and baseline["throughput_bps"]:
            drop = 1.0 - w.throughput_bps / baseline["throughput_bps"]
            w.signals["throughput"] = drop > cfg.thr_drop_ratio
            sev.append(_clip01(0.5 * drop / cfg.thr_drop_ratio))
        w.available = len(w.signals)
        w.level = sum(1 for v in w.signals.values() if v)
        w.index = statistics.fmean(sev) if sev else 0.0
        strong = bool(sev) and max(sev) >= 1.0  # one signal at >= 2x its threshold
        w.congested = w.available > 0 and (w.level >= min(2, w.available) or strong)

    onset = recovery = decision = None
    post = [i for i, w in enumerate(windows) if w.t_start >= base_end - 1e-9]
    for i in post:
        run = windows[i: i + cfg.persist]
        if len(run) == cfg.persist and all(w.congested for w in run):
            onset = windows[i].t_start
            decision = run[-1].t_end
            for j in range(i + cfg.persist, len(windows)):
                run2 = windows[j: j + cfg.persist]
                if len(run2) == cfg.persist and not any(w.congested for w in run2):
                    recovery = windows[j].t_start
                    break
            break
    return CongestionResult(cfg, baseline, windows, onset, recovery, decision)


def emit_congestion(sink, result: CongestionResult) -> None:
    for w in result.windows:
        ts = int(w.t_end * 1e9)
        sink.emit("congestion", "level", w.level, ts_ns=ts, available=w.available,
                  signals=w.signals, window_s=result.config.window_s)
        sink.emit("congestion", "index", w.index, ts_ns=ts)
    if result.onset_s is not None:
        sink.emit("congestion", "onset", result.onset_s, ts_ns=int(result.onset_s * 1e9))
    if result.recovery_s is not None:
        sink.emit("congestion", "recovery", result.recovery_s,
                  ts_ns=int(result.recovery_s * 1e9))
