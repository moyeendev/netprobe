"""Session / run object and the unified record schema.

Every measurement in NetProbe passes through :meth:`Session.emit`, which

1. validates ``(probe, metric, unit)`` against :data:`METRICS`,
2. stamps the record from the session :class:`~netprobe.core.clock.Clock`
   (or accepts an explicit event time ``ts_ns`` that was itself read from
   that clock or mapped onto it), and
3. appends it to the in-memory list and to persistent storage under one lock.

Probes never construct :class:`Record` objects themselves and never write
to storage; they receive a *sink* (the Session, or a queue-backed proxy when
a probe runs in an isolated child process) and call ``sink.emit``.
"""

from __future__ import annotations

import json
import math
import multiprocessing as mp
import platform
import queue as _queue
import secrets
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from netprobe.core import storage as _storage
from netprobe.core.clock import Clock, ClockAnchor

SCHEMA_VERSION = 1

#: probe -> metric -> unit. The single source of truth for the schema.
METRICS: dict[str, dict[str, str]] = {
    "delay": {
        "rtt": "ms",  # per-probe round-trip time, ts = departure time
        "jitter": "ms",  # RFC 3550 interarrival-jitter estimator over RTT samples
        "lost": "count",  # one record per lost probe, value 1, ts = departure time
        "loss": "ratio",  # summary at end of probe
        "sent": "count",  # summary at end of probe
    },
    "bandwidth": {
        "throughput": "bps",  # per interval, ts = interval end
        "tcp_rtt": "ms",  # kernel smoothed RTT (Linux TCP_INFO)
        "cwnd": "segments",  # congestion window (Linux TCP_INFO)
        "retrans": "count",  # retransmitted segments in interval (Linux TCP_INFO)
        "goodput_total": "bps",  # whole-transfer goodput, receiver-confirmed
    },
    "stress": {
        "offered_rate": "bps",  # achieved send rate per interval
        "packets": "count",  # packets sent in interval
        "event": "marker",  # meta.event in {"start","stop"}
    },
    "sniff": {
        "pkts": "count",  # packets in bin, ts = bin end
        "bytes": "bytes",
        "tcp_retrans": "count",  # heuristic retransmissions seen on the wire
    },
    "congestion": {
        "level": "level",  # 0..3 active congestion signals in window
        "index": "ratio",  # 0..1 severity, 0.5 == at threshold
        "onset": "marker",  # value = onset time in s
        "recovery": "marker",
    },
}


class SchemaError(ValueError):
    """A probe tried to emit something outside the unified schema."""


def register_metric(probe: str, metric: str, unit: str) -> None:
    """Extend the schema for a user-defined probe (see docs/api.md)."""
    existing = METRICS.setdefault(probe, {}).get(metric)
    if existing is not None and existing != unit:
        raise SchemaError(f"{probe}.{metric} already registered with unit {existing!r}")
    METRICS[probe][metric] = unit


def validate(probe: str, metric: str, unit: str | None) -> str:
    if probe not in METRICS:
        raise SchemaError(f"unknown probe {probe!r}; known: {sorted(METRICS)}")
    expected = METRICS[probe].get(metric)
    if expected is None:
        raise SchemaError(f"unknown metric {probe}.{metric}; known: {sorted(METRICS[probe])}")
    if unit is not None and unit != expected:
        raise SchemaError(f"{probe}.{metric} must be in {expected!r}, got {unit!r}")
    return expected


@dataclass(frozen=True, slots=True)
class Record:
    """One measurement in the unified schema."""

    ts_monotonic: int  # ns since session anchor (monotonic)
    ts_wall: float  # UNIX epoch seconds derived from the anchor
    probe: str
    target: str
    metric: str
    value: float
    unit: str
    meta: dict = field(default_factory=dict)

    @property
    def t_s(self) -> float:
        return self.ts_monotonic / 1e9

    def to_dict(self) -> dict:
        return {
            "ts_monotonic": self.ts_monotonic,
            "ts_wall": self.ts_wall,
            "probe": self.probe,
            "target": self.target,
            "metric": self.metric,
            "value": self.value,
            "unit": self.unit,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Record:
        return cls(
            int(d["ts_monotonic"]),
            float(d["ts_wall"]),
            d["probe"],
            d.get("target", ""),
            d["metric"],
            float(d["value"]),
            d["unit"],
            dict(d.get("meta") or {}),
        )


class Sink(Protocol):
    """What a probe function receives. Implemented by Session and _QueueSink."""

    clock: Clock
    stop_event: Any
    target: str | None
    out_dir: Path | None

    def emit(
        self,
        probe: str,
        metric: str,
        value: float,
        unit: str | None = None,
        *,
        target: str | None = None,
        ts_ns: int | None = None,
        **meta: Any,
    ) -> Any: ...


class ProbeHandle:
    """A probe running in the background (thread or isolated process)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.result: Any = None
        self.error: BaseException | None = None
        self._thread: threading.Thread | None = None
        self.error_observed = False

    @property
    def done(self) -> bool:
        return self._thread is not None and not self._thread.is_alive()

    def join(self, timeout: float | None = None) -> Any:
        if self._thread is not None:
            self._thread.join(timeout)
        if self.error is not None:
            self.error_observed = True
            raise self.error
        return self.result


def _jsonable(v: Any) -> Any:
    try:
        json.dumps(v)
        return v
    except TypeError:
        return repr(v)


def _result_to_dict(result: Any) -> Any:
    to_dict = getattr(result, "to_dict", None)
    return to_dict() if callable(to_dict) else _jsonable(result)


class Session:
    """A measurement run. All probes in a session share one clock and one log.

    Parameters
    ----------
    target:
        Default target (``host`` or ``host:port``) for probes.
    out_dir:
        Directory for records/manifest/pcap. Defaults to ``runs/<run_id>``.
    persist:
        If False nothing is written to disk (useful in notebooks and tests).
    sqlite:
        Also write records to ``records.sqlite``.
    """

    def __init__(
        self,
        target: str | None = None,
        *,
        out_dir: str | Path | None = None,
        run_id: str | None = None,
        persist: bool = True,
        sqlite: bool = False,
        label: str | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
        self.target = target
        self.label = label
        self.clock = clock or Clock()
        if persist:
            self.out_dir: Path | None = Path(out_dir) if out_dir else Path("runs") / self.run_id
            self.out_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.out_dir = None
        self._storage = _storage.open_storage(self.out_dir, sqlite=sqlite)
        self._lock = threading.Lock()
        self._records: list[Record] = []
        self._handles: list[ProbeHandle] = []
        self._invocations: list[dict] = []
        self._closed = False
        self._mp_ctx = mp.get_context("spawn")
        self._mp_stop: Any = None
        self.stop_event = threading.Event()
        self._started_wall = self.clock.rel_to_wall(0)

    # ------------------------------------------------------------------ emit
    def emit(
        self,
        probe: str,
        metric: str,
        value: float,
        unit: str | None = None,
        *,
        target: str | None = None,
        ts_ns: int | None = None,
        **meta: Any,
    ) -> Record:
        """Validate, timestamp and persist one measurement."""
        if self._closed:
            raise RuntimeError("session is closed")
        unit = validate(probe, metric, unit)
        value = float(value)
        if not math.isfinite(value):
            raise SchemaError(f"{probe}.{metric} value must be finite, got {value}")
        ts = self.clock.now_ns() if ts_ns is None else int(ts_ns)
        rec = Record(
            ts_monotonic=ts,
            ts_wall=self.clock.rel_to_wall(ts),
            probe=probe,
            target=target if target is not None else (self.target or ""),
            metric=metric,
            value=value,
            unit=unit,
            meta={k: _jsonable(v) for k, v in meta.items()},
        )
        with self._lock:
            self._records.append(rec)
            self._storage.write(rec)
        return rec

    # --------------------------------------------------------------- access
    @property
    def records(self) -> list[Record]:
        with self._lock:
            return sorted(self._records, key=lambda r: r.ts_monotonic)

    def query(
        self, probe: str | None = None, metric: str | None = None, target: str | None = None
    ) -> list[Record]:
        return [
            r
            for r in self.records
            if (probe is None or r.probe == probe)
            and (metric is None or r.metric == metric)
            and (target is None or r.target == target)
        ]

    # ------------------------------------------------------------ execution
    def run_probe(
        self,
        fn: Callable[..., Any],
        *,
        name: str | None = None,
        background: bool = False,
        isolate: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Run ``fn(sink, **kwargs)`` inside this session.

        ``background=True`` returns a :class:`ProbeHandle` immediately.
        ``isolate=True`` runs the probe in a separate *process* that rebuilds
        the session clock from its anchor; use it for CPU-heavy probes
        (load generation, capture) so they do not perturb timestamping in
        the other probes through the interpreter lock. ``fn`` must then be
        an importable module-level function.
        """
        name = name or getattr(fn, "__name__", "probe")
        self._invocations.append(
            {
                "probe": name,
                "function": f"{getattr(fn, '__module__', '?')}.{getattr(fn, '__qualname__', '?')}",
                "params": {k: _jsonable(v) for k, v in kwargs.items()},
                "background": background,
                "isolate": isolate,
                "started_s": self.clock.now_s(),
            }
        )
        if not background and not isolate:
            return fn(self, **kwargs)

        handle = ProbeHandle(name)
        if isolate:
            target_fn = self._isolated_runner(fn, kwargs, handle)
        else:

            def target_fn() -> None:
                try:
                    handle.result = fn(self, **kwargs)
                except BaseException as e:  # noqa: BLE001 - re-raised on join()
                    handle.error = e

        t = threading.Thread(target=target_fn, name=f"netprobe-{name}", daemon=True)
        handle._thread = t
        self._handles.append(handle)
        t.start()
        if not background:
            return handle.join()
        return handle

    def _isolated_runner(
        self, fn: Callable[..., Any], kwargs: dict, handle: ProbeHandle
    ) -> Callable[[], None]:
        if self._mp_stop is None:
            self._mp_stop = self._mp_ctx.Event()
            if self.stop_event.is_set():
                self._mp_stop.set()
        q = self._mp_ctx.Queue()
        proc = self._mp_ctx.Process(
            target=_child_main,
            args=(
                fn,
                self.clock.anchor.to_dict(),
                q,
                self._mp_stop,
                self.target,
                str(self.out_dir) if self.out_dir else None,
                kwargs,
            ),
            daemon=True,
        )

        def drain() -> None:
            proc.start()
            finished = False
            while not finished:
                try:
                    msg = q.get(timeout=0.2)
                except _queue.Empty:
                    if not proc.is_alive():
                        # Child exited; drain whatever is left without blocking.
                        try:
                            msg = q.get(timeout=0.5)
                        except _queue.Empty:
                            if handle.error is None and handle.result is None:
                                handle.error = RuntimeError(
                                    f"isolated probe {handle.name} exited "
                                    f"with code {proc.exitcode}"
                                )
                            break
                    else:
                        continue
                kind = msg[0]
                if kind == "rec":
                    _, probe, metric, value, unit, tgt, ts_ns, meta = msg
                    try:
                        self.emit(probe, metric, value, unit, target=tgt, ts_ns=ts_ns, **meta)
                    except BaseException as e:  # noqa: BLE001
                        handle.error = e
                elif kind == "result":
                    handle.result = msg[1]
                elif kind == "error":
                    handle.error = RuntimeError(f"isolated probe {handle.name} failed:\n{msg[1]}")
                elif kind == "done":
                    finished = True
            proc.join(timeout=5)

        return drain

    # convenience wrappers ---------------------------------------------------
    def delay(self, target: str | None = None, *, background: bool = False, **kw: Any) -> Any:
        """RTT / jitter / loss. See :func:`netprobe.probes.delay.run_delay`."""
        from netprobe.probes.delay import run_delay

        return self.run_probe(
            run_delay, name="delay", background=background, target=target or self.target, **kw
        )

    def bandwidth(self, target: str | None = None, *, background: bool = False, **kw: Any) -> Any:
        """TCP throughput. See :func:`netprobe.probes.bandwidth.run_bandwidth`."""
        from netprobe.probes.bandwidth import run_bandwidth

        return self.run_probe(
            run_bandwidth,
            name="bandwidth",
            background=background,
            target=target or self.target,
            **kw,
        )

    def stress(
        self,
        target: str | None = None,
        *,
        background: bool = False,
        isolate: bool = False,
        **kw: Any,
    ) -> Any:
        """Rate-limited load. See :func:`netprobe.probes.stress.run_stress`."""
        from netprobe.probes.stress import run_stress

        return self.run_probe(
            run_stress,
            name="stress",
            background=background,
            isolate=isolate,
            target=target or self.target,
            **kw,
        )

    def sniff(self, *, background: bool = False, isolate: bool = False, **kw: Any) -> Any:
        """Packet capture to pcap. See :func:`netprobe.probes.sniff.run_sniff`."""
        from netprobe.probes.sniff import run_sniff

        return self.run_probe(run_sniff, name="sniff", background=background, isolate=isolate, **kw)

    def congestion(self, emit: bool = True, **config: Any) -> Any:
        """Estimate congestion level/onset from the records collected so far."""
        from netprobe.probes.congestion import CongestionConfig, emit_congestion, estimate

        result = estimate(self.records, CongestionConfig(**config))
        if emit:
            emit_congestion(self, result)
        return result

    def correlate(self, **kw: Any) -> Any:
        from netprobe.analysis.correlate import correlate

        return correlate(self.records, manifest=self.manifest(), **kw)

    def report(self, path: str | Path | None = None, **kw: Any) -> Path:
        """Write the HTML + JSON correlation report and return the HTML path."""
        from netprobe.analysis.report import write_report

        if path is None:
            if self.out_dir is None:
                raise ValueError("persist=False session: pass an explicit report path")
            path = self.out_dir / "report.html"
        return write_report(self.records, self.manifest(), Path(path), **kw)

    # ---------------------------------------------------------- lifecycle
    def stop(self) -> None:
        """Ask all running probes to finish early."""
        self.stop_event.set()
        if self._mp_stop is not None:
            self._mp_stop.set()

    def wait(self, timeout: float | None = None) -> list[Any]:
        """Join all background probes; re-raises the first unobserved probe error."""
        results, first_error = [], None
        for h in list(self._handles):
            if h.error_observed:
                continue
            try:
                results.append(h.join(timeout))
            except BaseException as e:  # noqa: BLE001
                first_error = first_error or e
        if first_error is not None:
            raise first_error
        return results

    def manifest(self) -> dict:
        from netprobe import __version__
        from netprobe.utils.privileges import privilege_report

        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "netprobe",
            "version": __version__,
            "run_id": self.run_id,
            "label": self.label,
            "target": self.target,
            "started_wall": self._started_wall,
            "clock": {
                "source": "time.monotonic_ns (CLOCK_MONOTONIC on Linux)",
                "anchor": self.clock.anchor.to_dict(),
            },
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "privileges": privilege_report(),
            "invocations": list(self._invocations),
            "units": METRICS,
        }

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.wait()
        finally:
            manifest = self.manifest()
            manifest["ended_wall"] = self.clock.rel_to_wall(self.clock.now_ns())
            manifest["duration_s"] = self.clock.now_s()
            manifest["clock"]["drift_ns_at_close"] = self.clock.drift_ns()
            manifest["record_count"] = len(self._records)
            if self.out_dir is not None:
                _storage.write_manifest(self.out_dir, manifest)
            self._storage.close()
            self._closed = True

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.stop()
            try:
                self.close()
            except BaseException:  # noqa: BLE001 - keep the original exception
                pass
        else:
            self.close()


# ---------------------------------------------------------------------------
# Isolated (child-process) execution
# ---------------------------------------------------------------------------
class _QueueSink:
    """Sink used inside an isolated child process; forwards to the parent."""

    def __init__(self, anchor: dict, q: Any, stop_event: Any, target: str | None, out_dir):
        self.clock = Clock.from_anchor(ClockAnchor.from_dict(anchor))
        self._q = q
        self.stop_event = stop_event
        self.target = target
        self.out_dir = Path(out_dir) if out_dir else None

    def emit(self, probe, metric, value, unit=None, *, target=None, ts_ns=None, **meta):
        validate(probe, metric, unit)
        ts = self.clock.now_ns() if ts_ns is None else int(ts_ns)
        self._q.put(("rec", probe, metric, float(value), unit, target, ts, meta))


def _child_main(fn, anchor, q, stop_event, target, out_dir, kwargs) -> None:
    sink = _QueueSink(anchor, q, stop_event, target, out_dir)
    try:
        result = fn(sink, **kwargs)
        q.put(("result", _result_to_dict(result)))
    except BaseException:  # noqa: BLE001
        q.put(("error", traceback.format_exc()))
    finally:
        q.put(("done",))
        sys.stdout.flush()
