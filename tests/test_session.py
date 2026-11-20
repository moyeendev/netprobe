import json

import pytest

from netprobe.core.session import METRICS, Record, SchemaError, Session, register_metric
from netprobe.core.storage import load_manifest, load_records


def test_emit_validates_schema(mem_session):
    r = mem_session.emit("delay", "rtt", 1.5, seq=3)
    assert r.unit == "ms" and r.target == "127.0.0.1" and r.meta == {"seq": 3}
    with pytest.raises(SchemaError):
        mem_session.emit("delay", "bogus", 1)
    with pytest.raises(SchemaError):
        mem_session.emit("nope", "rtt", 1)
    with pytest.raises(SchemaError):
        mem_session.emit("delay", "rtt", 1, unit="s")
    with pytest.raises(SchemaError):
        mem_session.emit("delay", "rtt", float("nan"))


def test_record_has_unified_fields(mem_session):
    r = mem_session.emit("bandwidth", "throughput", 1e6)
    assert set(r.to_dict()) == {"ts_monotonic", "ts_wall", "probe", "target", "metric",
                                "value", "unit", "meta"}
    assert Record.from_dict(json.loads(json.dumps(r.to_dict()))) == r
    assert r.ts_wall == pytest.approx(mem_session.clock.rel_to_wall(r.ts_monotonic))


def test_explicit_event_time(fixed_clock_session):
    r = fixed_clock_session.emit("delay", "lost", 1, ts_ns=42)
    assert r.ts_monotonic == 42 and r.ts_wall == 42 / 1e9


def test_register_custom_metric(mem_session):
    register_metric("custom", "temperature", "C")
    try:
        assert mem_session.emit("custom", "temperature", 40).unit == "C"
        with pytest.raises(SchemaError):
            register_metric("custom", "temperature", "K")
    finally:
        METRICS.pop("custom")


def test_persist_jsonl_sqlite_and_manifest(tmp_path):
    with Session(target="10.1.1.1", out_dir=tmp_path / "r", sqlite=True, label="t") as s:
        s.emit("delay", "rtt", 2.0)
        s.emit("delay", "rtt", 1.0, ts_ns=0)
    a = load_records(tmp_path / "r")
    b = load_records(tmp_path / "r" / "records.sqlite")
    assert [r.value for r in a] == [1.0, 2.0] == [r.value for r in b]
    m = load_manifest(tmp_path / "r")
    assert m["record_count"] == 2 and m["label"] == "t" and "anchor" in m["clock"]
    assert "drift_ns_at_close" in m["clock"]


def test_background_errors_surface(mem_session):
    def bad(sink):
        raise RuntimeError("boom")

    h = mem_session.run_probe(bad, background=True)
    with pytest.raises(RuntimeError, match="boom"):
        h.join()


def _child_probe(sink, n=5):
    for i in range(n):
        sink.emit("stress", "packets", i)
    return {"n": n}


def test_isolated_probe_shares_clock(tmp_path):
    with Session(target="127.0.0.1", out_dir=tmp_path) as s:
        t_before = s.clock.now_ns()
        res = s.run_probe(_child_probe, isolate=True, n=5)
        t_after = s.clock.now_ns()
    assert res == {"n": 5}
    recs = s.query("stress", "packets")
    assert [r.value for r in recs] == [0, 1, 2, 3, 4]
    assert all(t_before <= r.ts_monotonic <= t_after for r in recs)
