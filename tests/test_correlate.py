"""Correlation correctness on synthetic runs with known ground truth."""

import random

import pytest

from netprobe.analysis import correlate as C
from netprobe.analysis.report import render_html, write_report
from netprobe.probes.congestion import CongestionConfig, estimate

S = 1_000_000_000


def synth(s, onset=10.0, end=30.0, stop=20.0, seed=1, with_stress=True, with_sniff=True):
    """Baseline RTT 20 ms / 50 Mbit/s; congested 60 ms / 20 Mbit/s / 5% loss."""
    rnd = random.Random(seed)
    t = 0.0
    seq = 0
    while t < end:
        cong = onset <= t < stop
        ns = int(t * S)
        if cong and rnd.random() < 0.05:
            s.emit("delay", "lost", 1, ts_ns=ns, seq=seq)
        else:
            base = 60.0 if cong else 20.0
            s.emit("delay", "rtt", base + rnd.gauss(0, 1.0), ts_ns=ns, seq=seq)
            s.emit("delay", "jitter", 1.0, ts_ns=ns, seq=seq)
        seq += 1
        t = round(t + 0.05, 6)
    t = 0.25
    while t <= end:
        cong = onset <= t < stop
        s.emit("bandwidth", "throughput", (20e6 if cong else 50e6) * (1 + rnd.gauss(0, 0.02)),
               ts_ns=int(t * S), window_ns=int(0.25 * S))
        t = round(t + 0.25, 6)
    if with_stress:
        s.emit("stress", "event", 1, ts_ns=int(onset * S), event="start", rate_bps=30e6)
        t = onset + 0.25
        while t <= stop:
            s.emit("stress", "offered_rate", 30e6, ts_ns=int(t * S))
            t = round(t + 0.25, 6)
        s.emit("stress", "event", 0, ts_ns=int(stop * S), event="stop")
    if with_sniff:
        frame = 1
        for b in range(int(end / 0.5)):
            ts = int((b + 1) * 0.5 * S)
            cong = onset <= b * 0.5 < stop
            n = 400
            meta = dict(frame_first=frame, frame_last=frame + n - 1, pcap="capture.pcap",
                        bin_ns=S // 2)
            s.emit("sniff", "pkts", n, ts_ns=ts, **meta)
            s.emit("sniff", "tcp_retrans", 12 if cong else 0, ts_ns=ts, **meta)
            frame += n


@pytest.mark.parametrize("onset", [8.0, 10.0, 13.0])
def test_onset_detected_within_one_window(fixed_clock_session, onset):
    synth(fixed_clock_session, onset=onset, stop=onset + 10)
    c = fixed_clock_session.correlate()
    assert c.onset_s is not None
    assert abs(c.onset_s - onset) <= 1.0
    assert abs(c.onset_error_s) <= 1.0
    # decision is taken at the end of the persistence run (2 windows of 1 s)
    assert c.congestion.decision_s == pytest.approx(c.onset_s + 2.0)
    assert 1.0 <= c.detection_latency_s <= 3.0
    assert c.recovery_s == pytest.approx(onset + 10, abs=1.0)


def test_no_false_onset_without_congestion(fixed_clock_session):
    synth(fixed_clock_session, onset=1e9, stop=1e9, with_stress=False)
    c = fixed_clock_session.correlate()
    assert c.onset_s is None
    assert all(not w.congested for w in c.congestion.windows)


def test_onset_without_stress_marker_uses_baseline_period(fixed_clock_session):
    synth(fixed_clock_session, onset=12.0, stop=22.0, with_stress=False)
    c = fixed_clock_session.correlate()
    assert c.onset_s == pytest.approx(12.0, abs=1.0)
    assert "before_onset" in c.phases and "congested" in c.phases


def test_phase_statistics_and_lags(fixed_clock_session):
    synth(fixed_clock_session)
    c = fixed_clock_session.correlate()
    base, load = c.phases["baseline"], c.phases["load"]
    assert base["rtt_median_ms"] == pytest.approx(20, abs=1)
    assert load["rtt_median_ms"] == pytest.approx(60, abs=1)
    assert base["throughput_mean_bps"] == pytest.approx(50e6, rel=0.02)
    assert load["throughput_mean_bps"] == pytest.approx(20e6, rel=0.02)
    assert base["loss"] == 0 and 0.02 < load["loss"] < 0.09
    assert load["wire_retrans"] > 0 and base["wire_retrans"] == 0
    assert c.lags["load->rtt"]["r"] > 0.9
    assert c.lags["load->throughput"]["r"] < -0.9
    assert abs(c.lags["load->rtt"]["lag_s"]) <= 0.5


def test_capture_evidence_points_at_onset_frames(fixed_clock_session):
    synth(fixed_clock_session, onset=10.0)
    c = fixed_clock_session.correlate()
    ev = c.evidence
    assert ev["pcap"] == "capture.pcap" and ev["tcp_retrans"] > 0
    # bins are 400 frames; bin covering t in (10, 10.5] is bin index 20 -> frames 8001..
    assert ev["frame_first"] == 20 * 400 + 1


def test_timeline_alignment_and_aggregation(fixed_clock_session):
    s = fixed_clock_session
    s.emit("delay", "rtt", 1, ts_ns=0)
    s.emit("delay", "rtt", 3, ts_ns=100)
    s.emit("delay", "rtt", 100, ts_ns=200)
    s.emit("delay", "lost", 1, ts_ns=S // 2 + 1)
    s.emit("delay", "lost", 1, ts_ns=S // 2 + 2)
    s.emit("bandwidth", "throughput", 10, ts_ns=S)
    tl = C.build_timeline(s.records, bin_s=0.5)
    assert tl.t == [0.0, 0.5, 1.0]
    assert tl.series["delay.rtt"] == [3, None, None]  # median
    assert tl.series["delay.lost"] == [None, 2.0, None]  # sum
    assert tl.series["bandwidth.throughput"][2] == 10
    assert "delay.loss" not in tl.series  # summaries are not series
    assert tl.to_csv().splitlines()[0] == "t_s,bandwidth.throughput,delay.lost,delay.rtt"


def test_pearson_and_lag():
    x = [0, 0, 1, 1, 0, 0, 1, 1, 0, 0] * 3
    y = [0, 0] + x[:-2]
    assert C.pearson(x, x) == pytest.approx(1.0)
    best = max((p for p in C.lagged_correlation(x, y, 4) if p[1] is not None),
               key=lambda p: p[1])
    assert best[0] == 2
    assert C.pearson([1, 1, 1], [1, 2, 3]) is None


def test_estimate_signal_degradation_when_only_rtt():
    from netprobe.core.session import Record

    recs = [Record(int(t * 0.05 * S), 0, "delay", "x", "rtt", 10.0 if t < 200 else 40.0, "ms")
            for t in range(400)]
    res = estimate(recs, CongestionConfig())
    assert res.onset_s == pytest.approx(10.0, abs=1.0)
    assert res.windows[-1].available == 2  # rtt + loss (derived from delay), no throughput


def test_report_files(tmp_path, fixed_clock_session):
    synth(fixed_clock_session)
    p = write_report(fixed_clock_session.records, {"run_id": "x", "target": "t"},
                     tmp_path / "report.html")
    html = p.read_text(encoding="utf-8")
    assert "Congestion onset" in html and "prefers-color-scheme:dark" in html
    assert (tmp_path / "report.json").exists() and (tmp_path / "timeline.csv").exists()
    corr = C.correlate(fixed_clock_session.records)
    assert "</script><script" not in render_html(corr, {})[:200]
