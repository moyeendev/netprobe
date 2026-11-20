import threading
import time

import pytest

from netprobe.core.clock import Clock, ClockAnchor, take_anchor


def test_now_is_monotonic_under_threads():
    c = Clock()
    seen = []

    def worker():
        last = -1
        for _ in range(5000):
            t = c.now_ns()
            assert t >= last
            last = t
        seen.append(last)

    ts = [threading.Thread(target=worker) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(seen) == 4


def test_anchor_picks_tightest_bracket():
    seq = iter([0, 100, 1000,   2000, 2010, 3000,   5000, 5050, 9000])
    calls = iter([0, 1, 2, 3, 4, 5, 6, 7, 8])
    # mono values at positions 0,2 | 3,5 | 6,8 ; wall at 1,4,7
    vals = list(seq)
    idx = iter(calls)

    def mono():
        return vals[next(idx)]

    def wall():
        return vals[next(idx)]

    a = take_anchor(mono, wall, samples=3)
    # spans: 1000, 1000, 4000 -> first tightest wins
    assert a.mono_ns == 500 and a.wall_ns == 100 and a.uncertainty_ns == 500


def test_anchor_rejects_backwards_clock():
    vals = iter([10, 0, 5])
    with pytest.raises(RuntimeError):
        take_anchor(lambda: next(vals), lambda: 0, samples=1)


def test_wall_roundtrip_and_kernel_mapping():
    c = Clock(anchor=ClockAnchor(mono_ns=5_000, wall_ns=1_700_000_000_000_000_000,
                                 uncertainty_ns=0))
    assert c.rel_to_wall(0) == 1_700_000_000.0
    assert c.wall_ns_to_rel(1_700_000_000_250_000_000) == 250_000_000
    assert c.wall_s_to_rel(c.rel_to_wall(123_000_000)) == pytest.approx(123_000_000, abs=1000)
    assert c.mono_to_rel(5_500) == 500


def test_from_anchor_reproduces_clock():
    c = Clock()
    c2 = Clock.from_anchor(c.anchor.to_dict())
    a, b = c.now_ns(), c2.now_ns()
    assert abs(a - b) < 50_000_000  # same anchor, same system-wide monotonic source


def test_drift_detects_wall_step(fake_time):
    c = Clock(mono_ns=fake_time.mono_ns, wall_ns=fake_time.wall_ns)
    assert c.drift_ns() == 0
    fake_time.wall += 2_000_000  # NTP step of +2 ms
    assert c.drift_ns() == 2_000_000


def test_real_clock_tracks_sleep():
    c = Clock()
    t0 = c.now_ns()
    time.sleep(0.05)
    assert c.now_ns() - t0 >= 40_000_000
