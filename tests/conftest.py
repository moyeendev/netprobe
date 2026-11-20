import pytest

from netprobe.core.clock import Clock, ClockAnchor
from netprobe.core.session import Session


class FakeTime:
    """Deterministic monotonic + wall sources."""

    def __init__(self, mono=1_000_000_000, wall=1_700_000_000_000_000_000, step=0):
        self.mono = mono
        self.wall = wall
        self.step = step

    def mono_ns(self):
        self.mono += self.step
        return self.mono

    def wall_ns(self):
        return self.wall + (self.mono - 1_000_000_000)


@pytest.fixture
def fake_time():
    return FakeTime()


@pytest.fixture
def mem_session():
    s = Session(target="127.0.0.1", persist=False)
    yield s
    s.close()


@pytest.fixture
def fixed_clock_session():
    """Session with a clock anchored at mono=0/wall=0 so ts_ns are literal."""
    clock = Clock(anchor=ClockAnchor(0, 0, 0))
    s = Session(target="10.0.0.2", persist=False, clock=clock)
    yield s
    s.close()
