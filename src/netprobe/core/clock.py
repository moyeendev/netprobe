"""Unified timestamp source.

All NetProbe records are stamped with *session-relative monotonic
nanoseconds* (``ts_monotonic``). A single anchor pairs one monotonic reading
with one wall-clock reading at session start; wall time for any record is
derived from that anchor rather than read independently. Consequences:

* Records from different probes (threads or child processes) are ordered on
  one axis that cannot jump when NTP steps the wall clock.
* Kernel packet timestamps, which are wall-clock based, are mapped onto the
  same axis through the anchor (:meth:`Clock.wall_ns_to_rel`).
* On Linux ``CLOCK_MONOTONIC`` is system-wide, so a child process can rebuild
  the identical clock from the serialized anchor (:meth:`Clock.from_anchor`).

The anchor is taken as the tightest of several ``mono, wall, mono`` bracket
readings; half the bracket width is recorded as ``uncertainty_ns``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

NS_PER_S = 1_000_000_000


@dataclass(frozen=True)
class ClockAnchor:
    """One simultaneous (monotonic, wall) reading."""

    mono_ns: int
    wall_ns: int
    uncertainty_ns: int

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> ClockAnchor:
        return cls(int(d["mono_ns"]), int(d["wall_ns"]), int(d["uncertainty_ns"]))


def take_anchor(
    mono_ns: Callable[[], int] = time.monotonic_ns,
    wall_ns: Callable[[], int] = time.time_ns,
    samples: int = 7,
) -> ClockAnchor:
    """Pair a monotonic and a wall reading, keeping the tightest bracket."""
    if samples < 1:
        raise ValueError("samples must be >= 1")
    best: tuple[int, int, int] | None = None
    for _ in range(samples):
        a = mono_ns()
        w = wall_ns()
        b = mono_ns()
        span = b - a
        if span < 0:
            raise RuntimeError("monotonic clock went backwards while anchoring")
        if best is None or span < best[2]:
            best = ((a + b) // 2, w, span)
    assert best is not None
    mid, w, span = best
    return ClockAnchor(mono_ns=mid, wall_ns=w, uncertainty_ns=(span + 1) // 2)


class Clock:
    """Session clock. ``now_ns()`` returns ns since the anchor (monotonic)."""

    def __init__(
        self,
        mono_ns: Callable[[], int] = time.monotonic_ns,
        wall_ns: Callable[[], int] = time.time_ns,
        anchor: ClockAnchor | None = None,
        anchor_samples: int = 7,
    ) -> None:
        self._mono = mono_ns
        self._wall = wall_ns
        self.anchor = anchor or take_anchor(mono_ns, wall_ns, anchor_samples)

    @classmethod
    def from_anchor(cls, anchor: ClockAnchor | dict) -> Clock:
        """Rebuild the session clock in another thread or process."""
        if isinstance(anchor, dict):
            anchor = ClockAnchor.from_dict(anchor)
        return cls(anchor=anchor)

    # -- reading -----------------------------------------------------------
    def now_ns(self) -> int:
        """Session-relative monotonic nanoseconds."""
        return self._mono() - self.anchor.mono_ns

    def now_s(self) -> float:
        return self.now_ns() / NS_PER_S

    # -- conversions ---------------------------------------------------------
    def mono_to_rel(self, mono_ns: int) -> int:
        """Absolute ``time.monotonic_ns()`` value -> session-relative ns."""
        return mono_ns - self.anchor.mono_ns

    def rel_to_wall(self, rel_ns: int) -> float:
        """Session-relative ns -> UNIX epoch seconds (derived, not re-read)."""
        return (self.anchor.wall_ns + rel_ns) / NS_PER_S

    def wall_ns_to_rel(self, wall_ns: int) -> int:
        """Wall-clock ns (e.g. kernel packet timestamp) -> session-relative ns."""
        return wall_ns - self.anchor.wall_ns

    def wall_s_to_rel(self, wall_s: float) -> int:
        return self.wall_ns_to_rel(round(wall_s * NS_PER_S))

    # -- diagnostics ---------------------------------------------------------
    def drift_ns(self) -> int:
        """Wall-clock movement relative to monotonic since the anchor.

        A non-zero value means the wall clock was slewed or stepped (NTP,
        manual change) during the session. Wall-stamped inputs such as
        kernel packet timestamps are then offset by this amount; NetProbe
        records it in the session manifest so the error is bounded.
        """
        now = take_anchor(self._mono, self._wall, samples=3)
        expected_wall = self.anchor.wall_ns + (now.mono_ns - self.anchor.mono_ns)
        return now.wall_ns - expected_wall
