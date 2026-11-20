"""NetProbe: unified-clock network measurement.

Every probe (delay, bandwidth, congestion, stress, sniff) writes into one
record schema stamped by one monotonic clock, so that bandwidth pressure,
delay/jitter/loss, congestion onset and packet-capture evidence from the
same run can be correlated without manual alignment.

Typical use::

    from netprobe import Session

    with Session(target="10.0.0.2") as s:
        s.delay(count=50)
        s.bandwidth(duration=5)
        print(s.congestion().onset_s)
"""

from netprobe.core.clock import Clock, ClockAnchor
from netprobe.core.session import METRICS, ProbeHandle, Record, SchemaError, Session

__version__ = "0.1.0"

__all__ = [
    "Clock",
    "ClockAnchor",
    "METRICS",
    "ProbeHandle",
    "Record",
    "SchemaError",
    "Session",
    "__version__",
]
