"""Controlled load generator (UDP), rate-limited with safe defaults.

Safety model (enforced in :func:`check_safety`, not only in the CLI):

* explicit acknowledgement is mandatory (``i_understand=True`` /
  ``--i-understand-this-sends-traffic``);
* default rate is :data:`DEFAULT_RATE_BPS` (10 Mbit/s), never "as fast as
  possible"; rates above :data:`HARD_MAX_RATE_BPS` are refused unless
  ``rate_cap_override=True``;
* duration is bounded by :data:`HARD_MAX_DURATION_S`;
* only private / loopback / link-local / CGNAT IPv4 targets are accepted
  unless ``allow_public=True``; multicast, broadcast and unspecified
  addresses are always refused.

Packets carry the ``NPST`` magic so ``netprobe server`` discards them
instead of echoing. ``raw=True`` sends hand-built IPv4/UDP headers through
an ``IPPROTO_RAW`` socket (to set TOS/TTL) and requires ``CAP_NET_RAW``.

Pacing uses a token bucket with a small burst (``burst_ms`` of traffic) and
``time.sleep`` between bursts so the generator yields the interpreter to
other probes; run it with ``isolate=True`` for the cleanest timestamps.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import asdict, dataclass

from netprobe.probes.delay import STRESS_MAGIC
from netprobe.utils import privileges
from netprobe.utils.net import DEFAULT_PORT, is_private_target, parse_target, resolve_ipv4

DEFAULT_RATE_BPS = 10_000_000
HARD_MAX_RATE_BPS = 1_000_000_000
DEFAULT_DURATION_S = 10.0
HARD_MAX_DURATION_S = 600.0
DEFAULT_PACKET = 1200
MIN_PACKET = 32
MAX_PACKET = 1472  # keeps a 1500-byte MTU frame unfragmented


class SafetyError(ValueError):
    """A stress request violated the safety policy."""


def check_safety(
    ip: str,
    *,
    rate_bps: float,
    duration: float,
    packet_size: int,
    i_understand: bool,
    allow_public: bool = False,
    rate_cap_override: bool = False,
) -> None:
    if not i_understand:
        raise SafetyError(
            "stress sends real traffic; pass i_understand=True "
            "(CLI: --i-understand-this-sends-traffic)"
        )
    if rate_bps <= 0:
        raise SafetyError("rate must be > 0")
    if rate_bps > HARD_MAX_RATE_BPS and not rate_cap_override:
        raise SafetyError(
            f"rate {rate_bps:.0f} bps exceeds hard cap {HARD_MAX_RATE_BPS} bps "
            "(override with rate_cap_override=True / --max-rate-override)"
        )
    if not 0 < duration <= HARD_MAX_DURATION_S:
        raise SafetyError(f"duration must be in (0, {HARD_MAX_DURATION_S}] s")
    if not MIN_PACKET <= packet_size <= MAX_PACKET:
        raise SafetyError(f"packet_size must be in [{MIN_PACKET}, {MAX_PACKET}]")
    if not is_private_target(ip):
        import ipaddress

        a = ipaddress.IPv4Address(ip)
        if a.is_multicast or a.is_unspecified or ip == "255.255.255.255":
            raise SafetyError(f"refusing multicast/broadcast/unspecified target {ip}")
        if not allow_public:
            raise SafetyError(
                f"refusing non-private target {ip}; pass allow_public=True "
                "(CLI: --allow-public-target) only for networks you are authorized to load"
            )


class TokenBucket:
    def __init__(self, rate_bps: float, burst_bytes: float, now_s: float) -> None:
        self.rate_Bps = rate_bps / 8.0
        self.burst = max(burst_bytes, 1.0)
        self.tokens = 0.0
        self.t = now_s

    def refill(self, now_s: float) -> None:
        self.tokens = min(self.burst, self.tokens + (now_s - self.t) * self.rate_Bps)
        self.t = now_s

    def take(self, n: int) -> bool:
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def wait_for(self, n: int) -> float:
        return max(0.0, (n - self.tokens) / self.rate_Bps)


@dataclass
class StressSummary:
    target: str
    rate_bps: float
    duration_s: float
    packets: int
    bytes: int
    achieved_bps: float
    start_s: float
    stop_s: float

    def to_dict(self) -> dict:
        return asdict(self)


def _ipv4_udp_header(src: str, dst: str, sport: int, dport: int, payload_len: int,
                     tos: int, ttl: int) -> bytes:
    total = 20 + 8 + payload_len
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, tos & 0xFF, total, 0, 0, ttl & 0xFF, socket.IPPROTO_UDP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # kernel fills checksum (and id when 0) for IPPROTO_RAW
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)  # UDP checksum optional (v4)
    return ip + udp


def run_stress(
    sink,
    target: str | None = None,
    *,
    rate_bps: float = DEFAULT_RATE_BPS,
    duration: float = DEFAULT_DURATION_S,
    packet_size: int = DEFAULT_PACKET,
    start_delay: float = 0.0,
    port: int = DEFAULT_PORT,
    i_understand: bool = False,
    allow_public: bool = False,
    rate_cap_override: bool = False,
    raw: bool = False,
    tos: int = 0,
    ttl: int = 64,
    report_interval: float = 0.25,
    burst_ms: float = 2.0,
) -> StressSummary:
    target = target or sink.target
    if not target:
        raise ValueError("stress probe needs a target")
    host, port = parse_target(target, port)
    ip = resolve_ipv4(host)
    check_safety(ip, rate_bps=rate_bps, duration=duration, packet_size=packet_size,
                 i_understand=i_understand, allow_public=allow_public,
                 rate_cap_override=rate_cap_override)
    label = f"{ip}:{port}"
    if raw:
        privileges.require("raw-socket stress (--raw)", ["CAP_NET_RAW"])
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.connect((ip, port))
        src = probe_sock.getsockname()[0]
        probe_sock.close()
        sport = 40000 + (id(sock) % 20000)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((ip, port))

    if start_delay > 0 and sink.stop_event.wait(start_delay):
        sock.close()
        return StressSummary(label, rate_bps, 0.0, 0, 0, 0.0, 0.0, 0.0)

    clock = sink.clock
    payload_body = STRESS_MAGIC + b"\x00" * (packet_size - len(STRESS_MAGIC))
    frame = (_ipv4_udp_header(src, ip, sport, port, packet_size, tos, ttl) + payload_body
             if raw else payload_body)
    wire_bytes = packet_size  # rate accounting on UDP payload bytes
    t0 = clock.now_ns()
    sink.emit("stress", "event", 1, target=label, ts_ns=t0, event="start", rate_bps=rate_bps,
              packet_size=packet_size, raw=raw)
    bucket = TokenBucket(rate_bps, rate_bps / 8.0 * burst_ms / 1000.0 + wire_bytes, t0 / 1e9)
    t_end = t0 + int(duration * 1e9)
    report_ns = int(report_interval * 1e9)
    next_report = t0 + report_ns
    last_report = t0
    packets = total_bytes = 0
    win_packets = win_bytes = 0
    try:
        while not sink.stop_event.is_set():
            now = clock.now_ns()
            if now >= t_end:
                break
            bucket.refill(now / 1e9)
            while bucket.take(wire_bytes):
                try:
                    if raw:
                        sock.sendto(frame, (ip, 0))
                    else:
                        sock.send(frame)
                except (BlockingIOError, ConnectionRefusedError, OSError):
                    continue  # dropped locally; rate accounting stays honest
                packets += 1
                total_bytes += wire_bytes
                win_packets += 1
                win_bytes += wire_bytes
            now = clock.now_ns()
            if now >= next_report:
                dt = (now - last_report) / 1e9
                sink.emit("stress", "offered_rate", win_bytes * 8 / dt, target=label, ts_ns=now,
                          window_ns=now - last_report)
                sink.emit("stress", "packets", win_packets, target=label, ts_ns=now)
                win_packets = win_bytes = 0
                last_report = now
                next_report += report_ns
            sleep_s = min(bucket.wait_for(wire_bytes), (next_report - now) / 1e9,
                          (t_end - now) / 1e9)
            time.sleep(max(sleep_s, 0.0002))
    finally:
        sock.close()
    t1 = clock.now_ns()
    sink.emit("stress", "event", 0, target=label, ts_ns=t1, event="stop", packets=packets,
              bytes=total_bytes)
    elapsed = (t1 - t0) / 1e9
    return StressSummary(
        target=label, rate_bps=rate_bps, duration_s=elapsed, packets=packets, bytes=total_bytes,
        achieved_bps=total_bytes * 8 / max(elapsed, 1e-9), start_s=t0 / 1e9, stop_s=t1 / 1e9,
    )
