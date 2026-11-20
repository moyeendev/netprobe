"""Delay probe: RTT, jitter (RFC 3550 estimator) and loss.

Modes
-----
``udp``  (default, unprivileged) — UDP echo against ``netprobe server``.
``tcp``  (unprivileged, no server) — TCP handshake time to any open/closed port.
``icmp`` — ICMP echo; unprivileged via ``SOCK_DGRAM`` when
           ``net.ipv4.ping_group_range`` allows it, else needs CAP_NET_RAW.

Timestamp semantics
-------------------
An RTT sample's ``ts_monotonic`` is the probe's *departure* time (the moment
the network was sampled); its arrival time is in ``meta.recv_ns``. A lost
probe produces a ``lost`` record (value 1) at its departure time once the
timeout expires. Duplicate and late (post-timeout) replies are ignored.

Jitter
------
RFC 3550 §6.4.1 defines ``J += (|D| - J) / 16`` with ``D`` the difference in
transit time between consecutive packets. For a round-trip measurement
``D_i = RTT_i - RTT_{i-1}`` over consecutively *received* probes.
"""

from __future__ import annotations

import os
import select
import socket
import statistics
import struct
import threading
from dataclasses import asdict, dataclass

from netprobe.utils import privileges
from netprobe.utils.net import DEFAULT_PORT, parse_target, resolve_ipv4

MAGIC = b"NPRB"
STRESS_MAGIC = b"NPST"
HDR = struct.Struct("!4sIQ")  # magic, seq (u32), departure ns (u64)
MIN_SIZE = HDR.size


class JitterEstimator:
    """RFC 3550 interarrival jitter, applied to RTT samples (milliseconds)."""

    def __init__(self) -> None:
        self.value = 0.0
        self._prev: float | None = None

    def update(self, rtt_ms: float) -> float:
        if self._prev is not None:
            d = abs(rtt_ms - self._prev)
            self.value += (d - self.value) / 16.0
        self._prev = rtt_ms
        return self.value


@dataclass
class DelaySummary:
    target: str
    mode: str
    sent: int
    received: int
    lost: int
    loss: float
    rtt_min_ms: float | None
    rtt_mean_ms: float | None
    rtt_median_ms: float | None
    rtt_max_ms: float | None
    rtt_stdev_ms: float | None
    jitter_ms: float

    def to_dict(self) -> dict:
        return asdict(self)


def summarize(target: str, mode: str, rtts: list[float], sent: int, jitter: float) -> DelaySummary:
    received = len(rtts)
    lost = sent - received
    return DelaySummary(
        target=target,
        mode=mode,
        sent=sent,
        received=received,
        lost=lost,
        loss=(lost / sent) if sent else 0.0,
        rtt_min_ms=min(rtts) if rtts else None,
        rtt_mean_ms=statistics.fmean(rtts) if rtts else None,
        rtt_median_ms=statistics.median(rtts) if rtts else None,
        rtt_max_ms=max(rtts) if rtts else None,
        rtt_stdev_ms=statistics.stdev(rtts) if len(rtts) > 1 else None,
        jitter_ms=jitter,
    )


def build_payload(seq: int, t_ns: int, size: int) -> bytes:
    hdr = HDR.pack(MAGIC, seq & 0xFFFFFFFF, t_ns & 0xFFFFFFFFFFFFFFFF)
    return hdr + b"\x00" * max(0, size - len(hdr))


def parse_payload(data: bytes) -> int | None:
    if len(data) < HDR.size:
        return None
    magic, seq, _ = HDR.unpack_from(data)
    return seq if magic == MAGIC else None


# ---------------------------------------------------------------------------
# Echo server (used by udp mode)
# ---------------------------------------------------------------------------
class UdpEchoServer:
    """Echoes NetProbe delay probes; silently discards stress traffic."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.echoed = 0
        self.discarded = 0

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if data[:4] == MAGIC:
                try:
                    self.sock.sendto(data, addr)
                    self.echoed += 1
                except OSError:
                    pass
            else:
                self.discarded += 1

    def start(self) -> UdpEchoServer:
        self._thread = threading.Thread(target=self.serve_forever, name="np-echo", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.sock.close()

    def __enter__(self) -> UdpEchoServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Pingers: send(seq) / recv(timeout) -> (seq, recv_rel_ns) | None
# ---------------------------------------------------------------------------
class UdpPinger:
    def __init__(self, ip: str, port: int, size: int, clock) -> None:
        self.clock = clock
        self.size = max(size, MIN_SIZE)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((ip, port))
        self.sock.setblocking(False)

    def send(self, seq: int, t_ns: int) -> None:
        try:
            self.sock.send(build_payload(seq, t_ns, self.size))
        except (BlockingIOError, ConnectionRefusedError, ConnectionResetError):
            pass  # counted as loss by timeout

    def recv(self, timeout_s: float) -> tuple[int, int] | None:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout_s))
        if not r:
            return None
        try:
            data = self.sock.recv(65535)
        except (BlockingIOError, ConnectionRefusedError, ConnectionResetError, OSError):
            return None
        t = self.clock.now_ns()
        seq = parse_payload(data)
        return None if seq is None else (seq, t)

    def close(self) -> None:
        self.sock.close()


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_icmp_echo(ident: int, seq16: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq16)
    csum = icmp_checksum(hdr + payload)
    return struct.pack("!BBHHH", 8, 0, csum, ident, seq16) + payload


class IcmpPinger:
    def __init__(self, ip: str, size: int, clock) -> None:
        self.clock = clock
        self.ip = ip
        self.size = max(size, MIN_SIZE)
        self.ident = os.getpid() & 0xFFFF
        self.raw = False
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            if not privileges.has_capability("CAP_NET_RAW"):
                raise privileges.PrivilegeError(
                    "ICMP delay mode",
                    ["CAP_NET_RAW"],
                    "Unprivileged ICMP is disabled (sysctl net.ipv4.ping_group_range).\n"
                    "Use --mode udp or --mode tcp, or:\n"
                    + privileges.elevation_hint(["CAP_NET_RAW"]),
                ) from None
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.raw = True
        self.sock.setblocking(False)

    def send(self, seq: int, t_ns: int) -> None:
        pkt = build_icmp_echo(self.ident, seq & 0xFFFF, build_payload(seq, t_ns, self.size))
        try:
            self.sock.sendto(pkt, (self.ip, 0))
        except (BlockingIOError, OSError):
            pass

    def recv(self, timeout_s: float) -> tuple[int, int] | None:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout_s))
        if not r:
            return None
        try:
            data, addr = self.sock.recvfrom(65535)
        except (BlockingIOError, OSError):
            return None
        t = self.clock.now_ns()
        if self.raw:
            ihl = (data[0] & 0x0F) * 4
            data = data[ihl:]
            if addr[0] != self.ip:
                return None
        if len(data) < 8 or data[0] != 0:  # echo reply
            return None
        if self.raw and struct.unpack_from("!H", data, 4)[0] != self.ident:
            return None
        seq = parse_payload(data[8:])
        return None if seq is None else (seq, t)

    def close(self) -> None:
        self.sock.close()


# ---------------------------------------------------------------------------
# Probe entry point
# ---------------------------------------------------------------------------
def run_delay(
    sink,
    target: str | None = None,
    *,
    mode: str = "udp",
    count: int = 100,
    interval: float = 0.2,
    size: int = 64,
    timeout: float = 1.0,
    port: int = DEFAULT_PORT,
) -> DelaySummary:
    """Send ``count`` probes every ``interval`` s and emit rtt/jitter/lost."""
    target = target or sink.target
    if not target:
        raise ValueError("delay probe needs a target")
    if count < 1 or interval <= 0 or timeout <= 0:
        raise ValueError("count >= 1, interval > 0, timeout > 0 required")
    host, port = parse_target(target, port)
    ip = resolve_ipv4(host)
    label = f"{ip}:{port}" if mode == "udp" else ip if mode == "icmp" else f"{ip}:{port}"
    if mode == "tcp":
        return _run_tcp_connect(sink, ip, port, label, count, interval, timeout)
    if mode == "udp":
        pinger = UdpPinger(ip, port, size, sink.clock)
    elif mode == "icmp":
        pinger = IcmpPinger(ip, size, sink.clock)
    else:
        raise ValueError(f"unknown delay mode {mode!r}")

    clock = sink.clock
    interval_ns = int(interval * 1e9)
    timeout_ns = int(timeout * 1e9)
    pending: dict[int, int] = {}
    rtts: list[float] = []
    jit = JitterEstimator()
    seq = 0
    next_send = clock.now_ns()
    try:
        while not sink.stop_event.is_set():
            now = clock.now_ns()
            if seq < count and now >= next_send:
                t_send = clock.now_ns()
                pinger.send(seq, t_send)
                pending[seq] = t_send
                seq += 1
                next_send += interval_ns
                if next_send < now - interval_ns:  # fell far behind: resynchronize
                    next_send = now + interval_ns
            for s, t in list(pending.items()):
                if now - t > timeout_ns:
                    del pending[s]
                    sink.emit("delay", "lost", 1, target=label, ts_ns=t, seq=s, mode=mode)
            if seq >= count and not pending:
                break
            if seq < count:
                wait_ns = next_send - clock.now_ns()
            else:
                wait_ns = min(t + timeout_ns for t in pending.values()) - clock.now_ns()
            got = pinger.recv(max(0, wait_ns) / 1e9)
            if got is None:
                continue
            s, t_recv = got
            t_send = pending.pop(s, None)
            if t_send is None:
                continue  # duplicate or late reply
            rtt_ms = (t_recv - t_send) / 1e6
            rtts.append(rtt_ms)
            j = jit.update(rtt_ms)
            sink.emit(
                "delay", "rtt", rtt_ms, target=label, ts_ns=t_send, seq=s, recv_ns=t_recv,
                mode=mode,
            )
            sink.emit("delay", "jitter", j, target=label, ts_ns=t_send, seq=s, mode=mode)
    finally:
        pinger.close()
    summary = summarize(label, mode, rtts, seq, jit.value)
    sink.emit("delay", "sent", summary.sent, target=label, mode=mode)
    sink.emit("delay", "loss", summary.loss, target=label, mode=mode)
    return summary


def _run_tcp_connect(sink, ip, port, label, count, interval, timeout) -> DelaySummary:
    clock = sink.clock
    rtts: list[float] = []
    jit = JitterEstimator()
    sent = 0
    next_send = clock.now_ns()
    for s in range(count):
        if sink.stop_event.is_set():
            break
        wait = (next_send - clock.now_ns()) / 1e9
        if wait > 0:
            sink.stop_event.wait(wait)
        t0 = clock.now_ns()
        sent += 1
        refused = False
        try:
            conn = socket.create_connection((ip, port), timeout=timeout)
            t1 = clock.now_ns()
            conn.close()
        except ConnectionRefusedError:
            t1 = clock.now_ns()  # an RST is still a round trip
            refused = True
        except (TimeoutError, OSError):
            sink.emit("delay", "lost", 1, target=label, ts_ns=t0, seq=s, mode="tcp")
            next_send = t0 + int(interval * 1e9)
            continue
        rtt_ms = (t1 - t0) / 1e6
        rtts.append(rtt_ms)
        j = jit.update(rtt_ms)
        sink.emit("delay", "rtt", rtt_ms, target=label, ts_ns=t0, seq=s, recv_ns=t1,
                  mode="tcp", refused=refused)
        sink.emit("delay", "jitter", j, target=label, ts_ns=t0, seq=s, mode="tcp")
        next_send = t0 + int(interval * 1e9)
    summary = summarize(label, "tcp", rtts, sent, jit.value)
    sink.emit("delay", "sent", summary.sent, target=label, mode="tcp")
    sink.emit("delay", "loss", summary.loss, target=label, mode="tcp")
    return summary

