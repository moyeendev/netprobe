"""Bandwidth probe: TCP bulk transfer against ``netprobe server``.

Directions
----------
``up`` (default): client sends. Per-interval throughput is computed from the
kernel's ``tcpi_bytes_acked`` counter (Linux ``TCP_INFO``), i.e. bytes the
*receiver acknowledged*, which avoids the send-buffer bias of counting
``send()`` calls. Where ``TCP_INFO`` is unavailable the probe falls back to
bytes handed to the socket (``meta.basis == "sent"``). The same ``TCP_INFO``
sample gives smoothed RTT, congestion window and retransmissions, which
become first-class records on the session timeline. At the end the server
returns the byte count it received; ``goodput_total`` is computed from it.

``down``: server sends, client counts received bytes per interval.

Per-interval records are stamped at the interval end; ``meta.window_ns``
gives the interval length.

Protocol: client sends one JSON line ``{"dir": "up"|"down", "duration": s}``;
for ``up`` the server answers after EOF with ``{"bytes": N, "elapsed": s}``.
"""

from __future__ import annotations

import json
import select
import socket
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass

from netprobe.utils.net import DEFAULT_PORT, parse_target, resolve_ipv4

CHUNK = 64 * 1024
MSS_HINT = 1448  # minimum send unit for the pacer
MAX_HEADER = 1024

# struct tcp_info (linux/tcp.h): 8 x u8, 24 x u32, then 4 x u64 on kernels >= 4.1
_TI_BASE = struct.Struct("=8B24I")
_TI_EXT = struct.Struct("=8B24I4Q")
TCP_INFO_LEN = 232  # ask for more than we parse; kernel truncates to its size


def parse_tcp_info(raw: bytes) -> dict | None:
    """Decode the fields NetProbe uses from a ``TCP_INFO`` buffer."""
    if len(raw) < _TI_BASE.size:
        return None
    if len(raw) >= _TI_EXT.size:
        v = _TI_EXT.unpack_from(raw)
        bytes_acked = v[32 + 2]
    else:
        v = _TI_BASE.unpack_from(raw)
        bytes_acked = None
    u = v[8:]
    return {
        "state": v[0],
        "ca_state": v[1],
        "snd_mss": u[2],
        "lost": u[6],
        "retrans": u[7],
        "rtt_us": u[15],
        "rttvar_us": u[16],
        "snd_ssthresh": u[17],
        "snd_cwnd": u[18],
        "total_retrans": u[23],
        "bytes_acked": bytes_acked,
    }


def read_tcp_info(sock: socket.socket) -> dict | None:
    opt = getattr(socket, "TCP_INFO", None)
    if opt is None:
        return None
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, opt, TCP_INFO_LEN)
    except OSError:
        return None
    return parse_tcp_info(raw)


@dataclass
class BandwidthSummary:
    target: str
    direction: str
    duration_s: float
    bytes: int
    mean_bps: float
    server_bytes: int | None
    server_bps: float | None
    retrans_total: int | None
    basis: str
    samples: int

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class BandwidthServer:
    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _read_header(self, conn: socket.socket) -> tuple[dict, bytes]:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(MAX_HEADER)
            if not chunk:
                raise ConnectionError("client closed before header")
            buf += chunk
            if len(buf) > MAX_HEADER and b"\n" not in buf:
                raise ValueError("header too long")
        line, rest = buf.split(b"\n", 1)
        return json.loads(line), rest

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(30)
        try:
            hdr, rest = self._read_header(conn)
            direction = hdr.get("dir", "up")
            if direction == "up":
                total = len(rest)
                t0 = time.monotonic()
                while True:
                    chunk = conn.recv(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                elapsed = time.monotonic() - t0
                conn.sendall(json.dumps({"bytes": total, "elapsed": elapsed}).encode() + b"\n")
            elif direction == "down":
                duration = min(float(hdr.get("duration", 10)), 3600.0)
                end = time.monotonic() + duration
                buf = b"\x00" * CHUNK
                while time.monotonic() < end and not self._stop.is_set():
                    conn.sendall(buf)
        except (OSError, ValueError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def start(self) -> BandwidthServer:
        self._thread = threading.Thread(target=self.serve_forever, name="np-bw", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.sock.close()

    def __enter__(self) -> BandwidthServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def run_bandwidth(
    sink,
    target: str | None = None,
    *,
    duration: float = 10.0,
    direction: str = "up",
    interval: float = 0.25,
    port: int = DEFAULT_PORT,
    chunk: int = CHUNK,
    connect_timeout: float = 5.0,
    rate_bps: float | None = None,
) -> BandwidthSummary:
    """Bulk TCP transfer. ``rate_bps`` (upload only) paces the application
    send rate, turning the probe into a controlled *bandwidth-pressure*
    source that does not by itself saturate the path; ``None`` = unpaced."""
    target = target or sink.target
    if not target:
        raise ValueError("bandwidth probe needs a target")
    if duration <= 0 or interval <= 0:
        raise ValueError("duration and interval must be > 0")
    if direction not in ("up", "down"):
        raise ValueError("direction must be 'up' or 'down'")
    if rate_bps is not None and (rate_bps <= 0 or direction != "up"):
        raise ValueError("rate_bps must be > 0 and is only supported for direction='up'")
    host, port = parse_target(target, port)
    ip = resolve_ipv4(host)
    label = f"{ip}:{port}"
    sock = socket.create_connection((ip, port), timeout=connect_timeout)
    sock.sendall(json.dumps({"dir": direction, "duration": duration}).encode() + b"\n")
    try:
        if direction == "up":
            return _upload(sink, sock, label, duration, interval, chunk, rate_bps)
        return _download(sink, sock, label, duration, interval)
    finally:
        sock.close()


def _upload(sink, sock, label, duration, interval, chunk, rate_bps=None) -> BandwidthSummary:
    clock = sink.clock
    buf = b"\x00" * chunk
    interval_ns = int(interval * 1e9)
    info0 = read_tcp_info(sock)
    use_acked = bool(info0 and info0["bytes_acked"] is not None)
    basis = "acked" if use_acked else "sent"
    base_acked = info0["bytes_acked"] if use_acked else 0
    base_retrans = info0["total_retrans"] if info0 else 0
    sent = 0
    last_count, last_retrans = 0, 0
    t_start = clock.now_ns()
    t_end = t_start + int(duration * 1e9)
    last_t = t_start
    next_sample = t_start + interval_ns
    samples = 0
    bucket = None
    if rate_bps is not None:
        from netprobe.probes.stress import TokenBucket

        # burst: 5 ms of data on Linux (fine-grained sleeps), 20 ms elsewhere
        # (e.g. ~15.6 ms Windows timer); at least 4 segments
        burst_s = 0.005 if sys.platform.startswith("linux") else 0.02
        bucket = TokenBucket(rate_bps, max(4 * MSS_HINT, rate_bps / 8 * burst_s), t_start / 1e9)
        bucket.tokens = MSS_HINT
    sock.setblocking(False)
    while not sink.stop_event.is_set():
        now = clock.now_ns()
        if now >= t_end:
            break
        timeout = max(0, min(next_sample, t_end) - now) / 1e9
        budget = chunk
        if rate_bps is not None:
            # Token bucket with burst capped at one chunk: credit that could not
            # be used (e.g. while the path was congested) is discarded, so the
            # flow never "catches up" with a burst above its configured rate.
            bucket.refill(now / 1e9)
            budget = int(min(bucket.tokens, chunk))
            if budget < MSS_HINT:
                sink.stop_event.wait(max(0.0002, min(bucket.wait_for(MSS_HINT), timeout)))
                budget = 0
        if budget > 0:
            _, w, _ = select.select([], [sock], [], timeout)
            if w:
                try:
                    n = sock.send(buf[:budget])
                    sent += n
                    if bucket is not None:
                        bucket.tokens -= n
                except (BlockingIOError, InterruptedError):
                    pass
        now = clock.now_ns()
        if now >= next_sample:
            info = read_tcp_info(sock)
            count = (info["bytes_acked"] - base_acked) if (use_acked and info) else sent
            dt = (now - last_t) / 1e9
            sink.emit("bandwidth", "throughput", (count - last_count) * 8 / dt, target=label,
                      ts_ns=now, window_ns=now - last_t, basis=basis, direction="up")
            if info:
                retrans = info["total_retrans"] - base_retrans
                sink.emit("bandwidth", "tcp_rtt", info["rtt_us"] / 1000, target=label, ts_ns=now)
                sink.emit("bandwidth", "cwnd", info["snd_cwnd"], target=label, ts_ns=now)
                sink.emit("bandwidth", "retrans", retrans - last_retrans, target=label, ts_ns=now)
                last_retrans = retrans
            last_count, last_t = count, now
            samples += 1
            next_sample += interval_ns
            if next_sample <= now:
                next_sample = now + interval_ns
    elapsed = (clock.now_ns() - t_start) / 1e9
    sock.setblocking(True)
    sock.settimeout(max(10.0, duration))
    server_bytes = server_bps = None
    try:
        sock.shutdown(socket.SHUT_WR)
        reply = b""
        while b"\n" not in reply:
            part = sock.recv(1024)
            if not part:
                break
            reply += part
        if reply:
            d = json.loads(reply.split(b"\n", 1)[0])
            server_bytes = int(d["bytes"])
            server_bps = server_bytes * 8 / max(float(d["elapsed"]), 1e-9)
            sink.emit("bandwidth", "goodput_total", server_bps, target=label,
                      bytes=server_bytes, elapsed_s=d["elapsed"], basis="server")
    except (OSError, ValueError, KeyError):
        pass
    info = read_tcp_info(sock)
    retrans_total = (info["total_retrans"] - base_retrans) if info else None
    return BandwidthSummary(
        target=label, direction="up" if rate_bps is None else f"up@{rate_bps:.0f}bps",
        duration_s=elapsed, bytes=sent,
        mean_bps=sent * 8 / max(elapsed, 1e-9), server_bytes=server_bytes,
        server_bps=server_bps, retrans_total=retrans_total, basis=basis, samples=samples,
    )


def _download(sink, sock, label, duration, interval) -> BandwidthSummary:
    clock = sink.clock
    interval_ns = int(interval * 1e9)
    sock.setblocking(False)
    total = last_total = 0
    t_start = clock.now_ns()
    hard_end = t_start + int((duration + 5) * 1e9)
    last_t = t_start
    next_sample = t_start + interval_ns
    samples = 0
    eof = False
    while not eof and not sink.stop_event.is_set():
        now = clock.now_ns()
        if now >= hard_end:
            break
        r, _, _ = select.select([sock], [], [], max(0, next_sample - now) / 1e9)
        if r:
            try:
                data = sock.recv(256 * 1024)
                if not data:
                    eof = True
                total += len(data)
            except (BlockingIOError, InterruptedError):
                pass
            except OSError:
                eof = True
        now = clock.now_ns()
        if now >= next_sample or (eof and now > last_t):
            dt = (now - last_t) / 1e9
            if dt > 0:
                sink.emit("bandwidth", "throughput", (total - last_total) * 8 / dt, target=label,
                          ts_ns=now, window_ns=now - last_t, basis="received", direction="down")
                samples += 1
            last_total, last_t = total, now
            next_sample = now + interval_ns
    elapsed = (clock.now_ns() - t_start) / 1e9
    mean = total * 8 / max(elapsed, 1e-9)
    sink.emit("bandwidth", "goodput_total", mean, target=label, bytes=total, elapsed_s=elapsed,
              basis="received")
    return BandwidthSummary(
        target=label, direction="down", duration_s=elapsed, bytes=total, mean_bps=mean,
        server_bytes=None, server_bps=None, retrans_total=None, basis="received",
        samples=samples,
    )
