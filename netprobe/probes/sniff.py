"""Packet capture to pcap, summarized onto the unified timeline.

Requires ``CAP_NET_RAW`` (checked up front; see docs/privileges.md).

Backends
--------
``afpacket`` (default on Linux, no dependencies): ``AF_PACKET``/``SOCK_RAW``
socket bound to one interface, kernel receive timestamps via
``SO_TIMESTAMPNS``, optional user-space host/port filter.
``scapy``: ``scapy.AsyncSniffer`` with a kernel BPF filter (``pip install
netprobe[scapy]``).

Kernel timestamps are wall-clock based; they are mapped onto session
monotonic time through the session anchor (``Clock.wall_ns_to_rel``).

Timeline records
----------------
Every ``bin_s`` the probe emits ``pkts``, ``bytes`` and ``tcp_retrans`` for
the bin (stamped at the bin end). Each record's meta carries ``frame_first``
and ``frame_last`` (1-based pcap frame numbers) so that a report can point
to the exact packets behind any point on the timeline. ``tcp_retrans``
uses the common heuristic that a TCP segment with payload whose sequence
range ends at or before the highest sequence already seen on that flow is a
retransmission.
"""

from __future__ import annotations

import queue
import socket
import struct
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from netprobe.utils import privileges

ETH_P_ALL = 0x0003
SO_TIMESTAMPNS = 35
PACKET_OUTGOING = 4
LINKTYPE_ETHERNET = 1
PCAP_MAGIC_NS = 0xA1B23C4D


# ---------------------------------------------------------------------------
# pcap I/O (nanosecond-resolution pcap, readable by tcpdump/Wireshark)
# ---------------------------------------------------------------------------
class PcapWriter:
    def __init__(self, path: str | Path, snaplen: int = 65535,
                 linktype: int = LINKTYPE_ETHERNET) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        self._fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_NS, 2, 4, 0, 0, snaplen, linktype))
        self.snaplen = snaplen
        self.frames = 0

    def write(self, ts_wall_ns: int, data: bytes) -> int:
        cap = data[: self.snaplen]
        sec, nsec = divmod(ts_wall_ns, 1_000_000_000)
        self._fh.write(struct.pack("<IIII", sec, nsec, len(cap), len(data)))
        self._fh.write(cap)
        self.frames += 1
        return self.frames

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()


def read_pcap(path: str | Path) -> Iterator[tuple[int, bytes]]:
    """Yield ``(ts_wall_ns, frame)``; supports us- and ns-resolution pcap."""
    with Path(path).open("rb") as fh:
        gh = fh.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == PCAP_MAGIC_NS:
            mult = 1
        elif magic == 0xA1B2C3D4:
            mult = 1000
        else:
            raise ValueError("unsupported pcap format")
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            sec, frac, incl, _orig = struct.unpack("<IIII", rh)
            yield sec * 1_000_000_000 + frac * mult, fh.read(incl)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PacketInfo:
    length: int
    proto: int  # IP protocol number, 0 if not IPv4
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    tcp_seq: int = 0
    payload_len: int = 0
    tcp_flags: int = 0


def parse_ethernet(frame: bytes) -> PacketInfo:
    n = len(frame)
    if n < 14:
        return PacketInfo(n, 0)
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    if ethertype == 0x8100 and n >= 18:  # 802.1Q
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        off = 18
    if ethertype != 0x0800 or n < off + 20:
        return PacketInfo(n, 0)
    ihl = (frame[off] & 0x0F) * 4
    total_len = struct.unpack_from("!H", frame, off + 2)[0]
    proto = frame[off + 9]
    src = socket.inet_ntoa(frame[off + 12: off + 16])
    dst = socket.inet_ntoa(frame[off + 16: off + 20])
    l4 = off + ihl
    if proto == 6 and n >= l4 + 20:
        sport, dport, seq = struct.unpack_from("!HHI", frame, l4)
        doff = (frame[l4 + 12] >> 4) * 4
        flags = frame[l4 + 13]
        payload = max(0, total_len - ihl - doff)
        return PacketInfo(n, 6, src, dst, sport, dport, seq, payload, flags)
    if proto == 17 and n >= l4 + 8:
        sport, dport, ulen = struct.unpack_from("!HHH", frame, l4)
        return PacketInfo(n, 17, src, dst, sport, dport, 0, max(0, ulen - 8))
    return PacketInfo(n, proto, src, dst)


class RetransDetector:
    """Per-flow highest-sequence tracking (mod 2^32)."""

    def __init__(self) -> None:
        self._max_end: dict[tuple, int] = {}

    def observe(self, p: PacketInfo) -> bool:
        if p.proto != 6 or p.payload_len == 0:
            return False
        flow = (p.src, p.sport, p.dst, p.dport)
        end = (p.tcp_seq + p.payload_len) & 0xFFFFFFFF
        prev = self._max_end.get(flow)
        if prev is None:
            self._max_end[flow] = end
            return False
        # end <= prev in sequence-space arithmetic
        if ((prev - end) & 0xFFFFFFFF) < 0x80000000:
            return True
        self._max_end[flow] = end
        return False


def matches(p: PacketInfo, host: str | None, port: int | None) -> bool:
    if host and host not in (p.src, p.dst):
        return False
    if port and port not in (p.sport, p.dport):
        return False
    return True


# ---------------------------------------------------------------------------
# backends: recv(timeout) -> (ts_wall_ns, frame) | None
# ---------------------------------------------------------------------------
class AfPacketBackend:
    def __init__(self, iface: str) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET is Linux-only")
        self.iface = iface
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((iface, 0))
        self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        self.sock.settimeout(0.1)
        self._loopback = iface == "lo"

    def recv(self, timeout: float):
        self.sock.settimeout(timeout)
        try:
            data, anc, _flags, addr = self.sock.recvmsg(65535, 64)
        except TimeoutError:
            return None
        if self._loopback and addr[2] == PACKET_OUTGOING:
            return None  # loopback delivers each packet twice; keep the inbound copy
        ts = None
        for level, ctype, cdata in anc:
            if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS and len(cdata) >= 16:
                sec, nsec = struct.unpack("qq", cdata[:16])
                ts = sec * 1_000_000_000 + nsec
        if ts is None:
            import time

            ts = time.time_ns()
        return ts, data

    def close(self) -> None:
        self.sock.close()


class ScapyBackend:
    def __init__(self, iface: str, bpf: str | None) -> None:
        try:
            from scapy.all import AsyncSniffer  # type: ignore
        except ImportError as e:
            raise ImportError("scapy backend needs `pip install netprobe[scapy]`") from e
        self._q: queue.Queue = queue.Queue(maxsize=200_000)
        self._sniffer = AsyncSniffer(iface=iface, filter=bpf, store=False, prn=self._on_pkt)
        self._sniffer.start()

    def _on_pkt(self, pkt) -> None:
        try:
            self._q.put_nowait((int(round(float(pkt.time) * 1e9)), bytes(pkt)))
        except queue.Full:
            pass

    def recv(self, timeout: float):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        try:
            self._sniffer.stop()
        except Exception:  # noqa: BLE001
            pass


@dataclass
class SniffSummary:
    iface: str
    pcap: str | None
    frames: int
    matched: int
    bytes: int
    tcp_retrans: int
    backend: str

    def to_dict(self) -> dict:
        return asdict(self)


def run_sniff(
    sink,
    *,
    iface: str = "lo",
    duration: float = 10.0,
    pcap: str | Path | None = "capture.pcap",
    bin_s: float = 0.5,
    bpf: str | None = None,
    host: str | None = None,
    port: int | None = None,
    backend: str | object = "auto",
) -> SniffSummary:
    """Capture for ``duration`` s, write pcap, emit per-bin summaries.

    ``backend`` may be ``"auto"``, ``"afpacket"``, ``"scapy"`` or an object
    with ``recv(timeout)``/``close()`` (used by the test-suite to inject
    packets without privileges).
    """
    if isinstance(backend, str):
        privileges.require(f"packet capture on {iface}", ["CAP_NET_RAW"])
        name = backend
        if backend == "auto":
            name = "scapy" if bpf else "afpacket"
        be = ScapyBackend(iface, bpf) if name == "scapy" else AfPacketBackend(iface)
    else:
        be, name = backend, type(backend).__name__

    pcap_path = None
    if pcap is not None:
        pcap_path = Path(pcap)
        if not pcap_path.is_absolute() and getattr(sink, "out_dir", None) is not None:
            pcap_path = Path(sink.out_dir) / pcap_path
    writer = PcapWriter(pcap_path) if pcap_path else None

    clock = sink.clock
    bin_ns = int(bin_s * 1e9)
    det = RetransDetector()
    t_start = clock.now_ns()
    t_end = t_start + int(duration * 1e9)
    cur_bin = t_start // bin_ns
    acc = {"pkts": 0, "bytes": 0, "retrans": 0, "first": None, "last": None}
    totals = {"frames": 0, "matched": 0, "bytes": 0, "retrans": 0}
    label = iface

    def flush(bin_idx: int) -> None:
        end_ns = (bin_idx + 1) * bin_ns
        meta = {"bin_ns": bin_ns, "frame_first": acc["first"], "frame_last": acc["last"],
                "pcap": pcap_path.name if pcap_path else None}
        sink.emit("sniff", "pkts", acc["pkts"], target=label, ts_ns=end_ns, **meta)
        sink.emit("sniff", "bytes", acc["bytes"], target=label, ts_ns=end_ns, **meta)
        sink.emit("sniff", "tcp_retrans", acc["retrans"], target=label, ts_ns=end_ns, **meta)
        acc.update(pkts=0, bytes=0, retrans=0, first=None, last=None)

    try:
        while not sink.stop_event.is_set():
            now = clock.now_ns()
            if now >= t_end:
                break
            item = be.recv(min(0.1, (t_end - now) / 1e9))
            if item is None:
                # close bins that have elapsed even without traffic
                while (clock.now_ns() // bin_ns) > cur_bin:
                    flush(cur_bin)
                    cur_bin += 1
                continue
            ts_wall_ns, frame = item
            frame_no = writer.write(ts_wall_ns, frame) if writer else totals["frames"] + 1
            totals["frames"] += 1
            info = parse_ethernet(frame)
            if not matches(info, host, port):
                continue
            rel = clock.wall_ns_to_rel(ts_wall_ns)
            b = max(rel, 0) // bin_ns
            while b > cur_bin:
                flush(cur_bin)
                cur_bin += 1
            retrans = det.observe(info)
            acc["pkts"] += 1
            acc["bytes"] += info.length
            acc["retrans"] += int(retrans)
            acc["first"] = acc["first"] or frame_no
            acc["last"] = frame_no
            totals["matched"] += 1
            totals["bytes"] += info.length
            totals["retrans"] += int(retrans)
        flush(cur_bin)
    finally:
        be.close()
        if writer:
            writer.close()
    return SniffSummary(iface, str(pcap_path) if pcap_path else None, totals["frames"],
                        totals["matched"], totals["bytes"], totals["retrans"], name)


if __name__ == "__main__":  # pragma: no cover
    for ts, fr in read_pcap(sys.argv[1]):
        print(ts, parse_ethernet(fr))
