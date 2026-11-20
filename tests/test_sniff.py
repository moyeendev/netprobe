import socket
import struct

import pytest

from netprobe.probes import sniff as N
from netprobe.utils import privileges


def eth_tcp(src, dst, sport, dport, seq, payload_len):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0)
    total = 20 + 20 + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + b"x" * payload_len


def test_parse_ethernet_tcp():
    p = N.parse_ethernet(eth_tcp("10.0.0.1", "10.0.0.2", 1111, 2222, 1000, 100))
    assert (p.proto, p.src, p.dst, p.sport, p.dport, p.tcp_seq, p.payload_len) == (
        6, "10.0.0.1", "10.0.0.2", 1111, 2222, 1000, 100)
    assert N.parse_ethernet(b"\x00" * 5).proto == 0


def test_retrans_detection_with_wraparound():
    d = N.RetransDetector()

    def seg(seq, n=100):
        return N.parse_ethernet(eth_tcp("10.0.0.1", "10.0.0.2", 1, 2, seq, n))

    assert not d.observe(seg(1000))
    assert not d.observe(seg(1100))
    assert d.observe(seg(1000))  # resent
    d2 = N.RetransDetector()
    assert not d2.observe(seg(0xFFFFFF00, 100))  # ends at 0xFFFFFF64
    assert not d2.observe(seg(0xFFFFFF64, 0x100))  # crosses 2^32, ends at 0x64
    assert d2.observe(seg(0xFFFFFF00, 100))  # old data after wrap -> retransmission


def test_pcap_roundtrip(tmp_path):
    w = N.PcapWriter(tmp_path / "c.pcap")
    f1, f2 = eth_tcp("10.0.0.1", "10.0.0.2", 1, 2, 0, 10), b"\x00" * 60
    w.write(1_700_000_000_123_456_789, f1)
    w.write(1_700_000_001_000_000_000, f2)
    w.close()
    frames = list(N.read_pcap(tmp_path / "c.pcap"))
    assert frames == [(1_700_000_000_123_456_789, f1), (1_700_000_001_000_000_000, f2)]


class FakeBackend:
    """Replays (rel_ns, frame) packets mapped through the session anchor."""

    def __init__(self, clock, packets):
        self.clock = clock
        self.packets = list(packets)

    def recv(self, timeout):
        if not self.packets:
            return None
        rel, frame = self.packets.pop(0)
        return self.clock.anchor.wall_ns + rel, frame

    def close(self):
        pass


def test_run_sniff_bins_and_evidence(tmp_path):
    from netprobe.core.session import Session

    with Session(target="10.0.0.2", out_dir=tmp_path) as s:
        pk = [
            (100_000_000, eth_tcp("10.0.0.1", "10.0.0.2", 5, 6, 0, 100)),
            (200_000_000, eth_tcp("10.0.0.1", "10.0.0.2", 5, 6, 100, 100)),
            (700_000_000, eth_tcp("10.0.0.1", "10.0.0.2", 5, 6, 0, 100)),  # retrans
            (800_000_000, eth_tcp("10.0.0.9", "10.0.0.8", 5, 6, 0, 100)),  # filtered out
        ]
        res = s.sniff(iface="fake", duration=0.3, bin_s=0.5, host="10.0.0.2",
                      backend=FakeBackend(s.clock, pk))
    assert res.frames == 4 and res.matched == 3 and res.tcp_retrans == 1
    pk_recs = s.query("sniff", "pkts")
    by_t = {r.ts_monotonic: r for r in pk_recs}
    assert by_t[500_000_000].value == 2 and by_t[1_000_000_000].value == 1
    assert by_t[1_000_000_000].meta["frame_first"] == 3
    rt = {r.ts_monotonic: r.value for r in s.query("sniff", "tcp_retrans")}
    assert rt[1_000_000_000] == 1
    assert (tmp_path / "capture.pcap").exists()
    assert len(list(N.read_pcap(tmp_path / "capture.pcap"))) == 4


def test_sniff_requires_privilege(monkeypatch, mem_session):
    monkeypatch.setattr(privileges, "is_linux", lambda: True)
    monkeypatch.setattr(privileges, "has_capability", lambda *_: False)
    with pytest.raises(privileges.PrivilegeError, match="CAP_NET_RAW"):
        mem_session.sniff(iface="lo", duration=0.1)
