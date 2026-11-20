import socket
import struct

import pytest

from netprobe.probes import delay as D
from netprobe.utils import privileges


def test_jitter_matches_rfc3550_hand_computation():
    j = D.JitterEstimator()
    rtts = [10.0, 12.0, 11.0, 15.0]
    expected = 0.0
    prev = None
    for r in rtts:
        if prev is not None:
            expected += (abs(r - prev) - expected) / 16
        prev = r
        got = j.update(r)
    assert got == pytest.approx(expected)
    # explicit numbers: 2/16 = .125 ; .125 + (1-.125)/16 = .1796875 ; + (4-.1796875)/16
    assert got == pytest.approx(0.1796875 + (4 - 0.1796875) / 16)


def test_constant_rtt_has_zero_jitter():
    j = D.JitterEstimator()
    for _ in range(50):
        v = j.update(5.0)
    assert v == 0.0


def test_summary_loss():
    s = D.summarize("t", "udp", [1.0, 2.0, 3.0], sent=4, jitter=0.1)
    assert s.lost == 1 and s.loss == 0.25 and s.rtt_median_ms == 2.0


def test_payload_roundtrip():
    p = D.build_payload(7, 123, 64)
    assert len(p) == 64 and D.parse_payload(p) == 7
    assert D.parse_payload(b"XXXX" + p[4:]) is None
    assert D.parse_payload(b"short") is None


def test_icmp_checksum_valid():
    pkt = D.build_icmp_echo(0x1234, 1, b"abcd")
    assert D.icmp_checksum(pkt) == 0


@pytest.mark.integration
def test_udp_loopback_end_to_end(mem_session):
    with D.UdpEchoServer("127.0.0.1", 0) as srv:
        res = mem_session.delay(f"127.0.0.1:{srv.port}", count=20, interval=0.01, timeout=0.5)
    assert res.sent == 20 and res.received == 20 and res.loss == 0
    rtts = mem_session.query("delay", "rtt")
    assert len(rtts) == 20 and all(0 < r.value < 100 for r in rtts)
    # rtt samples are stamped at departure, in send order
    assert [r.meta["seq"] for r in rtts] == list(range(20))
    assert all(r.meta["recv_ns"] > r.ts_monotonic for r in rtts)


@pytest.mark.integration
def test_udp_loss_is_timestamped_at_departure(mem_session):
    # A bound socket that never answers -> every probe is lost.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    port = sink.getsockname()[1]
    try:
        res = mem_session.delay(f"127.0.0.1:{port}", count=5, interval=0.01, timeout=0.05)
    finally:
        sink.close()
    assert res.lost == 5 and res.loss == 1.0
    lost = mem_session.query("delay", "lost")
    assert [r.meta["seq"] for r in lost] == list(range(5))
    assert mem_session.query("delay", "loss")[0].value == 1.0


@pytest.mark.integration
def test_tcp_connect_mode(mem_session):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    try:
        res = mem_session.delay(f"127.0.0.1:{port}", mode="tcp", count=5, interval=0.01)
    finally:
        srv.close()
    assert res.received == 5


def test_icmp_without_privilege_raises_clear_error(monkeypatch, mem_session):
    def deny(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(D.socket, "socket", deny)
    monkeypatch.setattr(privileges, "has_capability", lambda *_: False)
    with pytest.raises(privileges.PrivilegeError, match="ping_group_range"):
        mem_session.delay("127.0.0.1", mode="icmp", count=1)


def test_icmp_reply_parsing_raw(monkeypatch):
    """Parse a raw-socket echo reply (with IP header) without opening sockets."""

    class FakeSock:
        def __init__(self, data):
            self.data = data

        def setblocking(self, _):
            pass

        def recvfrom(self, _):
            return self.data, ("10.0.0.9", 0)

        def fileno(self):
            return 0

    clock = type("C", (), {"now_ns": staticmethod(lambda: 99)})()
    p = D.IcmpPinger.__new__(D.IcmpPinger)
    p.clock, p.ip, p.ident, p.raw = clock, "10.0.0.9", 0x4242, True
    payload = D.build_payload(1234, 5, 32)
    icmp = struct.pack("!BBHHH", 0, 0, 0, 0x4242, 1234 & 0xFFFF) + payload
    ip_hdr = bytes([0x45]) + b"\x00" * 19
    p.sock = FakeSock(ip_hdr + icmp)
    monkeypatch.setattr(D.select, "select", lambda r, w, x, t: (r, [], []))
    assert p.recv(0.1) == (1234, 99)
