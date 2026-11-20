import socket

import pytest

from netprobe.probes import stress as S
from netprobe.utils import privileges
from netprobe.utils.net import is_private_target, parse_rate

OK = dict(rate_bps=1e6, duration=1, packet_size=1200, i_understand=True)


def test_requires_acknowledgement():
    with pytest.raises(S.SafetyError, match="i-understand"):
        S.check_safety("127.0.0.1", **{**OK, "i_understand": False})


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "193.0.14.129"])
def test_refuses_public_targets(ip):
    with pytest.raises(S.SafetyError, match="non-private"):
        S.check_safety(ip, **OK)
    S.check_safety(ip, **OK, allow_public=True)  # explicit override works


@pytest.mark.parametrize("ip", ["224.0.0.1", "255.255.255.255", "0.0.0.0"])
def test_always_refuses_multicast_broadcast(ip):
    with pytest.raises(S.SafetyError):
        S.check_safety(ip, **OK, allow_public=True)


def test_rate_and_duration_caps():
    with pytest.raises(S.SafetyError, match="hard cap"):
        S.check_safety("10.0.0.1", **{**OK, "rate_bps": 2e9})
    S.check_safety("10.0.0.1", **{**OK, "rate_bps": 2e9}, rate_cap_override=True)
    with pytest.raises(S.SafetyError):
        S.check_safety("10.0.0.1", **{**OK, "duration": 10_000})
    with pytest.raises(S.SafetyError):
        S.check_safety("10.0.0.1", **{**OK, "packet_size": 9000})


def test_defaults_are_conservative():
    assert S.DEFAULT_RATE_BPS == 10_000_000
    assert S.DEFAULT_RATE_BPS < S.HARD_MAX_RATE_BPS


def test_private_classification():
    for ip in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1",
               "100.64.0.1"]:
        assert is_private_target(ip)
    for ip in ["8.8.8.8", "224.0.0.1", "0.0.0.0", "255.255.255.255"]:
        assert not is_private_target(ip)


def test_parse_rate():
    assert parse_rate("10M") == 1e7 and parse_rate("500k") == 5e5 and parse_rate("1G") == 1e9
    assert parse_rate("2.5Mbps") == 2.5e6 and parse_rate(1000) == 1000
    with pytest.raises(ValueError):
        parse_rate("fast")


def test_token_bucket_math():
    tb = S.TokenBucket(rate_bps=8000, burst_bytes=500, now_s=0.0)  # 1000 B/s
    tb.refill(0.25)
    assert tb.tokens == pytest.approx(250)
    assert tb.take(200) and not tb.take(100)
    assert tb.wait_for(100) == pytest.approx(0.05)
    tb.refill(10.0)
    assert tb.tokens == 500  # capped at burst


@pytest.mark.integration
def test_loopback_rate_accuracy(mem_session):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]
    try:
        res = mem_session.stress(f"127.0.0.1:{port}", rate_bps=4e6, duration=1.0,
                                 i_understand=True)
    finally:
        rx.close()
    assert res.achieved_bps == pytest.approx(4e6, rel=0.10)
    evs = mem_session.query("stress", "event")
    assert [e.meta["event"] for e in evs] == ["start", "stop"]


def test_raw_mode_requires_capability(monkeypatch, mem_session):
    monkeypatch.setattr(privileges, "is_linux", lambda: True)
    monkeypatch.setattr(privileges, "has_capability", lambda *_: False)
    with pytest.raises(privileges.PrivilegeError, match="CAP_NET_RAW"):
        mem_session.stress("127.0.0.1", raw=True, i_understand=True, duration=0.1)


def test_privilege_detection_from_proc(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nCapEff:\t0000000000002000\n")  # bit 13 = NET_RAW
    assert privileges.has_capability("CAP_NET_RAW", status)
    assert not privileges.has_capability("CAP_NET_ADMIN", status)
    status.write_text("CapEff:\t0000000000000000\n")
    assert privileges.missing_capabilities(["CAP_NET_RAW"], status) == ["CAP_NET_RAW"]
