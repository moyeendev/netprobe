import struct
import sys

import pytest

from netprobe.probes import bandwidth as B


def _tcp_info_bytes(rtt_us=12345, cwnd=42, total_retrans=7, bytes_acked=10_000, ext=True):
    u8 = [1, 0, 0, 0, 0, 0, 0, 0]
    u32 = [0] * 24
    u32[2] = 1448
    u32[15] = rtt_us
    u32[18] = cwnd
    u32[23] = total_retrans
    if ext:
        return struct.pack("=8B24I4Q", *u8, *u32, 0, 0, bytes_acked, 0)
    return struct.pack("=8B24I", *u8, *u32)


def test_parse_tcp_info_extended():
    info = B.parse_tcp_info(_tcp_info_bytes())
    assert info["rtt_us"] == 12345 and info["snd_cwnd"] == 42
    assert info["total_retrans"] == 7 and info["bytes_acked"] == 10_000
    assert info["snd_mss"] == 1448


def test_parse_tcp_info_old_kernel_and_short():
    info = B.parse_tcp_info(_tcp_info_bytes(ext=False))
    assert info["bytes_acked"] is None
    assert B.parse_tcp_info(b"\x00" * 10) is None


@pytest.mark.integration
@pytest.mark.parametrize("direction", ["up", "down"])
def test_loopback_transfer(mem_session, direction):
    with B.BandwidthServer("127.0.0.1", 0) as srv:
        res = mem_session.bandwidth(f"127.0.0.1:{srv.port}", duration=0.6, interval=0.1,
                                    direction=direction)
    assert res.bytes > 0 and res.mean_bps > 1e6
    thr = mem_session.query("bandwidth", "throughput")
    assert len(thr) >= 3
    assert all(r.meta["window_ns"] > 0 for r in thr)
    assert mem_session.query("bandwidth", "goodput_total")
    if direction == "up":
        assert res.server_bytes is not None and res.server_bytes >= 0.9 * res.bytes
        if sys.platform.startswith("linux"):
            assert res.basis == "acked"
            assert mem_session.query("bandwidth", "tcp_rtt")


@pytest.mark.integration
def test_paced_upload_holds_rate(mem_session):
    with B.BandwidthServer("127.0.0.1", 0) as srv:
        res = mem_session.bandwidth(f"127.0.0.1:{srv.port}", duration=1.0, interval=0.1,
                                    rate_bps=20e6)
    assert res.server_bps == pytest.approx(20e6, rel=0.15)


def test_rejects_bad_args(mem_session):
    with pytest.raises(ValueError):
        mem_session.bandwidth("127.0.0.1", duration=0)
    with pytest.raises(ValueError):
        mem_session.bandwidth("127.0.0.1", direction="sideways")
    with pytest.raises(ValueError):
        mem_session.bandwidth("127.0.0.1", direction="down", rate_bps=1e6)
