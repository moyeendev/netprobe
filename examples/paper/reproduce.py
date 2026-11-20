"""Paper experiments. Run via examples/run_reproduce_paper.sh (root, netns testbed).

E1  delay accuracy   : ping vs NetProbe (icmp, udp) under netem delay/jitter/loss
E2  bandwidth accuracy: iperf3 vs NetProbe under netem rate limits
E3  congestion        : integrated run; onset detection latency vs. load start

This script doubles as an example of the Python API: every NetProbe
measurement below is a few lines of `with Session(...) as s: ...`.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import time
from pathlib import Path

from netprobe import Session, __version__
from netprobe.probes.delay import JitterEstimator

SRV = "10.78.0.2"  # server netns, behind the router netns (examples/netns.sh)
IFACE = "np0"  # client-side capture interface
ROUTER_NS, BOTTLENECK = "np_rtr", "r1"

DELAY_CONDS = [
    ("no netem", None, 0.0, 0.0),
    ("delay 10ms", "delay 10ms", 10.0, 0.0),
    ("delay 50ms 5ms", "delay 50ms 5ms", 50.0, 0.0),
    ("delay 100ms", "delay 100ms", 100.0, 0.0),
    ("delay 20ms loss 1%", "delay 20ms loss 1%", 20.0, 0.01),
    ("delay 20ms loss 5%", "delay 20ms loss 5%", 20.0, 0.05),
]
RATE_CONDS = [10, 50, 100, 200]  # Mbit/s, with 5 ms delay


def sh(*cmd: str, check: bool = True) -> str:
    return subprocess.run(cmd, check=check, capture_output=True, text=True).stdout


def netem(spec: str | None) -> None:
    tc = ["ip", "netns", "exec", ROUTER_NS, "tc", "qdisc"]
    subprocess.run([*tc, "del", "dev", BOTTLENECK, "root"], capture_output=True)
    if spec:
        sh(*tc, "add", "dev", BOTTLENECK, "root", "netem", *spec.split())
    time.sleep(0.3)


def run_ping(n: int, interval: float) -> dict:
    out = sh("ping", "-n", "-c", str(n), "-i", str(interval), "-W", "1", SRV, check=False)
    rtts = [float(m) for m in re.findall(r"time=([0-9.]+) ms", out)]
    m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
    sent, recv = (int(m.group(1)), int(m.group(2))) if m else (n, len(rtts))
    j = JitterEstimator()
    for r in rtts:
        j.update(r)
    return {
        "tool": "ping", "sent": sent, "received": recv, "loss": 1 - recv / sent if sent else None,
        "rtt_mean_ms": statistics.fmean(rtts) if rtts else None,
        "rtt_median_ms": statistics.median(rtts) if rtts else None,
        "rtt_min_ms": min(rtts) if rtts else None,
        "jitter_ms": j.value,
    }


def run_np_delay(out: Path, label: str, mode: str, n: int, interval: float) -> dict:
    with Session(target=SRV, out_dir=out, label=label) as s:
        r = s.delay(mode=mode, count=n, interval=interval, timeout=1.0)
    d = r.to_dict()
    d["tool"] = f"netprobe-{mode}"
    d["run_dir"] = str(out)
    return d


def run_iperf3(duration: float) -> dict:
    out = sh("iperf3", "-c", SRV, "-t", str(duration), "-J", check=False)
    try:
        j = json.loads(out)
        return {"tool": "iperf3",
                "receiver_bps": j["end"]["sum_received"]["bits_per_second"],
                "sender_bps": j["end"]["sum_sent"]["bits_per_second"],
                "retrans": j["end"]["sum_sent"].get("retransmits")}
    except (ValueError, KeyError) as e:
        return {"tool": "iperf3", "error": repr(e), "raw": out[-500:]}


def run_np_bw(out: Path, label: str, duration: float) -> dict:
    with Session(target=SRV, out_dir=out, label=label) as s:
        r = s.bandwidth(duration=duration)
    thr = [x.value for x in s.query("bandwidth", "throughput")]
    d = r.to_dict()
    d.update(tool="netprobe", interval_mean_bps=statistics.fmean(thr) if thr else None,
             run_dir=str(out))
    return d


def run_congestion(out: Path, label: str, duration: float, load_bps: float,
                   load_start: float, load_dur: float) -> dict:
    with Session(target=SRV, out_dir=out, label=label) as s:
        s.sniff(background=True, isolate=True, iface=IFACE, duration=duration + 1,
                host=SRV)
        s.delay(background=True, count=int(duration / 0.05), interval=0.05)
        s.bandwidth(background=True, duration=duration, rate_bps=20e6)
        s.stress(background=True, isolate=True, rate_bps=load_bps, duration=load_dur,
                 start_delay=load_start, i_understand=True)
        s.wait()
        c = s.correlate()
        s.congestion()
        s.report()
    return {
        "run_dir": str(out),
        "stress_start_s": c.stress[0].start_s if c.stress else None,
        "stress_stop_s": c.stress[0].stop_s if c.stress else None,
        "onset_s": c.onset_s,
        "recovery_s": c.recovery_s,
        "detection_latency_s": c.detection_latency_s,
        "onset_error_s": c.onset_error_s,
        "decision_s": c.congestion.decision_s,
        "recovery_latency_s": (c.recovery_s - c.stress[0].stop_s
                               if c.recovery_s is not None and c.stress else None),
        "phases": c.phases,
        "lags": c.lags,
        "evidence": c.evidence,
        "baseline": c.congestion.baseline,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="paper/results")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", choices=["delay", "bandwidth", "congestion"],
                    help="re-run one experiment and merge into an existing results.json")
    a = ap.parse_args()
    out = Path(a.out)
    runs = out / "runs"
    q = a.quick
    reps = 1 if q else 3
    n_probe, iv = (50, 0.02) if q else (500, 0.02)
    bw_t = 3 if q else 10
    cong_reps = 1 if q else 5
    cong_t = 20 if q else 35

    res: dict = {
        "netprobe_version": __version__,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "ping_version": sh("ping", "-V", check=False).strip(),
        "iperf3_version": sh("iperf3", "--version", check=False).splitlines()[0:1],
        "params": {"reps": reps, "probes": n_probe, "interval_s": iv, "bw_duration_s": bw_t,
                   "congestion_reps": cong_reps, "congestion_duration_s": cong_t},
        "delay": [], "bandwidth": [], "congestion": [],
    }

    prev = out / "results.json"
    if a.only and prev.exists():
        old = json.loads(prev.read_text())
        for k in ("delay", "bandwidth", "congestion"):
            if k != a.only:
                res[k] = old[k]
    def run(k):
        return (a.only in (None, k))

    for name, spec, cfg_delay, cfg_loss in (DELAY_CONDS if run("delay") else []):
        netem(spec)
        for rep in range(reps):
            tag = re.sub(r"\W+", "_", name)
            rows = [
                run_ping(n_probe, iv),
                run_np_delay(runs / f"delay_{tag}_icmp_{rep}", name, "icmp", n_probe, iv),
                run_np_delay(runs / f"delay_{tag}_udp_{rep}", name, "udp", n_probe, iv),
            ]
            for r in rows:
                r.update(condition=name, netem=spec, cfg_delay_ms=cfg_delay,
                         cfg_loss=cfg_loss, rep=rep)
                res["delay"].append(r)
            print(f"[E1] {name} rep {rep}: " + ", ".join(
                f"{r['tool']}={r.get('rtt_mean_ms') or float('nan'):.2f}ms" for r in rows),
                flush=True)

    for rate in (RATE_CONDS if run("bandwidth") else []):
        spec = f"delay 5ms rate {rate}mbit"
        netem(spec)
        for rep in range(reps):
            rows = [run_iperf3(bw_t),
                    run_np_bw(runs / f"bw_{rate}_{rep}", spec, bw_t)]
            for r in rows:
                r.update(condition=spec, cfg_rate_bps=rate * 1e6, rep=rep)
                res["bandwidth"].append(r)
            print(f"[E2] {rate} Mbit/s rep {rep}: iperf3="
                  f"{(rows[0].get('receiver_bps') or 0) / 1e6:.2f} "
                  f"netprobe={(rows[1].get('server_bps') or 0) / 1e6:.2f}", flush=True)

    netem("delay 10ms rate 50mbit limit 200")
    for rep in range(cong_reps if run("congestion") else 0):
        r = run_congestion(runs / f"congestion_{rep}", "congestion 50mbit, TCP 20M + UDP 40M",
                           cong_t, 40e6, 10.0, 15.0 if not q else 5.0)
        r["rep"] = rep
        res["congestion"].append(r)
        print(f"[E3] rep {rep}: load start {r['stress_start_s']:.2f}s onset {r['onset_s']} "
              f"latency {r['detection_latency_s']}", flush=True)
    netem(None)

    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=1, default=str))
    print(f"wrote {out / 'results.json'}")


if __name__ == "__main__":
    main()
