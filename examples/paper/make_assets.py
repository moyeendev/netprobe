"""Build the paper's tables and the correlation-timeline figure from results.json."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from netprobe.analysis.correlate import build_timeline, correlate
from netprobe.core.storage import load_manifest, load_records

SERIES = "#2a78d6"
ONSET = "#e34948"
INK2 = "#52514e"
GOODPUT_FRACTION = 1448 / 1514


def _m(xs):
    xs = [x for x in xs if x is not None]
    return statistics.fmean(xs) if xs else None


def _sd(xs):
    xs = [x for x in xs if x is not None]
    return statistics.stdev(xs) if len(xs) > 1 else 0.0


def f(x, nd=2, scale=1.0, pct=False):
    if x is None:
        return "–"
    return f"{100 * x:.{nd}f}" if pct else f"{x * scale:.{nd}f}"


def delay_table(res: dict) -> str:
    conds = list(dict.fromkeys(r["condition"] for r in res["delay"]))
    head = ("| netem (client→server) | ping mean RTT [ms] | NetProbe ICMP [ms] | NetProbe UDP [ms]"
            " | max abs. diff vs ping [ms] | ping loss [%] | NetProbe UDP loss [%]"
            " | ping jitter* [ms] | NetProbe UDP jitter [ms] |\n|" + "---|" * 9)
    lines = [head]
    for c in conds:
        rows = [r for r in res["delay"] if r["condition"] == c]

        def g(tool, key, rows=rows):
            return _m([r.get(key) for r in rows if r["tool"] == tool])

        p, i, u = (g(t, "rtt_mean_ms") for t in ("ping", "netprobe-icmp", "netprobe-udp"))
        diff = max(abs(x - p) for x in (i, u) if x is not None and p is not None) \
            if p is not None else None
        lines.append(
            f"| {c} | {f(p)} | {f(i)} | {f(u)} | {f(diff)} | {f(g('ping', 'loss'), 1, pct=True)}"
            f" | {f(g('netprobe-udp', 'loss'), 1, pct=True)} | {f(g('ping', 'jitter_ms'), 3)}"
            f" | {f(g('netprobe-udp', 'jitter_ms'), 3)} |")
    return "\n".join(lines) + (
        "\n\n*RFC 3550 estimator applied to ping's per-packet RTTs, for comparability.\n")


def bw_table(res: dict) -> str:
    rates = sorted({r["cfg_rate_bps"] for r in res["bandwidth"]})
    lines = ["| netem rate [Mbit/s] | ideal TCP goodput† [Mbit/s] | iperf3 receiver [Mbit/s]"
             " | NetProbe receiver-confirmed [Mbit/s] | NetProbe per-interval mean [Mbit/s]"
             " | NetProbe vs ideal [%] | iperf3 vs ideal [%] |",
             "|---|---|---|---|---|---|---|"]
    for rate in rates:
        rows = [r for r in res["bandwidth"] if r["cfg_rate_bps"] == rate]
        ip = [r.get("receiver_bps") for r in rows if r["tool"] == "iperf3"]
        npb = [r.get("server_bps") for r in rows if r["tool"] == "netprobe"]
        npi = [r.get("interval_mean_bps") for r in rows if r["tool"] == "netprobe"]
        mi, mn = _m(ip), _m(npb)
        ideal = rate * GOODPUT_FRACTION
        lines.append(f"| {rate / 1e6:.0f} | {f(ideal, 2, 1e-6)}"
                     f" | {f(mi, 2, 1e-6)} ± {f(_sd(ip), 2, 1e-6)}"
                     f" | {f(mn, 2, 1e-6)} ± {f(_sd(npb), 2, 1e-6)} | {f(_m(npi), 2, 1e-6)}"
                     f" | {f((mn - ideal) / ideal if mn else None, 1, pct=True)}"
                     f" | {f((mi - ideal) / ideal if mi else None, 1, pct=True)} |")
    return "\n".join(lines) + (
        "\n†netem rate × 1448/1514: TCP payload per full Ethernet frame (MSS 1448 with "
        "timestamps); netem's rate limiter accounts the 14-byte Ethernet header.\n")


def congestion_table(res: dict) -> str:
    lines = ["| run | load start [s] | onset window [s] | decision latency [s] | recovery after"
             " load stop [s] | RTT median base→load [ms] | TCP throughput base→load [Mbit/s]"
             " | probe loss base→load [%] | wire retrans in onset window |",
             "|" + "---|" * 9]
    lat = []
    for r in res["congestion"]:
        b, ld = r["phases"].get("baseline", {}), r["phases"].get("load", {})
        ev = r.get("evidence") or {}
        lat.append(r["detection_latency_s"])
        lines.append(
            f"| {r['rep']} | {f(r['stress_start_s'])} | {f(r['onset_s'], 1)}"
            f" | {f(r['detection_latency_s'])} | {f(r['recovery_latency_s'])}"
            f" | {f(b.get('rtt_median_ms'), 1)} → {f(ld.get('rtt_median_ms'), 1)}"
            f" | {f(b.get('throughput_mean_bps'), 1, 1e-6)} → "
            f"{f(ld.get('throughput_mean_bps'), 1, 1e-6)}"
            f" | {f(b.get('loss'), 1, pct=True)} → {f(ld.get('loss'), 1, pct=True)}"
            f" | {ev.get('tcp_retrans', '–')} (frames {ev.get('frame_first', '–')}–"
            f"{ev.get('frame_last', '–')}) |")
    ok = [x for x in lat if x is not None]
    lines.append(f"\nDetected in {len(ok)}/{len(lat)} runs; latency mean {f(_m(ok))} s, "
                 f"sd {f(_sd(ok))} s (window 1 s, persistence 2).\n")
    return "\n".join(lines)


def figure(run_dir: Path, out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    recs = load_records(run_dir)
    corr = correlate(recs, manifest=load_manifest(run_dir))
    tl = build_timeline([r for r in recs if r.probe != "congestion"], 0.5)
    lvl = {int(w.t_start / 0.5): w.level for w in corr.congestion.windows}
    panels = [
        ("stress.offered_rate", "Offered UDP load\n[Mbit/s]", 1e-6, True),
        ("bandwidth.throughput", "TCP throughput\n[Mbit/s]", 1e-6, False),
        ("delay.rtt", "Probe RTT, median\n[ms]", 1.0, False),
        ("delay.lost", "Lost probes\n[per 0.5 s]", 1.0, True),
        ("sniff.tcp_retrans", "Retransmissions\non wire [per 0.5 s]", 1.0, True),
    ]
    panels = [p for p in panels if p[0] in tl.series]
    fig, axes = plt.subplots(len(panels) + 1, 1, figsize=(7.2, 1.25 * (len(panels) + 1)),
                             sharex=True, constrained_layout=True)
    t = [x + 0.25 for x in tl.t]
    for ax, (key, lab, sc, zero) in zip(axes, panels, strict=False):
        v = [None if x is None else x * sc for x in tl.series[key]]
        if zero:
            v = [0.0 if x is None else x for x in v]
        ax.plot(t, [float("nan") if x is None else x for x in v], color=SERIES, lw=1.6)
        ax.set_ylabel(lab, fontsize=7.5, color=INK2)
    ax = axes[-1]
    levels = [lvl.get(int(x // 1.0 / 0.5), 0) for x in tl.t]
    ax.step(t, levels, where="mid", color=SERIES, lw=1.6)
    ax.set_ylim(-0.2, 3.2)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_ylabel("Congestion\nlevel", fontsize=7.5, color=INK2)
    ax.set_xlabel("session time [s] (one monotonic clock for all panels)", fontsize=8)
    for a in axes:
        for s in corr.stress:
            a.axvspan(s.start_s, s.stop_s or t[-1], color="0.5", alpha=0.12, lw=0)
        if corr.onset_s is not None:
            a.axvline(corr.onset_s, color=ONSET, ls="--", lw=1.1)
        a.tick_params(labelsize=7)
        a.grid(axis="y", color="0.9", lw=0.6)
        for sp in ("top", "right"):
            a.spines[sp].set_visible(False)
    if corr.onset_s is not None:
        axes[0].annotate(f"onset {corr.onset_s:.0f} s", (corr.onset_s, 1.0),
                         xycoords=("data", "axes fraction"), xytext=(4, -10),
                         textcoords="offset points", fontsize=7, color=ONSET)
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(out / "fig_correlation.pdf")
    fig.savefig(out / "fig_correlation.png", dpi=200)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="paper/results")
    ap.add_argument("--figures", default="paper/figures")
    a = ap.parse_args()
    rdir = Path(a.results)
    res = json.loads((rdir / "results.json").read_text())
    (rdir / "table_accuracy.md").write_text(
        "## Delay\n\n" + delay_table(res) + "\n## Throughput\n\n" + bw_table(res))
    (rdir / "table_congestion.md").write_text(congestion_table(res))
    if res["congestion"]:
        figure(Path(res["congestion"][0]["run_dir"]), Path(a.figures))
    print((rdir / "table_accuracy.md").read_text())
    print((rdir / "table_congestion.md").read_text())


if __name__ == "__main__":
    main()
