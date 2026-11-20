"""Unified CLI: ``netprobe <command>``.

Commands: server, delay, bandwidth, stress, sniff, run, report, analyze,
privileges. ``run`` is the integrated workflow: delay + bandwidth (+ load)
(+ capture) concurrently in one session, then congestion estimation and the
correlation report.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from netprobe import __version__
from netprobe.core.session import Session
from netprobe.utils import privileges
from netprobe.utils.net import DEFAULT_PORT, parse_rate

EX_NOPERM = 77
EX_USAGE = 64


def _ensure(args, feature: str, caps: list[str]) -> None:
    """Check capabilities before starting; offer sudo re-exec on a TTY."""
    try:
        privileges.require(feature, caps)
    except privileges.PrivilegeError as e:
        print(f"netprobe: {e}", file=sys.stderr)
        if privileges.is_linux() and not args.no_elevate and privileges.can_prompt():
            ans = input("Re-run this command with sudo? [y/N] ").strip().lower()
            if ans in ("y", "yes"):
                privileges.reexec_with_sudo(sys.argv[1:])
        sys.exit(EX_NOPERM)


def _session(args, target=None) -> Session:
    return Session(target=target, out_dir=args.out, sqlite=args.sqlite, label=args.label)


def _print(obj, as_json: bool) -> None:
    d = obj.to_dict() if hasattr(obj, "to_dict") else obj
    if as_json:
        print(json.dumps(d, indent=2, default=str))
        return
    for k, v in d.items():
        if isinstance(v, float):
            v = f"{v:.4g}"
        print(f"  {k:>16}: {v}")


# --------------------------------------------------------------------- cmds
def cmd_server(args) -> int:
    from netprobe.probes.bandwidth import BandwidthServer
    from netprobe.probes.delay import UdpEchoServer

    echo = UdpEchoServer(args.bind, args.port).start()
    bw = BandwidthServer(args.bind, args.port).start()
    print(f"netprobe server: UDP echo + TCP bandwidth on {args.bind}:{args.port} (Ctrl-C to stop)")
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.wait(0.5):
            pass
    finally:
        echo.stop()
        bw.stop()
    return 0


def cmd_delay(args) -> int:
    with _session(args, args.target) as s:
        res = s.delay(mode=args.mode, count=args.count, interval=args.interval, size=args.size,
                      timeout=args.timeout, port=args.port)
    print(f"delay -> {s.out_dir}")
    _print(res, args.json)
    return 0


def cmd_bandwidth(args) -> int:
    with _session(args, args.target) as s:
        res = s.bandwidth(duration=args.duration, direction=args.direction,
                          interval=args.interval, port=args.port,
                          rate_bps=parse_rate(args.rate) if args.rate else None)
    print(f"bandwidth -> {s.out_dir}")
    _print(res, args.json)
    return 0


def _stress_kwargs(args) -> dict:
    return dict(
        rate_bps=parse_rate(args.rate), packet_size=args.packet_size, port=args.port,
        i_understand=args.i_understand_this_sends_traffic,
        allow_public=args.allow_public_target, rate_cap_override=args.max_rate_override,
        raw=args.raw, tos=args.tos,
    )


def cmd_stress(args) -> int:
    if args.raw:
        _ensure(args, "raw-socket stress", ["CAP_NET_RAW"])
    with _session(args, args.target) as s:
        res = s.stress(duration=args.duration, start_delay=args.start_delay,
                       **_stress_kwargs(args))
    print(f"stress -> {s.out_dir}")
    _print(res, args.json)
    return 0


def cmd_sniff(args) -> int:
    _ensure(args, f"packet capture on {args.iface}", ["CAP_NET_RAW"])
    with _session(args) as s:
        res = s.sniff(iface=args.iface, duration=args.duration, bpf=args.bpf, host=args.host,
                      port=args.filter_port, bin_s=args.bin)
    print(f"sniff -> {s.out_dir}")
    _print(res, args.json)
    return 0


def cmd_run(args) -> int:
    """Integrated, concurrently-scheduled measurement on one clock."""
    if args.sniff:
        _ensure(args, f"packet capture on {args.sniff}", ["CAP_NET_RAW"])
    if args.stress_rate and args.raw:
        _ensure(args, "raw-socket stress", ["CAP_NET_RAW"])
    count = max(1, int(args.duration / args.delay_interval))
    with _session(args, args.target) as s:
        handles = []
        if args.sniff:
            handles.append(s.sniff(background=True, isolate=True, iface=args.sniff,
                                   duration=args.duration + 1.0, bpf=args.bpf,
                                   host=args.sniff_host, port=args.sniff_port, bin_s=args.bin))
        handles.append(s.delay(background=True, mode=args.delay_mode, count=count,
                               interval=args.delay_interval, port=args.port,
                               timeout=args.delay_timeout))
        if not args.no_bandwidth:
            handles.append(s.bandwidth(background=True, duration=args.duration,
                                       direction=args.bw_direction, interval=args.bw_interval,
                                       port=args.port,
                                       rate_bps=parse_rate(args.bw_rate) if args.bw_rate
                                       else None))
        if args.stress_rate:
            kw = _stress_kwargs(argparse.Namespace(**{**vars(args), "rate": args.stress_rate}))
            handles.append(s.stress(background=True, isolate=not args.no_isolate,
                                    duration=args.stress_duration,
                                    start_delay=args.stress_start, **kw))
        try:
            s.wait()
        except KeyboardInterrupt:
            s.stop()
            s.wait()
        cres = s.congestion(window_s=args.window, baseline_s=args.baseline, persist=args.persist)
        report = s.report(bin_s=args.bin, congestion={"window_s": args.window,
                                                      "baseline_s": args.baseline,
                                                      "persist": args.persist})
    print(f"run {s.run_id} -> {s.out_dir}")
    for h in handles:
        print(f"[{h.name}]")
        _print(h.result if isinstance(h.result, dict) else h.result, args.json)
    print(f"congestion onset: {cres.onset_s} s (decided at {cres.decision_s} s), "
          f"recovery: {cres.recovery_s} s")
    print(f"report: {report}")
    return 0


def _load(run_dir):
    from netprobe.core.storage import load_manifest, load_records

    return load_records(run_dir), load_manifest(run_dir)


def cmd_report(args) -> int:
    from netprobe.analysis.report import write_report

    recs, man = _load(args.run_dir)
    out = Path(args.output) if args.output else Path(args.run_dir) / "report.html"
    path = write_report(recs, man, out, bin_s=args.bin,
                        congestion={"window_s": args.window, "baseline_s": args.baseline,
                                    "persist": args.persist})
    print(path)
    return 0


def cmd_analyze(args) -> int:
    from netprobe.analysis.correlate import correlate

    recs, man = _load(args.run_dir)
    c = correlate(recs, manifest=man, bin_s=args.bin,
                  congestion={"window_s": args.window, "baseline_s": args.baseline,
                              "persist": args.persist})
    d = c.to_dict()
    d.pop("timeline")
    d["congestion"].pop("windows")
    print(json.dumps(d, indent=2, default=str))
    return 0


def cmd_privileges(args) -> int:
    rep = privileges.privilege_report()
    print(json.dumps(rep, indent=2))
    needs = {"delay (udp/tcp)": [], "bandwidth": [], "congestion": [], "stress (udp)": [],
             "delay (icmp)": ["CAP_NET_RAW*"], "stress --raw": ["CAP_NET_RAW"],
             "sniff": ["CAP_NET_RAW"]}
    for k, v in needs.items():
        print(f"  {k:<18} {'unprivileged' if not v else ', '.join(v)}")
    print("  * unless net.ipv4.ping_group_range admits your group")
    return 0


# ------------------------------------------------------------------ parser
def _add_stress_opts(p, rate_flag: str = "--rate", rate_default="10M") -> None:
    p.add_argument(rate_flag, default=rate_default,
                   help="target rate, e.g. 500k, 10M (default 10M; hard cap 1G)")
    p.add_argument("--packet-size", type=int, default=1200)
    p.add_argument("--i-understand-this-sends-traffic", action="store_true",
                   help="mandatory acknowledgement for load generation")
    p.add_argument("--allow-public-target", action="store_true",
                   help="permit non-private targets (only networks you are authorized to load)")
    p.add_argument("--max-rate-override", action="store_true", help="permit rates above 1 Gbit/s")
    p.add_argument("--raw", action="store_true", help="raw IPv4 socket (needs CAP_NET_RAW)")
    p.add_argument("--tos", type=lambda s: int(s, 0), default=0, help="IP TOS byte (raw mode)")


def _add_analysis_opts(p) -> None:
    p.add_argument("--bin", type=float, default=0.5, help="timeline bin width, s")
    p.add_argument("--window", type=float, default=1.0, help="congestion window, s")
    p.add_argument("--baseline", type=float, default=5.0, help="baseline period, s")
    p.add_argument("--persist", type=int, default=2, help="windows required for onset")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="netprobe", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"netprobe {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", help="run directory (default runs/<run_id>)")
    common.add_argument("--sqlite", action="store_true", help="also write records.sqlite")
    common.add_argument("--label", help="free-text label stored in the manifest")
    common.add_argument("--json", action="store_true", help="print summaries as JSON")
    common.add_argument("--no-elevate", action="store_true",
                        help="never offer to re-run with sudo")
    common.add_argument("--port", type=int, default=DEFAULT_PORT, help="server port")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("server", parents=[common], help="UDP echo + TCP bandwidth responder")
    p.add_argument("--bind", default="0.0.0.0")
    p.set_defaults(fn=cmd_server)

    p = sub.add_parser("delay", parents=[common], help="RTT / jitter / loss")
    p.add_argument("target")
    p.add_argument("--mode", choices=["udp", "tcp", "icmp"], default="udp")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--interval", type=float, default=0.2)
    p.add_argument("--size", type=int, default=64)
    p.add_argument("--timeout", type=float, default=1.0)
    p.set_defaults(fn=cmd_delay)

    p = sub.add_parser("bandwidth", parents=[common], help="TCP throughput")
    p.add_argument("target")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--direction", choices=["up", "down"], default="up")
    p.add_argument("--interval", type=float, default=0.25)
    p.add_argument("--rate", help="pace the upload at this rate (e.g. 20M); default unpaced")
    p.set_defaults(fn=cmd_bandwidth)

    p = sub.add_parser("stress", parents=[common], help="rate-limited UDP load (safety-gated)")
    p.add_argument("target")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--start-delay", type=float, default=0.0)
    _add_stress_opts(p)
    p.set_defaults(fn=cmd_stress)

    p = sub.add_parser("sniff", parents=[common], help="packet capture (needs CAP_NET_RAW)")
    p.add_argument("--iface", default="lo")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--bpf", help="kernel BPF filter (uses scapy backend)")
    p.add_argument("--host", help="user-space host filter")
    p.add_argument("--filter-port", type=int, help="user-space port filter")
    p.add_argument("--bin", type=float, default=0.5)
    p.set_defaults(fn=cmd_sniff)

    p = sub.add_parser("run", parents=[common],
                       help="integrated run: delay+bandwidth(+load)(+capture) -> report")
    p.add_argument("target")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument("--delay-mode", choices=["udp", "tcp", "icmp"], default="udp")
    p.add_argument("--delay-interval", type=float, default=0.05)
    p.add_argument("--delay-timeout", type=float, default=1.0)
    p.add_argument("--no-bandwidth", action="store_true")
    p.add_argument("--bw-direction", choices=["up", "down"], default="up")
    p.add_argument("--bw-interval", type=float, default=0.25)
    p.add_argument("--bw-rate", help="pace the TCP probe (bandwidth pressure), e.g. 20M")
    _add_stress_opts(p, "--stress-rate", None)
    p.add_argument("--stress-start", type=float, default=10.0)
    p.add_argument("--stress-duration", type=float, default=10.0)
    p.add_argument("--no-isolate", action="store_true",
                   help="run the load generator in-process instead of a child process")
    p.add_argument("--sniff", metavar="IFACE", help="capture on IFACE during the run")
    p.add_argument("--bpf")
    p.add_argument("--sniff-host")
    p.add_argument("--sniff-port", type=int)
    _add_analysis_opts(p)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("report", help="(re)build the HTML/JSON report for a run directory")
    p.add_argument("run_dir")
    p.add_argument("-o", "--output")
    _add_analysis_opts(p)
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("analyze", help="print the correlation summary of a run as JSON")
    p.add_argument("run_dir")
    _add_analysis_opts(p)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("privileges", parents=[common], help="show capability status")
    p.set_defaults(fn=cmd_privileges)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except privileges.PrivilegeError as e:
        print(f"netprobe: {e}", file=sys.stderr)
        return EX_NOPERM
    except ValueError as e:  # includes SafetyError, SchemaError
        print(f"netprobe: {e}", file=sys.stderr)
        return EX_USAGE


if __name__ == "__main__":
    sys.exit(main())
