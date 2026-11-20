# Privilege and safety model

## Capability matrix

| Command / API call                  | Privilege needed | Why |
|-------------------------------------|------------------|-----|
| `delay --mode udp` / `s.delay()`    | none             | ordinary UDP socket to `netprobe server` |
| `delay --mode tcp`                  | none             | TCP `connect()` timing (works against any host/port) |
| `delay --mode icmp`                 | none **or** `CAP_NET_RAW` | `SOCK_DGRAM`/`IPPROTO_ICMP` works if `net.ipv4.ping_group_range` admits the user's group; otherwise a raw ICMP socket is needed |
| `bandwidth` / `s.bandwidth()`       | none             | TCP; `TCP_INFO` is readable by the socket owner |
| `congestion` / `s.congestion()`     | none             | pure function of recorded data |
| `stress` (UDP)                      | none             | ordinary UDP socket, but gated by the safety policy below |
| `stress --raw`                      | `CAP_NET_RAW`    | `IPPROTO_RAW` socket to set TOS/TTL |
| `sniff` / `run --sniff`             | `CAP_NET_RAW`    | `AF_PACKET` socket (or scapy/libpcap) |
| `examples/run_*_scenario.sh`        | root             | creates network namespaces and attaches `tc netem` (`CAP_NET_ADMIN`) |

## Detection

`netprobe.utils.privileges` reads the **effective** capability mask (`CapEff`)
from `/proc/self/status`. This recognizes, without requiring full root:

* `sudo`/root,
* an interpreter given file capabilities (`setcap cap_net_raw+eip`),
* a container started with `--cap-add NET_RAW`.

`netprobe privileges` prints the current state.

## Graceful elevation — never silent failure

1. Unprivileged commands never call the check and never ask for elevation.
2. Privileged subcommands (`sniff`, `stress --raw`, `run --sniff`) check
   **before starting any probe**, so a run never half-starts.
3. If a capability is missing, NetProbe prints which capability, why, and
   three remediation options (sudo, `setcap`, container flag). On an
   interactive terminal it offers to re-execute the same command line under
   `sudo`; `--no-elevate` disables the offer (for scripts/CI). The exit code
   is 77 (`EX_NOPERM`).
4. In the Python API the same condition raises
   `netprobe.utils.privileges.PrivilegeError` (a `PermissionError` subclass)
   carrying `.feature`, `.missing` and `.hint`.
5. On non-Linux platforms privileged features raise the same error with an
   explanation that they depend on Linux kernel interfaces.

Recommended least-privilege setup for a field device:

```bash
python -m venv /opt/netprobe && /opt/netprobe/bin/pip install netprobe
sudo setcap cap_net_raw+eip "$(readlink -f /opt/netprobe/bin/python3)"
```

(File capabilities apply to every script run by that interpreter; use a
dedicated venv copy of the interpreter, not the system one.)

## Load-generation safety policy

Enforced in `netprobe.probes.stress.check_safety`, i.e. in the API as well
as the CLI:

| Rule | Default | Override |
|------|---------|----------|
| explicit acknowledgement | required | `i_understand=True` / `--i-understand-this-sends-traffic` (no default-on) |
| rate | 10 Mbit/s | any value ≤ 1 Gbit/s; above needs `rate_cap_override=True` / `--max-rate-override` |
| duration | 10 s | ≤ 600 s, no override |
| packet size | 1200 B | 32–1472 B, no override |
| target | private / loopback / link-local / CGNAT IPv4 only | `allow_public=True` / `--allow-public-target` |
| multicast, broadcast, `0.0.0.0/8` | always refused | none |

There is no "as fast as possible" mode. Stress packets carry an `NPST`
magic so that `netprobe server` drops rather than echoes them.
