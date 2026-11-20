"""Capability model and graceful elevation.

Delay (UDP/TCP modes), bandwidth and congestion run unprivileged.
Packet capture and raw-socket load need ``CAP_NET_RAW``. ICMP delay works
unprivileged when ``net.ipv4.ping_group_range`` includes the user's group,
otherwise it also needs ``CAP_NET_RAW``.

Checks read the *effective* capability set from ``/proc/self/status`` so
that a ``setcap``-ed interpreter or a container granted ``NET_RAW`` is
recognized without requiring full root. A missing capability always raises
:class:`PrivilegeError` with a remediation hint: nothing fails silently.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

CAPABILITIES = {"CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13}
PROC_STATUS = "/proc/self/status"


class PrivilegeError(PermissionError):
    def __init__(self, feature: str, missing: list[str], hint: str) -> None:
        self.feature = feature
        self.missing = missing
        self.hint = hint
        super().__init__(f"{feature} requires {', '.join(missing)}.\n{hint}")


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def effective_capabilities(status_path: str | Path = PROC_STATUS) -> int | None:
    """Bitmask of effective capabilities, or None if it cannot be read."""
    try:
        text = Path(status_path).read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    return None


def has_capability(name: str, status_path: str | Path = PROC_STATUS) -> bool:
    bit = CAPABILITIES[name]
    caps = effective_capabilities(status_path)
    if caps is not None:
        return bool(caps & (1 << bit))
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def missing_capabilities(caps: list[str], status_path: str | Path = PROC_STATUS) -> list[str]:
    return [c for c in caps if not has_capability(c, status_path)]


def elevation_hint(caps: list[str]) -> str:
    if not is_linux():
        return (
            "This feature uses Linux-only kernel interfaces (AF_PACKET, CAP_NET_RAW); "
            "it is not available on this platform."
        )
    py = os.path.realpath(sys.executable)
    cap_list = ",".join(c.lower() for c in caps)
    return (
        "Options:\n"
        f"  1) re-run with sudo:     sudo {py} -m netprobe ...\n"
        f"  2) grant capabilities:   sudo setcap {cap_list}+eip {py}\n"
        "     (applies to every script run by that interpreter; prefer a venv copy)\n"
        "  3) in a container:       docker run --cap-add NET_RAW ..."
    )


def require(feature: str, caps: list[str] | tuple[str, ...] = ("CAP_NET_RAW",)) -> None:
    """Raise :class:`PrivilegeError` unless all ``caps`` are effective."""
    caps = list(caps)
    if not is_linux():
        raise PrivilegeError(feature, caps, elevation_hint(caps))
    missing = missing_capabilities(caps)
    if missing:
        raise PrivilegeError(feature, missing, elevation_hint(missing))


def privilege_report() -> dict:
    geteuid = getattr(os, "geteuid", None)
    return {
        "platform": sys.platform,
        "euid": geteuid() if geteuid else None,
        "capabilities": {c: has_capability(c) for c in CAPABILITIES} if is_linux() else {},
    }


def can_prompt() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty() and shutil.which("sudo") is not None


def reexec_with_sudo(argv: list[str]) -> None:  # pragma: no cover - replaces process
    """Replace the current process with ``sudo python -m netprobe <argv>``."""
    os.execvp("sudo", ["sudo", "-E", sys.executable, "-m", "netprobe", *argv])
