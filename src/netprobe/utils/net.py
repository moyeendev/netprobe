"""Target parsing, IPv4 resolution, address safety classification."""

from __future__ import annotations

import ipaddress
import re
import socket

DEFAULT_PORT = 47001

_RATE_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([kKmMgG]?)(bps|bit|b)?\s*$")
_RATE_MULT = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}


def parse_target(target: str, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """``"host"`` / ``"host:port"`` -> (host, port). IPv4/hostnames only."""
    if not target:
        raise ValueError("a target is required")
    if target.startswith("[") or target.count(":") > 1:
        raise ValueError("IPv6 targets are not supported in this version (see README, Limitations)")
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = target, default_port
    if not 0 < port < 65536:
        raise ValueError(f"invalid port {port}")
    return host, port


def resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"cannot resolve {host!r} to an IPv4 address")
    return infos[0][4][0]


def is_private_target(ip: str) -> bool:
    """True for RFC 1918, loopback, link-local and CGNAT (RFC 6598) unicast.

    Unspecified, multicast and limited-broadcast addresses are never
    considered safe targets.
    """
    addr = ipaddress.IPv4Address(ip)
    if addr.is_unspecified or addr.is_multicast or addr == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if addr in ipaddress.IPv4Network("0.0.0.0/8"):
        return False
    cgnat = ipaddress.IPv4Network("100.64.0.0/10")
    return bool(addr.is_loopback or addr.is_link_local or addr.is_private or addr in cgnat)


def parse_rate(text: str | float | int) -> float:
    """``"10M"`` -> 1e7 bits/s. Plain numbers are bits/s."""
    if isinstance(text, (int, float)):
        return float(text)
    m = _RATE_RE.match(text)
    if not m:
        raise ValueError(f"cannot parse rate {text!r} (examples: 500k, 10M, 1G)")
    return float(m.group(1)) * _RATE_MULT[m.group(2).lower()]
