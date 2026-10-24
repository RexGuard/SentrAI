"""What containment must never touch: protected addresses, private networks, infrastructure and accounts.

Entries are plain addresses ("203.0.113.7"), networks ("10.0.0.0/8") or names ("localhost"). A target
matches when it equals an entry or falls inside one of its networks; IPv4-mapped IPv6 counts as IPv4.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable

# Private and shared address space (RFC 1918, RFC 6598 carrier-grade NAT, RFC 4193 unique local IPv6).
# On by default: an attack seen from inside the network is reported, but a person decides on the block,
# because the "attacker" may be a NAT gateway, a proxy or a colleague's laptop.
PRIVATE_NETS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7"

# Accounts that are never auto-locked: locking them can shut the operator or a service out.
DEFAULT_USERS = (
    "root,admin,administrator,sentrai,cactai,"
    "www-data,nginx,apache,httpd,mysql,postgres,redis,sshd,daemon,nobody,systemd-network,systemd-resolve,"
    "system,localsystem,localservice,networkservice"
)

OFF = ("", "off", "none", "0", "no", "false")


def split(text: str | None) -> set[str]:
    return {x.strip() for x in (text or "").split(",") if x.strip()}


def nets(text: str | None) -> set[str]:
    """A comma list of networks, or nothing when it says off/none."""
    return set() if (text or "").strip().lower() in OFF else split(text)


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def matches(target: str | None, entries: Iterable[str]) -> bool:
    """True when the target is one of the entries or inside one of their networks."""
    if not target:
        return False
    target = str(target).strip()
    ip = _ip(target)
    for entry in entries:
        if target == entry:
            return True
        if ip is None:
            continue
        if "/" in entry:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except (ValueError, TypeError):
                continue
        elif (other := _ip(entry)) is not None and other == ip:
            return True
    return False


def user_matches(target: str | None, users: Iterable[str]) -> bool:
    """Account names compare without case (Windows treats Administrator and administrator as one)."""
    if not target:
        return False
    t = str(target).strip().lower()
    return any(t == u.strip().lower() for u in users)


def detect_infra(resolv: Path = Path("/etc/resolv.conf"), route: Path = Path("/proc/net/route")) -> set[str]:
    """This machine's DNS servers and default gateway (Linux; empty elsewhere). Blocking either one
    cuts the server off, so they join the protected list automatically."""
    found: set[str] = set()
    try:
        for line in resolv.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m and _ip(m.group(1)) is not None:
                found.add(str(_ip(m.group(1))))
    except OSError:
        pass
    try:
        for line in route.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            cols = line.split()
            if len(cols) > 2 and cols[1] == "00000000" and cols[2] != "00000000":
                found.add(str(ipaddress.IPv4Address(bytes.fromhex(cols[2])[::-1])))
    except (OSError, ValueError):
        pass
    return {ip for ip in found if not ipaddress.ip_address(ip).is_loopback}
