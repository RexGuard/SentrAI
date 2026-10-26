"""What runs on this machine: the listening services the agent reports to the panel every minute.

Read-only: the listening sockets (psutil) and the name of the process behind each one. Where the
process name cannot be read (another user's process without root), the well-known port names it.
Only names, ports and protocols leave the machine; no command lines, users or file paths.
"""
from __future__ import annotations

import socket
from typing import Any, Callable, Iterable

import psutil

# Ports most small-business servers run, named the way a person would say them.
KNOWN_PORTS = {
    21: "ftp", 22: "sshd", 25: "smtp", 53: "dns", 80: "web", 110: "pop3", 143: "imap", 443: "web",
    465: "smtp", 587: "smtp", 993: "imap", 995: "pop3", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "web", 8443: "web", 9200: "elasticsearch",
    11211: "memcached", 25565: "minecraft", 27015: "game-server", 27017: "mongodb",
}
# Process names that say more than the port does, shortened (nginx: worker process -> nginx).
NAME_FIXES = {"sshd-session": "sshd", "mysqld": "mysql", "mariadbd": "mysql", "postgres": "postgres",
              "httpd": "apache", "apache2": "apache", "redis-server": "redis", "mongod": "mongodb",
              "java": None, "python": None, "python3": None, "node": None}  # None: the port names it better
LOOPBACK = {"127.0.0.1", "::1"}


def _name(process: str | None, port: int) -> str:
    base = (process or "").strip().lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base:
        fixed = NAME_FIXES.get(base, base)
        if fixed:
            return fixed
    return KNOWN_PORTS.get(port, f"port-{port}")


def listening(connections: Callable[[], Iterable[Any]] | None = None,
              process_name: Callable[[int], str | None] | None = None,
              include_local: bool = False) -> list[dict[str, Any]]:
    """[{"name", "port", "proto", "process"}] for every service listening on this machine, one per
    port and protocol. Services that only listen on loopback are left out unless include_local."""
    def default_conns():
        return psutil.net_connections(kind="inet")

    def default_name(pid: int) -> str | None:
        try:
            return psutil.Process(pid).name()
        except (psutil.Error, OSError):
            return None

    conns = connections or default_conns
    pname = process_name or default_name
    try:
        rows = list(conns())
    except (psutil.Error, OSError):
        return []
    found: dict[tuple[int, str], dict[str, Any]] = {}
    for c in rows:
        proto = "udp" if c.type == socket.SOCK_DGRAM else "tcp"
        if proto == "tcp" and c.status != psutil.CONN_LISTEN:
            continue
        if proto == "udp" and (c.raddr or not c.laddr or int(c.laddr[1]) not in KNOWN_PORTS):
            continue  # client and short-lived UDP sockets look the same as services: keep known ones only
        if not c.laddr:
            continue
        ip, port = c.laddr[0], int(c.laddr[1])
        if ip in LOOPBACK and not include_local:
            continue
        key = (port, proto)
        if key in found:
            continue
        process = pname(c.pid) if c.pid else None
        found[key] = {"name": _name(process, port), "port": port, "proto": proto,
                      "process": (process or None) and process[:64]}
    return sorted(found.values(), key=lambda s: (s["port"], s["proto"]))
