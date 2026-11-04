"""How this machine's hardware is doing: the reading the agent sends the panel every 30 seconds.

Read-only, through psutil: CPU use and load, memory and swap, each real disk's use, network traffic,
uptime, and temperatures where the machine has sensors psutil can read (most Linux boxes; Windows
usually has none without extra tools, so the panel just shows no temperature). Only numbers, disk
mount points and sensor names leave the machine.
"""
from __future__ import annotations

import platform
import time
from typing import Any, Callable

import psutil

# File systems that are not disks a person fills up: memory, snaps, containers, kernel views.
SKIP_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "autofs",
           "tracefs", "debugfs", "securityfs", "pstore", "efivarfs", "fusectl", "configfs", "ramfs", "nsfs", ""}
SKIP_MOUNTS = ("/snap/", "/var/lib/docker/", "/run/", "/sys/", "/proc/", "/dev/")
MAX_DISKS, MAX_TEMPS = 16, 12


def _usage(u: Any) -> dict[str, Any]:
    return {"total": max(0, int(u.total)), "used": max(0, int(u.used)),
            "percent": round(min(100.0, max(0.0, float(u.percent))), 1)}


def disks(partitions: Callable[[], list[Any]] = psutil.disk_partitions,
          usage: Callable[[str], Any] = psutil.disk_usage) -> list[dict[str, Any]]:
    """Each real disk once (a device mounted twice counts once), fullest first."""
    out, devices = [], set()
    try:
        parts = partitions()
    except (psutil.Error, OSError):
        return []
    for p in parts:
        if p.fstype.lower() in SKIP_FS or "cdrom" in (p.opts or "") or p.mountpoint.startswith(SKIP_MOUNTS):
            continue
        if p.device and p.device in devices:
            continue
        try:
            u = usage(p.mountpoint)
        except (psutil.Error, OSError):
            continue  # an empty card reader, a network drive that is down
        if not u.total:
            continue
        devices.add(p.device)
        out.append({"mount": p.mountpoint[:128], **_usage(u)})
    out.sort(key=lambda d: -d["percent"])
    return out[:MAX_DISKS]


def temperatures(read: Callable[[], dict[str, list[Any]]] | None = None) -> list[dict[str, Any]]:
    """[{"label", "current", "high"}], hottest first; empty where the machine has no readable sensors."""
    read = read or getattr(psutil, "sensors_temperatures", None)
    if read is None:
        return []
    try:
        groups = read() or {}
    except (psutil.Error, OSError, RuntimeError):
        return []
    out = []
    for group, entries in groups.items():
        for e in entries:
            if e.current is None or not -100 <= e.current <= 300:
                continue
            label = f"{group} {e.label}".strip() if e.label else group
            high = e.high if e.high and 0 < e.high <= 300 else None
            out.append({"label": label[:64], "current": round(float(e.current), 1), "high": high})
    out.sort(key=lambda t: -t["current"])
    return out[:MAX_TEMPS]


class Reader:
    """Takes readings one after another: CPU use and network speed are worked out since the last one."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._net: tuple[float, int, int] | None = None
        try:
            psutil.cpu_percent(interval=None)  # the first call only starts the count
        except (psutil.Error, OSError):
            pass

    def _net_rates(self) -> dict[str, Any]:
        try:
            c = psutil.net_io_counters()
        except (psutil.Error, OSError):
            return {}
        if c is None:
            return {}
        now = self.clock()
        out: dict[str, Any] = {"sent": int(c.bytes_sent), "recv": int(c.bytes_recv)}
        if self._net is not None and now > self._net[0]:
            span = now - self._net[0]
            # counters start again after a reboot or a wrap: no speed for that one reading
            if c.bytes_sent >= self._net[1] and c.bytes_recv >= self._net[2]:
                out["sent_rate"] = round((c.bytes_sent - self._net[1]) / span, 1)
                out["recv_rate"] = round((c.bytes_recv - self._net[2]) / span, 1)
        self._net = (now, int(c.bytes_sent), int(c.bytes_recv))
        return out

    def read(self) -> dict[str, Any]:
        cpu: dict[str, Any] = {}
        try:
            cpu["percent"] = round(float(psutil.cpu_percent(interval=None)), 1)
            cpu["cores"] = psutil.cpu_count() or None
        except (psutil.Error, OSError):
            pass
        try:
            cpu["load"] = [round(x, 2) for x in psutil.getloadavg()]
        except (AttributeError, OSError):
            pass
        reading: dict[str, Any] = {"cpu": cpu, "disks": disks(), "net": self._net_rates(), "temps": temperatures(),
                                   "os": f"{platform.system()} {platform.release()}".strip()[:120] or None}
        try:
            reading["memory"] = _usage(psutil.virtual_memory())
            reading["swap"] = _usage(psutil.swap_memory())
        except (psutil.Error, OSError):
            pass
        try:
            reading["uptime_s"] = max(0.0, round(time.time() - psutil.boot_time()))
        except (psutil.Error, OSError):
            pass
        return reading
