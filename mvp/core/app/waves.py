"""Waves: many addresses doing the same kind of attack to one machine, handled as one thing.

A public game server or a big network is scanned and password-guessed by hundreds of addresses a
day. Each one is still its own incident (so it can be blocked, approved and undone on its own), but
once WAVE_MIN_ADDRESSES of them hit the same machine with the same kind of attack within
WAVE_WINDOW_MIN, they are grouped into a wave:

- one alert when the wave starts, then one summary every WAVE_UPDATE_MIN instead of one per address;
- the wave counts on the risk index about as much as its worst member, not the sum of all of them,
  so background noise does not pin the index at 100 and something new still stands out.

BUSY_SERVER=on turns waves on (config.py). The grouping is kept in memory and in the saved state
(meta "waves"); each incident carries the id of its wave.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

# Incident statuses a new address can join a wave from: the same ones events merge into (saguaro.py).
JOIN_STATUSES = ("open", "acknowledged", "contained")
KEEP_WAVES = 200  # quiet waves kept for the dashboard; the oldest go first

# How much each extra member of a wave adds to its risk points, and the most a wave can add in all,
# as multiples of its worst member: 300 scanners count like two, not like 300.
EXTRA_SHARE = 0.1
MAX_TIMES_WORST = 2.0


def network_of(address: str | None) -> str | None:
    """The /24 (IPv4) or /48 (IPv6) an address is in: one hosting provider's block, roughly."""
    try:
        ip = ipaddress.ip_address(str(address or "").strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def wave_points(contributions: list[float]) -> float:
    """A wave's share of the risk index: its worst member, plus a little for each other one, capped."""
    if not contributions:
        return 0.0
    ranked = sorted(contributions, reverse=True)
    worst = ranked[0]
    return min(worst + EXTRA_SHARE * sum(ranked[1:]), MAX_TIMES_WORST * worst)


class Waves:
    def __init__(self, min_addresses: int, window_s: float, update_s: float, categories: set[str]) -> None:
        self.min_addresses = max(0, int(min_addresses))
        self.window_s = max(1.0, float(window_s))
        self.update_s = max(0.0, float(update_s))
        self.categories = set(categories)
        self.waves: dict[str, dict[str, Any]] = {}
        self._next = 1

    @property
    def enabled(self) -> bool:
        return self.min_addresses >= 2

    # ------------------------------------------------------------------ grouping
    def _active(self, host: str, category: str, now: float) -> dict[str, Any] | None:
        for w in reversed(list(self.waves.values())):
            if w["host"] == host and w["category"] == category and now - w["_last_ts"] <= self.window_s:
                return w
        return None

    def consider(self, inc: dict[str, Any], incidents: dict[str, dict[str, Any]],
                 now: float) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Called for every new incident. Returns (wave, incidents that just joined) when it is part of
        one: only the new incident when a wave was already going, all of them when this one starts it."""
        if not self.enabled or inc["category"] not in self.categories or inc.get("wave"):
            return None
        host, category = str(inc.get("host") or "unknown"), inc["category"]
        wave = self._active(host, category, now)
        if wave is not None:
            self._add(wave, inc, now)
            return wave, [inc]
        recent = [i for i in incidents.values()
                  if not i.get("wave") and i["category"] == category and str(i.get("host") or "unknown") == host
                  and i["status"] in JOIN_STATUSES and now - i["_opened_ts"] <= self.window_s]
        if len({i.get("src_ip") or i.get("user") or i["id"] for i in recent}) < self.min_addresses:
            return None
        wave = self._start(host, category, min(i["_opened_ts"] for i in recent), now)
        for i in sorted(recent, key=lambda x: x["_opened_ts"]):
            self._add(wave, i, now)
        return wave, recent

    def _start(self, host: str, category: str, first_ts: float, now: float) -> dict[str, Any]:
        wid = f"WAVE-{self._next:03d}"
        self._next += 1
        wave = {"id": wid, "host": host, "category": category, "incidents": [], "addresses": [],
                "networks": {}, "updates_sent": 0, "folded": {},
                "_first_ts": first_ts, "_last_ts": now, "_next_update_ts": now + self.update_s}
        self.waves[wid] = wave
        while len(self.waves) > KEEP_WAVES:
            self.waves.pop(next(iter(self.waves)))
        return wave

    def _add(self, wave: dict[str, Any], inc: dict[str, Any], now: float) -> None:
        inc["wave"] = wave["id"]
        wave["incidents"].append(inc["id"])
        wave["_last_ts"] = now
        addr = inc.get("src_ip")
        if addr and addr not in wave["addresses"]:
            wave["addresses"].append(addr)
            if net := network_of(addr):
                wave["networks"][net] = wave["networks"].get(net, 0) + 1

    def get(self, wid: str | None) -> dict[str, Any] | None:
        return self.waves.get(wid) if wid else None

    # -------------------------------------------------------------------- alerts
    def fold(self, wave: dict[str, Any], kind: str) -> None:
        """An alert about one member that goes into the next summary instead of out on its own."""
        wave["folded"][kind] = wave["folded"].get(kind, 0) + 1
        wave["_new_since_update"] = True

    def due(self, now: float) -> list[dict[str, Any]]:
        """Waves with folded alerts whose summary is due."""
        return [w for w in self.waves.values() if w.get("_new_since_update") and now >= w["_next_update_ts"]]

    def sent_update(self, wave: dict[str, Any], now: float) -> None:
        wave["folded"] = {}
        wave["_new_since_update"] = False
        wave["updates_sent"] += 1
        wave["_next_update_ts"] = now + self.update_s

    @staticmethod
    def top_networks(wave: dict[str, Any], n: int = 3) -> list[tuple[str, int]]:
        """The networks with the most addresses in the wave; a network with only one is not worth naming."""
        return [(net, c) for net, c in Counter(wave["networks"]).most_common(n) if c > 1]

    # ---------------------------------------------------------- saving, the API
    def saved(self) -> dict[str, Any]:
        return {"next": self._next, "waves": list(self.waves.values())}

    def restore(self, data: dict[str, Any] | None) -> None:
        if not data:
            return
        self._next = int(data.get("next", self._next))
        self.waves = {w["id"]: w for w in data.get("waves", []) if isinstance(w, dict) and "id" in w}

    def public(self, wave: dict[str, Any], now: float, iso: Any) -> dict[str, Any]:
        return {
            "id": wave["id"], "host": wave["host"], "category": wave["category"],
            "addresses": len(wave["addresses"]), "incidents": list(wave["incidents"]),
            "networks": [{"network": net, "addresses": count} for net, count in self.top_networks(wave, 10)],
            "started_at": iso(wave["_first_ts"]), "last_seen_at": iso(wave["_last_ts"]),
            "active": now - wave["_last_ts"] <= self.window_s, "updates_sent": wave["updates_sent"],
        }
