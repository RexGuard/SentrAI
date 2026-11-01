"""Tuning: the noisiest sources of alerts this week and what would quiet them, so a new install does not drown
its one or two IT people in alerts.

Out of the box the rules use general baselines. On a live server some of what they flag is normal for that server
(a monitoring service, a CDN, a busy game server scanned all day). GET /ui/tuning ranks what made the most incidents
and alerts in the last TUNING_DAYS days and, for each, a suggestion in plain words: trust a known-good network,
turn on busy-server waves, or leave it (real attacks stay loud). Nothing changes on its own: the page shows where
to set it (Configuration) and the person decides. It also says whether the install is still in its first week,
when more alerts are expected.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from fastapi import FastAPI

from .summary import plain_title
from .waves import network_of

TUNING_DAYS = 7
LEARNING_DAYS = 7
FALSE_WORDS = ("false", "test", "ours", "our own", "expected", "normal", "benign", "known", "monitor")
KEEP_ROWS = 6  # the loudest real-attack rows, for context; the actionable ones come first
NOISY_PER_DAY = 20  # more alerts a day than one or two people can read with care


def _epoch(ts: Any) -> float | None:
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() if ts else None
    except ValueError:
        return None


def false_alarm(inc: dict[str, Any]) -> bool:
    """Closed by a person as not a real attack: rejected, or a closing note that says so."""
    if inc.get("status") == "rejected":
        return True
    note = str(inc.get("resolution") or "").lower()
    return inc.get("status") == "resolved" and any(w in note for w in FALSE_WORDS)


def suggest(kind: str, cat: str, n: int, false_n: int, addresses: int, busy: bool, key: str) -> dict[str, str]:
    if kind == "network" and n >= 3 and false_n * 2 >= n:
        return {"do": "trust", "text": f"Staff closed {false_n} of {n} as not a real attack. If {key} is yours or a "
                "service you use (monitoring, CDN, relay), add it to Trusted addresses so it is not analysed.",
                "where": "TRUSTED_IPS"}
    if kind == "machine" and addresses >= 10 and cat in ("port_scan", "brute_force") and not busy:
        return {"do": "busy", "text": f"{addresses} different addresses did this to one machine. Turn on Busy server "
                "mode to group them into one wave: one alert instead of one each.", "where": "BUSY_SERVER"}
    if false_n * 2 >= n and n >= 3:
        return {"do": "review", "text": f"Staff closed {false_n} of {n} as not a real attack. Look at what they have "
                "in common before trusting anything.", "where": ""}
    return {"do": "keep", "text": "Looks like real attacks. Keep these alerts on.", "where": ""}


def tuning(core: Any) -> dict[str, Any]:
    s = core.settings
    with core.lock:
        now = core.clock.now()
        since = now - TUNING_DAYS * 86400
        incs = [i for i in core.incidents.values() if (i.get("_opened_ts") or 0) >= since]
        alerts = [n for n in core.notifications if (_epoch(n.get("created_at")) or 0) >= since and n.get("kind") != "summary"]
    first = core.audit.records_after(0, 1)
    started = _epoch(first[0]["ts"]) if first else now
    age_days = max(0, int((now - (started or now)) // 86400))

    by_machine: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_net: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for i in incs:
        by_machine[(i.get("host") or "unknown", i.get("category") or "")].append(i)
        net = network_of(i.get("src_ip"))
        if net:
            by_net[net].append(i)

    def row(kind: str, key: str, cat: str, members: list[dict[str, Any]]) -> dict[str, Any]:
        n, f = len(members), sum(1 for m in members if false_alarm(m))
        addrs = len({m.get("src_ip") for m in members if m.get("src_ip")})
        kinds = Counter(plain_title(m.get("category")) for m in members)
        return {"kind": kind, "key": key, "what": plain_title(cat) if cat else kinds.most_common(1)[0][0],
                "incidents": n, "false_alarms": f, "addresses": addrs, "per_day": round(n / TUNING_DAYS, 1),
                "suggestion": suggest(kind, cat, n, f, addrs, s.busy_server, key)}

    rows = [row("machine", host, cat, m) for (host, cat), m in by_machine.items()]
    rows += [row("network", net, "", m) for net, m in by_net.items() if len(m) >= 3]
    rows.sort(key=lambda r: (r["suggestion"]["do"] == "keep", -r["incidents"]))
    per_day = round(len(alerts) / TUNING_DAYS, 1)
    return {
        "days": TUNING_DAYS, "incidents": len(incs), "alerts": len(alerts), "alerts_per_day": per_day,
        "noisy": per_day > NOISY_PER_DAY, "false_alarms": sum(1 for i in incs if false_alarm(i)),
        "learning": {"day": min(age_days + 1, LEARNING_DAYS), "of": LEARNING_DAYS, "on": age_days < LEARNING_DAYS},
        "settings": {"busy_server": s.busy_server, "trusted": sorted(s.trusted_ips)},
        "rows": [r for r in rows if r["suggestion"]["do"] != "keep"][:20]
                + [r for r in rows if r["suggestion"]["do"] == "keep"][:KEEP_ROWS],
    }


def install(app: FastAPI, core: Any) -> None:
    @app.get("/ui/tuning")
    def get_tuning() -> dict[str, Any]:
        return tuning(core)
