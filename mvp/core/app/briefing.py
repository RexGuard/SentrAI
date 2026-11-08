"""Sentry's proactive side: the briefing, the safety drill and "what happened then".

Three ideas taken from network assistants that work before anyone asks (HPE Aruba's Marvis among them),
cut down to what a business owner with no IT team needs:

- ``briefing``: what SentrAI handled by itself and what still needs a person, since a given time. The chat
  shows it when it opens, so the owner sees "2 handled, 1 needs you" without typing a question. Fixes that
  SentrAI checked afterwards say whether they worked.
- ``drill``: a safety drill. Pretend attacks (password guessing, a website attack, someone looking for weak
  spots, a decoy being touched) go through a private copy of SentrAI's detection rules, and the drill reports
  which ones were spotted. Nothing is sent anywhere, no incident is opened and nothing is blocked: the copy is
  thrown away afterwards. It also checks that protection is on, every computer is reporting, earlier fixes
  worked and backups are fresh.
- ``timeline``: what happened between two times ("last night", "Tuesday afternoon"): incidents opened, what
  SentrAI did, decisions people made. All read-only.

Everything here reads the core; nothing changes state, so the chat's read-only promise holds.
"""

from __future__ import annotations

import inspect
import time
from datetime import datetime
from typing import Any, Callable

from .classifier import default_chain
from .rules import RulesEngine
from .summary import PLAIN_ACTIONS, plain_names, plain_title

STILL_OPEN = ("open", "acknowledged", "contained")
NEEDS_A_PERSON = ("open", "acknowledged")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MAX_ITEMS = 8
MAX_TIMELINE = 60
SILENT_AFTER_S = 30 * 60      # a computer quiet for longer than this is "not reporting"
BACKUP_STALE_S = 2 * 86400    # no good backup for two days


def _epoch(iso: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(iso)).timestamp()
    except (TypeError, ValueError):
        return None


def _when(value: Any, default: float) -> float:
    """An ISO time, a number of seconds since 1970, or nothing (the default)."""
    if value in (None, ""):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    ts = _epoch(value)
    if ts is None:
        raise ValueError(f"not a time: {value!r} (use an ISO time like 2026-11-08T09:00:00+08:00)")
    return ts


def how_sure(inc: dict[str, Any]) -> str:
    """How sure SentrAI is that this is real, in words an owner understands."""
    if inc.get("needs_review"):
        return "not sure: a person should look"
    reason = str(inc.get("classification_reason") or "")
    if reason.startswith(("Tripwire:", "Cactus spine:")):
        return "certain: a decoy was touched, and no real user ever touches one"
    if inc.get("classified_by") == "rules" or inc.get("strong_signal"):
        return "sure: it matched a known attack pattern"
    conf = float(inc.get("ai_confidence") or 0)
    return "fairly sure" if conf >= 0.8 else "somewhat sure"


def _fix_check(actions: list[dict[str, Any]]) -> str | None:
    """What the after-action checks found, in a few words, or None when nothing was checked yet."""
    checks = [a["check"] for a in actions if isinstance(a.get("check"), dict)]
    if not checks:
        return "check pending" if any(a.get("status") in ("active", "permanent") for a in actions) else None
    if any(c.get("worked") is False for c in checks):
        return "did not work"
    if any(c.get("disruption") is True for c in checks):
        return "worked, may be getting in the way of real users"
    if all(c.get("worked") is True for c in checks):
        return "checked: it worked"
    return "could not be checked"


def _did(actions: list[dict[str, Any]]) -> str:
    kinds = list(dict.fromkeys(PLAIN_ACTIONS.get(str(a.get("type")), str(a.get("type") or "").replace("_", " "))
                               for a in actions))
    return ", ".join(k for k in kinds if k) or "acted"


def _item(inc: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    host = str(inc.get("host") or "")
    return {"incident": inc.get("id"), "title": plain_title(inc.get("category")), "severity": inc.get("severity"),
            "status": inc.get("status"), "computer": names.get(host) or host or None, "opened_at": inc.get("opened_at"),
            "how_sure": how_sure(inc)}


def briefing(core: Any, names: dict[str, str] | None = None, since: Any = None, hours: float = 24.0) -> dict[str, Any]:
    """What SentrAI handled on its own and what needs a person, for incidents active since `since`
    (default: the last `hours`). Open incidents that need a decision are always listed, however old."""
    names = names or {}
    now = core.clock.now()
    start = _when(since, now - max(0.25, min(float(hours or 24), 24 * 31)) * 3600)
    incs = core.list_incidents()
    handled, needs_you, by_person = [], [], 0
    for inc in incs:
        actions = [a for a in inc.get("actions") or [] if (_epoch(a.get("applied_at")) or 0) >= start]
        if inc.get("status") in NEEDS_A_PERSON:
            needs_you.append(inc)
            continue
        if not actions:
            continue
        if any(a.get("mode") == "autonomous" for a in actions):
            handled.append((inc, actions))
        else:
            by_person += 1
    needs_you.sort(key=lambda i: str(i.get("opened_at") or ""), reverse=True)
    needs_you.sort(key=lambda i: (not i.get("sla_breached"), SEVERITY_RANK.get(str(i.get("severity")), 9)))
    handled.sort(key=lambda p: max(str(a.get("applied_at") or "") for a in p[1]), reverse=True)
    checks = [a["check"] for i in incs for a in i.get("actions") or []
              if isinstance(a.get("check"), dict) and (_epoch(a["check"].get("at")) or 0) >= start]
    out_handled = [{**_item(i, names), "did": _did(a), "fix_check": _fix_check(a),
                    "until": min((str(x.get("expires_at")) for x in a if x.get("status") == "active"), default=None)}
                   for i, a in handled[:MAX_ITEMS]]
    out_needs = [{**_item(i, names), "suggested": plain_names(str(i.get("recommended_action") or "")),
                  "overdue": bool(i.get("sla_breached") and not i.get("acked"))}
                 for i in needs_you[:MAX_ITEMS]]
    risk = core.risk(history=0)
    if needs_you:
        n = len(needs_you)
        headline = f"{n} thing{'s' if n != 1 else ''} need{'s' if n == 1 else ''} you"
        if handled:
            headline += f"; SentrAI handled {len(handled)} by itself"
    elif handled:
        headline = f"Nothing needs you. SentrAI handled {len(handled)} thing{'s' if len(handled) != 1 else ''} by itself"
    else:
        headline = "All quiet. Nothing needs you"
    return {
        "since": core.clock.iso(start), "now": core.clock.iso(now), "headline": headline + ".",
        "band": risk.get("band"), "protection": "off" if risk.get("monitor_only") else "on",
        "handled_count": len(handled), "needs_you_count": len(needs_you), "decided_by_people": by_person,
        "fixes_checked": {"worked": sum(1 for c in checks if c.get("worked") is True),
                          "did_not_work": sum(1 for c in checks if c.get("worked") is False)},
        "handled": out_handled, "needs_you": out_needs,
    }


# ------------------------------------------------------------------ safety drill
DRILL_HOST = "sentrai-drill"
DRILL_IP = "192.0.2.{n}"  # TEST-NET-1: an address range that never exists on the internet


def _drill_event(n: int, raw: str, source: str, ip: int, sec: int, layer: str = "web") -> dict[str, Any]:
    return {"event_id": f"drill-{n}", "timestamp": f"2026-01-01T00:{sec // 60:02d}:{sec % 60:02d}+00:00",
            "source": source, "layer": layer, "src_ip": DRILL_IP.format(n=ip), "user": "drill",
            "host": DRILL_HOST, "raw": raw, "drill": True}


# (what an owner would call it, the kind SentrAI should see, the pretend log lines)
DRILLS: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("Someone guessing passwords on your sign-in page", "brute_force",
     [("POST /login 401 user=admin", "flask_auth")] * 6),
    ("A break-in attempt through your website's search box", "sql_injection",
     [("GET /search?q=' OR 1=1 -- 200", "flask_access")]),
    ("A stranger looking for weak spots on your website", "port_scan",
     [(f"GET /wp-admin/setup-config{i}.php 404", "flask_access") for i in range(12)]),
    ("Someone using a fake password SentrAI planted as bait", "brute_force",
     [("tripwire honeytoken_credential: decoy password used on /login", "tripwire")]),
]


def _fresh_rules(rules: RulesEngine | None) -> RulesEngine:
    """A new rules engine with the same limits as the live one, and none of its memory."""
    if rules is None:
        return RulesEngine()
    params = inspect.signature(RulesEngine.__init__).parameters
    return RulesEngine(**{k: getattr(rules, k) for k in params if k != "self" and hasattr(rules, k)})


def drill(core: Any, names: dict[str, str] | None = None, backups: Any = None,
          machines: Callable[[], list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    """Run the safety drill. Read-only: the pretend attacks go through a throw-away copy of the rules."""
    started = time.monotonic()
    names = names or {}
    chain = default_chain(_fresh_rules(getattr(core, "rules", None)))
    attacks = []
    n = 0
    for i, (label, want, lines) in enumerate(DRILLS):
        got = None
        for raw, source in lines:
            got = chain.classify(_drill_event(n, raw, source, 10 + i, n), 0.0)
            n += 1
            if got.category == want:
                break
        spotted = got is not None and got.category == want
        attacks.append({"attack": label, "spotted": spotted,
                        "as": plain_title(got.category) if got else None})
    checks = []
    prot = core.protection()
    checks.append({"check": "Protection is switched on", "ok": prot.get("protection") == "on",
                   "detail": "SentrAI can block attackers" if prot.get("protection") == "on"
                   else "SentrAI is only watching and will not block anything until it is switched back on"})
    limits = core.limits()
    auto = [PLAIN_ACTIONS.get(t, t.replace("_", " ")) for t in limits.get("auto_actions") or []]
    checks.append({"check": "SentrAI may act on its own in an emergency", "ok": bool(auto),
                   "detail": ("it may: " + ", ".join(auto[:4])) if auto
                   else "every action waits for a person, so attacks at night wait until morning"})
    now = core.clock.now()
    computers = [m for m in (machines() if machines else core.machines()) if m.get("host") != DRILL_HOST]
    quiet = [names.get(str(m["host"])) or m["host"] for m in computers
             if m.get("silent") or (m.get("last_seen") and now - (_epoch(m["last_seen"]) or now) > SILENT_AFTER_S)]
    checks.append({"check": "Every computer is reporting in", "ok": bool(computers) and not quiet,
                   "detail": (f"{len(computers)} computer{'s' if len(computers) != 1 else ''} reporting" if computers and not quiet
                              else "no computer has reported yet" if not computers
                              else "not heard from lately: " + ", ".join(map(str, quiet[:5])))})
    checks_done = [a["check"] for i in core.list_incidents() for a in i.get("actions") or [] if isinstance(a.get("check"), dict)]
    failed = sum(1 for c in checks_done if c.get("worked") is False)
    if checks_done:
        checks.append({"check": "Earlier fixes worked when SentrAI checked them", "ok": failed == 0,
                       "detail": f"{len(checks_done) - failed} of {len(checks_done)} worked"})
    if backups is not None:
        try:
            st = backups.status()
        except Exception:  # noqa: BLE001  a broken backup folder must not break the drill
            st = None
        if st is not None:
            last = next((b for b in st.get("backups") or [] if b.get("reason") != "before_restore"), None)
            age = now - float(last.get("created_ts") or 0) if last else None
            ok = bool(last) and not st.get("overdue") and (age is None or age < BACKUP_STALE_S)
            checks.append({"check": "A recent backup exists", "ok": ok,
                           "detail": (f"last one {round(age / 3600)} hours ago" if last and age is not None
                                      else "no backup yet") + ("; backups are switched off" if not st.get("enabled") else "")})
    spotted = sum(1 for a in attacks if a["spotted"])
    problems = [c for c in checks if not c["ok"]]
    if spotted == len(attacks) and not problems:
        verdict = "Passed. SentrAI spotted every pretend attack and everything around it is ready."
    elif spotted == len(attacks):
        verdict = f"SentrAI spotted every pretend attack, but {len(problems)} thing{'s' if len(problems) != 1 else ''} need attention."
    else:
        verdict = (f"SentrAI missed {len(attacks) - spotted} of {len(attacks)} pretend attacks. "
                   "SentrAI's team should look at this.")
    return {"verdict": verdict, "passed": spotted == len(attacks) and not problems,
            "attacks": attacks, "checks": checks, "took_ms": round((time.monotonic() - started) * 1000),
            "note": "A drill only: pretend attacks went through a private copy of SentrAI's detection. "
                    "Nothing was sent, opened or blocked."}


# ------------------------------------------------------------------ what happened then
def timeline(core: Any, names: dict[str, str] | None = None, since: Any = None, until: Any = None,
             computer: str | None = None) -> dict[str, Any]:
    """Incidents opened, actions taken and people's decisions between two times, oldest first."""
    names = names or {}
    now = core.clock.now()
    end = _when(until, now)
    start = _when(since, end - 24 * 3600)
    if start > end:
        start, end = end, start
    entries: list[dict[str, Any]] = []
    opened = 0
    for inc in core.list_incidents(host=computer) if computer else core.list_incidents():
        host = str(inc.get("host") or "")
        where = names.get(host) or host or None
        for t in inc.get("timeline") or []:
            ts = _epoch(t.get("ts"))
            if ts is None or not start <= ts <= end:
                continue
            kind = str(t.get("kind") or "")
            if kind in ("notified", "delivered"):
                continue  # messages sent about it: noise for "what happened"
            opened += kind == "detected"
            entries.append({"at": t.get("ts"), "incident": inc.get("id"), "what": plain_title(inc.get("category")),
                            "computer": where, "kind": kind, "text_untrusted": plain_names(str(t.get("text") or ""))[:220],
                            "_ts": ts})
    entries.sort(key=lambda e: e["_ts"])
    more = max(0, len(entries) - MAX_TIMELINE)
    out = [{k: v for k, v in e.items() if k != "_ts"} for e in entries[-MAX_TIMELINE:]]
    return {"from": core.clock.iso(start), "to": core.clock.iso(end), "incidents_opened": opened,
            "entries": out, **({"older_entries_left_out": more} if more else {}),
            **({} if out else {"note": "Nothing happened in this window."})}
