"""The one-page client summary: what happened on the client's machines in the last day or week.

Plan items 10, 11 and 14. Written for an owner or CEO, not for the security team: plain words,
no internal part names, and a short "how to check this" line backed by the audit fingerprint.
Every number comes from the same incidents, actions and alerts the evidence reports use.

The client picks daily or weekly (and the time of day) on the dashboard or with
SENTRAI_SUMMARY / SENTRAI_SUMMARY_AT / SENTRAI_SUMMARY_DAY. The choice is kept in summary.json
next to the audit database. At each due time the core queues a "summary" notice with a signed
link to the PDF, and the alert channels (Telegram, email) carry it to the client.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import anchor
from .pdfdoc import ACCENT, BLACK, BOLD, EDGE, MUTED, PAGE_W, SOFT_ON_DARK, Column, PdfDoc, text_width

if TYPE_CHECKING:
    from .saguaro import Saguaro

PERIODS = {"daily": 1, "weekly": 7}
EVERY = ("daily", "weekly", "off")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
OPEN = ("open", "acknowledged")
CLOSED = ("resolved", "rejected")
MAX_ROWS = 6  # rows per table, so the summary always fits on one page

# What each kind of threat is, in everyday words.
PLAIN_TITLES = {
    "brute_force": "Password guessing",
    "sql_injection": "Attack on the website's database",
    "xss": "Attempt to plant code on the website",
    "port_scan": "Someone looking for a way in",
    "privilege_escalation": "Attempt to take over a machine",
    "data_exfiltration": "Large data download",
    "misconfiguration": "Unsafe setting",
    "log_tampering": "Attempt to erase the records",
    "malware": "Harmful file or program",
    "prompt_injection": "Attempt to trick the AI",
    "unauthorised_admin": "Administrator access from an unrecognised sign-in",
}

# What a containment step does, in everyday words.
PLAIN_ACTIONS = {
    "block_ip": "blocked an address",
    "lock_user": "locked an account",
    "rate_limit": "slowed down sign-in attempts",
    "waf_rule": "added a website filter",
    "kill_process": "stopped a harmful program",
    "revoke_public_acl": "closed public access",
}


# The internal part names, as the job each one does. Client-facing pages (reports, summary) use these.
ROLE_NAMES = {
    "Countersign": "safety check", "Gatehouse": "website monitor", "Vault": "database monitor",
    "Watchtower": "network monitor", "Garrison-Linux": "Linux responder", "Garrison-Win": "Windows responder",
    "Watchdog": "collector monitor", "Scribe": "record keeper", "Warden": "risk engine", "Cyanide": "AI responder",
    "HelpDesk": "help desk", "Jev": "AI classifier", "jev": "AI classifier",
}
_ROLE_RX = re.compile(r"\b(" + "|".join(sorted(map(re.escape, ROLE_NAMES), key=len, reverse=True)) + r")\b")


def plain_names(obj: Any) -> Any:
    """A copy of `obj` with every internal part name swapped for the job it does."""
    if isinstance(obj, str):
        return _ROLE_RX.sub(lambda m: ROLE_NAMES[m.group(1)], obj)
    if isinstance(obj, dict):
        return {k: plain_names(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [plain_names(v) for v in obj]
    return obj


def plain_title(category: str | None) -> str:
    return PLAIN_TITLES.get(str(category), str(category or "Suspicious activity").replace("_", " ").capitalize())


def _epoch(iso: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(iso)).timestamp()
    except (TypeError, ValueError):
        return None


def _closed_ts(inc: dict[str, Any]) -> float | None:
    return inc.get("_closed_ts") or _epoch(inc.get("closed_at"))


def _ago(seconds: float) -> str:
    h = int(seconds // 3600)
    if h >= 48:
        return f"{h // 24} days"
    if h >= 1:
        return f"{h} h"
    return f"{max(1, int(seconds // 60))} min"


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%a %d %b %Y")


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %H:%M")


# ------------------------------------------------------------------ schedule
def clock_time(text: str) -> str | None:
    """'8:00' -> '08:00'; None when it is not a time of day."""
    try:
        h, m = (int(x) for x in str(text).strip().split(":"))
    except ValueError:
        return None
    return f"{h:02d}:{m:02d}" if 0 <= h < 24 and 0 <= m < 60 else None


@dataclass
class Schedule:
    """The client's choice: how often, at what local time, on which weekday (weekly), and who gets it."""
    every: str = "daily"
    at: str = "08:00"
    day: str = "mon"
    to: str = "Client"
    changed_by: str | None = None
    changed_at: str | None = None
    last_sent_ts: float | None = None

    @classmethod
    def from_settings(cls, s: Any) -> "Schedule":
        return cls(every=s.summary_every, at=s.summary_at, day=s.summary_day, to=s.summary_to).checked()

    def checked(self) -> "Schedule":
        self.every = self.every.strip().lower() if self.every.strip().lower() in EVERY else "daily"
        self.day = self.day.strip().lower()[:3] if self.day.strip().lower()[:3] in DAYS else "mon"
        self.at = clock_time(self.at) or "08:00"
        self.to = self.to.strip() or "Client"
        return self

    def last_slot(self, now: float) -> float | None:
        """The most recent due time at or before `now` (local time), or None when switched off."""
        if self.every == "off":
            return None
        h, m = (int(x) for x in self.at.split(":"))
        local = datetime.fromtimestamp(now)
        slot = local.replace(hour=h, minute=m, second=0, microsecond=0)
        if self.every == "weekly":
            slot -= timedelta(days=(slot.weekday() - DAYS.index(self.day)) % 7)
        if slot > local:
            slot -= timedelta(days=PERIODS[self.every])
        return slot.timestamp()

    def next_slot(self, now: float) -> float | None:
        last = self.last_slot(now)
        if last is None:
            return None
        return (datetime.fromtimestamp(last) + timedelta(days=PERIODS[self.every])).timestamp()

    def public(self, now: float) -> dict[str, Any]:
        nxt = self.next_slot(now)
        return {"every": self.every, "at": self.at, "day": self.day, "to": self.to,
                "changed_by": self.changed_by, "changed_at": self.changed_at,
                "last_sent_at": datetime.fromtimestamp(self.last_sent_ts).astimezone().isoformat(timespec="seconds")
                if self.last_sent_ts else None,
                "next_at": datetime.fromtimestamp(nxt).astimezone().isoformat(timespec="seconds") if nxt else None}


def load_schedule(path: Path, s: Any, now: float) -> Schedule:
    """The saved choice wins over the environment, so a change made on the dashboard survives restarts."""
    sched = Schedule.from_settings(s)
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
        for k in ("every", "at", "day", "to", "changed_by", "changed_at", "last_sent_ts"):
            if saved.get(k) is not None:
                setattr(sched, k, saved[k])
        sched.checked()
    except (OSError, ValueError, TypeError):
        pass
    if sched.last_sent_ts is None:
        sched.last_sent_ts = now  # first start: the first summary goes out at the next due time, not now
        save_schedule(path, sched)
    return sched


def save_schedule(path: Path, sched: Schedule) -> None:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({k: getattr(sched, k) for k in (
            "every", "at", "day", "to", "changed_by", "changed_at", "last_sent_ts")}, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass  # the schedule still works for this run


# ------------------------------------------------------------------ content
def build_summary(core: "Saguaro", period: str = "daily", until: float | None = None) -> dict[str, Any]:
    """Everything on the one page, as data. `until` is the end of the period (default now)."""
    if period not in PERIODS:
        raise ValueError(f"period must be one of {', '.join(PERIODS)}")
    with core.lock:
        now = core.clock.now()
        end = min(until, now) if until else now
        start = end - PERIODS[period] * 86400.0
        for inc in core.incidents.values():
            core._refresh_incident(inc, now)
        incs = list(core.incidents.values())

        def in_period(ts: float | None) -> bool:
            return ts is not None and start <= ts <= end

        new = [i for i in incs if in_period(i["_opened_ts"])]
        closed = [i for i in incs if in_period(_closed_ts(i))]
        actions = [a for a in core.actions if in_period(_epoch(a.get("applied_at")))]
        auto = {a["incident"] for a in actions if a["mode"] == "autonomous"}
        by_staff = {i["id"] for i in new if i.get("decisions") or i.get("acked")}
        # Still open at the end of the period (opened before it ended, not closed by then)
        still_open = [i for i in incs if i["_opened_ts"] <= end
                      and not (i["status"] in CLOSED and (_closed_ts(i) or 0) <= end)
                      and i["status"] in OPEN]
        missed = [i for i in new if i.get("sla_breached")]
        alerts = [n for n in core.notifications if in_period(_epoch(n.get("created_at"))) and n["kind"] != "summary"]

        attention = []
        for i in sorted(still_open, key=lambda x: (-x.get("points", 0), x["_opened_ts"])):
            steps = i.get("next_steps") or []
            attention.append({
                "incident": i["id"], "what": plain_title(i["category"]), "machine": i.get("host") or "-",
                "severity": i.get("severity"), "open_for": _ago(end - i["_opened_ts"]),
                "seen_by_staff": bool(i.get("acked")), "late": bool(i.get("sla_breached")),
                "next_step": steps[0] if steps else "Ask your technical staff to take a look.",
            })
        for i in new:
            if i.get("needs_review") and i["status"] in OPEN and i["id"] not in {a["incident"] for a in attention}:
                attention.append({"incident": i["id"], "what": plain_title(i["category"]), "machine": i.get("host") or "-",
                                  "severity": i.get("severity"), "open_for": _ago(end - i["_opened_ts"]),
                                  "seen_by_staff": bool(i.get("acked")), "late": bool(i.get("sla_breached")),
                                  "next_step": (i.get("next_steps") or ["Please take a look."])[0]})

        machines: dict[str, dict[str, Any]] = {}
        for i in new + [i for i in still_open if i not in new]:
            m = machines.setdefault(i.get("host") or "unknown", {"machine": i.get("host") or "unknown",
                                                                "threats": 0, "stopped": 0, "open": 0})
            if i in new:
                m["threats"] += 1
            if i["id"] in auto or i["status"] == "contained":
                m["stopped"] += 1
            if i in still_open:
                m["open"] += 1
        kinds: dict[str, int] = {}
        for i in new:
            kinds[plain_title(i["category"])] = kinds.get(plain_title(i["category"]), 0) + 1

        did: dict[str, int] = {}
        for a in actions:
            did[PLAIN_ACTIONS.get(a["type"], a["type"].replace("_", " "))] = did.get(
                PLAIN_ACTIONS.get(a["type"], a["type"].replace("_", " ")), 0) + 1
        undone = sum(1 for a in actions if a["status"] == "rolled_back")
        expired = sum(1 for a in actions if a["status"] == "expired")
        permanent = sum(1 for a in actions if a["status"] == "permanent")

        chain_valid, bad_seq = core.audit.verify()
        fp = anchor.fingerprint(core.audit, core.anchor_key)
        risk = core._last_risk
        label = "today" if period == "daily" else "this week"
        threats = f"{len(new)} threat{'' if len(new) == 1 else 's'} {label}"
        if not new and not still_open:
            headline = f"All quiet {label}: no threats were found."
        elif not attention:
            headline = f"{threats}, all handled. Nothing needs you."
        else:
            headline = f"{threats}. {len(attention)} still need{'s' if len(attention) == 1 else ''} your attention."
        if not chain_valid:
            headline += " Warning: the activity record has been changed; ask your technical staff now."
        delivered = sum(1 for n in alerts if n["delivered"])
        acked_alerts = sum(1 for n in alerts if n.get("incident") in core.incidents
                           and core.incidents[n["incident"]].get("acked"))

        return {
            "summary_id": f"SUM-{period[0].upper()}-{datetime.fromtimestamp(end).strftime('%Y%m%d-%H%M')}",
            "title": "Daily security summary" if period == "daily" else "Weekly security summary",
            "period": period,
            "from": core.clock.iso(start),
            "until": core.clock.iso(end),
            "until_ts": int(end),
            "period_text": (_day(end) if period == "daily" else f"{_day(start)} to {_day(end)}"),
            "generated_at": core.clock.iso(now),
            "client": core.summary_schedule.to if hasattr(core, "summary_schedule") else "Client",
            "headline": headline,
            "numbers": {
                "threats": len(new),
                "stopped_automatically": len(auto),
                "handled_by_staff": len(by_staff),
                "closed": len(closed),
                "need_attention": len(attention),
                "late_response": len(missed),
                "alerts_sent": len(alerts),
                "alerts_delivered": delivered,
                "alerts_acknowledged": acked_alerts,
            },
            "risk_now": {"index": risk["risk_index"], "band": risk["band"]},
            "attention": attention,
            "machines": sorted(machines.values(), key=lambda m: (-m["open"], -m["threats"], m["machine"])),
            "kinds": sorted(({"what": k, "count": v} for k, v in kinds.items()), key=lambda k: (-k["count"], k["what"])),
            "actions": {"done": did, "total": len(actions), "undone": undone, "expired": expired, "permanent": permanent},
            "proof": {
                "chain_valid": chain_valid, "first_invalid_seq": bad_seq,
                "records": fp.seq, "fingerprint": fp.line(), "short": fp.short(),
                "how_to_check": "Keep this summary. Your technical staff can check the line below against the "
                                "record on the server at any time (GET /audit/verify or python -m app.anchor verify). "
                                "If anyone changed or removed a record since, the check fails.",
            },
            "responsible": core.settings.on_duty,
        }


def _did_text(r: dict[str, Any]) -> list[str]:
    a = r["actions"]
    if not a["total"]:
        return ["SentrAI did not need to step in."]
    out = [("It " + ", ".join(f"{verb} ({n}x)" for verb, n in sorted(a["done"].items()))) + "."]
    since = [f"{n} {what}" for n, what in ((a["expired"], "ended on time"), (a["undone"], "undone by your staff"),
                                           (a["permanent"], "made permanent by your staff")) if n]
    out.append("Each step is temporary, with an end time, and can be undone. "
               + (f"So far: {', '.join(since)}." if since else "All are still in force."))
    return out


def render_markdown(r: dict[str, Any]) -> str:
    n = r["numbers"]
    lines = [
        f"# 🛡️ {r['title']}",
        "",
        f"**{r['period_text']}** · for {r['client']} · {r['summary_id']}",
        "",
        f"> **{r['headline']}**",
        "",
        "| Threats found | Stopped automatically | Handled by your staff | Need attention | Late responses |",
        "| --- | --- | --- | --- | --- |",
        f"| {n['threats']} | {n['stopped_automatically']} | {n['handled_by_staff']} | {n['need_attention']} | {n['late_response']} |",
        "",
        "## Needs your attention",
        "",
    ]
    if r["attention"]:
        lines += ["| What | Machine | Open for | Seen by staff | What to do next |", "| --- | --- | --- | --- | --- |"]
        for a in r["attention"][:MAX_ROWS]:
            lines.append(f"| {a['what']} ({a['incident']}) | {a['machine']} | {a['open_for']}{' (late)' if a['late'] else ''} | "
                         f"{'yes' if a['seen_by_staff'] else 'not yet'} | {a['next_step'].replace('|', '/')} |")
        if len(r["attention"]) > MAX_ROWS:
            lines.append(f"\n_and {len(r['attention']) - MAX_ROWS} more on the dashboard._")
    else:
        lines.append("Nothing. 🎉")
    lines += ["", "## What SentrAI did", ""] + [f"- {t}" for t in _did_text(r)]
    lines += ["", "## By machine", ""]
    if r["machines"]:
        lines += ["| Machine | Threats | Stopped | Still open |", "| --- | --- | --- | --- |"]
        lines += [f"| {m['machine']} | {m['threats']} | {m['stopped']} | {m['open']} |" for m in r["machines"][:MAX_ROWS]]
    else:
        lines.append("No machine had a threat.")
    if r["kinds"]:
        lines += ["", "## Kinds of threat", ""] + [f"- {k['what']}: {k['count']}" for k in r["kinds"][:MAX_ROWS]]
    lines += ["", "## Alerts", "",
              f"{n['alerts_sent']} alert(s) sent, {n['alerts_delivered']} delivered, "
              f"{n['alerts_acknowledged']} answered by staff. Responsible: {r['responsible']}."]
    p = r["proof"]
    lines += ["", "## Can I trust this?", "",
              ("The activity record is complete and unchanged" if p["chain_valid"]
               else f"**The activity record was changed (at record {p['first_invalid_seq']}).**")
              + f" ({p['records']} records). {p['how_to_check']}", "", f"`{p['fingerprint']}`", "", "---", "",
              f"_🛡️ SentrAI · {r['summary_id']} · {r['from']} to {r['until']} · generated {r['generated_at']}_", ""]
    return "\n".join(lines)


GREEN, RED, AMBER = (0.102, 0.455, 0.278), (0.753, 0.157, 0.180), (0.690, 0.416, 0.0)


def render_pdf(r: dict[str, Any]) -> bytes:
    """The summary on a single A4 page (tables are capped at MAX_ROWS rows)."""
    n, p = r["numbers"], r["proof"]
    doc = PdfDoc(title=f"{r['title']} {r['summary_id']}",
                 footer=f"SentrAI  |  {r['summary_id']}  |  generated {r['generated_at']}  |  record {p['short']}")
    top = doc.y + 42
    band = 96
    doc.rect(0, top - band, PAGE_W, band, BLACK)
    doc.rect(0, top - band - 3, PAGE_W, 3, EDGE)
    doc.logo(40, top - 50, 26)
    doc.text(PAGE_W - 42 - text_width(r["summary_id"], BOLD, 9), top - 36, r["summary_id"], BOLD, 9, SOFT_ON_DARK)
    doc.text(42, top - 72, r["title"], BOLD, 19, (1, 1, 1))
    doc.text(42, top - 87, f"{r['period_text']}  |  for {r['client']}", size=8.5, color=(0.647, 0.698, 0.776))
    doc.y = top - band - 3 - 14

    ok = not r["attention"] and p["chain_valid"]
    doc.rect(42, doc.y - 30, doc.width, 30, tuple(0.93 + 0.07 * c for c in (GREEN if ok else AMBER)))
    doc.rect(42, doc.y - 30, 3, 30, GREEN if ok else AMBER)
    doc.text(54, doc.y - 19, r["headline"][:110], BOLD, 11, GREEN if ok else AMBER)
    doc.y -= 42

    tiles = [("Threats found", str(n["threats"]), ACCENT),
             ("Stopped automatically", str(n["stopped_automatically"]), GREEN),
             ("Handled by staff", str(n["handled_by_staff"]), ACCENT),
             ("Need attention", str(n["need_attention"]), AMBER if n["need_attention"] else GREEN),
             ("Record intact", "Yes" if p["chain_valid"] else "No", GREEN if p["chain_valid"] else RED)]
    gap, h = 6.0, 40.0
    w = (doc.width - gap * (len(tiles) - 1)) / len(tiles)
    for i, (label, value, color) in enumerate(tiles):
        x = 42 + i * (w + gap)
        doc.rect(x, doc.y - h, w, h, tuple(0.93 + 0.07 * c for c in color))
        doc.rect(x, doc.y - h, 3, h, color)
        doc.text(x + 9, doc.y - 14, label.upper(), BOLD, 6.2, MUTED)
        doc.text(x + 9, doc.y - 32, value, BOLD, 14, color)
    doc.y -= h + 6

    doc.heading("Needs your attention", 11)
    if r["attention"]:
        rows = [[f"{a['what']} ({a['incident']})", a["machine"], a["open_for"] + (" (late)" if a["late"] else ""),
                 "yes" if a["seen_by_staff"] else "not yet", a["next_step"]] for a in r["attention"][:MAX_ROWS]]
        doc.table([Column("What", 1.5, BOLD), Column("Machine", 0.8), Column("Open for", 0.65),
                   Column("Seen", 0.45), Column("What to do next", 2.6)], rows, size=7.8,
                  colors=[RED if a["late"] else None for a in r["attention"][:MAX_ROWS]])
        if len(r["attention"]) > MAX_ROWS:
            doc.paragraph(f"and {len(r['attention']) - MAX_ROWS} more on the dashboard.", size=8, color=MUTED)
    else:
        doc.paragraph("Nothing needs you right now.", size=9)

    doc.heading("What SentrAI did", 11)
    for t in _did_text(r):
        doc.bullet(t, size=8.8)

    doc.heading("By machine", 11)
    if r["machines"]:
        doc.table([Column("Machine", 2.0, BOLD), Column("Threats", 1.0), Column("Stopped", 1.0), Column("Still open", 1.0)],
                  [[m["machine"], m["threats"], m["stopped"], m["open"]] for m in r["machines"][:MAX_ROWS]], size=8,
                  colors=[AMBER if m["open"] else None for m in r["machines"][:MAX_ROWS]])
    else:
        doc.paragraph("No machine had a threat.", size=9)
    if r["kinds"]:
        doc.paragraph("Kinds of threat: " + ", ".join(f"{k['what']} ({k['count']})" for k in r["kinds"][:MAX_ROWS]) + ".",
                      size=8.5)
    doc.paragraph(f"Alerts: {n['alerts_sent']} sent, {n['alerts_delivered']} delivered, {n['alerts_acknowledged']} answered "
                  f"by staff. Responsible: {r['responsible']}.", size=8.5)

    doc.heading("Can I trust this?", 11)
    doc.paragraph(("The activity record is complete and unchanged" if p["chain_valid"]
                   else f"The activity record was changed (at record {p['first_invalid_seq']})")
                  + f" ({p['records']} records). {p['how_to_check']}", size=8, color=GREEN if p["chain_valid"] else RED)
    doc.paragraph(p["fingerprint"], "F3", 6.5, MUTED)
    return doc.to_bytes()
