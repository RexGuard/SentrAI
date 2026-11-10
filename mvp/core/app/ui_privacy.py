"""The web dashboard's Privacy page: what SentrAI records about people, why, who can see it and how long it is kept.

SentrAI logs security events (addresses, user names), staff acknowledgements and on-duty shifts, staff reports and
dashboard sign-ins. Under PDPA that is personal data, so the organisation has to tell its staff and keep it no
longer than needed. This page is the inventory, a retention policy the Owner or an Admin sets, and a staff notice
HR can hand out (GET /ui/privacy/notice.md).

The retention periods are the organisation's policy. SentrAI shows how old the oldest record of each kind is and
flags what is past its period; it does not delete anything on its own (the audit record is a hash chain, so it is
archived whole, never trimmed line by line). The one exception is the Security Coach (coach.py): its activity
records and coaching notes are deleted automatically when their period here runs out, so those two need a period. The policy lives in privacy.json (sentrai_paths "core.privacy") and
every change goes on the audit record.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
import sentrai_accounts as acc  # noqa: E402

# What SentrAI keeps. `months` is the default retention; None = while the account or setting exists.
KINDS: list[dict[str, Any]] = [
    {"key": "events", "what": "Security events", "about": "Lines from server and website logs: internet addresses, "
     "user names that tried to sign in, web addresses asked for, time.", "why": "To spot and stop attacks.", "months": 6},
    {"key": "incidents", "what": "Incidents and the steps taken", "about": "What happened, on which machine, which "
     "address was blocked, who approved or undid a step, closing notes.", "why": "To handle attacks and learn from them.",
     "months": 24},
    {"key": "staff_activity", "what": "Staff response record", "about": "Who was on duty, who was alerted, when they "
     "acknowledged and how long they took.", "why": "So an alert never goes unanswered and escalates when it does. "
     "Not used to rate staff performance.", "months": 12},
    {"key": "staff_reports", "what": "Reports from staff", "about": "What a staff member reported as suspicious, "
     "their name and how to reach them.", "why": "To follow up on what staff noticed.", "months": 12},
    {"key": "accounts", "what": "Dashboard accounts and sign-ins", "about": "Name, email, role, authenticator set up, "
     "sign-in times and addresses; administrator sessions on the servers.", "why": "To control who can see and "
     "change security settings.", "months": None},
    {"key": "audit", "what": "Audit record", "about": "A tamper-proof list of everything above that SentrAI or a person "
     "did. Entries cannot be changed or removed one by one.", "why": "To prove what happened, for you and regulators.",
     "months": 24},
    {"key": "backups", "what": "Backups", "about": "Copies of the folders you chose, which may hold personal data.",
     "why": "To recover after an attack such as ransomware.", "months": None},
    {"key": "coach_activity", "what": "Work app activity (Security Coach)", "about": "Risky actions in the work apps "
     "the admin connected: work email, app, kind of action, time, sign-in country, device type. Never the text of "
     "emails, chats or files; file names only if the admin turns them on.", "why": "To teach each person right after "
     "a risky action.", "months": 1, "min": 0, "max": 3, "deletes": True},
    {"key": "coach_notes", "what": "Coaching notes and lesson progress", "about": "The notes each person got, their "
     "answers (fixed, that was me, not me) and the lessons they finished.", "why": "So lessons get deeper when the "
     "same slip happens again, and people can see their progress.", "months": 12, "min": 1, "max": 24,
     "deletes": True},
    {"key": "ai", "what": "Questions to the AI", "about": "When an AI model is set up, chat questions and incident "
     "details (log lines, addresses, account names) are sent to that provider as they are, to get an answer.", "why": "To explain threats and suggest fixes.", "months": 0},
]
KEYS = {k["key"] for k in KINDS}
SEE = {
    "view": "Owner, Admin and Auditor accounts can see it on the dashboard.",
    "export": "Owner, Admin and Auditor accounts can download it in reports.",
    "people": "Only Owner and Admin accounts can see the account list.",
}
MAX_MONTHS = 120


class PrivacyPolicy:
    """The organisation's choices: who to contact, and the retention period of each kind, in months."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        months = {k["key"]: k["months"] for k in KINDS}
        for key, v in (data.get("months") or {}).items():
            if key in KEYS and (v is None or isinstance(v, int)):
                months[key] = v
        return {"organisation": str(data.get("organisation") or ""), "contact": str(data.get("contact") or ""),
                "months": months, "updated_at": data.get("updated_at"), "updated_by": data.get("updated_by")}

    def save(self, body: dict[str, Any], by: str) -> dict[str, Any]:
        cur = self.load()
        org = str(body.get("organisation", cur["organisation"]) or "").strip()[:120]
        contact = str(body.get("contact", cur["contact"]) or "").strip()[:200]
        months = dict(cur["months"])
        for key, v in (body.get("months") or {}).items():
            if key not in KEYS:
                raise ValueError(f"Unknown kind of data: {key}")
            k = next(k for k in KINDS if k["key"] == key)
            lo, hi = k.get("min", 0), k.get("max", MAX_MONTHS)
            if k.get("deletes") and v is None:
                raise ValueError(f"{k['what']} needs a period: {lo} to {hi} months.")
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi):
                raise ValueError(f"Keep {key} for {lo} to {hi} months, or leave it empty for 'while it exists'.")
            months[key] = v
        out = {"organisation": org, "contact": contact, "months": months,
               "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "updated_by": by}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        return out


def _kept(months: int | None) -> str:
    if months is None:
        return "while it exists"
    if months == 0:
        return "not kept by SentrAI"
    return f"{months} month{'' if months == 1 else 's'}"


def _epoch(ts: Any) -> float | None:
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _age_days(ts: Any, now: float) -> int | None:
    t = None if ts is None else _epoch(ts)
    return None if t is None else max(0, int((now - t) // 86400))


def page(core: Any, policy: PrivacyPolicy, ai_on: bool, coach_on: bool = False) -> dict[str, Any]:
    p = policy.load()
    now = core.clock.now()
    with core.lock:
        opened = [i.get("_opened_ts") for i in core.incidents.values() if i.get("_opened_ts")]
    first = core.audit.records_after(0, 1)
    oldest = {"incidents": min(opened) if opened else None, "audit": first[0]["ts"] if first else None}
    rows = []
    for k in KINDS:
        months = p["months"][k["key"]]
        age = _age_days(oldest.get(k["key"]), now)
        over = bool(age is not None and months and age > months * 30.4)
        who = SEE["people"] if k["key"] == "accounts" else SEE["export"]
        if k["key"] == "ai":
            who = "Sent to the AI provider you chose on Configuration." if ai_on else "No AI model is set up, so nothing is sent."
        if k["key"].startswith("coach_"):
            who = ("Owner and Admin accounts see team totals; names only for urgent moments or if the admin turns "
                   "names on. Each person can see their own.")
        rows.append({**k, "months": months, "kept": _kept(months), "who": who, "oldest_days": age, "over": over,
                     "in_use": coach_on or not k["key"].startswith("coach_")})
    return {"policy": p, "kinds": rows, "over": [r["key"] for r in rows if r["over"]], "ai_on": ai_on,
            "roles": {r: sorted(acc.PERMISSIONS[r]) for r in acc.ROLES}}


def notice(data: dict[str, Any]) -> str:
    """The staff notice: plain words, for HR to adapt and share. Built from the live policy."""
    p = data["policy"]
    org = p["organisation"] or "[Organisation name]"
    contact = p["contact"] or "[who to contact about your data]"
    lines = [f"# How {org} uses SentrAI: notice to staff", "",
             f"{org} uses SentrAI to protect its computers, websites and the personal data it holds. To do that, "
             "SentrAI records some information about how systems are used, including by staff. This notice explains "
             "what is recorded, why, who can see it and how long it is kept.", "",
             "| What is recorded | Why | How long it is kept |", "| --- | --- | --- |"]
    lines += [f"| {k['what']}: {k['about']} | {k['why']} | {k['kept']} |" for k in data["kinds"] if k.get("in_use", True)]
    lines += ["", "## Who can see it", "",
              "Only people with a dashboard account: Owners and Admins (who can also change settings and act) and "
              "Auditors (who can only look and download reports). Alerts go to the people on duty by message or email.",
              "", "## What it is not used for", "",
              "The staff response record exists so security alerts are answered in time. It is not used to rate "
              "performance or to monitor work outside security alerts.", "",
              "## Every step is on the record", "",
              "Every action SentrAI or a person takes is written to a tamper-proof record, so nobody, including "
              "administrators, can quietly change what happened.", "",
              "## Your rights", "",
              f"You can ask to see the personal data SentrAI holds about you, or ask questions about this notice: "
              f"{contact}.", ""]
    if data["ai_on"]:
        lines += ["To explain threats, SentrAI sends chat questions and incident details (such as log lines, "
                  "addresses, account and computer names) to an outside AI provider. SentrAI never sends its own "
                  "settings, sign-in passwords or keys, but it does not remove anything from the log lines it "
                  "sends: if a log line holds a password or personal detail, the provider sees it.", ""]
    lines += ["_This notice is a starting point. Check it with your data protection officer against the PDPA and "
              "your own IT and HR policies before you share it._", ""]
    return "\n".join(lines)


def install(app: FastAPI, core: Any, policy: PrivacyPolicy, ai_on: Any, coach_on: Any = lambda: False) -> None:
    @app.get("/ui/privacy")
    def get_privacy() -> dict[str, Any]:
        return page(core, policy, bool(ai_on()), bool(coach_on()))

    @app.post("/ui/privacy")
    def post_privacy(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "configure"):
            raise HTTPException(403, "Only an Owner or Admin can change the privacy policy.")
        who = (account or {}).get("email") or str(body.get("operator") or "dashboard")
        try:
            saved = policy.save(body, who)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        core.scribe.record(core.name, "privacy_policy_changed", {"operator": who, "months": saved["months"],
                                                                 "organisation": saved["organisation"]})
        return page(core, policy, bool(ai_on()), bool(coach_on()))

    @app.get("/ui/privacy/notice.md", response_class=PlainTextResponse)
    def get_notice() -> PlainTextResponse:
        return PlainTextResponse(notice(page(core, policy, bool(ai_on()), bool(coach_on()))), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="sentrai-staff-notice.md"'})
