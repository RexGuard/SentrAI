"""After an attack: a recovery checklist for one incident, in five phases a small team can follow.

Stopping an attacker is half the job. Afterwards someone has to make sure they cannot come back, put things back
as they were, tell the people who must be told and learn from it. GET /ui/recovery gives that plan for one incident:
the usual steps for the type of attack, the backup made just before it started (to restore from), and whether
personal data may be involved (PDPA). People tick steps off with POST /ui/recovery/check; each tick goes on the
audit record, so the plan doubles as proof of what was done. Ticks live in recovery.json (sentrai_paths
"core.recovery"). Nothing here acts on a machine: restoring still goes through the Backups page and a person.
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

from .config import sentrai_config  # noqa: F401  (config.py puts mvp/ on sys.path)
from .summary import plain_title
import sentrai_accounts as acc  # noqa: E402

PHASES = [
    ("contain", "Stop it", "Make sure the attacker is cut off."),
    ("secure", "Lock the doors", "Change what the attacker may have learned or used."),
    ("restore", "Put things back", "Return changed or lost data and settings to how they were."),
    ("tell", "Tell people", "Inform the people who must know, on time."),
    ("learn", "Learn from it", "So the same attack does not work twice."),
]

# Extra steps per kind of attack, by phase. Every plan also gets the common steps below.
BY_KIND: dict[str, dict[str, list[str]]] = {
    "brute_force": {"secure": ["Reset the password of every account that was targeted", "Turn on two-step sign-in for those accounts"],
                    "learn": ["Limit sign-in attempts on that service"]},
    "sql_injection": {"secure": ["Change the website's database password", "Ask the developer to fix the page the attack used"],
                      "restore": ["Check the database for records that were changed or added"],
                      "learn": ["Add a website filter rule for this kind of request"]},
    "xss": {"secure": ["Remove any script the attacker planted on the site", "Sign out every user session on the site"],
            "learn": ["Ask the developer to clean up input on the page the attack used"]},
    "port_scan": {"secure": ["Close network ports nobody needs"], "learn": ["Check the firewall only allows what is needed"]},
    "privilege_escalation": {"secure": ["Change every administrator password and SSH key on that machine",
                                        "Remove any account or scheduled task you did not create"],
                             "restore": ["Rebuild the machine from a clean backup if you cannot trust it"]},
    "data_exfiltration": {"secure": ["Change the passwords and keys of the account that downloaded the data"],
                          "tell": ["Work out which personal data left and whose it was"]},
    "misconfiguration": {"secure": ["Fix the unsafe setting"], "learn": ["Add the setting to your setup checklist"]},
    "log_tampering": {"secure": ["Change administrator passwords on that machine"],
                      "restore": ["Compare the machine's logs with SentrAI's tamper-proof record to see what was erased"]},
    "malware": {"contain": ["Keep the machine off the network until it is clean"],
                "secure": ["Change every password used on that machine"],
                "restore": ["Rebuild or restore the machine from a backup made before the infection"]},
    "prompt_injection": {"secure": ["Check what the AI was asked to do and undo anything it changed"],
                         "learn": ["Keep the AI's actions behind a person's approval"]},
    "unauthorised_admin": {"secure": ["Confirm with the administrator whether it was them",
                                      "If not: change that account's password and keys and end its sessions"]},
}
COMMON: dict[str, list[str]] = {
    "contain": ["Check the attacker's address is still blocked and nothing else from it got through"],
    "secure": ["Change any API keys or tokens stored on the machine"],
    "restore": ["Restore anything changed from the last good backup (Backups page)", "Check the machine works as normal"],
    "tell": ["Tell your manager what happened and what was done",
             "If personal data may be involved, ask your data protection officer whether to report it (PDPA: "
             "a notifiable breach goes to the PDPC within 3 days)"],
    "learn": ["Write down what happened and what to do differently in the closing note"],
}
PERSONAL = {"data_exfiltration", "sql_injection", "malware", "privilege_escalation", "unauthorised_admin", "log_tampering"}


def _epoch(ts: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() if ts else None
    except ValueError:
        return None


def steps_for(category: str) -> list[dict[str, Any]]:
    extra = BY_KIND.get(category, {})
    out = []
    for key, title, about in PHASES:
        items = COMMON[key] + extra.get(key, []) if key == "contain" else extra.get(key, []) + COMMON[key]
        out.append({"key": key, "title": title, "about": about,
                    "steps": [{"id": f"{key}-{n}", "text": t} for n, t in enumerate(items, 1)]})
    return out


class Ticks:
    """Which steps are done, per incident: {incident: {step id: {"by", "at"}}}."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def all(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def set(self, incident: str, step: str, done: bool, by: str) -> dict[str, Any]:
        with self._lock:
            data = self.all()
            mine = data.setdefault(incident, {})
            if done:
                mine[step] = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            else:
                mine.pop(step, None)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
            return mine


def backup_before(backups: Any, opened_ts: float | None) -> dict[str, Any] | None:
    """The newest backup made before the incident opened, preferring one whose check passed."""
    if backups is None or opened_ts is None:
        return None
    try:
        rows = backups.status().get("backups") or []
    except Exception:  # backups are optional; the plan still works without them
        return None
    before = [b for b in rows if (_epoch(b.get("created")) or 0) < opened_ts]
    before.sort(key=lambda b: (bool((b.get("verified") or {}).get("ok")), b.get("created") or ""), reverse=True)
    if not before:
        return None
    b = before[0]
    return {"id": b.get("id"), "created": b.get("created"), "checked": (b.get("verified") or {}).get("ok")}


def plan(core: Any, ticks: Ticks, backups: Any, incident: str) -> dict[str, Any]:
    with core.lock:
        inc = core.incidents.get(incident)
        if inc is None:
            raise KeyError(incident)
        cat, host, opened = inc.get("category") or "", inc.get("host") or "", inc.get("_opened_ts")
        status = inc.get("status")
    done = ticks.all().get(incident, {})
    phases = steps_for(cat)
    total = 0
    for ph in phases:
        for s in ph["steps"]:
            s["done"] = done.get(s["id"])
            total += 1
    n_done = sum(1 for ph in phases for s in ph["steps"] if s["done"])
    return {"incident": incident, "what": plain_title(cat), "machine": host, "status": status, "phases": phases,
            "done": n_done, "total": total, "personal_data": cat in PERSONAL,
            "backup": backup_before(backups, opened)}


def install(app: FastAPI, core: Any, ticks: Ticks, backups: Any) -> None:
    @app.get("/ui/recovery")
    def get_recovery(incident: str) -> dict[str, Any]:
        try:
            return plan(core, ticks, backups, incident)
        except KeyError:
            raise HTTPException(404, f"no incident {incident}")

    @app.post("/ui/recovery/check")
    def post_check(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        account = getattr(request.state, "account", None)
        if account and not acc.can(account.get("role"), "act"):
            raise HTTPException(403, "Your role can read everything but change nothing.")
        incident, step = str(body.get("incident") or ""), str(body.get("step") or "")
        try:
            current = plan(core, ticks, backups, incident)
        except KeyError:
            raise HTTPException(404, f"no incident {incident}")
        text = next((s["text"] for ph in current["phases"] for s in ph["steps"] if s["id"] == step), None)
        if text is None:
            raise HTTPException(400, f"no step {step} in this plan")
        who = (account or {}).get("email") or str(body.get("operator") or "dashboard")
        done = bool(body.get("done", True))
        ticks.set(incident, step, done, who)
        core.scribe.record(core.name, "recovery_step", {"incident": incident, "step": step, "text": text,
                                                        "done": done, "operator": who})
        return plan(core, ticks, backups, incident)
