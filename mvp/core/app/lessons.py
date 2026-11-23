"""Lessons SentrAI learns about one company, each backed by the incidents that prove it (ARTEX idea 8).

When staff close the same kind of alert from the same network as "not a threat" again and again, SentrAI
suggests a lesson: "brute-force sign-ins from 203.0.113.0/24 are normal for you", with the incidents behind it.
Nothing changes until a person says yes. A confirmed lesson changes no rule and silences nothing: new alerts that
match it still come, labelled "closed as not a threat 3 times before", the AI that plans the fix is told, and the
approval's risk tag says a block may hit someone legitimate.

Evidence, not memory: lessons are worked out again from the incidents every time, so each one lists exactly the
incidents behind it, evidence older than KEEP_DAYS stops counting, and the moment a person treats a matching alert
as a real attack (approves its fix, keeps its block, or closes it as real), the lesson is withdrawn, with that
incident named. Only a person's yes or no is saved (company/lessons.json).

Never learned: the kinds of alert that must stay loud whatever happened before (malware, log tampering, data
leaving, privilege escalation, root sign-ins, prompt injection), anything that touched a decoy, and alerts with
no outside address (a pattern on one of the company's own computers is too broad to call normal).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from fastapi import Body, FastAPI, HTTPException, Request

from .rules import TRIPWIRE_REASONS
from .summary import plain_title
from .ui_tuning import _epoch as _parse, false_alarm
from .waves import network_of

MIN_EVIDENCE = 2   # closed as not a threat at least this often before SentrAI suggests a lesson
KEEP_DAYS = 90     # older closures stop counting
SHOW_IDS = 5       # incidents named in a lesson's words
NEVER = {"malware", "log_tampering", "data_exfiltration", "privilege_escalation", "unauthorised_admin",
         "prompt_injection", "staff_report"}


def _epoch(ts: Any) -> float:
    return _parse(ts) or 0.0


def key_of(inc: dict[str, Any]) -> str | None:
    """"brute_force|203.0.113.0/24": the kind of alert and the outside network, or None when never learned."""
    cat = str(inc.get("category") or "")
    if not cat or cat in NEVER or str(inc.get("classification_reason") or "").startswith(TRIPWIRE_REASONS):
        return None
    net = network_of(inc.get("src_ip"))
    return f"{cat}|{net}" if net else None


def verdict(inc: dict[str, Any]) -> str | None:
    """What a person decided: "not_a_threat", "real" (approved the fix, kept the block, closed it as real), or None."""
    if false_alarm(inc):
        return "not_a_threat"
    if any(d.get("decision") == "approve" for d in inc.get("decisions") or [] if isinstance(d, dict)):
        return "real"
    if any(a.get("status") == "permanent" for a in inc.get("actions") or [] if isinstance(a, dict)):
        return "real"
    if inc.get("status") == "resolved":
        return "real"
    return None


def _when(inc: dict[str, Any]) -> float:
    return _epoch(inc.get("closed_at")) or _epoch(inc.get("opened_at"))


def words(cat: str, net: str, ids: list[str]) -> str:
    n = len(ids)
    shown = ", ".join(ids[:SHOW_IDS]) + (f" and {n - SHOW_IDS} more" if n > SHOW_IDS else "")
    return (f"Your team closed {plain_title(cat).lower()} from {net} as not a threat {n} time{'s' if n != 1 else ''} "
            f"({shown}).")


class Lessons:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.Lock()

    # -- the only thing saved: a person's yes or no
    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def build(self, incidents: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Every lesson with its evidence, worked out now. Each: key, kind, network, state (suggested,
        confirmed, withdrawn, dismissed), evidence (ids closed as not a threat), against (ids treated as real),
        words, and who decided and when."""
        since = self.clock() - KEEP_DAYS * 86400
        found: dict[str, dict[str, list[str]]] = {}
        for inc in incidents:
            key = key_of(inc)
            v = verdict(inc) if key else None
            if not v or _when(inc) < since:
                continue
            found.setdefault(key, {"not_a_threat": [], "real": []})[v].append(str(inc.get("id")))
        saved = self._read()
        out = []
        for key in sorted(set(found) | set(saved)):
            ev = found.get(key, {"not_a_threat": [], "real": []})
            yes, real = sorted(ev["not_a_threat"]), sorted(ev["real"])
            said = saved.get(key) or {}
            if said.get("state") == "dismissed":
                state = "dismissed"
            elif said.get("state") == "confirmed":
                state = "withdrawn" if real else "confirmed" if yes else "expired"
            elif real or len(yes) < MIN_EVIDENCE:
                continue
            else:
                state = "suggested"
            cat, net = key.split("|", 1)
            text = words(cat, net, yes) if yes else f"No recent {plain_title(cat).lower()} from {net} to go by."
            if state == "withdrawn":
                text += f" But {', '.join(real[:SHOW_IDS])} from there was treated as a real attack, so SentrAI " \
                        "no longer calls it normal."
            out.append({"key": key, "kind": cat, "kind_words": plain_title(cat), "network": net, "state": state,
                        "evidence": yes, "against": real, "words": text,
                        **({"by": said.get("by"), "at": said.get("at")} if said else {})})
        return out

    def decide(self, key: str, yes: bool, by: str, incidents: Iterable[dict[str, Any]]) -> dict[str, Any]:
        """A person's answer to a lesson: yes ("this is normal for us") or no ("keep treating it as an attack").
        Yes only for a lesson whose evidence holds now. KeyError for an unknown one, ValueError for a yes that
        the evidence does not back."""
        with self._lock:
            now = {lesson["key"]: lesson for lesson in self.build(incidents)}
            lesson = now.get(key)
            if lesson is None:
                raise KeyError(key)
            if yes and (lesson["against"] or len(lesson["evidence"]) < MIN_EVIDENCE):
                raise ValueError("the incidents no longer back this lesson")
            saved = self._read()
            saved[key] = {"state": "confirmed" if yes else "dismissed", "by": by,
                          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())),
                          "evidence": lesson["evidence"]}
            self._write(saved)
        return next(lesson for lesson in self.build(incidents) if lesson["key"] == key)

    def forget(self, key: str) -> bool:
        """Remove a person's answer (the lesson is worked out from the incidents again)."""
        with self._lock:
            saved = self._read()
            if key not in saved:
                return False
            del saved[key]
            self._write(saved)
            return True

    def confirmed(self, incidents: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """The confirmed lessons by key, worked out once for a whole list (the approvals, the risk bubbles)."""
        if not self._read():
            return {}
        return {x["key"]: x for x in self.build(incidents) if x["state"] == "confirmed"}

    def match(self, inc: dict[str, Any], incidents: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
        """The confirmed lesson this incident matches, or None. The incident itself is not its own evidence."""
        key = key_of(inc)
        if key is None or key not in self._read():
            return None
        iid = str(inc.get("id"))
        lesson = next((x for x in self.build(i for i in incidents if str(i.get("id")) != iid) if x["key"] == key), None)
        return lesson if lesson and lesson["state"] == "confirmed" else None


def install(app: FastAPI, core: Any, store: Lessons) -> None:
    def who(request: Request) -> str:
        return (getattr(request.state, "account", None) or {}).get("email") or "team (API token)"

    @app.get("/ui/lessons")
    def get_lessons() -> dict[str, Any]:
        """What SentrAI has learned about this company, each lesson with the incidents behind it."""
        rows = store.build(core.list_incidents(host=None))
        return {"lessons": rows, "suggested": sum(1 for r in rows if r["state"] == "suggested"),
                "min_evidence": MIN_EVIDENCE, "keep_days": KEEP_DAYS}

    @app.post("/ui/lessons/decide")
    def post_decide(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """{"key": "brute_force|203.0.113.0/24", "yes": true}: yes = "this is normal for us", no = "keep
        treating it as an attack". Written to the audit trail with the incidents it rests on."""
        key, yes = str(body.get("key") or ""), bool(body.get("yes"))
        try:
            lesson = store.decide(key, yes, who(request), core.list_incidents(host=None))
        except KeyError:
            raise HTTPException(404, "no such lesson") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        core.scribe.record(core.name, "lesson_confirmed" if yes else "lesson_dismissed",
                           {"operator": who(request), "lesson": key, "evidence": lesson["evidence"]})
        text = ("Noted. SentrAI still alerts you, but tells you it has seen this before." if yes
                else "Noted. SentrAI keeps treating these as possible attacks.")
        return {"lesson": lesson, "message": text}

    @app.post("/ui/lessons/forget")
    def post_forget(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        key = str(body.get("key") or "")
        if not store.forget(key):
            raise HTTPException(404, "nobody has answered that lesson")
        core.scribe.record(core.name, "lesson_forgotten", {"operator": who(request), "lesson": key})
        return {"message": "Forgotten. SentrAI works it out again from the incidents."}
