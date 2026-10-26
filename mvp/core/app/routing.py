"""Who hears about an incident, who owns it, and who it goes to when nobody answers.

Contacts, routing rules and the follow-up policy come from a JSON file (CACTAI_ROUTING, default
``routing.json`` next to the database). Without one, the four people in the settings (ON_DUTY,
TEAM_LEAD, IT_MANAGER, CXO) form a chain where each one backs up the one before.

    {
      "contacts": {
        "amir":  {"name": "Amir (on duty)", "role": "on_duty", "email": "amir@example.com",
                  "telegram": "@amir", "backup": "lee"},
        "lee":   {"name": "Lee (team lead)", "role": "team_lead", "email": "lee@example.com", "backup": "it"},
        "it":    {"name": "IT manager", "role": "it_manager", "backup": "boss"},
        "boss":  {"name": "Owner", "role": "cxo"}
      },
      "rules": [
        {"name": "Database box", "match": {"host": "db-*"}, "owner": "lee", "notify": ["it"]},
        {"name": "Critical", "match": {"severity": "critical"}, "owner": "amir", "notify": ["lee", "it", "boss"]},
        {"name": "Everything else", "match": {}, "owner": "amir"}
      ],
      "follow_up": {"escalate_after_reminders": 2, "max_escalations": 3, "resolve_within_hours": 24}
    }

A rule matches on any of category, severity, host and layer (a value, a list of values, or a
shell pattern such as ``web-*``); the first rule that matches wins. Its owner is assigned the
incident and hears every reminder; the people under notify are told about it once.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("cactai.routing")

MATCH_KEYS = ("category", "severity", "host", "layer")
# Kept by the attacker's touch on files or data: the IT manager hears about them as well.
INSIDE_JOBS = ("malware", "data_exfiltration", "log_tampering", "privilege_escalation")


@dataclass
class Contact:
    id: str
    name: str
    role: str = ""
    email: str = ""
    telegram: str = ""
    backup: str = ""  # contact id

    def address(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "email": self.email, "telegram": self.telegram}

    def public(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "role": self.role, "email": self.email,
                "telegram": self.telegram, "backup": self.backup}


@dataclass
class Rule:
    name: str
    match: dict[str, list[str]]
    owner: str
    notify: list[str] = field(default_factory=list)

    def matches(self, inc: dict[str, Any]) -> bool:
        for key, wanted in self.match.items():
            value = str(inc.get(key) or "").lower()
            if not any(fnmatch.fnmatchcase(value, w.lower()) for w in wanted):
                return False
        return True

    def public(self) -> dict[str, Any]:
        return {"name": self.name, "match": self.match, "owner": self.owner, "notify": self.notify}


@dataclass
class FollowUp:
    escalate_after_reminders: int = 2  # unanswered reminders to one owner before the backup takes over
    max_escalations: int = 3
    resolve_within_hours: float = 24.0  # acknowledged but still not resolved: remind the owner (0 = never)


@dataclass
class Route:
    """What routing decided for one incident."""
    rule: str
    owner: Contact
    notify: list[Contact]


class Router:
    def __init__(self, contacts: dict[str, Contact], rules: list[Rule], follow_up: FollowUp,
                 source: str = "defaults") -> None:
        self.contacts = contacts
        self.rules = rules
        self.follow_up = follow_up
        self.source = source
        first = next(iter(contacts.values()))
        if not rules or rules[-1].match:  # something always matches
            self.rules.append(Rule("Everything else", {}, first.id))

    # ------------------------------------------------------------------ lookups
    def contact(self, ref: str | None) -> Contact | None:
        """A contact by id, name, role or Telegram handle (case-insensitive)."""
        if not ref:
            return None
        if ref in self.contacts:
            return self.contacts[ref]
        low = ref.strip().lower().lstrip("@")
        for c in self.contacts.values():
            if low in (c.id.lower(), c.name.lower(), c.role.lower(), c.telegram.lower().lstrip("@")):
                return c
        return None

    def person(self, ref: str) -> Contact:
        """A known contact, or someone outside the book (a Telegram user who pressed Take it)."""
        return self.contact(ref) or Contact(id="", name=ref.strip())

    def by_role(self, role: str, fallback: str) -> str:
        c = next((c for c in self.contacts.values() if c.role == role), None)
        return c.name if c else fallback

    def backup_of(self, contact: Contact) -> Contact | None:
        b = self.contacts.get(contact.backup) if contact.backup else None
        return b if b is not None and b.id != contact.id else None

    def addresses(self, names: list[str]) -> list[dict[str, str]]:
        """Where to send a message for these recipients: the email and Telegram of each known one."""
        out, seen = [], set()
        for n in names:
            c = self.contact(n)
            if c is not None and c.id not in seen:
                seen.add(c.id)
                out.append(c.address())
        return out

    def route(self, inc: dict[str, Any]) -> Route:
        rule = next(r for r in self.rules if r.matches(inc))
        owner = self.contacts.get(rule.owner) or next(iter(self.contacts.values()))
        notify = [self.contacts[x] for x in rule.notify if x in self.contacts and x != owner.id]
        return Route(rule.name, owner, notify)

    def public(self) -> dict[str, Any]:
        return {"source": self.source, "contacts": [c.public() for c in self.contacts.values()],
                "rules": [r.public() for r in self.rules], "follow_up": self.follow_up.__dict__}


# ---------------------------------------------------------------------- loading

def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)] if str(v).strip() else []


def defaults(on_duty: str, team_lead: str, it_manager: str, cxo: str) -> Router:
    """The four people in the settings, each backing up the one before."""
    contacts = {
        "on_duty": Contact("on_duty", on_duty, "on_duty", backup="team_lead"),
        "team_lead": Contact("team_lead", team_lead, "team_lead", backup="it_manager"),
        "it_manager": Contact("it_manager", it_manager, "it_manager", backup="cxo"),
        "cxo": Contact("cxo", cxo, "cxo"),
    }
    rules = [
        Rule("Critical", {"severity": ["critical"]}, "on_duty", ["team_lead", "it_manager", "cxo"]),
        Rule("Attacker inside", {"category": list(INSIDE_JOBS)}, "on_duty", ["team_lead", "it_manager"]),
        Rule("High", {"severity": ["high"]}, "on_duty", ["team_lead"]),
        Rule("Everything else", {}, "on_duty"),
    ]
    return Router(contacts, rules, FollowUp())


def parse(data: dict[str, Any], fallback: Router) -> Router:
    raw_contacts = data.get("contacts") or {}
    if isinstance(raw_contacts, list):
        raw_contacts = {str(c.get("id") or c.get("name")): c for c in raw_contacts if isinstance(c, dict)}
    contacts = {}
    for cid, c in raw_contacts.items():
        if not isinstance(c, dict):
            continue
        contacts[str(cid)] = Contact(str(cid), str(c.get("name") or cid), str(c.get("role") or ""),
                                     str(c.get("email") or "").strip(), str(c.get("telegram") or "").strip(),
                                     str(c.get("backup") or ""))
    if not contacts:
        contacts = dict(fallback.contacts)
    rules = []
    for n, r in enumerate(data.get("rules") or [], 1):
        if not isinstance(r, dict):
            continue
        match = {k: _as_list(v) for k, v in (r.get("match") or {}).items() if k in MATCH_KEYS and _as_list(v)}
        owner = str(r.get("owner") or "")
        if owner not in contacts:
            log.warning("routing rule %s: owner %r is not a contact; rule skipped", n, owner)
            continue
        rules.append(Rule(str(r.get("name") or f"Rule {n}"), match, owner,
                          [x for x in _as_list(r.get("notify")) if x in contacts]))
    if not rules and not data.get("rules"):
        # Contacts only: keep the default rules wherever their contact ids exist.
        rules = [Rule(r.name, r.match, r.owner, [x for x in r.notify if x in contacts])
                 for r in fallback.rules if r.owner in contacts]
    f = data.get("follow_up") or {}
    fu = FollowUp()
    try:
        fu = FollowUp(int(f.get("escalate_after_reminders", fu.escalate_after_reminders)),
                      int(f.get("max_escalations", fu.max_escalations)),
                      float(f.get("resolve_within_hours", fu.resolve_within_hours)))
    except (TypeError, ValueError):
        log.warning("routing follow_up has a non-number; using the defaults")
    return Router(contacts, rules, fu)


def load(path: Path, on_duty: str, team_lead: str, it_manager: str, cxo: str) -> Router:
    base = defaults(on_duty, team_lead, it_manager, cxo)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return base
    except (OSError, ValueError) as exc:
        log.warning("could not read routing file %s (%s); using the settings' four contacts", path, exc)
        return base
    if not isinstance(data, dict):
        return base
    router = parse(data, base)
    router.source = str(path)
    return router


def from_settings(s: Any) -> Router:
    path = Path(os.getenv("CACTAI_ROUTING", "").strip() or s.db_path.parent / "routing.json")
    return load(path, s.on_duty, s.team_lead, s.it_manager, s.cxo)
