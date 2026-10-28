"""Who hears about an incident, who owns it, and who it goes to when nobody answers.

Contacts, routing rules and the follow-up policy come from a JSON file (SENTRAI_ROUTING, default
``people/routing.json`` next to the database). Without one, the four people in the settings (ON_DUTY,
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
      "follow_up": {"escalate_after_reminders": 2, "max_escalations": 3, "resolve_within_hours": 24},
      "layout": {"incident": [0, 120], "rules": [[210, 0], [210, 90], [210, 180]], "contacts": {"amir": [620, 40]}}
    }

A rule matches on any of category, severity, host and layer (a value, a list of values, or a
shell pattern such as ``web-*``); the first rule that matches wins. Its owner is assigned the
incident and hears every reminder; the people under notify are told about it once.

The dashboard edits this file through POST /routing: ``validate`` checks a whole new version and
``save`` writes it in one go, so a half-written or broken file never reaches the router. ``layout`` is
only where the dashboard's map draws each box (rules in their order, people by id); routing ignores it.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import math
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .risk import SEVERITIES, SEVERITY
import sentrai_paths

log = logging.getLogger("sentrai.routing")

MATCH_KEYS = ("category", "severity", "host", "layer")
# Kept by the attacker's touch on files or data: the IT manager hears about them as well. Root from a
# sign-in SentrAI does not recognise (admins.py) belongs here too: it is either an intruder inside or an
# administrator it has not met, and the IT manager knows which.
INSIDE_JOBS = ("malware", "data_exfiltration", "log_tampering", "privilege_escalation", "unauthorised_admin")


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
                 source: str = "defaults", layout: dict[str, Any] | None = None) -> None:
        self.contacts = contacts
        self.rules = rules
        self.follow_up = follow_up
        self.source = source
        self.layout = layout or {}  # the dashboard map's box positions; nothing here reads them
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
                "rules": [r.public() for r in self.rules], "follow_up": self.follow_up.__dict__,
                "layout": self.layout}


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
    router.layout = clean_layout(data.get("layout"), router.contacts, len(router.rules))
    return router


def path_from_settings(s: Any) -> Path:
    """people/routing.json next to the database (SENTRAI_ROUTING moves it)."""
    return sentrai_paths.path("core.routing", Path(s.db_path).parent)


def from_settings(s: Any) -> Router:
    return load(path_from_settings(s), s.on_duty, s.team_lead, s.it_manager, s.cxo)


# ---------------------------------------------------------------------- editing

CONTACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
MAX_CONTACTS, MAX_RULES, MAX_TEXT = 200, 100, 120
LAYOUT_LIMIT = 100_000  # map coordinates, in pixels either way from the middle


def clean_layout(raw: Any, contacts: Any, rules: int) -> dict[str, Any]:
    """The map positions worth keeping: {"incident": [x, y], "rules": [[x, y] or None, ...] (one per rule,
    in order), "contacts": {id: [x, y]}}. Anything that is not a pair of plain numbers, or names someone
    who is not in the file, is dropped; the dashboard lays those boxes out itself."""
    def point(v: Any) -> list[int] | None:
        if isinstance(v, (list, tuple)) and len(v) == 2 and all(
                isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n)
                and abs(n) <= LAYOUT_LIMIT for n in v):
            return [round(v[0]), round(v[1])]
        return None

    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    if (p := point(raw.get("incident"))) is not None:
        out["incident"] = p
    if isinstance(raw.get("rules"), list):
        pts = [point(v) for v in raw["rules"][:rules]]
        if any(p is not None for p in pts):
            out["rules"] = pts
    if isinstance(raw.get("contacts"), dict):
        keep = {cid: p for cid in contacts if (p := point(raw["contacts"].get(cid))) is not None}
        if keep:
            out["contacts"] = keep
    return out


def _text(v: Any, what: str, required: bool = False) -> str:
    t = str(v or "").strip()
    if required and not t:
        raise ValueError(f"{what} is empty")
    if len(t) > MAX_TEXT:
        raise ValueError(f"{what} is longer than {MAX_TEXT} characters")
    return t


def validate(data: Any) -> dict[str, Any]:
    """A whole routing file, checked and tidied, or ValueError with a reason a person can act on."""
    if not isinstance(data, dict):
        raise ValueError("the routing must be an object with contacts, rules and follow_up")
    raw = data.get("contacts") or {}
    if isinstance(raw, list):
        raw = {str(c.get("id") or ""): c for c in raw if isinstance(c, dict)}
    if not isinstance(raw, dict) or not raw:
        raise ValueError("keep at least one person in the routing")
    if len(raw) > MAX_CONTACTS:
        raise ValueError(f"at most {MAX_CONTACTS} people")
    contacts: dict[str, dict[str, str]] = {}
    names: set[str] = set()
    for cid, c in raw.items():
        cid = str(cid)
        if not CONTACT_ID.match(cid):
            raise ValueError(f"{cid!r} is not a usable id (letters, digits, _ . - only)")
        if not isinstance(c, dict):
            raise ValueError(f"contact {cid} is not an object")
        name = _text(c.get("name"), f"the name of {cid}", required=True)
        if name.lower() in names:
            raise ValueError(f"two people are called {name!r}: give each a different name")
        names.add(name.lower())
        email = _text(c.get("email"), f"{name}'s email")
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError(f"{name}'s email {email!r} does not look like an email address")
        contacts[cid] = {"name": name, "role": _text(c.get("role"), f"{name}'s role"), "email": email,
                         "telegram": _text(c.get("telegram"), f"{name}'s Telegram"),
                         "backup": _text(c.get("backup"), f"{name}'s backup")}
    for cid, c in contacts.items():
        if c["backup"] and c["backup"] not in contacts:
            raise ValueError(f"{c['name']}'s backup {c['backup']!r} is not one of the people")
        if c["backup"] == cid:
            raise ValueError(f"{c['name']} cannot be their own backup")
    rules = []
    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise ValueError(f"rules must be a list of at most {MAX_RULES}")
    for n, r in enumerate(raw_rules, 1):
        if not isinstance(r, dict):
            raise ValueError(f"rule {n} is not an object")
        name = _text(r.get("name"), f"the name of rule {n}", required=True)
        match: dict[str, list[str]] = {}
        for key, v in (r.get("match") or {}).items():
            if key not in MATCH_KEYS:
                raise ValueError(f"rule {name!r}: can only match on {', '.join(MATCH_KEYS)}")
            values = [_text(x, f"rule {name!r} {key}") for x in _as_list(v)]
            values = [x for x in values if x]
            # Every incident type the core makes (staff reports too, which the classifier never picks).
            known = {"category": SEVERITY, "severity": SEVERITIES}.get(key)
            bad = [x for x in values if known is not None and x not in known]
            if bad:
                raise ValueError(f"rule {name!r}: unknown {key} {', '.join(bad)}")
            if values:
                match[key] = values
        owner = str(r.get("owner") or "")
        if owner not in contacts:
            raise ValueError(f"rule {name!r} needs an owner who is one of the people")
        notify = [x for x in dict.fromkeys(_as_list(r.get("notify"))) if x != owner]
        bad = [x for x in notify if x not in contacts]
        if bad:
            raise ValueError(f"rule {name!r} tells {', '.join(bad)}, who are not among the people")
        rules.append({"name": name, "match": match, "owner": owner, "notify": notify})
    f = data.get("follow_up") or {}
    try:
        fu = {"escalate_after_reminders": int(f.get("escalate_after_reminders", 2)),
              "max_escalations": int(f.get("max_escalations", 3)),
              "resolve_within_hours": float(f.get("resolve_within_hours", 24))}
    except (TypeError, ValueError):
        raise ValueError("follow_up needs whole numbers of reminders and escalations and a number of hours")
    if not (1 <= fu["escalate_after_reminders"] <= 20 and 0 <= fu["max_escalations"] <= 20
            and 0 <= fu["resolve_within_hours"] <= 24 * 30):
        raise ValueError("follow_up is out of range (1-20 reminders, 0-20 escalations, 0-720 hours)")
    out = {"contacts": contacts, "rules": rules, "follow_up": fu}
    layout = clean_layout(data.get("layout"), contacts, len(rules))
    if layout:
        out["layout"] = layout
    return out


def changed_parts(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Which parts of the file a save changed: people, rules, follow_up and/or layout (the map only)."""
    names = {"contacts": "people", "rules": "rules", "follow_up": "follow_up", "layout": "layout"}
    return [label for key, label in names.items() if (before.get(key) or {}) != (after.get(key) or {})]


def save(path: Path, data: dict[str, Any]) -> None:
    """Write the routing file in one step (temporary file, then rename), readable by its owner only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".routing-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
