"""Which Telegram chat reaches each contact, so alerts go to people directly instead of one group.

A Telegram bot cannot message someone by their @handle: the person has to open a private chat
with the bot first. Linking does that once:

1. Someone with dashboard access makes a one-time link code for a contact (Incidents page, or
   POST /telegram/link-codes). The code is valid for 30 minutes and works once.
2. The person sends ``/link CODE`` to the bot in a private chat (or opens the bot's
   ``t.me/<bot>?start=CODE`` link, which does the same).
3. The notifier hands the code and that private chat's id to the core (POST /telegram/link), and
   from then on every alert routed to that contact goes to their own chat.

Links are kept in ``telegram_links.json`` next to the database. A contact whose ``telegram`` in the
routing file is already a numeric chat id counts as linked without a code.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("cactai.telegram_links")

CODE_TTL_S = 30 * 60
# No 0/O or 1/I/L, so a code read off a screen is typed right the first time.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LEN = 8


@dataclass
class Link:
    contact_id: str
    chat_id: str
    username: str = ""
    linked_at: str = ""
    linked_by: str = ""  # who made the code


def is_chat_id(value: str) -> bool:
    return bool(value) and value.lstrip("-").isdigit()


def normalize_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


class LinkBook:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.links: dict[str, Link] = {}
        self._codes: dict[str, tuple[str, float, str]] = {}  # code -> (contact id, expires at, made by)
        self._load()

    # ------------------------------------------------------------------ storage
    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.warning("could not read %s (%s); starting with no Telegram links", self.path, exc)
            return
        for row in data.get("links") or [] if isinstance(data, dict) else []:
            if isinstance(row, dict) and row.get("contact_id") and is_chat_id(str(row.get("chat_id") or "")):
                link = Link(str(row["contact_id"]), str(row["chat_id"]), str(row.get("username") or ""),
                            str(row.get("linked_at") or ""), str(row.get("linked_by") or ""))
                self.links[link.contact_id] = link

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"links": [asdict(x) for x in self.links.values()]}, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)  # chat ids say who works security here
            except OSError:
                pass
        except OSError as exc:
            log.warning("could not save Telegram links to %s: %s", self.path, exc)

    # ------------------------------------------------------------------ codes
    def new_code(self, contact_id: str, made_by: str, now: float | None = None) -> tuple[str, float]:
        now = time.time() if now is None else now
        self._codes = {c: v for c, v in self._codes.items() if v[1] > now and v[0] != contact_id}
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))
        self._codes[code] = (contact_id, now + CODE_TTL_S, made_by)
        return code, now + CODE_TTL_S

    def redeem(self, code: str, chat_id: str, username: str, linked_at: str,
               now: float | None = None) -> tuple[Link | None, Link | None]:
        """(new link, the link it replaced) for a valid code, or (None, None). A code works once."""
        now = time.time() if now is None else now
        entry = self._codes.pop(normalize_code(code), None)
        if entry is None or entry[1] <= now or not is_chat_id(chat_id):
            return None, None
        contact_id, _, made_by = entry
        # One chat is one person: a chat that was linked to someone else is moved, not shared.
        old_owner = next((cid for cid, x in self.links.items() if x.chat_id == chat_id and cid != contact_id), None)
        if old_owner:
            self.links.pop(old_owner)
        replaced = self.links.get(contact_id)
        link = Link(contact_id, chat_id, username.lstrip("@"), linked_at, made_by)
        self.links[contact_id] = link
        self._save()
        return link, replaced

    # ------------------------------------------------------------------ lookups
    def chat_for(self, contact_id: str, telegram: str = "") -> str:
        """The private chat that reaches this contact: a linked chat, else a chat id in the routing file."""
        link = self.links.get(contact_id)
        if link is not None:
            return link.chat_id
        return telegram if is_chat_id(telegram) else ""

    def by_chat(self, chat_id: str) -> Link | None:
        return next((x for x in self.links.values() if x.chat_id == str(chat_id)), None)

    def unlink(self, contact_id: str) -> Link | None:
        link = self.links.pop(contact_id, None)
        if link is not None:
            self._save()
        return link

    def public(self) -> list[dict[str, Any]]:
        return [asdict(x) for x in self.links.values()]


def from_settings(s: Any) -> LinkBook:
    path = Path(os.getenv("CACTAI_TELEGRAM_LINKS", "").strip() or s.db_path.parent / "telegram_links.json")
    return LinkBook(path)
