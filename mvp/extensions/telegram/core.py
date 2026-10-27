"""Telegram extension, core part: which Telegram chat reaches each contact, so alerts go to people
directly instead of one group. The bot itself runs in the notifier (notifier.py next to this file).

A Telegram bot cannot message someone by their @handle: the person has to open a private chat
with the bot first. Linking does that once:

1. Someone with dashboard access makes a one-time link code for a contact (Incidents page, or
   POST /telegram/link-codes). The code is valid for 30 minutes and works once.
2. The person sends ``/link CODE`` to the bot in a private chat (or opens the bot's
   ``t.me/<bot>?start=CODE`` link, which does the same).
3. The notifier hands the code and that private chat's id to the core (POST /telegram/link), and
   from then on every alert routed to that contact goes to their own chat.

Links are kept in ``people/telegram_links.json`` in the core's data folder (SENTRAI_TELEGRAM_LINKS moves it). A
contact whose ``telegram`` in the routing file is already a numeric chat id counts as linked without a
code. Removing the extension keeps the file, so adding it again brings every link back.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Union

from fastapi import HTTPException
from pydantic import BaseModel

import sentrai_paths

from app.extensions import Context, Extension

log = logging.getLogger("sentrai.ext.telegram")

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


class LinkError(ValueError):
    """A code that is wrong, already used or expired (the API answers 400)."""


def _n(n: int, word: str) -> str:
    return f"{n} {word if n == 1 else word + 's'}"


class Telegram(Extension):
    def __init__(self, ctx: Context, book: LinkBook) -> None:
        self.ctx = ctx
        self.book = book

    def contacts(self, rows: list[dict[str, Any]]) -> None:
        for c in rows:
            c["telegram_linked"] = bool(self.book.chat_for(c["id"], c.get("telegram") or ""))

    def addresses(self, rows: list[dict[str, Any]]) -> None:
        for a in rows:
            a["telegram_chat"] = self.book.chat_for(a["id"], a.get("telegram") or "")

    def status(self) -> dict[str, Any]:
        linked = _n(len(self.links_public()), "personal chat")
        if not self.ctx.setting("TELEGRAM_BOT_TOKEN"):
            return {"configured": False, "detail": "Make a bot with @BotFather and paste its token."}
        if not self.ctx.setting("TELEGRAM_CHAT_ID"):
            return {"configured": False, "detail": f"Paste the team group's chat id too. {linked} linked."}
        return {"configured": True, "detail": f"The notifier runs the bot · {linked} linked"}

    # ------------------------------------------------------------------ personal chats
    def _contact(self, ref: str) -> Any:
        c = self.ctx.contact(ref)
        if c is None:
            raise KeyError(ref)
        return c

    def link_code(self, contact: str, operator: str) -> dict[str, Any]:
        """A one-time code the contact sends to the bot (/link CODE) to get their alerts in a private chat."""
        with self.ctx.lock:
            c = self._contact(contact)
            code, expires = self.book.new_code(c.id, operator)
            self.ctx.record("telegram_link_code", {"contact": c.id, "name": c.name, "operator": operator,
                                                   "expires_at": self.ctx.iso(expires)})
            return {"contact": c.id, "name": c.name, "code": code, "expires_at": self.ctx.iso(expires),
                    "valid_minutes": CODE_TTL_S // 60, "send": f"/link {code}"}

    def link(self, code: str, chat_id: str, username: str = "") -> dict[str, Any]:
        """The notifier passes on a /link CODE it received in a private chat."""
        with self.ctx.lock:
            link, replaced = self.book.redeem(code, str(chat_id), username or "", self.ctx.iso())
            if link is None:
                raise LinkError("That code is wrong, already used or expired. Ask for a new one.")
            c = self._contact(link.contact_id)
            self.ctx.record("telegram_linked", {
                "contact": c.id, "name": c.name, "chat_id": link.chat_id, "username": link.username,
                "code_made_by": link.linked_by, "replaced_chat": replaced.chat_id if replaced else None})
            return {**self._public(link), "replaced": bool(replaced)}

    def unlink(self, contact: str | None, chat_id: str | None, operator: str) -> dict[str, Any]:
        with self.ctx.lock:
            link = self.book.by_chat(chat_id) if chat_id else None
            cid = link.contact_id if link else (self._contact(contact).id if contact else "")
            gone = self.book.unlink(cid) if cid else None
            if gone is None:
                raise KeyError(contact or chat_id or "")
            self.ctx.record("telegram_unlinked", {"contact": cid, "chat_id": gone.chat_id, "operator": operator})
            return {"contact": cid, "unlinked": True}

    def _public(self, link: Link) -> dict[str, Any]:
        c = self.ctx.contact(link.contact_id)
        return {**link.__dict__, "name": c.name if c else link.contact_id, "role": c.role if c else ""}

    def links_public(self) -> list[dict[str, Any]]:
        """Linked chats (by link code), then contacts whose routing entry is a chat id already."""
        with self.ctx.lock:
            out = [self._public(x) for x in self.book.links.values()]
            linked = {x["contact_id"] for x in out}
            for c in self.ctx.contacts():
                if c.id not in linked and is_chat_id(c.telegram):
                    out.append({"contact_id": c.id, "chat_id": c.telegram, "username": "", "linked_at": "",
                                "linked_by": "routing file", "name": c.name, "role": c.role})
            return out


def setup(ctx: Context) -> Extension:
    path = sentrai_paths.path("core.telegram_links", Path(ctx.state_dir))  # SENTRAI_TELEGRAM_LINKS moves it
    return Telegram(ctx, LinkBook(path))


class LinkCodeIn(BaseModel):
    operator: str
    contact: str


class TelegramLinkIn(BaseModel):
    code: str
    chat_id: Union[str, int]
    username: Optional[str] = ""


class TelegramUnlinkIn(BaseModel):
    operator: str
    contact: Optional[str] = None
    chat_id: Optional[Union[str, int]] = None


def routes(router: Any, live: Any) -> None:
    """Personal Telegram alerts: a contact links their private chat with a one-time code."""

    @router.post("/telegram/link-codes")
    def post_link_code(body: LinkCodeIn) -> dict[str, Any]:
        try:
            return live().link_code(body.contact, body.operator)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"no contact called {body.contact!r} in the routing file")

    @router.post("/telegram/link")
    def post_telegram_link(body: TelegramLinkIn) -> dict[str, Any]:
        try:
            return live().link(body.code, str(body.chat_id), body.username or "")
        except LinkError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except KeyError:
            raise HTTPException(status_code=404, detail="that contact is no longer in the routing file")

    @router.post("/telegram/unlink")
    def post_telegram_unlink(body: TelegramUnlinkIn) -> dict[str, Any]:
        try:
            return live().unlink(body.contact, None if body.chat_id is None else str(body.chat_id), body.operator)
        except KeyError:
            raise HTTPException(status_code=404, detail="no linked Telegram chat for that contact")

    @router.get("/telegram/links")
    def get_telegram_links() -> list[dict[str, Any]]:
        return live().links_public()
