"""Who gets a Telegram message for each alert: each person in their own chat, the group when needed.

The core puts the people an alert is for under ``deliver_to``; each one carries ``telegram_chat``
once that person has linked a private chat with the bot (``/link CODE``). Those people get the alert
directly. The group chat (TELEGRAM_CHAT_ID) gets it as well when:

- the alert is not for anyone in particular (a fingerprint, backup or summary notice), or
- somebody it is for has not linked a chat yet (they are @mentioned there, as before), or
- TELEGRAM_GROUP_COPY=always (the group keeps a copy of every alert, for the team record).

TELEGRAM_GROUP_COPY=off keeps the group quiet unless nobody could be reached directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("sentrai.notifier")

GROUP_MODES = ("fallback", "always", "off")


@dataclass(frozen=True)
class Target:
    chat_id: str
    to: str | None  # the person's name for a direct message, None for the group

    @property
    def direct(self) -> bool:
        return self.to is not None


def group_mode(value: str | None) -> str:
    v = (value or "").strip().lower()
    return v if v in GROUP_MODES else "fallback"


def plan(notification: dict, group_chat: str, mode: str = "fallback") -> list[Target]:
    """Direct messages first (one per linked chat), then the group if this alert needs it."""
    direct: list[Target] = []
    unlinked = False
    seen: set[str] = set()
    for d in notification.get("deliver_to") or []:
        if not isinstance(d, dict):
            continue
        chat = str(d.get("telegram_chat") or "").strip()
        if not chat:
            unlinked = True
            continue
        if chat not in seen:
            seen.add(chat)
            direct.append(Target(chat, str(d.get("name") or d.get("id") or chat)))
    if not direct:
        need_group = True
    elif mode == "always":
        need_group = True
    elif mode == "off":
        need_group = False
    else:
        need_group = unlinked
    if need_group and group_chat and group_chat not in seen:
        direct.append(Target(group_chat, None))
    return direct


def receipts(result, channel: str) -> list[tuple[str, str, str | None]]:
    """A sender's result as (channel, message id, person) receipts, for POST /notifications/{id}/delivered.

    A sender may return a message id, (channel, message id), or a list of (channel, message id, person)."""
    if isinstance(result, list):
        return [(str(c), str(m), p) for c, m, p in result]
    if isinstance(result, tuple):
        return [(str(result[0]), str(result[1]), None)]
    return [(channel, str(result), None)]


def deliver(targets: list[Target], send_one: Callable[[Target], str], group_chat: str,
            note: Callable[[Exception], str] = str) -> list[tuple[str, str, str | None]]:
    """Send to each target; a direct message that fails (the person blocked the bot) goes to the group
    instead, once. Returns (channel, message id, person) receipts; raises only if nothing was sent."""
    out: list[tuple[str, str, str | None]] = []
    group_done = False
    last_error: Exception | None = None
    for t in targets:
        if not t.direct and group_done:
            continue
        try:
            mid = send_one(t)
        except Exception as exc:
            last_error = exc
            if t.direct and group_chat and not group_done:
                log.warning("direct message to %s failed (%s); the group gets it instead", t.to, note(exc))
                try:
                    out.append(("telegram", send_one(Target(group_chat, None)), None))
                    group_done = True
                except Exception as exc2:
                    last_error = exc2
            continue
        if t.direct:
            out.append(("telegram-direct", mid, t.to))
        else:
            group_done = True
            out.append(("telegram", mid, None))
    if not out:
        raise last_error or RuntimeError("no Telegram chat to send to")
    return out
