"""Protection readiness: the short list at the top of the Command Center that says what is still missing.

A new panel looks quiet whether it is fully set up or not watching anything at all. This list tells the two apart
in plain words: protection is on, computers report in, every computer really blocks (not a dry run), someone gets
alerts, and there is a recent backup. Each line that is not ready says what is missing; the fix is for SentrAI's
team (the owner is not walked through settings), and `fix_cli` is the command the team runs.

Read-only. `sentrai status` prints the same list.
"""
from __future__ import annotations

import os
from typing import Any, Callable

from fastapi import FastAPI

from . import briefing
from .config import sentrai_config as cfg
import sentrai_llm  # noqa: E402  (mvp/ is on the path, see __init__)

TEAM = "SentrAI's team can set this up for you."


def _setting(values: dict[str, str], env: str) -> str:
    return str(values.get(env) or os.environ.get(env) or "").strip()


def alert_channels(values: dict[str, str], added: Callable[[str], bool], owner_emails: int = 0) -> list[str]:
    """The ways an alert reaches a person outside the panel: email, Telegram or Slack, set up and switched on.
    Email needs a mail server (the company's own, or the SentrAI mail relay) and someone to send to: ALERT_EMAIL_TO,
    or the Owner and Admin accounts (notifier/emailer.py), unless SENTRAI_ALERT_OWNERS is off."""
    out = []
    to_owners = _setting(values, "SENTRAI_ALERT_OWNERS").lower() not in ("0", "off", "no", "false")
    if _setting(values, "SMTP_HOST") or _setting(values, "SENTRAI_RELAY_SMTP_HOST"):
        if _setting(values, "ALERT_EMAIL_TO"):
            out.append("email")
        elif to_owners and owner_emails:
            out.append("email to the Owner and Admin accounts")
    if added("telegram") and _setting(values, "TELEGRAM_BOT_TOKEN"):
        out.append("Telegram")
    if added("slack") and _setting(values, "SLACK_WEBHOOK_URL"):
        out.append("Slack")
    return out


def checks(protection: str, machines: dict[str, Any], channels: list[str], backup: dict[str, Any] | None,
           now: float) -> list[dict[str, Any]]:
    """The readiness lines, in the order an owner should fix them. Each: key, ok, state, title, detail, fix,
    fix_cli. state is "ok", "missing" or "not_checked" (SentrAI could not look); ok is True only for "ok", so a
    line nobody could check is never shown as ready. backup "unreadable": the backup folder could not be read."""
    out: list[dict[str, Any]] = []

    def add(key: str, ok: bool | None, title: str, detail: str, fix_cli: str) -> None:
        out.append({"key": key, "ok": ok is True, "state": "ok" if ok else "not_checked" if ok is None else "missing",
                    "title": title, "detail": detail, "fix": "" if ok else TEAM, "fix_cli": "" if ok else fix_cli})

    on = protection == "on"
    add("protection", on, "Protection is switched on",
        "SentrAI can block attackers." if on else "SentrAI is only watching. It will not block anything until it is "
        "switched back on.", "sudo sentrai protection on")

    rows = [r for r in machines.get("machines") or [] if isinstance(r, dict)]
    quiet = [str(r.get("name") or r.get("host")) for r in rows if not r.get("online")]
    add("reporting", bool(rows) and not quiet, "Your computers are reporting in",
        (f"{len(rows)} computer{'s' if len(rows) != 1 else ''} reporting." if rows and not quiet
         else "No computer has reported yet, so SentrAI cannot see anything." if not rows
         else "Not heard from lately: " + ", ".join(quiet[:5]) + ("…" if len(quiet) > 5 else "") + "."),
        "sudo sentrai machines list   # then: sudo sentrai machines join-code --name NAME")

    dry = [str(r.get("name") or r.get("host")) for r in rows if (r.get("blocking") or {}).get("state") == "dry_run"]
    old = [str(r.get("name") or r.get("host")) for r in rows if (r.get("blocking") or {}).get("state") == "unknown"]
    detail = ("Every computer with SentrAI on it really blocks attackers." if not dry and not old else
              " ".join(x for x in (
                  ("Only practising (a dry run) on: " + ", ".join(dry[:5]) + ". Blocks there are written down but "
                   "not made.") if dry else "",
                  ("Too old to say: " + ", ".join(old[:5]) + ".") if old else "") if x))
    if not rows:
        detail = "Not checked: no computer has reported yet, so SentrAI cannot tell whether blocks there work."
    add("blocking", None if not rows else not dry and not old, "Blocks really stop attackers", detail,
        "sudo sentrai machines blocking HOST on" if dry else "sudo sentrai-update   # on that computer")

    add("alerts", bool(channels), "Someone is told when it matters",
        ("Alerts go out by " + " and ".join(channels) + ".") if channels else
        "Alerts only show here on the panel. Nobody is told at night or when the panel is closed.",
        "sudo sentrai settings set SMTP_HOST=... ALERT_EMAIL_TO=...   # or: sentrai integrations on telegram")

    if backup == "unreadable":
        add("backup", None, "There is a recent backup", "Not checked: SentrAI could not read its backup folder.",
            "sudo sentrai backups list")
    elif backup is not None:
        last = next((b for b in backup.get("backups") or [] if b.get("reason") != "before_restore"), None)
        age = now - float(last.get("created_ts") or 0) if last else None
        ok = bool(last) and not backup.get("overdue") and age is not None and age < briefing.BACKUP_STALE_S
        add("backup", ok, "There is a recent backup",
            (f"The last one is {max(1, round(age / 3600))} hour{'s' if round(age / 3600) > 1 else ''} old."
             if last and age is not None else "No backup has been made yet.")
            + ("" if backup.get("enabled", True) else " Backups are switched off."), "sudo sentrai backups now")
    return out


def summary(lines: list[dict[str, Any]]) -> dict[str, Any]:
    missing = [c for c in lines if not c["ok"]]
    unchecked = sum(1 for c in missing if c.get("state") == "not_checked")
    todo = len(missing) - unchecked
    if not missing:
        headline = "SentrAI is fully set up and protecting you."
    elif not todo:
        headline = f"{unchecked} thing{'s' if unchecked != 1 else ''} SentrAI could not check yet, so it cannot say you are fully protected."
    else:
        headline = (f"{todo} thing{'s' if todo != 1 else ''} still to set up before SentrAI fully protects you"
                    + (f", and {unchecked} it could not check." if unchecked else "."))
    return {"ready": not missing, "missing": len(missing), "not_checked": unchecked, "checks": lines,
            "headline": headline}


def install(app: FastAPI, core: Any, machines_page: Callable[[], dict[str, Any]], backups: Any,
            owner_emails: Callable[[], list[str]] = lambda: []) -> None:
    @app.get("/ui/readiness")
    def get_readiness() -> dict[str, Any]:
        try:
            st = backups.status() if backups is not None else None
        except Exception:  # noqa: BLE001  a broken backup folder must not break the Command Center
            st = "unreadable"  # shown as not checked, never left out (a missing line would read as ready)
        try:
            values = cfg.read()
        except Exception:  # noqa: BLE001
            values = {}
        try:
            owners = len(owner_emails())
        except Exception:  # noqa: BLE001
            owners = 0
        channels = alert_channels(values, core.extensions.added, owners)
        lines = checks(str(core.protection().get("protection") or ""), machines_page(), channels, st,
                       core.clock.now())
        out = summary(lines)
        try:
            out["ai_spend"] = sentrai_llm.spent_this_month()
        except Exception:  # noqa: BLE001
            pass
        return out
