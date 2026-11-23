"""Is SentrAI actually looking? "Quiet" only means safe when the computers are reporting in.

A panel with no computer reporting, or with some gone silent, has nothing to raise, so every list is empty and
every headline says "All quiet". That is a green light for something nobody checked. This module gives the one
answer the headlines use instead: watching (every computer reports in), partly (some have gone quiet) or
not_watching (none reports), with the plain sentence to say in place of "All quiet".

It reads the Machines page's own rows (ui_machines.py), so "reporting in" means the same everywhere.
"""
from __future__ import annotations

from typing import Any, Callable

WATCHING, PARTLY, NOT_WATCHING = "watching", "partly", "not_watching"
NOT_WATCHING_WORDS = "No computer is reporting in, so SentrAI cannot see anything yet."


def of(page: dict[str, Any] | None) -> dict[str, Any]:
    """{"state", "total", "reporting", "quiet" (names, at most 10), "words"} from GET /ui/machines' answer."""
    rows = [r for r in (page or {}).get("machines") or [] if isinstance(r, dict)]
    reporting = [r for r in rows if r.get("online")]
    quiet = [str(r.get("name") or r.get("host") or "a computer") for r in rows if not r.get("online")]
    state = WATCHING if rows and not quiet else PARTLY if reporting else NOT_WATCHING
    if state == WATCHING:
        words = ""
    elif state == PARTLY:
        names = ", ".join(quiet[:3]) + (f" and {len(quiet) - 3} more" if len(quiet) > 3 else "")
        words = f"SentrAI has not heard from {names} lately, so it cannot say {'that one is' if len(quiet) == 1 else 'those are'} quiet."
    else:
        words = NOT_WATCHING_WORDS
    return {"state": state, "total": len(rows), "reporting": len(reporting), "quiet": quiet[:10], "words": words}


def safe(watching: Callable[[], dict[str, Any]] | None) -> dict[str, Any] | None:
    """The core's watching() answer, or None when this core has none or it failed (then say nothing extra)."""
    if watching is None:
        return None
    try:
        return watching()
    except Exception:  # noqa: BLE001  a broken machine list must not break the headlines
        return None


def quiet_headline(all_quiet: str, nothing_new: str, cov: dict[str, Any] | None) -> str:
    """What to say when nothing needs a person: `all_quiet` only when every computer reports in. Otherwise
    `nothing_new` (no "quiet", no "safe") followed by why that is not the whole story."""
    if cov is None or cov.get("state") == WATCHING:
        return all_quiet
    return f"{nothing_new} {cov['words']}"
