"""Everything SentrAI can connect to outside itself, in one list: the built-in channels (webhook, email)
and the installed extensions (mvp/extensions/*), each with whether it is set up and how it last went.

GET /integrations is the old name of this list and still answers; GET /extensions is the same rows.
The dashboard's Extensions page reads them. Secrets are never returned: only whether they are set.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

BUILT_IN: dict[str, dict[str, Any]] = {
    "webhook": {
        "title": "Any other system (webhook)", "kind": "Blocking",
        "what": "Sends each block and its removal to a URL you choose: n8n, Zapier, a router, a SOAR.",
        "settings": ["SENTRAI_RESPONDER_WEBHOOK_URL", "SENTRAI_RESPONDER_WEBHOOK_SECRET", "SENTRAI_RESPONDER_WEBHOOK_ACTIONS"],
        "docs": "", "about": "Part of SentrAI: set a URL to hand blocks to another system.",
    },
    "email": {
        "title": "Email", "kind": "Alerts",
        "what": "Emails alerts, as a backup to the other alert channels or always.",
        "settings": ["SMTP_HOST", "ALERT_EMAIL_TO"],
        "docs": "", "about": "Part of SentrAI: set an SMTP server and the recipients.",
    },
}


def built_in(core: Any) -> list[dict[str, Any]]:
    """The two channels that are part of SentrAI itself: always installed, never added or removed."""
    hook = core.webhook_responder
    rows = {
        "webhook": {"configured": hook is not None,
                    "detail": f"Sends {', '.join(hook.actions)} to {urlsplit(hook.url).netloc}" if hook else
                              "Set a URL to hand blocks to another system.",
                    "last_error": hook.last_error if hook else None},
        "email": {"configured": bool(os.getenv("SMTP_HOST") and os.getenv("ALERT_EMAIL_TO")),
                  "detail": "Handled by the notifier."},
    }
    return [{"name": k, **BUILT_IN[k], "built_in": True, "added": True, "added_by": "built_in", "running": True,
             "testable": False, "last_ok": None, "last_error": None, "error": None, "source": "built_in",
             "on_when": [], "parts": [], "requires": {}, **v} for k, v in rows.items()]


def status(core: Any) -> list[dict[str, Any]]:
    """Every extension row, then the built-in channels. No secrets."""
    return [*core.extensions.rows(), *built_in(core)]


def test(core: Any, name: str) -> dict[str, Any]:
    if name in BUILT_IN:
        return {"ok": False, "error": f"{BUILT_IN[name]['title']} has no test here yet."}
    return core.extensions.test(name)  # KeyError for a name that is not installed
