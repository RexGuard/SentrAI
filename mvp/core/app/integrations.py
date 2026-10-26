"""Outside services SentrAI connects to, in one place: what each does, whether it is set up, and a test.

GET /integrations lists them for the dashboard's Integrations page; POST /integrations/{name}/test checks
one with a harmless call (reads Cloudflare, looks up 1.1.1.1 on AbuseIPDB, posts one test line to Slack).
Secrets are never returned: only whether they are set.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

# poster(url, body bytes, headers) -> HTTP status; raises on network errors (same shape as responders.Poster).
Poster = Callable[[str, bytes, dict[str, str]], int]

CATALOG: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "title": "Cloudflare", "kind": "Blocking",
        "what": "Blocks attacking addresses at Cloudflare's edge, so they never reach your site. "
                "Removed again when SentrAI's block ends.",
        "settings": ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_METHOD",
                     "CLOUDFLARE_LIST_ID", "CLOUDFLARE_MODE"],
        "docs": "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
    },
    "abuseipdb": {
        "title": "AbuseIPDB", "kind": "Lookups",
        "what": "Shows how often other people have reported an attacking address, on each incident.",
        "settings": ["ABUSEIPDB_API_KEY", "ABUSEIPDB_CACHE_HOURS"],
        "docs": "https://www.abuseipdb.com/account/api",
    },
    "slack": {
        "title": "Slack", "kind": "Alerts",
        "what": "Posts a copy of every alert to a Slack channel, next to Telegram and email.",
        "settings": ["SLACK_WEBHOOK_URL"],
        "docs": "https://api.slack.com/messaging/webhooks",
    },
    "webhook": {
        "title": "Any other system (webhook)", "kind": "Blocking",
        "what": "Sends each block and its removal to a URL you choose: n8n, Zapier, a router, a SOAR.",
        "settings": ["CACTAI_RESPONDER_WEBHOOK_URL", "CACTAI_RESPONDER_WEBHOOK_SECRET", "CACTAI_RESPONDER_WEBHOOK_ACTIONS"],
        "docs": "",
    },
    "telegram": {
        "title": "Telegram", "kind": "Alerts",
        "what": "Sends alerts with Approve / Reject buttons to a Telegram chat.",
        "settings": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
        "docs": "https://core.telegram.org/bots/tutorial",
    },
    "email": {
        "title": "Email", "kind": "Alerts",
        "what": "Emails alerts, as a backup to Telegram or always.",
        "settings": ["SMTP_HOST", "ALERT_EMAIL_TO"],
        "docs": "",
    },
}


def _httpx_poster(timeout_s: float = 5.0) -> Poster:
    import httpx

    def post(url: str, body: bytes, headers: dict[str, str]) -> int:
        return httpx.post(url, content=body, headers=headers, timeout=timeout_s, follow_redirects=False).status_code

    return post


def _when(ts: float | None) -> str | None:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else None


def slack_test(url: str, poster: Poster | None = None) -> dict[str, Any]:
    if not url.lower().startswith("https://"):
        return {"ok": False, "error": "the Slack webhook URL must start with https://"}
    body = json.dumps({"text": ":shield: SentrAI test message: alerts will arrive in this channel."}).encode()
    try:
        status = (poster or _httpx_poster())(url, body, {"Content-Type": "application/json"})
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
    if not 200 <= status < 300:
        return {"ok": False, "error": f"Slack answered HTTP {status}"}
    return {"ok": True, "detail": "Test message posted. Check the channel."}


def status(core: Any) -> list[dict[str, Any]]:
    """Every integration with whether it is set up and how it last went. No secrets."""
    s = core.settings
    cf, rep = core.cloudflare, core.reputation
    hook = core.webhook_responder
    rows: dict[str, dict[str, Any]] = {
        "cloudflare": {"configured": cf is not None,
                       "detail": (f"{'IP list' if cf.method == 'list' else 'IP Access rules, ' + cf.mode} on "
                                  f"{'zone ' + s.cloudflare_zone_id if s.cloudflare_zone_id and cf.method != 'list' else 'account'}"
                                  f" · {len(cf.status()['blocked'])} address(es) blocked now") if cf else
                                 "Paste an API token and a zone or account id to turn it on.",
                       "last_ok": _when(cf.last_ok) if cf else None, "last_error": cf.last_error if cf else None,
                       "testable": cf is not None, "error": core.cloudflare_error},
        "abuseipdb": {"configured": rep is not None,
                      "detail": f"{rep.lookups} lookup(s) since start, answers kept {s.abuseipdb_cache_hours:g} h"
                                if rep else "Paste a free API key to turn it on.",
                      "last_ok": _when(rep.last_ok) if rep else None, "last_error": rep.last_error if rep else None,
                      "testable": rep is not None},
        "slack": {"configured": bool(s.slack_webhook_url),
                  "detail": "The notifier posts each alert there." if s.slack_webhook_url else
                            "Create an incoming webhook in Slack and paste its URL.",
                  "testable": bool(s.slack_webhook_url)},
        "webhook": {"configured": hook is not None,
                    "detail": f"Sends {', '.join(hook.actions)} to {urlsplit(hook.url).netloc}" if hook else
                              "Set a URL to hand blocks to another system.",
                    "last_error": hook.last_error if hook else None, "testable": False},
        "telegram": {"configured": bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")),
                     "detail": "Handled by the notifier.", "testable": False},
        "email": {"configured": bool(os.getenv("SMTP_HOST") and os.getenv("ALERT_EMAIL_TO")),
                  "detail": "Handled by the notifier.", "testable": False},
    }
    return [{"name": k, **CATALOG[k], **v} for k, v in rows.items()]


def test(core: Any, name: str, poster: Poster | None = None) -> dict[str, Any]:
    if name not in CATALOG:
        raise KeyError(f"no integration called {name}")
    if name == "cloudflare":
        return core.cloudflare.test() if core.cloudflare else {"ok": False, "error": core.cloudflare_error or
                                                               "Cloudflare is not set up (no API token)."}
    if name == "abuseipdb":
        return core.reputation.test() if core.reputation else {"ok": False, "error": "No AbuseIPDB API key set."}
    if name == "slack":
        url = core.settings.slack_webhook_url
        return slack_test(url, poster) if url else {"ok": False, "error": "No Slack webhook URL set."}
    return {"ok": False, "error": f"{CATALOG[name]['title']} has no test here yet."}
