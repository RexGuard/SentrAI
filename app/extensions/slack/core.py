"""Slack extension, core part: whether the webhook is set, and the Test button.

The alerts themselves are posted by the notifier (notifier.py next to this file): a copy of every
alert, read-only, with a link to the report but no buttons. Decisions stay in Telegram and the dashboard.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from app.extensions import Context, Extension, NotSetUp

# poster(url, body bytes, headers) -> HTTP status; raises on network errors.
Poster = Callable[[str, bytes, dict[str, str]], int]

TEST_TEXT = ":shield: SentrAI test message: alerts will arrive in this channel."


def _httpx_poster(timeout_s: float = 5.0) -> Poster:
    import httpx

    def post(url: str, body: bytes, headers: dict[str, str]) -> int:
        return httpx.post(url, content=body, headers=headers, timeout=timeout_s, follow_redirects=False).status_code

    return post


def slack_test(url: str, poster: Poster | None = None) -> dict[str, Any]:
    """Posts one test line to the webhook."""
    if not url.lower().startswith("https://"):
        return {"ok": False, "error": "the Slack webhook URL must start with https://"}
    body = json.dumps({"text": TEST_TEXT}).encode()
    try:
        status = (poster or _httpx_poster())(url, body, {"Content-Type": "application/json"})
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
    if not 200 <= status < 300:
        return {"ok": False, "error": f"Slack answered HTTP {status}"}
    return {"ok": True, "detail": "Test message posted. Check the channel."}


class Slack(Extension):
    def __init__(self, url: str, poster: Poster | None = None) -> None:
        self.url = url
        self.poster = poster

    def status(self) -> dict[str, Any]:
        if not self.url.lower().startswith("https://"):
            return {"configured": False, "testable": False, "detail": "The webhook URL must start with https://."}
        return {"configured": True, "testable": True, "detail": "The notifier posts a copy of each alert there."}

    def test(self) -> dict[str, Any]:
        return slack_test(self.url, self.poster)


def setup(ctx: Context, poster: Poster | None = None) -> Extension:
    url = ctx.setting("SLACK_WEBHOOK_URL")
    if not url:
        return NotSetUp("Create an incoming webhook in Slack and paste its URL.")
    return Slack(url, poster)
