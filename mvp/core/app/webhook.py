"""Webhook source: any tool that can POST JSON (a WAF, an IDS, a SIEM, a cloud alert) becomes a
collector. `POST /webhook/<name>` maps each JSON object onto the `POST /events` contract
(CONTRACT.md) and ingests it like any other event.

How fields are found, per contract field: the source's own map first (CACTAI_WEBHOOK_MAPS), then
the common key names below. A map value is a dotted path ("data.srcip"), a list of paths (first one
present wins) or a fixed value starting with "=" ("=os"):

    CACTAI_WEBHOOK_MAPS='{"wazuh": {"src_ip": "data.srcip", "raw": "full_log", "layer": "=os",
                                    "host": "agent.name", "timestamp": "timestamp"}}'

CACTAI_WEBHOOK_MAPS may also be the path of a JSON file holding the same object.

The sender writes everything here, so nothing is trusted: the source is always "webhook_<name>"
(it cannot pose as a heartbeat, tripwire or integrity check), events never carry a line chain,
`raw` is capped, and the event id is a hash of the object so a re-delivery is ignored.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

MAX_ITEMS = 500
MAX_RAW = 8000
LAYERS = ("web", "db", "os", "network", "cloud")
NAME = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
LIST_KEYS = ("events", "alerts", "records", "items", "logs", "data")

# Common key names used by log shippers and security tools, tried in order.
GUESS: dict[str, tuple[str, ...]] = {
    "event_id": ("event_id", "id", "_id", "uuid", "alert_id", "eventId"),
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "date", "datetime", "created_at", "eventTime"),
    "host": ("host", "hostname", "host.name", "agent.name", "server", "device", "computer", "beat.hostname"),
    "src_ip": ("src_ip", "source_ip", "srcip", "client_ip", "clientip", "remote_addr", "remote_ip", "ip",
               "source.ip", "client.ip", "data.srcip", "sourceIPAddress", "attacker_ip"),
    "user": ("user", "username", "user_name", "account", "login", "user.name", "actor.login", "data.dstuser",
             "userIdentity.userName"),
    "raw": ("raw", "message", "msg", "log", "full_log", "description", "summary", "text", "event.original"),
    "layer": ("layer",),
    "asset_criticality": ("asset_criticality", "criticality"),
}


class WebhookError(ValueError):
    pass


def load_maps(value: str | None = None) -> dict[str, dict[str, Any]]:
    """CACTAI_WEBHOOK_MAPS: inline JSON, or the path of a JSON file. Bad input means no maps."""
    value = (os.getenv("CACTAI_WEBHOOK_MAPS", "") if value is None else value).strip()
    if not value:
        return {}
    try:
        text = value if value.startswith("{") else Path(value).read_text(encoding="utf-8")
        maps = json.loads(text)
    except (OSError, ValueError):
        return {}
    return {str(k): v for k, v in maps.items() if isinstance(v, dict)} if isinstance(maps, dict) else {}


def lookup(obj: Any, path: str) -> Any:
    """obj["a"]["b"] for "a.b"; a key that itself contains dots ("host.name") is tried whole first."""
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _pick(obj: dict[str, Any], spec: Any) -> Any:
    paths = spec if isinstance(spec, list) else [spec]
    for p in paths:
        if isinstance(p, str) and p.startswith("="):
            return p[1:]
        if isinstance(p, str) and (v := lookup(obj, p)) not in (None, ""):
            return v
    return None


def _text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    s = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)
    return s[:limit]


def items_of(payload: Any) -> list[dict[str, Any]]:
    """The JSON objects in a webhook body: the object itself, a list of them, or a list under a common key."""
    if isinstance(payload, dict):
        for key in LIST_KEYS:
            if isinstance(payload.get(key), list) and payload[key] and all(isinstance(x, dict) for x in payload[key]):
                return payload[key]
        return [payload]
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    raise WebhookError("the body must be a JSON object or a list of objects")


def to_event(obj: dict[str, Any], name: str, mapping: dict[str, Any] | None = None,
             layer: str | None = None, host: str | None = None) -> dict[str, Any]:
    """One JSON object -> one contract Event."""
    mapping = mapping or {}

    def field(key: str) -> Any:
        v = _pick(obj, mapping[key]) if key in mapping else None
        return v if v not in (None, "") else _pick(obj, list(GUESS.get(key, ())))

    body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    raw = _text(field("raw"), MAX_RAW) or body[:MAX_RAW]
    lay = str(field("layer") or layer or "web").lower()
    try:
        crit = min(3.0, max(0.5, float(field("asset_criticality") or 1.0)))
    except (TypeError, ValueError):
        crit = 1.0
    given = _text(field("event_id"), 80)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:20]
    return {
        "event_id": f"wh-{name}-{given or digest}",
        "timestamp": _text(field("timestamp"), 64),
        "host": _text(field("host") or host, 120) or f"webhook-{name}",
        "layer": lay if lay in LAYERS else "web",
        "source": f"webhook_{name}",
        "src_ip": _text(field("src_ip"), 64),
        "user": _text(field("user"), 120),
        "raw": raw,
        "asset_criticality": crit,
    }


def to_events(payload: Any, name: str, maps: dict[str, dict[str, Any]] | None = None,
              layer: str | None = None, host: str | None = None) -> list[dict[str, Any]]:
    if not NAME.match(name or ""):
        raise WebhookError("the webhook name may use letters, digits, '-' and '_' (at most 40)")
    items = items_of(payload)
    if len(items) > MAX_ITEMS:
        raise WebhookError(f"at most {MAX_ITEMS} objects per request")
    mapping = (maps or {}).get(name)
    return [to_event(obj, name, mapping, layer, host) for obj in items]
