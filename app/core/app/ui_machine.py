"""What the web dashboard's single-machine page needs beyond /ui/machines: who is signed in and the known
administrators (Signed in tab), what listens on it (Services tab) and its package check (Packages tab).

Same rules as the Streamlit console (sentrai_ui/shaping.py: session_rows, admin_activity_rows, admin_entries,
service_rows, latest_dep_scan, undoable_updates, dep_line) in plain Python. Times stay ISO strings; the page
shows them in the viewer's own time zone.
"""
from __future__ import annotations

from typing import Any, Iterable

from fastapi import FastAPI

from . import jobs
from .ui_approvals import category_label

TRUST_WORDS = {"trusted": "Known administrator", "unknown": "Not known as an administrator", "suspect": "Suspect"}
VIA_WORDS = {"ssh": "SSH", "windows": "Windows", "console": "console", "who": "terminal", "logind": "terminal"}
ADMIN_KINDS = {"address": "Address or network", "key": "SSH key fingerprint", "account": "Account"}


def short_key(fingerprint: Any) -> str:
    text = str(fingerprint or "")
    return text if len(text) <= 20 else text[:19] + "…"


def signin_how(via: Any, method: Any = None, key: Any = None, address: Any = None) -> str:
    via, method = str(via or ""), str(method or "")
    if via == "ssh":
        if key or method == "publickey":
            return "SSH key"
        return "SSH password" if method in ("", "password", "keyboard-interactive") else f"SSH ({method})"
    if via == "windows":
        return "remote desktop" if method == "remote_desktop" else "Windows sign-in"
    if via in ("console", "who", "logind"):
        return "terminal session" if address else "console"
    return "no sign-in seen"


def session_rows(sessions: Iterable[dict] | None) -> list[dict[str, Any]]:
    rows = []
    for s in sessions or []:
        if not isinstance(s, dict):
            continue
        how = signin_how(s.get("via"), s.get("method"), s.get("key"), s.get("address"))
        if s.get("key"):
            how += f" {short_key(s['key'])}"
        rows.append({"user": s.get("user") or "-", "how": how, "from": s.get("address") or s.get("tty") or "-",
                     "trust": str(s.get("trust") or "unknown"),
                     "trust_words": TRUST_WORDS.get(str(s.get("trust") or ""), "Unknown"),
                     "since": s.get("since"), "preexisting": bool(s.get("preexisting")),
                     "actions": int(s.get("actions") or 0), "why": s.get("why") or ""})
    return rows


def activity_rows(activity: Iterable[dict] | None) -> list[dict[str, Any]]:
    rows = []
    for a in activity or []:
        if not isinstance(a, dict):
            continue
        how = VIA_WORDS.get(str(a.get("via") or ""), str(a.get("via") or "-"))
        rows.append({"at": a.get("at"), "user": a.get("user") or "-",
                     "how": how + (f" from {a['address']}" if a.get("address") else ""), "what": a.get("what") or "-",
                     "would_have_been": category_label(a.get("flagged_as")) if a.get("flagged_as") else "",
                     "why": a.get("reason") or ""})
    return rows


def how_known(entry: dict) -> dict[str, Any]:
    """How SentrAI came to know an administrator: {how, by, at} for the page to put in words."""
    return {"how": str(entry.get("how") or ""), "by": str(entry.get("by") or ""), "at": entry.get("at"),
            "last_seen": entry.get("last_seen")}


def admin_entries(data: dict | None, host: str | None = None) -> list[dict[str, Any]]:
    """The known administrators as rows: kind, value, the machine an account is for ("*" every machine),
    headline, how it is known, and whether Forget applies (never to a setting)."""
    data = data if isinstance(data, dict) else {}
    out: list[dict[str, Any]] = []
    for a in data.get("accounts") or []:
        if not isinstance(a, dict) or not a.get("account") or (host and a.get("host") not in (None, "*", host)):
            continue
        where = "every machine" if a.get("host") in (None, "*") else str(a["host"])
        out.append({"kind": "account", "value": str(a["account"]), "host": str(a.get("host") or "*"),
                    "headline": f"{a['account']} on {where}", "known": how_known(a), "note": "",
                    "forget": a.get("how") != "setting"})
    for x in data.get("addresses") or []:
        if not isinstance(x, dict) or not x.get("address"):
            continue
        out.append({"kind": "address", "value": str(x["address"]), "host": None,
                    "headline": str(x["address"]) + (f" · {x['label']}" if x.get("label") else ""),
                    "known": how_known(x), "note": "", "forget": x.get("how") != "setting"})
    for s in data.get("sign_ins") or []:
        if not isinstance(s, dict) or not s.get("address"):
            continue
        out.append({"kind": "address", "value": str(s["address"]), "host": None, "headline": str(s["address"]),
                    "known": {"how": "sign_in", "by": str(s.get("email") or "an administrator"),
                              "at": s.get("until"), "last_seen": None},
                    "note": f"vouched for by the dashboard sign-in of {s.get('email') or 'an administrator'} "
                            f"({s.get('role') or 'Owner'})", "forget": True})
    for k in data.get("keys") or []:
        if not isinstance(k, dict) or not k.get("fingerprint"):
            continue
        users = ", ".join(str(u) for u in k.get("users") or [] if u)
        note = " · ".join(p for p in (str(k["type"]) if k.get("type") else "", f"used by {users}" if users else "") if p)
        out.append({"kind": "key", "value": str(k["fingerprint"]), "host": None,
                    "headline": str(k["fingerprint"]) + (f" · {k['label']}" if k.get("label") else ""),
                    "known": how_known(k), "note": note, "forget": k.get("how") != "setting"})
    return out


def service_rows(services: Iterable[dict] | None) -> list[dict[str, Any]]:
    rows = [{"name": x.get("name"), "port": x.get("port"), "proto": (x.get("proto") or "").upper() or "-",
             "process": x.get("process") or "-", "open_incidents": int(x.get("open_incidents") or 0)}
            for x in services or [] if isinstance(x, dict) and x.get("name")]
    rows.sort(key=lambda r: (-r["open_incidents"], r["port"] if r["port"] is not None else 1 << 17))
    return rows


def dep_line(f: dict) -> str:
    """One vulnerable package in a sentence: name, version, fix and the flaws behind it."""
    ids = [(v.get("aliases") or [v.get("id")])[0] for v in f.get("vulns") or [] if isinstance(v, dict)]
    more = int(f.get("vuln_count") or len(ids)) - len(ids[:3])
    fix = f"→ {f['fixed']}" if f.get("fixed") else "no fix yet"
    return (f"{f.get('name')} {f.get('version')} {fix} · {', '.join(i for i in ids[:3] if i)}"
            + (f" and {more} more" if more > 0 else ""))


def undoable_updates(mine: Iterable[dict]) -> list[dict[str, Any]]:
    """Package updates made on one machine that were not undone yet, newest first."""
    mine = [j for j in mine or [] if isinstance(j, dict)]
    undone = {(j.get("params") or {}).get("update") for j in mine
              if j.get("kind") == "dep_rollback" and j.get("status") in ("queued", "running", "done")}
    return [j["result"] for j in mine if j.get("kind") == "dep_update" and j.get("status") == "done"
            and (j.get("result") or {}).get("id") and j["result"]["id"] not in undone]


def packages(mine: list[dict]) -> dict[str, Any]:
    scan = jobs.latest_deps(mine)
    result = dict((scan or {}).get("result") or {}) if scan else None
    if result is not None:
        result["findings"] = [{**f, "line": dep_line(f)} for f in result.get("findings") or [] if isinstance(f, dict)]
    busy = next((j for j in mine if j.get("kind") in ("dep_scan", "dep_update", "dep_rollback")
                 and j.get("status") in ("queued", "running")), None)
    return {"latest": result, "updates": undoable_updates(mine),
            "busy": {"kind": busy["kind"], "status": busy["status"]} if busy else None}


def install(app: FastAPI, core: Any, machine_jobs: Any) -> None:
    @app.get("/ui/machines/{host}/details")
    def get_machine_details(host: str) -> dict[str, Any]:
        """The Signed in, Services and Packages tabs of one machine."""
        m = next((x for x in core.machines() if isinstance(x, dict) and x.get("host") == host), None) or {}
        data = core.admins_public(host) or {}
        return {
            "host": host,
            "services": service_rows(m.get("services")), "services_at": m.get("services_at"),
            "admins": {"on": data.get("on") is not False, "sessions": session_rows(data.get("sessions")),
                       "suspect": [s for s in data.get("suspect") or [] if isinstance(s, dict) and s.get("address")],
                       "activity": activity_rows(data.get("activity")), "entries": admin_entries(data, host)},
            "packages": packages(machine_jobs.list(host)),
            "admin_kinds": ADMIN_KINDS,
        }
