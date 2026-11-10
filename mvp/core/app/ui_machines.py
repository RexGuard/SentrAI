"""What the web dashboard's Machines page needs: the list (worst first), the joined agents and a join code.

Same rules as the Streamlit console (sentrai_ui/shaping.py: panel_machines, machine, join_commands) in plain
Python. On a central panel (SENTRAI_RISK_SCOPE=host) every machine the core scores is listed, plus joined agents
that have sent nothing yet; otherwise it is this computer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request

from . import fleet
from .saguaro import AGENT_OWNER
from .ui_approvals import parse_ts, span_label

AGENT_STALE_S = 60.0  # an agent that has not called in for this long shows as offline
BAND_WORD = {"green": "Calm", "amber": "Elevated", "red": "High", "critical": "Critical"}


def band_for(index: Any) -> str:
    if index is None:
        return "unknown"
    v = max(0, min(100, round(float(index))))
    return "green" if v < 30 else "amber" if v < 60 else "red" if v < 80 else "critical"


def seen_ago(ts: Any, now: datetime) -> str:
    t = parse_ts(ts)
    if t is None:
        return "never"
    if t.tzinfo is None:
        t = t.astimezone()
    secs = (now - t).total_seconds()
    if secs < 10:
        return "just now"
    return f"{int(secs)} s ago" if secs < 60 else f"{span_label(secs)} ago"


def hardware_line(hw: Any) -> dict[str, float | None]:
    hw = hw if isinstance(hw, dict) else {}
    disks = [d.get("percent") for d in hw.get("disks") or [] if isinstance(d, dict) and d.get("percent") is not None]
    return {"cpu": (hw.get("cpu") or {}).get("percent"), "memory": (hw.get("memory") or {}).get("percent"),
            "disk": max(disks) if disks else None}


def owner_row(o: dict | None, contacts: dict[str, str]) -> dict | None:
    """Who answers for a machine, as the list shows it: {"kind", "name", "contact", "backup", "backup_name"}."""
    if not o:
        return None
    if o.get("kind") == "agent":
        return {"kind": "agent", "name": AGENT_OWNER, "contact": "", "backup": o.get("backup") or "",
                "backup_name": contacts.get(o.get("backup") or "", "")}
    cid = str(o.get("contact") or "")
    return {"kind": "person", "name": contacts.get(cid, cid), "contact": cid, "backup": "", "backup_name": "",
            **({} if cid in contacts else {"missing": True})}


def blocking_row(agent: Any, has_agent: bool) -> dict[str, Any] | None:
    """Whether blocks on this machine really change its firewall, as the Machines page shows it.

    None for a machine with no agent (the panel itself, or one only named in logs). "unknown" for an agent too old
    to say (update it), "dry_run" when it only logs the commands, "on" when it really blocks."""
    if not has_agent:
        return None
    if not isinstance(agent, dict):
        return {"state": "unknown", "word": "Not known", "backend": None, "version": None,
                "detail": "This machine's agent is too old to say whether it really blocks. Update it."}
    on = bool(agent.get("enforce"))
    return {"state": "on" if on else "dry_run", "word": "Blocking" if on else "Not blocking yet",
            "backend": agent.get("backend"), "version": agent.get("version"),
            "detail": ("Blocks really change this machine's firewall." if on else
                       "Dry run: SentrAI decides blocks for this machine but its agent only writes them down. "
                       "Turn real blocking on once its log looks right.")}


def build(found: list[dict], agents: list[dict], risk: dict, panel: bool, name: str, now: datetime,
          names: dict[str, str] | None = None, owners: dict[str, dict] | None = None,
          contacts: dict[str, str] | None = None) -> list[dict]:
    """The machine list, worst first. `names` are the names people gave machines (Rename); the host stays the id.
    `owners` (fleet.Fleet.owners) say who answers for each machine; `contacts` are Routing's {id: name}."""
    names, owners, contacts = names or {}, owners or {}, contacts or {}
    threshold = float(risk.get("threshold") or 80)
    if not panel:
        idx = risk.get("risk_index")
        return [{"name": name, "host": "", "place": "Local", "online": True, "waiting": False,
                 "index": None if idx is None else max(0.0, min(100.0, float(idx))),
                 "band": risk.get("band") or band_for(idx), "threshold": threshold,
                 "monitor_only": bool(risk.get("monitor_only")), "open": 0, "contained": 0, "blocked": 0,
                 "last_seen": "", "services": [], "hardware": hardware_line(None), "sessions": None, "owner": None,
                 "blocking": None}]
    live = {str(a.get("host")): a for a in agents if isinstance(a, dict) and not a.get("revoked_at")}
    rows, seen = [], set()
    for m in found:
        if not isinstance(m, dict) or not m.get("host"):
            continue
        host = str(m["host"])
        seen.add(host)
        agent = live.get(host)
        last = parse_ts((agent or {}).get("last_seen") or m.get("last_seen"))
        if last is not None and last.tzinfo is None:
            last = last.astimezone(timezone.utc)
        stale = bool(agent) and (last is None or (now - last).total_seconds() > AGENT_STALE_S)
        idx = m.get("risk_index")
        online = not (m.get("silent") or stale)
        rows.append({
            "name": names.get(host, host), "host": host, "place": "Agent" if agent else "Seen in logs", "online": online, "waiting": False,
            "index": None if idx is None else max(0.0, min(100.0, float(idx))),
            "band": m.get("band") or band_for(idx), "threshold": threshold,
            "monitor_only": bool(risk.get("monitor_only")), "open": int(m.get("open_incidents") or 0),
            "contained": int(m.get("contained_incidents") or 0), "blocked": int(m.get("blocked") or 0),
            "last_seen": seen_ago(last, now),
            "services": [str(x.get("name")) + (f" :{x['port']}" if x.get("port") else "")
                         for x in m.get("services") or [] if isinstance(x, dict) and x.get("name")][:4],
            "hardware": hardware_line(m.get("hardware")) if online else hardware_line(None),
            "sessions": int(m["sessions"]) if isinstance(m.get("sessions"), (int, float)) else None,
            "owner": owner_row(owners.get(host), contacts), "blocking": blocking_row(m.get("agent"), bool(agent))})
    for host, agent in live.items():
        if host not in seen:
            rows.append({"name": names.get(host, host), "host": host, "place": "Agent", "online": False, "waiting": True, "index": None,
                         "band": "unknown", "threshold": threshold, "monitor_only": False, "open": 0, "contained": 0,
                         "blocked": 0, "last_seen": "never", "services": [], "hardware": hardware_line(None),
                         "sessions": None, "owner": owner_row(owners.get(host), contacts), "blocking": None})
    rows.sort(key=lambda r: (-(r["index"] or 0), r["name"]))
    return rows


def join_commands(panel_url: str, code: str, name: str | None, pin: str | None) -> dict[str, str]:
    url = panel_url.rstrip("/")
    return {
        "linux": f"sudo ./mvp/deploy/install-agent.sh --panel {url} --code {code}" + (f" --name {name}" if name else "")
                 + (f" --pin {pin}" if pin else ""),
        "windows": (f"powershell -ExecutionPolicy Bypass -File .\\mvp\\deploy\\install-agent.ps1 -Panel {url} -Code {code}"
                    + (f" -Name {name}" if name else "") + (f" -Pin {pin}" if pin else "")),
    }


def agent_rows(agents: list[dict]) -> list[dict]:
    rows = []
    for a in agents:
        if not isinstance(a, dict):
            continue
        rows.append({"host": a.get("host"), "agent_id": a.get("agent_id"), "joined_at": a.get("joined_at"),
                     "invited_by": a.get("invited_by") or "", "last_seen": a.get("last_seen"),
                     "status": f"Revoked by {a.get('revoked_by') or '?'}" if a.get("revoked_at") else "Active"})
    rows.sort(key=lambda r: (r["status"] != "Active", str(r["host"])))
    return rows


def still_removed(removed: dict | None) -> bool:
    """A removed machine stays hidden, even while logs that name it keep arriving. Only joining again (a new
    code) or `sentrai machines restore HOST` brings it back: both clear its "removed" entry."""
    return bool(removed)


def install(app: FastAPI, core: Any, machines: fleet.Fleet, health: Any) -> Any:
    """Adds the endpoints; returns the machine list's builder (the readiness check reads it too)."""
    @app.get("/ui/machines")
    def get_machines_page() -> dict[str, Any]:
        risk = core.risk(history=0, host=None)
        panel = risk.get("risk_scope") == "host"
        now = datetime.now(timezone.utc)
        gone = machines.removed()
        found = [{**m, "hardware": health.latest(m["host"])} for m in core.machines()
                 if not still_removed(gone.get(m["host"]))] if panel else []
        agents = machines.agents()
        contacts = {c.id: c.name for c in core.router.contacts.values()}
        rows = build(found, agents, risk, panel, "This computer", now, machines.names(),  # not the core agent's name: people read it
                     machines.owners(), contacts)
        online = sum(1 for r in rows if r["online"])
        return {
            "panel": panel, "machines": rows, "joined": agent_rows(agents) if panel else [],
            "stats": {"machines": len(rows), "online": online, "offline": len(rows) - online,
                      "need_a_look": sum(1 for r in rows if r["open"] or r["band"] in ("red", "critical")),
                      "blocks": sum(r["blocked"] for r in rows),
                      "dry_run": sum(1 for r in rows if (r.get("blocking") or {}).get("state") == "dry_run")},
            "panel_info": fleet.panel_info(), "band_words": BAND_WORD,
            "contacts": [{"id": cid, "name": n} for cid, n in contacts.items()], "agent_name": AGENT_OWNER,
            "removed": [{"host": h, "at": v.get("at"), "by": v.get("by")} for h, v in sorted(gone.items())] if panel else [],
        }

    @app.post("/ui/machines/join-code")
    def post_join(request: Request, body: dict = Body(...)) -> dict[str, Any]:
        """A one-time join code with the commands to paste on the new machine."""
        account = getattr(request.state, "account", None)
        operator = (account or {}).get("email") or str(body.get("operator") or "operator")
        name = str(body.get("name") or "").strip() or None
        info = fleet.panel_info()
        url = str(body.get("panel_url") or info["panel_url"] or "").strip()
        if not url:
            raise HTTPException(400, "Say which address the new machine should use to reach this panel.")
        try:
            made = machines.join_code(operator, name)
        except fleet.FleetError as exc:
            raise HTTPException(400, str(exc)) from exc
        core.scribe.record(core.name, "join_code_created", {"operator": operator, "name": made["name"],
                                                            "expires_at": made["expires_at"]})
        pin = info["pin"] if url.startswith("https://") else None
        return {"code": made["code"], "expires_at": made["expires_at"], "https": url.startswith("https://"),
                "pin": pin, "commands": join_commands(url, made["code"], made.get("name"), pin)}

    return get_machines_page
