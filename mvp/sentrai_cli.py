"""`sentrai`: the SentrAI team's command line for everything the business owner's web panel leaves out.

The web panel is for the business owner. Setup, fine-tuning and day-to-day control by the SentrAI team happen
here. Every command is a call to the core's API with the API token (the same one the collector and notifier
use), so the core checks it, applies it and writes it to the audit log exactly as it does for the panel.
The one exception is `team`: the core keeps people management to signed-in people, so on the panel machine
this command changes the accounts file directly, as an Owner (the same file `sentrai-admin` uses).

On the panel (installed as /usr/local/bin/sentrai, runs as the service account):
    sudo sentrai status
    sudo sentrai settings show [SECTION] [--all]       sudo sentrai settings set NAME=VALUE ...
    sudo sentrai settings preset [strict|moderate|minimum]
    sudo sentrai tuning                                   sudo sentrai limits show | set NAME=VALUE ...
    sudo sentrai routing export > routing.json            sudo sentrai routing import - < routing.json
    sudo sentrai integrations list | on NAME | off NAME | test NAME | reload
    sudo sentrai machines list | rename HOST NAME | delete HOST | join-code [--name N] | agents | revoke AGENT_ID
    sudo sentrai jobs list [--host H] | scan HOST | backup HOST | deps HOST | packages HOST
                      | update HOST FINDING | undo HOST UPDATE | cancel JOB
    sudo sentrai deps show | scan
    sudo sentrai backups list | now | copies | key | unlock HOST BACKUP_ID
    sudo sentrai incidents list [--all] | show ID | approve ID... | reject ID... --why W | rollback ID... | keep ID...
                           | resolve ID --note N
    sudo sentrai protection on|off [--reason R]
    sudo sentrai team list | invite EMAIL [--role admin] | role EMAIL ROLE | remove EMAIL | reset EMAIL | withdraw EMAIL
    sudo sentrai api GET|POST PATH [JSON]                 any other core endpoint (docs/api/)
    sudo sentrai mcp                                      lets your own Claude keep or undo blocks (docs/claude.md)

From another computer: SENTRAI_CORE_URL=https://panel:8443 SENTRAI_API_TOKEN=... python sentrai_cli.py status
(`team` only works on the panel machine itself). Add --json to any command for the raw answer.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sentrai_config as cfg  # noqa: E402

DEFAULT_CORE = "http://127.0.0.1:8000"
PRESET_ENV = "SENTRAI_PRESET"
PRESET_NAMES = {"minimum": "balanced"}  # the label people see -> the saved key (Balanced was renamed Minimum)
JOB_KINDS = {"scan": "threat_scan", "backup": "backup", "deps": "dep_scan"}
BULK = {"approve": "approve", "reject": "reject", "rollback": "rollback", "keep": "keep"}


class CliError(Exception):
    """Something the person asked for that did not work; the message says why."""


Call = Callable[[str, str, Any], Any]


def http_call(url: str, token: str, timeout: float = 30.0) -> Call:
    """A function that sends one request to the core and returns its JSON (or text) answer."""
    def call(method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url.rstrip("/") + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - the operator's own core
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(raw).get("detail", raw)
            except (ValueError, AttributeError):
                detail = raw
            raise CliError(f"{e.code}: {detail}") from None
        except urllib.error.URLError as e:
            raise CliError(f"cannot reach the core at {url} ({e.reason}). Is SentrAI running? "
                           "(sudo systemctl status sentrai-core)") from None
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return call


def operator_name() -> str:
    who = os.environ.get("SENTRAI_OPERATOR") or os.environ.get("SUDO_USER") or getpass.getuser()
    return f"cli:{who}"


# ------------------------------------------------------------------ output helpers

def table(rows: list[list[Any]], head: list[str]) -> str:
    cells = [[str(c) for c in head]] + [["" if c is None else str(c) for c in r] for r in rows]
    width = [max(len(r[i]) for r in cells) for i in range(len(head))]
    lines = ["  ".join(c.ljust(width[i]) for i, c in enumerate(r)).rstrip() for r in cells]
    lines.insert(1, "  ".join("-" * w for w in width))
    return "\n".join(lines)


def pairs(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        name, eq, value = item.partition("=")
        if not eq or not name.strip():
            raise CliError(f"write NAME=VALUE, not {item!r}")
        out[name.strip()] = value
    return out


# ------------------------------------------------------------------ commands

def cmd_status(call: Call, a: argparse.Namespace) -> Any:
    prot = call("GET", "/protection")
    risks = call("GET", "/ui/risks")
    machines = call("GET", "/ui/machines")
    out = {"protection": prot, "risks": risks, "machines": machines.get("stats", {})}
    if a.json:
        return out
    s = machines.get("stats", {})
    levels = ", ".join(f"{lv['severity']} {lv['count']}" for lv in risks.get("levels", []))
    return "\n".join([
        f"Protection: {prot.get('protection')}"
        f"   Active blocks: {len(prot.get('active_actions') or [])}",
        f"Machines:   {s.get('machines', 0)} ({s.get('online', 0)} online, {s.get('offline', 0)} offline,"
        f" {s.get('need_a_look', 0)} need a look)",
        f"Waiting:    {levels}",
        risks.get("headline", ""),
    ])


def _settings(call: Call) -> dict:
    return call("GET", "/ui/settings")


def _fields(data: dict) -> dict[str, dict]:
    return {f["env"]: f for s in data["sections"] for f in s["fields"]}


def cmd_settings(call: Call, a: argparse.Namespace) -> Any:
    data = _settings(call)
    if a.action == "show":
        if a.json:
            return data
        lines = []
        for s in data["sections"]:
            if a.section and a.section.lower() not in (s["key"].lower(), s.get("name", "").lower(), s["title"].lower()):
                continue
            lines.append(f"\n{s['title']}" + (f"  ({s['about']})" if a.all and s.get("about") else ""))
            for f in s["fields"]:
                if not a.all and not f["is_set"] and not f["value"]:
                    continue
                value = ("(set)" if f["is_set"] else "(empty)") if f["secret"] or f["generated"] else f["value"]
                mark = " [preset]" if f["preset_field"] else ""
                lines.append(f"  {f['env']:<30} {value}{mark}   # {f['prompt']}")
        return "\n".join(lines).strip() or f"no section named {a.section!r}"
    if a.action == "get":
        f = _fields(data).get(a.name)
        if not f:
            raise CliError(f"{a.name} is not a setting (sentrai settings show --all lists them)")
        return f if a.json else ("(secret: set)" if f["is_set"] else "(secret: empty)") if f["secret"] else f["value"]
    if a.action == "set":
        values = pairs(a.values)
        known = _fields(data)
        unknown = [k for k in values if k not in known]
        if unknown:
            raise CliError(f"not settings: {', '.join(unknown)} (sentrai settings show --all lists them)")
        if PRESET_ENV in values:
            values = {**preset_values(data, values[PRESET_ENV]), **values}
        out = call("POST", "/ui/settings", {"values": values})
        return out if a.json else out.get("message", out)
    # preset
    presets = data.get("presets", {})
    current = _fields(data).get(PRESET_ENV, {}).get("value", "")
    if not a.name:
        if a.json:
            return {"current": current, "presets": presets}
        names = list(presets)
        envs = list(presets[names[0]]["values"]) if names else []
        label = presets.get(current, {}).get("label") or ("Advanced (values set by hand)" if current else "?")
        rows = [[e] + [presets[n]["values"].get(e, "") for n in names] for e in envs]
        return f"Current preset: {label}\n\n" + table(rows, ["Setting"] + [presets[n]["label"] for n in names]) + \
            "\n\n" + "\n".join(f"{presets[n]['label']}: {presets[n]['about']}" for n in names)
    values = {PRESET_ENV: preset_key(data, a.name), **preset_values(data, a.name)}
    out = call("POST", "/ui/settings", {"values": values})
    return out if a.json else out.get("message", out)


def preset_key(data: dict, name: str) -> str:
    want = name.strip().lower()
    want = PRESET_NAMES.get(want, want)
    for key, p in data.get("presets", {}).items():
        if want in (key, p["label"].lower()):
            return key
    if want == data.get("advanced"):
        return want
    raise CliError(f"no preset {name!r}; pick one of: " + ", ".join(p["label"] for p in data.get("presets", {}).values()))


def preset_values(data: dict, name: str) -> dict[str, str]:
    key = preset_key(data, name)
    return dict(data.get("presets", {}).get(key, {}).get("values", {}))


def cmd_tuning(call: Call, a: argparse.Namespace) -> Any:
    t = call("GET", "/ui/tuning")
    if a.json:
        return t
    learn = t.get("learning") or {}
    head = (f"Last {t.get('days')} days: {t.get('incidents')} incidents, {t.get('alerts')} alerts "
            f"({t.get('alerts_per_day')} a day), {t.get('false_alarms')} marked as false alarms.")
    if learn.get("on"):
        head += f" Still learning: day {learn.get('day')} of {learn.get('of')}, more alerts are expected."
    s = t.get("settings") or {}
    head += f"\nBusy-server waves: {'on' if s.get('busy_server') else 'off'}   Trusted networks: " \
            f"{', '.join(s.get('trusted') or []) or 'none'}"
    rows = [[r.get("key"), r.get("what"), r.get("incidents"), r.get("false_alarms"), r.get("suggestion", {}).get("text")]
            for r in t.get("rows", [])]
    tip = ("\n\nTo act on a tip: sentrai settings set TRUSTED_IPS=... or BUSY_SERVER=1 "
           "(sentrai settings show --all lists the names).")
    return head + "\n\n" + (table(rows, ["Source", "What", "Incidents", "False", "Suggestion"]) if rows
                            else "Nothing noisy this week.") + (tip if rows else "")


def cmd_limits(call: Call, a: argparse.Namespace) -> Any:
    cur = call("GET", "/ui/limits")
    if a.action == "show":
        if a.json:
            return cur
        acts = ", ".join(f"{k} ({w})" for k, w in cur.get("actions", []))
        return "\n".join(f"  {k:<28} {v}" for k, v in cur["settings"].items()) + f"\n\nActions it knows: {acts}"
    changed = pairs(a.values)
    unknown = [k for k in changed if k not in cur["settings"]]
    if unknown:
        raise CliError(f"not a limit: {', '.join(unknown)}; limits are {', '.join(cur['settings'])}")
    out = call("POST", "/ui/limits", {"settings": {**cur["settings"], **changed}, "operator": operator_name()})
    return out if a.json else (out.get("message") or out.get("result") or "Saved.")


def cmd_routing(call: Call, a: argparse.Namespace) -> Any:
    if a.action == "export":
        r = call("GET", "/routing")
        r = {k: r[k] for k in ("contacts", "rules", "follow_up", "layout") if k in r}
        text = json.dumps(r, indent=2)
        if a.file:
            Path(a.file).write_text(text + "\n", encoding="utf-8")
            return f"Saved the routing to {a.file}. Edit it, then: sentrai routing import {a.file}"
        return text
    try:
        data = json.loads(sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise CliError(f"cannot read {a.file}: {e}") from None
    out = call("POST", "/routing", {"operator": operator_name(), "routing": data,
                                    "summary": a.summary or "routing imported from the command line"})
    return out if a.json else "Saved. New alerts follow the new routing."


def cmd_integrations(call: Call, a: argparse.Namespace) -> Any:
    if a.action == "list":
        rows = call("GET", "/extensions")
        if a.json:
            return rows
        return table([[r["name"], r["title"], "on" if r.get("running") else ("added" if r.get("added") else "off"),
                       "built-in" if r.get("feature") or r.get("built_in") else "", r.get("detail") or ""] for r in rows],
                     ["Name", "Title", "State", "", "Detail"])
    if a.action == "reload":
        out = call("POST", "/extensions/reload", {})
        return out if a.json else "Reloaded."
    if not a.name:
        raise CliError("which integration? (sentrai integrations list)")
    if a.action == "test":
        out = call("POST", f"/extensions/{a.name}/test", {})
    else:
        out = call("POST", f"/extensions/{a.name}/{'add' if a.action == 'on' else 'remove'}", {"operator": operator_name()})
    if a.json:
        return out
    if isinstance(out, dict):
        return out.get("message") or out.get("detail") or json.dumps(out)
    return str(out)


def cmd_machines(call: Call, a: argparse.Namespace) -> Any:
    op = operator_name()
    if a.action == "list":
        m = call("GET", "/ui/machines")
        if a.json:
            return m
        words = m.get("band_words", {})
        rows = [[r.get("name"), r.get("host"), "online" if r.get("online") else ("waiting" if r.get("waiting") else "offline"),
                 "off" if r.get("monitor_only") else "on", f"{r.get('index', 0):.0f} {words.get(r.get('band'), '')}",
                 r.get("open"), r.get("blocked"), r.get("last_seen") or ""] for r in m.get("machines", [])]
        return table(rows, ["Name", "Host", "State", "Protection", "Risk", "Open", "Blocks", "Last seen"])
    if a.action == "agents":
        rows = call("GET", "/fleet/agents")
        return rows if a.json else table([[r.get("agent_id"), r.get("host"), r.get("joined_at") or r.get("enrolled_at"),
                                           r.get("last_seen"), "revoked" if r.get("revoked_at") else "active"] for r in rows],
                                         ["Agent", "Host", "Joined", "Last seen", "Key"])
    if a.action == "rename":
        out = call("POST", f"/ui/machines/{a.host}/rename", {"name": a.name or "", "operator": op})
    elif a.action == "delete":
        out = call("POST", f"/ui/machines/{a.host}/delete", {"operator": op})
    elif a.action == "revoke":
        out = call("POST", f"/fleet/agents/{a.host}/revoke", {"operator": op})
        return out if a.json else f"Key revoked for {out.get('host')}."
    else:  # join-code
        out = call("POST", "/ui/machines/join-code", {"operator": op, "name": a.name or "", "panel_url": a.panel_url or ""})
        if a.json:
            return out
        lines = [f"Join code: {out.get('code')}  (works once, until {out.get('expires_at')})"]
        for k, v in (out.get("commands") or {}).items():
            lines += [f"\n{k}:", f"  {v}"]
        return "\n".join(lines)
    return out if a.json else out.get("message", out)


def cmd_jobs(call: Call, a: argparse.Namespace) -> Any:
    op = operator_name()
    if a.action == "list":
        rows = call("GET", "/fleet/jobs" + (f"?host={a.host}" if a.host else ""))
        return rows if a.json else table([[j.get("id"), j.get("host"), j.get("kind"), j.get("status"), j.get("requested_by"),
                                           j.get("created_at"), j.get("summary") or ""] for j in rows],
                                         ["Job", "Host", "Kind", "Status", "By", "Asked", "Result"])
    if a.action == "packages":
        done = next((j for j in call("GET", f"/fleet/jobs?host={a.host}")
                     if j.get("kind") == "dep_scan" and j.get("status") == "done"), None)
        if done is None:
            raise CliError(f"no finished package check on {a.host} yet: sentrai jobs deps {a.host}")
        return done if a.json else f"Package check {done['id']} from {done.get('finished_at')}\n" + deps_table(done.get("result") or {}) + \
            f"\n\nTo update one: sentrai jobs update {a.host} ID"
    if a.action == "cancel":
        out = call("POST", f"/fleet/jobs/{a.host}/cancel", {"operator": op})
        return out if a.json else f"{out.get('id')}: {out.get('status')}"
    body: dict[str, Any] = {"host": a.host, "operator": op}
    if a.action in JOB_KINDS:
        body["kind"] = JOB_KINDS[a.action]
    elif a.action == "update":
        body |= {"kind": "dep_update", "params": {"finding": a.ref}}
    else:  # undo
        body |= {"kind": "dep_rollback", "params": {"update": a.ref}}
    if a.action in ("update", "undo") and not a.ref:
        raise CliError("which one? update needs a finding id (sentrai jobs list), undo needs an update id (u-...)")
    out = call("POST", "/fleet/jobs", body)
    return out if a.json else f"Queued {out.get('id')} on {a.host}: the machine picks it up within about 15 s. " \
                              f"Check with: sentrai jobs list --host {a.host}"


def cmd_backups(call: Call, a: argparse.Namespace) -> Any:
    op = operator_name()
    if a.action == "now":
        out = call("POST", "/backups", {"operator": op})
        if a.json:
            return out
        if not out.get("ok"):
            raise CliError(out.get("error") or out.get("note") or "the backup failed")
        return f"Backup {out['id']}: {out.get('files')} files, {(out.get('bytes') or 0) / 1048576:.1f} MB"
    if a.action == "key":
        out = call("POST", "/backups/recovery-code", {"operator": op})
        return out if a.json else (
            "Recovery code for this panel's backups. Write it down and keep it away from this server:\n\n"
            f"    {out['code']}\n\nIf this panel is lost, take the newest copy from any machine "
            "(/var/lib/sentrai/agent/backups/copies/_panel/*.sbk) and unlock it with:\n"
            "    python -m app.sealed open COPY.sbk backup.tar.gz --code CODE     (run in mvp/core)")
    if a.action == "unlock":
        if not (a.host and a.ref):
            raise CliError("which copy? sentrai backups unlock HOST BACKUP_ID (sentrai backups copies lists them)")
        out = call("POST", "/backups/copies/unlock", {"owner": a.host, "id": a.ref, "operator": op})
        return out if a.json else f"Unlocked into {out['unlocked_to']}. {out['note']}"
    if a.action == "copies":
        out = call("GET", "/backups/copies")
        if a.json:
            return out
        rows = [[m["name"], c["id"], c.get("created"), f"{(c.get('bytes') or 0) / 1048576:.1f}",
                 ", ".join((["panel"] if c.get("on_panel") else []) + c.get("held_on", [])) or "-"]
                for m in out.get("machines", []) for c in m.get("copies", [])]
        head = f"Each backup is kept on {out.get('replicas')} other machines ({out.get('machines_available')} can keep copies)."
        if not out.get("recovery_code_shown"):
            head += "\nThe recovery code was never shown: sudo sentrai backups key"
        return head + "\n\n" + table(rows, ["Machine", "Backup", "Made", "MB", "Kept on"])
    out = call("GET", "/backups")
    return out if a.json else table(
        [[b["id"], b.get("created"), b.get("reason"), b.get("files"), f"{(b.get('bytes') or 0) / 1048576:.1f}",
          ", ".join(b.get("held_on") or []) or "-"] for b in out.get("backups", [])],
        ["Backup", "Made", "Why", "Files", "MB", "Also on"])


def cmd_deps(call: Call, a: argparse.Namespace) -> Any:
    out = call("POST", "/deps/scan", {"operator": operator_name()}) if a.action == "scan" else call("GET", "/deps")
    if a.json:
        return out
    return f"Checked: {out.get('scanned_at') or 'never (sentrai deps scan)'}\n" + deps_table(out)


def deps_table(result: dict) -> str:
    rows = [[f.get("id"), f.get("name"), f.get("version"), f.get("severity"), f.get("fixed") or "", f.get("path") or ""]
            for f in result.get("findings") or []]
    return table(rows, ["Id", "Package", "Version", "Severity", "Fixed in", "Where"]) if rows else "No known problems."


def cmd_incidents(call: Call, a: argparse.Namespace) -> Any:
    op = operator_name()
    if a.action == "list":
        rows = call("GET", "/incidents?fields=id,severity,category,host,src_ip,status,opened_at,acked_by")
        if not a.all:
            rows = [r for r in rows if r.get("status") not in ("resolved", "closed", "rejected")]
        return rows if a.json else table([[r.get("id"), r.get("severity"), r.get("category"), r.get("host"),
                                           r.get("src_ip") or "", r.get("status"), r.get("opened_at")] for r in rows],
                                         ["Id", "Severity", "Type", "Host", "Address", "Status", "Opened"])
    if not a.ids:
        raise CliError("which incident? (sentrai incidents list)")
    if a.action == "show":
        out = call("GET", f"/incidents/{a.ids[0]}")
        if a.json:
            return out
        lines = [f"{out['id']}  {out.get('severity')} {out.get('category')} on {out.get('host')}  [{out.get('status')}]",
                 out.get("explanation") or "", f"Suggested: {out.get('recommended_action') or '-'}", ""]
        lines += [f"  {t.get('ts')}  {t.get('text')}" for t in out.get("timeline", [])]
        return "\n".join(lines)
    if a.action == "resolve":
        if not a.note:
            raise CliError("say what was done: --note \"...\"")
        out = call("POST", f"/incidents/{a.ids[0]}/resolve", {"operator": op, "note": a.note})
        return out if a.json else f"{a.ids[0]} resolved."
    if a.action == "reject" and not a.why:
        raise CliError("a reason is needed to reject: --why \"...\"")
    out = call("POST", "/ui/approvals/bulk", {"verb": BULK[a.action], "ids": a.ids, "operator": op,
                                              "justification": a.why or ""})
    return out if a.json else out.get("message", out)


def cmd_feedback(call: Call, a: argparse.Namespace) -> Any:
    if a.action == "list":
        out = call("GET", "/ui/feedback" + ("?all=true" if a.all else ""))
        if a.json:
            return out
        rows = out.get("feedback", [])
        if not rows:
            return "No open messages." if not a.all else "No messages yet."
        blocks = [f"{r.get('id')}  {r.get('at')}  {r.get('name')} <{r.get('contact')}>{'  [done]' if r.get('done') else ''}\n"
                  + "\n".join("    " + line for line in str(r.get("message") or "").splitlines()) for r in rows]
        return "\n\n".join(blocks) + f"\n\n{len(rows)} message{'s' if len(rows) != 1 else ''}. Mark one handled: sentrai feedback done ID"
    if not a.ids:
        raise CliError("which message? (sentrai feedback list)")
    out = call("POST", "/ui/feedback/done", {"ids": a.ids, "done": a.action == "done"})
    return out if a.json else out.get("message", out)


def cmd_switch(path: str) -> Callable[[Call, argparse.Namespace], Any]:
    def run(call: Call, a: argparse.Namespace) -> Any:
        out = call("POST", path, {"on": a.state == "on", "operator": operator_name(), "reason": a.reason or ""})
        return out if a.json else (out.get("message") if isinstance(out, dict) and out.get("message") else f"{a.cmd} is {a.state}.")
    return run


def cmd_api(call: Call, a: argparse.Namespace) -> Any:
    body = None
    if a.body:
        try:
            body = json.loads(a.body)
        except ValueError as e:
            raise CliError(f"the body is not JSON: {e}") from None
    return call(a.method.upper(), a.path if a.path.startswith("/") else "/" + a.path, body)


# ------------------------------------------------------------------ team (local accounts file)

def cmd_mcp(call: Call, _a: argparse.Namespace) -> None:
    """Serve SentrAI's blocks to your own Claude over MCP on stdin/stdout (sentrai_mcp.py, docs/claude.md)."""
    import sentrai_mcp

    def tool_call(method: str, path: str, body: Any = None) -> Any:
        try:
            return call(method, path, body)
        except CliError as e:
            raise sentrai_mcp.ToolError(str(e)) from None

    sentrai_mcp.serve(tool_call, operator_name().replace("cli:", "claude:", 1))


def cmd_team(_call: Call, a: argparse.Namespace) -> Any:
    import sentrai_accounts as acc  # only here: it reads the accounts file, which only the panel machine has
    people = acc.people()
    if a.action == "list":
        if a.json:
            return {"people": people, "invites": acc.pending_invites()}
        out = table([[p["email"], p["name"], acc.ROLE_LABEL.get(p["role"], p["role"]),
                      "yes" if p["authenticator"] else "no", p.get("last_sign_in") or ""] for p in people],
                    ["Email", "Name", "Role", "Authenticator", "Last sign-in"])
        inv = acc.pending_invites()
        if inv:
            out += "\n\nInvites waiting:\n" + "\n".join(f"  {i['email']} as {acc.ROLE_LABEL.get(i['role'])}" for i in inv)
        return out
    owner = a.by or next((p["email"] for p in people if p["role"] == "owner"), "")
    if not owner:
        raise CliError("there is no Owner yet: run sudo sentrai-admin first")
    try:
        if a.action == "invite":
            code = acc.invite(owner, a.email, (a.role or "admin").lower())
            msg = f"Invite for {a.email} as {acc.ROLE_LABEL.get((a.role or 'admin').lower())}: open the web panel at " \
                  f"/?invite={code}  (works for {acc.INVITE_HOURS} h)"
            return {"code": code} if a.json else msg
        if a.action == "role":
            acc.set_role(owner, a.email, (a.role or "").lower())
            return f"{a.email} is now {acc.ROLE_LABEL.get((a.role or '').lower())}."
        if a.action == "remove":
            acc.remove(owner, a.email)
            return f"{a.email} can no longer sign in."
        if a.action == "reset":
            code = acc.reset(owner, a.email)
            return {"code": code} if a.json else f"Reset link for {a.email}: /?invite={code}"
        acc.withdraw_invite(owner, a.email)
        return "Invite withdrawn."
    except acc.AccountError as e:
        raise CliError(str(e)) from None


# ------------------------------------------------------------------ parser

def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print the core's raw answer")
    p = argparse.ArgumentParser(prog="sentrai", description="SentrAI team console: setup, tuning and control.",
                                parents=[common])
    p.add_argument("--url", default=None, help=f"core URL (default SENTRAI_CORE_URL or {DEFAULT_CORE})")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, fn: Callable, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_, parents=[common])
        sp.set_defaults(fn=fn)
        return sp

    add("status", cmd_status, "protection, machines and what waits for a person")
    s = add("settings", cmd_settings, "show or change any setting, including the ones the panel hides")
    s.add_argument("action", choices=["show", "get", "set", "preset"])
    s.add_argument("rest", nargs="*", help="show: SECTION · get: NAME · set: NAME=VALUE ... · preset: NAME")
    s.add_argument("--all", action="store_true", help="show empty settings and section notes too")
    add("tuning", cmd_tuning, "the noisiest alert sources this week and what would quiet them")
    lm = add("limits", cmd_limits, "safety limits on automatic actions")
    lm.add_argument("action", choices=["show", "set"])
    lm.add_argument("values", nargs="*", help="NAME=VALUE ...")
    r = add("routing", cmd_routing, "who gets which alert")
    r.add_argument("action", choices=["export", "import"])
    r.add_argument("file", nargs="?")
    r.add_argument("--summary", help="what changed, for the audit log")
    i = add("integrations", cmd_integrations, "Telegram, Slack, Cloudflare, AbuseIPDB, Jev")
    i.add_argument("action", choices=["list", "on", "off", "test", "reload"])
    i.add_argument("name", nargs="?")
    m = add("machines", cmd_machines, "joined computers")
    m.add_argument("action", choices=["list", "agents", "rename", "delete", "revoke", "join-code"])
    m.add_argument("host", nargs="?", help="host name (revoke: agent id)")
    m.add_argument("name", nargs="?", help="rename: the new name (blank goes back to the host name)")
    m.add_argument("--name", dest="name_opt", help="join-code: fix the new machine's name")
    m.add_argument("--panel-url", help="join-code: the address new machines use (default SENTRAI_PANEL_URL)")
    j = add("jobs", cmd_jobs, "ask a machine to scan, back up or update packages")
    j.add_argument("action", choices=["list", "scan", "backup", "deps", "packages", "update", "undo", "cancel"])
    j.add_argument("host", nargs="?", help="host name (cancel: job id)")
    j.add_argument("ref", nargs="?", help="update: finding id · undo: update id")
    j.add_argument("--host", dest="host_opt")
    d = add("deps", cmd_deps, "this panel machine's package check")
    d.add_argument("action", choices=["show", "scan"])
    bk = add("backups", cmd_backups, "this panel's backups and their copies on other machines")
    bk.add_argument("action", choices=["list", "now", "copies", "key", "unlock"])
    bk.add_argument("host", nargs="?", help="unlock: the machine whose copy to unlock")
    bk.add_argument("ref", nargs="?", help="unlock: the backup id (b-...)")
    n = add("incidents", cmd_incidents, "list, approve, reject, roll back, keep or resolve")
    n.add_argument("action", choices=["list", "show", "approve", "reject", "rollback", "keep", "resolve"])
    n.add_argument("ids", nargs="*")
    n.add_argument("--all", action="store_true", help="list: closed ones too")
    n.add_argument("--why", help="reject: the reason (also saved for the others)")
    n.add_argument("--note", help="resolve: what was done")
    fb = add("feedback", cmd_feedback, "messages sent with the panel's Contact Us form")
    fb.add_argument("action", choices=["list", "done", "open"])
    fb.add_argument("ids", nargs="*")
    fb.add_argument("--all", action="store_true", help="list: handled ones too")
    for name, path, what in (("protection", "/protection", "protection on, or watch only"),):
        sw = add(name, cmd_switch(path), what)
        sw.add_argument("state", choices=["on", "off"])
        sw.add_argument("--reason")
    add("mcp", cmd_mcp, "let your own Claude see, keep or undo blocks (MCP over stdin/stdout; docs/claude.md)")
    t = add("team", cmd_team, "people who may sign in to the web panel (panel machine only)")
    t.add_argument("action", choices=["list", "invite", "role", "remove", "reset", "withdraw"])
    t.add_argument("email", nargs="?")
    t.add_argument("role", nargs="?", help="role: owner, admin or auditor")
    t.add_argument("--role", dest="role_opt", help="invite: owner, admin or auditor (default admin)")
    t.add_argument("--by", help="the Owner or Admin making the change (default: the first Owner)")
    api = add("api", cmd_api, "call any core endpoint (docs/api/)")
    api.add_argument("method", choices=["GET", "POST", "DELETE", "get", "post", "delete"])
    api.add_argument("path")
    api.add_argument("body", nargs="?", help="JSON body")
    return p


def normalise(a: argparse.Namespace) -> argparse.Namespace:
    """Fold the positional leftovers into named fields, and check what each action needs."""
    if a.cmd == "settings":
        rest = a.rest
        a.section = rest[0] if a.action == "show" and rest else ""
        a.name = rest[0] if a.action in ("get", "preset") and rest else ""
        a.values = rest if a.action == "set" else []
        if a.action == "get" and not a.name:
            raise CliError("which setting? sentrai settings get NAME")
        if a.action == "set" and not a.values:
            raise CliError("what to set? sentrai settings set NAME=VALUE ...")
    elif a.cmd == "limits" and a.action == "set" and not a.values:
        raise CliError("what to set? sentrai limits set NAME=VALUE ... (sentrai limits show lists them)")
    elif a.cmd == "routing" and a.action == "import" and not a.file:
        raise CliError("which file? sentrai routing import FILE (make one with: sentrai routing export FILE)")
    elif a.cmd == "machines":
        if a.action == "join-code":
            a.name = a.name_opt or a.host
        elif a.action in ("rename", "delete", "revoke") and not a.host:
            raise CliError(f"which machine? sentrai machines {a.action} HOST")
    elif a.cmd == "jobs":
        if a.action == "list":
            a.host = a.host_opt or a.host
        elif not a.host:
            raise CliError(f"which {'job' if a.action == 'cancel' else 'machine'}? sentrai jobs {a.action} ...")
    elif a.cmd == "team":
        a.role = a.role or a.role_opt
        if a.action != "list" and not a.email:
            raise CliError(f"whose? sentrai team {a.action} EMAIL")
        if a.action == "role" and not a.role:
            raise CliError("which role? sentrai team role EMAIL owner|admin|auditor")
    return a


def main(argv: list[str] | None = None, call: Call | None = None, out=None) -> int:
    out = out or sys.stdout
    try:
        a = normalise(parser().parse_args(argv))
        if call is None and a.cmd != "team":
            cfg.load()
            url = a.url or os.environ.get("SENTRAI_CORE_URL") or DEFAULT_CORE
            call = http_call(url, cfg.api_token())
        result = a.fn(call, a)
    except CliError as e:
        print(f"sentrai: {e}", file=sys.stderr)
        return 1
    if isinstance(result, (dict, list)):
        result = json.dumps(result, indent=2)
    if result not in (None, ""):
        print(result, file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
