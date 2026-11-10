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
    sudo sentrai machines list | rename HOST NAME | delete HOST | restore HOST | join-code [--name N] | agents | revoke AGENT_ID
    sudo sentrai machines owner HOST PERSON | owner HOST --agent [--backup PERSON] | owner HOST --clear | ping HOST
    sudo sentrai jobs list [--host H] | scan HOST | backup HOST | deps HOST | packages HOST
                      | update HOST FINDING | undo HOST UPDATE | cancel JOB
                      | threats HOST | quarantine HOST FINDING | restore HOST QUARANTINE_ID
    sudo sentrai signatures list | add HASH... [--name N] | import FILE | remove HASH... | remove --source S
    sudo sentrai deps show | scan
    sudo sentrai backups list | now | copies | key | unlock HOST BACKUP_ID
    sudo sentrai incidents list [--all] | show ID | approve ID... | reject ID... --why W | rollback ID... | keep ID...
                           | resolve ID --note N
    sudo sentrai ideas list [--all] | planned ID... | done ID... | dismiss ID... | open ID...  [--note N]
    sudo sentrai coach status | setup --regions sg,my [--checks-done] [--notice-shared] [--names on|off]
                       | apps on|off APP... | person EMAIL [--name N] [--group G] [--region R] [--reach R]
                       | data EMAIL | erase EMAIL | sample [--clear] | notice > notice.md
                       | app-invite EMAIL | phones | phone-signout ID
    sudo sentrai rules list | add FILE [--title T] [--not-for-staff] | text TITLE --about TEXT | link URL [--title T]
                       [--about TEXT] | show ID | remove ID | ask QUESTION... | facts [--it-contact C]
                       [--report-how H] [--allowed A,B] [--blocked A,B] | system NAME [--what W] [--looks-after P]
                       [--importance critical|important|normal] | system NAME --remove
    sudo sentrai websites list | add DOMAIN | verify DOMAIN | check DOMAIN | show DOMAIN | remove DOMAIN
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
import urllib.parse
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
    try:
        ready = call("GET", "/ui/readiness")
    except CliError:  # a panel older than the readiness check
        ready = None
    out = {"protection": prot, "risks": risks, "machines": machines.get("stats", {}), "readiness": ready}
    if a.json:
        return out
    s = machines.get("stats", {})
    levels = ", ".join(f"{lv['severity']} {lv['count']}" for lv in risks.get("levels", []))
    lines = [
        f"Protection: {prot.get('protection')}"
        f"   Active blocks: {len(prot.get('active_actions') or [])}",
        f"Machines:   {s.get('machines', 0)} ({s.get('online', 0)} online, {s.get('offline', 0)} offline,"
        f" {s.get('need_a_look', 0)} need a look"
        + (f", {s['dry_run']} not blocking yet" if s.get("dry_run") else "") + ")",
        f"Waiting:    {levels}",
        risks.get("headline", ""),
    ]
    if ready:
        lines += ["", f"Readiness:  {ready.get('headline', '')}"]
        for c in ready.get("checks") or []:
            lines.append(f"  [{'x' if c.get('ok') else ' '}] {c.get('title')}: {c.get('detail')}")
            if c.get("fix_cli"):
                lines.append(f"        fix: {c['fix_cli']}")
        if (spend := ready.get("ai_spend")):
            cap = spend.get("budget_usd") or 0
            lines.append(f"AI helper:  USD {spend.get('usd', 0):.2f} spent in {spend.get('month')}"
                         + (f" of USD {cap:g}" if cap > 0 else " (no monthly cap)")
                         + (" - budget used up, answering from playbooks" if 0 < cap <= spend.get("usd", 0) else ""))
    return "\n".join(lines)


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


def owner_cell(o: Any) -> str:
    if not isinstance(o, dict):
        return "-"
    if o.get("kind") == "agent":
        return "AI agent" + (f" (backup {o.get('backup_name') or o.get('backup')})" if o.get("backup") else "")
    return str(o.get("name") or o.get("contact") or "-")


def cmd_machines(call: Call, a: argparse.Namespace) -> Any:
    op = operator_name()
    if a.action == "list":
        m = call("GET", "/ui/machines")
        if a.json:
            return m
        words = m.get("band_words", {})
        rows = [[r.get("name"), r.get("host"), "online" if r.get("online") else ("waiting" if r.get("waiting") else "offline"),
                 "off" if r.get("monitor_only") else "on", f"{r.get('index') or 0:.0f} {words.get(r.get('band'), '')}",
                 r.get("open"), r.get("blocked"), (r.get("blocking") or {}).get("word") or "-",
                 owner_cell(r.get("owner")), r.get("last_seen") or ""]
                for r in m.get("machines", [])]
        out = table(rows, ["Name", "Host", "State", "Protection", "Risk", "Open", "Blocks", "Blocking", "Owner",
                           "Last seen"])
        if m.get("stats", {}).get("dry_run"):
            out += ("\n\nNot blocking yet = a dry run: blocks are only written down on that machine."
                    "\nTurn real blocking on with: sentrai machines blocking HOST on")
        gone = m.get("removed") or []
        if gone:
            out += "\n\nDeleted (hidden): " + ", ".join(str(g.get("host")) for g in gone) \
                   + "\nBring one back with: sentrai machines restore HOST"
        return out
    if a.action == "agents":
        rows = call("GET", "/fleet/agents")
        return rows if a.json else table([[r.get("agent_id"), r.get("host"), r.get("joined_at") or r.get("enrolled_at"),
                                           r.get("last_seen"), "revoked" if r.get("revoked_at") else "active"] for r in rows],
                                         ["Agent", "Host", "Joined", "Last seen", "Key"])
    if a.action == "rename":
        out = call("POST", f"/ui/machines/{a.host}/rename", {"name": a.name or "", "operator": op})
    elif a.action == "delete":
        out = call("POST", f"/ui/machines/{a.host}/delete", {"operator": op})
    elif a.action == "restore":
        out = call("POST", f"/ui/machines/{a.host}/restore", {"operator": op})
    elif a.action == "owner":
        if a.clear:
            body = {"kind": ""}
        elif a.agent:
            body = {"kind": "agent", "backup": a.backup or ""}
        else:
            body = {"kind": "person", "contact": a.name}
        out = call("POST", f"/ui/machines/{a.host}/owner", {**body, "operator": op})
    elif a.action == "ping":
        out = call("POST", f"/ui/machines/{a.host}/ping", {"operator": op})
    elif a.action == "blocking":
        if a.name not in ("on", "off"):
            raise CliError("say on (really change the firewall) or off (back to a dry run): "
                             "sentrai machines blocking HOST on")
        out = call("POST", "/fleet/jobs", {"host": a.host, "kind": f"blocking_{a.name}", "operator": op})
        if a.json:
            return out
        return (f"Asked {a.host} to {'really block from now on' if a.name == 'on' else 'go back to a dry run'} "
                f"({out.get('id')}). Its agent picks this up within about 15 seconds.")
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
    if a.action == "threats":
        rows = call("GET", f"/fleet/threats?host={a.host}")["findings"]
        if a.json:
            return rows
        if not rows:
            return f"Nothing found by {a.host}'s file watch since the panel started."
        return table([[f.get("id") or "", f.get("seen_at"), f.get("severity"), f.get("kind"), f.get("label"), f.get("path")]
                      for f in rows], ["Finding", "Seen", "Severity", "Kind", "What", "Where"]) + \
            f"\n\nTo lock one away: sentrai jobs quarantine {a.host} FINDING"
    if a.action == "cancel":
        out = call("POST", f"/fleet/jobs/{a.host}/cancel", {"operator": op})
        return out if a.json else f"{out.get('id')}: {out.get('status')}"
    body: dict[str, Any] = {"host": a.host, "operator": op}
    if a.action in JOB_KINDS:
        body["kind"] = JOB_KINDS[a.action]
    elif a.action == "update":
        body |= {"kind": "dep_update", "params": {"finding": a.ref}}
    elif a.action == "quarantine":
        body |= {"kind": "quarantine", "params": {"finding": a.ref}}
    elif a.action == "restore":
        body |= {"kind": "restore", "params": {"item": a.ref}}
    else:  # undo
        body |= {"kind": "dep_rollback", "params": {"update": a.ref}}
    if a.action in ("update", "undo", "quarantine", "restore") and not a.ref:
        raise CliError("which one? update and quarantine need a finding id (sentrai jobs list, sentrai jobs threats HOST), "
                       "undo needs an update id (u-...), restore a quarantine id (q-...)")
    out = call("POST", "/fleet/jobs", body)
    return out if a.json else f"Queued {out.get('id')} on {a.host}: the machine picks it up within about 15 s. " \
                              f"Check with: sentrai jobs list --host {a.host}"


def cmd_signatures(call: Call, a: argparse.Namespace) -> Any:
    """The shared list of known-bad file fingerprints every machine checks against."""
    op = operator_name()
    if a.action == "list":
        out = call("GET", "/signatures")
        if a.json:
            return out
        src = ", ".join(f"{k} {v}" for k, v in sorted(out.get("by_source", {}).items())) or "none yet"
        rows = [[r["hash"][:16] + "…", r.get("name") or "", r.get("source"), r.get("by"), r.get("at")]
                for r in out.get("recent") or []]
        return f"{out.get('count', 0)} fingerprints (version {out.get('version')}); from: {src}" + \
            ("\n\n" + table(rows, ["Fingerprint", "Name", "Source", "By", "Added"]) if rows else "")
    if a.action == "add":
        if not a.items:
            raise CliError("which fingerprints? sentrai signatures add SHA256... [--name N]")
        out = call("POST", "/signatures", {"hashes": a.items, "name": a.name or "", "operator": op})
    elif a.action == "import":
        if len(a.items) != 1:
            raise CliError("which file? sentrai signatures import FILE (one fingerprint per line, a CSV export "
                           "with a sha256 column, or a ClamAV .hdb/.hsb)")
        f = Path(a.items[0])
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise CliError(f"cannot read {f}: {e.strerror}") from None
        out = call("POST", "/signatures", {"text": text, "source": a.name or f.name, "operator": op})
    else:  # remove
        if not a.items and not a.source:
            raise CliError("which ones? sentrai signatures remove SHA256..., or --source import:FILE")
        out = call("POST", "/signatures/remove", {"hashes": a.items, "source": a.source, "operator": op})
        return out if a.json else f"Removed {out.get('removed')} fingerprint(s). Machines pick up the change within 30 minutes."
    return out if a.json else (f"Added {out.get('added')} ({out.get('known')} already known, {out.get('refused')} not "
                               f"fingerprints); the list has {out.get('count')}. Machines pick it up within 30 minutes.")


def cmd_websites(call: Call, a: argparse.Namespace) -> Any:
    """The company's own websites: prove ownership, then let Sentry look at them from the outside."""
    op = operator_name()
    if a.action != "list" and not a.domain:
        raise CliError(f"which website? sentrai websites {a.action} DOMAIN")
    d = urllib.parse.quote(a.domain or "", safe="")
    if a.action == "list":
        out = call("GET", "/ui/websites")
        if a.json:
            return out
        rows = [[s["domain"], "yes" if s["verified"] else "NO", (s["last"] or {}).get("grade") or "-",
                 ((s["last"] or {}).get("checked_at") or "never")[:16]] for s in out.get("sites", [])]
        return table(rows, ["Website", "Proven", "Grade", "Last checked"]) if rows else \
            "No websites yet. Add one: sentrai websites add example.com"
    if a.action == "add":
        out = call("POST", "/ui/websites", {"domain": a.domain, "operator": op})
        if a.json or out.get("verified"):
            return out if a.json else f"{out['domain']} is on the list and already proven ({out['verified_by']})."
        p = out["proof"]
        return (f"Added {out['domain']}. Before it can be checked, prove the company owns it (either one):\n"
                f"  DNS:  TXT record on {p['dns_name']}  =  {p['dns_value']}\n"
                f"  File: {p['file_url']}  containing only  {p['file_text']}\n"
                f"Keep it published (it is read before every check), then: sentrai websites verify {out['domain']}")
    if a.action == "verify":
        out = call("POST", f"/ui/websites/{d}/verify", {"operator": op})
        if a.json:
            return out
        if out.get("found"):
            return f"{out['domain']} is proven by {out['found']}. Check it: sentrai websites check {out['domain']}"
        raise CliError(f"no proof found yet for {out['domain']}. {out['proof']['how']} "
                       "(DNS changes can take a few minutes to show.)")
    if a.action == "remove":
        out = call("DELETE", f"/ui/websites/{d}")
        return out if a.json else f"Removed {out['removed']}; Sentry will not check it any more."
    out = call("POST", f"/ui/websites/{d}/check", {"operator": op}) if a.action == "check" \
        else call("GET", f"/ui/websites/{d}")
    if a.json:
        return out
    rows = [[f["id"], f["severity_word"], f["title"], f.get("detail", "")[:70]] for f in out.get("findings", [])]
    lines = [f"{out['domain']}  grade {out['grade']} ({out['score']}/100)  {out['checked_at']}  "
             f"{out['requests']} requests", out["headline"]]
    if rows:
        lines += ["", table(rows, ["Id", "How serious", "Finding", "Evidence"])]
    if out.get("not_checked"):
        lines += ["", "Not checked: " + ", ".join(out["not_checked"])]
    if out.get("fixed_since"):
        lines += ["Fixed since last time: " + "; ".join(out["fixed_since"])]
    return "\n".join(lines)


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


def cmd_ideas(call: Call, a: argparse.Namespace) -> Any:
    """Feature ideas: what people asked Sentry for that SentrAI can't do yet, most asked first."""
    if a.action == "list":
        out = call("GET", "/ui/feature-ideas" + ("?all=true" if a.all else ""))
        if a.json:
            return out
        rows = out.get("ideas", [])
        if not rows:
            return "No feature ideas waiting." if not a.all else "No feature ideas yet."
        blocks = []
        for r in rows:
            head = (f"{r.get('id')}  asked {r.get('count')}x by {r.get('asked_by')} "
                    f"{'person' if r.get('asked_by') == 1 else 'people'}  last {str(r.get('last_at') or '')[:10]}"
                    + (f"  [{r.get('status')}]" if r.get("status") != "new" else ""))
            body = [f"    {r.get('title')}"] + [f"      \"{x}\"" for x in (r.get("examples") or [])
                                               if x.strip().lower() != str(r.get("title") or "").strip().lower()]
            blocks.append("\n".join([head] + body))
        return ("\n\n".join(blocks) + f"\n\n{len(rows)} idea{'s' if len(rows) != 1 else ''}. "
                "Mark them: sentrai ideas planned|done|dismiss ID ...")
    if not a.ids:
        raise CliError(f"which idea? sentrai ideas {a.action} ID ... (sentrai ideas list)")
    status = {"planned": "planned", "done": "done", "dismiss": "dismissed", "open": "new"}[a.action]
    out = call("POST", "/ui/feature-ideas/status", {"ids": a.ids, "status": status, "operator": operator_name(),
                                                    "note": a.note or ""})
    return out if a.json else out.get("message", out)


def cmd_rules(call: Call, a: argparse.Namespace) -> Any:
    """Company Rules: the guides, policies and quick facts this company taught SentrAI."""
    who = operator_name()
    if a.action == "list":
        out = call("GET", "/ui/knowledge")
        if a.json:
            return out
        f = out["facts"]
        lines = [f"{len(out['guides'])} guide{'' if len(out['guides']) == 1 else 's'}:"]
        lines += [f"  {g['id']}  {g['title']}  ({g['kind']}, {g['passages']} passages"
                  + ("" if g["for_staff"] else ", not shown to staff") + ")" for g in out["guides"]] or ["  (none yet)"]
        lines += ["Quick facts:",
                  f"  IT contact:   {f['it_contact'] or '-'}", f"  How to report: {f['report_how'] or '-'}",
                  f"  Allowed apps: {', '.join(f['allowed_apps']) or '-'}",
                  f"  Not allowed:  {', '.join(f['blocked_apps']) or '-'}"]
        lines += [f"  System: {x['name']} ({x['importance']})" + (f", {x['what']}" if x["what"] else "")
                  + (f", looked after by {x['looks_after']}" if x["looks_after"] else "") for x in f["systems"]]
        return "\n".join(lines)
    if a.action in ("add", "text", "link"):
        if not a.target:
            raise CliError({"add": "which file? sentrai rules add policy.docx",
                            "text": "sentrai rules text TITLE --about \"the rule\"",
                            "link": "sentrai rules link https://intranet/policy --about \"what it says\""}[a.action])
        body: dict[str, Any] = {"operator": who, "for_staff": not a.not_for_staff}
        if a.title:
            body["title"] = a.title
        if a.action == "add":
            import base64
            path = Path(a.target)
            if not path.is_file():
                raise CliError(f"no file {a.target}")
            body |= {"kind": "file", "name": path.name, "content_base64": base64.b64encode(path.read_bytes()).decode()}
        elif a.action == "text":
            if not a.about:
                raise CliError("say the rule with --about \"...\"")
            body |= {"kind": "text", "title": a.title or a.target, "text": a.about}
        else:
            body |= {"kind": "link", "url": a.target, "text": a.about or ""}
        out = call("POST", "/ui/knowledge/guides", body)
        return out if a.json else (f"{'Updated' if out['replaced'] else 'Learned'} \"{out['title']}\" ({out['id']}, "
                                   f"{out['passages']} passages).")
    if a.action in ("show", "remove"):
        if not a.target:
            raise CliError(f"which guide? sentrai rules {a.action} ID  (sentrai rules list shows ids)")
        if a.action == "show":
            out = call("GET", f"/ui/knowledge/guides/{a.target}")
            return out if a.json else f"{out['title']} ({out['source']})\n\n{out['text']}"
        out = call("DELETE", f"/ui/knowledge/guides/{a.target}")
        return out if a.json else f"Removed \"{out['removed']['title']}\". Sentry and the coach no longer use it."
    if a.action == "ask":
        q = " ".join(([a.target] if a.target else []) + list(a.words or []))
        if not q:
            raise CliError("sentrai rules ask \"can staff use WhatsApp?\"")
        out = call("GET", "/ui/knowledge/ask?" + urllib.parse.urlencode({"q": q}))
        if a.json:
            return out
        return "\n\n".join([out["text"]] + [f"[{h['title']}] {h['text']}" for h in out["passages"]]
                            + ([out["help"]] if out["help"] else []))
    if a.action == "facts":
        body = {"operator": who}
        for key, val in (("it_contact", a.it_contact), ("report_how", a.report_how), ("allowed_apps", a.allowed),
                         ("blocked_apps", a.blocked)):
            if val is not None:
                body[key] = val
        out = call("POST", "/ui/knowledge/facts", body) if len(body) > 1 else call("GET", "/ui/knowledge")
        return out if a.json else cmd_rules(call, argparse.Namespace(**{**vars(a), "action": "list"}))
    if a.action == "system":
        if not a.target:
            raise CliError("sentrai rules system NAME [--what W] [--looks-after P] [--importance critical]")
        systems = [x for x in call("GET", "/ui/knowledge")["facts"]["systems"] if x["name"].lower() != a.target.lower()]
        if not a.remove:
            systems.append({"name": a.target, "what": a.what or "", "looks_after": a.looks_after or "",
                            "importance": a.importance or "normal"})
        call("POST", "/ui/knowledge/facts", {"operator": who, "systems": systems})
        return f"{'Removed' if a.remove else 'Saved'} {a.target}. SentrAI knows {len(systems)} important system" + \
            ("" if len(systems) == 1 else "s") + "."
    raise CliError("sentrai rules list | add | text | link | show | remove | ask | facts | system")


def cmd_coach(call: Call, a: argparse.Namespace) -> Any:
    """Security Coach: which work apps it reads, the regions' checklists, the people it coaches."""
    if a.action == "status":
        out = call("GET", "/ui/coach")
        if a.json:
            return out
        s, t = out["settings"], out["team"]
        apps = ", ".join(x["name"] for x in out["apps"] if x["key"] in s["apps_on"]) or "none"
        lines = [("On: recording and coaching." if out["ready"] else "Off: " + out["why_not_ready"]),
                 f"Apps: {apps}", f"Regions: {', '.join(s['regions']) or 'none'}   names shown: "
                 f"{'yes' if s['show_names'] else 'team totals only'}   file names kept: {'yes' if s['file_names'] else 'no'}",
                 f"People: {t['people']} ({t['notice_confirmed']} confirmed the notice)   last 30 days: "
                 f"{t['moments_30d']} risky moments, {t['fixed_30d']} fixed, {t['urgent_open']} urgent open, "
                 f"{t['lessons_done']} lessons done",
                 f"Kept: activity {out['kept']['activity']}, notes {out['kept']['notes']} (Privacy page)"]
        return "\n".join(lines)
    if a.action == "setup":
        body: dict[str, Any] = {"operator": operator_name()}
        if a.regions:
            body["regions"] = [r.strip().lower() for r in a.regions.split(",") if r.strip()]
        if a.checks_done:
            regions = body.get("regions") or call("GET", "/ui/coach")["settings"]["regions"]
            info = {r["key"]: r for r in call("GET", "/ui/coach")["regions"]}
            body["region_checks"] = {r: list(range(len(info[r]["checks"]))) for r in regions if r in info}
        if a.notice_shared:
            body["notice_shared"] = True
        if a.names:
            body["show_names"] = a.names == "on"
        out = call("POST", "/ui/coach/settings", body)
        return out if a.json else ("Coach is on." if out["ready"] else "Saved. Still off: " + out["why_not_ready"])
    if a.action == "apps":
        if a.state not in ("on", "off") or not a.items:
            raise CliError("sentrai coach apps on|off APP ...  (google, microsoft, okta, slack, ...)")
        cur = set(call("GET", "/ui/coach")["settings"]["apps_on"])
        cur = cur | set(a.items) if a.state == "on" else cur - set(a.items)
        out = call("POST", "/ui/coach/settings", {"apps_on": sorted(cur), "operator": operator_name()})
        return out if a.json else "Apps on: " + (", ".join(out["settings"]["apps_on"]) or "none")
    if a.action == "sample":
        out = call("POST", "/ui/coach/sample", {"clear": bool(a.clear), "operator": operator_name()})
        if a.json:
            return out
        return ("Sample people and activity removed." if a.clear else
                f"Added 3 sample people and {out['added']['moments']} risky moments. Remove: sentrai coach sample --clear")
    if a.action == "notice":
        return call("GET", "/ui/coach/notice.md")
    if a.action == "phones":
        out = call("GET", "/ui/mobile")
        if a.json:
            return out
        t = out["team"]
        lines = [f"{len(out['phones'])} phone sign-in(s). Phone checks: {t['phones_checked']}, all good: "
                 f"{t['all_good']}."]
        lines += [f"  {k}: {v}" for k, v in sorted(t["by_problem"].items())]
        lines += [f"  {p['id']}  {p['email']}  {p['device']}  ({p['kind']}, last used {p['last_at']})"
                  for p in out["phones"]]
        return "\n".join(lines)
    if a.action == "phone-signout":
        if not a.state:
            raise CliError("which phone? sentrai coach phone-signout ID  (sentrai coach phones lists them)")
        out = call("POST", f"/ui/mobile/{a.state}/sign-out", {})
        return out if a.json else f"Signed out {out['device']} ({out['email']})."
    if not a.state or "@" not in a.state:
        raise CliError(f"whose? sentrai coach {a.action} EMAIL")
    if a.action == "person":
        body = {"email": a.state}
        for k in ("name", "group", "region", "reach"):
            if getattr(a, k) is not None:
                body[k] = getattr(a, k)
        out = call("POST", "/ui/coach/people", body)
        return out if a.json else f"Saved {out['person']['email']}."
    if a.action == "data":
        return call("GET", f"/ui/coach/people/{a.state}/data")
    if a.action == "app-invite":
        out = call("POST", "/ui/mobile/invites", {"email": a.state})
        return out if a.json else (f"App invite for {out['email']}: {out['code']} (works once, until "
                                   f"{out['expires_at']}).\n" + "\n".join(f"  {n}. {s}" for n, s in
                                                                      enumerate(out["steps"], 1)))
    out = call("POST", f"/ui/coach/people/{a.state}/erase", {})
    return out if a.json else "Erased: " + ", ".join(f"{v} {k}" for k, v in out["erased"].items())


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
    m.add_argument("action", choices=["list", "agents", "rename", "delete", "restore", "revoke", "join-code", "owner", "ping",
                                      "blocking"])
    m.add_argument("host", nargs="?", help="host name (revoke: agent id)")
    m.add_argument("name", nargs="?", help="rename: the new name (blank goes back to the host name) · "
                                           "owner: the person responsible (a Routing contact id or name) · "
                                           "blocking: on (really change its firewall) or off (back to a dry run)")
    m.add_argument("--agent", action="store_true", help="owner: the AI agent answers for it and handles its alerts")
    m.add_argument("--backup", help="owner --agent: the person it hands decisions to (a Routing contact)")
    m.add_argument("--clear", action="store_true", help="owner: nobody; the Routing rules decide again")
    m.add_argument("--name", dest="name_opt", help="join-code: fix the new machine's name")
    m.add_argument("--panel-url", help="join-code: the address new machines use (default SENTRAI_PANEL_URL)")
    j = add("jobs", cmd_jobs, "ask a machine to scan, back up, update packages or lock a file away")
    j.add_argument("action", choices=["list", "scan", "backup", "deps", "packages", "update", "undo", "cancel",
                                      "threats", "quarantine", "restore"])
    j.add_argument("host", nargs="?", help="host name (cancel: job id)")
    j.add_argument("ref", nargs="?", help="update, quarantine: finding id · undo: update id · restore: quarantine id")
    j.add_argument("--host", dest="host_opt")
    sg = add("signatures", cmd_signatures, "the shared list of known-bad file fingerprints")
    sg.add_argument("action", choices=["list", "add", "import", "remove"])
    sg.add_argument("items", nargs="*", help="add/remove: fingerprints · import: the list file")
    sg.add_argument("--name", help="add: what they are · import: the list's name (default: the file name)")
    sg.add_argument("--source", help="remove: every fingerprint from this source (import:FILE)")
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
    ide = add("ideas", cmd_ideas, "feature ideas: what people asked Sentry for that SentrAI can't do yet")
    ide.add_argument("action", choices=["list", "planned", "done", "dismiss", "open"])
    ide.add_argument("ids", nargs="*")
    ide.add_argument("--all", action="store_true", help="list: done and dismissed ones too")
    ide.add_argument("--note", help="planned/done/dismiss: a short note kept with the idea")
    co = add("coach", cmd_coach, "Security Coach: work apps it reads, regions' checklists, people it coaches")
    co.add_argument("action", choices=["status", "setup", "apps", "person", "data", "erase", "sample", "notice",
                                       "app-invite", "phones", "phone-signout"])
    co.add_argument("state", nargs="?", help="apps: on or off · person, data, erase, app-invite: the work email · "
                                             "phone-signout: the phone's id")
    co.add_argument("items", nargs="*", help="apps: google, microsoft, okta, slack, zoom, dropbox, box, github, ...")
    co.add_argument("--regions", help="setup: where staff work, e.g. sg,my,eu (sentrai coach status lists them)")
    co.add_argument("--checks-done", action="store_true", help="setup: every region's checklist is done")
    co.add_argument("--notice-shared", action="store_true", help="setup: staff have the notice (sentrai coach notice)")
    co.add_argument("--names", choices=["on", "off"], help="setup: show people's names to Owners and Admins")
    co.add_argument("--name")
    co.add_argument("--group")
    co.add_argument("--region")
    co.add_argument("--reach", choices=["email", "slack", "teams", "app"])
    co.add_argument("--clear", action="store_true", help="sample: remove the sample people and activity")
    ru = add("rules", cmd_rules, "Company Rules: guides, policies and quick facts SentrAI follows for this company")
    ru.add_argument("action", choices=["list", "add", "text", "link", "show", "remove", "ask", "facts", "system"])
    ru.add_argument("target", nargs="?", help="add: a file · text: a title · link: the address · show, remove: the "
                                              "guide's id · ask: the question · system: its name")
    ru.add_argument("words", nargs="*", help="ask: the rest of the question")
    ru.add_argument("--title")
    ru.add_argument("--about", help="text: the rule itself · link: what the page says, in a few lines")
    ru.add_argument("--not-for-staff", action="store_true", help="add, text, link: Sentry uses it, staff don't see it")
    ru.add_argument("--it-contact", help="facts: who staff ask for IT or security help")
    ru.add_argument("--report-how", help="facts: how staff report something suspicious")
    ru.add_argument("--allowed", help="facts: apps staff may use, comma separated")
    ru.add_argument("--blocked", help="facts: apps staff must not use, comma separated")
    ru.add_argument("--what", help="system: what it is for")
    ru.add_argument("--looks-after", help="system: who looks after it")
    ru.add_argument("--importance", choices=["critical", "important", "normal"])
    ru.add_argument("--remove", action="store_true", help="system: forget this system")
    we = add("websites", cmd_websites, "the company's own websites: prove ownership, check them from outside")
    we.add_argument("action", choices=["list", "add", "verify", "check", "show", "remove"])
    we.add_argument("domain", nargs="?")
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
        elif a.action in ("rename", "delete", "restore", "revoke", "owner", "ping") and not a.host:
            raise CliError(f"which machine? sentrai machines {a.action} HOST")
        elif a.action == "owner" and not (a.clear or a.agent or a.name):
            raise CliError("who? sentrai machines owner HOST PERSON, or --agent [--backup PERSON], or --clear")
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
