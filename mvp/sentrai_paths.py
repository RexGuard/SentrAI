"""Where every part of SentrAI keeps its data: one root folder, one folder per part, one lookup.

    python sentrai_paths.py           # the map for this machine: each file, where it is, who writes it
    python sentrai_paths.py index     # also write INDEX.md into the data root (run.sh / run.ps1 and the
                                      # installers do this; it moves files from their old places first)
    python sentrai_paths.py migrate   # only move files from the places older versions used

The root is ``SENTRAI_HOME``; else the folder of ``SENTRAI_CONFIG`` (every install puts the settings
file at the root); else ``~/.sentrai``. deploy/install.sh uses /var/lib/sentrai, install-agent.sh
/var/lib/sentrai/agent and install-agent.ps1 C:\\ProgramData\\SentrAI\\agent.

    <root>/
      INDEX.md                      this map, written by `sentrai_paths.py index`
      config.json                   settings, read by every part                     SENTRAI_CONFIG
      accounts.json                 who may sign in to the dashboard                 SENTRAI_ACCOUNTS
      approval-groups.json          approvals bundled into named groups              SENTRAI_APPROVAL_GROUPS
      core/                         the core service (on a server, only it may open this folder)
        sentrai.db (+ -wal, -shm)   Scribe: the audit chain and the working state   SENTRAI_DB
        anchor.key                  Scribe: the key that signs audit fingerprints
        archive/                    Scribe: chains archived by a reset
        protection.json             Warden: the monitor-only switch
        summary.json                when the client summary goes out
        extensions.json             extensions added or removed on the dashboard
        remote-copy.token           the witness's append token (install.sh --remote-copy)
        people/routing.json         who gets what: contacts, routing rules, escalation   SENTRAI_ROUTING
        people/telegram_links.json  contacts linked to Telegram chats                SENTRAI_TELEGRAM_LINKS
        people/staff_reports.json   what staff reported                              SENTRAI_STAFF_REPORTS
        people/admins.json          the administrators: accounts, addresses, keys     SENTRAI_ADMINS
        machines/fleet.json         machines that joined the panel (hashed keys)
        machines/jobs.json          scans and backups queued for those machines
        threats/threat_seen.json    ThreatWatch: findings already raised             SENTRAI_THREAT_STATE
        threats/quarantine/         ThreatWatch: files moved out of reach            SENTRAI_QUARANTINE
        backups/                    BackupWatch: archives                            SENTRAI_BACKUP_DIR
        restores/                   BackupWatch: restored copies
      collector/state.json          read positions and the line chain               SENTRAI_COLLECTOR_STATE
      scout/sources.json            log files a person approved                     SENTRAI_SCOUT_SOURCES
      scout/pending.json            Scout's proposals waiting for a person          SENTRAI_SCOUT_PENDING
      scout/trails/                 expert trails recorded on this machine          SENTRAI_SCOUT_TRAILS
      notifier/last_witness.txt     the last audit fingerprint delivered            NOTIFIER_WITNESS_FILE
      agent/agent.json              the fleet agent: machine key, blocks in force   SENTRAI_AGENT_FILE
      agent/backups/                backups the panel asked this machine to make    SENTRAI_BACKUP_DIR
      agent/deps/                   the last dependency scan, updates made and their undo copies
      logs/                         JSON-lines logs the collector tails             SENTRAI_LAB_LOGS

Rules:

* A variable that is set always wins, so a server set up by install.sh changes nothing it pinned.
* "Next to" relations hold: the core's files sit next to the database wherever SENTRAI_DB points,
  pending.json next to sources.json, the agent's backups next to agent.json.
* A file an older version kept somewhere else (the checkout's mvp/core/data, mvp/lab/scout,
  mvp/notifier/data, or flat in ~/.sentrai) is moved the first time its part looks for it, by
  renaming, never copying, and only when nothing is at the new place yet. When a move fails (the
  file is open, another drive) the old place stays in use and is named once on stderr. Nothing is
  deleted or overwritten. ``SENTRAI_MIGRATE=off`` turns moving off: old files are left where they
  are and the new places are used (the test suites set it, so a test run never moves a developer's
  own files out of their checkout).

Stdlib only, like sentrai_env: every part imports this through sentrai_config.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import sentrai_env  # the ~/.cactai -> ~/.sentrai move, and the CACTAI_* names

MVP_DIR = Path(__file__).resolve().parent
ROOT_ENV = "SENTRAI_HOME"
INDEX_NAME = "INDEX.md"

_warned: set[str] = set()
moved: list[tuple[Path, Path]] = []  # (old, new) moves made by this process, for the CLI and tests


def _warn(key: str, text: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"[sentrai] {text}", file=sys.stderr)


@dataclass(frozen=True)
class Part:
    name: str
    what: str
    anchor_env: str = ""          # the variable that, when set, places the whole folder (SENTRAI_DB -> core/)
    old_dirs: tuple[str, ...] = ()  # where an older version kept the whole folder ("mvp:core/data")


@dataclass(frozen=True)
class Entry:
    key: str                      # "core.db"
    part: str                     # root, core, collector, scout, notifier, agent
    rel: str                      # inside the part's folder, with "/"
    what: str                     # one line for the map
    agent: str = ""               # the SentrAI agent (or part) that owns it
    env: str = ""                 # the variable that moves it
    kind: str = "file"            # or "dir"
    companions: tuple[str, ...] = ()  # suffixes that travel with it (sqlite -wal / -shm)
    old: tuple[str, ...] = ()     # earlier places, newest first: "part:name", "root:name", "mvp:rel", a glob
    seed: str = ""                # files that ship with SentrAI, copied into a new folder ("mvp:...glob")
    optional: bool = False        # exists only once a feature is used
    near: str = ""                # a variable whose file this one sits next to when it is set (accounts -> config)


PARTS: dict[str, Part] = {p.name: p for p in (
    Part("root", "settings and sign-in, read by every part"),
    Part("core", "the core service: audit record, agents' state, backups", "SENTRAI_DB", ("mvp:core/data",)),
    Part("collector", "the collector's read positions", "SENTRAI_COLLECTOR_STATE"),
    Part("scout", "approved log files and expert trails", "SENTRAI_SCOUT_SOURCES"),
    Part("notifier", "the notifier's delivered fingerprint", "NOTIFIER_WITNESS_FILE", ("mvp:notifier/data",)),
    Part("agent", "the fleet agent on a guarded machine", "SENTRAI_AGENT_FILE"),
)}

ENTRIES: dict[str, Entry] = {e.key: e for e in (
    Entry("index", "root", INDEX_NAME, "this map, for this machine", "sentrai_paths.py", optional=True),
    Entry("config", "root", "config.json", "settings, read by every part when it starts", "every part", "SENTRAI_CONFIG"),
    Entry("accounts", "root", "accounts.json", "who may sign in, with password hashes and authenticator secrets",
          "Dashboard", "SENTRAI_ACCOUNTS", near="SENTRAI_CONFIG"),
    Entry("approval_groups", "root", "approval-groups.json", "approvals a person bundled into named groups",
          "Dashboard", "SENTRAI_APPROVAL_GROUPS", near="SENTRAI_CONFIG", optional=True),
    Entry("logs", "root", "logs", "JSON-lines logs the collector tails (an input, not SentrAI's own data)",
          "Collector", "SENTRAI_LAB_LOGS", kind="dir"),
    Entry("core.db", "core", "sentrai.db", "the hash-chained audit record and the working state (incidents, actions)",
          "Scribe", "SENTRAI_DB", companions=("-wal", "-shm"), old=("part:cactai.db",)),
    Entry("core.anchor_key", "core", "anchor.key", "signs the audit fingerprints sent to the alert channels", "Scribe"),
    Entry("core.archive", "core", "archive", "audit chains set aside by a reset (never deleted)", "Scribe",
          kind="dir", optional=True),
    Entry("core.protection", "core", "protection.json", "the monitor-only switch, as an operator last set it", "Warden"),
    Entry("core.summary", "core", "summary.json", "when the client summary goes out (Reports page)", "Scribe"),
    Entry("core.extensions", "core", "extensions.json", "extensions added or removed on the dashboard (Extensions page)",
          "Extensions", optional=True, old=("part:extensions.json",)),
    Entry("core.remote_copy_token", "core", "remote-copy.token", "the witness's append token (install.sh --remote-copy)",
          "Scribe", "SENTRAI_REMOTE_COPY_TOKEN_FILE", optional=True),
    Entry("core.playbooks", "core", "playbooks.json", "playbooks an AI model drafted from similar past incidents "
          "(Analytics page)", "Analytics", optional=True),
    Entry("core.privacy", "core", "privacy.json", "the privacy policy: retention periods and the staff contact "
          "(Privacy page)", "Scribe", optional=True),
    Entry("core.routing", "core", "people/routing.json", "who gets what: contacts, routing rules, escalation",
          "Warden", "SENTRAI_ROUTING", old=("part:routing.json",)),
    Entry("core.telegram_links", "core", "people/telegram_links.json", "contacts linked to their Telegram chats",
          "Notifier", "SENTRAI_TELEGRAM_LINKS", old=("part:telegram_links.json",)),
    Entry("core.staff_reports", "core", "people/staff_reports.json", "what staff reported (/report, the report page)",
          "HelpDesk", "SENTRAI_STAFF_REPORTS", old=("part:staff_reports.json",)),
    Entry("core.admins", "core", "people/admins.json", "the administrators: their accounts, sign-in addresses and "
          "SSH keys (taught or learned), and who is signed in now", "Warden", "SENTRAI_ADMINS", optional=True),
    Entry("core.fleet", "core", "machines/fleet.json", "machines that joined the panel: hashed keys and join codes",
          "Fleet", old=("part:fleet.json",)),
    Entry("core.jobs", "core", "machines/jobs.json", "scans and backups queued for those machines", "Fleet",
          old=("part:jobs.json",)),
    Entry("core.threat_state", "core", "threats/threat_seen.json", "findings already raised, so each one alerts once",
          "ThreatWatch", "SENTRAI_THREAT_STATE", old=("part:threat_seen.json", "mvp:core/data/threat_seen.json")),
    Entry("core.quarantine", "core", "threats/quarantine", "files moved out of reach, with what they were (restorable)",
          "ThreatWatch", "SENTRAI_QUARANTINE", kind="dir", old=("part:quarantine", "mvp:core/data/quarantine")),
    Entry("core.backups", "core", "backups", "backup archives and their manifests", "BackupWatch",
          "SENTRAI_BACKUP_DIR", kind="dir"),
    Entry("core.restores", "core", "restores", "folders a backup was restored into", "BackupWatch", kind="dir",
          optional=True),
    Entry("collector.state", "collector", "state.json", "where each log was read up to, and the line chain",
          "Collector", "SENTRAI_COLLECTOR_STATE", old=("root:collector-state.json",)),
    Entry("scout.sources", "scout", "sources.json", "log files a person approved; the collector tails them",
          "Scout", "SENTRAI_SCOUT_SOURCES", old=("mvp:lab/scout/sources.json",)),
    Entry("scout.pending", "scout", "pending.json", "Scout's proposals waiting for a person", "Scout",
          "SENTRAI_SCOUT_PENDING", old=("mvp:lab/scout/pending.json",)),
    Entry("scout.trails", "scout", "trails", "expert trails recorded here (new folders start with the examples)",
          "Scout", "SENTRAI_SCOUT_TRAILS", kind="dir", old=("mvp:lab/scout/trails/*.jsonl",),
          seed="mvp:lab/scout/trails/example-*.jsonl"),
    Entry("notifier.witness", "notifier", "last_witness.txt", "the last audit fingerprint delivered to the alert chat",
          "Notifier", "NOTIFIER_WITNESS_FILE", old=("mvp:notifier/data/last_witness.txt",)),
    Entry("agent.file", "agent", "agent.json", "machine key, panel address and pin, blocks in force, local rules",
          "Agent", "SENTRAI_AGENT_FILE", old=("root:agent.json",)),
    Entry("agent.backups", "agent", "backups", "backups the panel asked this machine to make", "Agent",
          "SENTRAI_BACKUP_DIR", kind="dir", old=("root:backups",)),
    Entry("agent.deps", "agent", "deps", "the last dependency scan, package updates made here and what undoes them",
          "Agent", kind="dir", optional=True),
)}

ELSEWHERE = (
    "Service settings: /etc/sentrai/sentrai.env and agent.env, the dashboard certificate in /etc/sentrai/tls "
    "(a server), the <env> lines in SentrAIAgent.xml (a Windows agent).",
    "The witness keeps its copy of the audit record on its own machine: /var/lib/sentrai-witness.",
    "run.sh / run.ps1 keep their process ids and output in mvp/.run_pids.json and mvp/.run_logs/ (not data).",
)


# ------------------------------------------------------------------ where things are

def _env(name: str) -> str:
    return os.environ.get(name, "").strip() if name else ""


def moves_on() -> bool:
    """False with SENTRAI_MIGRATE=off: files older versions left elsewhere are not moved."""
    return _env("SENTRAI_MIGRATE").lower() not in ("off", "0", "no", "false")


def root() -> Path:
    """The data root: SENTRAI_HOME, else the settings file's folder, else ~/.sentrai."""
    home = _env(ROOT_ENV)
    if home:
        return Path(home).expanduser()
    conf = _env("SENTRAI_CONFIG")
    if conf:
        return Path(conf).expanduser().parent
    return sentrai_env.home_dir()


def _old_places(spec: str, part_dir: Path) -> list[Path]:
    """'part:name' (inside the part's folder), 'root:name', 'mvp:rel' (inside the checkout); a glob lists files."""
    kind, _, rel = spec.partition(":")
    base = {"part": part_dir, "root": root(), "mvp": MVP_DIR}[kind]
    if "*" in rel:
        return [Path(p) for p in sorted(glob.glob(str(base / rel)))]
    return [base / rel]


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return a == b


def _writable(p: Path) -> bool:
    """Whether SentrAI could keep writing at p (a file's folder, or the folder itself)."""
    try:
        return os.access(p if p.is_dir() else p.parent, os.W_OK)
    except OSError:
        return False


def _keep_note(key: str, old: Path, new: Path) -> None:
    """Both places hold something (two checkouts, a backup copied back by hand): the new one is used."""
    _warn(f"keep:{key}", f"{old} is where an older version kept this and {new} is the one in use. Both are "
                         "kept: to use the older one, stop SentrAI and put it in place of the newer one")


def _move(old: Path, new: Path, key: str, companions: tuple[str, ...] = ()) -> bool:
    """Rename old to new: never a copy, never over something already at new. True when new holds it
    now (also when another SentrAI process moved it a moment ago); False, with one warning, if not."""
    try:
        new.parent.mkdir(parents=True, exist_ok=True)
        if new.exists():
            if old.exists():
                _keep_note(key, old, new)
                return False
            return True
        old.rename(new)
    except OSError as exc:
        if new.exists() and not old.exists():  # another part moved it meanwhile
            return True
        hint = " (another drive: move it by hand, or set SENTRAI_HOME on that drive)" \
            if getattr(exc, "errno", None) == 18 or getattr(exc, "winerror", None) == 17 else ""
        _warn(f"move:{key}", f"could not move {old} to {new}: {exc.strerror or exc}{hint}")
        return False
    for suffix in companions:
        c_old, c_new = old.with_name(old.name + suffix), new.with_name(new.name + suffix)
        if c_old.exists() and not c_new.exists():
            try:
                c_old.rename(c_new)
            except OSError as exc:
                _warn(f"move:{key}{suffix}", f"could not move {c_old} with {new.name} ({exc.strerror or exc})")
    moved.append((old, new))
    _warn(f"moved:{key}", f"moved {old} to {new}")
    return True


def _seed(entry: Entry, new: Path) -> None:
    """A new folder starts with the files that ship with SentrAI (Scout's example trails)."""
    if not entry.seed or new.exists():
        return
    try:
        new.mkdir(parents=True, exist_ok=True)
        for src in _old_places(entry.seed, new):
            if src.is_file() and not (new / src.name).exists():
                shutil.copyfile(src, new / src.name)
    except OSError as exc:
        _warn(f"seed:{entry.key}", f"could not start {new} with the examples ({exc.strerror or exc})")


def part_dir(part: str, base: Path | None = None, migrate: bool = True) -> Path:
    """The folder a part writes: base when given, the folder of its anchor variable when that is set
    (SENTRAI_DB places core/, SENTRAI_SCOUT_SOURCES scout/ ...), else <root>/<part>."""
    if base is not None:
        return Path(base)
    p = PARTS[part]
    if part == "root":
        return root()
    anchor = _env(p.anchor_env)
    if anchor:
        return Path(anchor).expanduser().parent
    d = root() / part
    if migrate and moves_on():
        for spec in p.old_dirs:
            for old in _old_places(spec, d):
                if not old.is_dir() or _same(old, d):
                    continue
                if d.exists():
                    _keep_note(part, old, d)
                    continue
                return d if _move(old, d, part) or not _writable(old) else old
    return d


def path(key: str, base: Path | None = None, migrate: bool = True) -> Path:
    """Where one entry lives on this machine. ``base`` is the part's folder when the caller knows it
    (the core passes its database's folder, so Settings(db_path=...) keeps everything together).
    With ``migrate`` the file is first moved from where an older version kept it."""
    return _resolve(key, base, migrate, seed=migrate)


def _resolve(key: str, base: Path | None, migrate: bool, seed: bool) -> Path:
    e = ENTRIES[key]
    value = _env(e.env)
    if value:
        return Path(value).expanduser()
    near = _env(e.near)
    d = Path(near).expanduser().parent if near and base is None else part_dir(e.part, base, migrate)
    new = d.joinpath(*e.rel.split("/")) if e.rel else d
    if migrate and not new.exists():
        if seed:
            _seed(e, new)  # a folder that starts with the files SentrAI ships (made first: the moves below land in it)
        for spec in e.old if moves_on() else ():
            olds = [o for o in _old_places(spec, d) if o.exists() and not _same(o, new)]
            if not olds:
                continue
            if "*" in spec:  # loose files into a folder (old trails): each one on its own, examples stay
                mine = [o for o in olds if not o.name.startswith("example-")]
                if mine:
                    _seed(e, new)  # the folder is made here, so it starts with the examples like any new one
                for o in mine:
                    _move(o, new / o.name, f"{key}:{o.name}")
                continue
            if not _move(olds[0], new, key, e.companions) and _writable(olds[0]):
                return olds[0]  # still in use where it was (a file held open, another drive): nothing lost
            break
    elif migrate and moves_on():  # in place already: an older copy left elsewhere is named, never used
        for spec in e.old:
            olds = [] if "*" in spec else [o for o in _old_places(spec, d) if o.exists() and not _same(o, new)]
            if olds:
                _keep_note(key, olds[0], new)
                break
    return new


def default(key: str, base: Path | None = None) -> Path:
    """Where an entry goes when its own variable is not set (the wizard's default for the logs folder)."""
    e = ENTRIES[key]
    d = part_dir(e.part, base, migrate=False)
    return d.joinpath(*e.rel.split("/")) if e.rel else d


def own_dirs(base: Path | None = None) -> list[Path]:
    """SentrAI's own data folders on this machine (quarantine, backups, restores, archive, trails),
    wherever their variables put them, for a threat scan to skip: they hold what was found and copies
    of scanned files. Not the logs folder (an input) nor a part's whole folder (a variable can put
    that anywhere; its own files are not ones a scan reads). Moves nothing."""
    return list(dict.fromkeys(_resolve(e.key, base if e.part == "core" else None, migrate=False, seed=False)
                              for e in ENTRIES.values() if e.kind == "dir" and e.part != "root"))


def migrate_all(base: Path | None = None) -> list[tuple[Path, Path]]:
    """Move every file from the place an older version used (folders are not created or filled).
    Returns the moves made by this process."""
    for name in PARTS:
        if name != "root":
            part_dir(name, base if name == "core" else None)
    for key in ENTRIES:
        _resolve(key, base if key.startswith("core.") else None, migrate=True, seed=False)
    return list(moved)


# ------------------------------------------------------------------ the map

def describe(base: Path | None = None) -> list[dict[str, Any]]:
    """One row per entry: where it is on this machine, whether it exists, what set it. Moves nothing."""
    rows = []
    for e in ENTRIES.values():
        p = _resolve(e.key, base if e.part == "core" else None, migrate=False, seed=False)
        rows.append({"key": e.key, "part": e.part, "agent": e.agent, "what": e.what, "path": str(p),
                     "exists": p.exists(), "kind": e.kind, "env": e.env, "set": bool(_env(e.env)),
                     "optional": e.optional})
    return rows


def root_source() -> str:
    if _env(ROOT_ENV):
        return f"{ROOT_ENV}"
    if _env("SENTRAI_CONFIG"):
        return "the folder of SENTRAI_CONFIG"
    return f"the default (set {ROOT_ENV} to move it)"


def index_markdown(base: Path | None = None) -> str:
    lines = ["# SentrAI data on this machine", "",
             f"Root: `{root()}` ({root_source()}). Written {time.strftime('%Y-%m-%d %H:%M')} by "
             "`python sentrai_paths.py index`; every part moves its own files here the first time it starts.",
             "Each part writes only its own folder; on a server the core's folder is readable by the core alone.", "",
             "| Part | Owner | What | Where | Set with |", "| --- | --- | --- | --- | --- |"]
    for r in describe(base):
        written = r["exists"] or r["key"] == "index"  # this file, about to be written
        where = f"`{r['path']}`" + ("" if written else " (not yet)" if not r["optional"] else " (not used)")
        var = f"`{r['env']}`" + (" (set)" if r["set"] else "") if r["env"] else ""
        lines.append(f"| {r['part']} | {r['agent']} | {r['what']} | {where} | {var} |")
    lines += ["", "Elsewhere:", ""] + [f"- {x}" for x in ELSEWHERE] + [""]
    return "\n".join(lines)


def write_index(base: Path | None = None) -> Path | None:
    """INDEX.md in the root; None when the root cannot be written (a sandboxed service)."""
    target = path("index", migrate=False)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(index_markdown(base), encoding="utf-8")
        return target
    except OSError as exc:
        _warn("index", f"could not write {target} ({exc.strerror or exc})")
        return None


def _table(rows: list[dict[str, Any]]) -> str:
    out = [f"SentrAI data root: {root()}  ({root_source()})", ""]
    width = max(len(r["key"]) for r in rows)
    for r in rows:
        mark = "" if r["exists"] else "   (not yet)" if not r["optional"] else "   (not used)"
        var = f"   [{r['env']}{' set' if r['set'] else ''}]" if r["env"] else ""
        out.append(f"{r['key']:<{width}}  {r['path']}{mark}{var}")
        out.append(f"{'':<{width}}  {r['agent']}: {r['what']}")
    out += ["", "Elsewhere:"] + [f"  {x}" for x in ELSEWHERE]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "map"
    if cmd in ("-h", "--help", "help") or cmd not in ("map", "index", "migrate", "json"):
        print(__doc__.split("The root is")[0].rstrip())
        return 0 if cmd in ("-h", "--help", "help") else 2
    sys.path.insert(0, str(MVP_DIR))
    import sentrai_config  # noqa: E402  (here, not at the top: it imports this module)
    sentrai_config.load()  # the saved settings name the logs folder
    if cmd in ("index", "migrate"):
        if not moves_on():
            print("SENTRAI_MIGRATE is off: files older versions left elsewhere stay where they are", file=sys.stderr)
        done = migrate_all()
        for old, new in done:
            print(f"moved {old} -> {new}")
        if cmd == "migrate":
            print("nothing to move" if not done else f"{len(done)} moved")
            return 0
        target = write_index()
        if target is None:
            return 1
        print(f"wrote {target}")
        return 0
    rows = describe()
    print(json.dumps(rows, indent=1) if cmd == "json" else _table(rows))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(MVP_DIR))
    import sentrai_paths as _module  # the copy sentrai_config imports, so both share one state
    sys.exit(_module.main())
