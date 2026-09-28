"""Trails: recordings of how a person found the security logs on a system.

An experienced technician runs ``python -m scout record`` and browses with a few simple
commands. Every step (which folder they opened, which file they looked inside, which file
they chose and why) is saved as one JSON line in ``scout/trails/``. Scout's confirmed
finds are saved the same way. Scout reads the trails before each search, so it follows
the same route an expert would and skips the dead ends they already ruled out.
"""
from __future__ import annotations

import json
import shlex
import time
from pathlib import Path
from typing import Callable

from .tools import SafeFS

TRAILS_DIR = Path(__file__).resolve().parent / "trails"
LAYERS = ("web", "db", "os", "network", "cloud")
MAX_LESSON_CHARS = 6000


class Trail:
    def __init__(self, goal: str, actor: str, trails_dir: Path = TRAILS_DIR) -> None:
        trails_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.path = trails_dir / f"{stamp}-{actor}.jsonl"
        self.log({"action": "goal", "text": goal, "actor": actor})

    def log(self, step: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": time.time(), **step}) + "\n")


def load_trails(trails_dir: Path = TRAILS_DIR) -> list[list[dict]]:
    out = []
    for f in sorted(trails_dir.glob("*.jsonl"), reverse=True):  # newest first
        steps = []
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                steps.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if any(s.get("action") == "pick" for s in steps):  # only trails that found something teach
            out.append(steps)
    return out


def lessons(trails_dir: Path = TRAILS_DIR, budget: int = MAX_LESSON_CHARS) -> str:
    """The trails condensed into short worked examples for Scout's prompt, newest first."""
    parts: list[str] = []
    used = 0
    for steps in load_trails(trails_dir):
        goal = next((s["text"] for s in steps if s.get("action") == "goal"), "?")
        actor = next((s.get("actor") for s in steps if s.get("action") == "goal"), "?")
        route = [f"{s['action']} {s.get('path', s.get('pattern', ''))}".strip()
                 for s in steps if s.get("action") in ("ls", "peek", "find")]
        picks = [f"- chose {s['path']} as {s['layer']} because {s.get('why', '')}"
                 for s in steps if s.get("action") == "pick"]
        notes = [f"- note: {s['text']}" for s in steps if s.get("action") == "note"]
        block = (f"Goal ({actor}): {goal}\nRoute: " + " -> ".join(route[-15:]) + "\n"
                 + "\n".join(picks + notes))
        if used + len(block) > budget:
            break
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


HELP = """Commands:
  ls [folder]              list a folder (default: current)
  cd <folder>              move into a folder
  peek <file> [lines]      show the last lines of a file
  head <file> [lines]      show the first lines of a file
  find <pattern> [folder]  find files by name, e.g. find *auth*.log
  pick <file> <layer> <why...>   this file has security events (layer: web, db, os, network, cloud)
  note <text>              tip for next time, e.g. "IIS logs live under inetpub"
  quit"""


def record(fs: SafeFS, goal: str, actor: str = "human", ask: Callable[[str], str] = input,
           say: Callable[[str], None] = print, trails_dir: Path = TRAILS_DIR) -> Path:
    """Interactive recorder: a tiny read-only shell that logs every step."""
    trail = Trail(goal, actor, trails_dir)
    cwd = fs.roots[0]
    say(f"Recording to {trail.path.name}. Browse to where the security logs are.\n{HELP}")
    while True:
        try:
            parts = shlex.split(ask(f"{cwd}> "))
        except (EOFError, KeyboardInterrupt):
            break
        except ValueError as e:
            say(str(e))
            continue
        if not parts:
            continue
        cmd, args = parts[0].lower(), parts[1:]
        try:
            if cmd == "quit":
                break
            if cmd == "ls":
                target = fs.resolve(str(cwd / args[0]) if args else str(cwd))
                say(fs.list_dir(str(target)))
                trail.log({"action": "ls", "path": str(target)})
            elif cmd == "cd" and args:
                target = fs.resolve(str(cwd / args[0]))
                if target.is_dir():
                    cwd = target
                    trail.log({"action": "cd", "path": str(target)})
                else:
                    say(f"{target} is not a folder")
            elif cmd in ("peek", "head") and args:
                target = fs.resolve(str(cwd / args[0]))
                n = int(args[1]) if len(args) > 1 else 20
                say(fs.peek_file(str(target), n, tail=cmd == "peek"))
                trail.log({"action": "peek", "path": str(target)})
            elif cmd == "find" and args:
                under = str(fs.resolve(str(cwd / args[1]))) if len(args) > 1 else str(cwd)
                say(fs.find_files(args[0], under))
                trail.log({"action": "find", "pattern": args[0], "path": under})
            elif cmd == "pick" and len(args) >= 2:
                target = fs.resolve(str(cwd / args[0]))
                layer = args[1].lower()
                if layer not in LAYERS or not target.is_file():
                    say(f"Usage: pick <file> <layer> <why>; layer is one of {', '.join(LAYERS)}")
                    continue
                trail.log({"action": "pick", "path": str(target), "layer": layer, "why": " ".join(args[2:])})
                say(f"Saved: {target} ({layer})")
            elif cmd == "note" and args:
                trail.log({"action": "note", "text": " ".join(args)})
                say("Noted.")
            else:
                say(HELP)
        except (PermissionError, ValueError, OSError) as e:
            say(str(e))
    say(f"Trail saved: {trail.path}")
    return trail.path
