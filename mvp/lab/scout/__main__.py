"""Scout command line (run from mvp/lab).

  python -m scout record --root C:\\ "find the IIS web logs"     an expert shows the way (saved as a trail)
  python -m scout find --root C:\\ "where are the login logs?"   Claude finds them for a novice
  python -m scout list                                          the log files the collector will watch
"""
from __future__ import annotations

import argparse
import getpass
import sys

from . import sources
from .tools import SafeFS
from .trails import Trail, record


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="scout", description="Find security logs for the CactAI collector")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("record", "find"):
        p = sub.add_parser(name)
        p.add_argument("goal", help="what you are looking for, in plain words")
        p.add_argument("--root", action="append", required=True, help="folder Scout may look in (repeatable)")
        p.add_argument("--who", default=getpass.getuser(), help="your name, saved with the trail")
    sub.add_parser("list")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for s in sources.load() or []:
            print(f"{s['layer']:8} {s['path']}  ({s.get('why', '')})")
        return
    fs = SafeFS(args.root)
    if args.cmd == "record":
        record(fs, args.goal, actor=args.who)
        return

    from .agent import Scout  # needs the anthropic package and a key

    scout = Scout(fs)
    proposals = scout.run(args.goal)
    trail = Trail(args.goal, "scout")
    for step in scout.steps:
        trail.log(step)
    if not proposals:
        print("Scout did not propose any log files.")
    for p in proposals:
        print(f"\n{p['path']}\n  layer: {p['layer']}   why: {p['why']}")
        if input("Watch this file? [y/N] ").strip().lower().startswith("y"):
            sources.add(p, args.who)
            trail.log({"action": "pick", **p, "confirmed_by": args.who})
            print("  Added. Restart the collector to start watching it.")
        else:
            reason = input("  Why not? (helps Scout learn, optional) ").strip()
            trail.log({"action": "note", "text": f"not {p['path']}: {reason or 'rejected'}"})
    print(f"\nTrail saved to {trail.path.name}; Scout reads it next time.")


if __name__ == "__main__":
    sys.exit(main())
