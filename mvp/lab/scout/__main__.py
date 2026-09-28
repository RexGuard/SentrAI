"""Scout command line (run from mvp/lab).

  python -m scout record --root C:\\ "find the IIS web logs"     an expert shows the way (saved as a trail)
  python -m scout find --root C:\\ "where are the login logs?"   the AI finds them for a novice
  python -m scout list                                          the log files the collector will watch
  python -m scout pending                                       proposals waiting for a yes or no
  python -m scout approve <id or path> [--layer os]             watch a proposed file
  python -m scout reject <id or path> [--why "a backup"]        drop a proposal

With no terminal attached (a service, cron, ssh without -t) or with --no-input, `find` never
waits for keyboard answers: Scout decides on its own and leaves its proposals pending, to be
approved on the dashboard's Collector page or with `approve`. Every proposal is saved as soon as
Scout makes it, so stopping Scout part way keeps what it found.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from . import sources
from .tools import SafeFS
from .trails import LAYERS, Trail, record

NO_TECHNICIAN = ("(No technician is at a terminal right now. Decide from what you can see, and name this "
                 "open question in your summary so a person can check it.)")


def has_terminal() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="scout", description="Find security logs for the CactAI collector")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("record", "find"):
        p = sub.add_parser(name)
        p.add_argument("goal", help="what you are looking for, in plain words")
        p.add_argument("--root", action="append", required=True, help="folder Scout may look in (repeatable)")
        p.add_argument("--who", default=getpass.getuser(), help="your name, saved with the trail")
        if name == "find":
            p.add_argument("--no-input", action="store_true",
                           help="never ask at the keyboard; leave proposals pending (automatic without a terminal)")
    sub.add_parser("list")
    sub.add_parser("pending")
    p = sub.add_parser("approve")
    p.add_argument("key", help="proposal id or file path (see `pending`)")
    p.add_argument("--layer", choices=LAYERS)
    p.add_argument("--who", default=getpass.getuser())
    p = sub.add_parser("reject")
    p.add_argument("key", help="proposal id or file path (see `pending`)")
    p.add_argument("--why", default="", help="why not (helps Scout learn)")
    p.add_argument("--who", default=getpass.getuser())
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for s in sources.load() or []:
            print(f"{s['layer']:8} {s['path']}  ({s.get('why', '')})")
        return
    if args.cmd == "pending":
        waiting = sources.load_pending()
        if not waiting:
            print("No Scout proposals waiting.")
        for s in waiting:
            print(f"{s['id']}  {s['layer']:8} {s['path']}\n    why: {s.get('why', '')}")
        return
    if args.cmd in ("approve", "reject"):
        goal = (sources.find_pending(args.key) or {}).get("goal") or "find security logs"
        try:
            if args.cmd == "approve":
                e = sources.approve(args.key, args.who, args.layer)
                print(f"Watching {e['path']} as {e['layer']}. The collector picks it up within a few seconds.")
                _note(goal, {"action": "pick", **e, "confirmed_by": args.who})
            else:
                e = sources.reject(args.key)
                print(f"Dropped {e['path']}.")
                _note(goal, {"action": "note", "text": f"not {e['path']}: {args.why or 'rejected'}"})
        except KeyError as e:
            sys.exit(str(e).strip("'\""))
        return
    fs = SafeFS(args.root)
    if args.cmd == "record":
        record(fs, args.goal, actor=args.who)
        return

    from .agent import Scout, cactai_llm  # needs an AI key (python cactai_config.py setup, section 5)

    interactive = not args.no_input and has_terminal()
    try:
        scout = Scout(fs, ask=input if interactive else (lambda _q: NO_TECHNICIAN),
                      on_propose=lambda p: sources.propose(p, "Scout", args.goal))
    except Exception as e:  # no key, or the provider's package is missing
        sys.exit(f"Scout cannot start: {e}")
    trail = Trail(args.goal, "scout")
    try:
        proposals = scout.run(args.goal)
    except cactai_llm.LLMError as e:  # the AI service failed part way: keep what was found
        print(f"Scout stopped early: {e}")
        proposals = scout.proposals
    finally:  # a stop part way still keeps the route and the saved proposals
        for step in scout.steps:
            trail.log(step)
    if not proposals:
        print("Scout did not propose any log files.")
    for p in proposals:
        print(f"\n{p['path']}\n  layer: {p['layer']}   why: {p['why']}")
        if not interactive:
            continue
        try:
            yes = input("Watch this file? [y/N] ").strip().lower().startswith("y")
            reason = "" if yes else input("  Why not? (helps Scout learn, optional) ").strip()
        except EOFError:  # the terminal went away: leave the rest pending
            interactive = False
            continue
        if yes:
            sources.approve(p["path"], args.who)
            trail.log({"action": "pick", **p, "confirmed_by": args.who})
            print("  Added. The collector starts watching it within a few seconds.")
        else:
            sources.drop_pending(p["path"])
            trail.log({"action": "note", "text": f"not {p['path']}: {reason or 'rejected'}"})
    waiting = [p for p in proposals if sources.find_pending(p["path"])]
    if waiting:
        print(f"\n{len(waiting)} proposal(s) wait for a person: approve them on the dashboard's Collector page, "
              f"or with `python -m scout approve <id>` (see `python -m scout pending`).")
    print(f"\nTrail saved to {trail.path.name}; Scout reads it next time.")


def _note(goal: str, step: dict) -> None:
    """A yes or no given after the search still teaches Scout: save it as a short trail."""
    Trail(goal, "scout").log(step)


if __name__ == "__main__":
    sys.exit(main())
