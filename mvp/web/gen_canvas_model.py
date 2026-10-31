"""Regenerate core/app/canvas_model.py from the Streamlit console's shaping.py.

The overview canvas needs about 50 of shaping.py's functions and constants. Rather than keep two hand-written
copies, this takes them (and everything they use) as they are, so the core can serve the canvas without pandas.
Run it from mvp/ after changing one of them:  python web/gen_canvas_model.py
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROOTS = ["flow_map_data", "flow_canvas_data", "clean_canvas_doc", "check_block_settings", "setting_specs",
         "panel_machines", "machine", "check_limits", "LIMIT_FIELDS", "limits_map_data",
         "routing_editor_data", "routing_from_editor"]
HEAD = '''"""The overview canvas's model: what every block shows, its settings, the wires and the saved layout.

GENERATED from dashboard/sentrai_ui/shaping.py (the Streamlit console's functions, unchanged) by taking the
functions and constants the canvas needs, so the core can serve the canvas without pandas or plotly. When
shaping.py changes one of them, regenerate this file the same way.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable

'''

src = (ROOT / "dashboard/sentrai_ui/shaping.py").read_text(encoding="utf-8")
lines = src.splitlines(keepends=True)
defs: dict[str, ast.AST] = {}
for n in ast.parse(src).body:
    if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
        defs[n.name] = n
    elif isinstance(n, ast.Assign):
        defs.update({t.id: n for t in n.targets if isinstance(t, ast.Name)})
    elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
        defs[n.target.id] = n

need: set[str] = set()
todo = list(ROOTS)
while todo:
    k = todo.pop()
    if k in need or k not in defs:
        continue
    need.add(k)
    todo += [x.id for x in ast.walk(defs[k]) if isinstance(x, ast.Name) and x.id in defs]

nodes = sorted({id(defs[k]): defs[k] for k in need}.values(), key=lambda n: n.lineno)
for n in nodes:
    if any(isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name) and x.value.id in ("pd", "go") for x in ast.walk(n)):
        raise SystemExit(f"{getattr(n, 'name', '?')} uses pandas or plotly: the canvas model cannot take it")


def segment(n: ast.AST) -> str:
    start = n.lineno - 1
    while start > 0 and lines[start - 1].lstrip().startswith("#"):  # the comment lines just above stay with it
        start -= 1
    return "".join(lines[start:n.end_lineno])


(ROOT / "core/app/canvas_model.py").write_text(HEAD + "\n\n".join(segment(n) for n in nodes) + "\n", encoding="utf-8")
print(f"{len(nodes)} definitions written to core/app/canvas_model.py")
