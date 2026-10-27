"""The console's icons: Lucide, bundled as a font under the names app.py and shaping.py use."""
import ast
import json
import re
from pathlib import Path

from sentrai_ui import shaping as sh
from sentrai_ui import theme as th

DASH = Path(__file__).resolve().parents[1]
ICONS = DASH / "sentrai_ui" / "icons"
NAMES = {k for k in json.loads((ICONS / "icons.json").read_text(encoding="utf-8")) if not k.startswith("_")}
HINT = "add it to sentrai_ui/icons/icons.json and rebuild the font (icons/README.md)"


def names_in_source(path: Path) -> set[str]:
    """Every icon name a page script refers to: ':material/x:' markers, the names handed to icon(), section(),
    empty() and fold() (and their defaults), the first field of PAGES and the second of INTEGRATION_KINDS."""
    src = path.read_text(encoding="utf-8")
    found = set(re.findall(r":material/([a-z0-9_]+):", src))
    tree = ast.parse(src)
    helpers = {"icon": 0, "section": 2, "empty": 1, "fold": 2}

    def take(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
            found.add(node.value)
        elif isinstance(node, ast.IfExp):
            take(node.body)
            take(node.orelse)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if fn in helpers:
                if len(node.args) > helpers[fn]:
                    take(node.args[helpers[fn]])
                for kw in node.keywords:
                    if kw.arg == "ico":
                        take(kw.value)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in helpers:
            fns = [node] if isinstance(node, ast.FunctionDef) else [n for n in node.body if isinstance(n, ast.FunctionDef)]
            for fn in fns:
                for arg, default in zip(reversed(fn.args.args), reversed(fn.args.defaults)):
                    if arg.arg == "ico":
                        take(default)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("PAGES", "INTEGRATION_KINDS")
                                                   for t in node.targets):
            field = 0 if node.targets[0].id == "PAGES" else 1
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Tuple) and len(sub.elts) > field:
                    take(sub.elts[field])
    return found


def test_every_icon_the_pages_use_is_in_the_font():
    used = names_in_source(DASH / "app.py")
    assert len(used) > 80  # the scan found them (a refactor of the helpers would empty it silently)
    assert used <= NAMES, f"icon names missing from the font: {sorted(used - NAMES)}; {HINT}"


def test_every_icon_shaping_draws_is_in_the_font():
    used = {ico for ico, _ in sh.AGENTS.values()}
    feed = sh.build_activity_feed([{"seq": 1, "ts": "2026-10-27T01:00:00+08:00", "type": "unknown_type", "data": {}}])
    used |= {e["icon"] for e in feed}  # the fallback icon for an agent the feed does not know
    base = {"name": "A", "place": "Local", "online": True, "band": "green", "index": 12.0, "threshold": 80.0,
            "monitor_only": False, "services": {}}
    machines = [base, {**base, "monitor_only": True}, {**base, "online": False}, {**base, "waiting": True}]
    for opened in (None, True, False):
        html = sh.machine_rows_html(machines, opened)
        used |= set(re.findall(r'class="[^"]*\bmi\b[^"]*"[^>]*>([a-z0-9_]+)<', html))
    assert len(used) >= 6
    assert used <= NAMES, f"icon names missing from the font: {sorted(used - NAMES)}; {HINT}"


def test_icon_font_is_bundled_with_its_licence():
    css = th.icon_css()
    assert css.count("@font-face") == 1 and th.ICON_FONT in css
    assert "data:font/woff2;base64,d09GMg" in css  # a real WOFF2 ("wOF2"), inlined
    assert (ICONS / "sentrai-icons.woff2").stat().st_size < 80_000  # a subset, not the whole Lucide set
    licence = (ICONS / "LICENSE").read_text(encoding="utf-8")
    assert "ISC License" in licence and "Lucide" in licence
