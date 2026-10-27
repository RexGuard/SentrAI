"""Panels are set apart by shading, not outlines: every theme defines the depth variables console.css reads,
and app.py makes its bordered panels through card(), so console.css can find them."""
import re
from pathlib import Path

from sentrai_ui import theme as th

HERE = Path(__file__).resolve().parent.parent


def test_every_theme_defines_depth():
    for name in th.THEMES:
        css = th.css(name)
        for var in ("--card:", "--card-shadow:", "--dots:", "--hatch:"):
            assert var in css, (name, var)


def test_console_css_uses_only_defined_depth_vars():
    css = (HERE / "sentrai_ui" / "console.css").read_text(encoding="utf-8")
    used = set(re.findall(r"var\(--(card|card-shadow|dots|hatch)\)", css))
    assert used and all(f"--{v}:" in th.css("dark") for v in used)


def test_panels_go_through_card():
    # A plain st.container(border=True) would keep Streamlit's outline; only the keyed ones below are styled.
    src = (HERE / "app.py").read_text(encoding="utf-8")
    plain = [m.group(0) for m in re.finditer(r"\.container\([^)]*border=True[^)]*\)", src)
             if "key=" not in m.group(0)]
    assert plain == []
