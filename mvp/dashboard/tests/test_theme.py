"""Black / White themes, accent colours and where the look is saved."""
import sys
from pathlib import Path

import pytest

from sentrai_ui import shaping as sh
from sentrai_ui import theme as th

sys.path.append(str(Path(__file__).resolve().parents[2]))
import sentrai_config as cfg  # noqa: E402


@pytest.mark.parametrize("theme", list(th.THEMES))
@pytest.mark.parametrize("accent", [*th.ACCENTS, "#ffd400", "#123456", "#fff"])
def test_brand_text_and_button_text_stay_readable(theme, accent):
    p = th.palette(theme, accent)
    assert th.contrast(p["brand"], p["bg"]) >= 4.5
    assert th.contrast(p["ink"], p["surface"]) >= 7
    assert th.contrast(p["on-brand"], p["brand-fill"]) >= 3  # bold button text
    assert th.contrast(p["on-brand"], p["brand-fill-hover"]) >= 3  # same text while hovered
    assert p["brand-fill-hover"] != p["brand-fill"]  # and the hover shows


def test_every_primary_button_kind_uses_the_readable_text_colour():
    css = (Path(__file__).resolve().parents[1] / "sentrai_ui" / "console.css").read_text(encoding="utf-8")
    for selector in ('.stButton button[kind="primary"]', '.stFormSubmitButton button[kind="primaryFormSubmit"]',
                     '.stDownloadButton button[kind="primary"]', '.stLinkButton a[kind="primary"]'):
        assert selector in css


@pytest.mark.parametrize("theme", list(th.THEMES))
def test_risk_colours_read_on_cards(theme):
    t = th.THEMES[theme]
    for color in t.risk.values():
        assert th.contrast(color, t.colors["surface"]) >= 3


def test_mono_follows_the_ink():
    assert th.palette("dark", "mono")["brand-fill"] == th.THEMES["dark"].colors["ink"]
    assert th.palette("light", "mono")["brand-fill"] == th.THEMES["light"].colors["ink"]


def test_bad_values_fall_back():
    assert th.parse_hex("#ABC") == "#aabbcc"
    assert th.parse_hex("red") is None
    assert th.palette("purple", "nonsense") == th.palette(th.DEFAULT_THEME, th.DEFAULT_ACCENT)


def test_risk_like_accents_are_flagged():
    assert th.risk_like("#e5484d") == "red"
    assert th.risk_like("#e8b34a") == "amber"
    assert th.risk_like("#22c55e") == "green"
    assert th.risk_like("#8057f0") == th.risk_like("#3b82f6") == th.risk_like("") == ""


def test_streamlit_options_cover_both_themes():
    assert th.streamlit_options("light")["theme.base"] == "light"
    assert th.streamlit_options("dark", "violet")["theme.primaryColor"] == "#8057f0"


def test_set_palette_switches_chart_colours():
    try:
        sh.set_palette(th.chart_colors("light"))
        assert sh.BAND_COLORS["critical"] == th.THEMES["light"].risk["critical"]
        assert th.contrast(sh.AGENTS["Watchtower"][1], th.THEMES["light"].colors["surface"]) >= 4.5
    finally:
        sh.set_palette(th.chart_colors("dark"))


def test_appearance_is_kept_apart_from_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    assert cfg.appearance() == {}
    cfg.save_appearance("light", "#14b8a6")
    cfg.save({"SENTRAI_OPERATOR": "erick"})  # saving the settings keeps the look
    assert cfg.appearance() == {"theme": "light", "accent": "#14b8a6"}
    assert "theme" not in cfg.read() and cfg.read()["SENTRAI_OPERATOR"] == "erick"


def test_agent_colours_never_look_like_risk_colours():
    """Green, amber and red mean risk only, so no agent name is painted in them."""
    for name, color in sh._AGENT_BASE.items():
        assert not th.risk_like(color), name


@pytest.mark.parametrize("theme", list(th.THEMES))
def test_faint_text_meets_aa(theme):
    c = th.THEMES[theme].colors
    for surface in ("bg", "surface", "surface-2"):
        assert th.contrast(c["ink-faint"], c[surface]) >= 4.5, surface


def test_bundled_fonts_inline_and_reach_streamlit():
    faces = th.font_css()
    assert faces.count("@font-face") == 6 and "IBM Plex Sans" in faces and "JetBrains Mono" in faces
    opts = th.streamlit_options("dark")
    assert opts["theme.font"].startswith("'IBM Plex Sans'") and opts["theme.codeFont"].startswith("'JetBrains Mono'")
    assert "--mono:'JetBrains Mono'" in th.css("light")
