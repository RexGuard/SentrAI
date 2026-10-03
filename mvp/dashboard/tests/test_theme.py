"""Black / White themes, accent colours and where the look is saved."""
import sys
from pathlib import Path

import pytest

from cactai_ui import shaping as sh
from cactai_ui import theme as th

sys.path.append(str(Path(__file__).resolve().parents[2]))
import cactai_config as cfg  # noqa: E402


@pytest.mark.parametrize("theme", list(th.THEMES))
@pytest.mark.parametrize("accent", [*th.ACCENTS, "#ffd400", "#123456", "#fff"])
def test_brand_text_and_button_text_stay_readable(theme, accent):
    p = th.palette(theme, accent)
    assert th.contrast(p["brand"], p["bg"]) >= 4.5
    assert th.contrast(p["ink"], p["surface"]) >= 7
    assert th.contrast(p["on-brand"], p["brand-fill"]) >= 3  # bold button text


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
    monkeypatch.setenv("CACTAI_CONFIG", str(tmp_path / "config.json"))
    assert cfg.appearance() == {}
    cfg.save_appearance("light", "#14b8a6")
    cfg.save({"CACTAI_OPERATOR": "erick"})  # saving the settings keeps the look
    assert cfg.appearance() == {"theme": "light", "accent": "#14b8a6"}
    assert "theme" not in cfg.read() and cfg.read()["CACTAI_OPERATOR"] == "erick"
