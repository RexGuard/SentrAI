"""Console themes: Black or White, plus an accent colour (Mono, a preset, or any custom colour).

Everything the console paints comes from here: the CSS variables console.css reads, Streamlit's own
theme options (buttons, toggles, tables) and the risk / chart colours in shaping.py. The accent is
only ever the brand colour; green, amber and red stay reserved for risk in both themes.

Free of Streamlit imports, so it can be unit tested; app.py applies the result.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_THEME = "dark"
DEFAULT_ACCENT = "mono"


@dataclass(frozen=True)
class Theme:
    label: str
    base: str  # Streamlit's base theme
    colors: dict[str, str]  # neutrals, as CSS variables without the leading --
    risk: dict[str, str]  # band colours, readable on this background
    unknown: str
    grid: str
    glow_alpha: float


THEMES = {
    "dark": Theme("Black", "dark", {
        "bg": "#0a0a0a", "surface": "#141414", "surface-2": "#1b1b1b", "surface-3": "#262626",
        "sidebar": "#0f0f0f", "ink": "#f5f5f5", "ink-soft": "#b3b3b3", "ink-muted": "#8c8c8c",
        "ink-faint": "#666666", "line": "#2e2e2e", "line-soft": "#212121",
    }, {"green": "#4fb67c", "amber": "#e8b34a", "red": "#ec835a", "critical": "#e5484d"},
        "#8c8c8c", "rgba(255,255,255,0.07)", .10),
    "light": Theme("White", "light", {
        "bg": "#fafafa", "surface": "#ffffff", "surface-2": "#f4f4f4", "surface-3": "#e8e8e8",
        "sidebar": "#f4f4f4", "ink": "#0a0a0a", "ink-soft": "#404040", "ink-muted": "#666666",
        "ink-faint": "#8c8c8c", "line": "#dedede", "line-soft": "#ebebeb",
    }, {"green": "#15803d", "amber": "#a16207", "red": "#c2410c", "critical": "#dc2626"},
        "#6b6b6b", "rgba(0,0,0,0.08)", .07),
}

# Preset accents. Mono uses the theme's own ink (white on Black, black on White).
# Violet is the logo's colour. No greens, ambers or reds: those mean risk.
ACCENTS = {
    "mono": ("Mono", ""),
    "violet": ("Violet", "#8057f0"),
    "blue": ("Blue", "#3b82f6"),
}
CUSTOM = "custom"
_HEX = re.compile(r"^#?([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$")


# ---------------------------------------------------------------- colour maths

def parse_hex(value: str) -> str | None:
    """'#AbC' or 'aabbcc' -> '#aabbcc'; None when it is not a colour."""
    m = _HEX.match((value or "").strip())
    if not m:
        return None
    h = m.group(1).lower()
    return "#" + (h if len(h) == 6 else "".join(c * 2 for c in h))


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb: tuple[float, float, float]) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c))):02x}" for c in rgb)


def mix(a: str, b: str, amount: float) -> str:
    """`amount` of colour a over colour b."""
    return _hex(tuple(x * amount + y * (1 - amount) for x, y in zip(_rgb(a), _rgb(b))))


def luminance(hex_color: str) -> float:
    def lin(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in _rgb(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def readable(color: str, background: str, target: float = 4.5) -> str:
    """The colour, nudged towards black or white until text in it reads on the background."""
    toward = "#ffffff" if luminance(background) < 0.2 else "#000000"
    step = 0.0
    out = color
    while contrast(out, background) < target and step < 1:
        step += 0.04
        out = mix(toward, color, step)
    return out


def rgba(hex_color: str, alpha: float) -> str:
    r, g, b = _rgb(hex_color)
    return f"rgba({r},{g},{b},{alpha})"


# ---------------------------------------------------------------- palette

def accent_hex(accent: str) -> str:
    """'' for Mono, else the accent's colour. Unknown names fall back to Mono."""
    if accent in ACCENTS:
        return ACCENTS[accent][1]
    return parse_hex(accent) or ""


def palette(theme: str = DEFAULT_THEME, accent: str = DEFAULT_ACCENT) -> dict[str, str]:
    """Every console colour for a theme and accent, as {css variable name: value}."""
    t = THEMES.get(theme, THEMES[DEFAULT_THEME])
    c = dict(t.colors)
    bg, ink = c["bg"], c["ink"]
    fill = accent_hex(accent)
    if not fill:  # Mono: the accent is the ink itself
        c |= {"brand": ink, "brand-2": c["ink-soft"], "brand-fill": ink, "on-brand": bg,
              "brand-soft": c["surface-3"], "brand-line": mix(ink, bg, .28), "glow": rgba(ink, t.glow_alpha / 3)}
    else:
        on = "#ffffff" if contrast("#ffffff", fill) >= contrast("#0a0a0a", fill) else "#0a0a0a"
        c |= {"brand": readable(fill, bg), "brand-2": readable(fill, bg, 3), "brand-fill": fill, "on-brand": on,
              "brand-soft": mix(fill, c["surface"], .14), "brand-line": mix(fill, c["surface"], .42),
              "glow": rgba(fill, t.glow_alpha)}
    c |= {k: v for k, v in t.risk.items()} | {"green-line": mix(t.risk["green"], c["surface"], .4),
                                              "unknown": t.unknown}
    return c


def css(theme: str = DEFAULT_THEME, accent: str = DEFAULT_ACCENT) -> str:
    """A :root block of CSS variables for console.css."""
    t = THEMES.get(theme, THEMES[DEFAULT_THEME])
    body = "".join(f"--{k}:{v};" for k, v in palette(theme, accent).items())
    return f":root{{{body}color-scheme:{t.base};}}"


def streamlit_options(theme: str = DEFAULT_THEME, accent: str = DEFAULT_ACCENT) -> dict[str, str]:
    """Streamlit [theme] options, so its own widgets match the console."""
    t = THEMES.get(theme, THEMES[DEFAULT_THEME])
    p = palette(theme, accent)
    return {
        "theme.base": t.base,
        "theme.primaryColor": p["brand-fill"],
        "theme.backgroundColor": p["bg"],
        "theme.secondaryBackgroundColor": p["surface"],
        "theme.textColor": p["ink"],
        "theme.linkColor": p["brand"],
        "theme.borderColor": p["line"],
        "theme.dataframeBorderColor": p["line-soft"],
        "theme.dataframeHeaderBackgroundColor": p["surface-2"],
        "theme.greenColor": t.risk["green"],
        "theme.redColor": t.risk["critical"],
        "theme.orangeColor": t.risk["red"],
        "theme.yellowColor": t.risk["amber"],
        "theme.sidebar.backgroundColor": p["sidebar"],
        "theme.sidebar.secondaryBackgroundColor": p["surface"],
    }


def chart_colors(theme: str = DEFAULT_THEME) -> dict[str, object]:
    """Colours shaping.py uses for chips, charts and agent names."""
    t = THEMES.get(theme, THEMES[DEFAULT_THEME])
    c = t.colors
    return {"band": dict(t.risk), "unknown": t.unknown, "surface": c["surface"], "text": c["ink"],
            "text_secondary": c["ink-soft"], "text_muted": c["ink-muted"], "grid": t.grid,
            "readable": lambda color: readable(color, c["surface"])}


def risk_like(hex_color: str) -> str:
    """'red', 'amber' or 'green' when an accent could be mistaken for a risk colour, else ''."""
    import colorsys

    if not parse_hex(hex_color or ""):
        return ""
    r, g, b = (c / 255 for c in _rgb(parse_hex(hex_color)))
    hue, light, sat = colorsys.rgb_to_hls(r, g, b)
    if sat < .35 or light < .15 or light > .9:
        return ""
    deg = hue * 360
    if deg < 22 or deg >= 340:
        return "red"
    if deg < 60:
        return "amber"
    if 75 <= deg < 165:
        return "green"
    return ""
