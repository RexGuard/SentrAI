"""Build sentrai-icons.woff2: Lucide icons as a ligature font that answers to Material Symbols names.

Streamlit draws every widget icon (`icon=":material/…:"`, chat avatars, expander arrows, its own menus)
as text in the "Material Symbols Rounded" font, with the icon's name as the ligature. The console ships
Lucide under that same family name, with the same metrics and the names in icons.json as ligatures, so
every icon in the console changes at once and app.py keeps its icon names. A name the font does not know
draws as one "unknown" glyph (a dashed square) instead of leaking the name as text.

Run from this folder, with fontTools, brotli and uharfbuzz installed and a copy of the lucide-static npm package:

    pip install fonttools brotli uharfbuzz
    npm pack lucide-static@1.55.0 && tar -xzf lucide-static-1.55.0.tgz
    python build_font.py package

The build shapes every name with HarfBuzz (the shaper Chrome and Firefox use) before it writes anything.

Only the .woff2, icons.json, LICENSE and README.md are committed.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from fontTools.feaLib.builder import addOpenTypeFeaturesFromString
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.recordingPen import DecomposingRecordingPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont

HERE = Path(__file__).resolve().parent
FAMILY = "SentrAI Icons"
# Material Symbols Rounded, as Streamlit bundles it: 24 grid units of 40, the icon box sitting on the
# baseline, 0.1 em of line space above and below. Same numbers, so a Lucide icon lands exactly where the
# Material one did and no CSS needs retuning.
UPM = 960
ASCENT, DESCENT = 1056, -96
WIN_ASCENT, WIN_DESCENT = 1062, 91

DIGITS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
LETTERS = [chr(c) for c in range(ord("a"), ord("z") + 1)]
COMPONENTS = {c: c for c in LETTERS} | {str(n): name for n, name in enumerate(DIGITS)} | {"_": "underscore"}


def glyph_name(lucide: str) -> str:
    return "i_" + re.sub(r"[^a-z0-9]", "_", lucide)


def main(package: Path) -> None:
    mapping = json.loads((HERE / "icons.json").read_text(encoding="utf-8"))
    unknown = mapping.pop("_unknown")
    names = {k: v for k, v in mapping.items() if not k.startswith("_")}
    bad = [k for k in names if not re.fullmatch(r"[a-z0-9_]+", k) or len(k) < 2]
    if bad:
        sys.exit(f"icon names must be 2+ of a-z, 0-9 and _: {bad}")

    src = TTFont(package / "font" / "lucide.ttf")
    version = json.loads((package / "package.json").read_text(encoding="utf-8"))["version"]
    codepoints = json.loads((package / "font" / "codepoints.json").read_text(encoding="utf-8"))
    cmap, glyph_set = src.getBestCmap(), src.getGlyphSet()
    missing = sorted({v for v in [*names.values(), unknown] if v not in codepoints})
    if missing:
        sys.exit(f"not in lucide-static {version}: {missing}")
    scale = UPM / src["head"].unitsPerEm

    glyphs, metrics = {}, {}

    def empty(name: str, advance: int = 0) -> None:
        glyphs[name] = TTGlyphPen(None).glyph()
        metrics[name] = (advance, 0)

    def lucide(name: str, lucide_name: str) -> None:
        rec = DecomposingRecordingPen(glyph_set)
        glyph_set[cmap[codepoints[lucide_name]]].draw(rec)
        pen, bounds = TTGlyphPen(None), BoundsPen(None)
        rec.replay(TransformPen(pen, (scale, 0, 0, scale, 0, 0)))
        rec.replay(TransformPen(bounds, (scale, 0, 0, scale, 0, 0)))
        glyphs[name] = pen.glyph()
        metrics[name] = (UPM, round(bounds.bounds[0]) if bounds.bounds else 0)

    empty(".notdef", UPM)
    empty("blank")
    for g in COMPONENTS.values():  # the letters of a name take no room: a known name is one glyph wide
        empty(g)
    icons = {glyph_name(v): v for v in names.values()}
    for g, lucide_name in sorted(icons.items()):
        lucide(g, lucide_name)
    lucide("unknown", unknown)

    order = [".notdef", "blank", *COMPONENTS.values(), *sorted(icons), "unknown"]
    fb = FontBuilder(UPM, isTTF=True)
    fb.setupGlyphOrder(order)
    fb.setupCharacterMap({ord(c): g for c, g in COMPONENTS.items()})
    fb.setupGlyf(glyphs)
    fb.setupHorizontalMetrics(metrics)
    fb.setupHorizontalHeader(ascent=ASCENT, descent=DESCENT)
    fb.setupNameTable({
        "familyName": FAMILY, "styleName": "Regular", "psName": "SentrAIIcons-Regular",
        "uniqueFontIdentifier": f"{FAMILY}; Lucide {version}", "version": "Version 1.0",
        "copyright": "Icons: Lucide Icons and Contributors (ISC), some derived from Feather by Cole Bemis (MIT).",
        "licenseDescription": "ISC License (Lucide); MIT License (Feather-derived icons). See LICENSE.",
        "description": f"Lucide {version} icons under the Material Symbols names SentrAI's console uses.",
    })
    fb.setupOS2(sTypoAscender=ASCENT, sTypoDescender=DESCENT, sTypoLineGap=0, usWinAscent=WIN_ASCENT,
                usWinDescent=WIN_DESCENT, fsSelection=0b11000000, version=4)  # regular, and use the typo metrics
    fb.setupPost()

    # 'liga' turns a name into its icon (longest name first, as the shaper matches). The rules after it fold
    # any name the font does not know, even one that starts or ends with a known name ("lock_reset"), into
    # the one "unknown" glyph: whatever is followed by more of the word goes blank, an icon left behind a
    # blank becomes the dashed square, and so does a letter left at the end.
    rules = "\n".join(f"  sub {' '.join(COMPONENTS[c] for c in name)} by {glyph_name(lucide_name)};"
                      for name, lucide_name in names.items())
    fea = f"""languagesystem DFLT dflt;
languagesystem latn dflt;
@letters = [{" ".join(COMPONENTS.values())}];
@icons = [{" ".join(sorted(icons))}];
lookup names {{
{rules}
}} names;
lookup hide {{ sub [@letters @icons] by blank; }} hide;
feature liga {{
  lookup names;
  sub [@letters @icons]' lookup hide [@letters @icons];
  sub blank @icons' by unknown;
  sub @letters by unknown;
}} liga;
"""
    addOpenTypeFeaturesFromString(fb.font, fea)
    check(fb.font, {k: glyph_name(v) for k, v in names.items()})

    out = HERE / "sentrai-icons.woff2"
    fb.font.flavor = "woff2"
    fb.save(out)
    (HERE / "LICENSE").write_text((package / "LICENSE").read_text(encoding="utf-8"), encoding="utf-8")
    write_preview(names, unknown, version)
    print(f"{out.name}: {out.stat().st_size:,} bytes, {len(icons)} Lucide {version} icons for {len(names)} names")


def check(font: TTFont, expected: dict[str, str]) -> None:
    """Shape every name with HarfBuzz: one glyph each, the right one; unknown names one dashed square."""
    import io

    import uharfbuzz as hb

    buf = io.BytesIO()
    font.save(buf)
    hb_font = hb.Font(hb.Face(buf.getvalue()))
    order = font.getGlyphOrder()

    def shape(text: str) -> list[str]:
        b = hb.Buffer()
        b.add_str(text)
        b.guess_segment_properties()
        hb.shape(hb_font, b, {"liga": True})
        return [order[i.codepoint] for i, p in zip(b.glyph_infos, b.glyph_positions) if p.x_advance]

    wrong = {n: got for n, want in expected.items() if (got := shape(n)) != [want]}
    for n in ("not_a_name", "lock_reset", "my_lock", "check_circle_x", "x"):  # unknown, around known names too
        if n not in expected and shape(n) != ["unknown"]:
            wrong[n] = shape(n)
    if wrong:
        sys.exit(f"shaping check failed: {wrong}")


def write_preview(names: dict[str, str], unknown: str, version: str) -> None:
    """preview.html: every name next to its icon, plus one unknown name, for a look in a browser."""
    rows = "".join(f'<div><span class="i">{n}</span><code>{n}</code><small>{v}</small></div>'
                   for n, v in names.items())
    rows += f'<div><span class="i">not_a_known_name</span><code>not_a_known_name</code><small>{unknown} (unknown)</small></div>'
    (HERE / "preview.html").write_text(f"""<!doctype html>
<meta charset="utf-8"><title>SentrAI icons (Lucide {version})</title>
<style>
@font-face {{ font-family: "SentrAI Icons"; src: url(sentrai-icons.woff2) format("woff2"); }}
body {{ font: 14px system-ui, sans-serif; margin: 24px; display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 6px 18px; }}
div {{ display: flex; align-items: center; gap: 10px; }} code {{ font-size: 12px; }} small {{ color: #888; margin-left: auto; }}
.i {{ font-family: "SentrAI Icons"; font-size: 24px; line-height: 1; font-feature-settings: "liga"; }}
</style>
{rows}
""", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
