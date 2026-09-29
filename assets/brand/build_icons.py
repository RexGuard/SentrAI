"""Render the SentrAI PNG/ICO icons and social card from the SVGs in this folder.

Needs: pip install playwright pillow  (uses the local Chromium; set PLAYWRIGHT_BROWSERS_PATH if needed)
Run:   python assets/brand/build_icons.py
"""
import os
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
NAVY = "#0b111d"


def page_html(body: str, bg: str = "transparent") -> str:
    return (f"<html><body style='margin:0;background:{bg};font-family:system-ui,-apple-system,"
            f"\"Segoe UI\",Roboto,Arial,sans-serif'>{body}</body></html>")


def svg(name: str) -> str:
    return (HERE / name).read_text(encoding="utf-8")


def shot(page, html: str, w: int, h: int, out: str, transparent: bool = True) -> None:
    page.set_viewport_size({"width": w, "height": h})
    page.set_content(html)
    page.screenshot(path=str(HERE / out), omit_background=transparent)


def main() -> None:
    with sync_playwright() as p:
        # CHROMIUM_PATH lets you point at an installed Chromium instead of Playwright's own download.
        exe = os.environ.get("CHROMIUM_PATH")
        page = p.chromium.launch(executable_path=exe or None).new_page()
        fav = svg("favicon.svg").replace("<svg ", "<svg width='SIZE' height='SIZE' ", 1)
        for s in (16, 32, 48):
            shot(page, page_html(fav.replace('SIZE', str(s))), s, s, f"favicon-{s}.png")
        # Home-screen icons: dark mark on a navy tile (the OS rounds the corners).
        tile = svg("mark-dark.svg").replace("<svg ", "<svg width='SIZE' height='SIZE' ", 1)
        for s, out in ((180, "apple-touch-icon.png"), (192, "icon-192.png"), (512, "icon-512.png")):
            m = round(s * 0.72)
            body = f"<div style='width:{s}px;height:{s}px;display:grid;place-items:center'>{tile.replace('SIZE', str(m))}</div>"
            shot(page, page_html(body, NAVY), s, s, out, transparent=False)
        # Social card (Open Graph / link previews), 1200x630.
        logo = svg("logo-dark.svg").replace("<svg ", "<svg width='600' height='160' ", 1)
        card = (f"<div style='width:1200px;height:630px;box-sizing:border-box;padding:96px 110px;color:#e7edf6;"
                f"background:radial-gradient(900px 480px at 0% 0%,rgba(76,141,255,.22),transparent 65%),{NAVY}'>"
                f"{logo}<p style='font-size:44px;font-weight:650;letter-spacing:-.01em;margin:56px 0 18px;max-width:900px'>"
                f"A sentry doesn't chase you. It just guards the gate.</p>"
                f"<p style='font-size:28px;color:#a5b2c6;margin:0'>AI-assisted defence for small networks. "
                f"It holds the line and never crosses it.</p></div>")
        shot(page, page_html(card), 1200, 630, "social-card.png", transparent=False)
    icons = [Image.open(HERE / f"favicon-{s}.png").convert("RGBA") for s in (48, 32, 16)]
    icons[0].save(HERE / "favicon.ico", format="ICO", sizes=[(48, 48), (32, 32), (16, 16)],
                  append_images=icons[1:])
    print("icons written to", HERE)


if __name__ == "__main__":
    main()
