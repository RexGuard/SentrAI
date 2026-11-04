"""Keys, tokens and codes must not be password boxes: Chrome and Edge offer to save any type="password" box as a
website login (with a nearby box guessed as the username). Only the sign-in and new-password boxes may be."""
import re
from pathlib import Path

APP = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
CSS = (Path(__file__).resolve().parents[1] / "sentrai_ui" / "console.css").read_text(encoding="utf-8")


def test_only_sign_in_boxes_are_password_boxes():
    boxes = [line.strip() for line in APP.splitlines() if 'type="password"' in line and not line.lstrip().startswith("#")]
    assert len(boxes) == 3, boxes
    assert all(re.search(r'"(Password|Type it again)|Password \(at least', b) for b in boxes), boxes


def test_secret_boxes_are_drawn_as_dots():
    assert 'div[class*="st-key-secret-"] input { -webkit-text-security: disc;' in CSS
    assert 'container(key=f"secret-' in APP and 'autocomplete="off"' in APP
