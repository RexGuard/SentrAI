"""A tiny PDF writer (standard library only) used for the evidence report.

It supports what the report needs: A4 pages, the built-in Helvetica and Courier fonts, wrapped paragraphs,
headings, filled boxes and simple tables that break across pages. Text is encoded as WinAnsi (cp1252), so
characters outside it are swapped for close ASCII equivalents.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

PAGE_W, PAGE_H = 595.28, 841.89  # A4 in points
MARGIN = 42.0

# Glyph widths (1/1000 em) for ASCII 32..126, from the standard Adobe AFM files.
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
         556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
         556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
         556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722,
         500, 500, 500, 334, 260, 334, 584]
_HELV_B = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
           556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722,
           611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556,
           611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778,
           556, 556, 500, 389, 280, 389, 584]
FONTS = {"F1": ("Helvetica", _HELV), "F2": ("Helvetica-Bold", _HELV_B), "F3": ("Courier", None)}
REGULAR, BOLD, MONO = "F1", "F2", "F3"

# SentrAI brand kit (assets/brand/tokens.json): light-theme tokens for the page, fixed navy/steel for the band.
NAVY = (0.043, 0.067, 0.114)       # navy-950 #0b111d
NAVY_SOFT = (0.086, 0.149, 0.290)  # dark brand-soft #16264a
BLUE = (0.122, 0.310, 0.722)       # steel-700 #1f4fb8 (light brand)
BLUE_SOFT = (0.498, 0.698, 1.0)    # steel-300 #7fb2ff
INK = (0.059, 0.102, 0.173)        # ink #0f1a2c
MUTED = (0.384, 0.435, 0.525)      # ink-muted #626f86
RULE = (0.835, 0.863, 0.910)       # line #d5dce8
STRIPE = (0.933, 0.949, 0.973)     # surface-2 #eef2f8
HEAD = NAVY                        # headings and table headers
ON_DARK = (0.906, 0.929, 0.965)    # dark ink #e7edf6

# The shield-and-eye mark (assets/brand/mark-dark.svg, 64x64 box, y down).
_SHIELD = [("m", 32, 4), ("l", 54, 11.5), ("l", 54, 29), ("c", 54, 43.5, 44.8, 54.2, 32, 60),
           ("c", 19.2, 54.2, 10, 43.5, 10, 29), ("l", 10, 11.5)]
_EYE = [("m", 17, 32), ("c", 22.5, 24, 27, 21.5, 32, 21.5), ("c", 37, 21.5, 41.5, 24, 47, 32),
        ("c", 41.5, 40, 37, 42.5, 32, 42.5), ("c", 27, 42.5, 22.5, 40, 17, 32)]


def _circle(cx: float, cy: float, r: float) -> list[tuple]:
    k = 0.5523 * r
    return [("m", cx + r, cy), ("c", cx + r, cy + k, cx + k, cy + r, cx, cy + r),
            ("c", cx - k, cy + r, cx - r, cy + k, cx - r, cy), ("c", cx - r, cy - k, cx - k, cy - r, cx, cy - r),
            ("c", cx + k, cy - r, cx + r, cy - k, cx + r, cy)]


_SWAPS = {"→": "->", "←": "<-", "✓": "OK", "✅": "OK", "✗": "x", "≥": ">=", "≤": "<=", "\t": "    "}


def clean(text: object) -> str:
    """Make text safe for WinAnsi: known symbols become ASCII, anything else unencodable becomes '?'."""
    s = "" if text is None else str(text)
    for a, b in _SWAPS.items():
        s = s.replace(a, b)
    return s.encode("cp1252", "replace").decode("cp1252")


def text_width(s: str, font: str, size: float) -> float:
    widths = FONTS[font][1]
    if widths is None:
        return 600 * len(s) * size / 1000
    return sum(widths[ord(c) - 32] if 32 <= ord(c) <= 126 else 556 for c in s) * size / 1000


def wrap(text: object, font: str, size: float, width: float) -> list[str]:
    """Greedy word wrap; words longer than the line (hashes, URLs) are split by character."""
    lines: list[str] = []
    for para in clean(text).split("\n"):
        line = ""
        for word in para.split(" "):
            cand = f"{line} {word}" if line else word
            if text_width(cand, font, size) <= width:
                line = cand
                continue
            if line:
                lines.append(line)
            while text_width(word, font, size) > width:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines


def _esc(s: str) -> bytes:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("cp1252", "replace")


def _rgb(color: tuple[float, float, float]) -> str:
    return " ".join(f"{c:.3f}" for c in color)


@dataclass
class Column:
    title: str
    width: float  # share of the table width
    font: str = REGULAR


@dataclass
class PdfDoc:
    title: str = "Document"
    footer: str = ""
    pages: list[list[bytes]] = field(default_factory=list)
    y: float = 0.0

    def __post_init__(self) -> None:
        self.new_page()

    # ---- low level ----
    @property
    def width(self) -> float:
        return PAGE_W - 2 * MARGIN

    def new_page(self) -> None:
        self.pages.append([])
        self.y = PAGE_H - MARGIN

    def _op(self, s: str | bytes) -> None:
        self.pages[-1].append(s if isinstance(s, bytes) else s.encode("latin-1"))

    def rect(self, x: float, y: float, w: float, h: float, fill: tuple[float, float, float]) -> None:
        self._op(f"{_rgb(fill)} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f\n")

    def line(self, x1: float, y1: float, x2: float, y2: float, color=RULE, w: float = 0.6) -> None:
        self._op(f"{_rgb(color)} RG {w:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S\n")

    def shield(self, x: float, y: float, size: float) -> None:
        """The SentrAI mark (dark variant, for the navy band) with its bottom-left corner at (x, y)."""
        k = size / 64

        def path(cmds: list[tuple]) -> str:
            out = []
            for op, *pts in cmds:
                xy = " ".join(f"{x + pts[i] * k:.2f} {y + (64 - pts[i + 1]) * k:.2f}" for i in range(0, len(pts), 2))
                out.append(f"{xy} {op}")
            return " ".join(out)

        self._op(f"{_rgb(NAVY_SOFT)} rg {_rgb(BLUE_SOFT)} RG {3 * k:.2f} w 1 j {path(_SHIELD)} h B\n")
        self._op(f"{_rgb(BLUE_SOFT)} rg {path(_EYE)} h f\n")
        self._op(f"{_rgb(NAVY)} rg {path(_circle(32, 32, 6))} h f\n")
        self._op(f"{_rgb(ON_DARK)} rg {path(_circle(34.2, 29.8, 1.8))} h f 0 j\n")

    def text(self, x: float, y: float, s: str, font: str = REGULAR, size: float = 10,
             color=INK) -> None:
        self._op(f"BT {_rgb(color)} rg /{font} {size:g} Tf {x:.2f} {y:.2f} Td (".encode("latin-1")
                 + _esc(clean(s)) + b") Tj ET\n")

    def ensure(self, h: float) -> None:
        if self.y - h < MARGIN + 18:  # leave room for the footer
            self.new_page()

    # ---- blocks ----
    def space(self, h: float) -> None:
        self.y -= h

    def heading(self, s: str, size: float = 13, color=HEAD) -> None:
        self.ensure(size * 2.6)
        self.y -= size * 1.2
        self.rect(MARGIN, self.y - 1, 3, size * 0.95, BLUE)  # steel-blue tab before each heading
        self.text(MARGIN + 9, self.y, s, BOLD, size, color)
        self.y -= 4
        self.line(MARGIN, self.y, MARGIN + self.width, self.y, RULE, 0.8)
        self.y -= size * 0.7

    def paragraph(self, s: object, font: str = REGULAR, size: float = 9.5, color=INK,
                  indent: float = 0.0) -> None:
        lead = size * 1.35
        for ln in wrap(s, font, size, self.width - indent):
            self.ensure(lead)
            self.y -= lead
            self.text(MARGIN + indent, self.y + size * 0.3, ln, font, size, color)
        self.y -= size * 0.4

    def bullet(self, s: object, size: float = 9.5) -> None:
        self.ensure(size * 1.35)
        self.text(MARGIN + 4, self.y - size * 1.05, "-", REGULAR, size)
        self.paragraph(s, size=size, indent=14)

    def table(self, columns: list[Column], rows: list[list[object]], size: float = 8.5,
              colors: list[tuple[float, float, float] | None] | None = None) -> None:
        """Rows wrap inside their cells; the header is repeated on each new page."""
        total = sum(c.width for c in columns)
        widths = [self.width * c.width / total for c in columns]
        pad, lead = 4.0, size * 1.3

        def header() -> None:
            h = lead + 2 * pad
            self.ensure(h + lead * 2)
            self.rect(MARGIN, self.y - h, self.width, h, HEAD)
            x = MARGIN
            for c, w in zip(columns, widths):
                self.text(x + pad, self.y - pad - size, c.title, BOLD, size, (1, 1, 1))
                x += w
            self.y -= h

        header()
        for i, row in enumerate(rows):
            cells = [wrap(v, c.font, size, w - 2 * pad) for v, c, w in zip(row, columns, widths)]
            h = max(len(c) for c in cells) * lead + 2 * pad
            if self.y - h < MARGIN + 18:
                self.new_page()
                header()
            if i % 2:
                self.rect(MARGIN, self.y - h, self.width, h, STRIPE)
            color = (colors[i] if colors and colors[i] else INK)
            x = MARGIN
            for lines, c, w in zip(cells, columns, widths):
                for k, ln in enumerate(lines):
                    self.text(x + pad, self.y - pad - size - k * lead + 1, ln, c.font, size, color)
                x += w
            self.y -= h
            self.line(MARGIN, self.y, MARGIN + self.width, self.y)
        self.y -= 8

    # ---- output ----
    def to_bytes(self) -> bytes:
        objs: list[bytes] = []

        def add(b: bytes) -> int:
            objs.append(b)
            return len(objs)

        catalog = add(b"")  # filled in below
        pages_id = add(b"")
        font_ids = {k: add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>".encode())
                    for k, (name, _) in FONTS.items()}
        fonts = " ".join(f"/{k} {v} 0 R" for k, v in font_ids.items())
        kids = []
        n = len(self.pages)
        for i, ops in enumerate(self.pages, 1):
            foot = []
            if self.footer or n > 1:
                y = MARGIN - 14
                foot.append(f"{_rgb(RULE)} RG 0.6 w {MARGIN:.2f} {y + 10:.2f} m {PAGE_W - MARGIN:.2f} {y + 10:.2f} l S\n".encode())
                foot.append(f"{_rgb(BLUE)} rg {MARGIN:.2f} {y + 9.4:.2f} 28 1.4 re f\n".encode())
                foot.append(f"BT {_rgb(MUTED)} rg /F1 7.5 Tf ".encode() + f"{MARGIN:.2f} {y:.2f} Td (".encode() + _esc(clean(self.footer)) + b") Tj ET\n")
                label = f"Page {i} of {n}"
                x = PAGE_W - MARGIN - text_width(label, REGULAR, 7.5)
                foot.append(f"BT {_rgb(MUTED)} rg /F1 7.5 Tf {x:.2f} {y:.2f} Td ({label}) Tj ET\n".encode())
            data = zlib.compress(b"".join(ops + foot))
            content = add(f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n".encode() + data + b"\nendstream")
            kids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                            f"/Resources << /Font << {fonts} >> >> /Contents {content} 0 R >>".encode()))
        objs[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
        objs[pages_id - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {n} >>".encode()
        info = add(b"<< /Title (" + _esc(clean(self.title)) + b") /Producer (SentrAI Scribe) >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
        out += f"trailer\n<< /Size {len(objs) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)
