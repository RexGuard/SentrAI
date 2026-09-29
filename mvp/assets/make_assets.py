"""Generate SentrAI video/slide B-roll PNGs (1920x1080, SentrAI brand kit dark theme: navy + steel blue).

Run:  .venv\\Scripts\\python make_assets.py   (from mvp\\assets)
"""
import math
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import Circle, FancyBboxPatch, PathPatch, Rectangle
from matplotlib.path import Path as MPath
import numpy as np

OUT = Path(__file__).resolve().parent

# ---- theme: SentrAI brand kit (assets/brand/tokens.json, dark) -------------
BG = "#0B111D"         # navy-950
PANEL = "#121A29"      # navy-900
PANEL2 = "#172134"     # navy-800
TEXT = "#E7EDF6"
MUTED = "#A5B2C6"
BLUE = "#7FB2FF"       # brand accent (steel-300): headings, highlights, the "AI"
BLUE_D = "#1F4FB8"     # steel-700: filled headers and badges
BLUE_SOFT = "#16264A"
# Green, amber and red mean risk and nothing else.
GREEN = "#6FCF97"
AMBER = "#E8B34A"
RED = "#E5484D"
CRIT = "#C2304F"
GRID = "#26324A"

for f in ["segoeui.ttf", "segoeuib.ttf", "seguisb.ttf", "segoeuil.ttf", "consola.ttf", "consolab.ttf"]:
    p = Path("C:/Windows/Fonts") / f
    if p.exists():
        font_manager.fontManager.addfont(str(p))
plt.rcParams.update({
    "font.family": "Segoe UI",
    "text.color": TEXT,
    "axes.labelcolor": TEXT,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.edgecolor": GRID,
    "figure.facecolor": BG,
    "axes.facecolor": BG,
})
MONO = "Consolas"


def canvas():
    fig = plt.figure(figsize=(19.2, 10.8), dpi=100)
    fig.patch.set_facecolor(BG)
    return fig


def save(fig, name):
    fig.savefig(OUT / name, dpi=100, facecolor=BG)
    plt.close(fig)
    print("wrote", name)


def accent_bar(fig, y=0.06, x0=0.06, w=0.06):
    fig.add_artist(Rectangle((x0, y), w, 0.006, transform=fig.transFigure, color=BLUE))


def wordmark(fig, x, y, size, ha="left", va="center"):
    """ "SentrAI" with "AI" in brand blue, as the brand kit asks."""
    t = fig.text(x, y, "Sentr", fontsize=size, weight="bold", color=TEXT, ha="left", va=va)
    fig.canvas.draw()
    bb = t.get_window_extent().transformed(fig.transFigure.inverted())
    if ha == "right":  # shift both parts so the whole word ends at x
        ai = fig.text(0, y, "AI", fontsize=size, weight="bold", color=BLUE, va=va)
        fig.canvas.draw()
        w_ai = ai.get_window_extent().transformed(fig.transFigure.inverted()).width
        t.set_x(x - bb.width - w_ai)
        ai.set_x(x - w_ai)
        return
    fig.text(bb.x1, y, "AI", fontsize=size, weight="bold", color=BLUE, ha="left", va=va)


def brand(fig, x=0.94, y=0.05):
    wordmark(fig, x, y, 22, ha="right")


# The shield-and-eye mark (assets/brand/mark-dark.svg), in its 64x64 box with y pointing down.
_SHIELD = "M32 4 L54 11.5 V29 C54 43.5 44.8 54.2 32 60 C19.2 54.2 10 43.5 10 29 V11.5 Z"
_EYE = "M17 32 C22.5 24 27 21.5 32 21.5 C37 21.5 41.5 24 47 32 C41.5 40 37 42.5 32 42.5 C27 42.5 22.5 40 17 32 Z"


def _svg_path(d):
    """Parse the absolute M/L/V/C/Z subset the mark uses into a matplotlib Path (y flipped)."""
    toks = re.findall(r"[MLVCZ]|-?[\d.]+", d)
    verts, codes, i, cur = [], [], 0, (0.0, 0.0)
    while i < len(toks):
        op = toks[i]; i += 1
        if op in "ML":
            cur = (float(toks[i]), float(toks[i + 1])); i += 2
            verts.append(cur); codes.append(MPath.MOVETO if op == "M" else MPath.LINETO)
        elif op == "V":
            cur = (cur[0], float(toks[i])); i += 1
            verts.append(cur); codes.append(MPath.LINETO)
        elif op == "C":
            pts = [(float(toks[i + k]), float(toks[i + k + 1])) for k in (0, 2, 4)]; i += 6
            verts += pts; codes += [MPath.CURVE4] * 3; cur = pts[-1]
        elif op == "Z":
            verts.append(verts[0]); codes.append(MPath.CLOSEPOLY)
    return MPath([(x, 64 - y) for x, y in verts], codes)


def mark(ax, glow=True):
    """Draw the SentrAI mark on an axis whose limits are the 64x64 box."""
    if glow:
        for r, a in [(38, 0.05), (33, 0.07), (29, 0.09)]:
            ax.add_patch(Circle((32, 32), r, fc=BLUE, ec="none", alpha=a))
    ax.add_patch(PathPatch(_svg_path(_SHIELD), fc=BLUE_SOFT, ec=BLUE, lw=6, joinstyle="round"))
    ax.add_patch(PathPatch(_svg_path(_EYE), fc=BLUE, ec="none"))
    ax.add_patch(Circle((32, 32), 6, fc=BG, ec="none"))
    ax.add_patch(Circle((34.2, 64 - 29.8), 1.8, fc=TEXT, ec="none"))


def risk_index(raw):
    return np.round(100 * (1 - np.exp(-np.asarray(raw, dtype=float) / 60)))


BANDS = [(0, 30, GREEN, "Green"), (30, 60, AMBER, "Amber"), (60, 80, RED, "Red"), (80, 100, CRIT, "Critical")]


def shade_bands(ax, xmax, alpha=0.13, labels=True, label_x=None):
    for lo, hi, c, name in BANDS:
        ax.axhspan(lo, hi, color=c, alpha=alpha, lw=0)
        if labels:
            ax.text(label_x if label_x is not None else xmax * 0.985, (lo + hi) / 2,
                    f"{name} {lo}-{hi - 1 if hi < 100 else 100}", ha="right", va="center",
                    fontsize=16, color=c, weight="bold", alpha=0.95)


def style_axis(ax):
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color(GRID)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(labelsize=16, length=0, pad=8)


# ---- 1. hook ---------------------------------------------------------------
def hook():
    fig = canvas()
    fig.text(0.06, 0.88, "SINGAPORE  ·  PDPC ENFORCEMENT DECISION  ·  OCT 2021", fontsize=20,
             color=BLUE, weight="bold")
    fig.text(0.06, 0.76, "ChampionTutor", fontsize=78, weight="bold", color=TEXT)
    fig.text(0.06, 0.685, "A tuition platform was warned. Nobody fixed it.", fontsize=32, color=MUTED)

    cards = [
        ("Dec 2020", "Pentest finds an\nSQL injection hole", BLUE),
        ("Not fixed", "The developer never\npatched it", AMBER),
        ("4,625", "students' data sold\non the dark web", RED),
        ("S$10,000", "PDPC financial\npenalty", CRIT),
    ]
    x, w, gap = 0.06, 0.2, 0.02
    for i, (big, small, c) in enumerate(cards):
        x0 = x + i * (w + gap)
        fig.add_artist(FancyBboxPatch((x0, 0.30), w, 0.30, transform=fig.transFigure,
                                      boxstyle="round,pad=0,rounding_size=0.012", fc=PANEL, ec=GRID, lw=1.5))
        fig.add_artist(Rectangle((x0, 0.585), w, 0.015, transform=fig.transFigure, color=c))
        fig.text(x0 + 0.02, 0.49, big, fontsize=46, weight="bold", color=c, va="center")
        fig.text(x0 + 0.02, 0.38, small, fontsize=22, color=TEXT, va="center", linespacing=1.3)

    fig.text(0.06, 0.20, "“…left unfixed until the Incident happened.”", fontsize=28, style="italic", color=TEXT)
    fig.text(0.06, 0.155, "The company only learned of the breach when the PDPC told it.", fontsize=22, color=MUTED)

    fig.add_artist(Rectangle((0.06, 0.095), 0.88, 0.0015, transform=fig.transFigure, color=GRID))
    fig.text(0.06, 0.055, "Source: PDPC, Breach of the Protection Obligation by ChampionTutor Inc. (Private Limited), "
             "Case No. DP-2103-B7984, published 14 Oct 2021 (pdpc.gov.sg)", fontsize=15, color=MUTED, va="center")
    save(fig, "hook_championtutor.png")


# ---- 2. risk formula ------------------------------------------------------
def formula():
    fig = canvas()
    fig.text(0.05, 0.9, "The 0-100 risk index", fontsize=48, weight="bold")
    fig.text(0.05, 0.845, "Stacking incidents flattens toward 100 and can never pass it.", fontsize=22, color=MUTED)

    # formula panel
    fig.add_artist(FancyBboxPatch((0.05, 0.14), 0.36, 0.64, transform=fig.transFigure,
                                  boxstyle="round,pad=0,rounding_size=0.012", fc=PANEL, ec=GRID, lw=1.5))
    lines = [
        ("event_points", "= base_severity\n   × ai_confidence\n   × asset_criticality"),
        ("raw_score", "= Σ open event_points\n   + inaction_penalty\n   − resolved_decay"),
        ("risk_index", "= round(100 × (1 − e^(−raw/60)))"),
    ]
    y = 0.73
    for name, body in lines:
        fig.text(0.07, y, name, fontsize=24, family=MONO, weight="bold", color=BLUE, va="top")
        fig.text(0.07, y - 0.045, body, fontsize=20, family=MONO, color=TEXT, va="top", linespacing=1.35)
        y -= 0.045 + 0.04 * (body.count("\n") + 1) + 0.04
    fig.text(0.07, 0.23, "Inaction penalty: +5 per hour\nunacknowledged, capped at +30", fontsize=19,
             color=AMBER, va="top", linespacing=1.3)

    ax = fig.add_axes([0.47, 0.13, 0.49, 0.66])
    xs = np.linspace(0, 200, 400)
    shade_bands(ax, 200, labels=True, label_x=197)
    ax.plot(xs, 100 * (1 - np.exp(-xs / 60)), color=TEXT, lw=4, zorder=3)
    ax.axhline(100, color=MUTED, lw=1.5, ls="--")
    ax.text(3, 101.5, "ceiling: 100", fontsize=15, color=MUTED, va="bottom")
    pts = [(35, 44), (70, 69), (97, 80), (140, 90)]
    offs = [(6, 10), (6, -12), (-40, 8), (6, -12)]
    for (r, v), (dx, dy) in zip(pts, offs):
        assert int(risk_index(r)) == v, (r, v, risk_index(r))
        ax.plot([r, r], [0, v], color=MUTED, lw=1.2, ls=":", zorder=2)
        ax.scatter([r], [v], s=190, color=BLUE, edgecolor=BG, lw=3, zorder=5)
        ax.text(r + dx, v + dy, f"raw {r} → {v}", fontsize=20, weight="bold", color=TEXT, zorder=6,
                va="center", bbox=dict(boxstyle="round,pad=0.3", fc=BG, ec=BLUE, lw=1.5))
    ax.set_xlim(0, 200)
    ax.set_ylim(0, 108)
    ax.set_yticks([0, 30, 60, 80, 100])
    ax.set_xlabel("raw_score (points)", fontsize=19, labelpad=10)
    ax.set_ylabel("risk_index", fontsize=19, labelpad=10)
    style_axis(ax)
    brand(fig)
    save(fig, "risk_formula.png")


# ---- 3. timeline ----------------------------------------------------------
def timeline():
    # numbers from SLIDES.md slide 7
    hours = [0, 1, 2, 3, 4, 5, 6, 6.5]
    raw = [42.3, 47.3, 52.3, 57.3, 62.3, 67.3, 72.3, 72.3 + 54]
    idx = risk_index(raw)
    expected = [51, 55, 58, 62, 65, 67, 70, 88]
    assert list(idx.astype(int)) == expected, idx

    fig = canvas()
    fig.text(0.05, 0.9, "Risk escalation over time", fontsize=48, weight="bold")
    fig.text(0.05, 0.845, "Every point of the climb from hour 0 to hour 6 is caused by inaction.",
             fontsize=22, color=MUTED)
    ax = fig.add_axes([0.07, 0.12, 0.88, 0.68])
    shade_bands(ax, 7.6, labels=True, label_x=7.55, alpha=0.12)
    ax.axhline(80, color=TEXT, lw=2, ls="--", zorder=2)
    ax.text(0.05, 81.5, "Org tolerance: 80", fontsize=17, color=TEXT, va="bottom", weight="bold")

    # baseline before attack
    ax.plot([-0.5, 0], [8, 8], color=GREEN, lw=4, zorder=3)
    ax.plot([0, 0], [8, idx[0]], color=TEXT, lw=4, zorder=3)
    ax.plot(hours[:-1], idx[:-1], color=TEXT, lw=4, zorder=3, marker="o", ms=10, mfc=TEXT, mec=BG, mew=2)
    ax.plot([6, 6.5], [idx[6], idx[6]], color=TEXT, lw=4, zorder=3)
    ax.plot([6.5, 6.5], [idx[6], idx[7]], color=CRIT, lw=5, zorder=3)
    ax.plot([6.5, 7.3], [idx[7], idx[7]], color=CRIT, lw=4, zorder=3, ls=(0, (2, 1.5)))
    ax.scatter([6.5], [idx[7]], s=230, color=CRIT, edgecolor=TEXT, lw=2.5, zorder=6)
    for h, v in zip(hours[:-1], idx[:-1]):
        ax.text(h, v - 5.5, f"{int(v)}", ha="center", va="top", fontsize=17, color=TEXT, weight="bold")

    def note(x, y, tx, ty, text, color):
        ax.annotate(text, xy=(x, y), xytext=(tx, ty), fontsize=17, color=TEXT, ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.45", fc=PANEL, ec=color, lw=2),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=2, mutation_scale=18,
                                    shrinkA=4, shrinkB=10), zorder=7)

    note(0, idx[0], 0.55, 22, "Hour 0 · Brute force\nTelegram alert sent\nAck: none", AMBER)
    note(2, idx[2], 2.2, 30, "Hour 2 · SLA breached\nReminder, team lead copied", AMBER)
    note(4, idx[4], 4.25, 38, "+5 per hour unacknowledged\n(inaction penalty)", RED)
    note(6.5, 76, 5.2, 93.5, "Hour 6.5 · SQL injection\n+≈54 points", RED)
    note(6.5, 80, 3.3, 93.5, "Threshold crossed", TEXT)
    note(6.6, idx[7], 6.95, 62, "Auto-contain\nCountersign approved\nIP blocked 2h", GREEN)
    ax.text(6.62, idx[7] + 2.5, f"{int(idx[7])}", fontsize=20, weight="bold", color=TEXT, va="bottom")

    ax.set_xlim(-0.5, 7.6)
    ax.set_ylim(0, 102)
    ax.set_xticks(range(0, 8))
    ax.set_xticklabels([f"{h}h" for h in range(0, 8)])
    ax.set_yticks([0, 30, 60, 80, 100])
    ax.set_xlabel("Demo time (1 real minute = 1 demo hour)", fontsize=18, labelpad=10)
    ax.set_ylabel("Risk index", fontsize=18, labelpad=10)
    style_axis(ax)
    fig.text(0.95, 0.035, "Expected values from CONTRACT.md math; replace with the live take.",
             fontsize=14, color=MUTED, ha="right")
    save(fig, "risk_timeline.png")


# ---- 4. ethics ------------------------------------------------------------
def ethics():
    fig = canvas()
    fig.text(0.5, 0.87, "A sentry doesn't chase you.", fontsize=58, weight="bold", ha="center")
    fig.text(0.5, 0.8, "It just guards the gate.", fontsize=28, color=BLUE, ha="center")

    def column(x0, title, color, mark, items):
        w = 0.42
        fig.add_artist(FancyBboxPatch((x0, 0.13), w, 0.59, transform=fig.transFigure,
                                      boxstyle="round,pad=0,rounding_size=0.014", fc=PANEL, ec=color, lw=2.5))
        fig.text(x0 + 0.03, 0.655, title, fontsize=36, weight="bold", color=color, va="center")
        y = 0.56
        for head, sub in items:
            fig.text(x0 + 0.035, y, mark, fontsize=30, weight="bold", color=color, va="center", ha="center")
            fig.text(x0 + 0.065, y + 0.004, head, fontsize=26, weight="bold", color=TEXT, va="bottom")
            fig.text(x0 + 0.065, y - 0.006, sub, fontsize=18, color=MUTED, va="top")
            y -= 0.105

    column(0.06, "Never: hack back", RED, "×", [
        ("Access the attacker's machine", "Computer Misuse Act s3: unauthorised access"),
        ("Modify or wipe their data", "CMA s5: unauthorised modification"),
        ("Disrupt or DDoS their system", "CMA s7: unauthorised obstruction of use"),
        ("Retaliate against an IP", "Often a spoofed or hijacked innocent machine"),
    ])
    column(0.52, "Always: defend in place", GREEN, "✓", [
        ("Block", "Temporary IP block, 2h TTL, Countersign-approved"),
        ("Tarpit", "Slow the attacker so the attack gets expensive"),
        ("Honeytokens", "Decoy credentials and records that raise alarms"),
        ("Evidence to SingCERT / police", "Hash-chained logs for attribution and prosecution"),
    ])
    fig.text(0.06, 0.06, "Source: Computer Misuse Act 1993 (2020 Rev. Ed.), s3, s5, s7 · sso.agc.gov.sg/Act/CMA1993",
             fontsize=15, color=MUTED, va="center")
    brand(fig, y=0.06)
    save(fig, "sentry_ethics.png")


# ---- 5. evidence report ---------------------------------------------------
def report():
    fig = canvas()
    fig.text(0.05, 0.9, "Security evidence report", fontsize=46, weight="bold")
    fig.text(0.05, 0.845, "Incident RSK-2026-081  ·  generated automatically after containment",
             fontsize=21, color=MUTED)
    # SAMPLE badge
    fig.add_artist(FancyBboxPatch((0.80, 0.875), 0.15, 0.06, transform=fig.transFigure,
                                  boxstyle="round,pad=0,rounding_size=0.01", fc=AMBER, ec="none"))
    fig.text(0.875, 0.905, "SAMPLE DATA", fontsize=22, weight="bold", color=BG, ha="center", va="center")

    rows = [
        ("Responsible entity", "Admin: John Doe (Sample) · ID SEC-409 · Shift Bravo", TEXT,
         "Who was on duty during\nthe inaction window"),
        ("SLA violation", "Overdue by 7 h 15 min (policy SLA: 2 h)", RED,
         "Measured against company policy"),
        ("Timeline of inaction", "14:00 anomaly detected (+25) → 16:00 reminder 1 (+10)\n→ 21:00 critical limit breached (+45)", TEXT,
         "Progressive neglect,\nnot a sudden incident"),
        ("Forced action taken", "Autonomous override: port 22 isolated (TTL 2 h)", GREEN,
         "The system stepped in\nbecause no human did"),
        ("Proof of non-repudiation", "Delivered to operator @ 14:00  ·  Ack: none", RED,
         "Hash-chained delivery receipt"),
    ]
    x0, x1, x2, x3 = 0.05, 0.265, 0.70, 0.95
    top, rh = 0.79, 0.105
    # header
    fig.add_artist(Rectangle((x0, top - 0.055), x3 - x0, 0.055, transform=fig.transFigure, fc=BLUE_D, ec="none"))
    for x, t in [(x1 - 0.18, "Field"), (x1 + 0.012, "Record"), (x2 + 0.012, "Why leadership needs it")]:
        fig.text(x if t != "Field" else x0 + 0.015, top - 0.0275, t, fontsize=19, weight="bold", color=TEXT, va="center")
    y = top - 0.055
    for i, (field, val, col, why) in enumerate(rows):
        fig.add_artist(Rectangle((x0, y - rh), x3 - x0, rh, transform=fig.transFigure,
                                 fc=PANEL if i % 2 == 0 else PANEL2, ec="none"))
        cy = y - rh / 2
        fig.text(x0 + 0.015, cy, field, fontsize=18, weight="bold", color=MUTED, va="center")
        fig.text(x1 + 0.012, cy, val, fontsize=20, color=col, va="center", linespacing=1.35,
                 weight="bold" if col != TEXT else "normal", family="Segoe UI")
        fig.text(x2 + 0.012, cy, why, fontsize=15, color=MUTED, va="center", linespacing=1.3)
        y -= rh
    # hash chain strip
    cy = 0.09
    fig.text(0.05, cy + 0.045, "Audit hash chain", fontsize=18, weight="bold", color=MUTED)
    blocks = [("#1041", "a3f9…", "7c21…"), ("#1042", "7c21…", "e04b…"), ("#1043", "e04b…", "19d8…"),
              ("#1044", "19d8…", "b6a2…")]
    bx, bw = 0.05, 0.14
    for i, (n, prev, h) in enumerate(blocks):
        x = bx + i * (bw + 0.035)
        fig.add_artist(FancyBboxPatch((x, cy - 0.035), bw, 0.065, transform=fig.transFigure,
                                      boxstyle="round,pad=0,rounding_size=0.008", fc=PANEL, ec=GRID, lw=1.5))
        fig.text(x + 0.01, cy, f"{n}  prev {prev}\n       hash {h}", fontsize=13, family=MONO, color=TEXT,
                 va="center", linespacing=1.4)
        if i < len(blocks) - 1:
            fig.text(x + bw + 0.0175, cy, "→", fontsize=24, color=BLUE, ha="center", va="center")
    fig.add_artist(FancyBboxPatch((0.765, cy - 0.035), 0.185, 0.065, transform=fig.transFigure,
                                  boxstyle="round,pad=0,rounding_size=0.008", fc="#1A7447", ec="none"))
    fig.text(0.8575, cy, "✓ chain valid", fontsize=22, weight="bold", color=TEXT, ha="center", va="center")
    save(fig, "evidence_report_mock.png")


# ---- 6. title / end cards -------------------------------------------------
def mark_axis(fig, rect, glow=True):
    ax = fig.add_axes(rect)
    ax.set_xlim(-8, 72)
    ax.set_ylim(-8, 72)
    ax.set_aspect("equal")
    ax.axis("off")
    mark(ax, glow)
    return ax


def title_card():
    fig = canvas()
    mark_axis(fig, [0.655, 0.2, 0.32, 0.6])
    wordmark(fig, 0.07, 0.62, 120, va="bottom")
    fig.text(0.07, 0.54, "Accountability-based security for small teams", fontsize=34, color=BLUE)
    fig.text(0.07, 0.44, "A sentry doesn't chase you.\nIt just guards the gate.", fontsize=28,
             color=MUTED, style="italic", va="top", linespacing=1.4)
    accent_bar(fig, y=0.25, x0=0.07, w=0.08)
    fig.text(0.07, 0.19, "Cybersecurity + AI  ·  Hackathon 2026", fontsize=22, color=TEXT)
    fig.text(0.07, 0.13, "Erick Sientaro · Ishmail · Hozen", fontsize=20, color=MUTED)
    save(fig, "title_card.png")


def end_card():
    fig = canvas()
    mark_axis(fig, [0.74, 0.52, 0.2, 0.4])
    wordmark(fig, 0.07, 0.8, 80)
    fig.text(0.07, 0.69, "Alerts tell you something is wrong.\nSentrAI makes sure someone answers,\nand proves it when they don't.",
             fontsize=30, color=BLUE, va="top", linespacing=1.35)
    team = [("Erick Sientaro", "Developer"), ("Ishmail", "CEO"), ("Hozen", "Notetaker")]
    w, gap = 0.27, 0.025
    for i, (name, role) in enumerate(team):
        x = 0.07 + i * (w + gap)
        fig.add_artist(FancyBboxPatch((x, 0.2), w, 0.16, transform=fig.transFigure,
                                      boxstyle="round,pad=0,rounding_size=0.012", fc=PANEL, ec=GRID, lw=1.5))
        fig.add_artist(Rectangle((x, 0.2), 0.006, 0.16, transform=fig.transFigure, color=BLUE))
        fig.text(x + 0.025, 0.305, name, fontsize=30, weight="bold", color=TEXT, va="center")
        fig.text(x + 0.025, 0.245, role, fontsize=22, color=MUTED, va="center")
    fig.text(0.07, 0.1, "github.com/RexGuard/SentrAI", fontsize=28, family=MONO, color=BLUE, va="center")
    fig.text(0.93, 0.1, "Cybersecurity + AI · Hackathon 2026", fontsize=20, color=MUTED, ha="right", va="center")
    save(fig, "end_card.png")


if __name__ == "__main__":
    hook()
    formula()
    timeline()
    ethics()
    report()
    title_card()
    end_card()
