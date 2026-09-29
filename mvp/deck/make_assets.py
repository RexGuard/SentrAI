"""Generate chart and illustration PNGs for the SentrAI deck (matplotlib)."""
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Circle, FancyBboxPatch, PathPatch, Polygon, Wedge
from matplotlib.path import Path as MPath

OUT = Path(__file__).parent / "assets"
OUT.mkdir(exist_ok=True)

BG = "#0F1B14"
CARD = "#182A1F"
GREEN = "#3FAE6A"
GREEN_D = "#1F5E3B"
TEXT = "#F2F5F3"
MUTED = "#A9BBAF"
BANDS = [(0, 30, "#2E8B57", "Green"), (30, 60, "#E0A100", "Amber"),
         (60, 80, "#C0392B", "Red"), (80, 100, "#7B1E3C", "Critical")]
BAND_TXT = {"Green": "#6FD39A", "Amber": "#F2C14E", "Red": "#FF7A66", "Critical": "#E68AAE"}

plt.rcParams.update({
    "font.family": "Segoe UI",
    "font.size": 15,
    "text.color": TEXT,
    "axes.labelcolor": MUTED,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.edgecolor": "#3A4D41",
})


def risk(raw):
    return round(100 * (1 - math.exp(-raw / 60)))


def style_axes(ax):
    ax.set_facecolor(CARD)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=14)


def shade_bands(ax, xmax, labels=True):
    for lo, hi, col, name in BANDS:
        ax.axhspan(lo, hi, color=col, alpha=0.18, lw=0, zorder=0)
        if labels:
            ax.text(xmax, (lo + hi) / 2, name, ha="right", va="center", fontsize=13,
                    color=BAND_TXT[name], fontweight="bold", alpha=0.95, zorder=1)


# ---------------------------------------------------------------- slide 7 chart
def escalation_chart():
    hours, raws = [], []
    for h in range(7):
        hours.append(h)
        raws.append(42.3 + min(5 * h, 30))
    hours += [6.5, 7]
    raws += [72.3 + 54, 72.3 + 54]
    idx = [risk(r) for r in raws]

    fig, ax = plt.subplots(figsize=(8.4, 5.6), dpi=200)
    fig.patch.set_facecolor(CARD)
    style_axes(ax)
    shade_bands(ax, 7.45)
    ax.axhline(80, ls="--", color=TEXT, lw=1.6, zorder=2)
    ax.text(0.05, 81.5, "Org tolerance (80)", fontsize=13, color=TEXT, va="bottom")

    ax.step(hours, idx, where="post", color=GREEN, lw=3.2, zorder=4)
    ax.scatter(hours[:-1], idx[:-1], s=60, color=TEXT, edgecolor=GREEN, lw=2, zorder=5)
    for h, v in zip(hours[:-1], idx[:-1]):
        ax.text(h, v - 6.5, str(v), ha="center", va="top", fontsize=13, color=TEXT, zorder=6)

    def callout(x, y, tx, ty, txt, col):
        ax.annotate(txt, xy=(x, y), xytext=(tx, ty), fontsize=12.5, color=TEXT, ha="left",
                    va="center", zorder=7,
                    bbox=dict(boxstyle="round,pad=0.35", fc=BG, ec=col, lw=1.5),
                    arrowprops=dict(arrowstyle="-", color=col, lw=1.5))

    callout(0, idx[0], 0.25, 20, "Alert delivered\nAck: none", "#F2C14E")
    callout(2, idx[2], 2.2, 32, "SLA breached:\nreminder, lead copied", "#F2C14E")
    callout(6.5, idx[7], 4.2, 95, "Countersign approved, IP blocked 2h", "#E68AAE")
    ax.annotate("", xy=(5.9, 68.5), xytext=(0.3, 49.5),
                arrowprops=dict(arrowstyle="->", color=MUTED, lw=1.2, ls=":"))
    ax.text(3.35, 48, "+5 per hour, no ack", fontsize=12.5, color=MUTED, rotation=10, ha="center")

    ax.set_xlim(-0.2, 7.5)
    ax.set_ylim(0, 102)
    ax.set_xticks(range(8))
    ax.set_yticks([0, 30, 60, 80, 100])
    ax.set_xlabel("Demo hour", fontsize=14)
    ax.set_ylabel("Risk index", fontsize=14)
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(OUT / "escalation.png", facecolor=CARD)
    plt.close(fig)
    return list(zip(hours, raws, idx))


# ---------------------------------------------------------------- slide 6 chart
def curve_chart():
    x = np.linspace(0, 220, 400)
    y = 100 * (1 - np.exp(-x / 60))
    fig, ax = plt.subplots(figsize=(6.6, 5.2), dpi=200)
    fig.patch.set_facecolor(CARD)
    style_axes(ax)
    shade_bands(ax, 218)
    ax.axhline(100, ls="--", color=MUTED, lw=1.2)
    ax.text(3, 101.5, "never exceeds 100", fontsize=12, color=MUTED, va="bottom")
    ax.plot(x, y, color=GREEN, lw=3.2, zorder=4)
    for r in (35, 70, 97, 140):
        v = risk(r)
        ax.scatter([r], [v], s=60, color=TEXT, edgecolor=GREEN, lw=2, zorder=5)
        ax.text(r + 4, v - 4, f"raw {r} → {v}", fontsize=12.5, color=TEXT, va="top", zorder=6)
    ax.set_xlim(0, 220)
    ax.set_ylim(0, 108)
    ax.set_yticks([0, 30, 60, 80, 100])
    ax.set_xlabel("raw_score", fontsize=14)
    ax.set_ylabel("risk_index", fontsize=14)
    fig.tight_layout()
    fig.savefig(OUT / "curve.png", facecolor=CARD)
    plt.close(fig)


# ---------------------------------------------------------------- illustrations
def draw_cactus(ax, cx, cy, s, col=GREEN, spines=True):
    def rbox(x, y, w, h):
        ax.add_patch(FancyBboxPatch((cx + x * s, cy + y * s), w * s, h * s,
                                    boxstyle=f"round,pad=0,rounding_size={min(w, h) * s / 2}",
                                    fc=col, ec="none", zorder=5))
    rbox(-0.17, -0.75, 0.34, 1.45)          # trunk
    rbox(-0.55, -0.12, 0.42, 0.2)           # left arm horizontal
    rbox(-0.55, -0.12, 0.2, 0.55)           # left arm up
    rbox(0.13, -0.3, 0.42, 0.2)             # right arm horizontal
    rbox(0.35, -0.3, 0.2, 0.6)              # right arm up
    if spines:
        for yy in np.linspace(-0.55, 0.55, 6):
            for sx in (-1, 1):
                x0 = cx + sx * 0.17 * s
                ax.plot([x0, x0 + sx * 0.09 * s], [cy + yy * s, cy + (yy + 0.04) * s],
                        color="#CFF3DC", lw=1.6, zorder=6)
    ax.add_patch(FancyBboxPatch((cx - 0.5 * s, cy - 0.85 * s), 1.0 * s, 0.12 * s,
                                boxstyle=f"round,pad=0,rounding_size={0.04 * s}",
                                fc=MUTED, ec="none", alpha=0.6, zorder=4))


def shield_outline(n=400):
    pts = []
    for x in np.linspace(-1, 1, 80):
        pts.append((x, 1.0 + 0.15 * (1 - x * x)))
    for y in np.linspace(1.0, 0.2, 40)[1:]:
        pts.append((1, y))
    for t in np.linspace(0, 1, 60)[1:]:
        p0, p1, p2 = np.array([1, 0.2]), np.array([0.95, -0.85]), np.array([0, -1.35])
        pts.append(tuple((1 - t) ** 2 * p0 + 2 * (1 - t) * t * p1 + t * t * p2))
    right = pts[80:]
    for p in reversed(right[:-1]):
        pts.append((-p[0], p[1]))
    pts = np.array(pts)
    seg = np.r_[0, np.cumsum(np.hypot(*np.diff(pts, axis=0).T))]
    t = np.linspace(0, seg[-1], n, endpoint=False)
    return np.c_[np.interp(t, seg, pts[:, 0]), np.interp(t, seg, pts[:, 1])]


def logo():
    fig, ax = plt.subplots(figsize=(5, 5.4), dpi=200)
    fig.patch.set_alpha(0)
    ax.set_aspect("equal")
    ax.axis("off")
    pts = shield_outline(1200)
    ax.plot(np.r_[pts[:, 0], pts[0, 0]], np.r_[pts[:, 1], pts[0, 1]], color=GREEN, lw=2.2, alpha=0.9)
    ax.fill(pts[:, 0], pts[:, 1], color=GREEN_D, alpha=0.35, zorder=1)
    spikes = shield_outline(46)
    # outward normals
    for i, (x, y) in enumerate(spikes):
        nx_, ny_ = spikes[(i + 1) % len(spikes)] - spikes[i - 1]
        nrm = np.array([ny_, -nx_])
        nrm /= np.linalg.norm(nrm)
        if nrm @ np.array([x, y + 0.1]) < 0:
            nrm = -nrm
        ax.plot([x, x + 0.16 * nrm[0]], [y, y + 0.16 * nrm[1]], color="#9FE3BA", lw=2.4,
                solid_capstyle="round")
    draw_cactus(ax, 0, 0.05, 1.05)
    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-1.6, 1.4)
    fig.savefig(OUT / "logo.png", transparent=True, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


def bell_team():
    fig, ax = plt.subplots(figsize=(5, 4.4), dpi=200)
    fig.patch.set_alpha(0)
    ax.set_aspect("equal")
    ax.axis("off")
    # bell
    verts = [(-0.9, -0.2), (-0.75, 0.1), (-0.7, 0.9), (-0.7, 1.5), (0, 1.55),
             (0.7, 1.5), (0.7, 0.9), (0.75, 0.1), (0.9, -0.2), (-0.9, -0.2)]
    codes = [MPath.MOVETO, MPath.LINETO, MPath.CURVE4, MPath.CURVE4, MPath.CURVE4,
             MPath.CURVE4, MPath.CURVE4, MPath.LINETO, MPath.LINETO, MPath.CLOSEPOLY]
    b = np.array(verts) * 1.0 + np.array([-0.2, 0.6])
    ax.add_patch(PathPatch(MPath(b, codes), fc="#E0A100", ec="none"))
    ax.add_patch(Circle((-0.2, 0.25), 0.22, fc="#E0A100"))
    ax.add_patch(Circle((-0.2, 2.25), 0.12, fc="#E0A100"))
    # badge
    ax.add_patch(Circle((0.62, 2.0), 0.55, fc="#C0392B", ec=CARD, lw=4, zorder=5))
    ax.text(0.62, 2.0, "99+", ha="center", va="center", fontsize=26, fontweight="bold",
            color="white", zorder=6)
    # two people
    for px in (1.9, 2.85):
        ax.add_patch(Circle((px, 0.95), 0.3, fc=MUTED))
        ax.add_patch(FancyBboxPatch((px - 0.42, -0.2), 0.84, 0.75,
                                    boxstyle="round,pad=0,rounding_size=0.3", fc=MUTED))
    ax.text(2.37, -0.55, "1–2 IT staff", ha="center", va="top", fontsize=20, color=TEXT)
    ax.set_xlim(-1.3, 3.5)
    ax.set_ylim(-1.0, 2.7)
    fig.savefig(OUT / "bell.png", transparent=True, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


def gauge(value=88):
    fig, ax = plt.subplots(figsize=(5.4, 3.6), dpi=200)
    fig.patch.set_alpha(0)
    ax.set_aspect("equal")
    ax.axis("off")
    for lo, hi, col, _ in BANDS:
        a1 = 180 - hi * 1.8
        a2 = 180 - lo * 1.8
        ax.add_patch(Wedge((0, 0), 1.0, a1, a2, width=0.24, fc=col, ec=BG, lw=3))
    ang = math.radians(180 - value * 1.8)
    ax.add_patch(Polygon([(0.05 * math.sin(ang), -0.05 * math.cos(ang)),
                          (0.86 * math.cos(ang), 0.86 * math.sin(ang)),
                          (-0.05 * math.sin(ang), 0.05 * math.cos(ang))], fc=TEXT))
    ax.add_patch(Circle((0, 0), 0.07, fc=TEXT))
    t80 = math.radians(180 - 80 * 1.8)
    ax.plot([1.04 * math.cos(t80), 1.16 * math.cos(t80)], [1.04 * math.sin(t80), 1.16 * math.sin(t80)],
            color=TEXT, lw=2.5)
    ax.text(1.2 * math.cos(t80) + 0.02, 1.2 * math.sin(t80), "80", fontsize=14, color=TEXT, va="bottom")
    ax.text(0, -0.22, f"{value}", ha="center", va="top", fontsize=44, fontweight="bold", color=TEXT)
    ax.text(0, -0.62, "CRITICAL", ha="center", va="top", fontsize=16, fontweight="bold",
            color=BAND_TXT["Critical"])
    ax.set_xlim(-1.2, 1.3)
    ax.set_ylim(-0.95, 1.3)
    fig.savefig(OUT / "gauge.png", transparent=True, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


def perimeter():
    fig, ax = plt.subplots(figsize=(5, 5), dpi=200)
    fig.patch.set_alpha(0)
    ax.set_aspect("equal")
    ax.axis("off")
    R = 1.5
    ax.add_patch(Circle((0, 0), R, fc=GREEN_D, alpha=0.25, ec="none"))
    ax.add_patch(Circle((0, 0), R, fc="none", ec=GREEN, lw=2.5, ls=(0, (6, 4))))
    for a in np.linspace(0, 2 * np.pi, 28, endpoint=False):
        if abs(a - np.radians(35)) < 0.25:
            continue
        c, s_ = np.cos(a), np.sin(a)
        ax.plot([R * c, (R - 0.22) * c], [R * s_, (R - 0.22) * s_], color="#9FE3BA", lw=2.4,
                solid_capstyle="round")
    draw_cactus(ax, 0, 0.05, 1.0)
    a = np.radians(35)
    ax.annotate("", xy=(2.25 * np.cos(a), 2.25 * np.sin(a)), xytext=(0.75 * np.cos(a), 0.75 * np.sin(a)),
                arrowprops=dict(arrowstyle="-|>,head_width=0.5,head_length=0.8", color="#E0533F", lw=5))
    mx, my = 1.75 * np.cos(a), 1.75 * np.sin(a)
    d = 0.32
    ax.plot([mx - d, mx + d], [my - d, my + d], color="#FF7A66", lw=7, solid_capstyle="round")
    ax.plot([mx - d, mx + d], [my + d, my - d], color="#FF7A66", lw=7, solid_capstyle="round")
    ax.set_xlim(-1.8, 2.5)
    ax.set_ylim(-1.8, 2.3)
    fig.savefig(OUT / "perimeter.png", transparent=True, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


if __name__ == "__main__":
    for row in escalation_chart():
        print("hour %-4s raw %-6.1f index %d" % row)
    curve_chart()
    logo()
    bell_team()
    gauge()
    perimeter()
    print("assets written to", OUT)
