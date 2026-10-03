# SentrAI brand kit

SentrAI is a sentry for small networks: it watches, blocks inside its own walls, and never hacks back.
The look is a night watch: deep navy and a steel-blue light. The logo is three interlocking violet-to-blue arcs that close in on one another and guard the space in the middle.
Open `preview.html` in a browser to see every asset in light and dark.

## Files

| File | Use |
|---|---|
| `logo.svg` | Horizontal logo for light backgrounds (mark + "SentrAI" wordmark, transparent) |
| `logo-dark.svg` | Horizontal logo for dark backgrounds (light wordmark, transparent) |
| `mark.svg` | The mark on its own (three arcs), transparent |
| `mark-dark.svg` | Mark for dark backgrounds (the same colours; they read on navy too) |
| `mark-mono.svg` | One-colour mark, takes `currentColor` (print, stamps, embossing) |
| `wordmark.svg` | "SentrAI" lettering on its own, takes `currentColor` |
| `favicon.svg` | Browser tab icon (the mark with a little padding) |
| `png/` | Transparent PNGs: `mark-` and `mark-mono-` at 64 to 1024 px, `logo-`, `logo-dark-` and `wordmark-` at 64 to 512 px tall (the wordmark files are cropped to the letters) |
| `source/sentrai-logo-original.png` | The original logo artwork the SVGs were traced from |
| `favicon.ico`, `favicon-16/32/48.png` | Fallback tab icons |
| `apple-touch-icon.png` (180), `icon-192.png`, `icon-512.png` | Home-screen and PWA icons (mark on white) |
| `social-card.png` (1200x630) | Link preview image (`og:image`) |
| `tokens.css` | Colour, type and radius tokens as `--sn-*` CSS variables, light and dark |
| `tokens.json` | The same tokens for Python (Streamlit, report PDFs, the deck, Telegram/email templates) |
| `build_icons.py` | Re-renders the PNG/ICO files, social card and `png/` exports from the SVGs |

Head snippet for a web page:

```html
<link rel="icon" href="assets/brand/favicon.svg" type="image/svg+xml">
<link rel="icon" href="assets/brand/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="assets/brand/apple-touch-icon.png">
<meta property="og:image" content="assets/brand/social-card.png">
<link rel="stylesheet" href="assets/brand/tokens.css">
```

## Colour

Dark values are the Risk Console's own (`mvp/dashboard/cactai_ui/console.css`), so the site, console, alerts and reports share one palette.

| Token | Light | Dark | Role |
|---|---|---|---|
| `--sn-bg` | `#f5f7fb` | `#0b111d` | Page background |
| `--sn-surface` | `#ffffff` | `#121a29` | Cards, panels |
| `--sn-surface-2` | `#eef2f8` | `#172134` | Raised or alternate rows |
| `--sn-surface-3` | `#e3e9f3` | `#1d2940` | Hover, inputs |
| `--sn-ink` | `#0f1a2c` | `#e7edf6` | Main text |
| `--sn-ink-soft` | `#44536b` | `#a5b2c6` | Secondary text |
| `--sn-ink-muted` | `#626f86` | `#6f7d93` | Timestamps, hints (dark: 14px+ only) |
| `--sn-line` | `#d5dce8` | `#26324a` | Borders |
| `--sn-brand` | `#1f4fb8` | `#7fb2ff` | Links, primary buttons |
| `--sn-brand-2` | `#2f6fe0` | `#4c8dff` | Hover, focus ring |
| `--sn-brand-soft` | `#e3ecfd` | `#16264a` | Selected rows, badges |
| `--sn-on-brand` | `#ffffff` | `#0b111d` | Text on a brand-filled button |
| `--sn-safe` | `#1a7447` | `#6fcf97` | Low risk, allowed, healthy |
| `--sn-warn` | `#8f5d00` | `#e8b34a` | Medium risk, waiting for approval |
| `--sn-danger` | `#c0282e` | `#e5484d` | High risk, blocked |

Fixed shades for slides: navy `#0b111d` `#121a29` `#172134` `#1d2940`, steel `#1f4fb8` `#4c8dff` `#7fb2ff`.
Logo colours (used only inside the logo): indigo `#522bbe`, violet `#8057f0`, periwinkle `#697ef5`; wordmark ink `#1d212b` on light, `#f3f5fa` on dark.

Rules:
- Blue is the brand; green, amber and red mean risk and nothing else. No cactus greens anywhere a person looks.
- Text colours pass WCAG AA (4.5:1) on `--sn-bg` and `--sn-surface` in both themes, except dark `--sn-ink-muted` on surfaces (4.2:1), which is for 14px+ secondary text.
- Dark theme is the default for the console, slides and alerts. The website follows the visitor's OS setting.

## Type

System fonts only (`--sn-font`, `--sn-mono`), so nothing loads from the internet and the demo works offline.
Headings use weight 750 with -0.02em tracking; body is 16px at 1.6 line height.
IPs, hashes, rule IDs and timestamps are always set in `--sn-mono`.
Scale: 12 / 14 / 16 / 20 / 28 / 40 px (`--sn-text-xs` to `--sn-text-2xl`).

## Logo use

- Leave clear space around the logo of at least half the mark's width.
- Use `logo.svg` on light and `logo-dark.svg` on dark; the mark keeps its three colours on both. Don't recolour, stretch, rotate, or add effects.
- The gaps between the arcs are part of the mark: place it on a plain background so they stay visible.
- Where an SVG won't do (slides, Word, email), use the transparent PNGs in `png/`.
- The wordmark is always "SentrAI", set in one colour. Never "Sentrai" or "SENTRAI".

## Voice

SentrAI talks like a calm guard on duty: plain, short, factual, never alarmist.

- Say what happened, what SentrAI did, and what it needs from you, in that order. "Blocked 203.0.113.7 after 40 failed SSH logins. Nothing to do."
- Numbers and names over adjectives. No "catastrophic", no "hackers are coming".
- It defends; it never attacks. Words like "block", "hold", "watch", "trap" are fine. "Strike back", "counter-attack", "hunt down" are not.
- The operator is in charge. Ask before anything big: "Block this range? It also covers your office Wi-Fi."
- Explain in terms a school IT admin knows; keep jargon for the details panel.

Taglines:
- **A sentry doesn't chase you. It just guards the gate.** (primary)
- **It holds the line and never crosses it.** (ethics and legal slides)

## Internal names

Code-level names stay as they are: `CACTAI_*` env vars, `cactai_*` modules, `~/.cactai`, service names, and the agent names Saguaro, Needle, Cyanide and cactus spines. Only what a person sees uses SentrAI.
