# SentrAI brand kit

SentrAI is a sentry for small networks: it watches, blocks inside its own walls, and never hacks back.
The look is a night watch in black and white: two themes, Black and White, with one optional accent. The logo is three interlocking violet-to-blue arcs that close in on one another and guard the space in the middle.
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

| Token | White | Black | Role |
|---|---|---|---|
| `--sn-bg` | `#fafafa` | `#0a0a0a` | Page background |
| `--sn-surface` | `#ffffff` | `#141414` | Cards, panels |
| `--sn-surface-2` | `#f4f4f4` | `#1b1b1b` | Raised or alternate rows |
| `--sn-surface-3` | `#e8e8e8` | `#262626` | Hover, inputs |
| `--sn-ink` | `#0a0a0a` | `#f5f5f5` | Main text |
| `--sn-ink-soft` | `#404040` | `#b3b3b3` | Secondary text |
| `--sn-ink-muted` | `#666666` | `#8c8c8c` | Timestamps, hints |
| `--sn-line` | `#dedede` | `#2e2e2e` | Borders |
| `--sn-brand` | `#0a0a0a` | `#f5f5f5` | Links, primary buttons (Mono: the ink itself) |
| `--sn-brand-2` | `#404040` | `#b3b3b3` | Hover, focus ring |
| `--sn-brand-soft` | `#e8e8e8` | `#262626` | Selected rows, badges |
| `--sn-on-brand` | `#ffffff` | `#0a0a0a` | Text on a brand-filled button |
| `--sn-accent` | `#7b54e6` | `#a88cf5` | Optional violet accent text (the logo's colour) |
| `--sn-safe` | `#15803d` | `#6fcf97` | Low risk, allowed, healthy |
| `--sn-warn` | `#a16207` | `#e8b34a` | Medium risk, waiting for approval |
| `--sn-danger` | `#dc2626` | `#e5484d` | High risk, blocked |

Fixed shades for slides: black `#0a0a0a` `#141414` `#1b1b1b` `#262626`, white `#ffffff`.
Logo colours (the logo keeps them in both themes and with every accent): indigo `#522bbe`, violet `#8057f0`, periwinkle `#697ef5`; wordmark ink `#1d212b` on White, `#f3f5fa` on Black.

Rules:
- The UI is black and white; the violet logo and the accent picked in the console are the only other colours. Green, amber and red mean risk and nothing else.
- The console's accent is set in Configuration > Appearance: Mono, Violet, Blue or a custom colour. `mvp/dashboard/cactai_ui/theme.py` derives readable shades from it.
- Text colours pass WCAG AA (4.5:1) on `--sn-bg` and `--sn-surface` in both themes.
- Black is the default for the console, slides and alerts. The website follows the visitor's OS setting.

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
