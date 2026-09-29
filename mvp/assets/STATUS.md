# mvp/assets status

## Done
- `make_assets.py` generates all 7 PNGs (1920x1080) in the SentrAI brand kit dark theme
  (navy `#0b111d`, steel blue `#7fb2ff`, shield-and-eye mark from `assets/brand/mark-dark.svg`):
  `hook_championtutor.png`, `risk_formula.png`, `risk_timeline.png`, `sentry_ethics.png`,
  `evidence_report_mock.png`, `title_card.png`, `end_card.png`.
  Green, amber and red appear only as risk colours; blue is the brand.
- Facts come only from `mvp/research/SOURCES.md`; timeline numbers from `mvp/pitch/SLIDES.md` slide 7
  (script asserts the formula reproduces 44/69/80/90 and 51..70, 88).
- 29 Sep 2026: cactus drawing replaced with the SentrAI mark; `cactus_ethics.png` renamed `sentry_ethics.png`.
  PNGs were rendered on Linux (DejaVu Sans); on Windows the script uses Segoe UI, so re-check for overflow there.

## How to regenerate
1. `cd mvp\assets` then `..\.venv\Scripts\python make_assets.py` (needs matplotlib and numpy)
2. Open each PNG and fix any overflow/overlap (text positions are figure fractions in `make_assets.py`).

## Asset to video timestamp (VIDEO_SCRIPT.md)
hook 0:00-0:15 (slide 2) · title_card 0:50 (slide 1) · sentry_ethics 0:58 and 3:40-4:00 (slide 10) ·
risk_formula 1:04 (slide 6) · risk_timeline 2:30-2:56 (slide 7) · evidence_report_mock 3:18 (slide 9) ·
end_card 4:40-5:00 (slide 12).
