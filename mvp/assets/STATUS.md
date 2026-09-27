# mvp/assets status (stopped on user request)

## Done
- `.venv/` created (Python 3.12, matplotlib 3.11.2, numpy).
- `make_assets.py` written: generates all 7 PNGs (1920x1080, dark theme, cactus-green accent):
  `hook_championtutor.png`, `risk_formula.png`, `risk_timeline.png`, `cactus_ethics.png`,
  `negligence_report_mock.png`, `title_card.png`, `end_card.png`.
  Facts come only from `mvp/research/SOURCES.md`; timeline numbers from `mvp/pitch/SLIDES.md` slide 7
  (script asserts the formula reproduces 44/69/80/90 and 51..70, 88).

## Not done
- Script has NOT been run yet, so no PNGs exist.
- PNGs not visually checked for text overflow/overlap.
- `README.md` (asset -> script timestamp mapping) not written.

## How to resume
1. `cd mvp\assets` then `.venv\Scripts\python make_assets.py`
2. Open each PNG and fix any overflow/overlap (text positions are figure fractions in `make_assets.py`).
3. Write `README.md` mapping assets to VIDEO_SCRIPT.md:
   hook 0:00-0:15 (slide 2) · title_card 0:50 (slide 1) · cactus_ethics 0:58 and 3:40-4:00 (slide 10) ·
   risk_formula 1:04 (slide 6) · risk_timeline 2:30-2:56 (slide 7) · negligence_report_mock 3:18 (slide 9) ·
   end_card 4:40-5:00 (slide 12).
