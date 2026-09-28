# Deck build status

## Done (28 Sep 2026)
- `make_assets.py` generates the charts and illustrations into `assets/` (escalation, curve, gauge, bell, logo, perimeter).
- `build.py` builds `CactAI.pptx`: 13 slides, 16:9, dark theme, speaker notes on every slide, content from `../pitch/SLIDES.md`.
- `CactAI.pdf` is a LibreOffice render of the deck, checked slide by slide for overflow.
  It predates a small review fix (slide 2 card text, chart labels on slides 6 and 7): re-export it from PowerPoint (File > Save As > PDF) before sharing.
- The placeholders in SLIDES.md are filled from `../research/SOURCES.md`: ChampionTutor hook (slide 2), PDPA s48J (slide 3), Computer Misuse Act s3/s5/s7 (slide 10), references (slide 13).
- "Negligence report" is called the Security Evidence Report throughout the deck. `architecture.png` is rendered from `../pitch/architecture.svg` with that rename applied.

## Before recording
- Open `CactAI.pptx` in PowerPoint and flip through once: the checked render used DejaVu Sans, PowerPoint will use Segoe UI (narrower, so text only gets more room).
- Slide 8: optionally swap the gauge for a real dashboard screenshot at the moment the gauge crosses 80.
- Slide 7 and 9: replace the expected numbers with the recorded take's numbers if they differ.

## Rebuild
```
pip install python-pptx matplotlib
python make_assets.py
python build.py
```
