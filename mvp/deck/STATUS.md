# Deck build status (stopped early on request)

## Done
- `.venv/` created (Python 3.12) with python-pptx, matplotlib, pymupdf installed.
- `architecture.png` rendered from `../pitch/architecture.svg` via headless Edge (2800x1800, checked visually: clean).
- `make_assets.py` written (not yet run). It generates into `assets/`: `escalation.png` (slide 7 chart,
  risk = round(100*(1-exp(-raw/60))), raw 42.3 +5/h capped +30, SQLi +54 at hour 6.5), `curve.png` (slide 6),
  `logo.png` (cactus-shield), `bell.png` (slide 3), `gauge.png` (slide 8, value 88), `perimeter.png` (slide 10).
- Verified tooling: PowerPoint 16.0 COM automation works (use for PNG render + PDF export); Edge present.

## Not done
- Assets not generated / not visually checked.
- `build.py` (python-pptx, 13 slides 16:9, dark theme BG 0F1B14 / cards 182A1F / green 3FAE6A, speaker notes) not written.
- `SentrAI.pptx`, `SentrAI.pdf`, slide renders, visual QA.

## How to resume
1. `.venv\Scripts\python.exe make_assets.py` and inspect `assets\*.png`.
2. Write `build.py` per the slide plan (SLIDES.md content, <=5 bullets, notes via `slide.notes_slide`).
3. Render via PowerShell COM: `$pp=New-Object -ComObject PowerPoint.Application; $p=$pp.Presentations.Open(path,$true,$false,$false); $p.Slides | % { $_.Export("renders\slide$($_.SlideIndex).png","PNG",1600,900) }; $p.SaveAs(pdfPath,32); $p.Close(); $pp.Quit()`.
4. Inspect renders, fix overflow, re-render.
