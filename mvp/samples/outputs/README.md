# SentrAI output samples

What people outside the dashboard receive, in the SentrAI brand kit (navy + steel blue, three-arc logo).
All data is sample data (RFC 5737 IPs, fictional incident).

| File | What it is | Made by |
|---|---|---|
| `telegram-alert.png` | Telegram alert (HTML parse mode, mocked bubble) with its buttons | `notifier/formatting.py` `format_telegram` |
| `email-alert.png`, `email.txt` | Email alert, HTML and plain-text parts | `notifier/emailer.py` `format_email` |
| `console.txt` | Console-mode alert box | `notifier/formatting.py` `format_console` |
| `blocked-page.png`, `blocked-page-mobile.png` | What a contained visitor sees on the lab portal | `lab/target_app/templates/blocked.html` |
| `sample-evidence-report.pdf`, `pdf-page1.png`, `pdf-page2.png` | Security Evidence Report as PDF | `core/app/reports.py` `render_pdf` |
| `sample-evidence-report.md` | The same report as Markdown | `core/app/reports.py` `render_markdown` |
| `architecture.png` | Architecture diagram recoloured to the brand (render of `pitch/architecture.svg`) | `pitch/architecture.svg` |

Regenerate the report samples: `cd mvp/core && python ../samples/outputs/make_sample_report.py ../samples/outputs`.
