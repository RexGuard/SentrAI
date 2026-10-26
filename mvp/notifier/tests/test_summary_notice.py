"""The client summary is a short notice with a link to the one-page PDF."""

from emailer import format_email
from formatting import button_specs, format_console, format_telegram

URL = "http://127.0.0.1:8000/summary/daily.pdf?until=1793000000&sig=" + "ab" * 16
N = {"id": "ntf-0009", "incident": None, "kind": "summary", "title": "Daily security summary: All quiet today.",
     "text": "Mon 26 Oct 2026. Threats found: 0.", "report_url": URL, "buttons": []}


def test_summary_notice_links_the_pdf():
    msg = format_telegram(N, None, {"risk_index": 3})
    assert "Security summary" in msg and f'href="{URL.replace("&", "&amp;")}"' in msg and "one-page summary" in msg
    assert "Severity" not in msg and button_specs(N, None) == []
    assert URL in format_console(N, None, None, color=False, width=200)
    subject, text, html_body = format_email(N)
    assert subject == "[SentrAI] Daily security summary: All quiet today."
    assert URL in text and "one-page summary" in html_body
