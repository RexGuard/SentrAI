# SentrAI: Slide Deck Content

12 slides. Owner: Hozen (content and sources), Ishmail (narration). Keep each slide to what is written here; the voice carries the rest. Numbers marked **[CHECK]** or **[SOURCE PENDING]** must be verified before export.

Suggested look: light background, dark green `#1F5E3B` for headings, amber `#E0A100`, red `#C0392B` and critical purple or deep red `#7B1E3C` for the risk bands, one sans-serif font throughout.

---

## Slide 1 · Title
**SentrAI: Accountability-based security for small teams**
- A sentry doesn't chase you. It just guards the gate.
- Cybersecurity + AI · Hackathon 2026

**Visual:** SentrAI shield icon; team names small at the bottom.
**Speaker note (Ishmail):** Do not read the slide. Start straight into the hook on slide 2.

---

## Slide 2 · The breach that was warned about
- [SOURCE PENDING: research agent] organisation, year, PDPC fine
- [SOURCE PENDING] records exposed
- Warning signs existed; nobody acted in time
- Missing response, not missing alert

**Visual:** big fine number, a single highlighted sentence from the PDPC decision, citation in the footer.
**Speaker note (Ishmail):** Keep it to 15 seconds. The point is that the alert existed.

---

## Slide 3 · The problem
- Singapore SMEs and private schools: lots of personal data, one or two IT staff
- No 24/7 SOC, so alerts pile up and get ignored (alert fatigue)
- PDPA penalty: up to 10% of annual SG turnover or S$1M **[CHECK]**
- After a breach, no one can prove who knew what, and when

**Visual:** notification bell with a "99+" badge next to a small team of two people.
**Speaker note (Ishmail):** "They already get alerts. The breach happens because nobody acts on them in time."

---

## Slide 4 · SentrAI in one sentence
- Scores your risk from 0 to 100 across web, database and OS
- Warns, reminds, then escalates to the people you choose
- Past your own tolerance line: temporary, reversible containment
- A tamper-evident record of who was warned and when

**Visual:** four-step horizontal flow: Warn → Remind → Contain (2h TTL) → Report.
**Speaker note (Ishmail):** Stress "your own tolerance line" and "temporary". Humans stay in charge.

---

## Slide 5 · CIA + NA
- **Confidentiality, Integrity, Availability**: protect the data
- **Non-repudiation**: every alert and acknowledgement is hash-chained
- **Authentication**: every decision is tied to a named operator
- Result: "I was never notified" is no longer an excuse

**Visual:** two columns, CIA and NA, with a chain-link icon under NA.
**Speaker note (Hozen):** Be honest: we prove delivery and acknowledgement, not that someone read it. The report says "Ack: none", not "they saw it".

---

## Slide 6 · The 0 to 100 risk index
- `event_points = base_severity × ai_confidence × asset_criticality`
- `raw_score = Σ open event_points + inaction_penalty − resolved_decay`
- `risk_index = round(100 × (1 − e^(−raw_score / 60)))`
- Inaction penalty: +5 per hour unacknowledged, capped at +30 per incident
- Bands: Green 0-29 · Amber 30-59 · Red 60-79 · Critical 80-100 (threshold set per org)

**Visual:** formula block on the left; on the right a curve of risk_index vs raw_score showing it flattens toward 100 and never exceeds it, with the four bands shaded. Mark the plan's examples: raw 35 → 44, raw 70 → 69, raw 97 → 80, raw 140 → 90.
**Speaker note (Erick):** Executives read 0 to 100 instantly. The curve means stacking incidents can never push it past 100. Severity examples: brute force high (30), SQL injection high (40), shell spawned critical (60), bulk data dump critical (70).

---

## Slide 7 · Risk escalation over time
- Brute force detected: index jumps into Amber
- Alert delivered, no acknowledgement: +5 points every hour
- SLA (2h) breached: reminder, team lead copied
- SQL injection lands on an already-neglected system: index crosses 80

**Visual (line chart):** x-axis demo hours 0 to 7, y-axis risk index 0 to 100, bands shaded green/amber/red/critical, dashed horizontal line at 80 labelled "Org tolerance". Expected values from `CONTRACT.md` math (brute force 30 × 0.94 × 1.5 = 42.3 points; replace with real values from the take):

| Demo hour | Event | Raw | Index |
| --- | --- | --- | --- |
| 0 | Brute force detected, Telegram alert sent | 42.3 | 51 (Amber) |
| 1 | No ack, +5 | 47.3 | 55 |
| 2 | No ack, SLA breached, reminder | 52.3 | 58 |
| 3 | No ack | 57.3 | 62 (Red) |
| 4 | No ack | 62.3 | 65 |
| 5 | No ack | 67.3 | 67 |
| 6 | No ack, penalty capped at +30 | 72.3 | 70 |
| 6.5 | SQL injection (40 × ~0.9 × 1.5 ≈ 54) | ≈126 | ≈88 (Critical) → containment |

Place markers on the line: bell icon at 0 ("alert delivered, Ack: none"), bell at 2 ("reminder"), shield at 6.5 ("Needle approved, IP blocked 2h").
**Speaker note (Erick):** The slope between hour 0 and 6 is entirely caused by inaction. That is the accountability story in one picture. Export this chart from the dashboard's `/risk` history if possible.

---

## Slide 8 · Live demo
- Lab app with synthetic member data, all on localhost
- Brute force → Jev tags it → Telegram alert ignored
- Inaction penalty climbs → SQL injection → crosses 80
- Needle approves → IP blocked 2h → evidence report → human decides

**Visual:** screenshot of the dashboard at the moment the gauge crosses 80 (used as the title card before the screen recording).
**Speaker note (Erick):** Say if the attack is a replay and if Jev is in fallback mode. Judges respect honesty more than polish.

---

## Slide 9 · The evidence report
- Responsible entity: on-duty operator and shift
- SLA violation: overdue by X h (policy 2h)
- Timeline of inaction: detected → alert delivered (Ack: none) → reminder → threshold crossed
- Forced action: IP blocked, TTL 2h, approved by Needle
- Proof: hash chain valid, each record links to the previous hash

**Visual:** mock report card with fields as rows, "Ack: none" highlighted in red, a small strip of chained hash blocks (`prev_hash → hash`) at the bottom with a green "chain valid" tick. Use the real report from `GET /reports/{id}` for the screenshot.
**Speaker note (Ishmail):** This is for leadership, not to punish. It shows where the process failed so it can be fixed. It is fact-based: delivered, acknowledged or not, and what the system did.

---

## Slide 10 · Ethics: no hack back
- SentrAI never attacks back. It holds the line and never crosses it.
- Hack back is an offence under the Computer Misuse Act [SOURCE PENDING: section]
- Attacker IPs are often spoofed or hijacked innocent machines
- Our "prick": block, tarpit, honeypots and honeytokens, evidence to SingCERT or police

**Visual:** sentry shield standing on a perimeter line; a red crossed-out arrow pointing outward.
**Speaker note (Hozen):** The attacker is pricked by attribution and prosecution, not retaliation.

---

## Slide 11 · Agent architecture
- Collectors (web, DB, OS) → rules → Jev → risk engine
- Saguaro leads; Root, Reservoir, Areole, Spine-Net specialise by layer
- Needle must approve every autonomous action (two-key rule)
- Watchdog checks heartbeats; Scribe writes the hash chain; Help Desk answers in Telegram
- AI judges and explains. Deterministic code scores and executes.

**Visual:** `architecture.svg` full-bleed.
**Speaker note (Erick):** For the MVP the agents are Python classes in one core service called in turn; separate processes are roadmap. No agent has a free shell: only allowlisted playbooks with a TTL.

---

## Slide 12 · Roadmap and team
- Now (MVP): web, DB, OS collectors, Jev, risk engine, blocklist containment, Telegram, evidence report (PDF)
- Next: Windows agent (Event Log, `netsh`), cloud config scan (S3, security groups), SMS/phone escalation
- Later: Go/Rust single-binary collectors, pilot with a Singapore private education institution
- Team: Erick Sientaro (Developer) · Ishmail (CEO) · Hozen (Notetaker, slides and sources)

**Visual:** three-column timeline (Now / Next / Later) above three team cards.
**Speaker note (Ishmail):** Close with: "Alerts tell you something is wrong. SentrAI makes sure someone answers, and proves it when they don't."

---

## Sources to list on a final "References" card (optional slide 13)
- PDPC enforcement decision used in the hook [SOURCE PENDING]
- PDPA financial penalty provision (PDPC site) [CHECK]
- Computer Misuse Act section on unauthorised access/modification [SOURCE PENDING]
- TypeSafe Jev / `typesafe_sdk` documentation
