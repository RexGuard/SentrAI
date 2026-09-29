# SentrAI: Video Script

**Assumed length: 5:00.** The plan does not state a video length, so this script targets 5 minutes. Lines tagged **[CUT-3]** can be removed to reach about 3:00 (see the trim plan at the bottom).

**Speakers:** Ishmail (CEO, main narrator) · Erick (Developer, drives and narrates the demo) · Hozen (Notetaker, ethics and sources).

**Rules while recording**
- Read the numbers that actually appear on screen. Values in `{braces}` are expected values from `CONTRACT.md` math; replace them with what the live run shows.
- Demo clock runs at 1 real minute = 1 demo hour. Say this out loud once (it is in the script).
- If the replay script is used instead of a live attack, keep the line marked **[REPLAY]**.
- If Jev is unavailable and the rules engine is used, keep the line marked **[FALLBACK]**.

---

## 0:00 to 0:20 · Hook

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 0:00 | Ishmail | "In [SOURCE PENDING: research agent: year], a Singapore organisation was fined by the PDPC after personal data of [SOURCE PENDING: number] people was exposed." | Black screen, white text: organisation name, fine amount, number of records. Source line at bottom: PDPC decision citation [SOURCE PENDING]. |
| 0:08 | Ishmail | "The warning signs were there. [SOURCE PENDING: one sentence on what was flagged or left unfixed.] Nobody acted in time." | Quote or key finding from the PDPC decision, highlighted. |
| 0:15 | Ishmail | "The problem was not a missing alert. It was a missing response." | Text fades to: "Missing response, not missing alert." |

## 0:20 to 0:50 · Problem

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 0:20 | Ishmail | "Singapore SMEs and private schools hold a lot of personal data, but most have one or two IT staff and no one watching at night." | Slide 2: target organisations, icons for SME, school, small IT team. |
| 0:28 | Ishmail | "They already get security alerts. Too many of them. So the alerts get ignored." | Animation: alert badges piling up to "99+". |
| 0:35 | Ishmail | "Under the PDPA, the penalty can reach ten percent of annual Singapore turnover, or one million dollars." | PDPA penalty figure with PDPC source line (Hozen verified). |
| 0:42 | Ishmail | "And after a breach, nobody can prove who knew what, and when." | Question marks over a blank timeline. |

## 0:50 to 1:20 · Solution and sentry metaphor

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 0:50 | Ishmail | "We built SentrAI. An accountability-based security system that gives leaders proof, not just alerts." | Slide 3: SentrAI logo and tagline. |
| 0:58 | Ishmail | "A sentry doesn't chase you. It just guards the gate." | Sentry shield illustration, quote in large type. |
| 1:04 | Ishmail | "SentrAI watches your web app, database and servers, and scores your risk from zero to one hundred." | Gauge graphic 0 to 100 with four colour bands. |
| 1:10 | Ishmail | "Humans stay in charge. But if the risk crosses the limit your own organisation set, SentrAI applies a temporary, reversible fix, and records exactly who was warned and when." | Flow: Warn → Remind → Contain (temporary) → Report. |

## 1:20 to 1:40 · CIA + NA **[CUT-3]**

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 1:20 | Hozen | "We design around CIA plus NA. Confidentiality, integrity and availability protect the data." | Slide 4: two columns, CIA left. |
| 1:28 | Hozen | "Non-repudiation and authentication protect the truth. Every alert and every button press is signed into a hash chain, so no one can say 'I was never told'." | NA column lights up; chain-link icon. |

## 1:40 to 3:40 · Live demo

Erick narrates. Screen layout: dashboard (left, large), Telegram on phone mirror or Telegram Desktop (right top), attacker terminal (right bottom). See `RECORDING_CHECKLIST.md`.

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 1:40 | Erick | "Here is our lab. A small login app with fake member data, and the SentrAI dashboard. Risk is {8}. Green." | Dashboard full screen, gauge green, empty incident queue. |
| 1:48 | Erick | "Everything runs on this one laptop. The clock is sped up: one real minute is one hour of demo time." | Zoom on demo clock indicator. |
| 1:55 | Erick | "Now I'm the attacker. I start a brute-force attack on the admin login." | Attacker terminal: brute-force command running, 401 responses scrolling. |
| 2:02 | Erick | **[REPLAY]** "For reliability this is a replay of a recorded attack, fed through the same pipeline." | Same terminal, replay script output. |
| 2:05 | Erick | "The rules group the failed logins into one event. Jev, TypeSafe's System One model, tags it: brute force, confidence {0.94}." | Incident card: category `brute_force`, `classified_by: jev`, confidence. |
| 2:10 | Erick | **[FALLBACK]** "Jev is offline for this take, so the rules engine classified it with a fixed confidence." | Incident card showing `classified_by: rules`. |
| 2:14 | Erick | "Risk jumps to {51}. Amber." | Gauge moves to amber. |
| 2:18 | Erick | "The operator gets a Telegram alert with two buttons: Approve and Patch, or Reject with Justification." | Telegram message: incident ID, risk, recommended action, two buttons. |
| 2:25 | Erick | "Our operator is busy. He ignores it." | Telegram message sits unread; cursor moves away. |
| 2:30 | Erick | "Every demo hour without an answer adds five points. This is the inaction penalty. Watch the gauge climb." | Gauge ticking up; incident card "inaction penalty +5, +10, +15..."; SLA timer. |
| 2:40 | Erick | "Two hours pass. The SLA is breached. A reminder goes out, the team lead is copied. Still no answer." | Reminder alert in Telegram; incident shows `sla_breached: true`; gauge in red around {70}. **[CUT-3: shorten to one sentence]** |
| 2:50 | Erick | "Now the attacker tries SQL injection on the search page." | Attacker terminal: `/search?q=' OR 1=1 --` style request. |
| 2:56 | Erick | "Second incident, SQL injection. The risk crosses eighty. Critical." | Gauge jumps past 80, turns critical colour. Risk history chart shows the 80 line crossed. |
| 3:02 | Erick | "SentrAI takes a snapshot, picks a pre-approved playbook, and asks Countersign, our reviewer agent, to approve. Two keys, always." | Audit feed: `snapshot`, `playbook_selected`, `countersign review`. |
| 3:10 | Erick | "The attacker IP is blocked for two hours. Not forever. Two hours." | Blocklist panel: IP, TTL 2h, expires_at. |
| 3:14 | Erick | "The attacker tries again. Forbidden." | Attacker terminal: HTTP 403. |
| 3:18 | Erick | "And here is the evidence report. Alert delivered at {14:00}. Acknowledged: none. SLA overdue. Action taken. Every line is hash-chained, and the chain is valid." | Report page: timeline, "Ack: none", SLA breach, action, `chain_valid: true`. |
| 3:28 | Erick | "Now the human decides. Roll back, or make it permanent, with a written reason. That decision goes into the chain too." | Click Rollback or Make Permanent, type justification; audit log shows new record with hash. |
| 3:36 | Erick | "Nothing was hidden, and nothing was permanent without a human." | Audit log view, last records highlighted. |

## 3:40 to 4:00 · Ethics: no hack back

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 3:40 | Hozen | "One rule we never break: SentrAI does not attack back. It holds the line and never crosses it." | Slide: crossed-out "hack back" icon. |
| 3:46 | Hozen | "Hacking the attacker is an offence under Singapore's Computer Misuse Act. [SOURCE PENDING: section number.] And the IP is often a hijacked, innocent computer." | Three reasons: illegal, wrong target, escalation. |
| 3:54 | Hozen | "So we block, slow down, deceive with honeypots, and hand evidence to SingCERT or the police." | Four icons: block, tarpit, honeypot, evidence. |

## 4:00 to 4:20 · Agent architecture **[CUT-3]**

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 4:00 | Erick | "Under the hood, Warden, our lead agent, coordinates specialists for the web, database, network and each operating system." | `architecture.svg`, agents row highlighted. |
| 4:08 | Erick | "No agent gets a free shell. Only allowlisted playbooks, each with a time limit. Countersign must approve every autonomous action. Scribe writes the audit chain." | Countersign and Scribe boxes highlighted; hash chain strip at bottom. |
| 4:15 | Erick | "AI judges and explains. Plain code scores and executes." | Caption on diagram. |

## 4:20 to 4:40 · Roadmap **[CUT-3]**

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 4:20 | Ishmail | "Next: Windows and cloud agents, SMS and phone escalation, and lightweight collectors written in Go or Rust." | Roadmap slide, three columns: now, next, later. |
| 4:30 | Ishmail | "Then a pilot with one private education institution in Singapore." | Pilot milestone highlighted. |

## 4:40 to 5:00 · Team and close

| Time | Speaker | Line | On screen |
| --- | --- | --- | --- |
| 4:40 | Ishmail | "We are Erick, our developer. Hozen, who keeps our notes and sources honest. And I'm Ishmail." | Team slide, three names and roles. |
| 4:48 | Ishmail | "Alerts tell you something is wrong. SentrAI makes sure someone answers, and proves it when they don't." | Gauge returning to green. |
| 4:55 | Ishmail | "SentrAI. A sentry doesn't chase you. It just guards the gate." | Logo and tagline, hold 3 seconds. |

---

## Trim plan to 3:00

| Section | 5:00 version | 3:00 version |
| --- | --- | --- |
| Hook | 0:20 | 0:15 (drop the middle line if no source detail) |
| Problem | 0:30 | 0:20 (drop the "99+" line) |
| Solution | 0:30 | 0:20 (keep metaphor + "humans stay in charge") |
| CIA + NA | 0:20 | cut; fold "no one can say I was never told" into the report line |
| Demo | 2:00 | 1:30 (drop 1:48 clock line into on-screen caption, drop 2:40 reminder line, drop 3:36) |
| Ethics | 0:20 | 0:15 (first two lines only) |
| Architecture | 0:20 | cut, or 5 s of the diagram under the ethics lines |
| Roadmap | 0:20 | cut |
| Team + close | 0:20 | 0:15 |

## Items still pending
- Hook case: [SOURCE PENDING: research agent]: organisation, year, fine, records, what was ignored, PDPC decision link.
- Computer Misuse Act section number: [SOURCE PENDING].
- PDPA penalty wording verified by Hozen against the PDPC site.
- Replace `{values}` with the numbers from the final take.
