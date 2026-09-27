# CactAI: verified sources for every [CHECK]

Research date: 2026-09-27. All quotes are under 15 words. Primary sources were fetched and read directly (PDPC PDFs, Singapore Statutes Online PDF, TypeSafe docs).

| # | Claim | Verdict |
|---|---|---|
| 1 | PDPA max financial penalty | **Confirmed** (wording tightened: "whichever is higher") |
| 2 | Real PDPC decision for the opening hook | **Confirmed**: 3 decisions found; recommend ChampionTutor |
| 3 | Computer Misuse Act sections (hack back is illegal) | **Confirmed**: s3, s5, s7 |
| 4 | TypeSafe System One / Jev Python SDK | **Corrected**: imports and call are right; use `None` criteria, a `with` block, and read answers via `response.choices[...]` / `response.nouls[...]` |
| 5 | Alert fatigue statistic | **Confirmed** (vendor survey, label it) |

---

## 1. PDPA maximum financial penalty

**Verdict: Confirmed.** Section 48J of the PDPA. For breaches of the Data Protection Provisions the PDPC may impose up to S$1 million or 10% of the organisation's annual turnover in Singapore, **whichever is higher**. The 10% limb applies only where Singapore turnover exceeds S$10 million. In force from **1 October 2022**.

PDPC wording (Guide on Active Enforcement, p.27): "up to S$1 million or 10% of the organisation's annual turnover in Singapore". Its footnote adds that the 10% limb applies where Singapore turnover exceeds S$10 million.

**Slide wording:**
> Under the PDPA (s48J), the PDPC can fine an organisation up to S$1 million, or 10% of its annual Singapore turnover if that turnover exceeds S$10 million, whichever is higher. (In force since 1 Oct 2022.)

Short version: *"PDPA fines: up to S$1M or 10% of Singapore turnover, whichever is higher."*

URLs:
- PDPC, Guide on Active Enforcement (revised 1 Oct 2022), "Financial Penalties (Section 48J of the PDPA)": https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/active-enforcement/guide-on-active-enforcement_oct2022.pdf
- Statute: https://sso.agc.gov.sg/Act/PDPA2012 (s48J; SSO blocked automated fetch, so the citation was checked via the PDPC guide above)

---

## 2. Real PDPC enforcement decisions (basic, known, unfixed weaknesses)

### A. ChampionTutor Inc. (Private Limited) (RECOMMENDED OPENING HOOK)
- **Published:** 14 Oct 2021 (decision summary; PDPC Case No. DP-2103-B7984)
- **Penalty:** S$10,000 (breach of s24 Protection Obligation)
- **Facts:** A Dec 2020 pentest found an SQL injection hole. The developer never fixed it. On 24 Feb 2021 the student database was being sold on the dark web. **The company did not know until the PDPC told it.** 4,625 students' names, emails, phone numbers and addresses were affected.
- **Why it's the hook:** it fits CactAI exactly. The vulnerability was **known** (found in a pentest), it was an **SQL injection** (which CactAI detects), nobody acted on it (**negligence**), and the org **didn't know it had been breached**. It is also an education-sector SME.
- Quote: the vulnerability "was left unfixed until the Incident happened." (PDPC decision, para 2)
- URLs:
  - Decision PDF: https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/decision--championtutor-inc-private-limited--10082021.pdf
  - Listing: https://www.pdpc.gov.sg/all-commissions-decisions/2021/10/breach-of-the-protection-obligation-by-championtutor

**Suggested opening line (voice-over):**
> "In December 2020, a Singapore tuition platform's own security test found a hole in its website. Nobody fixed it. Two months later, 4,625 students' details were for sale on the dark web, and the company only found out when the regulator told them."

### B. PPLingo Pte Ltd (LingoAce): weak admin password, no MFA
- **Decision:** [2023] SGPDPC 12, dated 24 Oct 2023, published 23 May 2024
- **Penalty:** S$74,000 (Protection Obligation s24 + Accountability Obligation s11(3): no DPO appointed)
- **Facts:** An attacker brute-forced an online-education platform's admin password, "lingoace123". The password had been unchanged for over 2 years, and the account had no MFA. **557,144 users** were affected, including **303,238 students aged 4 to 15**.
- URLs:
  - Grounds of decision: https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/gd_pplingo-pte-ltd-(revised)_241023.pdf
  - Listing: https://www.pdpc.gov.sg/all-commissions-decisions/2024/05/breach-of-the-accountability-and-protection-obligations-by-pplingo

### C. North London Collegiate School (Singapore) Pte. Ltd.: misconfigured web folder
- **Published:** 18 Feb 2022 (Case No. DP-2107-B8562)
- **Penalty:** S$10,000 (s24 Protection Obligation)
- **Facts:** From Dec 2019 to Jul 2021, admission documents uploaded by parents sat in a website folder that search engines could index. The school relied only on robots.txt. A parent found a student report through a search engine. Up to **1,742 passports and 1,714 NRICs** were exposed, along with birth certificates and immunisation records.
- URLs:
  - Decision PDF: https://www.pdpc.gov.sg/-/media/Files/PDPC/PDF-Files/Commissions-Decisions/Decision---NLCS---01122021.pdf
  - Listing: https://www.pdpc.gov.sg/all-commissions-decisions/2022/02/breach-of-the-protection-obligation-by-north-london-collegiate-school

**Slide wording (for the "negligence" point, replacing the generic claim):**
> PDPC decisions keep finding the same basic failures. ChampionTutor left a known SQL-injection hole unfixed (S$10k). LingoAce's admin password was "lingoace123" with no MFA (S$74k). A school let search engines index applicants' passports (S$10k).

---

## 3. Computer Misuse Act 1993 (why "hack back" is illegal)

**Verdict: Confirmed.** Checked against the SSO PDF, 2020 Revised Edition (consolidation in force from 30/12/2025).

| Section | Offence | First conviction max |
|---|---|---|
| **s3(1)** | Unauthorised access to computer material: "for the purpose of securing access without authority" | S$5,000 fine and/or 2 years |
| **s5(1)** | Unauthorised modification of computer material | S$10,000 and/or 3 years |
| **s7(1)** | Unauthorised obstruction of use of computer: "interferes with, or interrupts or obstructs the lawful use of" a computer | S$10,000 and/or 3 years |

There is no self-defence or "attacker's machine" exception. Access or interference "without authority" is the offence, whatever the motive.

**Slide wording:**
> Hacking back is a crime in Singapore. Accessing an attacker's machine without authority is an offence under s3 of the Computer Misuse Act. Disrupting or modifying it is an offence under s5 and s7. CactAI only defends systems its owner is authorised to control.

URLs:
- https://sso.agc.gov.sg/Act/CMA1993 (see s3, s5, s7)
- PDF: https://sso.agc.gov.sg/Act/CMA1993?ViewType=Pdf

---

## 4. TypeSafe System One ("Jev") Python SDK

**Verdict: Corrected (minor).** Confirmed from the live docs:

| Item | Verified value |
|---|---|
| Install | `pip install typesafe-sdk` (or `uv add typesafe-sdk`; optional extra `typesafe-sdk[http2]`) |
| Import module | `typesafe_sdk` |
| Classes | `TypeSafeClient` (sync), `AsyncTypeSafeClient` (async), `Choice`, `Noul`, `Score`: all confirmed |
| Call | `client.system_one(state=..., questions=...)`: confirmed; `state` may be a string, object or array |
| Auth env var | `TYPESAFE_API_KEY` (key from https://console.typesafe.ai/) |
| Default model | `jev-latest` (env `TYPESAFE_DEFAULT_MODEL`; or `TypeSafeClient(model="jev")`) |
| HTTP endpoint | `POST https://api.typesafe.ai/v1/systemone`, `Authorization: Bearer <key>` |
| Choice answer | `response.choices["q"].choice` (top option), `.probabilities` (dict option to prob, sums to 1), `.confidence` (0 to 1) |
| Noul answer | `response.nouls["q"].noul` = probability of "yes" (0 to 1); no separate confidence field |
| Score answer | `response.scores["q"].score`, plus `.probabilities`, `.confidence` |
| Limits | Choice up to 255 options; Score 2 to 10 levels |
| Errors | 401 bad key, 422 bad body, 429 rate limit, 529 overloaded (SDK retries 429/529 automatically) |
| Latency | Docs: "Most queries complete in about 100 ms." **Confirmed** (vendor claim) |

**Corrections to the doc's snippet:**
1. Criteria values: the docs use `None` for options with no description (`{"calm": None, ...}`), not `{}`. The API accepts string/object/array/null, but `None` or a short description string is the documented form. Better still, give each option a one-line description string to improve accuracy.
2. Use the client as a context manager (`with TypeSafeClient() as client:`), as the docs show.
3. Read answers from `answer.choices[...]` and `answer.nouls[...]`, not a flat dict. For the AI Confidence Factor, use `probabilities[choice]` (the chosen option's probability). Alternatively use the built-in `.confidence`, which comes from the whole distribution.
4. Keep `TYPESAFE_API_KEY` server-side only.

**Corrected minimal working snippet:**
```python
# pip install typesafe-sdk      ;  export TYPESAFE_API_KEY=...
from typesafe_sdk import Choice, Noul, TypeSafeClient

state = {"event": {"layer": "web", "raw": "POST /login 401 user=admin src=203.0.113.45"}}

questions = {
    "category": Choice(
        instructions="What kind of activity does `event.raw` show?",
        criteria={
            "benign": "Normal user or system activity",
            "brute_force": "Repeated login/password guessing",
            "sql_injection": "SQL syntax injected into input",
            "xss": "Script/HTML injected into input",
            "port_scan": "Probing many ports or services",
            "privilege_escalation": "Gaining higher rights than granted",
            "data_exfiltration": "Unusual bulk data leaving the system",
            "misconfiguration": "Insecure setting or exposed resource",
        },
    ),
    "malicious": Noul(
        instructions="Is `event.raw` likely part of an attack rather than normal use?"
    ),
}

with TypeSafeClient() as client:          # reads TYPESAFE_API_KEY; model defaults to jev-latest
    answer = client.system_one(state=state, questions=questions)

cat = answer.choices["category"]
category = cat.choice                              # e.g. "brute_force"
p_category = cat.probabilities[category]           # probability of chosen option
ai_confidence = min(1.0, max(0.5, p_category))     # clip 0.5 to 1.0 per design
p_malicious = answer.nouls["malicious"].noul       # P(yes), 0 to 1
needs_review = 0.4 <= p_malicious <= 0.6           # confidence-gated routing
```

URLs:
- https://docs.typesafe.ai/sdk/python.md (install, imports, sync/async example, `response.choices[..].choice`)
- https://docs.typesafe.ai/sdk/python/usage.md (env vars `TYPESAFE_API_KEY`, `TYPESAFE_DEFAULT_MODEL`)
- https://docs.typesafe.ai/sdk/python/api/types/responses.md (ChoiceAnswer: `choice`, `confidence`, `probabilities`; NoulAnswer: `noul`)
- https://docs.typesafe.ai/api.md (HTTP endpoint, answer schema, limits, errors)
- https://docs.typesafe.ai/concepts/how-to-build-with-system-one.md ("about 100 ms")
- https://raw.githubusercontent.com/typesafe-ai/skills/main/skills/typesafe-ai/SKILL.md (Noul has no separate confidence; Noul near 0.5 means uncertainty; keep keys server-side)

**Slide wording:**
> Jev (TypeSafe System One) answers typed questions (Choice / Yes-No / Score) with calibrated probabilities, in about 100 ms per query (vendor figure).

---

## 5. Alert fatigue (optional stat)

**Verdict: Confirmed (vendor survey).** Vectra AI, *2023 State of Threat Detection*: SOC teams receive **4,484 alerts per day** on average, and **67% are ignored**. Survey of 2,000 SOC analysts at organisations with 1,000+ employees, run by Sapio Research, Mar to Apr 2023.

**Slide wording:**
> SOC teams get ~4,500 alerts a day and ignore 67% of them. (Vectra AI 2023 survey of 2,000 SOC analysts)

URL: https://www.vectra.ai/resources/2023-state-of-threat-detection
