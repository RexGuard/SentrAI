# Suggested edits to `Cybersecurity + AI.md`

Apply these as exact find/replace edits. Sources for each are in `SOURCES.md`.

---

## Edit 1: PDPA penalty (line 21)

**Find:**
```
- They are bound by the PDPA. Since Oct 2022 the maximum financial penalty is up to 10% of annual Singapore turnover (for organizations above S$10M turnover) or S$1 million. **[CHECK]** wording on the PDPC site.
```
**Replace:**
```
- They are bound by the PDPA. Since 1 Oct 2022, s48J lets the PDPC impose a financial penalty of up to S$1 million or 10% of annual Singapore turnover (where that turnover exceeds S$10M), whichever is higher. Source: PDPC Guide on Active Enforcement (Oct 2022), https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/active-enforcement/guide-on-active-enforcement_oct2022.pdf
```

---

## Edit 2: Real PDPC decisions / opening hook (line 23)

**Find:**
```
- Many PDPC enforcement decisions involve basic misconfigurations left unfixed (public buckets, default passwords, unpatched servers). **[CHECK]** pick one real PDPC decision to open the video with.
```
**Replace:**
```
- Many PDPC enforcement decisions involve basic weaknesses left unfixed:
  - **ChampionTutor (Oct 2021, S$10,000), the video's opening hook.** A Dec 2020 pentest found an SQL-injection hole that was never fixed. By Feb 2021, 4,625 students' data was being sold on the dark web, and the company only learned of it from the PDPC. https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/decision--championtutor-inc-private-limited--10082021.pdf
  - **PPLingo / LingoAce ([2023] SGPDPC 12, published May 2024, S$74,000).** Its admin password was "lingoace123", unchanged for 2+ years, with no MFA, and was brute-forced. 557,144 users were affected, 303,238 of them students. https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/gd_pplingo-pte-ltd-(revised)_241023.pdf
  - **North London Collegiate School (Singapore) (Feb 2022, S$10,000).** Applicants' passports, NRICs and birth certificates sat in a website folder that search engines indexed, protected only by robots.txt. https://www.pdpc.gov.sg/-/media/Files/PDPC/PDF-Files/Commissions-Decisions/Decision---NLCS---01122021.pdf
```

---

## Edit 3: TypeSafe SDK snippet (lines 131-151)

**Find:**
```
from typesafe_sdk import Choice, Noul, TypeSafeClient

state = {"event": {"layer": "web", "raw": 'POST /login 401 user=admin src=203.0.113.45'}}

questions = {
    "category": Choice(
        instructions="What kind of activity does `event.raw` show?",
        criteria={
            "benign": {}, "brute_force": {}, "sql_injection": {}, "xss": {},
            "port_scan": {}, "privilege_escalation": {},
            "data_exfiltration": {}, "misconfiguration": {},
        },
    ),
    "malicious": Noul(
        instructions="Is `event.raw` likely part of an attack rather than normal use?"
    ),
}

client = TypeSafeClient()
answer = client.system_one(state=state, questions=questions)
```
**Replace:**
```
# pip install typesafe-sdk   ; set TYPESAFE_API_KEY in the environment
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

with TypeSafeClient() as client:        # model defaults to jev-latest
    answer = client.system_one(state=state, questions=questions)

category = answer.choices["category"].choice
ai_confidence = min(1.0, max(0.5, answer.choices["category"].probabilities[category]))
p_malicious = answer.nouls["malicious"].noul   # P(yes), 0 to 1
```

---

## Edit 4: Remove the SDK [CHECK] (line 157)

**Find:**
```
**[CHECK]** exact SDK field names against `https://docs.typesafe.ai/sdk/python.md` and get a TypeSafe API key before building.
```
**Replace:**
```
SDK fields verified against https://docs.typesafe.ai/sdk/python.md and https://docs.typesafe.ai/api.md (27 Sep 2026). Install `typesafe-sdk`; auth via `TYPESAFE_API_KEY` (from https://console.typesafe.ai/). Choice answers expose `.choice`, `.probabilities` and `.confidence`; Noul answers expose `.noul` (P(yes)). Docs claim "about 100 ms" per query. **[FILL]** get a TypeSafe API key before building.
```

---

## Edit 5: Computer Misuse Act (line 272)

**Find:**
```
- **Illegal:** accessing or disrupting the attacker's machine without authorization is an offence under Singapore's Computer Misuse Act, whatever the motive. **[CHECK]** cite the section.
```
**Replace:**
```
- **Illegal:** accessing or disrupting the attacker's machine without authorization is an offence under Singapore's Computer Misuse Act 1993, whatever the motive. Unauthorised access is s3 (up to S$5,000 and/or 2 years, first offence). Unauthorised modification is s5, and unauthorised obstruction/interference ("interferes with, or interrupts or obstructs") is s7 (each up to S$10,000 and/or 3 years). https://sso.agc.gov.sg/Act/CMA1993
```

---

## Optional Edit 6: add an alert-fatigue stat (anywhere in the Problem section)

Insert after line 23:
```
- Alert fatigue: SOC teams receive ~4,484 alerts a day and ignore 67% of them (Vectra AI, 2023 State of Threat Detection, vendor survey of 2,000 SOC analysts). https://www.vectra.ai/resources/2023-state-of-threat-detection
```
