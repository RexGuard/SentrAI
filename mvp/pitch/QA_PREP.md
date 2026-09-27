# CactAI: Judge Q&A Prep

Short answers first (say this), then backup detail (only if they push). Default answerer in brackets. Rule: if we do not know, say so and say how we would find out. Never invent numbers.

---

### 1. What about false positives? You could block a real customer.
**[Erick]** Three safeguards. Autonomous action only happens above the organisation's own threshold (default 80), which a single noisy event rarely reaches. If Jev is uncertain (0.4 to 0.6) nothing automatic happens; it goes to a human as "needs review". And every fix is temporary, 2 hours by default, with one-click rollback.
*Backup:* Needle, the reviewer agent, must approve every autonomous action. Playbooks are the least disruptive first: block one IP or rate-limit, not shut down the server. Verification re-runs the check and auto-rolls back if a health check breaks.

### 2. Isn't monitoring your own staff a privacy problem?
**[Hozen]** We monitor systems, not people's private lives. CactAI reads security logs the systems already produce: logins, queries, processes. It does not read email, chats or screens. The only person-level record is who was on duty, whether an alert was delivered, and whether they acknowledged it.
*Backup:* The organisation should tell staff in its IT policy that security alerts and acknowledgements are logged. The audit log itself is personal data under the PDPA, so it gets access control and a retention period. [CHECK with PDPC employee-monitoring guidance before claiming specific compliance.]

### 3. Is a "negligence report" fair to operators? Is it even legal?
**[Ishmail]** It is a factual timeline, not a verdict. It says "alert delivered 14:00, acknowledgement: none, SLA 2 hours". It does not say "John ignored it", because we cannot prove someone read a message. Leadership decides what it means. Often the finding is "one person on shift is not enough", which is a management problem, not an operator problem.
*Backup:* The report also records escalations to the team lead and CXO, so accountability goes up the chain, not just down. The operator can always reject an alert with a justification, which also goes in the record and protects them. We are not lawyers; an organisation should align the report with its HR policy before using it for discipline.

### 4. Why not just buy a SIEM?
**[Erick]** A SIEM collects and correlates alerts; it still needs a team to act on them. Our target has one or two IT staff and no SOC. CactAI adds the part SIEMs usually leave out: a risk score that climbs when nobody acts, bounded automatic containment, and proof of who was told.
*Backup:* CactAI can sit on top of a SIEM later; a SIEM would just be another collector. Cost and complexity of enterprise SIEMs is a real barrier for SMEs.

### 5. How much do the Jev calls cost, and what about latency?
**[Erick]** Jev is only called when rules cannot decide. The rules engine settles obvious cases in microseconds and groups many log lines into one event, so we call Jev per event, not per line. Each call is about 100 ms. Claude is only used off the hot path to write explanations and reports.
*Backup:* We do not have a production price yet [CHECK TypeSafe pricing]. If Jev is down or over budget, the system keeps working with rules and a fixed confidence; the incident card shows `classified_by: rules`.

### 6. What if CactAI itself is compromised?
**[Erick]** We designed so a compromised brain cannot do much damage. No agent has a shell; it can only trigger allowlisted playbooks like "block this IP for 2 hours". Every action needs Needle's approval, expires by default, and is written to a hash chain, so tampering with history is detectable.
*Backup:* Watchdog alerts if an agent or collector goes silent. Roadmap: run CactAI on a separate hardened host, sign the chain head externally (e.g. send daily chain hash to the CXO or a timestamping service), least-privilege credentials per agent.

### 7. Can an attacker use CactAI against you, for example by spoofing IPs to get legitimate users blocked?
**[Erick]** That is a real risk for any auto-blocking system. Blocks are short, scoped to one IP or account, and protected infrastructure (the operator's own IPs, payment gateways, health checks) can be allowlisted so they are never blocked. A flood of blocks would itself raise an alert.

### 8. How does it scale beyond one laptop?
**[Erick]** The MVP runs on one laptop. The design already separates the parts: lightweight collectors per host, a stream (Redis in the plan) into the core, and agents per layer. Scaling means more collectors and running agents as separate processes. Production collectors would be rewritten in Go or Rust as small single binaries.
*Backup:* Our target is small organisations with tens of hosts, not thousands, so the MVP architecture is close to what a pilot needs.

### 9. How is the 0 to 100 score calculated, and isn't it arbitrary?
**[Erick]** Each event is base severity times AI confidence times asset criticality. We add the inaction penalty, 5 points per hour unacknowledged, capped at 30 per incident. Then `100 × (1 − e^(−raw/60))` keeps it below 100. The weights are a starting point; each organisation sets its own threshold and asset criticality.
*Backup:* A single high-severity event on a PII asset lands in amber around 50. Only several incidents, or one incident plus hours of inaction, reach 80. That is deliberate.

### 10. Why not hack back and stop the attacker?
**[Hozen]** It is illegal under Singapore's Computer Misuse Act [SOURCE PENDING: section], the IP is often an innocent hijacked computer, and it invites escalation. CactAI blocks, slows down and deceives inside our own perimeter, and preserves evidence for SingCERT or the police.

### 11. What is actually real in the demo versus mocked?
**[Erick]** Real: the target app, the collectors, the rules, the risk engine, the hash-chained audit log, the blocklist that returns HTTP 403, the Telegram alert and the report. The data in the app is synthetic. Time is sped up (1 minute = 1 hour). [If used: the attack was a replay of recorded logs through the same pipeline / classification used the rules fallback.] Containment is enforced by the app reading our blocklist, not by changing the Windows firewall.
*Backup:* Agents are Python classes inside one core service in the MVP; separate processes, Windows and cloud agents are roadmap.

### 12. Who would pay for this, and why would an SME trust an AI to change its systems?
**[Ishmail]** Singapore SMEs and private education institutions that hold lots of personal data and face PDPA penalties of up to 10% of Singapore turnover or S$1 million [CHECK], but cannot afford a SOC. Trust comes from the limits: humans set the threshold, every fix is temporary and reversible, and every step is on the record. Our next step is a pilot with one private school.

---

## Bonus quick answers
- **"What does 'hash-chained' mean?"** Each log record contains the hash of the previous one. Change or delete any record and every hash after it stops matching. `GET /audit` reports `chain_valid`.
- **"Can you prove the operator read the alert?"** No, and we say so. We prove delivery (Telegram message ID and time) and acknowledgement (button press). The report says "Ack: none", not "they saw it".
- **"What if the operator is asleep at 3am?"** That is exactly the case: the ladder escalates to the team lead and IT manager, and above the threshold CactAI contains the threat temporarily so nobody has to wake up to stop the bleeding.
- **"Why the cactus?"** It never attacks. It just makes touching it a bad idea.
