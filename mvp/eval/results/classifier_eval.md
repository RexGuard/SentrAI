# CactAI classifier accuracy

178 labelled events (116 lab, 17 replay, 45 handcrafted). Built by `eval/build_dataset.py`, scored by `eval/evaluate.py`.
Jev: disabled: TYPESAFE_API_KEY not set (fallback classifier in use).

## Headline

| | Rules | Keyword fallback | Chain (as shipped) | Jev | Chain with Jev |
|---|---|---|---|---|---|
| Macro F1 | 78% | 58% | 79% | not run | not run |
| Accuracy | 62% | 58% | 76% | not run | not run |
| Attacks flagged | 56% | 25% | 57% | not run | not run |
| False alarms on benign | 1% | 2% | 2% | not run | not run |
| No answer | 41 | 0 | 0 | not run | not run |

## F1 per category

Precision / recall / F1. Support is the number of events with that label.

| Category | Support | Rules | Keyword fallback | Chain (as shipped) | Jev | Chain with Jev |
|---|---|---|---|---|---|---|
| benign | 82 | 70% / 70% / **70%** | 53% / 98% / **68%** | 66% / 98% / **79%** | not run | not run |
| brute_force | 46 | 100% / 39% / **56%** | 0% / 0% / **0%** | 100% / 39% / **56%** | not run | not run |
| sql_injection | 14 | 100% / 71% / **83%** | 100% / 43% / **60%** | 100% / 71% / **83%** | not run | not run |
| xss | 5 | 100% / 100% / **100%** | 100% / 100% / **100%** | 100% / 100% / **100%** | not run | not run |
| port_scan | 5 | 100% / 60% / **75%** | 100% / 60% / **75%** | 100% / 60% / **75%** | not run | not run |
| privilege_escalation | 10 | 100% / 80% / **89%** | 100% / 50% / **67%** | 100% / 90% / **95%** | not run | not run |
| data_exfiltration | 11 | 100% / 55% / **71%** | 50% / 9% / **15%** | 86% / 55% / **67%** | not run | not run |
| misconfiguration | 5 | 80% / 80% / **80%** | 80% / 80% / **80%** | 80% / 80% / **80%** | not run | not run |

## What the shipped chain gets wrong

| Event | Label | Predicted | Line |
|---|---|---|---|
| eval-0065 (lab) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0066 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0067 (lab) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0068 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0069 (lab) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0070 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0071 (lab) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0072 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0074 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0076 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0078 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0080 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0082 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0084 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0086 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0088 (lab) | brute_force | benign | `login fail user=admin` |
| eval-0095 (lab) | sql_injection | benign | `SELECT rows=0 q='1 AND 1=1'` |
| eval-0096 (lab) | sql_injection | benign | `SELECT rows=0 q="admin' #"` |
| eval-0098 (lab) | sql_injection | benign | `SELECT rows=0 q="' uNiOn/**/SeLeCt null,version()--"` |
| eval-0099 (lab) | sql_injection | benign | `SELECT rows=0 q="x' AND extractvalue(1,concat(0x7e,database()))--"` |
| eval-0106 (lab) | data_exfiltration | benign | `SELECT rows=40 q='SELECT * FROM members'` |
| eval-0108 (lab) | data_exfiltration | benign | `SELECT rows=40 q='SELECT * FROM members'` |
| eval-0110 (lab) | data_exfiltration | benign | `SELECT rows=40 q='SELECT * FROM members'` |
| eval-0112 (lab) | data_exfiltration | benign | `SELECT rows=40 q='SELECT * FROM members'` |
| eval-0120 (replay) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0121 (replay) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0122 (replay) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0123 (replay) | brute_force | benign | `POST /login 401 user=admin` |
| eval-0137 (handcrafted) | port_scan | benign | `firewall: 214 connection attempts to 97 distinct ports from 203.0.113.9 in 10s` |
| eval-0138 (handcrafted) | port_scan | benign | `kernel: TCP SYN to closed ports 21,22,23,25,80,110,139,443,445,3389 from 203.0.113.9` |
| eval-0143 (handcrafted) | misconfiguration | benign | `blob container 'reports' access level changed to public (anonymous read)` |
| eval-0146 (handcrafted) | privilege_escalation | benign | `sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash` |
| eval-0149 (handcrafted) | brute_force | benign | `EventID=4625 An account failed to log on. Account=administrator Source=203.0.113.60` |
| eval-0150 (handcrafted) | brute_force | benign | `EventID=4625 An account failed to log on. Account=administrator Source=203.0.113.60` |
| eval-0151 (handcrafted) | brute_force | benign | `EventID=4625 An account failed to log on. Account=administrator Source=203.0.113.60` |
| eval-0152 (handcrafted) | brute_force | benign | `EventID=4625 An account failed to log on. Account=administrator Source=203.0.113.60` |
| eval-0155 (handcrafted) | brute_force | benign | `sshd[812]: Failed password for root from 203.0.113.61 port 40100 ssh2` |
| eval-0156 (handcrafted) | brute_force | benign | `sshd[812]: Failed password for root from 203.0.113.61 port 40101 ssh2` |
| eval-0157 (handcrafted) | brute_force | benign | `sshd[812]: Failed password for root from 203.0.113.61 port 40102 ssh2` |
| eval-0158 (handcrafted) | brute_force | benign | `sshd[812]: Failed password for root from 203.0.113.61 port 40103 ssh2` |
| eval-0163 (handcrafted) | data_exfiltration | benign | `s3 GetObject x 1840 objects (2.1 GB) bucket=aegis-student-docs by key AKIA...XYZ from 203.` |
| eval-0175 (handcrafted) | benign | misconfiguration | `Security group sg-0a1 rule removed: ingress 0.0.0.0/0 tcp 3389` |
| eval-0178 (handcrafted) | benign | data_exfiltration | `GET /help/download all course notes 200` |

"Attacks flagged" counts any attack label on an attack event, even the wrong one. Rules "no answer" means the event was passed on to Jev or the fallback.
