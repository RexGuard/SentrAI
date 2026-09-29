# SentrAI classifier accuracy: public-server replay

1808 labelled synthetic events (1454 nginx access lines, 354 sshd lines). Built by `eval/realworld/build_replay.py`, scored by `eval/realworld/score_replay.py`. Jev not run.

## Headline

| | Rules | Keyword fallback | Chain (as shipped) | Chain, collector-parsed events | Chain before this change |
|---|---|---|---|---|---|
| Macro F1 | 94% | 49% | 94% | 94% | 62% |
| Accuracy | 94% | 77% | 94% | 94% | 83% |
| Attack lines flagged | 74% | 1% | 74% | 74% | 25% |
| False alarms on benign lines | 0% | 0% | 0% | 0% | 0% |
| No answer | 0 | 0 | 0 | 0 | 0 |
| Lines called data exfiltration (none are) | 0 | 1 | 0 | 0 | 3 |

## F1 per category

Precision / recall / F1. Support is the number of lines with that label.

| Category | Support | Rules | Keyword fallback | Chain (as shipped) | Chain, collector-parsed events | Chain before this change |
|---|---|---|---|---|---|---|
| benign | 1396 | 93% / 100% / **96%** | 77% / 100% / **87%** | 93% / 100% / **96%** | 93% / 100% / **96%** | 82% / 100% / **90%** |
| brute_force | 310 | 100% / 71% / **83%** | 0% / 0% / **0%** | 100% / 71% / **83%** | 100% / 71% / **83%** | 100% / 30% / **47%** |
| sql_injection | 5 | 100% / 100% / **100%** | 100% / 40% / **57%** | 100% / 100% / **100%** | 100% / 100% / **100%** | 100% / 60% / **75%** |
| xss | 1 | 100% / 100% / **100%** | 100% / 100% / **100%** | 100% / 100% / **100%** | 100% / 100% / **100%** | 100% / 100% / **100%** |
| port_scan | 96 | 100% / 81% / **90%** | 0% / 0% / **0%** | 100% / 81% / **90%** | 100% / 81% / **90%** | 0% / 0% / **0%** |
| data_exfiltration | 0 | 0% / 0% / **0%** | 0% / 0% / **0%** | 0% / 0% / **0%** | 0% / 0% / **0%** | 0% / 0% / **0%** |

## Per source (chain as shipped)

Attackers flagged: **25 of 28** (25 with the right category). Normal sources that raised any alarm: **0 of 52**.

| Attacker | Kind | Label | Lines | Flagged from line | Flagged as |
|---|---|---|---|---|---|
| ssh-compromise | guessed_password | brute_force | 9 | 5 | brute_force (4) |
| ssh-dict | invalid_user_dictionary | brute_force | 120 | 25 | brute_force (80) |
| ssh-keyonly-invalid | key_only_server | brute_force | 16 | 9 | brute_force (8) |
| ssh-keyonly-root | key_only_server | brute_force | 8 | 5 | brute_force (4) |
| ssh-root-bf | password_bruteforce | brute_force | 120 | 19 | brute_force (102) |
| ssh-scanner-0 | banner_grab | port_scan | 4 | 3 | port_scan (2) |
| ssh-scanner-1 | banner_grab | port_scan | 3 | 3 | port_scan (1) |
| ssh-scanner-2 | banner_grab | port_scan | 1 | - | missed |
| ssh-scanner-3 | banner_grab | port_scan | 2 | - | missed |
| ssh-scanner-4 | banner_grab | port_scan | 5 | 3 | port_scan (3) |
| ssh-slow-bf | slow_bruteforce | brute_force | 12 | - | missed |
| censys | scanner_ua | port_scan | 1 | 1 | port_scan (1) |
| dirbuster | path_bruteforce | port_scan | 30 | 10 | port_scan (21) |
| env-scanner | secret_file_probe | port_scan | 20 | 1 | port_scan (20) |
| log4shell | exploit_probe | port_scan | 1 | 1 | port_scan (1) |
| manual-sqli | sqli | sql_injection | 1 | 1 | sql_injection (1) |
| manual-xss | xss | xss | 1 | 1 | xss (1) |
| nikto | scanner_ua | port_scan | 3 | 1 | port_scan (3) |
| nuclei | scanner_ua | port_scan | 5 | 1 | port_scan (5) |
| phpunit-rce | exploit_probe | port_scan | 1 | 1 | port_scan (1) |
| proxy-check | proxy_probe | port_scan | 2 | 1 | port_scan (2) |
| router-bot | exploit_probe | port_scan | 2 | 1 | port_scan (2) |
| sqlmap | sqli_tool | sql_injection | 4 | 1 | sql_injection (4) |
| thinkphp | exploit_probe | port_scan | 1 | 1 | port_scan (1) |
| traversal | exploit_probe | port_scan | 1 | 1 | port_scan (1) |
| web-login-bf | login_bruteforce | brute_force | 25 | 5 | brute_force (21) |
| wp-scanner | cms_probe | port_scan | 12 | 1 | port_scan (12) |
| zgrab | scanner_ua | port_scan | 2 | 1 | port_scan (2) |

Before this change: 9 of 28 attackers flagged (7 with the right category); 0 normal sources raised an alarm.

## What the shipped chain gets wrong

| Source | Label | Predicted | Lines | Example |
|---|---|---|---|---|
| ssh-slow-bf | brute_force | benign | 12 | `Sep 28 00:01:00 srv-demo sshd[13894]: Failed password for root from 203.0.113.54 port 44000 ssh2` |
| ssh-scanner-0 | port_scan | benign | 2 | `Sep 28 00:08:00 srv-demo sshd[83387]: Did not receive identification string from 198.51.100.60 port ` |
| ssh-root-bf | brute_force | benign | 18 | `Sep 28 00:15:00 srv-demo sshd[48827]: pam_unix(sshd:auth): authentication failure; logname= uid=0 eu` |
| ssh-scanner-1 | port_scan | benign | 2 | `2026-09-28T00:25:00.850972+00:00 srv-demo sshd[76454]: banner exchange: Connection from 198.51.100.6` |
| ssh-scanner-2 | port_scan | benign | 1 | `Sep 28 00:42:00 srv-demo sshd[95204]: Unable to negotiate with 198.51.100.62 port 46000: no matching` |
| dirbuster | port_scan | benign | 9 | `198.51.100.12 - - [28/Sep/2026:00:58:00 +0000] "GET /admin HTTP/1.1" 404 514 "-" "Mozilla/5.0 (Windo` |
| ssh-scanner-3 | port_scan | benign | 2 | `2026-09-28T00:59:00.704359+00:00 srv-demo sshd[37149]: Connection closed by 198.51.100.63 port 46000` |
| ssh-dict | brute_force | benign | 40 | `2026-09-28T01:02:00.991232+00:00 srv-demo sshd[46478]: Invalid user admin from 203.0.113.51 port 410` |
| ssh-scanner-4 | port_scan | benign | 2 | `Sep 28 01:16:00 srv-demo sshd[90305]: Did not receive identification string from 198.51.100.64 port ` |
| web-login-bf | brute_force | benign | 4 | `203.0.113.20 - - [28/Sep/2026:01:20:00 +0000] "POST /login HTTP/1.1" 401 434 "-" "python-requests/2.` |
| ssh-keyonly-invalid | brute_force | benign | 8 | `Sep 28 01:30:00 srv-demo sshd[12388]: Invalid user admin from 203.0.113.52 port 42000` |
| ssh-keyonly-root | brute_force | benign | 4 | `Sep 28 01:35:00 srv-demo sshd[90727]: Connection closed by authenticating user root 203.0.113.53 por` |
| ssh-compromise | brute_force | benign | 5 | `Sep 28 01:40:00 srv-demo sshd[96697]: Failed password for deploy from 203.0.113.55 port 45000 ssh2` |

Every line of an attack session carries the attack label, so the first lines before a threshold (5 SSH guesses in 10 minutes, 10 not-found replies in 2 minutes, 5 failed web logins in 60 s) count as misses. The per-source table is the better guide to whether an attacker gets caught.
