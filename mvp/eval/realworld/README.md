# Public-server replay set

How well SentrAI's classifier catches what really hits a small public Linux server: web scanners,
exploit probes, SSH password guessing and SSH banner grabbers, next to normal visitors, crawlers,
uptime checks and the admin's own logins.

```
python eval/realworld/build_replay.py     # rebuilds events.jsonl, nginx_access.log, auth.log
python eval/realworld/score_replay.py     # scores them, writes results/realworld_eval.{md,json}
python -m pytest eval/realworld           # guards: attackers caught, no false alarms, no leaked addresses
```

`score_replay.py --core <another core/ dir> --tag before` scores an older copy of core (that is how
`results/before.json`, the main branch before this change, was made). `--parser` points at the
collector's `parsers.py` for the "collector-parsed" column; it is found automatically once PR #23 is
merged.

## The set

1,808 synthetic lines: 1,454 nginx "combined" access lines and 354 sshd lines (classic syslog and
the ISO-timestamp format of newer Debian/Ubuntu). `nginx_access.log` and `auth.log` hold the same lines
as plain log files, so they can also be replayed through the collector.

- Normal: 40 visitors with their assets and stray 404s (favicon, typos), a parent's login typo, a
  broken image refreshed six times, Googlebot re-crawling 15 dead links in a minute, Bingbot, an
  uptime check every minute, Let's Encrypt, the admin's SSH sessions, a CI deploy key every 10
  minutes, a teacher's password typo.
- Web attacks: a `.env`/`.git`/backup-file scanner, a WordPress scanner, a directory brute-forcer
  with no signature (only its 404 burst gives it away, and it asks for `/export.php` and
  `/admin/export`, which used to be called data exfiltration), zgrab, Censys, Nuclei, Nikto, TLS
  junk on port 80, Log4Shell, PHPUnit and router exploit probes, ThinkPHP, path traversal, an
  open-proxy check, sqlmap, a manual SQLi and XSS, and a web login brute force.
- SSH: a root password brute force, a dictionary of invalid users (the pattern seen on the real
  server), the same against a key-only server (no "Failed password" lines at all), a password
  guessed after 7 tries, a slow one-guess-every-5-minutes attempt, and 5 banner grabbers.

All addresses are documentation ranges (192.0.2.0/24 normal, 198.51.100.0/24 and 203.0.113.0/24
attackers); there is no real log data in it.

## Labels

Every line of an attack session carries that attack's category, including lines that cannot show
it alone (the first guesses before a threshold, `pam_unix(sshd:auth): check pass; user unknown`,
which names no address). Those count as misses, so per-line recall understates detection. The
per-source table ("attackers flagged: 25 of 28", "flagged from line") is the better measure.

## Known misses

- The slow brute force (one guess every 5 minutes) stays under the 5-guesses-in-10-minutes
  threshold. Raise `SSH_BRUTE_FORCE_WINDOW_S` to catch it, at the cost of flagging people who
  mistype their password a few times over an afternoon.
- Banner grabbers that connect only once or twice are not flagged (threshold 3), because uptime
  monitors that only check port 22 look the same.

I wrote both the rules and this set, so the numbers are optimistic; replaying a day of the real
server's logs (with the collector from PR #23) is the honest check.
