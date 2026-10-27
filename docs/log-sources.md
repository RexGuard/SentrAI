---
title: Log sources
nav: docs
description: The logs SentrAI can read, what it catches in each one, and the one setting some of them need.
---

# Log sources

SentrAI only reads the logs you approve. The quickest way to approve the usual ones is:

```bash
python -m collector.collector --add-system-logs   # from mvp/lab; the agent installer runs it for you
```

It looks for every log below at its usual place and approves the ones it finds. You can also
pick logs on the dashboard under **Collector**.

| Log | Where it usually is | What SentrAI catches |
| --- | --- | --- |
| nginx | `/var/log/nginx/access.log`, `error.log` | web scans, probes for secret files, SQL injection, cross-site scripting, web login guessing |
| SSH logins | `/var/log/auth.log`, `/var/log/secure`, or the systemd journal | password guessing, a guessed password, port scans |
| Windows Event Log | read straight from Windows | Windows and Remote Desktop password guessing, someone added to Administrators, a cleared event log, a suspicious new service, malware found by Microsoft Defender, SQL Server password guessing |
| Suricata | `/var/log/suricata/eve.json` | network alerts: scans, exploits, SQL injection, malware calling home, crypto miners, brute force |
| MySQL or MariaDB | `/var/log/mysql/error.log`, `/var/log/mysqld.log`, `/var/log/mariadb/mariadb.log` | password guessing; with the query log on, SQL injection and whole-table dumps |
| PostgreSQL | `/var/log/postgresql/postgresql-*-main.log` | password guessing, unknown accounts, blocked hosts; with statement logging on, SQL injection and whole-table dumps |
| MongoDB | `/var/log/mongodb/mongod.log` | password guessing, unknown accounts |

Five failed sign-ins from one address within 10 minutes is password guessing, for every service
in the table (the same rule as SSH). A sign-in that works right after that is flagged as a
password that may have been guessed.

## Settings some logs need

**Windows.** Run SentrAI as an administrator, or add its account to the **Event Log Readers**
group, so it can read the Security log. It reads the Security, System, Application and Microsoft
Defender logs every 5 seconds and carries on from the last record after a restart. Windows only
writes failed sign-ins when auditing is on, which it is by default on servers; on Windows 10 and 11
turn on **Audit logon events** (Failure) under Local Security Policy, Audit Policy.

**MySQL 8.** Failed sign-ins are only written with

```ini
[mysqld]
log_error_verbosity = 3
```

MariaDB writes them by default.

**PostgreSQL.** Failed sign-ins are always written. To see which address they came from, turn on

```ini
log_connections = on
```

or add `%h` to `log_line_prefix`. SentrAI joins each failed sign-in to the connection line of the
same process.

**Suricata.** The default `eve.json` output is enough. SentrAI keeps only the alerts and skips
flow, DNS and other records. When an alert is about traffic leaving your network, SentrAI blames
the outside address, never your own machine.

**Reading rights on Linux.** The collector (or the agent) runs as its own account, which is in the
`adm` and `systemd-journal` groups. On Debian and Ubuntu that already covers the nginx, SSH, MySQL
and PostgreSQL logs. Suricata and MongoDB logs are often readable by root only; let SentrAI read
one with `sudo setfacl -m u:sentrai:r /var/log/suricata/eve.json` (and `u:sentrai:rx` on its
folder). A log it cannot read is skipped with a message, never a crash.

## Logs SentrAI does not have a reader for

Any other log can still be approved. Each line is sent as plain text, and SentrAI guesses the
address and account from it. A tool that can post JSON can also send its alerts to SentrAI's
webhook (`POST /webhook/<name>`).
