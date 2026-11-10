"""Website check: looks at the company's own website from the outside, the way a stranger on the internet would,
and says in plain words what is open, what someone could do with it and how to fix it.

What it reads (a "quick look", at most MAX_REQUESTS requests to the site, spaced out, usually under 20 seconds):
- the home page and up to MAX_SCRIPTS of the site's own scripts (keys left in code, mixed content, forms that
  send passwords unprotected, error pages, folder listings)
- the security settings the site sends with every page (HTTPS, HSTS, CSP, framing, nosniff, cookies, version
  banners) and its certificate (expiry, TLS version, failures)
- two files that should never be public, /.env and /.git/HEAD, and /.well-known/security.txt
- public DNS records about the domain (SPF and DMARC, which stop strangers sending email as the company). DNS
  is read through a public DNS-over-HTTPS resolver, never from the site.

What it never does: sign in, fill or send a form, guess passwords, follow a link off the company's domain, or
keep going when the site slows down or refuses. Anything it could not look at is reported as "not checked",
never as passed.

Only websites the company owns. A domain is checked only after SentrAI's team adds it (`sentrai websites add`)
and the company proves it owns it with a DNS TXT record or a small file on the site. The proof is read again
before every check, so it must stay published; a sub-domain of a proven domain counts as proven. Addresses that
resolve to private, loopback or other non-public networks are refused, because this is an outside look only.

Values found (keys, .env lines) are never stored or shown in full: the first few characters only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

MAX_REQUESTS = 12          # requests to the site itself in one check (DNS lookups are not to the site)
MAX_SCRIPTS = 4            # the site's own scripts read for leaked keys
PAGE_BYTES = 1_500_000     # most of a home page that is read
SCRIPT_BYTES = 2_000_000
SMALL_BYTES = 16_384       # /.env, /.git/HEAD, security.txt, the proof file
TIMEOUT_S = 8.0
PAUSE_S = 0.25             # between two requests to the site
MAX_SITES = 25
HISTORY = 10               # grades kept per site
VERIFY_TXT = "sentrai-site-verification="
VERIFY_FILE = "/.well-known/sentrai-site-verification.txt"
DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "SentrAI-WebsiteCheck/1 (owner-approved outside check)"

SEVERITIES = ("urgent", "high", "medium", "low", "info")
WEIGHT = {"urgent": 35, "high": 15, "medium": 6, "low": 2, "info": 0}
SEVERITY_WORD = {"urgent": "Fix today", "high": "Serious", "medium": "Worth fixing", "low": "Small", "info": "Good to know"}

HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")

# Shaped like real secret keys. Public-by-design keys (Google Maps, Stripe pk_, Supabase anon) are left out.
SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("private_key", "a private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("stripe", "a Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("aws", "an Amazon Web Services access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github", "a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})")),
    ("slack", "a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("openai", "an OpenAI key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("anthropic", "an Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("sendgrid", "a SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
)
STACK_TRACE = re.compile(r"Traceback \(most recent call last\)|Whoops, looks like something went wrong|"
                         r"at [\w$.]+\([\w/.-]+\.(?:js|java|cs):\d+|<b>(?:Fatal|Parse) error</b>|"
                         r"Exception in thread \"main\"|DEBUG = True|Django tried these URL patterns")
DEV_BUILD = re.compile(r"react(?:-dom)?\.development\.js|vue\.global\.js|You are running Vue in development mode")
SESSIONISH = re.compile(r"(?i)sess|sid$|^sid|auth|token|jwt|login")
VERSION_IN = re.compile(r"\d+\.\d+")


class WebsiteError(Exception):
    """Something the person asked for that cannot be done; the message says why in plain words."""


# ------------------------------------------------------------------ the network, kept apart so tests can stand in

@dataclass
class Resp:
    status: int
    url: str
    headers: dict[str, str] = field(default_factory=dict)   # lower-case names
    cookies: list[str] = field(default_factory=list)        # raw Set-Cookie lines
    body: str = ""
    error: str = ""                                          # set when no answer came back


class Net:
    """The real network: plain HTTP(S) reads with no redirects followed, a TLS look and DNS TXT records."""

    def __init__(self, doh_url: str | None = None, pause_s: float = PAUSE_S) -> None:
        self.doh_url = doh_url or os.environ.get("SENTRAI_DOH_URL") or DOH_URL
        self.pause_s = pause_s

    def pause(self) -> None:
        time.sleep(self.pause_s)

    def addresses(self, host: str) -> list[str]:
        try:
            return sorted({i[4][0] for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        except OSError:
            return []

    def get(self, url: str, max_bytes: int) -> Resp:
        import httpx
        try:
            with httpx.Client(timeout=TIMEOUT_S, follow_redirects=False, verify=True,
                              headers={"User-Agent": USER_AGENT, "Accept": "*/*"}) as c:
                with c.stream("GET", url) as r:
                    buf = bytearray()
                    for chunk in r.iter_bytes():
                        buf += chunk
                        if len(buf) >= max_bytes:
                            break
                    return Resp(r.status_code, str(r.url), {k.lower(): v for k, v in r.headers.items()},
                                r.headers.get_list("set-cookie"), bytes(buf[:max_bytes]).decode("utf-8", "replace"))
        except httpx.HTTPError as e:
            return Resp(0, url, error=_short_error(e))

    def tls(self, host: str) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=TIMEOUT_S) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert = s.getpeercert() or {}
                    return {"version": s.version(), "not_after": cert.get("notAfter"),
                            "names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]}
        except ssl.SSLCertVerificationError as e:
            return {"cert_error": str(e.verify_message or e.reason or e)[:200]}
        except (OSError, ssl.SSLError) as e:
            return {"error": _short_error(e)}

    def txt(self, name: str) -> list[str] | None:
        """TXT records for a name, or None when DNS could not be read (not the same as "none")."""
        try:
            import dns.resolver  # type: ignore[import-not-found]  (dnspython, when installed)
            try:
                return ["".join(p.decode("utf-8", "replace") for p in r.strings)
                        for r in dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT_S)]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except Exception:  # noqa: BLE001
                return None
        except ImportError:
            pass
        import httpx
        try:
            r = httpx.get(self.doh_url, params={"name": name, "type": "TXT"}, timeout=TIMEOUT_S,
                          headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT})
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return None
        if data.get("Status") not in (0, 3):  # 0 found, 3 no such name
            return None
        return [_txt_data(a.get("data", "")) for a in data.get("Answer") or [] if a.get("type") == 16]


def _txt_data(raw: str) -> str:
    """'"v=spf1 include:a" " -all"' -> 'v=spf1 include:a -all' (a long record comes in quoted pieces)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
    return "".join(parts) if parts else raw


def _short_error(e: Exception) -> str:
    text = str(e) or type(e).__name__
    return text.splitlines()[0][:160]


# ------------------------------------------------------------------ small helpers

def clean_domain(raw: Any) -> str:
    """'https://WWW.Example.com/shop' -> 'www.example.com'. Raises WebsiteError for anything that is not a domain."""
    text = str(raw or "").strip().lower()
    if "://" not in text:
        text = "https://" + text
    host = (urlsplit(text).hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise WebsiteError(f"{raw!r} is not a website address.") from None
    try:
        ipaddress.ip_address(host)
        raise WebsiteError("Give the website's name (like example.com), not a number address.")
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise WebsiteError(f"{raw!r} is not a website address. Write it like example.com.")
    return host


def public_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def same_site(host: str, domain: str) -> bool:
    host = (host or "").lower().rstrip(".")
    base = domain[4:] if domain.startswith("www.") else domain
    return host == domain or host == base or host.endswith("." + base)


def redact(value: str) -> str:
    value = value.strip()
    return (value[:6] + "…" + value[-2:]) if len(value) > 12 else (value[:3] + "…")


def _cert_days(not_after: str | None, now: float) -> int | None:
    if not not_after:
        return None
    try:
        end = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int((end.timestamp() - now) // 86400)


class _Page(HTMLParser):
    """What the home page loads and sends: scripts, styles, frames, images, forms and a few meta tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str]] = []
        self.loads: list[tuple[str, str]] = []      # (tag, url) for images, styles, frames, media
        self.forms: list[dict[str, Any]] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "integrity": a.get("integrity", "")})
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.loads.append(("link", a["href"]))
        elif tag in ("img", "iframe", "audio", "video", "source", "embed") and a.get("src"):
            self.loads.append((tag, a["src"]))
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "password": False})
        elif tag == "input" and a.get("type", "").lower() == "password":
            if self.forms:
                self.forms[-1]["password"] = True
            else:
                self.forms.append({"action": "", "password": True})
        elif tag == "meta":
            key = (a.get("http-equiv") or a.get("name") or "").lower()
            if key:
                self.meta[key] = a.get("content", "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 200:
            self.title += data


# ------------------------------------------------------------------ one check

class _Budget(Exception):
    """The request allowance ran out or the site asked us to stop."""


class Check:
    """One quick look at one domain. Build it, call run(), read the result."""

    def __init__(self, domain: str, net: Net, now: float, by: str = "") -> None:
        self.domain, self.net, self.now, self.by = domain, net, now, by
        self.requests = 0
        self.failures = 0
        self.stopped = ""
        self.findings: list[dict[str, Any]] = []
        self.checks: dict[str, dict[str, Any]] = {}

    # -- bookkeeping
    def mark(self, key: str, label: str, status: str, note: str = "") -> None:
        if key not in self.checks or self.checks[key]["status"] != "problem":
            self.checks[key] = {"key": key, "label": label, "status": status, "note": note}

    def find(self, key: str, label: str, severity: str, title: str, saw: str, detail: str, risk: str, fix: str,
             where: str = "") -> None:
        self.mark(key, label, "problem")
        self.findings.append({
            "key": key, "check": label, "severity": severity, "severity_word": SEVERITY_WORD[severity],
            "title": title, "saw": saw, "detail": detail, "risk": risk, "fix": fix,
            "where": where or f"https://{self.domain}/",
            "fix_prompt": (f"My website {self.domain} has this security problem: {title}. {saw} Please fix it: {fix} "
                           f"Change nothing else, and tell me how to check that it worked.")})

    def fetch(self, url: str, max_bytes: int) -> Resp:
        if self.stopped:
            raise _Budget(self.stopped)
        if self.requests >= MAX_REQUESTS:
            raise _Budget(f"used all {MAX_REQUESTS} requests")
        host = urlsplit(url).hostname or ""
        if not same_site(host, self.domain):
            raise WebsiteError(f"refused to leave {self.domain}")  # never reached: callers check first
        addrs = self.net.addresses(host)
        if not addrs or not all(public_address(x) for x in addrs):
            self.stopped = f"{host} does not point to a public internet address"
            raise _Budget(self.stopped)
        if self.requests:
            self.net.pause()
        self.requests += 1
        r = self.net.get(url, max_bytes)
        if r.status in (429, 503) or (r.status == 0 and self.failures >= 1):
            self.stopped = ("the site asked us to slow down" if r.status == 429 else
                            "the site was busy" if r.status == 503 else f"the site stopped answering ({r.error})")
        if r.status == 0:
            self.failures += 1
        return r

    def follow(self, url: str, max_bytes: int, hops: int = 3) -> Resp:
        """GET, following redirects only while they stay on the company's own domain."""
        r = self.fetch(url, max_bytes)
        while r.status in (301, 302, 303, 307, 308) and hops > 0 and r.headers.get("location"):
            nxt = urljoin(r.url, r.headers["location"])
            if not same_site(urlsplit(nxt).hostname or "", self.domain):
                r.error = f"sends visitors on to {urlsplit(nxt).hostname} (not checked: another domain)"
                return r
            hops -= 1
            r = self.fetch(nxt, max_bytes)
        return r

    # -- the checks
    def run(self) -> dict[str, Any]:
        steps: tuple[tuple[str, Callable[[], None]], ...] = (
            ("https", self._https), ("files", self._files), ("tls", self._tls), ("email", self._email))
        for _name, step in steps:
            try:
                step()
            except _Budget:
                continue
        return self.result()

    def _https(self) -> None:
        d = self.domain
        plain = self.fetch(f"http://{d}/", SMALL_BYTES)
        loc = plain.headers.get("location", "")
        if plain.status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            self.mark("http_redirect", "Plain-web visitors are sent to the safe address", "ok")
        elif plain.status == 0:
            self.mark("http_redirect", "Plain-web visitors are sent to the safe address", "ok",
                      "Nothing answers on plain http, which is fine.")
        elif 200 <= plain.status < 300:
            self.find("http_redirect", "Plain-web visitors are sent to the safe address", "medium",
                      "Visitors who type the address without https are not protected",
                      f"http://{d}/ shows the site without moving visitors to the secure https:// address.",
                      f"http://{d}/ answered {plain.status} with no redirect to https.",
                      "On public Wi-Fi someone could read or change what those visitors see and send.",
                      "Make every http:// address redirect (301) to the same https:// address.", f"http://{d}/")
        else:
            self.mark("http_redirect", "Plain-web visitors are sent to the safe address", "not_checked",
                      f"http:// answered {plain.status}.")

        page = self.follow(f"https://{d}/", PAGE_BYTES)
        if not 200 <= page.status < 300:
            why = page.error or f"it answered {page.status}"
            self.mark("https", "The website opens over https", "not_checked", f"Could not read the home page: {why}.")
            if page.status == 0 and "certificate" in page.error.lower():
                self.find("cert_failure", "Certificate", "high", "Browsers will warn visitors that the site is unsafe",
                          "The secure connection failed the checks every browser makes.", page.error[:200],
                          "Visitors see a full-page warning and many leave; some learn to click past real warnings.",
                          "Renew or reinstall the site's certificate so it matches the address and is not expired.")
            return
        self.mark("https", "The website opens over https", "ok")
        self._headers(page)
        self._cookies(page)
        self._content(page)

    def _headers(self, page: Resp) -> None:
        h = page.headers
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if not hsts:
            self.find("hsts", "Browsers always use https (HSTS)", "low", "Browsers are not told to always use https",
                      "The site does not send the setting that makes browsers use https every time.",
                      "No Strict-Transport-Security header.",
                      "A visitor's first visit on a hostile network could be moved to a fake plain-web copy.",
                      "Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains.")
        elif not m or int(m.group(1)) < 15_552_000:
            self.find("hsts", "Browsers always use https (HSTS)", "low", "The always-use-https rule is very short",
                      "Browsers forget the always-use-https rule quickly.", f"Strict-Transport-Security: {hsts[:120]}",
                      "Visitors lose the protection between visits.", "Set max-age to at least 31536000 (one year).")
        else:
            self.mark("hsts", "Browsers always use https (HSTS)", "ok")

        csp = h.get("content-security-policy", "")
        if not csp:
            only_report = bool(h.get("content-security-policy-report-only"))
            self.find("csp", "Limits on where scripts may come from (CSP)", "low",
                      "Nothing limits which scripts can run on the site",
                      "The site does not tell browsers which places scripts may load from."
                      + (" A report-only policy is set, which warns but blocks nothing." if only_report else ""),
                      "No enforced Content-Security-Policy header.",
                      "If someone slips a script into a page (for example through a comment box), it runs freely and "
                      "can steal what visitors type.",
                      "Add a Content-Security-Policy header that allows scripts only from the site itself and the "
                      "few services it really uses. Start in report-only mode, then enforce it.")
        else:
            self.mark("csp", "Limits on where scripts may come from (CSP)", "ok")

        if "frame-ancestors" not in csp and not h.get("x-frame-options"):
            self.find("framing", "Other sites cannot hide yours in a frame", "low",
                      "Other websites can show your site inside theirs",
                      "Nothing stops another site from loading your pages inside a hidden frame.",
                      "No X-Frame-Options and no frame-ancestors in a Content-Security-Policy.",
                      "A fake page could trick visitors into clicking buttons on your real site (clickjacking).",
                      "Add X-Frame-Options: DENY (or SAMEORIGIN if you frame your own pages).")
        else:
            self.mark("framing", "Other sites cannot hide yours in a frame", "ok")

        if h.get("x-content-type-options", "").lower() != "nosniff":
            self.find("nosniff", "Browsers do not guess file types", "low", "Browsers may guess what a file is",
                      "The site does not stop browsers guessing file types.", "No X-Content-Type-Options: nosniff.",
                      "An uploaded file could be run as a script instead of shown as a picture or text.",
                      "Add the header X-Content-Type-Options: nosniff.")
        else:
            self.mark("nosniff", "Browsers do not guess file types", "ok")

        if not h.get("referrer-policy"):
            self.find("referrer", "Page addresses are not shared with other sites", "info",
                      "Full page addresses may be passed to other sites",
                      "When visitors click a link out, other sites may see the full address they came from.",
                      "No Referrer-Policy header.",
                      "Addresses with private details in them (order numbers, reset links) could leak.",
                      "Add the header Referrer-Policy: strict-origin-when-cross-origin.")
        else:
            self.mark("referrer", "Page addresses are not shared with other sites", "ok")

        banner = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version")
                  if h.get(k) and (k != "server" or VERSION_IN.search(h[k]))]
        if banner:
            self.find("version_banner", "The site does not announce its software versions", "low",
                      "The site tells everyone which software versions it runs",
                      "Every answer names the exact software behind the site.", "; ".join(banner)[:200],
                      "Attackers can look up known holes in that exact version without probing.",
                      "Hide version numbers (for example server_tokens off in nginx, ServerTokens Prod in Apache, "
                      "and remove X-Powered-By), and keep that software updated.")
        else:
            self.mark("version_banner", "The site does not announce its software versions", "ok")

    def _cookies(self, page: Resp) -> None:
        label = "Cookies are sent safely"
        if not page.cookies:
            self.mark("cookies", label, "ok", "The home page sets no cookies.")
            return
        insecure, script_readable, no_samesite = [], [], []
        for raw in page.cookies[:30]:
            name = raw.split("=", 1)[0].strip()[:60]
            attrs = {p.strip().split("=", 1)[0].lower() for p in raw.split(";")[1:]}
            if "secure" not in attrs:
                insecure.append(name)
            if "httponly" not in attrs and SESSIONISH.search(name):
                script_readable.append(name)
            if "samesite" not in attrs:
                no_samesite.append(name)
        if insecure:
            self.find("cookies", label, "medium", "Some cookies can travel unprotected",
                      f"{len(insecure)} cookie(s) may be sent over plain http: {', '.join(insecure[:5])}.",
                      "Set-Cookie without the Secure flag.",
                      "On a hostile network someone could copy them and act as that visitor.",
                      "Add the Secure flag to every cookie the site sets.")
        if script_readable:
            self.find("cookies", label, "low", "Sign-in cookies can be read by scripts",
                      f"Cookies that look like sign-in cookies can be read by page scripts: "
                      f"{', '.join(script_readable[:5])}.", "Set-Cookie without HttpOnly.",
                      "A harmful script on a page could steal someone's signed-in session.",
                      "Add the HttpOnly flag to sign-in and session cookies.")
        if no_samesite:
            self.find("cookies", label, "low", "Cookies do not say which sites may send them",
                      f"{len(no_samesite)} cookie(s) have no SameSite setting: {', '.join(no_samesite[:5])}.",
                      "Set-Cookie without SameSite.",
                      "Another site could make a signed-in visitor's browser do things on your site.",
                      "Add SameSite=Lax (or Strict) to every cookie.")
        if not (insecure or script_readable or no_samesite):
            self.mark("cookies", label, "ok")

    def _content(self, page: Resp) -> None:
        d = self.domain
        p = _Page()
        try:
            p.feed(page.body)
        except Exception:  # noqa: BLE001  broken HTML still gets the other checks
            pass
        body = page.body
        if "index of /" in p.title.lower():
            self.find("dir_listing", "Server folders are not listed", "medium", "The server lists its folders",
                      "The home page is an automatic list of the files in a folder.", f"Page title: {p.title[:80]}",
                      "Anyone can browse and download files that were never meant to be shared.",
                      "Turn off directory listing (autoindex off in nginx, Options -Indexes in Apache).")
        else:
            self.mark("dir_listing", "Server folders are not listed", "ok")
        trace = STACK_TRACE.search(body)
        if trace:
            self.find("errors", "Error details are hidden from visitors", "medium",
                      "The site shows technical error details to the public",
                      "The page shows programming error output that only developers should see.",
                      f"Found: {trace.group(0)[:80]}",
                      "It tells attackers how the site is built and sometimes shows file paths or settings.",
                      "Switch off debug mode on the live site and show a plain error page instead.")
        else:
            self.mark("errors", "Error details are hidden from visitors", "ok")

        mixed = [u for _t, u in p.loads if u.lower().startswith("http://")] + \
                [s["src"] for s in p.scripts if s["src"].lower().startswith("http://")]
        if mixed:
            self.find("mixed", "Everything on the page loads securely", "medium",
                      "Parts of the page load over plain http",
                      f"{len(mixed)} item(s) on the secure page load from plain http:// addresses.",
                      "; ".join(mixed[:4])[:300],
                      "Someone on the same network could swap those parts, for example a script that steals logins.",
                      "Change those addresses to https:// (or host the files on the site itself).")
        else:
            self.mark("mixed", "Everything on the page loads securely", "ok")

        bad_forms = [f for f in p.forms if f["action"].lower().startswith("http://")]
        if bad_forms:
            pw = any(f["password"] for f in bad_forms)
            self.find("forms", "Forms send what people type securely", "high" if pw else "medium",
                      "A form sends what people type without protection" + (" (including a password)" if pw else ""),
                      f"{len(bad_forms)} form(s) send to plain http:// addresses.",
                      "; ".join(f["action"] for f in bad_forms[:3])[:300],
                      "What people type, " + ("including passwords, " if pw else "") + "can be read on the way.",
                      "Make every form send to an https:// address.")
        else:
            self.mark("forms", "Forms send what people type securely", "ok")

        if DEV_BUILD.search(body):
            self.find("dev_build", "The live site runs the finished build", "low",
                      "The live site runs a developer build", "The page loads a development version of its scripts.",
                      f"Found: {DEV_BUILD.search(body).group(0)}",  # type: ignore[union-attr]
                      "Developer builds are slower and show extra detail about how the site works.",
                      "Publish the production build of the site.")

        third = [s for s in p.scripts if s["src"].startswith(("http://", "https://", "//"))
                 and not same_site(urlsplit(urljoin(page.url, s["src"])).hostname or "", d) and not s["integrity"]]
        if third:
            self.find("sri", "Outside scripts are locked to a known version", "low",
                      "Scripts from other companies are not locked to a known version",
                      f"{len(third)} script(s) load from other companies' servers without a fingerprint check.",
                      "; ".join(s["src"] for s in third[:4])[:300],
                      "If one of those companies is hacked, the harmful script runs on your site too.",
                      "Add an integrity=\"sha384-...\" fingerprint to those script tags, or host the files yourself.")
        else:
            self.mark("sri", "Outside scripts are locked to a known version", "ok")

        texts = [("the home page", page.url, body)]
        own = [urljoin(page.url, s["src"]) for s in p.scripts]
        own = [u for u in own if urlsplit(u).scheme == "https" and same_site(urlsplit(u).hostname or "", d)]
        maps = []
        for u in list(dict.fromkeys(own))[:MAX_SCRIPTS]:
            try:
                r = self.fetch(u, SCRIPT_BYTES)
            except _Budget:
                self.mark("secrets", "No secret keys in public code", "not_checked",
                          "Stopped before every script was read.")
                break
            if r.status == 200:
                texts.append((urlsplit(u).path or u, u, r.body))
                tail = r.body[-400:]
                if "sourceMappingURL=" in tail and "sourceMappingURL=data:" not in tail:
                    maps.append(urlsplit(u).path)
        hits: list[tuple[str, str, str, str]] = []
        for where, url, text in texts:
            for _key, what, rx in SECRET_PATTERNS:
                for m in rx.finditer(text):
                    hits.append((what, redact(m.group(0)), where, url))
                    break
        if hits:
            what, sample, where, url = hits[0]
            self.find("secrets", "No secret keys in public code", "urgent", "A secret key is visible to anyone",
                      f"Code anyone can download contains what looks like {what}"
                      + (f" (and {len(hits) - 1} more)" if len(hits) > 1 else "") + ".",
                      "; ".join(f"{w}: {s} in {loc}" for w, s, loc, _u in hits[:4])[:300],
                      "Anyone could use that key to reach the service it belongs to, often with payment or "
                      "customer data.",
                      "Treat the key as stolen: create a new one at the service, delete the old one, and move the "
                      "key to the server so it is never sent to browsers.", url)
        elif "secrets" not in self.checks:
            self.mark("secrets", "No secret keys in public code", "ok",
                      f"Read the home page and {len(texts) - 1} of the site's own script(s).")
        if maps:
            self.find("source_map", "Original code is not published", "info", "Scripts point to their original code",
                      "Some scripts name a source map, which may let anyone read the site's original code.",
                      "sourceMappingURL in: " + ", ".join(maps[:4]),
                      "It makes it easier to find weak spots. Not proof that the map is public.",
                      "Stop publishing source maps on the live site, or keep them private.")

    def _files(self) -> None:
        d = self.domain
        env = self.fetch(f"https://{d}/.env", SMALL_BYTES)
        lines = [ln for ln in env.body.splitlines()[:80] if re.match(r"^\s*(export\s+)?[A-Z][A-Z0-9_]{1,60}\s*=", ln)]
        htmlish = "<html" in env.body[:500].lower() or "text/html" in env.headers.get("content-type", "")
        if env.status == 200 and lines and not htmlish:
            names = [re.split(r"\s*=", ln.replace("export ", "").strip(), maxsplit=1)[0] for ln in lines]
            self.find("env_file", "Settings files are not public", "urgent",
                      "The site's secret settings file can be downloaded",
                      "Anyone can download the site's .env file, which usually holds passwords and keys.",
                      f"{len(names)} setting(s), for example {', '.join(names[:5])} (values not kept).",
                      "Someone could take database passwords, payment keys and email logins from it.",
                      "Block public access to .env (and other dot-files) at once, then change every password and "
                      "key that was in it.", f"https://{d}/.env")
        elif env.status == 0:
            self.mark("env_file", "Settings files are not public", "not_checked", env.error)
        else:
            self.mark("env_file", "Settings files are not public", "ok")

        git = self.fetch(f"https://{d}/.git/HEAD", SMALL_BYTES)
        head = git.body.strip()
        if git.status == 200 and (head.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}", head)):
            self.find("git_folder", "The site's code history is not public", "urgent",
                      "The site's code history can be downloaded",
                      "The hidden .git folder is published with the site.", f"/.git/HEAD answers: {head[:40]}",
                      "Someone could download the whole source code, often with passwords left in old versions.",
                      "Block public access to /.git at once (or remove it from the server), then change any "
                      "password or key that was ever in the code.", f"https://{d}/.git/HEAD")
        elif git.status == 0:
            self.mark("git_folder", "The site's code history is not public", "not_checked", git.error)
        else:
            self.mark("git_folder", "The site's code history is not public", "ok")

        sec = self.fetch(f"https://{d}/.well-known/security.txt", SMALL_BYTES)
        if sec.status == 200 and re.search(r"(?im)^contact:", sec.body):
            self.mark("security_txt", "People know how to report a problem", "ok")
        elif sec.status == 0:
            self.mark("security_txt", "People know how to report a problem", "not_checked", sec.error)
        else:
            self.find("security_txt", "People know how to report a problem", "info",
                      "There is no way for people to report a security problem",
                      "The site has no security.txt, the standard place that says who to tell about a weak spot.",
                      "No /.well-known/security.txt with a Contact line.",
                      "Someone who spots a problem may not know who to tell, or may tell the wrong people.",
                      "Publish /.well-known/security.txt with a Contact: line (an email address) and an Expires: date.",
                      f"https://{d}/.well-known/security.txt")

    def _tls(self) -> None:
        label = "Certificate and secure connection"
        t = self.net.tls(self.domain)
        if t.get("cert_error"):
            self.find("cert_failure", label, "high", "Browsers will warn visitors that the site is unsafe",
                      "The site's certificate failed the checks every browser makes.", t["cert_error"],
                      "Visitors see a full-page warning and many leave; some learn to click past real warnings.",
                      "Renew or reinstall the site's certificate so it matches the address and is not expired.")
            return
        if t.get("error"):
            self.mark("tls", label, "not_checked", t["error"])
            return
        days = _cert_days(t.get("not_after"), self.now)
        version = str(t.get("version") or "")
        if days is not None and days < 0:
            self.find("cert_expiry", label, "high", "The certificate has expired",
                      "The site's certificate ran out, so browsers show a warning.", f"Expired {-days} day(s) ago.",
                      "Visitors are warned away and cannot tell the real site from a fake.",
                      "Renew the certificate now, and switch on automatic renewal.")
        elif days is not None and days <= 30:
            self.find("cert_expiry", label, "high" if days <= 7 else "medium",
                      f"The certificate runs out in {days} day{'s' if days != 1 else ''}",
                      "The site's certificate is close to its end date.", f"Valid until {t.get('not_after')}.",
                      "When it runs out, browsers will warn every visitor away.",
                      "Renew the certificate and switch on automatic renewal (most hosts do it for free).")
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.find("tls_version", label, "medium", "The secure connection uses an old, weak version",
                      f"The site agreed to {version}, which browsers no longer trust.", f"Negotiated {version}.",
                      "Old versions have known weaknesses that let traffic be read.",
                      "Allow only TLS 1.2 and TLS 1.3 in the web server or hosting settings.")
        if "cert_expiry" not in self.checks and "tls_version" not in self.checks:
            self.mark("tls", label, "ok", f"{version or 'TLS'}, certificate good for {days} more days."
                      if days is not None else "")

    def _email(self) -> None:
        d = self.domain[4:] if self.domain.startswith("www.") else self.domain
        txt = self.net.txt(d)
        spf_label = "Strangers cannot send email as you (SPF)"
        if txt is None:
            self.mark("spf", spf_label, "not_checked", "DNS could not be read.")
        else:
            spf = [t for t in txt if t.lower().startswith("v=spf1")]
            if not spf:
                self.find("spf", spf_label, "medium", "Nothing says which servers may send your email",
                          f"{d} has no SPF record.", "No TXT record starting v=spf1.",
                          "Scammers can send email that looks like it comes from you, for example fake invoices.",
                          "Add an SPF record listing your email provider, ending in -all (your email provider shows "
                          "the exact text).")
            elif len(spf) > 1:
                self.find("spf", spf_label, "medium", "Your email settings disagree with each other",
                          f"{d} has {len(spf)} SPF records; mail servers then ignore all of them.",
                          " | ".join(s[:80] for s in spf[:3]), "Fake email in your name is not stopped.",
                          "Merge them into one SPF record.")
            else:
                rec = spf[0].lower()
                lookups = len(re.findall(r"\b(?:include:|a\b|a:|mx\b|mx:|ptr\b|ptr:|exists:|redirect=)", rec))
                if re.search(r"[+?]all\b", rec) or not re.search(r"[~-]all\b|redirect=", rec):
                    self.find("spf", spf_label, "high" if "+all" in rec else "medium",
                              "Your email settings let anyone send as you",
                              f"{d}'s SPF record does not reject other senders.", spf[0][:200],
                              "Scammers can send email that looks like it comes from you.",
                              "End the SPF record with -all (or ~all while testing).")
                elif lookups > 10:
                    self.find("spf", spf_label, "medium", "Your email settings are too long to work",
                              f"{d}'s SPF record needs {lookups} lookups; mail servers stop at 10 and ignore it.",
                              spf[0][:200], "Fake email in your name may not be stopped.",
                              "Shorten the SPF record (remove services you no longer use).")
                else:
                    self.mark("spf", spf_label, "ok")
        dm_label = "Fake email in your name is rejected (DMARC)"
        dm = self.net.txt(f"_dmarc.{d}")
        if dm is None:
            self.mark("dmarc", dm_label, "not_checked", "DNS could not be read.")
        else:
            rec = next((t for t in dm if t.lower().startswith("v=dmarc1")), "")
            policy = (re.search(r"\bp\s*=\s*(\w+)", rec.lower()) or [None, ""])[1] if rec else ""
            if not rec:
                self.find("dmarc", dm_label, "medium", "Mail servers are not told to reject fake email from you",
                          f"{d} has no DMARC record.", f"No TXT record at _dmarc.{d}.",
                          "Fake emails in your name (to customers or staff) reach inboxes.",
                          f"Add a TXT record at _dmarc.{d}: v=DMARC1; p=quarantine; rua=mailto:you@{d} "
                          "and move to p=reject once reports look clean.")
            elif policy == "none":
                self.find("dmarc", dm_label, "low", "Fake email in your name is only watched, not stopped",
                          f"{d}'s DMARC policy is p=none.", rec[:200],
                          "Fake emails still reach inboxes.", "Change the policy to p=quarantine, then p=reject.")
            else:
                self.mark("dmarc", dm_label, "ok")
            if rec and "rua=" not in rec.lower():
                self.find("dmarc_reports", dm_label, "info", "Nobody gets reports about fake email",
                          "DMARC does not name an address for its daily reports.", rec[:200],
                          "You would not hear that someone is sending email as you.",
                          f"Add rua=mailto:dmarc@{d} (or your provider's report address) to the DMARC record.")
        self.mark("dkim", "Email signatures (DKIM)", "not_checked",
                  "Needs a signed email to check; not part of the quick look.")

    # -- the answer
    def result(self) -> dict[str, Any]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(self.findings, key=lambda f: order[f["severity"]])
        for i, f in enumerate(findings, 1):
            f["id"] = f"w{i}"
        score = max(0, 100 - sum(WEIGHT[f["severity"]] for f in findings))
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        sev = {f["severity"] for f in findings}
        if "urgent" in sev and grade in "ABC":
            grade = "D"
        elif "high" in sev and grade in "AB":
            grade = "C"
        checks = list(self.checks.values())
        if self.stopped:
            done = {c["key"] for c in checks}
            for key, label in (("https", "The website opens over https"), ("env_file", "Settings files are not public"),
                               ("git_folder", "The site's code history is not public"),
                               ("tls", "Certificate and secure connection")):
                if key not in done:
                    checks.append({"key": key, "label": label, "status": "not_checked", "note": "Stopped early."})
        not_checked = [c["label"] for c in checks if c["status"] == "not_checked"]
        serious = [f for f in findings if f["severity"] in ("urgent", "high")]
        real = [f for f in findings if f["severity"] != "info"]
        page_read = self.checks.get("https", {}).get("status") == "ok"
        if (self.stopped or not page_read) and not serious:
            # A part-read site is never shown as clean: no grade until the home page and the files were read.
            grade = "?"
            headline = ("Not graded: the check could not read enough of the site"
                        + (f" ({self.stopped})." if self.stopped else ".")
                        + (f" It still found {len(real)} thing{'s' if len(real) != 1 else ''} worth fixing." if real
                           else ""))
        elif serious:
            headline = (f"Grade {grade}. {len(serious)} serious thing{'s' if len(serious) != 1 else ''} to fix. "
                        f"Start with: {serious[0]['title'].lower()}.")
        elif real:
            headline = f"Grade {grade}. Nothing serious; {len(real)} thing{'s' if len(real) != 1 else ''} worth tidying."
        else:
            headline = f"Grade {grade}. The quick look found nothing to fix."
        if grade == "?":
            pass
        elif self.stopped:
            headline += f" The check stopped early ({self.stopped}), so this is only part of the picture."
        elif not_checked:
            headline += f" {len(not_checked)} check{'s' if len(not_checked) != 1 else ''} could not run."
        return {"domain": self.domain, "url": f"https://{self.domain}/", "checked_ts": self.now,
                "checked_at": datetime.fromtimestamp(self.now, timezone.utc).isoformat(timespec="seconds"),
                "by": self.by, "grade": grade, "score": score, "partial": bool(self.stopped),
                "stopped": self.stopped, "requests": self.requests, "headline": headline,
                "fix_first": findings[0]["id"] if real else None, "findings": findings, "checks": checks,
                "not_checked": not_checked,
                "note": "A clean result means this quick look saw nothing wrong in what it read. It does not mean "
                        "the site cannot be broken into."}


# ------------------------------------------------------------------ the company's list of websites

class Websites:
    """The websites the company owns, their proof of ownership, and each one's latest check."""

    def __init__(self, path: Path, net: Net | None = None, clock: Callable[[], float] = time.time,
                 record: Callable[[str, dict[str, Any]], Any] | None = None) -> None:
        self.path, self.net, self.clock = Path(path), net or Net(), clock
        self.record = record or (lambda _t, _d: None)
        self.lock = threading.Lock()
        self.running: set[str] = set()

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        data.setdefault("sites", {})
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    @staticmethod
    def _proof(domain: str, token: str) -> dict[str, str]:
        return {"dns_name": domain, "dns_value": VERIFY_TXT + token,
                "file_url": f"https://{domain}{VERIFY_FILE}", "file_text": token,
                "how": f"Add a TXT record to {domain} with the value {VERIFY_TXT}{token}, or put a file at "
                       f"https://{domain}{VERIFY_FILE} that holds just {token}. Keep it there: it is read again "
                       "before every check."}

    def _parent(self, data: dict[str, Any], domain: str) -> str | None:
        for other, s in data["sites"].items():
            if other != domain and s.get("verified_ts") and domain.endswith("." + other):
                return other
        return None

    def _view(self, data: dict[str, Any], domain: str) -> dict[str, Any]:
        s = data["sites"][domain]
        last = s.get("last") or {}
        parent = self._parent(data, domain)
        return {"domain": domain, "added_by": s.get("added_by"), "added_ts": s.get("added_ts"),
                "verified": bool(s.get("verified_ts") or parent), "verified_by": s.get("verified_how") or
                (f"part of {parent}" if parent else None), "verified_ts": s.get("verified_ts"),
                "proof": self._proof(domain, s["token"]),
                "last": {k: last.get(k) for k in ("checked_at", "grade", "score", "headline", "partial")} if last else None,
                "grades": s.get("grades", [])}

    def overview(self) -> dict[str, Any]:
        with self.lock:
            data = self._load()
            return {"sites": [self._view(data, d) for d in sorted(data["sites"])], "max_requests": MAX_REQUESTS}

    def add(self, raw: Any, by: str) -> dict[str, Any]:
        domain = clean_domain(raw)
        with self.lock:
            data = self._load()
            if domain not in data["sites"]:
                if len(data["sites"]) >= MAX_SITES:
                    raise WebsiteError(f"This panel already checks {MAX_SITES} websites.")
                data["sites"][domain] = {"token": secrets.token_urlsafe(18), "added_by": by, "added_ts": self.clock()}
                self._save(data)
                self.record("website_added", {"operator": by, "domain": domain, "summary": f"{by} added {domain}"})
            return self._view(data, domain)

    def remove(self, raw: Any, by: str) -> dict[str, Any]:
        domain = clean_domain(raw)
        with self.lock:
            data = self._load()
            if data["sites"].pop(domain, None) is None:
                raise KeyError(domain)
            self._save(data)
        self.record("website_removed", {"operator": by, "domain": domain, "summary": f"{by} removed {domain}"})
        return {"removed": domain}

    def _site(self, data: dict[str, Any], raw: Any) -> tuple[str, dict[str, Any]]:
        domain = clean_domain(raw)
        s = data["sites"].get(domain)
        if s is None:
            raise WebsiteError(f"{domain} is not one of the company's websites. SentrAI only checks websites the "
                               "company owns; SentrAI's team can add it (sentrai websites add).")
        return domain, s

    def _prove(self, domain: str, token: str, check: Check | None = None) -> str | None:
        """How ownership is shown right now: 'dns' or 'file', or None."""
        want = VERIFY_TXT + token
        txt = self.net.txt(domain) or []
        if any(t.strip() == want for t in txt):
            return "dns"
        url = f"https://{domain}{VERIFY_FILE}"
        try:
            r = check.fetch(url, SMALL_BYTES) if check else self.net.get(url, SMALL_BYTES)
        except _Budget:
            return None
        if r.status == 200 and r.body.strip() == token:
            return "file"
        return None

    def verify(self, raw: Any, by: str) -> dict[str, Any]:
        with self.lock:
            data = self._load()
            domain, s = self._site(data, raw)
            token = s["token"]
        addrs = self.net.addresses(domain)
        if not addrs or not all(public_address(a) for a in addrs):
            raise WebsiteError(f"{domain} does not point to a public internet address, so it cannot be checked "
                               "from outside.")
        how = self._prove(domain, token)
        with self.lock:
            data = self._load()
            domain, s = self._site(data, domain)
            if how:
                s.update(verified_ts=self.clock(), verified_how=how)
            else:
                s.pop("verified_ts", None)
                s.pop("verified_how", None)
            self._save(data)
            view = self._view(data, domain)
        if how:
            self.record("website_verified", {"operator": by, "domain": domain, "how": how,
                                             "summary": f"{domain} proven by {how}"})
        return {**view, "found": how}

    def latest(self, raw: Any = None) -> list[dict[str, Any]]:
        with self.lock:
            data = self._load()
            if raw:
                domain, s = self._site(data, raw)
                return [s["last"]] if s.get("last") else []
            return [s["last"] for _d, s in sorted(data["sites"].items()) if s.get("last")]

    def checkable(self) -> list[str]:
        with self.lock:
            data = self._load()
            return [d for d in sorted(data["sites"]) if data["sites"][d].get("verified_ts") or self._parent(data, d)]

    def check(self, raw: Any, by: str) -> dict[str, Any]:
        with self.lock:
            data = self._load()
            domain, s = self._site(data, raw)
            token, parent = s["token"], self._parent(data, domain)
            if domain in self.running:
                raise WebsiteError(f"{domain} is being checked right now.")
            self.running.add(domain)
        try:
            c = Check(domain, self.net, self.clock(), by)
            try:
                proof_domain = parent or domain
                proof_token = data["sites"][parent]["token"] if parent else token
                how = self._prove(proof_domain, proof_token, c if proof_domain == domain else None)
            except _Budget:
                how = None
            if not how:
                with self.lock:
                    data = self._load()
                    if domain in data["sites"]:
                        data["sites"][domain].pop("verified_ts", None)
                        self._save(data)
                if c.stopped:
                    raise WebsiteError(f"Cannot check {domain}: {c.stopped}.")
                raise WebsiteError(f"Cannot check {domain} yet: the company has not proven it owns it (or the proof "
                                   f"was taken down). {self._proof(proof_domain, proof_token)['how']}")
            result = c.run()
        finally:
            with self.lock:
                self.running.discard(domain)
        with self.lock:
            data = self._load()
            s = data["sites"].get(domain)
            if s is not None:
                before = s.get("last") or {}
                was = {f["key"] + ":" + f["title"] for f in before.get("findings") or []}
                now_ = {f["key"] + ":" + f["title"] for f in result["findings"]}
                if before:
                    result["compared_with"] = before.get("checked_at")
                    result["fixed_since"] = sorted(t.split(":", 1)[1] for t in was - now_)
                    result["new_since"] = sorted(t.split(":", 1)[1] for t in now_ - was)
                s["last"] = result
                s["grades"] = (s.get("grades", []) + [{"at": result["checked_at"], "grade": result["grade"]}])[-HISTORY:]
                if parent is None and not s.get("verified_ts"):
                    s.update(verified_ts=self.clock(), verified_how=how)
                self._save(data)
        self.record("website_check", {"operator": by, "domain": domain, "grade": result["grade"],
                                      "findings": len(result["findings"]), "requests": result["requests"],
                                      "summary": f"{domain} checked: grade {result['grade']}"})
        return result


def for_model(result: dict[str, Any]) -> dict[str, Any]:
    """A check, trimmed for the chat model. Site text is data from the internet, never instructions."""
    keep = ("id", "severity", "severity_word", "title", "saw", "risk", "fix", "where")
    return {k: result.get(k) for k in ("domain", "checked_at", "grade", "score", "partial", "stopped", "headline",
                                       "not_checked", "fixed_since", "new_since", "note") if k in result} | {
        "findings": [{**{k: f.get(k) for k in keep}, "evidence_untrusted": f.get("detail")}
                     for f in result.get("findings", [])[:20]]}
