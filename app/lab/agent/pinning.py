"""Certificate pinning: the agent talks only to the panel whose certificate it was told about.

The panel's join code comes with the SHA-256 fingerprint of its certificate (``sha256:...``). With a
pin, every HTTPS call to the panel checks that exact certificate and nothing else: a self-signed panel
works without copying a certificate file, and a look-alike server or an intercepting proxy with a
certificate from any authority is refused. Without a pin the normal checks apply (the system's trusted
authorities, or the file given with --ca).
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

PIN_RE = re.compile(r"^[0-9a-f]{64}$")


class PinError(Exception):
    pass


def normalise(pin: str | None) -> str:
    """"sha256:AB:CD:..." in any case, with or without colons -> "sha256:abcd..."; raises if it is not one."""
    p = re.sub(r"[\s:]", "", (pin or "").strip().lower().removeprefix("sha256:"))
    if not PIN_RE.match(p):
        raise PinError(f"a pin looks like sha256: followed by 64 hex digits (got {pin!r})")
    return f"sha256:{p}"


def seen(url: str, timeout: float = 5.0) -> str:
    """The pin of the certificate the server at ``url`` shows right now (no trust check: for display)."""
    u = urlparse(url)
    host, port = u.hostname or "", u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw, \
            ctx.wrap_socket(raw, server_hostname=host) as tls:
        der = tls.getpeercert(binary_form=True)
    return "sha256:" + hashlib.sha256(der).hexdigest()


class PinnedAdapter(HTTPAdapter):
    """Checks the server's certificate against the pin (urllib3 ``assert_fingerprint``) instead of a
    chain of authorities. The pin is the stronger check, so the name on the certificate is not needed
    (a panel reached by IP address works)."""

    def __init__(self, pin: str, **kw: Any) -> None:
        self.fingerprint = normalise(pin).removeprefix("sha256:")
        super().__init__(**kw)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        params, pool_kw = super().build_connection_pool_key_attributes(request, False, cert)
        pool_kw["assert_fingerprint"] = self.fingerprint
        return params, pool_kw

    def cert_verify(self, conn, url, verify, cert):
        super().cert_verify(conn, url, False, cert)


class FixedVerifyAdapter(HTTPAdapter):
    """Always checks with this certificate file, even when REQUESTS_CA_BUNDLE is set (requests lets that
    variable win over a session's own setting)."""

    def __init__(self, verify: str, **kw: Any) -> None:
        self.ca_file = verify
        super().__init__(**kw)

    def send(self, request, **kw):
        kw["verify"] = self.ca_file
        return super().send(request, **kw)


def session(panel: str, pin: str | None = None, verify: str | bool = True) -> requests.Session:
    """A session for calls to the panel: pinned when there is a pin, otherwise checked with ``verify``."""
    s = requests.Session()
    prefix = panel.rstrip("/") + "/"
    if pin and panel.startswith("https://"):
        s.mount(prefix, PinnedAdapter(pin))
        s.verify = False  # replaced by the pin for the panel's address
    else:
        s.verify = verify
        if isinstance(verify, str):
            s.mount(prefix, FixedVerifyAdapter(verify))
    return s


def explain(exc: BaseException) -> str:
    """A pin mismatch or an untrusted certificate, said plainly; '' for other network errors."""
    text = str(exc)
    if "Fingerprints did not match" in text:
        return ("the panel showed a different certificate than its pin: refusing to talk to it (if the panel's "
                "certificate was renewed, set the new pin with: python -m agent pin sha256:...)")
    if "CERTIFICATE_VERIFY_FAILED" in text:
        return ("this machine does not trust the panel's certificate: join with the --pin shown on the panel's "
                "Add machine page (or --ca with its certificate file)")
    return ""
