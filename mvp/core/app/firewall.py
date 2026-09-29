"""Real host-firewall blocking for `block_ip` (opt-in, dry run by default).

`FirewallResponder` does everything `BlocklistResponder` does (the target app keeps
polling GET /blocklist) and also mirrors each blocked IP into the host firewall:

  * ``nftables``  Linux, one ``inet cactai`` table with a set of blocked addresses
  * ``iptables``  Linux, one DROP rule per address (ip6tables for IPv6)
  * ``netsh``     Windows, one ``netsh advfirewall`` inbound block rule per address

Settings (environment or setup wizard):

  CACTAI_FIREWALL          off (default) | auto | nftables | iptables | netsh
  CACTAI_FIREWALL_ENFORCE  0 (default: dry run, only log the command) | 1 (really run it)

With CACTAI_FIREWALL=off nothing changes: blocking stays portal-only, as in the demo.
With a backend chosen but ENFORCE=0 the commands are logged and written to the audit
trail, never run. The same approval gates, TTL expiry and rollback apply, because this
responder is called at exactly the points `BlocklistResponder` is.

Safety: commands are argument lists (no shell) built only from a parsed IP address, and
loopback, unspecified, multicast, link-local and protected addresses are never sent to
the firewall, whatever Needle decided.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import shutil
import subprocess
from collections.abc import Callable

from .responders import Action, BlocklistResponder

log = logging.getLogger("cactai.firewall")

BACKENDS = ("nftables", "iptables", "netsh")
Runner = Callable[[list[str]], "tuple[int, str]"]

NFT_TABLE = ("inet", "cactai")
IPT_COMMENT = "cactai"


def run_command(args: list[str]) -> tuple[int, str]:
    """Runs one firewall command without a shell. Returns (exit code, output)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)
    return p.returncode, (p.stdout + p.stderr).strip()


def detect_backend() -> str | None:
    if platform.system() == "Windows":
        return "netsh"
    if platform.system() == "Linux":
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
    return None


def resolve_backend(choice: str) -> str | None:
    """Maps the CACTAI_FIREWALL setting to a backend name, or None for off."""
    choice = (choice or "off").strip().lower()
    if choice in ("", "off", "0", "no", "false", "none"):
        return None
    if choice == "auto":
        return detect_backend()
    if choice not in BACKENDS:
        raise ValueError(f"CACTAI_FIREWALL must be off, auto or one of {', '.join(BACKENDS)} (got {choice!r})")
    return choice


def unsafe_reason(target: str, protected: set[str]) -> str | None:
    """Why this target must never reach the firewall, or None if it may."""
    if target in protected:
        return "protected address"
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return "not an IP address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) in protected:
        return "protected address"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return "loopback, unspecified, multicast or link-local address"
    return None


def _nft(*args: str) -> list[str]:
    return ["nft", *args]


def setup_commands(backend: str) -> list[list[str]]:
    """One-off commands before the first block (nftables needs its table, sets and chain)."""
    if backend != "nftables":
        return []
    fam, table = NFT_TABLE
    return [
        _nft("add", "table", fam, table),
        _nft("add", "set", fam, table, "blocked4", "{ type ipv4_addr ; }"),
        _nft("add", "set", fam, table, "blocked6", "{ type ipv6_addr ; }"),
        _nft("add", "chain", fam, table, "input", "{ type filter hook input priority -10 ; policy accept ; }"),
        _nft("flush", "chain", fam, table, "input"),  # so restarts don't stack duplicate rules
        _nft("add", "rule", fam, table, "input", "ip", "saddr", "@blocked4", "drop"),
        _nft("add", "rule", fam, table, "input", "ip6", "saddr", "@blocked6", "drop"),
    ]


def block_commands(backend: str, ip: str) -> tuple[list[str], list[str], list[str]]:
    """(add, check, remove) commands for one address."""
    v6 = ipaddress.ip_address(ip).version == 6
    if backend == "nftables":
        fam, table = NFT_TABLE
        s = "blocked6" if v6 else "blocked4"
        elem = "{ %s }" % ip
        return (_nft("add", "element", fam, table, s, elem),
                _nft("get", "element", fam, table, s, elem),
                _nft("delete", "element", fam, table, s, elem))
    if backend == "iptables":
        tool = "ip6tables" if v6 else "iptables"
        rule = ["INPUT", "-s", ip, "-m", "comment", "--comment", IPT_COMMENT, "-j", "DROP"]
        return [tool, "-I", *rule], [tool, "-C", *rule], [tool, "-D", *rule]
    if backend == "netsh":
        name = f"name=SentrAI-block-{ip}"
        base = ["netsh", "advfirewall", "firewall"]
        return ([*base, "add", "rule", name, "dir=in", "action=block", f"remoteip={ip}"],
                [*base, "show", "rule", name],
                [*base, "delete", "rule", name])
    raise ValueError(f"unknown firewall backend {backend!r}")


class FirewallResponder(BlocklistResponder):
    """App-level blocklist plus the host firewall for `block_ip`. Dry run unless enforce=True."""

    name = "firewall"

    def __init__(self, backend: str, enforce: bool = False, protected_ips: set[str] | None = None,
                 runner: Runner = run_command) -> None:
        if backend not in BACKENDS:
            raise ValueError(f"unknown firewall backend {backend!r}")
        super().__init__()
        self.backend = backend
        self.enforce = enforce
        self.protected_ips = protected_ips if protected_ips is not None else set()
        self.runner = runner
        self.enforcement = f"blocklist + firewall ({backend})" if enforce else f"blocklist + firewall dry run ({backend})"
        self._ready = False
        self._in_firewall: set[str] = set()  # addresses this responder put in the firewall
        self.history: list[dict[str, object]] = []  # every command run or logged, newest last

    # -- command plumbing
    def _run(self, args: list[str], probe: bool = False) -> tuple[int, str]:
        if not self.enforce:
            log.info("firewall dry run: %s", " ".join(args))
            self.history.append({"cmd": args, "dry_run": True})
            return 0, "dry run"
        rc, out = self.runner(args)
        (log.info if rc == 0 or probe else log.warning)("firewall %s -> %s %s", " ".join(args), rc, out)
        self.history.append({"cmd": args, "dry_run": False, "rc": rc, "output": out[:500]})
        return rc, out

    def _setup(self) -> bool:
        if self._ready:
            return True
        for cmd in setup_commands(self.backend):
            rc, _ = self._run(cmd)
            if rc != 0:
                return False
        self._ready = True
        return True

    def _record(self, action: Action, note: dict[str, object]) -> None:
        action["firewall"] = {"backend": self.backend, "dry_run": not self.enforce, **note}

    # -- Responder
    def apply(self, action: Action) -> bool:
        in_blocklist = super().apply(action)
        if action["type"] != "block_ip":
            return in_blocklist
        target = str(action["target"])
        reason = unsafe_reason(target, self.protected_ips)
        if reason:
            self._record(action, {"skipped": reason})
            return in_blocklist
        if target in self._in_firewall:  # another incident already blocked it
            self._record(action, {"already_blocked": True})
            return in_blocklist
        add, check, remove = block_commands(self.backend, target)
        start = len(self.history)
        ready = self._setup()
        if ready and self.enforce and self._run(check, probe=True)[0] == 0:
            # Already in the firewall, e.g. re-applied after a restart (saved state): adopt it, add no duplicate.
            self._in_firewall.add(target)
            self._record(action, {"commands": [" ".join(h["cmd"]) for h in self.history[start:]], "ok": True,
                                  "already_in_firewall": True})
            return in_blocklist
        ok = added = ready and self._run(add)[0] == 0
        if ok and self.enforce:
            ok = self._run(check)[0] == 0  # verify it is really in force
        if ok:
            self._in_firewall.add(target)
        elif added:
            self._run(remove)  # added but not verified: take it out again, it is being rolled back
        self._record(action, {"commands": [" ".join(h["cmd"]) for h in self.history[start:]], "ok": ok})
        return in_blocklist and ok

    def revert(self, action: Action) -> None:
        super().revert(action)
        target = str(action["target"])
        if action["type"] == "block_ip" and target in self._in_firewall and ("block_ip", target) not in self._active:
            self._remove(target)

    def _remove(self, target: str) -> None:
        _, _, remove = block_commands(self.backend, target)
        self._run(remove)
        self._in_firewall.discard(target)

    def reset(self) -> None:
        for target in sorted(self._in_firewall):
            self._remove(target)
        super().reset()

    def status(self) -> dict[str, object]:
        return {"backend": self.backend, "enforce": self.enforce, "blocked": sorted(self._in_firewall)}


def from_settings(backend_choice: str, enforce: bool, protected_ips: set[str],
                  runner: Runner = run_command) -> BlocklistResponder:
    """The `block_ip` responder the core should use: portal-only unless a firewall is chosen."""
    backend = resolve_backend(backend_choice)
    if backend is None:
        if (backend_choice or "off").strip().lower() == "auto":
            log.warning("CACTAI_FIREWALL=auto but no supported firewall found; blocking stays portal-only")
        return BlocklistResponder()
    return FirewallResponder(backend, enforce=enforce, protected_ips=protected_ips, runner=runner)

