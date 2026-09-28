"""Part 3 of 3: the responder. Carries out a containment action, and undoes it.

A responder is any `Responder` subclass: list the action types it handles in `actions`,
implement `apply()` and `revert()`. Every action is temporary and reversible, so both
are required. The allowlist of action types is simply whatever the registered
responders can handle.

Nothing here touches the host firewall, shell or OS: blocks are enforced by the target
app polling GET /blocklist, and the other playbooks are recorded only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from typing import Any

Action = dict[str, Any]  # {"action_id", "type", "target", ...} built by Areole.apply


class Responder(ABC):
    name = "responder"
    actions: tuple[str, ...] = ()
    enforcement = "recorded (simulated)"

    @abstractmethod
    def apply(self, action: Action) -> bool:
        """Put the action in place. Return True when it is verified to be in force."""

    @abstractmethod
    def revert(self, action: Action) -> None:
        """Take the action out again (rollback, rejection or TTL expiry)."""

    def reset(self) -> None:
        """Forget all state (demo reset)."""


class BlocklistResponder(Responder):
    """Blocks IPs and locks accounts through the app-level blocklist (GET /blocklist)."""

    name = "blocklist"
    actions = ("block_ip", "lock_user")
    enforcement = "blocklist"

    def __init__(self) -> None:
        # Counted, so two incidents blocking the same IP need two reverts to unblock it.
        self._active: Counter[tuple[str, str]] = Counter()

    def apply(self, action: Action) -> bool:
        key = (action["type"], action["target"])
        self._active[key] += 1
        return key in self._active

    def revert(self, action: Action) -> None:
        key = (action["type"], action["target"])
        self._active[key] -= 1
        if self._active[key] <= 0:
            del self._active[key]

    def reset(self) -> None:
        self._active.clear()

    def blocklist(self) -> dict[str, list[str]]:
        return {
            "ips": sorted(t for kind, t in self._active if kind == "block_ip"),
            "users": sorted(t for kind, t in self._active if kind == "lock_user"),
        }


class SimulatedResponder(Responder):
    """Playbooks the MVP only records (WAF rule, rate limit, kill process, revoke ACL)."""

    name = "simulated"
    actions = ("rate_limit", "waf_rule", "kill_process", "revoke_public_acl")

    def apply(self, action: Action) -> bool:
        return True

    def revert(self, action: Action) -> None:
        pass


class Responders:
    """Routes each action to the responder that handles its type."""

    def __init__(self, *responders: Responder) -> None:
        self.all = list(responders)
        self._by_type = {t: r for r in responders for t in r.actions}

    @property
    def allowlist(self) -> set[str]:
        return set(self._by_type)

    def for_type(self, action_type: str) -> Responder:
        try:
            return self._by_type[action_type]
        except KeyError:
            raise ValueError(f"{action_type} is not an allowlisted playbook") from None

    def apply(self, action: Action) -> bool:
        return self.for_type(action["type"]).apply(action)

    def revert(self, action: Action) -> None:
        self.for_type(action["type"]).revert(action)

    def reset(self) -> None:
        for r in self.all:
            r.reset()
