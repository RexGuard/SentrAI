"""Attack scripts must refuse any non-localhost target."""
from __future__ import annotations

import pytest

from attacks import _common
from attacks import brute_force, sqli, exfil, shell, benign


@pytest.mark.parametrize("host", ["evil.com", "10.0.0.5", "203.0.113.45",
                                   "example.org", "0.0.0.0"])
def test_require_localhost_refuses_remote(host):
    with pytest.raises(_common.NonLocalTargetError):
        _common.require_localhost(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_require_localhost_allows_local(host):
    _common.require_localhost(host)  # must not raise


def test_require_localhost_refuses_wrong_port():
    with pytest.raises(_common.NonLocalTargetError):
        _common.require_localhost("127.0.0.1", port=8080)


def test_base_url_refuses_remote():
    with pytest.raises(_common.NonLocalTargetError):
        _common.base_url("attacker.example")


def test_guard_or_exit_exits_on_remote(capsys):
    with pytest.raises(SystemExit) as exc:
        _common.guard_or_exit("evil.com", 5000)
    assert exc.value.code == 2
    assert "REFUSED" in capsys.readouterr().err


@pytest.mark.parametrize("mod", [brute_force, sqli, exfil, shell, benign])
def test_each_attack_run_refuses_remote(mod):
    # Every attack's run() funnels through guard_or_exit, so a remote host
    # exits before any request is sent.
    with pytest.raises(SystemExit):
        mod.run("evil.com", 5000, count=1, delay=0, src_ip="203.0.113.45")
