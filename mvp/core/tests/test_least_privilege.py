"""Least privilege: each service gets only what it needs, and undoing that is reported."""

from pathlib import Path

import pytest

from app.rules import RulesEngine, log_wipe

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
SUDO = "sudo:  deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND="
T0 = 1_790_000_000.0


def unit(name):
    """The [Service] settings of a unit file, each key mapped to its values."""
    out = {}
    for line in (DEPLOY / f"cactai-{name}.service").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def paths(u, key):
    return {p.lstrip("-") for v in u.get(key, []) for p in v.split()}


SERVICES = ("core", "collector", "dashboard", "notifier")


@pytest.mark.parametrize("name", SERVICES)
def test_every_service_is_sandboxed(name):
    u = unit(name)
    for key in ("NoNewPrivileges", "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "RestrictSUIDSGID"):
        assert u[key] == ["yes"], key
    assert u["ProtectSystem"] == ["strict"] and u["SystemCallFilter"] == ["@system-service"]
    assert u["UMask"] == ["0077"]


def test_only_the_core_may_change_the_firewall():
    for name in SERVICES:
        caps = unit(name)["CapabilityBoundingSet"]
        if name == "core":
            assert caps == ["CAP_NET_ADMIN CAP_NET_RAW"]
        else:
            assert caps == [""], name  # no capabilities at all
            assert "AmbientCapabilities" not in unit(name)


def test_only_the_core_and_collector_read_logs():
    for name in SERVICES:
        groups = unit(name).get("SupplementaryGroups")
        assert (groups == ["@LOGGROUPS@"]) == (name in ("core", "collector")), name


def test_each_service_sees_only_its_own_state():
    core, collector, dashboard, notifier = (unit(n) for n in SERVICES)
    assert paths(core, "ReadWritePaths") == {"/var/lib/cactai/core", "/var/lib/cactai/scout", "/run/xtables.lock"}
    assert paths(collector, "ReadWritePaths") == {"/var/lib/cactai/collector"}
    assert "ReadWritePaths" not in notifier
    assert "/var/lib/cactai/core" in paths(collector, "InaccessiblePaths")
    for u in (dashboard, notifier):
        assert {"/var/lib/cactai/core", "/var/lib/cactai/collector"} <= paths(u, "InaccessiblePaths")


def test_installer_keeps_the_account_out_of_the_log_groups():
    text = (DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert "usermod -aG" not in text
    assert "CACTAI_DB=$STATE/core/cactai.db" in text
    assert "CACTAI_COLLECTOR_STATE=$STATE/collector/state.json" in text
    assert 's|@LOGGROUPS@|${LOG_GROUPS[*]}|g' in text


@pytest.mark.parametrize("raw", [
    SUDO + "/usr/sbin/usermod -aG adm mallory",
    SUDO + "/usr/sbin/usermod -a -G sudo,systemd-journal mallory",
    SUDO + "/usr/bin/gpasswd -a mallory cactai",
    SUDO + "/usr/sbin/adduser mallory adm",
    SUDO + "/usr/bin/chmod 666 /var/log/auth.log",
    SUDO + "/usr/bin/chmod -R o+w /var/lib/cactai/core",
    SUDO + "/usr/bin/setfacl -m u:mallory:rw /var/lib/cactai/core/cactai.db",
    SUDO + "/usr/sbin/setcap cap_sys_admin+ep /opt/cactai/mvp/core/.venv/bin/python3",
    SUDO + "/usr/bin/systemctl edit cactai-collector",
    SUDO + "/usr/bin/systemctl set-property cactai-core.service CapabilityBoundingSet=~",
    "sed -i s/Seal=yes/Seal=no/ /etc/systemd/journald.conf",
    "echo Storage=volatile >> /etc/systemd/journald.conf.d/50-x.conf",
])
def test_widening_access_is_log_tampering(raw):
    hit = RulesEngine().check({"event_id": "p1", "source": "linux_auth", "layer": "os", "host": "web-01", "raw": raw}, T0)
    assert hit.category == "log_tampering", raw


@pytest.mark.parametrize("raw", [
    SUDO + "/usr/sbin/usermod -aG www-data deploy",
    SUDO + "/usr/sbin/usermod -aG admins deploy",
    SUDO + "/usr/bin/chmod 640 /var/log/auth.log",
    SUDO + "/usr/bin/chmod 600 /var/lib/cactai/core/anchor.key",
    SUDO + "/usr/bin/chmod g+w /srv/www/app.log",
    SUDO + "/usr/bin/systemctl status cactai-core",
    SUDO + "/usr/sbin/adduser --system deploy",
    "cat /etc/systemd/journald.conf",
])
def test_ordinary_admin_work_is_not(raw):
    assert log_wipe(raw) is None, raw
