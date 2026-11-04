"""The agent's installers install only lab/requirements-agent.txt: keep it small and in step."""
from __future__ import annotations

import re
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
DEPLOY = LAB.parents[1] / "deploy"  # the repo's deploy/, next to app/


def _names(path: Path) -> set[str]:
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0].lower())
    return out


def test_agent_needs_no_test_or_ai_packages():
    agent = _names(LAB / "requirements-agent.txt")
    assert agent == {"requests", "psutil", "tzdata"}
    assert not agent & {"pytest", "anthropic", "openai", "fastapi", "streamlit"}


def test_agent_packages_are_also_in_the_lab_requirements():
    # The lab venv (tests, a panel's collector) must still have everything the agent runs on.
    assert _names(LAB / "requirements-agent.txt") <= _names(LAB / "requirements.txt")


def test_both_agent_installers_use_the_agent_requirements():
    for name in ("install-agent.sh", "install-agent.ps1"):
        text = (DEPLOY / name).read_text(encoding="utf-8")
        assert "requirements-agent.txt" in text, name
        assert not re.search(r"lab[/\\]requirements\.txt\"", text), name


def test_old_panel_installer_name_forwards_to_the_new_one():
    for old, new in (("install.sh", "install-panel.sh"), ("uninstall.sh", "uninstall-panel.sh")):
        assert f'/{new}" "$@"' in (DEPLOY / old).read_text(encoding="utf-8")
