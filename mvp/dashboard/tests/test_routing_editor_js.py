"""The "Who gets what" editor's model (sentrai_ui/routing_editor.mjs) has its tests in JavaScript,
tests/routing_editor.test.mjs, run by Node's own test runner (no npm packages). This runs them as part of
pytest, and skips them where Node 20 or newer is missing."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parents[1]
# Relative to DASHBOARD, with forward slashes on every OS: newer Node reads the --test argument as a glob.
TEST_FILE = "tests/routing_editor.test.mjs"
MAPS_FILE = "tests/maps.test.mjs"  # the pipeline overview's grid and Automation guardrails (flow_canvas.mjs, limits_map.mjs)
CANVAS_FILE = "tests/canvas.test.mjs"  # the pipeline overview canvas: layout, wires, adding and taking off, the panel
GUARDRAILS_FILE = "tests/guardrails.test.mjs"  # the guardrails page's tags, percent and policy summary, the map's tips
MIN_NODE = 20
TIMEOUT = 120  # seconds
# The count in the summary node prints last: "<info sign> pass 65" from the spec reporter, "# pass 65" from TAP.
PASSED = re.compile(r"^(?:\u2139|#) pass (\d+)\s*$", re.MULTILINE)


def _node() -> str:
    """The node to run the tests with, or a skip that says why there is none."""
    node = shutil.which("node")
    if node is None:
        pytest.skip(f"node is not on PATH: {TEST_FILE} needs Node {MIN_NODE} or newer")
    try:
        version = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"{node} --version did not run ({exc}): {TEST_FILE} needs Node {MIN_NODE} or newer")
    major = re.match(r"v(\d+)\.", version)
    if major is None or int(major.group(1)) < MIN_NODE:
        pytest.skip(f"node {version or '(no version)'} is too old: {TEST_FILE} needs Node {MIN_NODE} or newer")
    return node


def _text(data: bytes | str | None) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data or ""


@pytest.mark.parametrize("test_file", [TEST_FILE, MAPS_FILE, GUARDRAILS_FILE, CANVAS_FILE])
def test_routing_editor_model_passes_its_node_tests(test_file):
    TEST_FILE = test_file  # noqa: N806  (the messages below name the file that ran)
    node = _node()
    try:
        proc = subprocess.run([node, "--test", "--test-reporter=spec", TEST_FILE], cwd=str(DASHBOARD),
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:  # its output arrives as bytes, whatever text= says
        pytest.fail(f"node --test {TEST_FILE} did not finish in {TIMEOUT} s:\n{_text(exc.stdout)}{_text(exc.stderr)}")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"node --test {TEST_FILE} failed (exit {proc.returncode}):\n{out}"
    passed = PASSED.findall(out)
    assert not passed or int(passed[-1]) > 0, f"node --test {TEST_FILE} ran no tests:\n{out}"
