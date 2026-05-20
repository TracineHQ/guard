# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Regression test: every hook in hooks.json must import cleanly when invoked
the way Claude Code invokes it -- a bare ``python3 <hook>.py`` with no
PYTHONPATH set.

This is the runtime contract that v1.4.1 broke: pytest happily imported
``from guard._utils import ...`` because pyproject installs the package
editably, but Claude Code's runtime invocation has no such convenience.
Each hook needs an in-file sys.path bootstrap so it works without env help.

To prove this test would have caught the original bug: temporarily remove
the bootstrap from one hook (e.g. drop the ``_SRC = Path(__file__)...``
block at the top of ``bash_command_validator.py``) and re-run this file.
The matching parametrized case fails with::

    ModuleNotFoundError: No module named 'guard'

Restore the bootstrap and the case passes. Verified 2026-05-20.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "hooks" / "hooks.json"

# Matchers that target file-modifying tools. Hooks gated only on these need a
# Write/Edit-shaped payload rather than a Bash one.
_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}

_BASH_PAYLOAD: dict[str, Any] = {
    "session_id": "subprocess-invocation-test",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
    "hook_event_name": "PreToolUse",
    "cwd": "/tmp",
    "permission_mode": "default",
}

_WRITE_PAYLOAD: dict[str, Any] = {
    "session_id": "subprocess-invocation-test",
    "tool_name": "Write",
    "tool_input": {"file_path": "/tmp/example.txt", "content": "hello"},
    "hook_event_name": "PreToolUse",
    "cwd": "/tmp",
    "permission_mode": "default",
}

_PERMISSION_REQUEST_PAYLOAD: dict[str, Any] = {
    "session_id": "subprocess-invocation-test",
    "tool_name": "Bash",
    "hook_event_name": "PermissionRequest",
    "cwd": "/tmp",
    "permission": {},
}


_COMMAND_RE = re.compile(r"python3\s+\$\{CLAUDE_PLUGIN_ROOT\}/bin/run-hook\s+([\w_]+)")


def _hook_name_from_command(command: str) -> str:
    """Return the hook module short name from a manifest command string."""
    match = _COMMAND_RE.search(command)
    assert match, f"Could not extract hook name from command: {command!r}"
    return match.group(1)


def _collect_hook_invocations() -> list[tuple[str, str, dict[str, Any]]]:
    """Yield ``(event, hook_name, payload)`` for every hook in the manifest."""
    manifest = json.loads(MANIFEST.read_text())
    out: list[tuple[str, str, dict[str, Any]]] = []
    for event, entries in manifest["hooks"].items():
        for entry in entries:
            matcher = entry.get("matcher", "")
            matcher_set = set(matcher.split("|")) if matcher and matcher != "*" else set()
            if event == "PermissionRequest":
                payload = _PERMISSION_REQUEST_PAYLOAD
            elif matcher_set & _WRITE_TOOLS and "Bash" not in matcher_set:
                payload = _WRITE_PAYLOAD
            else:
                # Bash is the most common matcher and is broadly accepted.
                payload = _BASH_PAYLOAD
            for hook in entry["hooks"]:
                name = _hook_name_from_command(hook["command"])
                out.append((event, name, payload))
    return out


_INVOCATIONS = _collect_hook_invocations()


def _clean_env() -> dict[str, str]:
    """Return an env stripped of PYTHONPATH, mirroring Claude Code's invocation."""
    return {
        key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}
    }


_WRAPPER = REPO_ROOT / "bin" / "run-hook"


@pytest.mark.parametrize(
    ("event", "hook_name", "payload"),
    _INVOCATIONS,
    ids=[f"{event}:{name}" for event, name, _ in _INVOCATIONS],
)
def test_hook_runs_through_wrapper(
    event: str,
    hook_name: str,
    payload: dict[str, Any],
) -> None:
    """Each manifest-registered hook must run cleanly through bin/run-hook.

    Mirrors Claude Code's invocation: ``python3 bin/run-hook <name>`` with
    PYTHONPATH wiped and ``-S`` to suppress site-packages so the editable
    install's .pth file does NOT add src/ to sys.path. The wrapper must
    self-bootstrap.

    Asserts:
      - exit code is 0 (allow / pass) or 2 (legitimate hard deny)
      - stderr contains no Python traceback or ModuleNotFoundError
    """
    assert _WRAPPER.exists(), f"Wrapper missing: {_WRAPPER}"

    proc = subprocess.run(
        [sys.executable, "-S", str(_WRAPPER), hook_name],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=_clean_env(),
        timeout=15,
        check=False,
    )

    assert "Traceback" not in proc.stderr, f"{hook_name} crashed: stderr=\n{proc.stderr}"
    assert "ModuleNotFoundError" not in proc.stderr, (
        f"{hook_name} could not import its package: stderr=\n{proc.stderr}"
    )
    assert proc.returncode in (0, 2), (
        f"{hook_name} returned rc={proc.returncode}; stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )


def test_manifest_lists_every_hook_file() -> None:
    """Belt-and-braces: ensure we collected at least one entry per hook module."""
    referenced = {name for _, name, _ in _INVOCATIONS}
    # Every .py file under src/guard/hooks except dunder/underscored helpers.
    on_disk = {
        p.stem
        for p in (REPO_ROOT / "src" / "guard" / "hooks").glob("*.py")
        if not p.name.startswith("_")
    }
    missing = on_disk - referenced
    assert not missing, f"Hook modules not exercised by manifest: {sorted(missing)}"
