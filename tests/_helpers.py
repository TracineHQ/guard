# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared test helpers for guard hooks.

Two shapes show up across hook tests: in-process ``decide()`` returns and
subprocess invocations of the hook script. The helpers below normalize the
extraction logic so a future change to the envelope shape only needs one
edit instead of fan-out across every test file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO_ROOT / "src" / "guard" / "hooks"


def hook_path(name: str) -> Path:
    """Return the absolute path to a hook script (``<name>.py``)."""
    return HOOKS_DIR / f"{name}.py"


def is_deny(result: object) -> bool:
    """True iff ``result`` is a decide() envelope (flat or wrapped) marking deny.

    Accepts both shapes: the legacy flat ``{"permissionDecision": "deny"}`` and
    the modern ``{"hookSpecificOutput": {"permissionDecision": "deny"}}``.
    """
    if not isinstance(result, dict):
        return False
    hso = result.get("hookSpecificOutput")
    if isinstance(hso, dict) and hso.get("permissionDecision") == "deny":
        return True
    return result.get("permissionDecision") == "deny"


def decision_from_stdout(stdout: str) -> str | None:
    """Parse a hook's stdout JSON and return its ``permissionDecision``, or None."""
    if not stdout.strip():
        return None
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    hso = envelope.get("hookSpecificOutput") if isinstance(envelope, dict) else None
    if isinstance(hso, dict):
        return hso.get("permissionDecision")
    return envelope.get("permissionDecision") if isinstance(envelope, dict) else None


def run_hook(  # noqa: PLR0913 - kw-only flags, all optional and orthogonal
    hook_name: str,
    command: str,
    *,
    strict: bool = False,
    permission_mode: str | None = None,
    decisions_path: Path | None = None,
    env_extra: Mapping[str, str] | None = None,
    session_id: str = "test",
    cwd: str = "/tmp",
) -> tuple[int, str, str]:
    """Spawn the named hook with a Bash PreToolUse payload, return (rc, stdout, stderr).

    The default payload is the canonical bash-command shape. ``strict=True``
    is a shortcut for ``permission_mode="dontAsk"``; pass ``permission_mode``
    directly for any other mode (``plan``, ``acceptEdits``, ...).
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    if decisions_path is not None:
        env["GUARD_DECISIONS_PATH"] = str(decisions_path)
    if env_extra:
        env.update(env_extra)
    mode = permission_mode if permission_mode is not None else ("dontAsk" if strict else "default")
    payload: dict[str, Any] = {
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
        "cwd": cwd,
        "permission_mode": mode,
    }
    proc = subprocess.run(
        [sys.executable, str(hook_path(hook_name))],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr
