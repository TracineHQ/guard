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

import guard

if TYPE_CHECKING:
    from collections.abc import Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO_ROOT / "src" / "guard" / "hooks"
# The guard package in-process tests import (site-packages in CI's wheel
# run). protected_files keys guard's own code on the real path of the copy
# that runs, so in-process tests name live files under it; tests that spawn
# a hook from src/ use HOOKS_DIR instead.
LIVE_GUARD = Path(guard.__file__).resolve().parent

# Patterns of every shape protected_files' matcher understands (directories,
# exact files, dotfiles, nested paths), for matcher tests that need more than
# guard's own trust root.
SAMPLE_PATTERNS: tuple[str, ...] = (
    ".git/hooks",
    ".git/config",
    ".git/info/attributes",
    ".git/info/exclude",
    ".gitmodules",
    ".gitattributes",
    ".claude/CLAUDE.md",
    ".aider.conf.yml.user",
    "CLAUDE.md",
    ".cursorrules",
    ".cursor/rules",
    ".aider.conf.yml",
    ".continue/config.json",
    ".claude/mcp_servers",
    ".claude/mcp.json",
    ".aws/config",
)


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


def run_hook(  # noqa: PLR0913 -- kw-only flags, all optional and orthogonal
    hook_name: str,
    command: str,
    *,
    permission_mode: str | None = None,
    decisions_path: Path | None = None,
    env_extra: Mapping[str, str] | None = None,
    session_id: str = "test",
    cwd: str = "/tmp",
) -> tuple[int, str, str]:
    """Spawn the named hook with a Bash PreToolUse payload, return (rc, stdout, stderr).

    The default payload is the canonical bash-command shape.
    ``permission_mode`` sets the payload field; it never changes the decision.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    if decisions_path is not None:
        env["GUARD_DECISIONS_PATH"] = str(decisions_path)
    else:
        # Defense in depth: if no test-scoped decision log is active (the
        # autouse fixture normally sets one), sink decisions to devnull so a
        # run_hook call outside that fixture can never append to the developer's
        # real ~/.claude/guard-decisions.jsonl. setdefault preserves an already
        # isolated path from the inherited environment.
        env.setdefault("GUARD_DECISIONS_PATH", os.devnull)
    if env_extra:
        env.update(env_extra)
    mode = permission_mode if permission_mode is not None else "default"
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
