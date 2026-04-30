"""End-to-end: when CLAUDE_AUTONOMOUS=1, bash_command_validator default-denies
unsafe segments and surfaces AUTONOMOUS_FEEDBACK custom messages.

Locks in the strict-mode safety net for subagents / driven agents so it can't
silently regress again.
"""
# ruff: noqa: S603 -- explicit interpreter, fixed hook path

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.registry import AUTONOMOUS_FEEDBACK

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "src" / "guard" / "hooks" / "bash_command_validator.py"


def _run(
    command: str,
    *,
    autonomous: bool,
    decisions_path: Path | None = None,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    env["CLAUDE_AUTONOMOUS"] = "1" if autonomous else "0"
    if decisions_path is not None:
        env["GUARD_DECISIONS_PATH"] = str(decisions_path)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(
            {
                "session_id": "auto-test",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "hook_event_name": "PreToolUse",
                "cwd": "/tmp",  # noqa: S108 -- hook payload string, not a filesystem op
            }
        ),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _decision(stdout: str) -> str | None:
    if not stdout.strip():
        return None
    return json.loads(stdout).get("hookSpecificOutput", {}).get("permissionDecision")


def test_autonomous_default_denies_unknown_command(tmp_path: Path) -> None:
    """In autonomous mode, an unknown command (not on safe allowlist) is denied."""
    _rc, stdout, stderr = _run(
        "flarbnoz --gronk", autonomous=True, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) == "deny", (
        f"expected deny, got stdout={stdout[:300]} stderr={stderr[:300]}"
    )


def test_autonomous_allows_safe_command(tmp_path: Path) -> None:
    """`ls -la` is on the safe-prefix allowlist; autonomous mode allows."""
    _rc, stdout, stderr = _run("ls -la", autonomous=True, decisions_path=tmp_path / "log.jsonl")
    decision = _decision(stdout)
    assert decision == "allow", f"expected allow, got {decision!r} stderr={stderr[:300]}"


def test_interactive_passes_through_unknown(tmp_path: Path) -> None:
    """Without CLAUDE_AUTONOMOUS=1, an unknown command falls through (no deny envelope).

    Claude Code's normal permission prompt handles it.
    """
    _rc, stdout, _stderr = _run(
        "flarbnoz --gronk", autonomous=False, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) is None, f"expected passthrough, got stdout={stdout[:300]}"


def test_interactive_still_denies_always_deny(tmp_path: Path) -> None:
    """`git add -A` is in ALWAYS_DENY — denied in BOTH modes."""
    for mode in (True, False):
        _rc, stdout, _stderr = _run(
            "git add -A", autonomous=mode, decisions_path=tmp_path / f"log-{mode}.jsonl"
        )
        assert _decision(stdout) == "deny", f"mode={mode} expected deny, got stdout={stdout[:300]}"


@pytest.mark.parametrize("prefix", sorted(AUTONOMOUS_FEEDBACK.keys()))
def test_autonomous_feedback_surfaces_custom_message(prefix: str, tmp_path: Path) -> None:
    """For each AUTONOMOUS_FEEDBACK entry, autonomous mode denies with the custom message."""
    _rc, stdout, _stderr = _run(prefix, autonomous=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"{prefix!r} should deny in autonomous mode"
    envelope = json.loads(stdout)
    reason = envelope["hookSpecificOutput"]["permissionDecisionReason"]
    expected = AUTONOMOUS_FEEDBACK[prefix]
    assert reason == expected or expected in reason, (
        f"AUTONOMOUS_FEEDBACK[{prefix!r}] = {expected!r} not surfaced; got reason={reason!r}"
    )


def test_autonomous_queue_path_is_writable(tmp_path: Path) -> None:
    """Verify the autonomous queue gets a record when a denial happens.

    Uses GUARD_AUTONOMOUS_QUEUE_PATH override.
    """
    queue = tmp_path / "queue.jsonl"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    env["CLAUDE_AUTONOMOUS"] = "1"
    env["GUARD_AUTONOMOUS_QUEUE_PATH"] = str(queue)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(
            {
                "session_id": "queue-test",
                "tool_name": "Bash",
                "tool_input": {"command": "flarbnoz --gronk"},
                "hook_event_name": "PreToolUse",
                "cwd": "/tmp",  # noqa: S108 -- hook payload string, not a filesystem op
            }
        ),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    # Queue should exist and have at least one entry.
    assert queue.exists(), f"queue file not created. stderr={proc.stderr[:300]}"
    lines = queue.read_text().strip().splitlines()
    assert lines, "queue is empty"
    record = json.loads(lines[-1])
    assert record["command"] == "flarbnoz --gronk"
