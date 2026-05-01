"""End-to-end: when CLAUDE_AUTONOMOUS=1, bash_command_validator default-denies
unsafe segments and surfaces AUTONOMOUS_FEEDBACK custom messages.

Locks in the strict-mode safety net for subagents / driven agents so it can't
silently regress again.
"""

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
                "cwd": "/tmp",
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


def test_autonomous_denies_deeply_stacked_env_python_dash_c(tmp_path: Path) -> None:
    """9 stacked ``env A=1 ...`` wrappers around ``python3 -c "pass"`` must deny.

    Locks in the inverted-default behavior: the inner ``python3 -c`` is not on
    SAFE_PREFIXES, so even if the unwrap fixpoint runs out of peels, autonomous
    mode default-denies the whole shape.
    """
    cmd = "env A=1 " * 9 + 'python3 -c "pass"'
    _rc, stdout, _stderr = _run(cmd, autonomous=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"9-stack env+python3 -c not denied: {stdout[:300]}"


def test_autonomous_denies_unicode_homoglyph_head(tmp_path: Path) -> None:
    """Cyrillic 'ie' (U+0435) homoglyph as the head of an eval-rm must deny.

    The head token is not ASCII eval, so the eval-builtin matcher doesn't fire,
    but the segment is also not on SAFE_PREFIXES — autonomous mode denies.
    The Cyrillic character is constructed from its codepoint so the source
    file itself stays ASCII (and ruff RUF001 stays quiet).
    """
    cmd = "еval rm -rf /"  # noqa: RUF001 -- leading Cyrillic ie is the bypass payload
    _rc, stdout, _stderr = _run(cmd, autonomous=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"unicode-homoglyph head not denied: {stdout[:300]}"


def test_autonomous_denies_encoded_base64_pipe_bash(tmp_path: Path) -> None:
    """``echo <b64> | base64 -d | bash`` must deny in autonomous mode."""
    cmd = "echo cm0gLXJmIC8K | base64 -d | bash"
    _rc, stdout, _stderr = _run(cmd, autonomous=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"encoded base64-pipe-bash not denied: {stdout[:300]}"


def test_autonomous_allows_neutral_safe_prefix(tmp_path: Path) -> None:
    """``git status`` is on SAFE_PREFIXES and must allow under the inverted default."""
    log = tmp_path / "log.jsonl"
    _rc, stdout, _stderr = _run("git status", autonomous=True, decisions_path=log)
    assert _decision(stdout) == "allow", f"git status not allowed: {stdout[:300]}"


def test_interactive_unchanged_for_unknown_command(tmp_path: Path) -> None:
    """Interactive mode (CLAUDE_AUTONOMOUS=0) must still passthrough unknown commands.

    The inverted-default in C1 only changes autonomous mode; the interactive
    32+16 verifier suite must continue to behave identically.
    """
    _rc, stdout, _stderr = _run(
        "flarbnoz --gronk", autonomous=False, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) is None, f"interactive should passthrough: {stdout[:300]}"


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
                "cwd": "/tmp",
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
