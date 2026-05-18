# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""End-to-end: when permission_mode is dontAsk/bypassPermissions,
bash_command_validator default-denies unsafe segments and surfaces
STRICT_FEEDBACK custom messages.

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

from guard.registry import STRICT_FEEDBACK
from tests._helpers import REPO_ROOT as REPO
from tests._helpers import decision_from_stdout as _decision

HOOK = REPO / "src" / "guard" / "hooks" / "bash_command_validator.py"


def _run(
    command: str,
    *,
    strict: bool,
    decisions_path: Path | None = None,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
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
                "permission_mode": "dontAsk" if strict else "default",
            }
        ),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_strict_default_denies_unknown_command(tmp_path: Path) -> None:
    """In strict mode, an unknown command (not on safe allowlist) is denied."""
    _rc, stdout, stderr = _run(
        "flarbnoz --gronk", strict=True, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) == "deny", (
        f"expected deny, got stdout={stdout[:300]} stderr={stderr[:300]}"
    )


def test_strict_allows_safe_command(tmp_path: Path) -> None:
    """`ls -la` is on the safe-prefix allowlist; strict mode allows."""
    _rc, stdout, stderr = _run("ls -la", strict=True, decisions_path=tmp_path / "log.jsonl")
    decision = _decision(stdout)
    assert decision == "allow", f"expected allow, got {decision!r} stderr={stderr[:300]}"


def test_interactive_passes_through_unknown(tmp_path: Path) -> None:
    """With permission_mode=default, an unknown command falls through (no deny envelope).

    Claude Code's normal permission prompt handles it.
    """
    _rc, stdout, _stderr = _run(
        "flarbnoz --gronk", strict=False, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) is None, f"expected passthrough, got stdout={stdout[:300]}"


@pytest.mark.parametrize("strict", [True, False])
def test_interactive_still_denies_always_deny(tmp_path: Path, strict: bool) -> None:  # noqa: FBT001
    """`git add -A` is in ALWAYS_DENY — denied in BOTH modes."""
    _rc, stdout, _stderr = _run(
        "git add -A", strict=strict, decisions_path=tmp_path / f"log-{strict}.jsonl"
    )
    assert _decision(stdout) == "deny", f"strict={strict} expected deny, got stdout={stdout[:300]}"


@pytest.mark.parametrize("prefix", sorted(STRICT_FEEDBACK.keys()))
def test_strict_feedback_surfaces_custom_message(prefix: str, tmp_path: Path) -> None:
    """For each STRICT_FEEDBACK entry, strict mode denies. The custom message
    is surfaced unless a more-specific synthetic matcher (e.g. bash.admin_default_deny)
    preempts with its own reason — in which case the deny still fires with rule id
    + override guidance, which is the contract callers depend on.
    """
    _rc, stdout, _stderr = _run(prefix, strict=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"{prefix!r} should deny in strict mode"
    envelope = json.loads(stdout)
    reason = envelope["hookSpecificOutput"]["permissionDecisionReason"]
    expected = STRICT_FEEDBACK[prefix]
    assert (
        expected in reason or "bash.admin_default_deny" in reason or "bash.always_deny" in reason
    ), (
        f"STRICT_FEEDBACK[{prefix!r}] = {expected!r} not surfaced and no fallback "
        f"matcher fired; got reason={reason!r}"
    )


def test_strict_denies_deeply_stacked_env_python_dash_c(tmp_path: Path) -> None:
    """9 stacked ``env A=1 ...`` wrappers around ``python3 -c "pass"`` must deny.

    Locks in the inverted-default behavior: the inner ``python3 -c`` is not on
    SAFE_PREFIXES, so even if the unwrap fixpoint runs out of peels, strict
    mode default-denies the whole shape.
    """
    cmd = "env A=1 " * 9 + 'python3 -c "pass"'
    _rc, stdout, _stderr = _run(cmd, strict=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"9-stack env+python3 -c not denied: {stdout[:300]}"


def test_strict_denies_unicode_homoglyph_head(tmp_path: Path) -> None:
    """Cyrillic 'ie' (U+0435) homoglyph as the head of an eval-rm must deny.

    The head token is not ASCII eval, so the eval-builtin matcher doesn't fire,
    but the segment is also not on SAFE_PREFIXES — strict mode denies.
    The Cyrillic character is constructed from its codepoint so the source
    file itself stays ASCII (and ruff RUF001 stays quiet).
    """
    cmd = "еval rm -rf /"  # noqa: RUF001 -- leading Cyrillic ie is the bypass payload
    _rc, stdout, _stderr = _run(cmd, strict=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"unicode-homoglyph head not denied: {stdout[:300]}"


def test_strict_denies_encoded_base64_pipe_bash(tmp_path: Path) -> None:
    """``echo <b64> | base64 -d | bash`` must deny in strict mode."""
    cmd = "echo cm0gLXJmIC8K | base64 -d | bash"
    _rc, stdout, _stderr = _run(cmd, strict=True, decisions_path=tmp_path / "log.jsonl")
    assert _decision(stdout) == "deny", f"encoded base64-pipe-bash not denied: {stdout[:300]}"


def test_strict_allows_neutral_safe_prefix(tmp_path: Path) -> None:
    """``git status`` is on SAFE_PREFIXES and must allow under the inverted default."""
    log = tmp_path / "log.jsonl"
    _rc, stdout, _stderr = _run("git status", strict=True, decisions_path=log)
    assert _decision(stdout) == "allow", f"git status not allowed: {stdout[:300]}"


def test_interactive_unchanged_for_unknown_command(tmp_path: Path) -> None:
    """Interactive mode (permission_mode=default) must still passthrough unknown commands.

    The inverted-default behavior is strict-mode-only; interactive mode
    is unchanged and continues to passthrough unknown commands.
    """
    _rc, stdout, _stderr = _run(
        "flarbnoz --gronk", strict=False, decisions_path=tmp_path / "log.jsonl"
    )
    assert _decision(stdout) is None, f"interactive should passthrough: {stdout[:300]}"


def test_strict_queue_path_is_writable(tmp_path: Path) -> None:
    """Verify the strict-deny queue gets a record when a denial happens.

    Uses GUARD_STRICT_DENY_QUEUE_PATH override.
    """
    queue = tmp_path / "queue.jsonl"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    env["GUARD_STRICT_DENY_QUEUE_PATH"] = str(queue)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(
            {
                "session_id": "queue-test",
                "tool_name": "Bash",
                "tool_input": {"command": "flarbnoz --gronk"},
                "hook_event_name": "PreToolUse",
                "cwd": "/tmp",
                "permission_mode": "dontAsk",
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
