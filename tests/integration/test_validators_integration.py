"""Integration tests — every hook runs as a real subprocess on benign and
representative-unsafe payloads. These tests verify that hooks never crash
and that they produce well-formed output for the harness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOKS_DIR = REPO / "src" / "guard" / "hooks"

HOOK_NAMES = [
    "bash_command_validator",
    "git_c_validator",
    "credential_check",
    "commit_message_validator",
    "agent_output_guard",
    "subagent_scope",
    "protected_files",
]


def _run_hook(hook_path, payload, env_overrides=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, str(hook_path)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


@pytest.mark.parametrize("hook_name", HOOK_NAMES)
def test_hook_handles_benign_payload(hook_name, tmp_path):
    """Each hook must run on a benign payload without crashing.

    Decision MAY be allow, deny, ask, or no-output, but the hook must not
    exit nonzero for ``credential_check`` (which has no PreToolUse contract;
    it's a check helper) or with a traceback on stderr for any hook.
    """
    hook = HOOKS_DIR / f"{hook_name}.py"
    assert hook.exists(), f"missing hook: {hook}"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    decisions_file = tmp_path / "guard-decisions.jsonl"
    rc, _stdout, stderr = _run_hook(hook, payload, {"GUARD_DECISIONS_PATH": str(decisions_file)})
    assert rc in (0, 2), f"hook {hook_name} crashed: rc={rc} stderr={stderr[:500]}"
    assert "Traceback" not in stderr, f"hook {hook_name} raised: stderr={stderr[:500]}"


def test_bash_validator_denies_dangerous_command(tmp_path):
    hook = HOOKS_DIR / "bash_command_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": "gh auth token"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload, {"GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")})
    if stdout.strip():
        decision = json.loads(stdout)
        permission = decision["hookSpecificOutput"]["permissionDecision"]
        assert permission in ("deny", "ask")
    else:
        assert rc == 2, f"expected deny, got rc={rc} stdout={stdout!r}"


def test_bash_validator_allows_safe_pipeline(tmp_path):
    hook = HOOKS_DIR / "bash_command_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": "# search\ngrep -rn foo src/ | head -5"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload, {"GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")})
    assert rc == 0
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "allow"


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git add --all",
        "git add .",
        "git branch -D feature",
        "terraform destroy",
    ],
)
def test_bash_validator_denies_always_deny_commands(command, tmp_path):
    """Single-segment ALWAYS_DENY entries must produce a deny envelope."""
    hook = HOOKS_DIR / "bash_command_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload, {"GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")})
    # Fix #7: deny path now exits 2.
    assert rc == 2, f"unexpected rc={rc} for {command!r}"
    assert stdout.strip(), f"expected deny envelope on stdout for {command!r}"
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "git add foo.py",  # specific file, not in ALWAYS_DENY
        "ls -la",  # benign, passthrough
    ],
)
def test_bash_validator_does_not_deny_safe(command, tmp_path):
    """Commands not in ALWAYS_DENY must not be denied by this path."""
    hook = HOOKS_DIR / "bash_command_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload, {"GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")})
    assert rc == 0
    if stdout.strip():
        decision = json.loads(stdout)
        assert decision["hookSpecificOutput"]["permissionDecision"] != "deny"


def test_git_c_validator_denies_destructive(tmp_path):
    hook = HOOKS_DIR / "git_c_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": "git -C /repo clean -fd"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    assert rc == 2
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_git_c_validator_allows_status(tmp_path):
    hook = HOOKS_DIR / "git_c_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {"command": "git -C /repo status"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    assert rc == 0
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_commit_message_validator_denies_ai_attribution(tmp_path):
    hook = HOOKS_DIR / "commit_message_validator.py"
    payload = {
        "session_id": "test",
        "tool_name": "Bash",
        "tool_input": {
            "command": ('git commit -m "fix\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>"')
        },
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    assert rc == 2
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_agent_output_guard_denies_output_read(tmp_path):
    hook = HOOKS_DIR / "agent_output_guard.py"
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "/private/tmp/claude-1/proj/sess/tasks/x.output"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    # Fix #7: deny path now exits 2.
    assert rc == 2
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_protected_files_asks_on_hook_edit(tmp_path):
    hook = HOOKS_DIR / "protected_files.py"
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": "/repo/src/guard/hooks/bash_command_validator.py"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    assert rc == 0
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_subagent_scope_denies_out_of_scope_edit(tmp_path):
    hook = HOOKS_DIR / "subagent_scope.py"
    scope_dir = tmp_path / ".claude"
    scope_dir.mkdir()
    (scope_dir / "subagent-scope.json").write_text(
        json.dumps({"task": "T1", "allowed": ["pkg/src/x.py"]})
    )
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": str(tmp_path / "pkg/src/y.py")},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    rc, stdout, _ = _run_hook(hook, payload)
    # Fix #7: deny path now exits 2.
    assert rc == 2
    decision = json.loads(stdout)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
