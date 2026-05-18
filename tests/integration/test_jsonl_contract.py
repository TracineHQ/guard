# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""JSONL output-format contract test (docs/output-format.md schema v1).

Drives each of the 8 hooks as a real subprocess with a payload that triggers
a decision. Verifies every emitted record has the spec-required fields, the
expected ``hook_id``, and stays within the 4096-byte envelope.

This test exists to catch any future drift between the writer and the
documented JSONL consumer contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from tests._helpers import REPO_ROOT as REPO

HOOKS_DIR = REPO / "src" / "guard" / "hooks"

# Required schema-v1 fields per docs/output-format.md §3.
_REQUIRED_FIELDS = (
    "schema_version",
    "timestamp",
    "hook_id",
    "event",
    "tool_name",
    "decision",
    "reason",
    "session_id",
)

_VALID_DECISIONS = {"allow", "deny", "ask", "pass", "defer"}


def _run_hook(
    hook_path: Path,
    payload: dict[str, Any],
    decisions_path: Path,
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    env["GUARD_DECISIONS_PATH"] = str(decisions_path)
    env["GUARD_STRICT_DENY_QUEUE_PATH"] = str(decisions_path.parent / "queue.jsonl")
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


# Each entry is (hook_module, payload-that-triggers-a-decision).
_HOOK_CASES: list[tuple[str, dict[str, Any]]] = [
    (
        "bash_command_validator",
        {
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git add -A"},
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
    (
        "git_c_validator",
        {
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git -C /repo clean -fd"},
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
    (
        "credential_check",
        {
            "session_id": "sess-1",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(Path.home() / ".aws" / "credentials")},
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
    (
        "commit_message_validator",
        {
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {
                "command": 'git commit -m "fix\n\nCo-Authored-By: Claude <noreply@anthropic.com>"'
            },
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
    (
        "agent_output_guard",
        {
            "session_id": "sess-1",
            "tool_name": "Read",
            "tool_input": {"file_path": "/private/tmp/claude-1/proj/sess/tasks/x.output"},
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
    (
        "subagent_scope",
        {
            "session_id": "sess-1",
            "tool_name": "Edit",
            "tool_input": {"file_path": "_SCOPE_TMP_/out_of_scope.py"},
            "hook_event_name": "PreToolUse",
            "cwd": "_SCOPE_TMP_",
        },
    ),
    (
        "protected_files",
        {
            "session_id": "sess-1",
            "tool_name": "Edit",
            "tool_input": {"file_path": "/repo/src/guard/hooks/bash_command_validator.py"},
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp/work",
        },
    ),
]


@pytest.mark.parametrize(("hook_name", "payload"), _HOOK_CASES, ids=[c[0] for c in _HOOK_CASES])
def test_hook_emits_spec_compliant_record(
    hook_name: str, payload: dict[str, Any], tmp_path: Path
) -> None:
    """Every hook that decides must emit a v1-compliant JSONL record."""
    hook = HOOKS_DIR / f"{hook_name}.py"
    assert hook.exists(), f"missing hook: {hook}"

    decisions_path = tmp_path / "decisions.jsonl"

    # subagent_scope needs a scope file in cwd; write it before invoking.
    if hook_name == "subagent_scope":
        scope_dir = tmp_path / ".claude"
        scope_dir.mkdir()
        (scope_dir / "subagent-scope.json").write_text(
            json.dumps({"task": "T1", "allowed": ["allowed.py"]})
        )
        payload = {
            **payload,
            "tool_input": {"file_path": str(tmp_path / "out_of_scope.py")},
            "cwd": str(tmp_path),
        }

    _run_hook(hook, payload, decisions_path)

    assert decisions_path.exists(), (
        f"{hook_name}: no JSONL written — hook didn't call log_decision()"
    )

    raw_lines = decisions_path.read_bytes().splitlines()
    assert raw_lines, f"{hook_name}: empty JSONL"

    # Each emitted record must independently pass schema validation.
    for raw in raw_lines:
        # Envelope size: line + trailing \n must fit in 4096 bytes.
        assert len(raw) + 1 <= 4096, f"{hook_name}: record exceeds 4 KiB envelope"

        record = json.loads(raw.decode("utf-8"))

        for field in _REQUIRED_FIELDS:
            assert field in record, f"{hook_name}: missing required field {field!r}"

        assert record["schema_version"] == 1
        assert record["hook_id"] == f"guard.{hook_name}"
        assert record["event"] == "PreToolUse"
        assert record["decision"] in _VALID_DECISIONS
        assert record["reason"], f"{hook_name}: empty reason field"
        assert isinstance(record["reason"], str)
        assert len(record["reason"]) <= 1024

        # Timestamp must parse as ISO-8601 UTC with the trailing Z.
        ts = record["timestamp"]
        assert isinstance(ts, str)
        assert ts.endswith("Z"), f"{hook_name}: timestamp missing Z suffix: {ts!r}"
        # On 3.11+ fromisoformat accepts the trailing Z directly.
        datetime.fromisoformat(ts)

        # Optional fields, if present, must be the right type.
        if "command_excerpt" in record:
            assert record["command_excerpt"] is None or isinstance(record["command_excerpt"], str)
            if isinstance(record["command_excerpt"], str):
                assert len(record["command_excerpt"]) <= 4096
        if "cwd" in record:
            assert record["cwd"] is None or isinstance(record["cwd"], str)


def test_bash_validator_session_id_comes_from_payload(tmp_path: Path) -> None:
    """``session_id`` in the JSONL record must match the payload, not the env."""
    decisions_path = tmp_path / "decisions.jsonl"
    payload = {
        "session_id": "PAYLOAD-SID-XYZ",
        "tool_name": "Bash",
        "tool_input": {"command": "git add -A"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    env_overrides = {"CLAUDE_SESSION_ID": "ENV-SID-ABC"}
    _run_hook(
        HOOKS_DIR / "bash_command_validator.py",
        payload,
        decisions_path,
        env_overrides=env_overrides,
    )
    line = decisions_path.read_text().splitlines()[-1]
    record = json.loads(line)
    assert record["session_id"] == "PAYLOAD-SID-XYZ"


def test_at_least_one_hook_emits_a_real_decision(tmp_path: Path) -> None:
    """Sanity: drive every hook against `git add -A` and assert >=1 decision logged.

    Confirms the ``log_decision`` wiring isn't silently a no-op across the
    board.
    """
    decisions_path = tmp_path / "decisions.jsonl"
    payload = {
        "session_id": "smoke",
        "tool_name": "Bash",
        "tool_input": {"command": "git add -A"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }
    for hook_name in (
        "bash_command_validator",
        "git_c_validator",
        "credential_check",
        "commit_message_validator",
        "agent_output_guard",
        "subagent_scope",
        "protected_files",
    ):
        _run_hook(HOOKS_DIR / f"{hook_name}.py", payload, decisions_path)

    # At least bash_command_validator should fire on `git add -A`.
    assert decisions_path.exists()
    lines = decisions_path.read_text().splitlines()
    assert lines, "no decisions logged for any hook on `git add -A`"

    # Every line must be valid JSON with schema_version 1.
    for line in lines:
        record = json.loads(line)
        assert record["schema_version"] == 1
        assert record["hook_id"].startswith("guard.")
