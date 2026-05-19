# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for permission_request_logger hook.

Observation-only contract: every test asserts the hook exits 0 with empty
stdout (so Claude Code's normal permission flow proceeds) AND writes
exactly one JSONL row of the new ``permission_request`` shape.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "permission_request_logger.py"
)


def _run(payload: dict, *, log_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the hook script with ``payload`` on stdin; return the completed process."""
    env = {
        "PATH": "/usr/bin:/bin",
        "GUARD_DECISIONS_PATH": str(log_path),
    }
    if cwd is not None:
        env["GUARD_DATA_DIR"] = str(cwd / ".claude" / "guard")
    return subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=10,
    )


def _read_one_row(log_path: Path) -> dict:
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected 1 row, got {len(lines)}: {lines!r}"
    return json.loads(lines[0])


def test_basic_payload_writes_row_and_passes_through(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "tool_use_id": "tu-123",
        "session_id": "sess-456",
        "permission_mode": "default",
        "cwd": str(tmp_path),
    }
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "", f"expected empty stdout, got: {result.stdout!r}"

    row = _read_one_row(log_path)
    assert row["type"] == "permission_request"
    assert row["v"] == 1
    assert row["schema_version"] == 1
    assert row["mode"] == "enforce"
    assert row["session_id"] == "sess-456"
    assert row["tool_name"] == "Bash"
    assert row["tool_use_id"] == "tu-123"
    assert row["permission_mode"] == "default"
    assert row["cwd"] == str(tmp_path)
    assert "ls -la" in row["tool_input_excerpt"]
    assert "timestamp" in row


def test_redacts_secrets_in_tool_input(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    # Use a high-confidence shape that the catalog redacts -- AWS access key id.
    fake_key = "AKIA" + "I" * 16
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": f"aws s3 ls --access-key {fake_key}"},
        "session_id": "s",
    }
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0
    row = _read_one_row(log_path)
    assert fake_key not in row["tool_input_excerpt"], (
        f"secret leaked into excerpt: {row['tool_input_excerpt']!r}"
    )


def test_missing_optional_fields_does_not_crash(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": "/tmp/x.py"},
        "session_id": "s",
        # no tool_use_id, no cwd, no permission_mode
    }
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0
    row = _read_one_row(log_path)
    assert row["type"] == "permission_request"
    assert row["tool_name"] == "Edit"
    assert "tool_use_id" not in row
    assert "permission_mode" not in row
    assert "cwd" not in row


def test_off_mode_skips_logging(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    cwd = tmp_path / "proj"
    cwd.mkdir()
    # Project-scope mode=off in the allowlist at the cwd.
    project_allowlist = cwd / ".claude" / "guard" / "allowlist.json"
    project_allowlist.parent.mkdir(parents=True)
    project_allowlist.write_text(json.dumps({"mode": "off"}), encoding="utf-8")

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "s",
        "cwd": str(cwd),
    }
    result = _run(payload, log_path=log_path, cwd=cwd)
    assert result.returncode == 0
    assert result.stdout == ""
    # off mode: no row written.
    assert not log_path.exists() or log_path.read_text(encoding="utf-8").strip() == ""


def test_non_dict_tool_input_does_not_crash(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    payload = {
        "tool_name": "Bash",
        "tool_input": "not-a-dict",  # malformed
        "session_id": "s",
    }
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0
    row = _read_one_row(log_path)
    assert row["type"] == "permission_request"


def test_empty_tool_name_no_op(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    payload = {"tool_name": "", "tool_input": {}, "session_id": "s"}
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0
    # No row written -- tool_name is required for a useful record.
    assert not log_path.exists() or log_path.read_text(encoding="utf-8").strip() == ""


def test_shadow_mode_still_logs(tmp_path: Path) -> None:
    """shadow mode is observation-on-deny for PreToolUse; for permission_request
    rows it has no behavioral difference from enforce (no enforcement, just
    logging) -- the mode field on the row records what guard's posture was."""
    log_path = tmp_path / "decisions.jsonl"
    cwd = tmp_path / "proj"
    cwd.mkdir()
    project_allowlist = cwd / ".claude" / "guard" / "allowlist.json"
    project_allowlist.parent.mkdir(parents=True)
    project_allowlist.write_text(json.dumps({"mode": "shadow"}), encoding="utf-8")

    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "session_id": "s",
        "cwd": str(cwd),
    }
    result = _run(payload, log_path=log_path, cwd=cwd)
    assert result.returncode == 0
    row = _read_one_row(log_path)
    assert row["mode"] == "shadow"


@pytest.mark.parametrize(
    "tool",
    ["Bash", "Edit", "Write", "Read", "Glob", "Grep", "WebFetch", "mcp__server__tool"],
)
def test_logs_for_every_tool_shape(tool: str, tmp_path: Path) -> None:
    """The matcher in hooks.json is ``*``; the hook itself must not gate on tool name."""
    log_path = tmp_path / "decisions.jsonl"
    payload = {"tool_name": tool, "tool_input": {}, "session_id": "s"}
    result = _run(payload, log_path=log_path)
    assert result.returncode == 0
    row = _read_one_row(log_path)
    assert row["tool_name"] == tool
