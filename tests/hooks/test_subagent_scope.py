"""Tests for subagent_scope hook."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from guard.hooks.subagent_scope import hook

if TYPE_CHECKING:
    from pathlib import Path


def _write_scope(tmp_path: Path, data) -> Path:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    scope_file = claude_dir / "subagent-scope.json"
    if isinstance(data, str):
        scope_file.write_text(data)
    else:
        scope_file.write_text(json.dumps(data))
    return tmp_path


class TestSubagentScope:
    def test_subagent_scope_imports(self):
        # The top-level import is the contract; this asserts the symbol is callable.
        assert callable(hook)

    def test_no_scope_file_passthrough(self, tmp_path, capsys):
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/x.py")},
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_subagent_scope_allows_safe_input(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/x.py")},
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_subagent_scope_denies_unsafe_input(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/y.py")},
                "cwd": str(tmp_path),
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_write_disallowed_file_denied(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/other.py")},
                "cwd": str(tmp_path),
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_glob_pattern_matching(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/tests/test_*.py"]})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/tests/test_foo.py")},
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_directory_pattern_matching(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/tests/"]})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": str(tmp_path / "pkg/tests/sub/deep.py"),
                },
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_read_tool_passthrough(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        hook(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/y.py")},
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_malformed_scope_file_passthrough(self, tmp_path, capsys):
        _write_scope(tmp_path, "{ not valid json")
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/y.py")},
                "cwd": str(tmp_path),
            }
        )
        assert capsys.readouterr().out == ""

    def test_deny_message_includes_allowed_list(self, tmp_path, capsys):
        allowed = ["pkg/src/x.py", "pkg/tests/test_x.py", "pkg/tests/fixtures/"]
        _write_scope(tmp_path, {"task": "T1", "allowed": allowed})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/other.py")},
                "cwd": str(tmp_path),
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        reason = envelope["hookSpecificOutput"]["permissionDecisionReason"]
        for entry in allowed:
            assert entry in reason

    def test_deny_message_includes_task_name(self, tmp_path, capsys):
        task_name = "Task 2.1: edit churn detection"
        _write_scope(tmp_path, {"task": task_name, "allowed": ["pkg/src/x.py"]})
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": str(tmp_path / "pkg/src/other.py")},
                "cwd": str(tmp_path),
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert task_name in envelope["hookSpecificOutput"]["permissionDecisionReason"]
