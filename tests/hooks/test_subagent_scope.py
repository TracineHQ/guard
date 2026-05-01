"""Tests for subagent_scope hook."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from guard.hooks.subagent_scope import hook, is_allowed

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
        # Fix #7: deny path now exits 2 — wrap in pytest.raises(SystemExit).
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        with pytest.raises(SystemExit) as exc:
            hook(
                {
                    "tool_name": "Edit",
                    "tool_input": {"file_path": str(tmp_path / "pkg/src/y.py")},
                    "cwd": str(tmp_path),
                }
            )
        assert exc.value.code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_write_disallowed_file_denied(self, tmp_path, capsys):
        # Fix #7: deny path now exits 2.
        _write_scope(tmp_path, {"task": "T1", "allowed": ["pkg/src/x.py"]})
        with pytest.raises(SystemExit) as exc:
            hook(
                {
                    "tool_name": "Write",
                    "tool_input": {"file_path": str(tmp_path / "pkg/src/other.py")},
                    "cwd": str(tmp_path),
                }
            )
        assert exc.value.code == 2
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
        # Fix #7: deny path now exits 2.
        allowed = ["pkg/src/x.py", "pkg/tests/test_x.py", "pkg/tests/fixtures/"]
        _write_scope(tmp_path, {"task": "T1", "allowed": allowed})
        with pytest.raises(SystemExit):
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
        # Fix #7: deny path now exits 2.
        task_name = "Task 2.1: edit churn detection"
        _write_scope(tmp_path, {"task": task_name, "allowed": ["pkg/src/x.py"]})
        with pytest.raises(SystemExit):
            hook(
                {
                    "tool_name": "Edit",
                    "tool_input": {"file_path": str(tmp_path / "pkg/src/other.py")},
                    "cwd": str(tmp_path),
                }
            )
        envelope = json.loads(capsys.readouterr().out)
        assert task_name in envelope["hookSpecificOutput"]["permissionDecisionReason"]


# === Plain-pattern matching is anchored to cwd ===
#
# Earlier versions fell through to ``abs_path.endswith("/" + pattern)`` which
# matched anywhere on disk: a plain allowlist entry like ``src/safe.py`` would
# silently allow ``/totally_unrelated/src/safe.py``. Match strictly within cwd.


class TestExpandedToolCoverage:
    """MultiEdit and NotebookEdit must be enforced like Edit/Write."""

    def test_multi_edit_out_of_scope_denied(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["allowed.py"]})
        with pytest.raises(SystemExit):
            hook(
                {
                    "tool_name": "MultiEdit",
                    "tool_input": {"file_path": str(tmp_path / "out.py"), "edits": []},
                    "cwd": str(tmp_path),
                }
            )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_notebook_edit_uses_notebook_path(self, tmp_path, capsys):
        _write_scope(tmp_path, {"task": "T1", "allowed": ["allowed.ipynb"]})
        with pytest.raises(SystemExit):
            hook(
                {
                    "tool_name": "NotebookEdit",
                    "tool_input": {"notebook_path": str(tmp_path / "out.ipynb")},
                    "cwd": str(tmp_path),
                }
            )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestAbsoluteDirPattern:
    """Absolute trailing-slash patterns must match against the abs path."""

    def test_absolute_dir_pattern_matches_descendant(self, tmp_path):
        # Construct a real absolute path outside cwd. Use tmp_path's own
        # parent as the pattern so resolve() doesn't symlink-rewrite it.
        cwd = tmp_path / "projA"
        cwd.mkdir()
        target_dir = tmp_path / "leak"
        target_dir.mkdir()
        target = target_dir / "data.txt"
        target.write_text("x")
        pattern = str(target_dir.resolve()) + "/"
        assert is_allowed(str(target), str(cwd), [pattern])

    def test_absolute_dir_pattern_does_not_match_sibling(self, tmp_path):
        cwd = tmp_path / "projA"
        cwd.mkdir()
        leak = tmp_path / "leak"
        leak.mkdir()
        sibling = tmp_path / "other" / "x.txt"
        sibling.parent.mkdir()
        sibling.write_text("x")
        pattern = str(leak.resolve()) + "/"
        assert not is_allowed(str(sibling), str(cwd), [pattern])


class TestGlobstarRecursion:
    """``**/<glob>`` must match top-level files too (Python fnmatch is FS-blind)."""

    def test_globstar_md_matches_top_level(self, tmp_path):
        target = tmp_path / "README.md"
        target.write_text("x")
        assert is_allowed(str(target), str(tmp_path), ["**/*.md"])

    def test_globstar_md_matches_nested(self, tmp_path):
        nested = tmp_path / "src" / "notes.md"
        nested.parent.mkdir(parents=True)
        nested.write_text("x")
        assert is_allowed(str(nested), str(tmp_path), ["**/*.md"])

    def test_globstar_does_not_match_other_extensions(self, tmp_path):
        target = tmp_path / "src" / "code.py"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        assert not is_allowed(str(target), str(tmp_path), ["**/*.md"])


class TestSubagentScopeF7:
    def test_plain_pattern_does_not_match_outside_cwd(self, tmp_path):
        # cwd = tmp_path/projA ; allowed = src/safe.py.
        # Edit target lives in tmp_path/other/src/safe.py — outside cwd.

        cwd = tmp_path / "projA"
        cwd.mkdir()
        outside = tmp_path / "other" / "src"
        outside.mkdir(parents=True)
        outside_file = outside / "safe.py"
        outside_file.write_text("x")
        assert not is_allowed(str(outside_file), str(cwd), ["src/safe.py"])

    def test_plain_pattern_basename_only_does_not_match_etc(self, tmp_path):

        cwd = tmp_path / "projA"
        cwd.mkdir()
        # Patterns of just a basename used to match anywhere via endswith.
        assert not is_allowed("/etc/something/safe.py", str(cwd), ["safe.py"])

    def test_plain_pattern_inside_cwd_still_matches(self, tmp_path):

        cwd = tmp_path
        target = tmp_path / "src" / "safe.py"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        assert is_allowed(str(target), str(cwd), ["src/safe.py"])

    def test_glob_pattern_does_not_match_outside_cwd(self, tmp_path):

        cwd = tmp_path / "projA"
        cwd.mkdir()
        outside = tmp_path / "other" / "tests"
        outside.mkdir(parents=True)
        outside_file = outside / "test_x.py"
        outside_file.write_text("x")
        assert not is_allowed(str(outside_file), str(cwd), ["tests/test_*.py"])

    def test_dir_pattern_does_not_match_outside_cwd(self, tmp_path):

        cwd = tmp_path / "projA"
        cwd.mkdir()
        outside = tmp_path / "other" / "tests" / "deep"
        outside.mkdir(parents=True)
        outside_file = outside / "x.py"
        outside_file.write_text("x")
        assert not is_allowed(str(outside_file), str(cwd), ["tests/"])

    def test_hook_denies_outside_cwd_plain(self, tmp_path, capsys):
        # End-to-end: scope file in cwd allows ``src/safe.py``; hook is
        # asked to Edit a file outside cwd that ends with the same suffix.
        claude_dir = tmp_path / "projA" / ".claude"
        claude_dir.mkdir(parents=True)
        (claude_dir / "subagent-scope.json").write_text(
            json.dumps({"task": "T1", "allowed": ["src/safe.py"]})
        )
        outside = tmp_path / "other" / "src"
        outside.mkdir(parents=True)
        outside_file = outside / "safe.py"
        outside_file.write_text("x")

        with pytest.raises(SystemExit) as exc:
            hook(
                {
                    "tool_name": "Edit",
                    "tool_input": {"file_path": str(outside_file)},
                    "cwd": str(tmp_path / "projA"),
                }
            )
        assert exc.value.code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"
