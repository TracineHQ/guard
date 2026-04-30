"""Tests for protected_files hook."""

from __future__ import annotations

import json

from guard.hooks.protected_files import PROTECTED_PATTERNS, hook, is_protected


class TestIsProtected:
    def test_matches_bash_validator_guard_layout(self):
        match = is_protected("/some/repo/src/guard/hooks/bash_command_validator.py")
        assert match == "guard/hooks/bash_command_validator.py"

    def test_matches_legacy_command_registry(self):
        match = is_protected("/repo/hooks/command_registry.py")
        assert match == "hooks/command_registry.py"

    def test_matches_legacy_hook_utils(self):
        match = is_protected("/any/path/hooks/_hook_utils.py")
        assert match == "hooks/_hook_utils.py"

    def test_matches_protected_files_itself(self):
        assert (
            is_protected("/some/path/src/guard/hooks/protected_files.py")
            == "guard/hooks/protected_files.py"
        )

    def test_no_match_for_regular_file(self):
        assert is_protected("/Users/dev/develop/myproject/src/main.py") is None

    def test_no_match_empty(self):
        assert is_protected("") is None

    def test_no_partial_match(self):
        # Shouldn't match when 'hooks/' prefix is missing from the suffix
        assert is_protected("/some/path/not_hooks/command_registry.py") is None

    def test_all_patterns_end_with_py_or_json(self):
        # Tranche 1 hardening C6: settings.json patterns added; widen the
        # invariant to cover both file types.
        for p in PROTECTED_PATTERNS:
            assert p.endswith((".py", ".json"))

    def test_matches_claude_settings_json(self):
        # Tranche 1 hardening C6: edits to ~/.claude/settings.json must
        # surface for review (this file is the harness's hook ASK-gate).
        match = is_protected("/Users/x/.claude/settings.json")
        assert match == ".claude/settings.json"

    def test_matches_claude_settings_local_json(self):
        match = is_protected("/Users/x/.claude/settings.local.json")
        assert match == ".claude/settings.local.json"


class TestHook:
    def test_protected_files_imports(self):
        # Top-level import is the contract.
        assert callable(hook)

    def test_protected_files_allows_safe_input(self, capsys):
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/repo/src/myproject/main.py"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_protected_files_denies_unsafe_input(self, capsys):
        # The "deny" semantics for protected_files is "ask" (forces confirmation).
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/repo/src/guard/hooks/bash_command_validator.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_asks_on_write_protected_file(self, capsys):
        hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "/anywhere/hooks/credential_check.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_passes_through_on_non_edit_tool(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "cat hooks/_hook_utils.py"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_passes_through_on_read_tool(self, capsys):
        hook(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/repo/hooks/command_registry.py"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_passes_through_on_missing_file_path(self, capsys):
        hook({"tool_name": "Edit", "tool_input": {}})
        assert capsys.readouterr().out == ""
