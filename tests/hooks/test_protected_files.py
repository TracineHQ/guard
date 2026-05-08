# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
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

    def test_all_patterns_end_with_py_json_or_git_path(self):
        # Patterns now include .py hook files, .json settings files, and
        # git-infra paths (.git/hooks, .git/config, .gitmodules, etc.).
        for p in PROTECTED_PATTERNS:
            assert (
                p.endswith((".py", ".json"))
                or p.startswith((".git/", ".gitmodules", ".gitattributes"))
                or p == ".git"
            )

    def test_matches_claude_settings_json(self):
        # Edits to ~/.claude/settings.json must surface for review — that
        # file is the harness's hook ASK-gate.
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
        # ``cat`` has no write-target; the Bash branch produces no candidates
        # so the hook passes through.
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "cat hooks/_hook_utils.py"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_read_protected_now_asks_under_fallthrough(self, capsys):
        # Defense-in-depth: under the universal path scanner, Read of a
        # protected file surfaces ASK. Previous behavior was passthrough.
        hook(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/repo/hooks/command_registry.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_passes_through_on_missing_file_path(self, capsys):
        hook({"tool_name": "Edit", "tool_input": {}})
        assert capsys.readouterr().out == ""


class TestExpandedToolCoverage:
    """Coverage for MultiEdit, NotebookEdit, and Bash write targets."""

    def test_multi_edit_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "MultiEdit",
                "tool_input": {"file_path": "/repo/src/guard/hooks/protected_files.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_notebook_edit_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "NotebookEdit",
                "tool_input": {"notebook_path": "/repo/src/guard/registry.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_bash_redirect_to_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "echo x > /repo/src/guard/hooks/credential_check.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_bash_tee_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "echo x | tee /repo/src/guard/registry.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_bash_cp_protected_dst_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": "cp /tmp/x.py /repo/src/guard/hooks/bash_command_validator.py"
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_bash_unrelated_command_passes(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }
        )
        assert capsys.readouterr().out == ""


class TestTruncatePatchTar:
    """Truncate / patch / tar-extract write shapes must surface ASK."""

    def test_truncate_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "truncate -s 0 "
                        "/Users/dev/develop/guard/src/guard/hooks/bash_command_validator.py"
                    )
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_truncate_size_after_path_asks(self, capsys):
        # ``truncate file -s 0`` — flag after path
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": ("truncate /Users/dev/develop/guard/src/guard/registry.py -s 0")
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_truncate_unrelated_passes(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "truncate -s 0 /tmp/scratch.txt"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_patch_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "patch /Users/dev/develop/guard/src/guard/hooks/"
                        "bash_command_validator.py < /tmp/p.patch"
                    )
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_patch_with_flags_protected_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "patch -p1 /Users/dev/develop/guard/src/guard/_utils.py < /tmp/p.patch"
                    )
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_patch_unrelated_passes(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "patch /tmp/foo.txt < /tmp/p.patch"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_tar_xf_C_protected_dir_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": ("tar -xf /tmp/x.tar -C /Users/dev/develop/guard/src/guard/hooks/")
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_tar_xzf_directory_long_form_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "tar xzf /tmp/x.tar.gz --directory=/Users/dev/develop/guard/src/guard"
                    )
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_tar_extract_unrelated_passes(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "tar -xf /tmp/x.tar -C /tmp/extract"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_tar_create_does_not_match(self, capsys):
        # ``tar c`` is read, not write — must not trip the extract-dir matcher.
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": ("tar -cf /tmp/x.tar -C /Users/dev/develop/guard/src/guard/hooks/ .")
                },
            }
        )
        assert capsys.readouterr().out == ""


class TestSubagentScopeFileProtected:
    """`.claude/subagent-scope.json` must surface for review (security L2).

    A subagent rewriting its own scope is a TOCTOU bypass of subagent_scope.py.
    """

    def test_subagent_scope_json_edit_asks(self, capsys):
        hook(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/repo/.claude/subagent-scope.json"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_subagent_scope_json_bash_redirect_asks(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": "echo {} > /repo/.claude/subagent-scope.json",
                },
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"


class TestFallthroughToolCoverage:
    """Defense-in-depth: any tool we don't handle explicitly still gets scanned."""

    def test_glob_with_protected_pattern_asks(self, capsys):
        # A Glob that targets a protected path (defensive — Glob is read-only
        # today, but the principle is "any tool call should look for the path").
        hook(
            {
                "tool_name": "Glob",
                "tool_input": {"pattern": "/repo/src/guard/hooks/protected_files.py"},
            }
        )
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_unknown_tool_with_safe_path_passes(self, capsys):
        hook(
            {
                "tool_name": "Glob",
                "tool_input": {"pattern": "/repo/src/myapp/main.py"},
            }
        )
        assert capsys.readouterr().out == ""
