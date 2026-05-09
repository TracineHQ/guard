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

    def test_all_patterns_have_recognizable_shape(self):
        # Patterns include hook source (.py), settings (.json), git-infra
        # paths (.git/hooks, .gitmodules), agent-config files (.md, .yml,
        # .cursorrules, .aider.conf.yml.user), and a small set of dot-dirs
        # (mcp_servers/, cursor/rules, etc.) where the last segment carries
        # no extension.
        recognized_suffixes = (
            ".py",
            ".json",
            ".md",
            ".yml",
            ".yaml",
            ".cursorrules",
            ".user",
            "/config",
            "/hooks",
            "/rules",
            "/mcp_servers",
        )
        recognized_prefixes = (".git/", ".gitmodules", ".gitattributes")
        for p in PROTECTED_PATTERNS:
            assert (
                p.endswith(recognized_suffixes) or p.startswith(recognized_prefixes) or p == ".git"
            ), f"pattern {p!r} is neither a known suffix nor a git-infra path"

    def test_matches_claude_settings_json(self):
        # Edits to ~/.claude/settings.json must surface for review — that
        # file is the harness's hook ASK-gate.
        match = is_protected("/Users/x/.claude/settings.json")
        assert match == ".claude/settings.json"

    def test_matches_claude_settings_local_json(self):
        match = is_protected("/Users/x/.claude/settings.local.json")
        assert match == ".claude/settings.local.json"

    # --- Agent-config poisoning surface (pass-4 T4.2) -------------------

    def test_matches_project_claude_md(self):
        assert is_protected("/repo/CLAUDE.md") == "CLAUDE.md"

    def test_matches_user_claude_md(self):
        assert is_protected("/Users/x/.claude/CLAUDE.md") == ".claude/CLAUDE.md"

    def test_matches_cursorrules(self):
        assert is_protected("/repo/.cursorrules") == ".cursorrules"

    def test_matches_cursor_rules_dir(self):
        assert is_protected("/repo/.cursor/rules/foo.md") == ".cursor/rules"

    def test_matches_aider_conf(self):
        assert is_protected("/repo/.aider.conf.yml") == ".aider.conf.yml"

    def test_matches_continue_config(self):
        assert is_protected("/repo/.continue/config.json") == ".continue/config.json"

    def test_matches_mcp_servers_dir(self):
        assert is_protected("/Users/x/.claude/mcp_servers/foo.json") == ".claude/mcp_servers"

    def test_matches_mcp_json(self):
        assert is_protected("/Users/x/.claude/mcp.json") == ".claude/mcp.json"

    def test_matches_aws_config(self):
        assert is_protected("/Users/x/.aws/config") == ".aws/config"

    def test_matches_guard_allowlist(self):
        assert (
            is_protected("/Users/x/.claude/guard/allowlist.json") == ".claude/guard/allowlist.json"
        )


class TestCaseInsensitiveFs:
    """On macOS APFS / Windows NTFS, ``.Claude`` and ``.claude`` resolve to
    the same on-disk file. Pattern matching must normalise case there or an
    attacker can edit ``.Claude/CLAUDE.md`` and evade ``is_protected``.

    These tests force ``_CASE_INSENSITIVE_FS = True`` regardless of the host
    platform so the behaviour is verified in CI on Linux.
    """

    def test_uppercased_dir_segment_matches_when_fs_is_case_insensitive(self, monkeypatch):
        from guard.hooks import protected_files as pf

        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", True)
        # ``.Claude`` capitalised — would NOT match on a case-sensitive FS,
        # MUST match on darwin/win32.
        assert pf.is_protected("/repo/.Claude/CLAUDE.md") == ".claude/CLAUDE.md"

    def test_uppercased_file_basename_matches_when_fs_is_case_insensitive(self, monkeypatch):
        from guard.hooks import protected_files as pf

        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", True)
        # ``Claude.MD`` mixed case — same on-disk file as ``CLAUDE.md`` on
        # darwin APFS.
        assert pf.is_protected("/repo/Claude.Md") == "CLAUDE.md"

    def test_uppercased_dotgit_hooks_matches_when_fs_is_case_insensitive(self, monkeypatch):
        from guard.hooks import protected_files as pf

        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", True)
        assert pf.is_protected("/repo/.GIT/hooks/post-commit") == ".git/hooks"

    def test_returns_original_case_pattern_in_match(self, monkeypatch):
        """The matched pattern returned to the caller MUST stay original-case
        so the deny message reads correctly to humans (``CLAUDE.md`` not
        ``claude.md``).
        """
        from guard.hooks import protected_files as pf

        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", True)
        assert pf.is_protected("/repo/.CLAUDE/claude.md") == ".claude/CLAUDE.md"

    def test_case_sensitive_fs_does_not_match_uppercased_variants(self, monkeypatch):
        """On Linux, ``.GIT`` and ``.git`` ARE different paths and must not
        collide. Verifies the per-platform branch still works. (We use
        ``.GIT/hooks/post-commit`` because ``.Claude/CLAUDE.md`` would still
        match on the basename ``CLAUDE.md``, which IS a protected pattern.)
        """
        from guard.hooks import protected_files as pf

        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", False)
        assert pf.is_protected("/repo/.GIT/hooks/post-commit") is None


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
