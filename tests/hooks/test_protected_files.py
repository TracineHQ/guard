# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for protected_files hook.

Hook-level behavior (guard mode, exit code, logging) lives in
``tests/test_steer_not_ask.py``; this file covers path matching and the
write-shape table through the pure ``decide()``.
"""

from __future__ import annotations

from typing import Any

import pytest

from guard.hooks import protected_files as pf
from guard.hooks.protected_files import LOCKDOWN_PATTERNS, PROTECTED_PATTERNS, decide, is_protected

_LOCKDOWN = pf._effective_patterns(mode="lockdown")  # noqa: SLF001 -- module-private pattern resolver


class TestIsProtected:
    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            (
                "/some/repo/src/guard/hooks/bash_command_validator.py",
                "guard/hooks/bash_command_validator.py",
            ),
            ("/some/path/src/guard/hooks/protected_files.py", "guard/hooks/protected_files.py"),
            ("/repo/hooks/command_registry.py", "hooks/command_registry.py"),
            ("/any/path/hooks/_hook_utils.py", "hooks/_hook_utils.py"),
            ("/Users/x/.claude/guard/allowlist.json", ".claude/guard/allowlist.json"),
        ],
    )
    def test_matches_trust_root(self, path: str, pattern: str) -> None:
        assert is_protected(path) == pattern

    @pytest.mark.parametrize(
        "path",
        [
            "/Users/dev/develop/myproject/src/main.py",
            "",
            "/some/path/not_hooks/command_registry.py",
        ],
    )
    def test_no_match_by_default(self, path: str) -> None:
        assert is_protected(path) is None

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("/repo/CLAUDE.md", "CLAUDE.md"),
            ("/Users/x/.claude/CLAUDE.md", ".claude/CLAUDE.md"),
            ("/repo/.cursorrules", ".cursorrules"),
            ("/repo/.cursor/rules/foo.md", ".cursor/rules"),
            ("/repo/.aider.conf.yml", ".aider.conf.yml"),
            ("/repo/.continue/config.json", ".continue/config.json"),
            ("/Users/x/.claude/mcp_servers/foo.json", ".claude/mcp_servers"),
            ("/Users/x/.claude/mcp.json", ".claude/mcp.json"),
            ("/Users/x/.aws/config", ".aws/config"),
            ("/repo/.git/hooks/pre-commit", ".git/hooks"),
        ],
    )
    def test_matches_lockdown_list(self, path: str, pattern: str) -> None:
        assert is_protected(path, _LOCKDOWN) == pattern

    def test_all_patterns_have_recognizable_shape(self) -> None:
        recognized_suffixes = (
            ".py",
            ".json",
            ".md",
            ".yml",
            ".cursorrules",
            ".user",
            "/config",
            "/hooks",
            "/rules",
            "/mcp_servers",
        )
        recognized_prefixes = (".git/", ".gitmodules", ".gitattributes")
        for p in (*PROTECTED_PATTERNS, *LOCKDOWN_PATTERNS):
            assert p.endswith(recognized_suffixes) or p.startswith(recognized_prefixes), p


class TestCaseInsensitiveFs:
    """On macOS APFS / Windows NTFS, ``.Claude`` and ``.claude`` resolve to the
    same on-disk file, so matching normalises case there. Forced on so CI on
    Linux verifies it."""

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("/repo/.Claude/CLAUDE.md", ".claude/CLAUDE.md"),
            ("/repo/Claude.Md", "CLAUDE.md"),
            ("/repo/.GIT/hooks/post-commit", ".git/hooks"),
            # The returned pattern stays original-case for the deny message.
            ("/repo/.CLAUDE/claude.md", ".claude/CLAUDE.md"),
            ("/repo/SRC/GUARD/_Utils.py", "guard/_utils.py"),
        ],
    )
    def test_case_insensitive_match(
        self, monkeypatch: pytest.MonkeyPatch, path: str, pattern: str
    ) -> None:
        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", True)
        assert is_protected(path, _LOCKDOWN) == pattern

    def test_case_sensitive_fs_does_not_match_uppercased_variants(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", False)
        assert is_protected("/repo/.GIT/hooks/post-commit", _LOCKDOWN) is None


_GUARD = "/Users/dev/develop/guard/src/guard"

# Each row: tool name, tool input, and whether protected_files denies it.
_WRITE_SHAPES: list[tuple[str, dict[str, Any], bool]] = [
    ("Edit", {"file_path": "/repo/src/myproject/main.py"}, False),
    ("Edit", {"file_path": "/repo/src/guard/hooks/bash_command_validator.py"}, True),
    ("Edit", {}, False),
    ("Write", {"file_path": "/anywhere/hooks/credential_check.py"}, True),
    ("MultiEdit", {"file_path": "/repo/src/guard/hooks/protected_files.py"}, True),
    ("NotebookEdit", {"notebook_path": "/repo/src/guard/registry.py"}, True),
    ("Edit", {"file_path": "/repo/.claude/subagent-scope.json"}, True),
    ("Bash", {"command": "cat hooks/_hook_utils.py"}, False),
    ("Bash", {"command": "ls /tmp"}, False),
    ("Bash", {"command": "echo x > /repo/src/guard/hooks/credential_check.py"}, True),
    ("Bash", {"command": "echo x | tee /repo/src/guard/registry.py"}, True),
    ("Bash", {"command": "cp /tmp/x.py /repo/src/guard/hooks/bash_command_validator.py"}, True),
    ("Bash", {"command": "echo {} > /repo/.claude/subagent-scope.json"}, True),
    ("Bash", {"command": f"truncate -s 0 {_GUARD}/hooks/bash_command_validator.py"}, True),
    ("Bash", {"command": f"truncate {_GUARD}/registry.py -s 0"}, True),
    ("Bash", {"command": "truncate -s 0 /tmp/scratch.txt"}, False),
    ("Bash", {"command": f"patch {_GUARD}/hooks/bash_command_validator.py < /tmp/p.patch"}, True),
    ("Bash", {"command": f"patch -p1 {_GUARD}/_utils.py < /tmp/p.patch"}, True),
    ("Bash", {"command": "patch /tmp/foo.txt < /tmp/p.patch"}, False),
    ("Bash", {"command": f"tar -xf /tmp/x.tar -C {_GUARD}/hooks/"}, True),
    ("Bash", {"command": f"tar xzf /tmp/x.tar.gz --directory={_GUARD}"}, True),
    ("Bash", {"command": "tar -xf /tmp/x.tar -C /tmp/extract"}, False),
    # ``tar c`` reads, it doesn't extract.
    ("Bash", {"command": f"tar -cf /tmp/x.tar -C {_GUARD}/hooks/ ."}, False),
    # A quoted operator is an operand, not a command boundary.
    ("Bash", {"command": f"echo x | tee ';' {_GUARD}/_utils.py"}, True),
    ("Bash", {"command": f"echo x | tee '&&' {_GUARD}/_utils.py"}, True),
    ("Bash", {"command": f"sed -i s/a/b/ ';' {_GUARD}/_utils.py"}, True),
    ("Bash", {"command": f"find /x -exec true {{}} \\; -fprint {_GUARD}/_utils.py"}, True),
    # Redirect spellings that aren't a bare ``>``.
    ("Bash", {"command": f"echo x >| {_GUARD}/_utils.py"}, True),
    ("Bash", {"command": f"echo x &> {_GUARD}/_utils.py"}, True),
    ("Bash", {"command": f"echo x 2>{_GUARD}/_utils.py"}, True),
    # Unspaced operators still end the in-place editor's operands.
    ("Bash", {"command": f"sed -i s/a/b/ notes.txt;cat {_GUARD}/_utils.py"}, False),
    ("Bash", {"command": f"sed -i s/a/b/ notes.txt&&cat {_GUARD}/_utils.py"}, False),
    # Interpreter bodies: write idioms count, a plain read doesn't.
    ("Bash", {"command": f"python3 -c \"print(1, file=open('{_GUARD}/_utils.py', 'a'))\""}, True),
    ("Bash", {"command": f'php -r \'file_put_contents("{_GUARD}/_utils.py", "x");\''}, True),
    (
        "Bash",
        {"command": f'node -e \'require("fs").cpSync("/tmp/x", "{_GUARD}/_utils.py")\''},
        True,
    ),
    ("Bash", {"command": f'node -e \'require("fs").rmSync("{_GUARD}/_utils.py")\''}, True),
    ("Bash", {"command": f"ruby -e 'File.delete(\"{_GUARD}/_utils.py\")'"}, True),
    ("Bash", {"command": f'perl -e \'open(F, "+<", "{_GUARD}/_utils.py"); print F 1\''}, True),
    ("Bash", {"command": f"python3 -c \"print(open('{_GUARD}/_utils.py').read())\""}, False),
    # Only file-writing tools and Bash are scanned; a question or todo that
    # merely names a guard file is how the agent tells the user.
    ("AskUserQuestion", {"question": f"May I edit {_GUARD}/_utils.py?"}, False),
    ("TodoWrite", {"todos": [{"content": f"edit {_GUARD}/_utils.py"}]}, False),
    # The agent can't reconfigure guard through its CLI either.
    ("Bash", {"command": "guard allowlist disable-rule guard.protected_files"}, True),
    (
        "Bash",
        {"command": "uv run guard allowlist allow-command --rule x --command y --reason z"},
        True,
    ),
    ("Bash", {"command": "guard mode off --global"}, True),
    ("Bash", {"command": "guard allowlist list"}, False),
    ("Bash", {"command": "guard mode"}, False),
]


@pytest.mark.parametrize(("tool_name", "tool_input", "denied"), _WRITE_SHAPES)
def test_write_shapes(tool_name: str, tool_input: dict[str, Any], *, denied: bool) -> None:
    result = decide(tool_name, tool_input)
    if denied:
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert result is None
