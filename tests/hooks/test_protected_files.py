# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for protected_files hook.

Hook-level behavior (guard mode, exit code, logging) lives in
``tests/test_steer_not_ask.py``; this file covers path matching and the
write-shape table through the pure ``decide()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from guard.hooks import protected_files as pf
from guard.hooks.protected_files import LOCKDOWN_PATTERNS, PROTECTED_PATTERNS, decide, is_protected
from tests._helpers import LIVE_GUARD

if TYPE_CHECKING:
    from pathlib import Path

_LOCKDOWN = pf._effective_patterns(mode="lockdown")  # noqa: SLF001 -- module-private pattern resolver
# The guard package these tests import: the live copy protected_files keys on.
_GUARD = str(LIVE_GUARD)
# A copy of guard's source somewhere else (a clone or worktree): ordinary code.
_COPY = "/Users/dev/develop/guard-wt/some-branch/src/guard"


class TestIsProtected:
    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            (
                f"{_GUARD}/hooks/bash_command_validator.py",
                f"{_GUARD}/hooks/bash_command_validator.py",
            ),
            (f"{_GUARD}/hooks/protected_files.py", f"{_GUARD}/hooks/protected_files.py"),
            (f"{_GUARD}/registry.py", f"{_GUARD}/registry.py"),
            (f"{_GUARD}/hooks/../_utils.py", f"{_GUARD}/_utils.py"),
            ("/home/u/.claude/hooks/command_registry.py", ".claude/hooks/command_registry.py"),
            ("/Users/x/.claude/hooks/_hook_utils.py", ".claude/hooks/_hook_utils.py"),
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
            # Copies of guard's source are not the code that runs.
            f"{_COPY}/hooks/bash_command_validator.py",
            f"{_COPY}/registry.py",
            f"{_COPY}/_utils.py",
            "/some/repo/src/guard/hooks/protected_files.py",
            # Legacy hook names only count under .claude/hooks/.
            "/repo/hooks/command_registry.py",
            "/repo/src/guard/hooks/credential_check.py",
            # A live module that isn't policy code.
            f"{_GUARD}/cli.py",
        ],
    )
    def test_no_match_by_default(self, path: str) -> None:
        assert is_protected(path) is None

    def test_live_code_is_keyed_on_the_running_package(self) -> None:
        live = [p for p in PROTECTED_PATTERNS if p.startswith("/")]
        assert live
        assert all(p.startswith(str(pf._LIVE_PACKAGE) + "/") for p in live)  # noqa: SLF001 -- module-private live package root
        assert LIVE_GUARD.resolve() == pf._LIVE_PACKAGE  # noqa: SLF001 -- module-private live package root

    def test_symlink_to_live_code_is_protected(self, tmp_path: Path) -> None:
        link = tmp_path / "link.py"
        link.symlink_to(LIVE_GUARD / "registry.py")
        assert is_protected(str(link)) == f"{_GUARD}/registry.py"

    @pytest.mark.parametrize(
        ("directory", "denied"),
        [
            (_GUARD, True),
            (f"{_GUARD}/hooks", True),
            (str(LIVE_GUARD.parent), True),
            ("/", True),
            (_COPY, False),
            (f"{_COPY}/hooks", False),
            (f"{_GUARD}/hooks/__pycache__", False),
        ],
    )
    def test_parent_dir_of_live_code(self, directory: str, *, denied: bool) -> None:
        matched = pf.is_protected_parent_dir(directory)
        assert (matched is not None) is denied

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
            (f"{_GUARD}/HOOKS/Protected_Files.py", f"{_GUARD}/hooks/protected_files.py"),
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


# Each row: tool name, tool input, and whether protected_files denies it.
_WRITE_SHAPES: list[tuple[str, dict[str, Any], bool]] = [
    ("Edit", {"file_path": "/repo/src/myproject/main.py"}, False),
    ("Edit", {"file_path": f"{_GUARD}/hooks/bash_command_validator.py"}, True),
    ("Edit", {}, False),
    ("Write", {"file_path": "/Users/x/.claude/hooks/credential_check.py"}, True),
    ("MultiEdit", {"file_path": f"{_GUARD}/hooks/protected_files.py"}, True),
    ("NotebookEdit", {"notebook_path": f"{_GUARD}/registry.py"}, True),
    # A worktree or clone of guard's source is editable.
    ("Edit", {"file_path": f"{_COPY}/hooks/bash_command_validator.py"}, False),
    ("Write", {"file_path": f"{_COPY}/hooks/protected_files.py"}, False),
    ("Write", {"file_path": "/anywhere/hooks/credential_check.py"}, False),
    ("Bash", {"command": f"echo x > {_COPY}/registry.py"}, False),
    ("Bash", {"command": f"cp /tmp/x.py {_COPY}/hooks/bash_command_validator.py"}, False),
    ("Bash", {"command": f"sed -i '' s/a/b/ {_COPY}/_utils.py"}, False),
    ("Bash", {"command": f"tar -xf /tmp/x.tar -C {_COPY}/hooks/"}, False),
    ("Edit", {"file_path": "/repo/.claude/subagent-scope.json"}, True),
    ("Bash", {"command": "cat hooks/_hook_utils.py"}, False),
    ("Bash", {"command": "ls /tmp"}, False),
    ("Bash", {"command": f"echo x > {_GUARD}/hooks/credential_check.py"}, True),
    ("Bash", {"command": f"echo x | tee {_GUARD}/registry.py"}, True),
    ("Bash", {"command": f"cp /tmp/x.py {_GUARD}/hooks/bash_command_validator.py"}, True),
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
    # An eval body's path can't be resolved, so naming guard's code there
    # with write intent denies even for a copy.
    ("Bash", {"command": f"python3 -c \"open('{_COPY}/_utils.py', 'w')\""}, True),
    # Only file-writing tools and Bash are scanned; a question or todo that
    # merely names a guard file is how the agent tells the user.
    ("AskUserQuestion", {"question": f"May I edit {_GUARD}/_utils.py?"}, False),
    ("TodoWrite", {"todos": [{"content": f"edit {_GUARD}/_utils.py"}]}, False),
    # The agent can't reconfigure guard through its CLI either.
    ("Bash", {"command": "guard allowlist disable-rule guard.protected_files"}, True),
    # Retired verb, but an older guard on PATH still writes the file with it.
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
