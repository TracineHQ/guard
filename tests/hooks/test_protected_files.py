# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for protected_files hook.

Hook-level behavior (guard mode, exit code, logging) lives in
``tests/test_steer_not_ask.py``; this file covers path matching and the
write-shape table through the pure ``decide()``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from guard.hooks import protected_files as pf
from guard.hooks.protected_files import LOCKDOWN_PATTERNS, PROTECTED_PATTERNS, decide, is_protected
from tests._helpers import LIVE_GUARD

_LOCKDOWN = pf._effective_patterns(mode="lockdown")  # noqa: SLF001 -- module-private pattern resolver
# The guard package these tests import: the live copy protected_files keys on.
_GUARD = str(LIVE_GUARD)
# The live-tree entry a path inside the package matches: ``src/`` for a
# source checkout, the package itself for a wheel install.
_LIVE = pf._LIVE_TREE[0]  # noqa: SLF001 -- module-private live tree
# A copy of guard's source somewhere else (a clone or worktree): ordinary code.
_COPY = "/Users/dev/develop/guard-wt/some-branch/src/guard"


class TestIsProtected:
    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            (f"{_GUARD}/hooks/bash_command_validator.py", _LIVE),
            (f"{_GUARD}/hooks/protected_files.py", _LIVE),
            (f"{_GUARD}/registry.py", _LIVE),
            (f"{_GUARD}/hooks/../_utils.py", _LIVE),
            # Everything the install runs, not just the policy modules.
            (f"{_GUARD}/cli.py", _LIVE),
            (f"{_GUARD}/allowlist.py", _LIVE),
            (f"{_GUARD}/_safe_io.py", _LIVE),
            (f"{_GUARD}/hooks/__init__.py", _LIVE),
            (f"{_GUARD}/hooks/_registry.py", _LIVE),
            (f"{_GUARD}/hooks/__pycache__/registry.cpython-313.pyc", _LIVE),
            (f"{_GUARD}/new_module.py", _LIVE),
            (_GUARD, _LIVE),
            (f"{_LIVE}/json.py", _LIVE),
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
            # Next to the install, not in it.
            f"{LIVE_GUARD.parents[1]}/notes.txt",
        ],
    )
    def test_no_match_by_default(self, path: str) -> None:
        assert is_protected(path) is None

    def test_live_tree_is_keyed_on_the_running_install(self) -> None:
        tree = pf._LIVE_TREE  # noqa: SLF001 -- module-private live tree
        assert LIVE_GUARD.resolve() == pf._LIVE_PACKAGE  # noqa: SLF001 -- module-private live package root
        assert all(entry in PROTECTED_PATTERNS for entry in tree)
        if pf._SOURCE_LAYOUT:  # noqa: SLF001 -- module-private layout flag
            root = LIVE_GUARD.parents[1]
            assert tree == (
                str(LIVE_GUARD.parent),
                str(root / "bin" / "run-hook"),
                str(root / "hooks" / "hooks.json"),
            )
            assert is_protected(str(root / "bin" / "run-hook")) == tree[1]
            assert is_protected(str(root / "hooks" / "hooks.json")) == tree[2]
        else:
            assert tree == (_GUARD,)

    def test_symlink_to_live_code_is_protected(self, tmp_path: Path) -> None:
        link = tmp_path / "link.py"
        link.symlink_to(LIVE_GUARD / "registry.py")
        assert is_protected(str(link)) == _LIVE

    def test_install_imported_through_a_symlink_keys_on_the_real_path(self, tmp_path: Path) -> None:
        link = tmp_path / "linked-src"
        link.symlink_to(LIVE_GUARD.parent, target_is_directory=True)
        probe = "from guard.hooks import protected_files as pf; print(pf._LIVE_PACKAGE)"
        env = {**os.environ, "PYTHONPATH": str(link)}
        out = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True, check=True, env=env
        )
        assert out.stdout.strip() == str(LIVE_GUARD.resolve())

    @pytest.mark.parametrize(
        ("directory", "denied"),
        [
            (_GUARD, True),
            (f"{_GUARD}/hooks", True),
            (str(LIVE_GUARD.parent), True),
            ("/", True),
            (_COPY, False),
            (f"{_COPY}/hooks", False),
            (f"{_GUARD}/hooks/__pycache__", True),
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
            if p in pf._LIVE_TREE:  # noqa: SLF001 -- module-private live tree
                continue
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
            (f"{_GUARD}/HOOKS/Protected_Files.py", _LIVE),
            # casefold, not lower: a long s is s, the st ligature is st.
            ("/repo/.claude/\u017fubagent-scope.json", ".claude/subagent-scope.json"),
            ("/Users/x/.claude/guard/allowli\ufb06.json", ".claude/guard/allowlist.json"),
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
    # A path in an eval body resolves like any other: a copy is ordinary code.
    # (One under a root that doesn't exist reads as a fragment code could
    # join onto anything, so the copy sits under /tmp.)
    ("Bash", {"command": "python3 -c \"open('/tmp/guard-copy/src/guard/_utils.py', 'w')\""}, False),
    ("Bash", {"command": "python3 -c \"open('/nope/src/guard/_utils.py', 'w')\""}, True),
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


# Paths around the live package. In a source checkout ``_PARENT`` is ``src``
# and ``_ROOT`` the checkout; for a wheel they are site-packages and its parent.
_PARENT = str(LIVE_GUARD.parent)
_ROOT = str(LIVE_GUARD.parents[1])
_PKG = LIVE_GUARD.name
_REL = f"{LIVE_GUARD.parent.name}/{_PKG}"

# Each row: a Bash command and whether protected_files denies it.
_LIVE_TREE_SHAPES: list[tuple[str, bool]] = [
    # Every file in the install, and the directory itself as a copy target.
    (f"cp /tmp/x/_utils.py {_GUARD}/", True),
    (f"cp /tmp/x.py {_GUARD}/hooks/_registry.py", True),
    (f"touch {_LIVE}/json.py", True),
    (f"cp -r /tmp/{_PKG} {_PARENT}/", True),
    (f"cp -t {_GUARD} /tmp/x.py", True),
    # Moving, removing or hard-linking live files.
    (f"mv {_GUARD}/_utils.py /tmp/u.py", True),
    (f"rm {_GUARD}/_utils.py", True),
    (f"sudo rm -f {_GUARD}/_utils.py", True),
    (f"git rm -q {_GUARD}/_utils.py", True),
    (f"rm -rf {_ROOT}", True),
    (f"find {_GUARD} -name '*.pyc' -delete", True),
    (f"ln {_GUARD}/_utils.py /tmp/h.py", True),
    (f"cp -l {_GUARD}/_utils.py /tmp/h.py", True),
    # Reading from the install, or naming it as data, is fine.
    (f"cp {_GUARD}/_utils.py /tmp/x.py", False),
    (f"cat {_GUARD}/_utils.py > /tmp/x.py", False),
    (f"ln -s {_GUARD}/_utils.py /nonexistent-guard-test/link.py", False),
    (f"grep -rn rm {_GUARD}", False),
    (f"git -C {_ROOT} pull --ff-only", False),
    ("rm -rf /tmp/build", False),
    ("cd /tmp && mv a b", False),
    # Quoting, redirects and wrappers don't hide the target.
    (f'echo x > "{_GUARD}/_utils.py"', True),
    (f"cp /tmp/x {_GUARD}/_utils.py 2>/dev/null", True),
    (f"bash -c 'cp /tmp/x {_GUARD}/_utils.py'", True),
    (f'sh -lc "echo x > {_GUARD}/_utils.py"', True),
    (f"eval 'cp /tmp/x {_GUARD}/_utils.py'", True),
    (f'echo "$(cp /tmp/x {_GUARD}/_utils.py)"', True),
    (f"echo `rm {_GUARD}/_utils.py`", True),
    (f"(cd {_GUARD} && sed -i '' s/a/b/ _utils.py)", True),
    (f"cd {_GUARD}; python3 -c \"open('_utils.py', 'w')\"", True),
    # Brace lists and globs expand before the check.
    (f"cp /tmp/x {_ROOT}/{{{LIVE_GUARD.parent.name},nope}}/{_PKG}/_utils.py", True),
    (f"cp /tmp/x {_ROOT}/{LIVE_GUARD.parent.name[:-1]}?/{_PKG}/_utils.py", True),
    # A command guard can't read for sure denies on any trust-root path in it.
    (f'echo "unterminated\ncp /tmp/x {_GUARD}/_utils.py', True),
    (f'cp /tmp/x {_GUARD}/_utils.py\necho "unterminated', True),
    ('echo "unterminated', False),
    (f"cat <<EOF\nrm -rf {_GUARD}", True),
    # Comments, escapes, $'...' and line continuations read as bash reads them.
    (f"echo ok # it's {_GUARD}/_utils.py", False),
    (f"echo ok # it's\ncp /tmp/x {_GUARD}/_utils.py", True),
    (f"echo \\ #; cp /tmp/x {_GUARD}/_utils.py", True),
    (f"echo $(true)#; cp /tmp/x {_GUARD}/_utils.py", True),
    (f"echo $'\\''\ncp /tmp/x {_GUARD}/_utils.py\necho '", True),
    ("cp /tmp/x $'" + f"{_GUARD}/_utils.py".replace("/", "\\057") + "'", True),
    (f"cp /tmp/x {_GUARD}/_ut\\\nils.py", True),
    # A heredoc is data unless a shell or an interpreter reads it.
    (f"cat > /tmp/notes.md <<'EOF'\nrm -rf {_GUARD}\nEOF", False),
    (f"cat <<'EOF'\nit's\nEOF\ncp /tmp/x {_GUARD}/_utils.py", True),
    (f'cat <<E"OF"\nhi\nEOF\ncp /tmp/x {_GUARD}/_utils.py', True),
    (f"cat <<EOF\nit's $(cp /tmp/x {_GUARD}/_utils.py)\nEOF", True),
    (f"cat <<'EOF'\nit's $(cp /tmp/x {_GUARD}/_utils.py)\nEOF", False),
    (f"bash <<'EOF'\ncp /tmp/x {_GUARD}/_utils.py\nEOF", True),
    (f"python3 - <<'EOF'\nopen('{_GUARD}/_utils.py', 'w')\nEOF", True),
    (f"python3 - <<'EOF'\nprint(open('{_GUARD}/_utils.py').read())\nEOF", False),
    ("cat > /tmp/t.py <<'EOF'\nlink = tmp_path / 'x'\nos.link(src, link)\nEOF", False),
    (f"gh pr create --body \"$(cat <<'EOF'\nIt's 1) done in {_GUARD}\nEOF\n)\"", False),
    # A here-string is not a heredoc; <( and >( are text in double quotes.
    (f'python3 {_ROOT}/bin/run-hook protected_files <<<"$P" | head -c 160', False),
    (f'grep -n "x\\|<(\\|>(" {_GUARD}/_utils.py', False),
    # find runs a write only through -exec with a writer, or -delete.
    (f"find {_GUARD} -name '*.py' -exec wc -l {{}} +", False),
    (f"find {_GUARD} -name '*.py' -exec sed -i '' s/a/b/ {{}} +", True),
    # Putting the install on sys.path reads it.
    (f"python3 -c \"import sys; sys.path.insert(0, '{_PARENT}')\"", False),
]


@pytest.mark.parametrize(("command", "denied"), _LIVE_TREE_SHAPES)
def test_live_tree_shapes(command: str, *, denied: bool) -> None:
    assert (decide("Bash", {"command": command}) is not None) is denied


# Targets whose leading part guard has to expand or can't know.
_UNRESOLVED_SHAPES: list[tuple[str, bool]] = [
    (f"sed -i '' s/a/b/ $HOME/{_REL}/_utils.py", True),
    (f"perl -pi -e s/a/b/ ~/{_REL}/hooks/protected_files.py", True),
    (f'cp /tmp/x "${{HOME}}/{_REL}/hooks/protected_files.py"', True),
    (f"echo x >> ~/{_REL}/_utils.py", True),
    (f"cd ~ && sed -i '' s/a/b/ {_REL}/_utils.py", True),
    (f"cd ~/{_REL} && sed -i '' s/a/b/ _utils.py", True),
    (f"pushd ~/{_REL} >/dev/null && touch x.py", True),
    ("cd ~ && echo x > notes.txt", False),
    # The unknown part could be any directory: the package-relative tail decides.
    (f"cp /tmp/x $GUARD_TEST_UNSET/{_PKG}/_utils.py", True),
    (f'cp /tmp/x "$(git rev-parse --show-toplevel)/{_REL}/_utils.py"', True),
    (f"cd \"$GUARD_TEST_UNSET\" && sed -i '' s/a/b/ {_PKG}/_utils.py", True),
    ("cd \"$GUARD_TEST_UNSET\" && sed -i '' s/a/b/ _utils.py", True),
    ("cp /tmp/x $GUARD_TEST_UNSET/.claude/guard/allowlist.json", True),
    ('cd "$GUARD_TEST_UNSET" && echo {} > allowlist.json', True),
    ("cp /tmp/x $GUARD_TEST_UNSET/out/report.txt", False),
    ('cd "$GUARD_TEST_UNSET" && echo x > notes.txt', False),
    # Names every package has don't place an unknown path in guard.
    ('rm -rf "$GUARD_TEST_UNSET/__pycache__"', False),
    ('cd "$GUARD_TEST_UNSET" && mv __pycache__ /tmp/old', False),
]


@pytest.mark.parametrize(("command", "denied"), _UNRESOLVED_SHAPES)
def test_unresolved_shapes(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, denied: bool
) -> None:
    monkeypatch.setenv("HOME", _ROOT)
    monkeypatch.delenv("GUARD_TEST_UNSET", raising=False)
    monkeypatch.chdir(tmp_path)
    assert (decide("Bash", {"command": command}) is not None) is denied


class TestInodes:
    """A hard link or a spelling the volume folds is the same file."""

    @pytest.fixture
    def fake_tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        live = tmp_path / "live" / "src"
        (live / "guard").mkdir(parents=True)
        (live / "guard" / "_utils.py").write_text("x", encoding="utf-8")
        monkeypatch.setattr(pf, "_LIVE_TREE", (str(live),))
        pf._inode_map.cache_clear()  # noqa: SLF001 -- module-private inode cache
        yield live
        pf._inode_map.cache_clear()  # noqa: SLF001 -- module-private inode cache

    def test_hard_link_to_a_live_file(self, fake_tree: Path, tmp_path: Path) -> None:
        link = tmp_path / "h.py"
        os.link(fake_tree / "guard" / "_utils.py", link)
        assert is_protected(str(link), (str(fake_tree),)) == str(fake_tree)

    def test_a_copy_is_not_a_link(self, fake_tree: Path, tmp_path: Path) -> None:
        copy = tmp_path / "c.py"
        copy.write_text("x", encoding="utf-8")
        assert is_protected(str(copy), (str(fake_tree),)) is None

    def test_folded_spelling(
        self, fake_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if not (tmp_path / "LIVE").exists():
            pytest.skip("case-sensitive volume")
        # Names compared as written: only the inode walk can see it.
        monkeypatch.setattr(pf, "_CASE_INSENSITIVE_FS", False)
        for spelled in ("\u017frc/guard/_utils.py", "SRC/guard/new.py", "src/GUARD"):
            path = str(fake_tree.parent / spelled)
            assert is_protected(path, (str(fake_tree),)) == str(fake_tree), spelled
        assert is_protected(str(tmp_path / "src" / "x.py"), (str(fake_tree),)) is None

    def test_rm_of_a_directory_above_the_tree(self, fake_tree: Path, tmp_path: Path) -> None:
        resolved = (tmp_path / "live").resolve()
        assert pf._live_entry(resolved, ancestors=True) == str(fake_tree)  # noqa: SLF001 -- module-private matcher
        assert pf._live_entry(resolved) is None  # noqa: SLF001 -- module-private matcher
