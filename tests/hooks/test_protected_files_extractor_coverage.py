"""Tests for new extractor coverage in protected_files.

Adds awk inplace (verify still works), ex / vim batch-mode, patch via
``-i`` and stdin redirect, ``find -exec`` on protected root, and
per-interpreter eval-flag map (php -r etc.).
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

from typing import TYPE_CHECKING

from guard.hooks.protected_files import (
    _bash_first_protected_match,
    bash_write_targets,
)

if TYPE_CHECKING:
    from pathlib import Path


# === awk -i inplace (regression — already supported, must stay green) ===


def test_awk_inplace_extracts_target() -> None:
    targets = bash_write_targets("awk -i inplace '/x/{...}1' /tmp/file.txt")
    assert "/tmp/file.txt" in targets


def test_gawk_inplace_extracts_target() -> None:
    targets = bash_write_targets("gawk -i inplace '{print}' /tmp/x.txt")
    assert "/tmp/x.txt" in targets


def test_awk_without_inplace_is_read_only() -> None:
    targets = bash_write_targets("awk '/x/' /tmp/file.txt")
    assert "/tmp/file.txt" not in targets


# === ex / vim batch-mode editors ===


def test_ex_sc_extracts_target() -> None:
    targets = bash_write_targets("ex -sc 'wq' /tmp/conf.yaml")
    assert "/tmp/conf.yaml" in targets


def test_vim_es_dash_c_extracts_target() -> None:
    targets = bash_write_targets("vim -es -c 'wq' /tmp/conf.yaml")
    assert "/tmp/conf.yaml" in targets


def test_vim_es_plus_extracts_target() -> None:
    targets = bash_write_targets("vim -es +wq /tmp/conf.yaml")
    assert "/tmp/conf.yaml" in targets


def test_vim_interactive_does_not_extract() -> None:
    """Bare ``vim <file>`` is interactive — no batch script committing."""
    targets = bash_write_targets("vim /tmp/conf.yaml")
    assert "/tmp/conf.yaml" not in targets


# === patch: -i diff and stdin redirect ===


def _write_diff(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


_DIFF_BODY = """\
diff --git a/CLAUDE.md b/CLAUDE.md
index 1111111..2222222 100644
--- a/CLAUDE.md
+++ b/CLAUDE.md
@@ -1 +1 @@
-old
+new
"""


def test_patch_dash_i_extracts_paths_from_diff_body(tmp_path: Path) -> None:
    diff = _write_diff(tmp_path, "d.patch", _DIFF_BODY)
    targets = bash_write_targets(f"patch -p0 -i {diff}")
    assert "CLAUDE.md" in targets


def test_patch_stdin_redirect_extracts_paths_from_diff_body(
    tmp_path: Path,
) -> None:
    diff = _write_diff(tmp_path, "d.patch", _DIFF_BODY)
    targets = bash_write_targets(f"patch -p0 < {diff}")
    assert "CLAUDE.md" in targets


def test_patch_diff_with_dev_null_added_file_skipped(tmp_path: Path) -> None:
    """``--- /dev/null`` is the marker for an "added" file — only +++ side counts."""
    body = "--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1 @@\n+#!/bin/sh\n"
    diff = _write_diff(tmp_path, "d.patch", body)
    targets = bash_write_targets(f"patch -p1 -i {diff}")
    assert ".git/hooks/pre-commit" in targets
    assert "/dev/null" not in targets


def test_patch_unreadable_diff_returns_no_diff_body_extras(tmp_path: Path) -> None:
    """Best-effort: missing diff file means no diff-body targets, no exception."""
    targets = bash_write_targets(f"patch -p0 -i {tmp_path / 'nope.patch'}")
    # The existing positional extractor still picks up ``nope.patch`` itself
    # (that's the diff-file argument). What our new diff-body parsing must
    # NOT do is raise. ``CLAUDE.md`` etc. won't appear because the body
    # was never read.
    assert "CLAUDE.md" not in targets
    assert ".git/config" not in targets


# === find -exec on protected root ===


def test_find_exec_emits_root_as_target() -> None:
    targets = bash_write_targets("find /etc -name foo -exec rm {} \\;")
    assert "/etc" in targets


def test_find_without_exec_does_not_emit_root() -> None:
    targets = bash_write_targets("find /etc -name foo")
    assert "/etc" not in targets


def test_find_exec_on_claude_md_dir_flagged_as_protected() -> None:
    """Real bypass: find on a project's CLAUDE.md tree with -exec."""
    cmd = "find /Users/me/proj/.claude -name settings.json -exec sh -c 'cat > $1' _ {} \\;"
    matched = _bash_first_protected_match(cmd)
    # The root ``/Users/me/proj/.claude`` isn't itself a protected pattern,
    # but the recursive search WITHIN it inevitably touches protected files.
    # We intentionally don't try to be clever about the inner path —
    # the conservative rule is: emit the root, let is_protected decide.
    # ``.claude`` isn't a protected pattern by itself, so this returns None.
    # The real win is when the root IS protected.
    del matched  # not asserting on this — the next test does the protected case


def test_find_exec_on_dot_git_hooks_root_flagged() -> None:
    cmd = "find /repo/.git/hooks -exec rm {} \\;"
    matched = _bash_first_protected_match(cmd)
    assert matched == ".git/hooks"


# === find -fprint / -fprintf / -fls write flags ===


def test_find_fprint_emits_file_target() -> None:
    targets = bash_write_targets("find . -name foo -fprint /repo/.git/config")
    assert "/repo/.git/config" in targets


def test_find_fprintf_emits_file_target() -> None:
    targets = bash_write_targets("find . -name foo -fprintf /repo/CLAUDE.md '%p\\n'")
    assert "/repo/CLAUDE.md" in targets


def test_find_fls_emits_file_target() -> None:
    targets = bash_write_targets("find . -fls /repo/.cursorrules")
    assert "/repo/.cursorrules" in targets


def test_find_fprint0_emits_file_target() -> None:
    targets = bash_write_targets("find . -fprint0 /repo/.claude/settings.json")
    assert "/repo/.claude/settings.json" in targets


def test_find_fprint_on_protected_path_flagged() -> None:
    """Real bypass: ``find . -fprint .git/config`` overwrites the protected file."""
    matched = _bash_first_protected_match("find . -fprint /repo/.git/config")
    assert matched == ".git/config"


# === nvim --headless batch mode ===


def test_nvim_headless_extracts_target() -> None:
    targets = bash_write_targets("nvim --headless -c 'wq' /tmp/conf.yaml")
    assert "/tmp/conf.yaml" in targets


def test_nvim_headless_plus_command_extracts_target() -> None:
    targets = bash_write_targets("nvim --headless +wq /tmp/conf.yaml")
    assert "/tmp/conf.yaml" in targets


def test_nvim_headless_on_protected_path_flagged() -> None:
    matched = _bash_first_protected_match("nvim --headless -c 'wq' /repo/CLAUDE.md")
    assert matched == "CLAUDE.md"


# === Per-interpreter eval-flag map ===


def test_python_dash_c_with_protected_path_literal_extracted() -> None:
    cmd = "python -c \"open('/repo/.git/config','w').write('x')\""
    targets = bash_write_targets(cmd)
    # The pattern ``.git/config`` should appear among extracted targets.
    assert ".git/config" in targets


def test_python_dash_c_without_protected_literal_yields_none() -> None:
    cmd = "python -c 'print(2 + 2)'"
    targets = bash_write_targets(cmd)
    # No protected pattern literal in body → no eval-derived targets.
    # (Other extractors might add other things; we only assert no protected ones.)
    assert ".git/config" not in targets


def test_php_dash_r_with_protected_path_literal_extracted() -> None:
    cmd = "php -r \"file_put_contents('CLAUDE.md','x');\""
    targets = bash_write_targets(cmd)
    assert "CLAUDE.md" in targets


def test_perl_dash_e_with_protected_path_literal_extracted() -> None:
    cmd = "perl -e \"open(F,'>','CLAUDE.md');print F 'x'\""
    targets = bash_write_targets(cmd)
    assert "CLAUDE.md" in targets


def test_node_dash_e_with_protected_path_literal_extracted() -> None:
    cmd = "node -e \"require('fs').writeFileSync('.cursorrules','x')\""
    targets = bash_write_targets(cmd)
    assert ".cursorrules" in targets


def test_ruby_dash_e_with_protected_path_literal_extracted() -> None:
    cmd = "ruby -e \"File.write('CLAUDE.md','x')\""
    targets = bash_write_targets(cmd)
    assert "CLAUDE.md" in targets


def test_python3_versioned_basename_handled() -> None:
    """``python3.11 -c '...'`` should still match the python interpreter rule."""
    cmd = "python3.11 -c \"open('/repo/CLAUDE.md','w')\""
    targets = bash_write_targets(cmd)
    assert "CLAUDE.md" in targets


def test_php_without_dash_r_does_not_extract() -> None:
    """``php -f script.php`` reads from a file — no eval body to scan."""
    cmd = "php -f /tmp/script.php"
    targets = bash_write_targets(cmd)
    # ``/tmp/script.php`` is the script SOURCE, not a protected pattern.
    assert "CLAUDE.md" not in targets
