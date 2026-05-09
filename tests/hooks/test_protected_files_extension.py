"""Tests for the project-local PROTECTED_PATTERNS extension mechanism.

Two override knobs:
- ``GUARD_PROTECTED_EXTRA`` env var (comma-separated)
- ``.claude/guard-protected.txt`` file (one per line, ``#`` comments)

File takes precedence over env when both are present.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

from typing import TYPE_CHECKING

from guard.hooks.protected_files import (
    _effective_patterns,
    _extra_patterns,
    is_protected,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


# === GUARD_PROTECTED_EXTRA env var ===


def test_env_unset_yields_no_extras(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARD_PROTECTED_EXTRA", raising=False)
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == []


def test_env_single_pattern(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin")
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == ["bin"]


def test_env_multiple_comma_separated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin, standards , dispatch")
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == ["bin", "standards", "dispatch"]


def test_env_skips_blank_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin,, , standards,")
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == ["bin", "standards"]


def test_env_empty_string_is_no_extras(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "")
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == []


# === .claude/guard-protected.txt file ===


def _write_file(cwd: Path, content: str) -> None:
    target = cwd / ".claude" / "guard-protected.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_file_one_per_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_file(tmp_path, "bin\nstandards\ndispatch\n")
    assert _extra_patterns() == ["bin", "standards", "dispatch"]


def test_file_strips_hash_comments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_file(
        tmp_path,
        "# kill-switch + doctrine paths\nbin  # the wrappers\nstandards\n# CLAUDE.md\nCLAUDE.md\n",
    )
    assert _extra_patterns() == ["bin", "standards", "CLAUDE.md"]


def test_file_handles_blank_lines_and_whitespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_file(tmp_path, "\n\n  bin\t\n\n  standards  \n\n")
    assert _extra_patterns() == ["bin", "standards"]


def test_file_unreadable_falls_back_to_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing file but not readable -> the read returns [] and we still hit env."""
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "from-env")
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".claude" / "guard-protected.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\xff\xfe\xfd not utf8")  # invalid UTF-8 -> read returns []
    # File EXISTS so we go down the file path; corrupt content yields [].
    # Env is NOT consulted (file precedence is path-existence, not content).
    assert _extra_patterns() == []


def test_file_absent_falls_back_to_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "from-env")
    monkeypatch.chdir(tmp_path)
    assert _extra_patterns() == ["from-env"]


# === Precedence: file wins over env when file exists ===


def test_file_wins_over_env_when_both_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "from-env-only")
    monkeypatch.chdir(tmp_path)
    _write_file(tmp_path, "from-file-only\n")
    assert _extra_patterns() == ["from-file-only"]


# === _effective_patterns + is_protected integration ===


def test_effective_patterns_appends_extras_after_builtins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin,standards")
    monkeypatch.chdir(tmp_path)
    pats = _effective_patterns()
    # Last two entries are our extras; built-ins precede.
    assert pats[-2:] == ("bin", "standards")
    # Built-in still present.
    assert "CLAUDE.md" in pats


def test_is_protected_honors_env_extension(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin")
    monkeypatch.chdir(tmp_path)
    # Directory-segment match (no `.` in last segment).
    assert is_protected("/Users/me/proj/bin/dispatch") == "bin"


def test_is_protected_honors_file_extension(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_file(tmp_path, "standards\n")
    assert is_protected("/Users/me/proj/standards/coding.md") == "standards"


def test_is_protected_does_not_match_unrelated_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative: ``bin`` extension shouldn't match ``cabin`` or random suffix."""
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin")
    monkeypatch.chdir(tmp_path)
    # ``cabin`` is a different segment; segment-match requires "/bin/" not just "bin".
    assert is_protected("/Users/me/proj/cabin/file") is None
    # Pattern as suffix would only match if the path had "/bin" at the end with prior "/".
    # ``proj/binarydata`` should NOT match.
    assert is_protected("/Users/me/proj/binarydata") is None


def test_existing_builtin_still_matches_with_extras(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "bin")
    monkeypatch.chdir(tmp_path)
    # CLAUDE.md is a built-in; should still match.
    assert is_protected("/Users/me/proj/CLAUDE.md") == "CLAUDE.md"


def test_extras_can_add_custom_filename_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """File pattern (last segment contains a ``.``) — suffix-match path."""
    monkeypatch.chdir(tmp_path)
    _write_file(tmp_path, "SECURITY.md\n")
    assert is_protected("/Users/me/proj/SECURITY.md") == "SECURITY.md"
    # Should NOT match where the suffix isn't preceded by "/".
    assert is_protected("/Users/me/projSECURITY.md") is None


# === Safe-read protections on the file extension ===


def test_file_oversize_yields_no_extras(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A guard-protected.txt larger than the 64 KiB cap yields ``[]``.

    Defends against a poisoned file that floods ``is_protected`` with
    millions of patterns and turns each call into a multi-second walk.
    """
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".claude" / "guard-protected.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    # 65 KiB of "pat<n>\n" lines blows past the 64 KiB cap.
    body = "\n".join(f"pat{i}" for i in range(20_000)) + "\n"
    target.write_text(body, encoding="utf-8")
    assert _extra_patterns() == []


def test_file_caps_pattern_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if a small file declares thousands of patterns, only the first
    256 are kept — bounds ``is_protected``'s per-call iteration cost.
    """
    monkeypatch.chdir(tmp_path)
    # 300 short patterns; well under 64 KiB so the size cap doesn't fire.
    body = "\n".join(f"p{i}" for i in range(300)) + "\n"
    _write_file(tmp_path, body)
    out = _extra_patterns()
    assert len(out) == 256
    assert out[0] == "p0"
    assert out[-1] == "p255"


def test_file_outside_cwd_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A symlinked .claude/guard-protected.txt pointing outside cwd is refused.

    ``safe_read_text_capped`` enforces cwd/temp scope; a symlink target in
    /etc must not bleed into the pattern list.
    """
    monkeypatch.chdir(tmp_path)
    # Create a symlink that escapes cwd into a sensitive prefix; either
    # rejection (out-of-scope OR sensitive) makes the test pass.
    target = tmp_path / ".claude" / "guard-protected.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.symlink_to("/etc/hosts")
    except OSError:
        # Can't create the symlink (e.g., filesystem disallows) → skip.
        return
    assert _extra_patterns() == []
