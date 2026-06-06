"""Tests for ``guard.allowlist`` — load + merge + match semantics."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def isolated_homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Return ``(global_dir, project_cwd)`` — both clean, no existing allowlists.

    Points ``GUARD_HOME`` at the temp global dir via env so the module-level
    constant resolves there without re-importing.
    """
    global_dir = tmp_path / "global" / ".claude" / "guard"
    project_cwd = tmp_path / "project"
    project_cwd.mkdir(parents=True)
    monkeypatch.setenv("GUARD_DATA_DIR", str(global_dir))
    # Re-import to pick up the env var.
    import importlib

    import guard._utils
    import guard.allowlist

    importlib.reload(guard._utils)  # noqa: SLF001 -- need to re-read GUARD_HOME after env override
    importlib.reload(guard.allowlist)
    return global_dir, project_cwd


def test_load_no_files(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert al.allow_commands == ()
    assert al.sources == ()


def test_load_project_only(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "disable_rules": ["bash.disk_destruction"],
            "allow_commands": [
                {
                    "rule": "bash.aws_s3_destruction",
                    "command": "aws s3 rm s3://test-bucket/cleanup --recursive",
                    "reason": "nightly cleanup job allowlist for test-bucket",
                },
            ],
        },
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"bash.disk_destruction"}
    assert len(al.allow_commands) == 1
    assert al.allow_commands[0].rule == "bash.aws_s3_destruction"
    assert al.allow_commands[0].source == "project"


def test_load_global_only(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(
        gdir / "allowlist.json",
        {"disable_rules": ["bash.npx_remote"]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"bash.npx_remote"}


def test_merge_unions_disable_rules(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": ["a", "b"]})
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"disable_rules": ["b", "c"]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"a", "b", "c"}


def test_merge_concatenates_allow_commands_project_first(
    isolated_homes: tuple[Path, Path],
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(
        gdir / "allowlist.json",
        {
            "allow_commands": [
                {"rule": "r", "command": "global-cmd", "reason": "global"},
            ]
        },
    )
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "allow_commands": [
                {"rule": "r", "command": "project-cmd", "reason": "project"},
            ]
        },
    )
    al = load_allowlist(cwd=cwd)
    sources_in_order = [e.source for e in al.allow_commands]
    assert sources_in_order == ["project", "global"]


def test_is_rule_disabled(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"disable_rules": ["bash.iac_destruction"]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.is_rule_disabled("bash.iac_destruction") is True
    assert al.is_rule_disabled("bash.something_else") is False


def test_find_command_exact_match(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "bash.disk_destruction",
                    "command": "dd if=/dev/zero of=/tmp/bench bs=1M count=1",
                    "reason": "perf bench fixture",
                },
            ]
        },
    )
    al = load_allowlist(cwd=cwd)
    e = al.find_command(
        "bash.disk_destruction",
        "dd if=/dev/zero of=/tmp/bench bs=1M count=1",
    )
    assert e is not None
    assert e.reason == "perf bench fixture"


def test_find_command_strips_whitespace(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"allow_commands": [{"rule": "r", "command": "ls -la", "reason": "ok"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.find_command("r", "  ls -la  ") is not None


def test_find_command_rule_must_match(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"allow_commands": [{"rule": "rule.a", "command": "x", "reason": "y"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.find_command("rule.b", "x") is None


def test_find_command_no_substring_match(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"allow_commands": [{"rule": "r", "command": "ls -la", "reason": "ok"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.find_command("r", "ls -la /tmp") is None


def test_malformed_json_emits_warning_and_skips(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    p = cwd / ".claude" / "guard" / "allowlist.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not valid json", encoding="utf-8")
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    err = capsys.readouterr().err
    assert "invalid JSON" in err


def test_top_level_not_object_skipped(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    p = cwd / ".claude" / "guard" / "allowlist.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("[]", encoding="utf-8")
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert "top-level must be an object" in capsys.readouterr().err


def test_disable_rules_wrong_type_warns(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(cwd / ".claude" / "guard" / "allowlist.json", {"disable_rules": "not a list"})
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert "must be a list" in capsys.readouterr().err


def test_allow_commands_wrong_type_warns(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Parallel coverage to disable_rules: a non-list ``allow_commands``
    must warn and skip rather than crash."""
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(cwd / ".claude" / "guard" / "allowlist.json", {"allow_commands": "not a list"})
    al = load_allowlist(cwd=cwd)
    assert al.allow_commands == ()
    assert "'allow_commands' must be a list of objects" in capsys.readouterr().err


def test_allow_commands_missing_field_skips_entry(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "allow_commands": [
                {"rule": "r", "command": "x"},  # missing reason
                {"rule": "r", "command": "y", "reason": "z"},
            ]
        },
    )
    al = load_allowlist(cwd=cwd)
    assert len(al.allow_commands) == 1
    assert al.allow_commands[0].command == "y"
    assert "missing 'reason'" in capsys.readouterr().err


def test_disable_rules_skips_non_string_entries(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"disable_rules": ["good.rule", 42, None, "another.rule"]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"good.rule", "another.rule"}


def test_sources_lists_present_files_only(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": ["x"]})
    al = load_allowlist(cwd=cwd)
    assert len(al.sources) == 1
    assert al.sources[0].name == "allowlist.json"


def test_mutation_preserves_mode_field(isolated_homes: tuple[Path, Path]) -> None:
    """Adding/removing rules or commands must not strip a top-level ``mode`` field.

    Regression: an earlier version of ``_read_raw`` normalised the doc to
    only ``disable_rules`` and ``allow_commands``; calling
    ``add_disable_rule`` on a file that had ``"mode": "shadow"`` set would
    silently rewrite it without ``mode``, dropping the operator's
    configured posture.
    """
    from guard.allowlist import (
        add_allow_command,
        add_disable_rule,
        load_allowlist,
        remove_allow_command,
        remove_disable_rule,
        set_mode,
    )

    _, cwd = isolated_homes
    project_path = cwd / ".claude" / "guard" / "allowlist.json"

    set_mode("shadow", scope="project", cwd=cwd)
    assert json.loads(project_path.read_text())["mode"] == "shadow"

    add_disable_rule("bash.disk_destruction", scope="project", cwd=cwd)
    assert json.loads(project_path.read_text())["mode"] == "shadow"

    add_allow_command(
        rule="bash.disk_destruction",
        command="dd if=/dev/zero of=/tmp/x bs=1 count=1",
        reason="benign smoke test",
        scope="project",
        cwd=cwd,
    )
    assert json.loads(project_path.read_text())["mode"] == "shadow"

    remove_disable_rule("bash.disk_destruction", scope="project", cwd=cwd)
    remove_allow_command(
        rule="bash.disk_destruction",
        command="dd if=/dev/zero of=/tmp/x bs=1 count=1",
        scope="project",
        cwd=cwd,
    )
    assert json.loads(project_path.read_text())["mode"] == "shadow"
    assert load_allowlist(cwd=cwd).mode == "shadow"


# === trusted_scripts (content-pinned interpreter-exec override) ===

import hashlib


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_load_trusted_scripts_project(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    sha = _sha256_text("print('hi')\n")
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "trusted_scripts": [
                {
                    "path": "/repo/scripts/scan.py",
                    "sha256": sha,
                    "reason": "vetted voice-scan helper",
                }
            ]
        },
    )
    al = load_allowlist(cwd=cwd)
    assert len(al.trusted_scripts) == 1
    entry = al.trusted_scripts[0]
    assert entry.path == "/repo/scripts/scan.py"
    assert entry.sha256 == sha
    assert entry.reason == "vetted voice-scan helper"
    assert entry.source == "project"


def test_find_trusted_script_requires_path_and_sha(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    sha = _sha256_text("payload\n")
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"trusted_scripts": [{"path": "/repo/x.py", "sha256": sha, "reason": "ok"}]},
    )
    al = load_allowlist(cwd=cwd)
    # Exact path + exact sha → match.
    assert al.find_trusted_script("/repo/x.py", sha) is not None
    # Right path, wrong sha (file was edited) → no match.
    assert al.find_trusted_script("/repo/x.py", _sha256_text("evil\n")) is None
    # Right sha, wrong path → no match (trust is scoped to the file location).
    assert al.find_trusted_script("/repo/other.py", sha) is None


def test_find_trusted_script_sha_case_insensitive(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    sha = _sha256_text("data\n")
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"trusted_scripts": [{"path": "/repo/x.py", "sha256": sha.upper(), "reason": "ok"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.find_trusted_script("/repo/x.py", sha) is not None


def test_trusted_scripts_merge_project_and_global(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    sha_g = _sha256_text("g\n")
    sha_p = _sha256_text("p\n")
    _write(
        gdir / "allowlist.json",
        {"trusted_scripts": [{"path": "/g.py", "sha256": sha_g, "reason": "global"}]},
    )
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"trusted_scripts": [{"path": "/p.py", "sha256": sha_p, "reason": "project"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert [e.source for e in al.trusted_scripts] == ["project", "global"]
    assert al.find_trusted_script("/p.py", sha_p) is not None
    assert al.find_trusted_script("/g.py", sha_g) is not None


def test_trusted_scripts_wrong_type_warns(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(cwd / ".claude" / "guard" / "allowlist.json", {"trusted_scripts": "nope"})
    al = load_allowlist(cwd=cwd)
    assert al.trusted_scripts == ()
    assert "'trusted_scripts' must be a list" in capsys.readouterr().err


def test_trusted_scripts_missing_field_skips_entry(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    good = _sha256_text("good\n")
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {
            "trusted_scripts": [
                {"path": "/a.py", "sha256": good},  # missing reason
                {"path": "/b.py", "sha256": good, "reason": "kept"},
            ]
        },
    )
    al = load_allowlist(cwd=cwd)
    assert len(al.trusted_scripts) == 1
    assert al.trusted_scripts[0].path == "/b.py"
    assert "missing 'reason'" in capsys.readouterr().err


def test_trusted_scripts_bad_sha_skips_entry(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(
        cwd / ".claude" / "guard" / "allowlist.json",
        {"trusted_scripts": [{"path": "/a.py", "sha256": "deadbeef", "reason": "too short"}]},
    )
    al = load_allowlist(cwd=cwd)
    assert al.trusted_scripts == ()
    assert "sha256" in capsys.readouterr().err


def test_add_trusted_script_idempotent_and_preserves_mode(
    isolated_homes: tuple[Path, Path],
) -> None:
    from guard.allowlist import add_trusted_script, load_allowlist, set_mode

    _, cwd = isolated_homes
    project_path = cwd / ".claude" / "guard" / "allowlist.json"
    sha = _sha256_text("vetted\n")

    set_mode("shadow", scope="project", cwd=cwd)
    assert (
        add_trusted_script(path="/repo/x.py", sha256=sha, reason="vetted", scope="project", cwd=cwd)
        is True
    )
    # Second add of the same (path, sha) is a no-op.
    assert (
        add_trusted_script(path="/repo/x.py", sha256=sha, reason="again", scope="project", cwd=cwd)
        is False
    )
    al = load_allowlist(cwd=cwd)
    assert al.find_trusted_script("/repo/x.py", sha) is not None
    # The mutation must not strip the operator's mode.
    assert json.loads(project_path.read_text())["mode"] == "shadow"


def test_add_trusted_script_replaces_stale_pin_for_path(
    isolated_homes: tuple[Path, Path],
) -> None:
    """Re-pinning an EDITED script (same path, new sha) must replace the prior
    pin, not append. One path == one trusted version, so the old bytes are no
    longer trusted (a revert to them is not silently re-allowed)."""
    from guard.allowlist import add_trusted_script, load_allowlist

    _, cwd = isolated_homes
    sha_old = _sha256_text("v1\n")
    sha_new = _sha256_text("v2\n")

    add_trusted_script(path="/repo/x.py", sha256=sha_old, reason="v1", scope="project", cwd=cwd)
    assert (
        add_trusted_script(path="/repo/x.py", sha256=sha_new, reason="v2", scope="project", cwd=cwd)
        is True
    )

    al = load_allowlist(cwd=cwd)
    entries = [e for e in al.trusted_scripts if e.path == "/repo/x.py"]
    assert len(entries) == 1
    assert entries[0].sha256 == sha_new
    assert al.find_trusted_script("/repo/x.py", sha_old) is None


def test_remove_trusted_script_removes_all_for_path(
    isolated_homes: tuple[Path, Path],
) -> None:
    from guard.allowlist import add_trusted_script, load_allowlist, remove_trusted_script

    _, cwd = isolated_homes
    sha = _sha256_text("vetted\n")
    add_trusted_script(path="/repo/x.py", sha256=sha, reason="ok", scope="project", cwd=cwd)

    assert remove_trusted_script(path="/repo/x.py", scope="project", cwd=cwd) is True
    assert load_allowlist(cwd=cwd).find_trusted_script("/repo/x.py", sha) is None
    # Removing again (nothing left) reports no-op.
    assert remove_trusted_script(path="/repo/x.py", scope="project", cwd=cwd) is False
