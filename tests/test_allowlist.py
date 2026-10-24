"""Tests for ``guard.allowlist``: loading the global file and ignoring retired config."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def isolated_homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Return ``(global_dir, project_cwd)``, both clean, no existing allowlists.

    Points ``GUARD_DATA_DIR`` at the temp global dir and reloads the module,
    which also resets its once-per-process warnings.
    """
    global_dir = tmp_path / "global" / ".claude" / "guard"
    project_cwd = tmp_path / "project"
    project_cwd.mkdir()
    monkeypatch.setenv("GUARD_DATA_DIR", str(global_dir))
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
    assert al.mode == "enforce"
    assert al.sources == ()


def test_load_global(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": ["bash.host_control"], "mode": "shadow"})
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"bash.host_control"}
    assert al.mode == "shadow"
    assert al.is_rule_disabled("bash.host_control") is True
    assert al.is_rule_disabled("bash.something_else") is False


def test_project_file_is_ignored_and_reported_once(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """A project file grants nothing, whatever it holds, and says so once per process."""
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": ["bash.host_control"]})
    project = cwd / ".claude" / "guard" / "allowlist.json"
    _write(
        project,
        {
            "mode": "off",
            "disable_rules": ["bash.disk_destruction"],
            "allow_commands": [{"rule": "bash.disk_destruction", "command": "x", "reason": "y"}],
        },
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"bash.host_control"}
    assert al.mode == "enforce"
    assert al.sources == (gdir / "allowlist.json",)
    err = capsys.readouterr().err
    assert err.splitlines() == [
        f"guard: allowlist: project allowlist {project} is retired and ignored; "
        "see guard's CHANGELOG"
    ]
    load_allowlist(cwd=cwd)
    assert capsys.readouterr().err == ""


def test_lockdown_in_project_file_is_ignored_too(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    _, cwd = isolated_homes
    _write(cwd / ".claude" / "guard" / "allowlist.json", {"mode": "lockdown"})
    assert load_allowlist(cwd=cwd).mode == "enforce"
    assert "retired" in capsys.readouterr().err


def test_global_lockdown_mode_is_retired_and_reported_once(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"mode": "lockdown", "disable_rules": ["bash.host_control"]})
    al = load_allowlist(cwd=cwd)
    assert al.mode == "enforce"
    assert al.disable_rules == {"bash.host_control"}
    assert capsys.readouterr().err.splitlines() == [
        "guard: allowlist: mode lockdown is retired and ignored; see guard's CHANGELOG"
    ]
    load_allowlist(cwd=cwd)
    assert capsys.readouterr().err == ""


def test_global_allow_commands_are_ignored_and_reported_once(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(
        gdir / "allowlist.json",
        {
            "disable_rules": ["bash.host_control"],
            "allow_commands": [{"rule": "bash.disk_destruction", "command": "x", "reason": "y"}],
        },
    )
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"bash.host_control"}
    assert not hasattr(al, "allow_commands")
    err = capsys.readouterr().err
    assert err.splitlines() == [
        f"guard: allowlist: allow_commands in {gdir / 'allowlist.json'} is retired and "
        "ignored; see guard's CHANGELOG"
    ]
    load_allowlist(cwd=cwd)
    assert capsys.readouterr().err == ""


def test_malformed_allow_commands_do_not_crash(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"allow_commands": "not a list", "mode": "shadow"})
    assert load_allowlist(cwd=cwd).mode == "shadow"
    assert "allow_commands" in capsys.readouterr().err


def test_global_file_is_not_reported_as_a_project_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With cwd = HOME the project path is the global file itself."""
    import guard.allowlist

    home = tmp_path / "home"
    monkeypatch.setenv("GUARD_DATA_DIR", str(home / ".claude" / "guard"))
    monkeypatch.setattr(guard.allowlist, "_WARNED_RETIRED", set())
    _write(home / ".claude" / "guard" / "allowlist.json", {"disable_rules": ["a"]})
    assert guard.allowlist.retired_project_file(home) is None
    assert guard.allowlist.load_allowlist(cwd=home).disable_rules == {"a"}
    assert capsys.readouterr().err == ""


def test_malformed_json_emits_warning_and_skips(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    gdir.mkdir(parents=True)
    (gdir / "allowlist.json").write_text("{not valid json", encoding="utf-8")
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert "invalid JSON" in capsys.readouterr().err


def test_top_level_not_object_skipped(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", [])
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert "top-level must be an object" in capsys.readouterr().err


def test_disable_rules_wrong_type_warns(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": "not a list"})
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == frozenset()
    assert "must be a list" in capsys.readouterr().err


def test_disable_rules_skips_non_string_entries(isolated_homes: tuple[Path, Path]) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"disable_rules": ["good.rule", 42, None, "another.rule"]})
    al = load_allowlist(cwd=cwd)
    assert al.disable_rules == {"good.rule", "another.rule"}


def test_invalid_mode_warns_and_defaults(
    isolated_homes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    gdir, cwd = isolated_homes
    _write(gdir / "allowlist.json", {"mode": "loose"})
    assert load_allowlist(cwd=cwd).mode == "enforce"
    assert "'mode' must be one of" in capsys.readouterr().err


def test_mutations_write_the_global_file_and_keep_other_keys(
    isolated_homes: tuple[Path, Path],
) -> None:
    """Rule and mode writes go to the global file and leave every other key alone.

    Regression: an earlier ``_read_raw`` normalised the doc to its known
    lists, so ``add_disable_rule`` on a file with ``"mode": "shadow"``
    silently dropped the operator's configured posture.
    """
    from guard.allowlist import add_disable_rule, load_allowlist, remove_disable_rule, set_mode

    gdir, cwd = isolated_homes
    path = gdir / "allowlist.json"
    _write(path, {"allow_commands": [{"rule": "r", "command": "c", "reason": "x"}]})

    assert set_mode("shadow") is None
    assert add_disable_rule("bash.disk_destruction") is True
    assert add_disable_rule("bash.disk_destruction") is False
    doc = json.loads(path.read_text())
    assert doc["mode"] == "shadow"
    assert doc["disable_rules"] == ["bash.disk_destruction"]
    assert doc["allow_commands"] == [{"rule": "r", "command": "c", "reason": "x"}]

    assert remove_disable_rule("bash.disk_destruction") is True
    assert remove_disable_rule("bash.disk_destruction") is False
    assert set_mode("enforce") == "shadow"
    assert json.loads(path.read_text())["disable_rules"] == []
    assert load_allowlist(cwd=cwd).mode == "enforce"
    assert not (cwd / ".claude").exists()
