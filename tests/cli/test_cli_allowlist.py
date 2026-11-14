"""Tests for ``guard allowlist`` CLI subcommands."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def isolated_scopes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Return ``(global_dir, project_cwd)`` and chdir the test into project_cwd."""
    global_dir = tmp_path / "global" / ".claude" / "guard"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("GUARD_DATA_DIR", str(global_dir))
    monkeypatch.chdir(project)
    return global_dir, project


def test_rules_lists_known_ids(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_rules

    payload, pretty = cmd_allowlist_rules()
    assert "bash.disk_destruction" in payload["rules"]
    assert "guard.protected_files" in payload["rules"]
    assert "bash.disk_destruction" in pretty


def test_list_empty_initially(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_list

    payload, pretty = cmd_allowlist_list()
    assert payload == {"disable_rules": [], "sources": []}
    assert "empty" in pretty


def test_disable_rule_creates_global_file(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    global_dir, project = isolated_scopes
    payload, pretty = cmd_allowlist_disable_rule("bash.disk_destruction")
    target = global_dir / "allowlist.json"
    assert payload == {"rule_id": "bash.disk_destruction", "added": True, "path": str(target)}
    assert json.loads(target.read_text(encoding="utf-8"))["disable_rules"] == [
        "bash.disk_destruction"
    ]
    assert str(target) in pretty
    assert not (project / ".claude").exists()


def test_disable_rule_idempotent(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    cmd_allowlist_disable_rule("bash.disk_destruction")
    payload2, _ = cmd_allowlist_disable_rule("bash.disk_destruction")
    assert payload2["added"] is False


def test_enable_rule_removes_it(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule, cmd_allowlist_enable_rule

    cmd_allowlist_disable_rule("bash.disk_destruction")
    payload, _ = cmd_allowlist_enable_rule("bash.disk_destruction")
    assert payload["removed"] is True


def test_enable_rule_idempotent_when_absent(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_enable_rule

    payload, _ = cmd_allowlist_enable_rule("bash.disk_destruction")
    assert payload["removed"] is False


def test_disable_unknown_rule_warns_but_succeeds(
    isolated_scopes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    payload, _ = cmd_allowlist_disable_rule("totally.fake")
    assert payload["added"] is True
    assert "unknown rule_id" in capsys.readouterr().err


def test_list_after_writes_shows_entries(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule, cmd_allowlist_list

    global_dir, _ = isolated_scopes
    cmd_allowlist_disable_rule("bash.disk_destruction")
    payload, pretty = cmd_allowlist_list()
    assert payload == {
        "disable_rules": ["bash.disk_destruction"],
        "sources": [str(global_dir / "allowlist.json")],
    }
    assert "bash.disk_destruction" in pretty


@pytest.mark.parametrize(
    "argv",
    [
        ["allowlist", "disable-rule", "bash.disk_destruction"],
        ["allowlist", "disable-rule", "bash.disk_destruction", "--global"],
    ],
    ids=["bare", "legacy-global-flag"],
)
def test_main_disable_rule_writes_global(
    isolated_scopes: tuple[Path, Path], argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.cli import main

    global_dir, _ = isolated_scopes
    assert main(["--json", *argv]) == 0
    capsys.readouterr()
    doc = json.loads((global_dir / "allowlist.json").read_text(encoding="utf-8"))
    assert doc["disable_rules"] == ["bash.disk_destruction"]


@pytest.mark.parametrize(
    "argv",
    [
        ["allowlist", "disable-rule", "bash.disk_destruction", "--project"],
        ["mode", "shadow", "--project"],
        ["allowlist", "allow-command", "--rule", "r", "--command", "c", "--reason", "x"],
        ["allowlist", "remove-command", "--rule", "r", "--command", "c"],
    ],
    ids=["disable-project", "mode-project", "allow-command", "remove-command"],
)
def test_retired_cli_forms_are_rejected(
    isolated_scopes: tuple[Path, Path], argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Retired verbs and ``--project`` fail loudly instead of writing somewhere else."""
    from guard.cli import main

    global_dir, project = isolated_scopes
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    capsys.readouterr()
    assert not (global_dir / "allowlist.json").exists()
    assert not (project / ".claude").exists()
