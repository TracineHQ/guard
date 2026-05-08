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
    project.mkdir(parents=True)
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
    assert payload == {"disable_rules": [], "allow_commands": [], "sources": []}
    assert "empty" in pretty


def test_disable_rule_creates_project_file(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    _, project = isolated_scopes
    payload, pretty = cmd_allowlist_disable_rule("bash.disk_destruction", scope="project")
    assert payload["added"] is True
    target = project / ".claude" / "guard" / "allowlist.json"
    assert target.exists()
    doc = json.loads(target.read_text(encoding="utf-8"))
    assert doc["disable_rules"] == ["bash.disk_destruction"]
    assert "added" in pretty


def test_disable_rule_idempotent(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    cmd_allowlist_disable_rule("bash.disk_destruction", scope="project")
    payload2, _ = cmd_allowlist_disable_rule("bash.disk_destruction", scope="project")
    assert payload2["added"] is False


def test_enable_rule_removes_it(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule, cmd_allowlist_enable_rule

    cmd_allowlist_disable_rule("bash.disk_destruction", scope="project")
    payload, _ = cmd_allowlist_enable_rule("bash.disk_destruction", scope="project")
    assert payload["removed"] is True


def test_enable_rule_idempotent_when_absent(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_enable_rule

    payload, _ = cmd_allowlist_enable_rule("bash.disk_destruction", scope="project")
    assert payload["removed"] is False


def test_allow_command_writes_entry(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_allow_command

    _, project = isolated_scopes
    payload, _ = cmd_allowlist_allow_command(
        rule="bash.disk_destruction",
        command="dd if=/dev/zero of=/tmp/x.qcow2 bs=1M count=1",
        reason="VM image fixture",
        scope="project",
    )
    assert payload["added"] is True
    doc = json.loads((project / ".claude" / "guard" / "allowlist.json").read_text(encoding="utf-8"))
    assert doc["allow_commands"][0]["reason"] == "VM image fixture"


def test_allow_command_idempotent(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_allow_command

    cmd_allowlist_allow_command(rule="r", command="c", reason="r1", scope="project")
    payload2, _ = cmd_allowlist_allow_command(rule="r", command="c", reason="r2", scope="project")
    assert payload2["added"] is False


def test_remove_command_works(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_allow_command, cmd_allowlist_remove_command

    cmd_allowlist_allow_command(rule="r", command="c", reason="x", scope="project")
    payload, _ = cmd_allowlist_remove_command(rule="r", command="c", scope="project")
    assert payload["removed"] is True


def test_global_scope_writes_to_guard_data_dir(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    global_dir, _ = isolated_scopes
    cmd_allowlist_disable_rule("bash.disk_destruction", scope="global")
    assert (global_dir / "allowlist.json").exists()


def test_disable_unknown_rule_warns_but_succeeds(
    isolated_scopes: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.cli import cmd_allowlist_disable_rule

    payload, _ = cmd_allowlist_disable_rule("totally.fake", scope="project")
    assert payload["added"] is True
    err = capsys.readouterr().err
    assert "unknown rule_id" in err


def test_list_after_writes_shows_entries(isolated_scopes: tuple[Path, Path]) -> None:
    from guard.cli import (
        cmd_allowlist_allow_command,
        cmd_allowlist_disable_rule,
        cmd_allowlist_list,
    )

    cmd_allowlist_disable_rule("bash.disk_destruction", scope="project")
    cmd_allowlist_allow_command(
        rule="bash.aws_destructive", command="aws s3 rm s3://x", reason="test", scope="project"
    )
    payload, pretty = cmd_allowlist_list()
    assert "bash.disk_destruction" in payload["disable_rules"]
    assert any(e["rule"] == "bash.aws_destructive" for e in payload["allow_commands"])
    assert "disable_rules" in pretty
