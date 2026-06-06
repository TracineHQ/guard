# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for the ``guard untrust-script`` CLI verb (revoke a content pin)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def project_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Chdir into an isolated project; point the global allowlist at an empty tmp dir."""
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path / "global" / ".claude" / "guard"))
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return project


def _trusted_paths(project_cwd: Path) -> list[str]:
    al = project_cwd / ".claude" / "guard" / "allowlist.json"
    if not al.exists():
        return []
    doc = json.loads(al.read_text(encoding="utf-8"))
    return [e["path"] for e in doc.get("trusted_scripts", [])]


def test_untrust_script_removes_entry(project_cwd: Path) -> None:
    from guard.cli import cmd_trust_script, cmd_untrust_script

    script = project_cwd / "scan.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    cmd_trust_script(str(script), reason="vetted", scope="project")
    assert _trusted_paths(project_cwd) == [str(script.resolve())]

    payload, pretty = cmd_untrust_script(str(script), scope="project")
    assert payload["removed"] is True
    assert _trusted_paths(project_cwd) == []
    assert "untrust" in pretty.lower()


def test_untrust_script_no_entry_reports_false(project_cwd: Path) -> None:
    from guard.cli import cmd_untrust_script

    (project_cwd / "scan.py").write_text("x\n", encoding="utf-8")
    payload, _ = cmd_untrust_script("scan.py", scope="project")
    assert payload["removed"] is False


def test_untrust_script_works_after_file_deleted(project_cwd: Path) -> None:
    """Untrust must not require the file to exist (you revoke trust precisely when
    a script is gone or compromised) — it resolves the path but never reads bytes."""
    from guard.cli import cmd_trust_script, cmd_untrust_script

    script = project_cwd / "scan.py"
    script.write_text("y\n", encoding="utf-8")
    cmd_trust_script(str(script), reason="vetted", scope="project")
    script.unlink()

    payload, _ = cmd_untrust_script(str(script), scope="project")
    assert payload["removed"] is True
    assert _trusted_paths(project_cwd) == []


def test_untrust_script_cli_main_exit_zero(project_cwd: Path) -> None:
    from guard.cli import main

    script = project_cwd / "scan.py"
    script.write_text("z\n", encoding="utf-8")
    assert main(["trust-script", "scan.py", "--reason", "vetted"]) == 0
    assert _trusted_paths(project_cwd) == [str(script.resolve())]

    assert main(["untrust-script", "scan.py"]) == 0
    assert _trusted_paths(project_cwd) == []
