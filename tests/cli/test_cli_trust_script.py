"""Tests for the ``guard trust-script`` CLI verb."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import hashlib
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


def test_trust_script_writes_entry(project_cwd: Path) -> None:
    from guard.cli import cmd_trust_script

    script = project_cwd / "scan.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    sha = hashlib.sha256(b"print('ok')\n").hexdigest()

    payload, pretty = cmd_trust_script(str(script), reason="vetted helper", scope="project")
    assert payload["added"] is True
    assert payload["sha256"] == sha

    doc = json.loads(
        (project_cwd / ".claude" / "guard" / "allowlist.json").read_text(encoding="utf-8")
    )
    entry = doc["trusted_scripts"][0]
    assert entry["path"] == str(script.resolve())
    assert entry["sha256"] == sha
    assert entry["reason"] == "vetted helper"
    assert "trust" in pretty.lower()


def test_trust_script_stores_resolved_abspath(project_cwd: Path) -> None:
    """A relative path is stored as the resolved absolute path so the hook's
    own ``.resolve()`` of the runtime arg matches."""
    from guard.cli import cmd_trust_script

    (project_cwd / "scan.py").write_text("x\n", encoding="utf-8")
    payload, _ = cmd_trust_script("scan.py", reason="rel path", scope="project")
    assert payload["path"] == str((project_cwd / "scan.py").resolve())


def test_trust_script_idempotent(project_cwd: Path) -> None:
    from guard.cli import cmd_trust_script

    (project_cwd / "scan.py").write_text("x\n", encoding="utf-8")
    cmd_trust_script("scan.py", reason="first", scope="project")
    payload, _ = cmd_trust_script("scan.py", reason="second", scope="project")
    assert payload["added"] is False


def test_trust_script_repin_after_edit_replaces(project_cwd: Path) -> None:
    """Re-pinning an edited file replaces the stale pin, leaving exactly one
    entry for the path (the new bytes) — not a second, stale-sha entry."""
    from guard.cli import cmd_trust_script

    script = project_cwd / "scan.py"
    script.write_text("v1\n", encoding="utf-8")
    cmd_trust_script("scan.py", reason="v1", scope="project")

    script.write_text("v2\n", encoding="utf-8")
    new_sha = hashlib.sha256(b"v2\n").hexdigest()
    payload, _ = cmd_trust_script("scan.py", reason="v2", scope="project")
    assert payload["added"] is True

    doc = json.loads(
        (project_cwd / ".claude" / "guard" / "allowlist.json").read_text(encoding="utf-8")
    )
    entries = [e for e in doc["trusted_scripts"] if e["path"] == str(script.resolve())]
    assert len(entries) == 1
    assert entries[0]["sha256"] == new_sha


def test_trust_script_missing_file_errors(project_cwd: Path) -> None:
    from guard.cli import cmd_trust_script

    with pytest.raises((FileNotFoundError, OSError)):
        cmd_trust_script("ghost.py", reason="nope", scope="project")


def test_trust_script_cli_main_exit_zero(project_cwd: Path) -> None:
    """End-to-end through main(): trust-script returns 0 and writes the file."""
    from guard.cli import main

    (project_cwd / "scan.py").write_text("y\n", encoding="utf-8")
    rc = main(["trust-script", "scan.py", "--reason", "via main"])
    assert rc == 0
    doc = json.loads(
        (project_cwd / ".claude" / "guard" / "allowlist.json").read_text(encoding="utf-8")
    )
    assert doc["trusted_scripts"][0]["reason"] == "via main"
