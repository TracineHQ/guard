"""Tests for the ``python -m guard status`` CLI."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path


def test_import_works() -> None:
    from guard import _status

    assert hasattr(_status, "render_status")


def test_render_status_contains_version() -> None:
    from guard import __version__
    from guard._status import render_status

    out = render_status()
    assert isinstance(out, str)
    assert __version__ in out


def test_render_status_no_settings_reports_install_hint(tmp_path: Path) -> None:
    from guard._status import INSTALL_HINT, render_status

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_cwd = tmp_path / "work"
    fake_cwd.mkdir()
    decisions = tmp_path / "decisions.jsonl"

    with (
        patch("guard._status.Path.home", return_value=fake_home),
        patch("os.environ", {"GUARD_DECISIONS_PATH": str(decisions)}),
        patch("guard._status.Path.cwd", return_value=fake_cwd),
    ):
        out = render_status()

    assert INSTALL_HINT in out


def test_render_status_with_wired_hooks(tmp_path: Path) -> None:
    from guard._status import render_status

    fake_home = tmp_path
    claude_dir = fake_home / ".claude"
    claude_dir.mkdir(exist_ok=True)
    settings_path = claude_dir / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python3 ${CLAUDE_PLUGIN_ROOT}/src/guard/"
                                        "hooks/bash_command_validator.py"
                                    ),
                                },
                                {
                                    "type": "command",
                                    "command": (
                                        "python3 ${CLAUDE_PLUGIN_ROOT}/src/guard/"
                                        "hooks/git_c_validator.py"
                                    ),
                                },
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    decisions = tmp_path / "decisions.jsonl"

    with (
        patch("guard._status.Path.home", return_value=fake_home),
        patch("os.environ", {"GUARD_DECISIONS_PATH": str(decisions)}),
        patch("guard._status.Path.cwd", return_value=tmp_path / "nowhere"),
    ):
        out = render_status()

    assert "[wired] bash_command_validator" in out
    assert "[wired] git_c_validator" in out
    assert "[not wired] credential_check" in out
    assert "matcher='Bash'" in out


def test_subprocess_invocation_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "guard", "status"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "guard " in result.stdout
