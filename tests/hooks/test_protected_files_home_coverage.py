# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Home-dir coverage for protected_files, derived from the bash validator's set.

protected_files protects $HOME-anchored sensitive targets (shell-rc,
~/.local/bin, ~/Library/LaunchAgents, keys, ~/.gnupg, ...) by reusing the SAME
``SENSITIVE_DEST_HOME_PATTERNS`` the bash gate uses, so an Edit/Write and a
shell redirect to the same file are judged consistently. The derived-coverage
fence pins the two gates together: a pattern added to the canonical set must be
picked up here automatically.
"""

from __future__ import annotations

import pytest

from guard._utils import SENSITIVE_DEST_HOME_PATTERNS
from guard.hooks.protected_files import is_protected


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    return h


class TestHomeCoverage:
    @pytest.mark.parametrize(
        "rel",
        [
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".local/bin/sudo",
            "Library/LaunchAgents/com.evil.persist.plist",
            ".ssh/config",
            ".ssh/authorized_keys",
            ".ssh/id_ed25519",
            ".aws/credentials",
            ".gnupg/gpg.conf",
        ],
    )
    def test_home_target_is_protected(self, home, rel: str) -> None:
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        assert is_protected(str(target)) is not None

    def test_file_outside_home_is_not_falsely_protected(self, home, tmp_path) -> None:
        outside = tmp_path / "elsewhere" / "project.py"
        outside.parent.mkdir(parents=True)
        assert is_protected(str(outside)) is None


def test_every_sensitive_home_pattern_is_covered(home) -> None:
    """Derived-coverage fence: every canonical pattern is caught via a home path."""
    for pat in SENSITIVE_DEST_HOME_PATTERNS:
        rel = pat + "file" if pat.endswith("/") else pat
        probe = home / rel
        assert is_protected(str(probe)) is not None, f"uncovered home pattern: {pat}"
