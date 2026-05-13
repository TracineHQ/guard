# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _format_deny_reason agent-guidance footer (Task 4.5)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

from guard.hooks.bash_command_validator import _format_deny_reason


def test_interactive_footer_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_AUTONOMOUS", raising=False)
    result = _format_deny_reason("bash.test", "test body")
    assert "explain what this rule protects against" in result


def test_autonomous_footer_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_AUTONOMOUS", "1")
    result = _format_deny_reason("bash.test", "test body")
    assert "hard fence in autonomous mode" in result
