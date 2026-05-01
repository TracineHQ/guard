"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_autonomous_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip CLAUDE_AUTONOMOUS from the environment before every test.

    The bash_command_validator (and several other hooks) branch on
    ``CLAUDE_AUTONOMOUS=1`` and return an explicit ``allow`` envelope rather
    than passthrough. Many tests assert ``decide(...)`` returns ``None`` for
    safe commands, so a leaked env var from the dev shell causes spurious
    failures.

    Tests that exercise autonomous-mode behavior set the var explicitly via
    ``monkeypatch.setenv`` or pass it through ``env=`` to subprocess; this
    fixture's ``monkeypatch.delenv`` is reverted after each test, so those
    tests are unaffected.
    """
    monkeypatch.delenv("CLAUDE_AUTONOMOUS", raising=False)
    monkeypatch.delenv("GUARD_AUTONOMOUS_QUEUE_PATH", raising=False)
    monkeypatch.delenv("GUARD_DECISIONS_PATH", raising=False)
