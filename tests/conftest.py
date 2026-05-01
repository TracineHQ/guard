"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


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


@pytest.fixture
def decision_log_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point ``GUARD_DECISIONS_PATH`` at an isolated JSONL under ``tmp_path``.

    Returned path is the JSONL file (which may not yet exist); tests that
    need to read the log can use it directly.
    """
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("GUARD_DECISIONS_PATH", str(log_path))
    return log_path


@pytest.fixture
def autonomous_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, decision_log_env: Path) -> Path:
    """Activate strict autonomous mode with isolated decision log + queue.

    Sets ``CLAUDE_AUTONOMOUS=1``, an isolated ``GUARD_DECISIONS_PATH`` (via
    ``decision_log_env``), and ``GUARD_AUTONOMOUS_QUEUE_PATH``. Returns
    ``tmp_path`` for tests that need to inspect both files.
    """
    monkeypatch.setenv("CLAUDE_AUTONOMOUS", "1")
    monkeypatch.setenv("GUARD_AUTONOMOUS_QUEUE_PATH", str(tmp_path / "queue.jsonl"))
    return tmp_path
