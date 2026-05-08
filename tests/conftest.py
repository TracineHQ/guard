# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolate_autonomous_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Strip CLAUDE_AUTONOMOUS from the environment + isolate ``GUARD_DATA_DIR``.

    The bash_command_validator (and several other hooks) branch on
    ``CLAUDE_AUTONOMOUS=1`` and return an explicit ``allow`` envelope rather
    than passthrough. Many tests assert ``decide(...)`` returns ``None`` for
    safe commands, so a leaked env var from the dev shell causes spurious
    failures.

    ``GUARD_DATA_DIR`` is pointed at a per-test empty tmp dir so the
    allowlist loader (``guard.allowlist.load_allowlist``) doesn't pick up
    the dev's real ``~/.claude/guard/allowlist.json`` and silently allow
    commands tests expect to deny.

    Tests that exercise autonomous-mode behavior set the var explicitly via
    ``monkeypatch.setenv`` or pass it through ``env=`` to subprocess; this
    fixture's ``monkeypatch.delenv`` is reverted after each test, so those
    tests are unaffected.
    """
    monkeypatch.delenv("CLAUDE_AUTONOMOUS", raising=False)
    monkeypatch.delenv("GUARD_AUTONOMOUS_QUEUE_PATH", raising=False)
    monkeypatch.delenv("GUARD_DECISIONS_PATH", raising=False)
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path / "guard-home"))


@pytest.fixture
def decision_log_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point ``GUARD_DECISIONS_PATH`` at an isolated JSONL under ``tmp_path``.

    Patches the env var (for subprocess-based tests) AND the module-level
    ``guard._utils.GUARD_DECISIONS_PATH`` attribute (for in-process
    ``log_decision`` calls — the constant is captured at import time and
    env-var changes don't propagate). Returned path is the JSONL file
    (which may not yet exist); tests that need to read the log can use it
    directly.
    """
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("GUARD_DECISIONS_PATH", str(log_path))
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
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
