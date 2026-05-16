# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolate_guard_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate ``GUARD_DATA_DIR`` + clear queue/decisions env overrides.

    ``GUARD_DATA_DIR`` is pointed at a per-test empty tmp dir so the
    allowlist loader (``guard.allowlist.load_allowlist``) doesn't pick up
    the dev's real ``~/.claude/guard/allowlist.json`` and silently allow
    commands tests expect to deny.

    Permission mode is now sourced from the PreToolUse payload, not env, so
    no env-var stripping is needed for strict-mode isolation. Tests that
    need strict mode pass ``permission_mode="dontAsk"`` directly.
    """
    monkeypatch.delenv("GUARD_STRICT_DENY_QUEUE_PATH", raising=False)
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
def strict_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, decision_log_env: Path) -> Path:
    """Isolate the strict-deny queue path + decision log.

    Sets ``GUARD_STRICT_DENY_QUEUE_PATH`` and inherits the isolated
    ``GUARD_DECISIONS_PATH`` from ``decision_log_env``. Returns ``tmp_path``
    so tests can inspect both files.

    NOTE: this fixture no longer activates strict mode — pass
    ``permission_mode="dontAsk"`` to ``decide()`` (or set it in the
    PreToolUse payload for subprocess tests).
    """
    monkeypatch.setenv("GUARD_STRICT_DENY_QUEUE_PATH", str(tmp_path / "queue.jsonl"))
    return tmp_path
