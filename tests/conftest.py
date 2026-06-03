# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _isolate_guard_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate ``GUARD_DATA_DIR`` + clear queue/decisions env overrides.

    ``GUARD_DATA_DIR`` is pointed at a per-test empty tmp dir so the
    allowlist loader (``guard.allowlist.load_allowlist``) doesn't pick up
    the dev's real ``~/.claude/guard/allowlist.json`` and silently allow
    commands tests expect to deny.

    Permission mode is sourced from the PreToolUse payload. Tests that need
    strict mode pass ``permission_mode="dontAsk"`` directly. ``CLAUDE_AUTONOMOUS``
    is the deprecated env-var fallback (one-cycle migration window); the dev
    shell may have it set, so we strip it here to keep tests deterministic.
    Reset ``_CLAUDE_AUTONOMOUS_WARNED`` so the one-time stderr warning gets
    its first chance each test (otherwise the assertion-via-stderr tests
    flake on test ordering).
    """
    from guard import _utils

    monkeypatch.delenv("CLAUDE_AUTONOMOUS", raising=False)
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path / "guard-home"))
    # Isolate the decision log too: the env var covers subprocess tests; the
    # setattr covers in-process decide() calls (the constant is import-captured,
    # so an env-var change alone never reaches the already-imported writer).
    log_path = tmp_path / "guard-decisions.jsonl"
    monkeypatch.setenv("GUARD_DECISIONS_PATH", str(log_path))
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
    # Isolate the strict-deny queue the same way. queue_denied_command imports
    # the path BY VALUE into bash_command_validator, so patch that binding too --
    # else in-process strict denials append to the real
    # ~/.claude/guard-strict-deny-queue.jsonl (caught by _no_real_log_pollution).
    queue_path = tmp_path / "guard-strict-deny-queue.jsonl"
    monkeypatch.setenv("GUARD_STRICT_DENY_QUEUE_PATH", str(queue_path))
    monkeypatch.setattr("guard._utils.GUARD_STRICT_DENY_QUEUE_PATH", str(queue_path))
    monkeypatch.setattr(
        "guard.hooks.bash_command_validator.GUARD_STRICT_DENY_QUEUE_PATH",
        str(queue_path),
        raising=False,
    )
    _utils._CLAUDE_AUTONOMOUS_WARNED["once"] = False  # noqa: SLF001 -- reset module-private warn-once flag


@pytest.fixture(scope="session", autouse=True)
def _no_real_log_pollution() -> Iterator[None]:
    """Structural backstop: fail the suite if any test writes guard's real logs.

    ``_isolate_guard_env`` (per-test) and ``run_hook``'s os.devnull default are
    per-path defenses. This is the catch-all: it snapshots the real ``~/.claude``
    decision log + strict-deny queue before the suite and asserts they are
    untouched after. Whatever the leak path -- a new test, a subprocess without
    isolation, a refactor that drops it -- a write to the operational log turns
    the suite red instead of silently polluting it (which is exactly how hundreds
    of thousands of test decisions ended up in the dev's real log).
    """
    real = (
        Path("~/.claude/guard-decisions.jsonl").expanduser(),
        Path("~/.claude/guard-strict-deny-queue.jsonl").expanduser(),
    )

    def _sig(p: Path) -> tuple[bool, int, int]:
        try:
            st = p.stat()
        except OSError:
            return (False, 0, 0)
        return (True, st.st_size, st.st_mtime_ns)

    before = {p: _sig(p) for p in real}
    yield
    polluted = [str(p) for p in real if _sig(p) != before[p]]
    assert not polluted, (
        f"test run wrote guard's real operational log(s): {polluted}. A test is "
        "not isolating GUARD_DECISIONS_PATH / GUARD_STRICT_DENY_QUEUE_PATH -- use "
        "run_hook (sinks to os.devnull) or an explicit tmp path; never let a hook "
        "fall back to the ~/.claude default."
    )


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
    log_path = tmp_path / "guard-decisions.jsonl"
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
