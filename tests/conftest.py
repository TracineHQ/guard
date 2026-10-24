# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared pytest fixtures for the guard test suite."""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

# Session-wide isolation, set before any guard module is imported (guard's
# module-level path constants read HOME / GUARD_* once at import). The run never
# reads the developer's real ~/.claude/guard/allowlist.json and never falls back
# to the real decision log, whatever a test forgets to isolate. Subprocess hooks inherit the same environment. Each xdist worker
# imports this file, so each gets its own home.
_TEST_HOME = Path(tempfile.mkdtemp(prefix="guard-test-home-"))
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
_TEST_CLAUDE = _TEST_HOME / ".claude"
DEFAULT_LOG_PATHS: tuple[Path, ...] = (_TEST_CLAUDE / "guard-decisions.jsonl",)
os.environ["HOME"] = str(_TEST_HOME)
os.environ["GUARD_DATA_DIR"] = str(_TEST_CLAUDE / "guard")
os.environ["GUARD_DECISIONS_PATH"] = str(DEFAULT_LOG_PATHS[0])


@pytest.fixture(autouse=True)
def _isolate_guard_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate ``GUARD_DATA_DIR`` + the decision log.

    ``GUARD_DATA_DIR`` is pointed at a per-test empty tmp dir so the
    allowlist loader (``guard.allowlist.load_allowlist``) doesn't pick up
    the dev's real ``~/.claude/guard/allowlist.json`` and silently allow
    commands tests expect to deny.
    """
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path / "guard-home"))
    # Isolate the decision log too: the env var covers subprocess tests; the
    # setattr covers in-process decide() calls (the constant is import-captured,
    # so an env-var change alone never reaches the already-imported writer).
    log_path = tmp_path / "guard-decisions.jsonl"
    monkeypatch.setenv("GUARD_DECISIONS_PATH", str(log_path))
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))


@pytest.fixture(scope="session", autouse=True)
def _no_real_log_pollution() -> Iterator[None]:
    """Structural backstop: fail the suite if any test writes guard's default logs.

    ``_isolate_guard_env`` (per-test) and ``run_hook``'s os.devnull default are
    per-path defenses. This is the catch-all. HOME is a throwaway directory for
    the whole run, so the default ``~/.claude`` decision log lives under it
    and must never be created: whatever the leak path -- a
    new test, a subprocess without isolation, a refactor that drops it -- a
    write that would have reached the operational log turns the suite red. It
    watches the throwaway home, not the real one, so other Claude Code sessions
    appending to the real log mid-run cannot trip it.
    """
    assert Path.home() == _TEST_HOME, "tests/conftest.py must set HOME before guard is imported"
    yield
    polluted = [str(p) for p in DEFAULT_LOG_PATHS if p.exists()]
    assert not polluted, (
        f"test run wrote guard's default operational log(s): {polluted}. A test is "
        "not isolating GUARD_DECISIONS_PATH -- use "
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
