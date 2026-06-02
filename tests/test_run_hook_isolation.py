# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Regression: the subprocess hook runner must not pollute the developer's logs.

``run_hook`` historically only isolated ``GUARD_DECISIONS_PATH`` when a caller
passed ``decisions_path``; otherwise the spawned hook inherited the ambient
environment and, lacking an override, fell back to
``~/.claude/guard-decisions.jsonl``. That leaked hundreds of thousands of test
decisions (session_id ``harden`` / ``wiring-test`` / ...) into the operational
log. ``run_hook`` now sinks both guard log paths to ``os.devnull`` by default,
so a call outside the autouse isolation fixture can never append to the real log.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from tests._helpers import decision_from_stdout, run_hook

if TYPE_CHECKING:
    import pytest


def test_run_hook_sinks_logs_when_no_path_given(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Drop the autouse fixture's isolation and redirect HOME so the hook's
    # default log path would resolve under tmp_path. Without the devnull
    # default, the denied command below would create it there.
    monkeypatch.delenv("GUARD_DECISIONS_PATH", raising=False)
    monkeypatch.delenv("GUARD_STRICT_DENY_QUEUE_PATH", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    _, stdout, _ = run_hook("bash_command_validator", "rm -rf /", strict=True)

    # The hook actually ran and reached its decision/logging path...
    assert decision_from_stdout(stdout) == "deny"
    # ...yet wrote nothing to the developer's real (HOME-relative) logs.
    assert not (tmp_path / ".claude" / "guard-decisions.jsonl").exists()
    assert not (tmp_path / ".claude" / "guard-strict-deny-queue.jsonl").exists()


def test_run_hook_honors_explicit_decisions_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Positive control: an explicit decisions_path is still captured, proving the
    # devnull default does not suppress intentional log inspection.
    monkeypatch.setenv("HOME", str(tmp_path))
    log = tmp_path / "decisions.jsonl"

    run_hook("bash_command_validator", "rm -rf /", strict=True, decisions_path=log)

    assert log.exists()
    assert not (tmp_path / ".claude" / "guard-decisions.jsonl").exists()
