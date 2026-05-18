# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for Phase 1 ops primitives: healthcheck, internal_error
records, and status counters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guard._utils import log_decision, log_internal_error

if TYPE_CHECKING:
    import pytest


def _read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_log_decision_writes_type_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="test",
    )
    records = _read_records(log_path)
    assert records
    assert records[0]["type"] == "decision"
    assert records[0]["decision"] == "deny"


def test_log_internal_error_record_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
    msg = "boom"
    try:
        raise ValueError(msg)  # noqa: TRY301 -- intentional: synthesise an exc to capture
    except ValueError as exc:
        log_internal_error(exc, session_id="sess-1")
    records = _read_records(log_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["type"] == "internal_error"
    assert rec["exc_class"] == "ValueError"
    assert rec["exc_msg"] == "boom"
    assert rec["traceback_hash"].startswith("sha256:")
    assert rec["session_id"] == "sess-1"


def test_log_internal_error_redacts_secret_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exception messages must run through ``_redact_secrets`` before landing in JSONL.

    Without this, a hook that crashes while constructing a deny reason that
    contains the offending command's credential would leak that credential
    into the audit log — the same channel guard exists to keep clean.
    """
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
    msg = "boom near AKIAIOSFODNN7EXAMPLE token"  # pragma: allowlist secret
    try:
        raise RuntimeError(msg)  # noqa: TRY301 -- intentional: synthesise an exc to capture
    except RuntimeError as exc:
        log_internal_error(exc)
    records = _read_records(log_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["type"] == "internal_error"
    assert "AKIAIOSFODNN7EXAMPLE" not in rec["exc_msg"]  # pragma: allowlist secret
    assert "[REDACTED-AWS-ID]" in rec["exc_msg"]


def test_counters_aggregate_by_type(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from guard.cli import JsonlReader

    log_path = tmp_path / "log.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(log_path))
    for d in ("allow", "deny", "deny", "allow"):
        log_decision(
            hook_id="guard.test",
            event="PreToolUse",
            tool_name="Bash",
            decision=d,
            reason="r",
        )
    msg = "oops"
    try:
        raise RuntimeError(msg)  # noqa: TRY301 -- intentional
    except RuntimeError as exc:
        log_internal_error(exc)
    counters = JsonlReader(log_path).counters()
    assert counters["decisions_total"] == 4
    assert counters["denies_total"] == 2
    assert counters["internal_errors_total"] == 1
    assert counters["last_activity_ts"] is not None


def test_healthcheck_returns_healthy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARD_DECISIONS_PATH", str(tmp_path / "log.jsonl"))
    from guard.cli import cmd_healthcheck

    payload, pretty = cmd_healthcheck()
    assert payload["healthy"] is True
    assert payload["elapsed_ms"] >= 0
    assert "OK" in pretty
    probes = payload["probes"]
    assert len(probes) >= 2, "healthcheck should run multiple probes"
    for probe in probes:
        assert probe["passed"] is True, f"probe failed: {probe}"
        assert probe["command"]
        assert probe["expected_rule"]
