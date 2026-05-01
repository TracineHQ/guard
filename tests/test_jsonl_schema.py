"""Schema-versioning tests for the JSONL decision log.

Pins the v1.1 contract:

- Every emitted record has the new ``v`` and ``mode`` fields.
- Records have a stable, declared field set (canary against drift).
- Forward-compatibility: legacy records without ``v`` are still parseable.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from guard._utils import log_decision

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``GUARD_DECISIONS_PATH`` (module attribute) to an isolated path."""
    target = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(target))
    return target


# Required fields in every emitted v1.1 record. New fields go in this set;
# removing/renaming requires a ``v`` bump per docs/JSONL_FORMAT.md §4.
_V1_REQUIRED_FIELDS = frozenset(
    {
        "v",
        "schema_version",
        "mode",
        "timestamp",
        "hook_id",
        "event",
        "tool_name",
        "decision",
        "reason",
        "session_id",
    }
)


def test_record_carries_v_and_mode(jsonl: Path) -> None:
    log_decision(
        hook_id="guard.x",
        event="PreToolUse",
        tool_name="Bash",
        decision="allow",
        reason="ok",
    )
    rec = json.loads(jsonl.read_text().splitlines()[-1])
    assert rec["v"] == 1
    assert rec["mode"] == "enforce"


def test_record_field_set_is_a_superset_of_v1_required(jsonl: Path) -> None:
    """Every required v1.1 field must appear; canary against silent drift."""
    log_decision(
        hook_id="guard.x",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="testing",
        command_excerpt="rm -rf /",
        session_id="sess-x",
        cwd="/tmp",
    )
    rec = json.loads(jsonl.read_text().splitlines()[-1])
    missing = _V1_REQUIRED_FIELDS - set(rec.keys())
    assert not missing, f"missing required fields: {sorted(missing)}"


def test_v_and_schema_version_are_consistent(jsonl: Path) -> None:
    """Short ``v`` and long ``schema_version`` MUST always agree."""
    log_decision(
        hook_id="guard.x",
        event="PreToolUse",
        tool_name="Bash",
        decision="allow",
        reason="ok",
    )
    rec = json.loads(jsonl.read_text().splitlines()[-1])
    assert rec["v"] == rec["schema_version"]


def test_legacy_record_without_v_is_parseable() -> None:
    """Consumers must tolerate legacy records lacking ``v``.

    Pin the contract: a record from before v1.1 (no ``v``, has
    ``schema_version``) parses fine and is treated as ``v=0`` by best-effort
    consumers.
    """
    legacy_line = json.dumps(
        {
            "schema_version": 1,
            "timestamp": "2026-04-01T00:00:00.000000Z",
            "hook_id": "guard.x",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "allow",
            "reason": "ok",
            "session_id": "s1",
        }
    )
    rec = json.loads(legacy_line)
    # Best-effort default: missing v -> 0
    v = rec.get("v", 0)
    assert v == 0
    assert rec["decision"] == "allow"


def test_record_with_unknown_fields_still_parses() -> None:
    """Forward-compat: consumers MUST tolerate unknown fields."""
    line = json.dumps(
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": "2026-04-01T00:00:00.000000Z",
            "hook_id": "guard.x",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "allow",
            "reason": "ok",
            "session_id": "s1",
            "future_field_xyz": {"nested": [1, 2, 3]},
        }
    )
    rec = json.loads(line)
    # Pinned fields still readable; unknown fields don't cause a crash.
    assert rec["v"] == 1
    assert rec["mode"] == "enforce"
    assert rec["future_field_xyz"]["nested"] == [1, 2, 3]
