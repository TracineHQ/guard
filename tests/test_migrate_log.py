"""Tests for the JSONL migration tool."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from guard.migrate_log import _migrate_one, migrate_file

if TYPE_CHECKING:
    from pathlib import Path


def _v1_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "v": 1,
        "schema_version": 1,
        "mode": "enforce",
        "timestamp": "2026-04-29T14:32:11.123456Z",
        "hook_id": "guard.bash_command_validator",
        "event": "PreToolUse",
        "tool_name": "Bash",
        "decision": "allow",
        "reason": "Read-only command",
        "command_excerpt": "ls -la",
        "session_id": "sess-1",
        "cwd": "/home/alice/project",
    }
    base.update(overrides)
    return base


def _v1_0_record(**overrides: object) -> dict[str, object]:
    """v1.0 = has schema_version and v1 fields, but no `v` or `mode`."""
    base: dict[str, object] = {
        "schema_version": 1,
        "timestamp": "2026-04-30T17:21:09.810568Z",
        "hook_id": "guard.agent_output_guard",
        "event": "PreToolUse",
        "tool_name": "Read",
        "decision": "deny",
        "reason": "raw output read denied",
        "session_id": "sess-2",
        "command_excerpt": "/private/tmp/x.output",
    }
    base.update(overrides)
    return base


def _v0_record(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ts": "2026-04-30T05:42:34.622360+00:00",
        "command": "ls",
        "decision": "passthrough",
        "reason": "no match",
        "segments": 1,
        "session_id": "",
        "base_cmd": "ls",
    }
    base.update(overrides)
    return base


def test_migrate_one_v1_passthrough() -> None:
    rec = _v1_record()
    line = json.dumps(rec) + "\n"
    category, out = _migrate_one(line)
    assert category == "v1"
    assert out == line


def test_migrate_one_v1_0_injects_v_and_mode() -> None:
    rec = _v1_0_record()
    line = json.dumps(rec) + "\n"
    category, out = _migrate_one(line)
    assert category == "v1_0"
    promoted = json.loads(out)
    assert promoted["v"] == 1
    assert promoted["mode"] == "enforce"
    assert promoted["hook_id"] == "guard.agent_output_guard"
    assert promoted["decision"] == "deny"


def test_migrate_one_v0_full_inference() -> None:
    rec = _v0_record(decision="deny", reason="rm -rf denied", command="rm -rf /")
    line = json.dumps(rec) + "\n"
    category, out = _migrate_one(line)
    assert category == "v0"
    promoted = json.loads(out)
    assert promoted["v"] == 1
    assert promoted["schema_version"] == 1
    assert promoted["mode"] == "enforce"
    assert promoted["hook_id"] == "guard.bash_command_validator"
    assert promoted["event"] == "PreToolUse"
    assert promoted["tool_name"] == "Bash"
    assert promoted["decision"] == "deny"
    assert promoted["reason"] == "rm -rf denied"
    assert promoted["command_excerpt"] == "rm -rf /"
    assert promoted["timestamp"] == "2026-04-30T05:42:34.622360Z"  # +00:00 → Z
    assert "ts" not in promoted
    assert "segments" not in promoted
    assert "base_cmd" not in promoted


def test_migrate_one_v0_passthrough_decision_renamed() -> None:
    rec = _v0_record()  # decision=passthrough
    category, out = _migrate_one(json.dumps(rec) + "\n")
    assert category == "v0"
    assert json.loads(out)["decision"] == "pass"


def test_migrate_one_v0_allow_decision_preserved() -> None:
    rec = _v0_record(decision="allow")
    category, out = _migrate_one(json.dumps(rec) + "\n")
    assert category == "v0"
    assert json.loads(out)["decision"] == "allow"


def test_migrate_one_invalid_json_preserved() -> None:
    line = "not json at all\n"
    category, out = _migrate_one(line)
    assert category == "invalid_json"
    assert out == line


def test_migrate_one_blank_preserved() -> None:
    category, out = _migrate_one("\n")
    assert category == "blank"
    assert out == "\n"


def test_migrate_one_unrecognized_dict_shape_preserved() -> None:
    rec = {"some": "other shape", "with": "no v or ts"}
    line = json.dumps(rec) + "\n"
    category, out = _migrate_one(line)
    assert category == "unrecognized"
    assert out == line


def test_migrate_file_writes_in_place_and_creates_backup(tmp_path: Path) -> None:
    log = tmp_path / "guard-decisions.jsonl"
    log.write_text(
        json.dumps(_v1_record())
        + "\n"
        + json.dumps(_v1_0_record())
        + "\n"
        + json.dumps(_v0_record())
        + "\n",
        encoding="utf-8",
    )
    report = migrate_file(log)
    assert report.total_lines == 3
    assert report.already_v1 == 1
    assert report.promoted_v1_0 == 1
    assert report.promoted_v0 == 1
    assert report.unrecognized == 0
    assert report.backup_path is not None
    assert report.backup_path.exists()
    # All output lines are valid v1 records.
    out_lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    assert all(rec["v"] == 1 for rec in out_lines)
    assert all(rec["mode"] in ("enforce", "shadow", "off") for rec in out_lines)


def test_migrate_file_dry_run_no_write(tmp_path: Path) -> None:
    log = tmp_path / "guard-decisions.jsonl"
    original = json.dumps(_v0_record()) + "\n"
    log.write_text(original, encoding="utf-8")
    report = migrate_file(log, dry_run=True)
    assert report.dry_run is True
    assert report.promoted_v0 == 1
    assert report.backup_path is None
    assert log.read_text(encoding="utf-8") == original


def test_migrate_file_no_backup_flag(tmp_path: Path) -> None:
    log = tmp_path / "guard-decisions.jsonl"
    log.write_text(json.dumps(_v0_record()) + "\n", encoding="utf-8")
    report = migrate_file(log, backup=False)
    assert report.backup_path is None
    # No .bak.* file in the directory.
    assert not list(tmp_path.glob("*.bak.*"))


def test_migrate_file_idempotent(tmp_path: Path) -> None:
    log = tmp_path / "guard-decisions.jsonl"
    log.write_text(json.dumps(_v0_record()) + "\n", encoding="utf-8")
    first = migrate_file(log, backup=False)
    assert first.promoted_v0 == 1
    second = migrate_file(log, backup=False)
    assert second.already_v1 == 1
    assert second.promoted_v0 == 0


def test_migrate_file_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        migrate_file(tmp_path / "nope.jsonl")


def test_migrate_file_handles_blank_and_invalid_lines(tmp_path: Path) -> None:
    log = tmp_path / "guard-decisions.jsonl"
    log.write_text(
        json.dumps(_v1_record()) + "\n" + "\n" + "not json\n" + json.dumps(_v0_record()) + "\n",
        encoding="utf-8",
    )
    report = migrate_file(log, backup=False)
    assert report.already_v1 == 1
    assert report.blank == 1
    assert report.invalid_json == 1
    assert report.promoted_v0 == 1
