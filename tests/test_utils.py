"""Tests for guard._utils."""
# ruff: noqa: S603, PTH111

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from guard import _utils
from guard._utils import (
    GUARD_DECISIONS_PATH,
    _env_int,
    emit_pretooluse_decision,
)

SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")


# === parse_hook_input / make_decision / safe_main (subprocess-based ports) ===


def test_parse_hook_input_valid():
    script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import parse_hook_input
result = parse_hook_input()
import json
print(json.dumps(result))
"""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    result = subprocess.run(
        [sys.executable, "-c", script],
        input=payload,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    assert parsed["tool_name"] == "Bash"
    assert parsed["tool_input"]["command"] == "ls"


def test_parse_hook_input_invalid_json():
    script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import parse_hook_input
result = parse_hook_input()
print("NONE" if result is None else "NOT_NONE")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        input="not json{{{",
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "NONE"


def test_parse_hook_input_empty():
    script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import parse_hook_input
result = parse_hook_input()
print("NONE" if result is None else "NOT_NONE")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        input="",
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "NONE"


def test_make_decision_deny():
    script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import make_decision
print(make_decision("deny", "blocked for testing"))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert output["hookSpecificOutput"]["permissionDecisionReason"] == "blocked for testing"


def test_make_decision_allow():
    script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import make_decision
print(make_decision("allow", "safe command"))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_safe_main_success():
    hook_script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import safe_main, make_decision

def my_hook(payload):
    cmd = payload.get("tool_input", {{}}).get("command", "")
    if cmd == "dangerous":
        print(make_decision("deny", "blocked"))
        sys.exit(2)

safe_main(my_hook)
"""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    result = subprocess.run(
        [sys.executable, "-c", hook_script],
        input=payload,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "dangerous"}})
    result = subprocess.run(
        [sys.executable, "-c", hook_script],
        input=payload,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_safe_main_exception_passthrough():
    hook_script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import safe_main

def my_hook(payload):
    raise RuntimeError("hook crashed")

safe_main(my_hook)
"""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    result = subprocess.run(
        [sys.executable, "-c", hook_script],
        input=payload,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_safe_main_invalid_json_passthrough():
    hook_script = f"""
import sys
sys.path.insert(0, {SRC_DIR!r})
from guard._utils import safe_main

def my_hook(payload):
    raise AssertionError("should not be called")

safe_main(my_hook)
"""
    result = subprocess.run(
        [sys.executable, "-c", hook_script],
        input="not json",
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


# === DD-17: JSONL path is user-scope (~/.claude/), not plugins/cache ===


def test_jsonl_path_user_scope() -> None:
    resolved = (
        os.path.expanduser(GUARD_DECISIONS_PATH)
        if isinstance(GUARD_DECISIONS_PATH, str)
        else str(GUARD_DECISIONS_PATH)
    )
    assert resolved.startswith(os.path.expanduser("~/.claude/"))
    assert "plugins/cache" not in resolved
    assert resolved.endswith("guard-decisions.jsonl")


# === DD-16: emit_pretooluse_decision modern envelope shape ===


def test_emit_pretooluse_decision_modern_shape() -> None:
    result = emit_pretooluse_decision("deny", "test reason")
    hso = result["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "test reason"


def test_emit_pretooluse_decision_with_optional_fields() -> None:
    result = emit_pretooluse_decision(
        "allow",
        "ok",
        updated_input={"command": "ls"},
        additional_context="from test",
    )
    hso = result["hookSpecificOutput"]
    assert hso["updatedInput"] == {"command": "ls"}
    assert hso["additionalContext"] == "from test"


def test_emit_pretooluse_decision_omits_optional_when_none() -> None:
    result = emit_pretooluse_decision("allow", "ok")
    assert "updatedInput" not in result["hookSpecificOutput"]
    assert "additionalContext" not in result["hookSpecificOutput"]


# === _env_int: malformed/unset handling ===


def test_env_int_unset_returns_default() -> None:
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("FAKE_VAR_X", None)
        assert _env_int("FAKE_VAR_X", 42) == 42


def test_env_int_valid_returns_parsed() -> None:
    with mock.patch.dict(os.environ, {"FAKE_VAR_X": "7"}):
        assert _env_int("FAKE_VAR_X", 42) == 7


def test_env_int_malformed_falls_back_to_default() -> None:
    with mock.patch.dict(os.environ, {"FAKE_VAR_X": "not-a-number"}):
        assert _env_int("FAKE_VAR_X", 42) == 42


# === Real I/O smoke: circuit breaker file round-trip ===
# `_utils.py` doesn't expose a JSONL writer (decision logging happens via the
# downstream hooks themselves), so we exercise a real-I/O path that the module
# does own: the circuit breaker state file.


def test_circuit_breaker_round_trip(tmp_path: Path, monkeypatch) -> None:
    """record_failure writes JSON state; check_circuit reads it; record_success clears it."""
    circuit_file = tmp_path / "circuit.json"
    monkeypatch.setattr(_utils, "CIRCUIT_FILE", circuit_file)

    # Closed when no file
    assert _utils.check_circuit("hook_a") is True

    # One failure: still closed (under threshold)
    _utils.record_failure("hook_a")
    assert circuit_file.exists()
    state = json.loads(circuit_file.read_text())
    assert state["hook_a"]["failures"] == 1
    assert _utils.check_circuit("hook_a") is True

    # Success clears that hook's entry
    _utils.record_success("hook_a")
    assert not circuit_file.exists()
