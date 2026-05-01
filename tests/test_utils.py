"""Tests for guard._utils."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from guard._utils import (
    GUARD_DECISIONS_PATH,
    _env_int,
    all_paths_in,
    append_jsonl,
    emit_pretooluse_decision,
    is_autonomous_mode,
    log_decision,
    sanitize_for_stderr,
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
    """Malformed JSON fails closed with rc=2 instead of silently passing."""
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
    assert result.returncode == 2
    assert "malformed JSON" in result.stderr


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
    """Malformed JSON triggers a fail-closed exit (rc=2) via
    parse_hook_input -> sys.exit(2). safe_main re-raises SystemExit so the
    wrapper exits with the same code.
    """
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
    assert result.returncode == 2
    assert "malformed JSON" in result.stderr


# === JSONL path is user-scope (~/.claude/), not plugins/cache ===


def test_jsonl_path_user_scope() -> None:
    resolved = (
        os.path.expanduser(GUARD_DECISIONS_PATH)
        if isinstance(GUARD_DECISIONS_PATH, str)
        else str(GUARD_DECISIONS_PATH)
    )
    assert resolved.startswith(os.path.expanduser("~/.claude/"))
    assert "plugins/cache" not in resolved
    assert resolved.endswith("guard-decisions.jsonl")


# === emit_pretooluse_decision envelope shape ===


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


def test_emit_pretooluse_decision_ask() -> None:
    """Advisory hooks (e.g. protected_files) emit 'ask' to surface a prompt."""
    result = emit_pretooluse_decision("ask", "confirm edit to protected file")
    hso = result["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "ask"
    assert hso["permissionDecisionReason"] == "confirm edit to protected file"


# === _env_int: malformed/unset handling ===


def test_is_autonomous_mode_when_unset() -> None:
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CLAUDE_AUTONOMOUS", None)
        assert is_autonomous_mode() is False


def test_is_autonomous_mode_when_set() -> None:
    with mock.patch.dict(os.environ, {"CLAUDE_AUTONOMOUS": "1"}):
        assert is_autonomous_mode() is True


def test_is_autonomous_mode_when_set_to_zero() -> None:
    with mock.patch.dict(os.environ, {"CLAUDE_AUTONOMOUS": "0"}):
        assert is_autonomous_mode() is False


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


# === log_decision: spec-compliant JSONL writer ===


def test_log_decision_writes_all_required_fields(tmp_path: Path, monkeypatch) -> None:
    """log_decision emits the schema v1 record with every required field."""
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="testing",
        command_excerpt="ls -la",
        session_id="sess-1",
        cwd="/tmp/work",
    )

    line = jsonl.read_text().splitlines()[-1]
    record = json.loads(line)
    assert record["schema_version"] == 1
    assert record["hook_id"] == "guard.test_hook"
    assert record["event"] == "PreToolUse"
    assert record["tool_name"] == "Bash"
    assert record["decision"] == "deny"
    assert record["reason"] == "testing"
    assert record["command_excerpt"] == "ls -la"
    assert record["session_id"] == "sess-1"
    assert record["cwd"] == "/tmp/work"
    # Timestamp must end with Z (UTC) and parse as ISO-8601
    assert record["timestamp"].endswith("Z")


def test_log_decision_omits_optional_fields(tmp_path: Path, monkeypatch) -> None:
    """When optional fields are None, the record omits them."""
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name=None,
        decision="allow",
        reason="ok",
    )

    record = json.loads(jsonl.read_text().splitlines()[-1])
    assert "command_excerpt" not in record
    assert "cwd" not in record
    assert record["tool_name"] is None
    assert record["session_id"] == ""


def test_log_decision_truncates_long_reason(tmp_path: Path, monkeypatch) -> None:
    """Reason is truncated to 1024 chars."""
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="x" * 5000,
    )

    record = json.loads(jsonl.read_text().splitlines()[-1])
    assert len(record["reason"]) == 1024


def test_log_decision_record_under_4096_bytes(tmp_path: Path, monkeypatch) -> None:
    """Total record size honours the 4096-byte envelope."""
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="x" * 4000,
        command_excerpt="y" * 8000,
    )

    raw = jsonl.read_bytes().splitlines()[-1] + b"\n"
    assert len(raw) <= 4096


def test_log_decision_oversize_record_is_valid_json(tmp_path: Path, monkeypatch) -> None:
    """Oversize records must remain valid JSON with the truncation marker.

    Spec contract (docs/output-format.md §5): records ≤ 4096 bytes AND parseable
    as JSON. Field-by-field truncation, never byte-slice.
    """
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="r" * 4000,
        command_excerpt="c" * 8000,
    )

    line = jsonl.read_bytes().splitlines()[-1]
    record = json.loads(line)  # raises if byte-sliced
    assert record["decision"] == "deny"
    assert record["hook_id"] == "guard.test_hook"
    assert record["schema_version"] == 1
    assert "timestamp" in record
    # At least one truncatable field carries the marker.
    assert any(
        isinstance(record.get(f), str) and "…[truncated]" in record[f]
        for f in ("command_excerpt", "reason")
    )


def test_is_autonomous_mode_accepts_string_truthy(monkeypatch) -> None:
    """`CLAUDE_AUTONOMOUS=true|yes|on|1` (case-insensitive) all enable strict mode."""
    for value in ("1", "true", "True", "TRUE", "yes", "YES", "on", "ON", "  true "):
        monkeypatch.setenv("CLAUDE_AUTONOMOUS", value)
        assert is_autonomous_mode(), f"truthy value rejected: {value!r}"


def test_is_autonomous_mode_rejects_falsy(monkeypatch) -> None:
    for value in ("", "0", "false", "no", "off", "anything-else"):
        monkeypatch.setenv("CLAUDE_AUTONOMOUS", value)
        assert not is_autonomous_mode(), f"falsy value accepted: {value!r}"


def test_append_jsonl_concurrent_writes_all_parse(tmp_path: Path) -> None:
    """50-way concurrent writes must all produce valid JSON lines."""
    from concurrent.futures import ThreadPoolExecutor

    jsonl = tmp_path / "concurrent.jsonl"

    def writer(i: int) -> None:
        append_jsonl(
            jsonl,
            {"schema_version": 1, "decision": "allow", "i": i, "pad": "x" * 200},
        )

    with ThreadPoolExecutor(max_workers=50) as pool:
        list(pool.map(writer, range(50)))

    lines = jsonl.read_bytes().splitlines()
    assert len(lines) == 50
    for line in lines:
        json.loads(line)  # raises on any interleaved or truncated record


# === sanitize_for_stderr: strip control characters ===


def test_sanitize_for_stderr_strips_ansi() -> None:
    """ANSI escape sequences are replaced with '?'."""
    text = "hello\x1b[31mRED\x1b[0mworld"
    result = sanitize_for_stderr(text)
    assert "\x1b" not in result
    assert "?" in result


def test_sanitize_for_stderr_truncates() -> None:
    """Output is capped at max_len."""
    result = sanitize_for_stderr("a" * 500, max_len=100)
    assert len(result) == 100


def test_sanitize_for_stderr_preserves_normal_text() -> None:
    """Normal printable text passes through unchanged."""
    text = "ls -la /tmp/foo"
    assert sanitize_for_stderr(text) == text


# === all_paths_in (universal path scanner) ===


def test_all_paths_in_extracts_absolute_path():
    paths = list(all_paths_in({"file_path": "/Users/dev/.aws/credentials"}))
    assert "/Users/dev/.aws/credentials" in paths


def test_all_paths_in_extracts_tilde_path():
    paths = list(all_paths_in({"command": "cat ~/.aws/credentials"}))
    assert "~/.aws/credentials" in paths


def test_all_paths_in_expands_home_var():
    paths = list(all_paths_in({"command": "cat $HOME/.aws/credentials"}))
    assert "$HOME/.aws/credentials" in paths
    home = str(Path.home())
    assert f"{home}/.aws/credentials" in paths


def test_all_paths_in_expands_braced_home_var():
    paths = list(all_paths_in({"command": "cat ${HOME}/.aws/credentials"}))
    home = str(Path.home())
    assert f"{home}/.aws/credentials" in paths


def test_all_paths_in_recurses_into_lists():
    paths = list(all_paths_in([{"a": "/etc/foo"}, {"b": "/var/bar"}]))
    assert "/etc/foo" in paths
    assert "/var/bar" in paths


def test_all_paths_in_strips_file_url():
    paths = list(all_paths_in({"url": "file:///etc/passwd"}))
    assert "/etc/passwd" in paths


def test_all_paths_in_dedupes():
    paths = list(all_paths_in({"a": "/etc/foo", "b": "/etc/foo"}))
    assert paths.count("/etc/foo") == 1


def test_all_paths_in_ignores_pure_strings_without_paths():
    paths = list(all_paths_in({"text": "just some text no paths here"}))
    assert paths == []
