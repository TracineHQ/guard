# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for guard._utils."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard._utils import (
    GUARD_DECISIONS_PATH,
    all_paths_in,
    append_jsonl,
    emit_pretooluse_decision,
    is_strict_mode,
    log_decision,
    read_permission_mode,
    sanitize_for_stderr,
)

SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")


@pytest.fixture
def guard_decisions_jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``guard._utils.GUARD_DECISIONS_PATH`` to an isolated JSONL.

    ``GUARD_DECISIONS_PATH`` is a module-level constant captured at import time;
    ``log_decision`` reads it directly. Patching the attribute (not the env
    var) is the right tool here.
    """
    jsonl = tmp_path / "decisions.jsonl"
    monkeypatch.setattr("guard._utils.GUARD_DECISIONS_PATH", str(jsonl))
    return jsonl


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


def test_read_permission_mode_default_when_missing() -> None:
    assert read_permission_mode({}) == "default"
    assert read_permission_mode(None) == "default"


@pytest.mark.parametrize(
    "mode", ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"]
)
def test_read_permission_mode_returns_value(mode: str) -> None:
    assert read_permission_mode({"permission_mode": mode}) == mode


def test_read_permission_mode_strips_whitespace() -> None:
    assert read_permission_mode({"permission_mode": "  dontAsk  "}) == "dontAsk"


def test_read_permission_mode_ignores_non_string() -> None:
    assert read_permission_mode({"permission_mode": 1}) == "default"
    assert read_permission_mode({"permission_mode": None}) == "default"
    assert read_permission_mode({"permission_mode": ""}) == "default"


def test_is_strict_mode_true_for_unattended_modes() -> None:
    """auto, dontAsk, bypassPermissions all imply no human at the prompt."""
    assert is_strict_mode({"permission_mode": "auto"}) is True
    assert is_strict_mode({"permission_mode": "dontAsk"}) is True
    assert is_strict_mode({"permission_mode": "bypassPermissions"}) is True


@pytest.mark.parametrize("mode", ["default", "plan", "acceptEdits"])
def test_is_strict_mode_false_for_attended_modes(mode: str) -> None:
    assert is_strict_mode({"permission_mode": mode}) is False


def test_is_strict_mode_false_when_missing() -> None:
    assert is_strict_mode({}) is False
    assert is_strict_mode(None) is False


# === log_decision: spec-compliant JSONL writer ===


def test_log_decision_writes_all_required_fields(guard_decisions_jsonl: Path) -> None:
    """log_decision emits the schema v1 record with every required field."""
    jsonl = guard_decisions_jsonl

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


def test_log_decision_omits_optional_fields(guard_decisions_jsonl: Path) -> None:
    """When optional fields are None, the record omits them."""
    jsonl = guard_decisions_jsonl

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


def test_log_decision_truncates_long_reason(guard_decisions_jsonl: Path) -> None:
    """Reason is truncated to 1024 chars."""
    jsonl = guard_decisions_jsonl

    log_decision(
        hook_id="guard.test_hook",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="x" * 5000,
    )

    record = json.loads(jsonl.read_text().splitlines()[-1])
    assert len(record["reason"]) == 1024


def test_log_decision_record_under_4096_bytes(guard_decisions_jsonl: Path) -> None:
    """Total record size honours the 4096-byte envelope."""
    jsonl = guard_decisions_jsonl

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


def test_log_decision_oversize_record_is_valid_json(guard_decisions_jsonl: Path) -> None:
    """Oversize records must remain valid JSON with the truncation marker.

    Spec contract (docs/output-format.md §5): records ≤ 4096 bytes AND parseable
    as JSON. Field-by-field truncation, never byte-slice.
    """
    jsonl = guard_decisions_jsonl

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


# Synthetic credential shapes used to verify the log-redaction catalog.
# All values are intentionally fake — pragma allowlists silence the
# detect-secrets pre-push hook on each line.
REDACTION_CASES = [
    ("AKIAIOSFODNN7EXAMPLE", "[REDACTED-AWS-ID]"),  # pragma: allowlist secret
    ("ASIAEXAMPLE12345ABCD", "[REDACTED-AWS-ID]"),  # pragma: allowlist secret
    ("sk-ant-api03-" + "a" * 64, "[REDACTED-ANTHROPIC-KEY]"),  # pragma: allowlist secret
    ("sk-proj-" + "B" * 32, "[REDACTED-OPENAI-PROJECT-KEY]"),  # pragma: allowlist secret
    ("github_pat_" + "A" * 82, "[REDACTED-GITHUB-PAT]"),  # pragma: allowlist secret
    ("ghp_" + "0" * 36, "[REDACTED-GITHUB-TOKEN]"),  # pragma: allowlist secret
    ("ghs_" + "0" * 36, "[REDACTED-GITHUB-TOKEN]"),  # pragma: allowlist secret
    ("glpat-" + "A" * 20, "[REDACTED-GITLAB-PAT]"),  # pragma: allowlist secret
    ("xoxb-1234567890-abcdef", "[REDACTED-SLACK-TOKEN]"),  # pragma: allowlist secret
    ("xoxe-1234567890-abcdef", "[REDACTED-SLACK-TOKEN]"),  # pragma: allowlist secret
    ("rk_live_" + "A" * 24, "[REDACTED-STRIPE-KEY]"),  # pragma: allowlist secret
    ("sk_test_" + "A" * 24, "[REDACTED-STRIPE-KEY]"),  # pragma: allowlist secret
    ("SG." + "A" * 22 + "." + "B" * 43, "[REDACTED-SENDGRID-KEY]"),  # pragma: allowlist secret
    ("npm_" + "A" * 36, "[REDACTED-NPM-TOKEN]"),  # pragma: allowlist secret
    ("pypi-AgEIcHlwaS5vcmc" + "A" * 80, "[REDACTED-PYPI-TOKEN]"),  # pragma: allowlist secret
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",  # pragma: allowlist secret
        "[REDACTED-JWT]",
    ),
]


@pytest.mark.parametrize(("secret", "marker"), REDACTION_CASES)
def test_log_decision_redacts_known_secret_shapes(
    secret: str,
    marker: str,
    guard_decisions_jsonl: Path,
) -> None:
    """Each known credential shape must be replaced before persistence."""
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason=f"caught: {secret}",
        command_excerpt=f"echo {secret}",
        session_id="redaction-test",
    )
    line = guard_decisions_jsonl.read_text("utf-8").strip()
    assert secret not in line, f"{secret!r} survived redaction in: {line}"
    assert marker in line, f"{marker} missing from log line: {line}"


def test_log_decision_redacts_pem_block(guard_decisions_jsonl: Path) -> None:
    """Multi-line PEM private key blocks must collapse to a single placeholder."""
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"  # pragma: allowlist secret
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz\n"  # pragma: allowlist secret
        "c2gtcnNhAAAAAwEAAQ==\n"  # pragma: allowlist secret
        "-----END OPENSSH PRIVATE KEY-----"  # pragma: allowlist secret
    )
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Write",
        decision="deny",
        reason=f"sees key: {pem}",
        session_id="redaction-test",
    )
    line = guard_decisions_jsonl.read_text("utf-8").strip()
    assert "BEGIN OPENSSH PRIVATE KEY" not in line  # pragma: allowlist secret
    assert "[REDACTED-PRIVATE-KEY]" in line


def test_log_decision_redacts_authorization_bearer(guard_decisions_jsonl: Path) -> None:
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="curl with auth",
        command_excerpt='curl -H "Authorization: Bearer abcdef-real-token-here" https://x',
        session_id="redaction-test",
    )
    line = guard_decisions_jsonl.read_text("utf-8").strip()
    assert "abcdef-real-token-here" not in line
    assert "[REDACTED]" in line


def test_log_decision_redacts_credential_named_kv(guard_decisions_jsonl: Path) -> None:
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="env-set leak",
        command_excerpt="aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",  # pragma: allowlist secret
        session_id="redaction-test",
    )
    line = guard_decisions_jsonl.read_text("utf-8").strip()
    assert "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY" not in line  # pragma: allowlist secret
    assert "[REDACTED]" in line


def test_append_jsonl_refuses_to_follow_symlink(tmp_path: Path) -> None:
    """O_NOFOLLOW: pre-planted symlink at the log path must not be followed.

    Without this, an attacker that pre-creates
    ``~/.claude/guard-decisions.jsonl -> /etc/cron.d/x`` could turn guard's
    append into an arbitrary-write primitive.
    """
    target = tmp_path / "actual-target.txt"
    target.write_text("untouched")
    link_path = tmp_path / "guard-decisions.jsonl"
    link_path.symlink_to(target)

    append_jsonl(link_path, {"schema_version": 1, "decision": "allow"})

    # Target must be byte-for-byte unchanged; the append silently fails.
    assert target.read_text() == "untouched"


def test_append_jsonl_silently_swallows_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing ``os.write`` (e.g. ENOSPC) must not propagate or partially-write.

    Per ``docs/JSONL_FORMAT.md`` §5: the writer fails silently on any
    ``OSError`` — guard's "guardrails not walls" contract means a logging
    failure must never block legitimate work.
    """
    jsonl = tmp_path / "decisions.jsonl"

    def fake_write(_fd: int, _buf: bytes) -> int:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr("guard._utils.os.write", fake_write)

    # Must not raise.
    result = append_jsonl(jsonl, {"schema_version": 1, "decision": "allow"})

    assert result is None
    # The file may have been created (O_CREAT) but no record bytes were written.
    if jsonl.exists():
        assert jsonl.read_bytes() == b""


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


def test_all_paths_in_skips_empty_strings():
    """Empty strings in the payload are skipped before regex search."""
    paths = list(all_paths_in({"empty": "", "real": "/etc/foo"}))
    assert paths == ["/etc/foo"]


# === In-process coverage for paths that subprocess tests skip ===
#
# parse_hook_input / make_decision / safe_main / log_internal_error are
# covered by subprocess tests above for end-to-end behavior, but coverage.py
# attributes those lines to the subprocess (which is dropped). The tests
# below exercise the same code paths inside the pytest process so coverage
# can see them.


def test_token_basename_returns_basename():
    from guard._utils import token_basename

    assert token_basename("/usr/bin/python3") == "python3"
    assert token_basename("python3") == "python3"
    assert token_basename("./foo/bar") == "bar"


def test_make_decision_in_process_shape():
    from guard._utils import make_decision

    out = json.loads(make_decision("deny", "no"))
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert hso["permissionDecisionReason"] == "no"


def test_redact_secrets_empty_string_short_circuits():
    """Empty input returns immediately without iterating the regex catalog."""
    from guard._utils import _redact_secrets

    assert _redact_secrets("") == ""


def test_log_decision_writes_permission_mode_and_extra(guard_decisions_jsonl: Path) -> None:
    """The optional ``permission_mode`` and ``extra`` merge paths get written verbatim."""
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="deny",
        reason="x",
        permission_mode="dontAsk",
        extra={"unknown_flags": ["--foo"], "matched_rule": "R-1"},
    )
    record = json.loads(guard_decisions_jsonl.read_text().splitlines()[-1])
    assert record["permission_mode"] == "dontAsk"
    assert record["unknown_flags"] == ["--foo"]
    assert record["matched_rule"] == "R-1"


def test_log_decision_falsy_extra_is_not_merged(guard_decisions_jsonl: Path) -> None:
    """Passing an empty ``extra`` dict must not crash and must not pollute the record."""
    log_decision(
        hook_id="guard.test",
        event="PreToolUse",
        tool_name="Bash",
        decision="allow",
        reason="ok",
        extra={},
    )
    record = json.loads(guard_decisions_jsonl.read_text().splitlines()[-1])
    # All canonical fields present, no spurious keys from extra={}.
    assert record["decision"] == "allow"


def test_log_internal_error_writes_hashed_traceback(guard_decisions_jsonl: Path) -> None:
    """``log_internal_error`` emits a structured record with a sha256 traceback hash."""
    from guard._utils import log_internal_error

    try:
        msg = "boom"
        raise RuntimeError(msg)  # noqa: TRY301 -- intentional: synthesise an exc to capture
    except RuntimeError as exc:
        log_internal_error(exc, session_id="sess-99")

    record = json.loads(guard_decisions_jsonl.read_text().splitlines()[-1])
    assert record["type"] == "internal_error"
    assert record["exc_class"] == "RuntimeError"
    assert record["exc_msg"] == "boom"
    assert record["session_id"] == "sess-99"
    assert record["traceback_hash"].startswith("sha256:")
    # Hashed 16 hex chars + ``sha256:`` prefix.
    assert len(record["traceback_hash"]) == len("sha256:") + 16


def test_log_internal_error_redacts_secret_in_message(guard_decisions_jsonl: Path) -> None:
    """If the exception message carries a credential shape it must be redacted."""
    from guard._utils import log_internal_error

    secret = "ghp_" + "0" * 36  # pragma: allowlist secret
    try:
        msg = f"crashed with token {secret}"
        raise RuntimeError(msg)  # noqa: TRY301 -- intentional: synthesise an exc to capture
    except RuntimeError as exc:
        log_internal_error(exc)

    record = json.loads(guard_decisions_jsonl.read_text().splitlines()[-1])
    assert secret not in record["exc_msg"]
    assert "[REDACTED-GITHUB-TOKEN]" in record["exc_msg"]


def test_parse_hook_input_oversize_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    """stdin > 1 MiB triggers ``sys.exit(2)`` with a stderr note."""
    from io import BytesIO

    from guard import _utils

    oversize = b"x" * (2 << 20)

    class FakeStdin:
        buffer = BytesIO(oversize)

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())
    with pytest.raises(SystemExit) as excinfo:
        _utils.parse_hook_input()
    assert excinfo.value.code == 2


def test_parse_hook_input_oserror_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``OSError`` from the stdin read collapses to ``None`` (fail-open)."""
    from guard import _utils

    class BrokenBuffer:
        def read(self, _n: int) -> bytes:
            msg = "stdin gone"
            raise OSError(msg)

    class FakeStdin:
        buffer = BrokenBuffer()

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())
    assert _utils.parse_hook_input() is None


def test_parse_hook_input_non_dict_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid JSON top-level array (not a dict) collapses to ``None``."""
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b'["not-a-dict"]')

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())
    assert _utils.parse_hook_input() is None


def test_parse_hook_input_valid_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b'{"tool_name": "Bash"}')

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())
    assert _utils.parse_hook_input() == {"tool_name": "Bash"}


def test_parse_hook_input_malformed_json_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed JSON triggers ``sys.exit(2)`` with a stderr note (fail-closed)."""
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b"not-json{{{")

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())
    with pytest.raises(SystemExit) as excinfo:
        _utils.parse_hook_input()
    assert excinfo.value.code == 2


def test_safe_main_in_process_passthrough_on_exception(
    monkeypatch: pytest.MonkeyPatch,
    guard_decisions_jsonl: Path,
) -> None:
    """``safe_main`` catches generic exceptions, logs an internal-error record, and returns."""
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b'{"tool_name": "Bash", "session_id": "abc"}')

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())

    def crashing_hook(_payload: dict) -> None:
        msg = "crashed"
        raise RuntimeError(msg)

    # Must not raise.
    _utils.safe_main(crashing_hook)

    # And it must have written an internal_error record with the session_id.
    record = json.loads(guard_decisions_jsonl.read_text().splitlines()[-1])
    assert record["type"] == "internal_error"
    assert record["session_id"] == "abc"


def test_safe_main_debug_branch_emits_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With ``GUARD_DEBUG=1`` set, the crash branch writes the traceback to stderr."""
    from io import BytesIO

    from guard import _utils

    monkeypatch.setenv("GUARD_DEBUG", "1")

    class FakeStdin:
        buffer = BytesIO(b'{"tool_name": "Bash"}')

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())

    def crashing_hook(_payload: dict) -> None:
        msg = "boom-debug"
        raise RuntimeError(msg)

    _utils.safe_main(crashing_hook)
    err = capsys.readouterr().err
    assert "hook crashed" in err
    assert "boom-debug" in err


def test_safe_main_reraises_systemexit(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SystemExit`` from the hook function propagates, not swallowed."""
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b'{"tool_name": "Bash"}')

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())

    def denying_hook(_payload: dict) -> None:
        raise SystemExit(2)

    with pytest.raises(SystemExit) as excinfo:
        _utils.safe_main(denying_hook)
    assert excinfo.value.code == 2


def test_safe_main_returns_when_payload_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty stdin yields ``None`` payload; the hook fn is not called."""
    from io import BytesIO

    from guard import _utils

    class FakeStdin:
        buffer = BytesIO(b"")

    monkeypatch.setattr(_utils.sys, "stdin", FakeStdin())

    called = []

    def hook_fn(_payload: dict) -> None:
        called.append(True)

    _utils.safe_main(hook_fn)
    assert called == []


# === CLAUDE_AUTONOMOUS deprecation fallback (env-var, one-cycle window) ===


def test_read_permission_mode_env_fallback_emits_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Legacy ``CLAUDE_AUTONOMOUS=1`` escalates to ``dontAsk`` + writes a deprecation note."""
    monkeypatch.setenv("CLAUDE_AUTONOMOUS", "1")
    # Point sentinel dir at fresh tmp_path so it doesn't pre-exist.
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path / "guard-home-warn"))
    from guard import _utils

    _utils._CLAUDE_AUTONOMOUS_WARNED["once"] = False  # noqa: SLF001 -- reset warn-once flag

    mode = _utils.read_permission_mode({})
    assert mode == "dontAsk"
    err = capsys.readouterr().err
    assert "CLAUDE_AUTONOMOUS is deprecated" in err

    # Sentinel file gets created so subsequent invocations skip the stderr write.
    sentinel = tmp_path / "guard-home-warn" / ".autonomous-warned"
    assert sentinel.exists()


def test_read_permission_mode_env_fallback_silent_after_sentinel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """When the sentinel exists, the warning is suppressed."""
    monkeypatch.setenv("CLAUDE_AUTONOMOUS", "yes")
    home = tmp_path / "guard-home-silent"
    monkeypatch.setenv("GUARD_DATA_DIR", str(home))
    home.mkdir(parents=True)
    (home / ".autonomous-warned").touch()

    from guard import _utils

    _utils._CLAUDE_AUTONOMOUS_WARNED["once"] = False  # noqa: SLF001 -- reset warn-once flag

    mode = _utils.read_permission_mode({})
    assert mode == "dontAsk"
    assert "deprecated" not in capsys.readouterr().err


def test_emit_autonomous_deprecation_warning_short_circuits_after_first_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Once the in-process ``_CLAUDE_AUTONOMOUS_WARNED`` flag is set, the function returns early."""
    from guard import _utils

    _utils._CLAUDE_AUTONOMOUS_WARNED["once"] = True  # noqa: SLF001 -- set warn-once flag
    _utils._emit_autonomous_deprecation_warning()  # noqa: SLF001 -- module-private
    assert capsys.readouterr().err == ""


def test_read_permission_mode_env_fallback_oserror_falls_back_to_in_proc_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``Path.exists`` raising ``OSError`` is suppressed; warning still fires once."""
    monkeypatch.setenv("CLAUDE_AUTONOMOUS", "true")
    from guard import _utils

    _utils._CLAUDE_AUTONOMOUS_WARNED["once"] = False  # noqa: SLF001 -- reset warn-once flag

    real_exists = Path.exists

    def boom(self: Path) -> bool:
        if self.name == ".autonomous-warned":
            msg = "denied"
            raise OSError(msg)
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", boom)

    mode = _utils.read_permission_mode({})
    assert mode == "dontAsk"
    assert "deprecated" in capsys.readouterr().err


# === _shrink_to_envelope corner cases ===


def test_shrink_to_envelope_handles_missing_truncatable_field() -> None:
    """When ``command_excerpt`` is absent, only ``reason`` is shrunk."""
    from guard._utils import _shrink_to_envelope

    entry = {
        "schema_version": 1,
        "decision": "deny",
        "hook_id": "guard.x",
        "timestamp": "t",
        "reason": "r" * 6000,
    }
    line = _shrink_to_envelope(entry)
    assert len(line) <= 4096
    parsed = json.loads(line)
    assert "command_excerpt" not in parsed
    assert "…[truncated]" in parsed["reason"]


def test_shrink_to_envelope_skips_non_string_field() -> None:
    """A non-string ``reason`` is skipped (continue branch), but the line still must fit."""
    from guard._utils import _shrink_to_envelope

    entry = {
        "schema_version": 1,
        "decision": "deny",
        "hook_id": "guard.x",
        "timestamp": "t",
        "reason": 12345,  # not a string -> skip shrink for this field
        "command_excerpt": "c" * 6000,
    }
    line = _shrink_to_envelope(entry)
    assert len(line) <= 4096
    parsed = json.loads(line)
    assert parsed["reason"] == 12345


def test_shrink_to_envelope_skips_empty_string_field() -> None:
    """An empty truncatable field is skipped without iteration.

    Force the loop to actually reach ``reason`` by leaving ``command_excerpt``
    empty (so the binary-search-shrink branch doesn't fit the record on the
    first iteration). Hits the ``if not original: continue`` skip on the
    second iteration when ``reason`` is also empty isn't possible because
    that wouldn't overflow; the realistic shape is empty ``command_excerpt``
    + huge ``reason``.
    """
    from guard._utils import _shrink_to_envelope

    entry = {
        "schema_version": 1,
        "decision": "deny",
        "hook_id": "guard.x",
        "timestamp": "t",
        "reason": "r" * 6000,
        "command_excerpt": "",
    }
    line = _shrink_to_envelope(entry)
    assert len(line) <= 4096
    parsed = json.loads(line)
    assert parsed["command_excerpt"] == ""
    assert "…[truncated]" in parsed["reason"]


def test_shrink_to_envelope_falls_back_to_minimal_record() -> None:
    """When non-truncatable fields alone overflow, the minimal-record path runs.

    Forced by giving ``hook_id`` a huge non-truncatable value: after both
    truncatable fields collapse to bare markers the line still exceeds 4 KiB,
    triggering the last-resort minimal record.
    """
    from guard._utils import _shrink_to_envelope

    entry = {
        "v": 1,
        "schema_version": 1,
        "mode": "enforce",
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "hook_id": "g." + "x" * 5000,  # huge non-truncatable
        "decision": "deny",
        "reason": "r" * 10,
        "command_excerpt": "c" * 10,
    }
    line = _shrink_to_envelope(entry)
    # The minimal record is small and parseable.
    parsed = json.loads(line)
    assert parsed["decision"] == "deny"
    assert parsed["reason"] == "…[truncated]"
    # The huge hook_id is preserved verbatim from the source entry — minimal
    # record carries `hook_id` through unchanged.
    assert parsed["hook_id"].startswith("g.xxx")


def test_log_debug_writes_when_env_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``_log_debug`` is silent unless ``GUARD_DEBUG=1``."""
    from guard._utils import _log_debug

    _log_debug("silent message")
    assert capsys.readouterr().err == ""

    monkeypatch.setenv("GUARD_DEBUG", "1")
    _log_debug("loud message")
    assert "loud message" in capsys.readouterr().err
