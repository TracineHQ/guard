"""Tests for the ``guard`` CLI (read-side query surface)."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import importlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# === since-parser ===


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("7d", timedelta(days=7)),
        ("1h", timedelta(hours=1)),
        ("30m", timedelta(minutes=30)),
        ("  12d ", timedelta(days=12)),
    ],
)
def test_parse_since_valid(text: str, expected: timedelta) -> None:
    from guard.cli import parse_since

    assert parse_since(text) == expected


@pytest.mark.parametrize(
    "text",
    ["", "7", "7y", "abc", "d7", "7 days", "-5d"],
)
def test_parse_since_invalid(text: str) -> None:
    from guard.cli import parse_since

    with pytest.raises(ValueError, match="invalid --since"):
        parse_since(text)


# === Fixture: write a synthetic decision log under decision_log_env ===


def _ts(now: datetime, *, hours_ago: float = 0, days_ago: float = 0) -> str:
    delta = timedelta(hours=hours_ago, days=days_ago)
    return (
        (now - delta).replace(tzinfo=UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _write_log(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


@pytest.fixture
def populated_log(decision_log_env: Path) -> Path:
    """Write a synthetic JSONL covering recent + stale records, multiple hooks."""
    now = datetime.now(tz=UTC).replace(tzinfo=None)
    records = [
        # Very recent — within 7d
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": _ts(now, hours_ago=1),
            "hook_id": "guard.bash_command_validator",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "deny",
            "reason": "git add -A blocked",
            "command_excerpt": "git add -A",
            "session_id": "sess-A",
        },
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": _ts(now, hours_ago=2),
            "hook_id": "guard.bash_command_validator",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "deny",
            "reason": "git add -A blocked again",
            "command_excerpt": "git add -A",
            "session_id": "sess-A",
        },
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": _ts(now, hours_ago=3),
            "hook_id": "guard.bash_command_validator",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "allow",
            "reason": "Read-only",
            "command_excerpt": "ls -la",
            "session_id": "sess-B",
        },
        # 5 days ago — still within 7d
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": _ts(now, days_ago=5),
            "hook_id": "guard.protected_files",
            "event": "PreToolUse",
            "tool_name": "Edit",
            "decision": "ask",
            "reason": "Edit to .env",
            "session_id": "sess-A",
        },
        # 90 days ago — stale (silent for 30d window)
        {
            "v": 1,
            "schema_version": 1,
            "mode": "enforce",
            "timestamp": _ts(now, days_ago=90),
            "hook_id": "guard.git_c_validator",
            "event": "PreToolUse",
            "tool_name": "Bash",
            "decision": "deny",
            "reason": "git -C clean blocked",
            "command_excerpt": "git -C /repo clean -fd",
            "session_id": "sess-old",
        },
    ]
    _write_log(decision_log_env, records)
    return decision_log_env


# === guard status ===


def test_status_returns_log_path_and_count(populated_log: Path) -> None:
    from guard.cli import cmd_status

    payload, pretty = cmd_status()
    assert payload["log_path"] == str(populated_log)
    assert payload["log_exists"] is True
    assert payload["line_count"] == 5
    assert payload["mode"] == "enforce"
    assert payload["schema_version"] == 1
    assert payload["last_record_timestamp"] is not None
    assert "guard " in pretty
    assert "records: 5" in pretty


def test_status_no_log(decision_log_env: Path) -> None:
    from guard.cli import cmd_status

    payload, pretty = cmd_status()
    assert payload["log_exists"] is False
    assert payload["line_count"] == 0
    assert payload["last_record_timestamp"] is None
    assert "exists: no" in pretty


# === guard status: wiring check ===


def test_check_wiring_all_negative(tmp_path: Path, decision_log_env: Path) -> None:
    from guard.cli import _check_wiring

    signals = _check_wiring(home=tmp_path)
    assert signals["plugin_cache_present"] is False
    assert signals["settings_references_guard"] is False
    assert signals["log_has_guard_records"] is False
    assert signals["active"] is False


def test_check_wiring_plugin_cache_versioned_dir(tmp_path: Path, decision_log_env: Path) -> None:
    from guard.cli import _check_wiring

    cache = tmp_path / ".claude" / "plugins" / "cache" / "guard@1.0.0"
    cache.mkdir(parents=True)
    signals = _check_wiring(home=tmp_path)
    assert signals["plugin_cache_present"] is True
    assert signals["active"] is True


def test_check_wiring_plugin_cache_unversioned_dir(tmp_path: Path, decision_log_env: Path) -> None:
    from guard.cli import _check_wiring

    (tmp_path / ".claude" / "plugins" / "cache" / "guard").mkdir(parents=True)
    signals = _check_wiring(home=tmp_path)
    assert signals["plugin_cache_present"] is True
    assert signals["active"] is True


def test_check_wiring_settings_reference(tmp_path: Path, decision_log_env: Path) -> None:
    from guard.cli import _check_wiring

    cdir = tmp_path / ".claude"
    cdir.mkdir()
    (cdir / "settings.json").write_text(
        json.dumps(
            {"hooks": {"PreToolUse": [{"hooks": [{"command": "guard.bash_command_validator"}]}]}}
        ),
        encoding="utf-8",
    )
    signals = _check_wiring(home=tmp_path)
    assert signals["settings_references_guard"] is True
    assert signals["active"] is True


def test_check_wiring_settings_local_path_match(tmp_path: Path, decision_log_env: Path) -> None:
    from guard.cli import _check_wiring

    cdir = tmp_path / ".claude"
    cdir.mkdir()
    (cdir / "settings.local.json").write_text(
        '{"hooks":[{"command":"~/some/guard/hooks/run.py"}]}',
        encoding="utf-8",
    )
    signals = _check_wiring(home=tmp_path)
    assert signals["settings_references_guard"] is True


def test_check_wiring_log_has_guard_records(tmp_path: Path, populated_log: Path) -> None:
    from guard.cli import _check_wiring

    signals = _check_wiring(home=tmp_path)
    assert signals["log_has_guard_records"] is True
    assert signals["active"] is True


def test_status_active_yes_when_wired(
    tmp_path: Path, populated_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import guard.cli as cli_mod

    monkeypatch.setattr(cli_mod.Path, "home", classmethod(lambda _cls: tmp_path))
    (tmp_path / ".claude" / "plugins" / "cache" / "guard").mkdir(parents=True)

    payload, pretty = cli_mod.cmd_status()
    assert payload["active"] is True
    assert payload["wiring"]["plugin_cache_present"] is True
    assert "active: yes" in pretty


def test_status_active_no_emits_remediation(
    tmp_path: Path, decision_log_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import guard.cli as cli_mod

    monkeypatch.setattr(cli_mod.Path, "home", classmethod(lambda _cls: tmp_path))

    payload, pretty = cli_mod.cmd_status()
    assert payload["active"] is False
    assert "active: no" in pretty
    assert "does not appear to be wired" in pretty
    assert "/plugin install guard" in pretty


# === guard noisy ===


def test_noisy_returns_top_n(populated_log: Path) -> None:
    from guard.cli import cmd_noisy

    payload, pretty = cmd_noisy(timedelta(days=7), limit=10)
    top = payload["top"]
    # Bash add-A deny pair fires twice in the recent window; should top.
    assert top
    assert top[0]["hook_id"] == "guard.bash_command_validator"
    assert top[0]["decision"] == "deny"
    assert top[0]["count"] == 2
    # Stale git_c_validator record (90d ago) MUST be excluded.
    hook_ids = [t["hook_id"] for t in top]
    assert "guard.git_c_validator" not in hook_ids
    assert "Top" in pretty


def test_noisy_limit_caps_results(populated_log: Path) -> None:
    from guard.cli import cmd_noisy

    payload, _ = cmd_noisy(timedelta(days=365), limit=2)
    assert len(payload["top"]) <= 2


def test_noisy_filters_by_decision(populated_log: Path) -> None:
    from guard.cli import cmd_noisy

    payload, _ = cmd_noisy(timedelta(days=365), limit=10, decision="deny")
    # Every returned row matches the requested decision.
    assert payload["top"]
    assert all(t["decision"] == "deny" for t in payload["top"])


def test_noisy_filters_by_hook(populated_log: Path) -> None:
    from guard.cli import cmd_noisy

    payload, _ = cmd_noisy(timedelta(days=365), limit=10, hook_id="guard.bash_command_validator")
    assert payload["top"]
    assert all(t["hook_id"] == "guard.bash_command_validator" for t in payload["top"])


def test_noisy_filter_returns_empty_when_no_match(populated_log: Path) -> None:
    from guard.cli import cmd_noisy

    payload, _ = cmd_noisy(timedelta(days=365), limit=10, hook_id="guard.nonexistent")
    assert payload["top"] == []


# === guard silent ===


def test_silent_lists_stale_pairs(populated_log: Path) -> None:
    from guard.cli import cmd_silent

    payload, pretty = cmd_silent(timedelta(days=30))
    silent = payload["silent"]
    # git_c_validator deny is the only pair stale > 30d AND ever-seen.
    silent_keys = [(s["hook_id"], s["decision"]) for s in silent]
    assert ("guard.git_c_validator", "deny") in silent_keys
    # The recent ones must NOT be listed.
    assert ("guard.bash_command_validator", "deny") not in silent_keys
    assert "guard.git_c_validator" in pretty


# === guard trace ===


def test_trace_filters_by_session(populated_log: Path) -> None:
    from guard.cli import cmd_trace

    payload, pretty = cmd_trace("sess-A")
    assert payload["session_id"] == "sess-A"
    # sess-A appears 3 times in the fixture.
    assert payload["count"] == 3
    timestamps = [r["timestamp"] for r in payload["records"]]
    assert timestamps == sorted(timestamps)
    assert "sess-A" in pretty


def test_trace_unknown_session_returns_zero(populated_log: Path) -> None:
    from guard.cli import cmd_trace

    payload, _ = cmd_trace("does-not-exist")
    assert payload["count"] == 0
    assert payload["records"] == []


# === guard test ===


def test_test_denies_rm_rf_root() -> None:
    from guard.cli import cmd_test

    payload, _ = cmd_test("rm -rf /")
    decisions = {r["hook_id"]: r["decision"] for r in payload["results"]}
    assert decisions["guard.bash_command_validator"] == "deny"


def test_test_allows_safe_command() -> None:
    from guard.cli import cmd_test

    payload, _ = cmd_test("ls -la")
    decisions = {r["hook_id"]: r["decision"] for r in payload["results"]}
    # Either allow or passthrough — both are non-deny outcomes.
    assert decisions["guard.bash_command_validator"] in {"allow", "passthrough"}


def test_test_payload_structure() -> None:
    from guard.cli import cmd_test

    payload, _ = cmd_test("ls")
    assert payload["command"] == "ls"
    assert isinstance(payload["results"], list)
    hook_ids = {r["hook_id"] for r in payload["results"]}
    assert "guard.bash_command_validator" in hook_ids
    assert "guard.git_c_validator" in hook_ids
    assert "guard.commit_message_validator" in hook_ids


# === guard diff ===


def test_diff_runs_without_error() -> None:
    from guard.cli import cmd_diff

    payload, pretty = cmd_diff()
    assert "layers" in payload
    assert payload["layers"][0]["name"] == "builtin"
    assert "user/project" in payload["note"]
    assert "Effective merged config" in pretty


# === main() dispatch ===


def test_main_status_returns_zero(populated_log: Path) -> None:
    from guard import cli

    rc = cli.main(["--json", "status"])
    assert rc == 0


def test_main_version_prints_three_lines(capsys) -> None:
    """``guard --version`` mirrors ``gh --version``: name+version, install, repo."""
    from guard import cli

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert len(lines) == 3, f"expected 3 lines, got {lines!r}"
    assert lines[0].startswith("guard ")
    assert "tracine-guard from " in lines[1]
    assert lines[2] == "https://github.com/TracineHQ/guard"


def test_main_no_args_prints_help_to_stderr_and_exits_2(capsys) -> None:
    """No-args returns 2 (POSIX convention for "missing operand")."""
    from guard import cli

    rc = cli.main([])
    assert rc == 2
    captured = capsys.readouterr()
    # Help on stderr, NOT stdout — pipes consuming guard's stdout shouldn't
    # be polluted with usage text on a missing-arg invocation.
    assert "guard read-side CLI" in captured.err
    assert captured.out == ""


def test_main_invalid_since_returns_2(decision_log_env: Path, capsys) -> None:
    from guard import cli

    rc = cli.main(["noisy", "--since", "bogus"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "invalid --since" in captured.err


def test_main_status_json_output_is_valid(populated_log: Path, capsys) -> None:
    from guard import cli

    rc = cli.main(["--json", "status"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["mode"] == "enforce"
    assert parsed["log_path"] == str(populated_log)


# === Reader tolerates malformed and redirect-pointer lines ===


def test_jsonl_reader_skips_malformed_and_redirect(decision_log_env: Path) -> None:
    from guard.cli import JsonlReader

    decision_log_env.write_text(
        json.dumps({"redirect": "/somewhere/else.jsonl"})
        + "\n"
        + "not-json\n"
        + json.dumps(
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
            }
        )
        + "\n"
    )
    reader = JsonlReader(decision_log_env)
    records = list(reader.iter_records())
    assert len(records) == 1
    assert records[0]["hook_id"] == "guard.x"


# === Subprocess invocation of the entry-point script ===


def test_subprocess_python_m_guard_status_zero() -> None:
    """``python -m guard status`` (legacy entry) still works."""
    result = subprocess.run(
        [sys.executable, "-m", "guard", "status"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "guard " in result.stdout


def test_subprocess_python_m_guard_cli_status(decision_log_env: Path) -> None:
    """The new CLI is reachable via ``python -m guard.cli status`` end-to-end."""
    # Write a single record so line_count > 0 and the path is populated.
    _write_log(
        decision_log_env,
        [
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
            }
        ],
    )
    env = {
        **__import__("os").environ,
        "GUARD_DECISIONS_PATH": str(decision_log_env),
        "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "guard.cli", "--json", "status"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["log_path"] == str(decision_log_env)
    assert parsed["line_count"] == 1


def test_module_reload_clean() -> None:
    """Reload guard.cli to ensure no global state corruption between tests."""
    import guard.cli

    importlib.reload(guard.cli)
    assert hasattr(guard.cli, "main")
    assert callable(guard.cli.main)
