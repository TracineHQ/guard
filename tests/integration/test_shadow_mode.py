# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""End-to-end: when allowlist mode is shadow, denies are logged with
mode=shadow but pass through to Claude Code (no exit 2, no envelope on
stdout). Off mode short-circuits the hook entirely. Enforce path is
unchanged.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests._helpers import REPO_ROOT as REPO
from tests._helpers import decision_from_stdout as _decision

HOOK = REPO / "src" / "guard" / "hooks" / "bash_command_validator.py"


def _write_mode(cwd: Path, mode: str) -> None:
    allow_dir = cwd / ".claude" / "guard"
    allow_dir.mkdir(parents=True, exist_ok=True)
    (allow_dir / "allowlist.json").write_text(json.dumps({"mode": mode}))


def _run(command: str, *, cwd: Path, decisions_path: Path) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    env["GUARD_DECISIONS_PATH"] = str(decisions_path)
    env["GUARD_DATA_DIR"] = str(cwd / ".isolated-guard-home")
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(
            {
                "session_id": "shadow-test",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "hook_event_name": "PreToolUse",
                "cwd": str(cwd),
                "permission_mode": "default",
            }
        ),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_shadow_logs_deny_without_enforcing(tmp_path: Path) -> None:
    """In shadow mode, an always-deny command is logged as deny+mode=shadow,
    but stdout is empty and rc=0 so Claude Code passthrough wins.
    """
    _write_mode(tmp_path, "shadow")
    log = tmp_path / "log.jsonl"
    rc, stdout, _stderr = _run("git push --force", cwd=tmp_path, decisions_path=log)

    assert rc == 0, f"shadow must not exit 2; got rc={rc}"
    assert _decision(stdout) is None, f"shadow must not emit deny envelope; got {stdout!r}"
    recs = _records(log)
    assert recs, "decision must still be logged in shadow"
    deny = next((r for r in recs if r.get("decision") == "deny"), None)
    assert deny is not None, f"expected at least one deny record, got {recs!r}"
    assert deny["mode"] == "shadow", f"mode must reflect shadow, got {deny.get('mode')!r}"


def test_enforce_path_unchanged_by_shadow_wiring(tmp_path: Path) -> None:
    """When no allowlist file exists, mode defaults to enforce; deny path
    still exits 2 and emits the envelope.
    """
    log = tmp_path / "log.jsonl"
    rc, stdout, _stderr = _run("git push --force", cwd=tmp_path, decisions_path=log)
    assert rc == 2, f"enforce default must exit 2 on always-deny; got rc={rc}"
    assert _decision(stdout) == "deny", f"enforce must emit deny envelope; got {stdout!r}"
    recs = _records(log)
    deny = next((r for r in recs if r.get("decision") == "deny"), None)
    assert deny is not None
    assert deny["mode"] == "enforce"


def test_off_mode_short_circuits_hook(tmp_path: Path) -> None:
    """mode=off bypasses the hook entirely: no decision, no log entry."""
    _write_mode(tmp_path, "off")
    log = tmp_path / "log.jsonl"
    rc, stdout, _stderr = _run("git push --force", cwd=tmp_path, decisions_path=log)
    assert rc == 0, f"off must exit 0; got rc={rc}"
    assert _decision(stdout) is None, f"off must emit nothing; got {stdout!r}"
    assert not log.exists() or not log.read_text().strip(), (
        f"off must not write a decision row; got {_records(log)!r}"
    )


def test_invalid_mode_falls_back_to_enforce(tmp_path: Path) -> None:
    """An unknown mode string in the allowlist warns + falls back to enforce."""
    _write_mode(tmp_path, "loud")
    log = tmp_path / "log.jsonl"
    rc, stdout, _stderr = _run("git push --force", cwd=tmp_path, decisions_path=log)
    assert rc == 2, f"invalid mode must fall back to enforce; got rc={rc}"
    assert _decision(stdout) == "deny"


def test_project_mode_overrides_global(tmp_path: Path) -> None:
    """When project sets shadow and global sets enforce, project wins."""
    # Global mode: enforce (via isolated GUARD_DATA_DIR).
    global_dir = tmp_path / ".isolated-guard-home"
    global_dir.mkdir()
    (global_dir / "allowlist.json").write_text(json.dumps({"mode": "enforce"}))
    # Project mode: shadow.
    _write_mode(tmp_path, "shadow")

    log = tmp_path / "log.jsonl"
    rc, stdout, _stderr = _run("git push --force", cwd=tmp_path, decisions_path=log)
    assert rc == 0, f"project shadow must override global enforce; got rc={rc}"
    assert _decision(stdout) is None
    recs = _records(log)
    deny = next((r for r in recs if r.get("decision") == "deny"), None)
    assert deny is not None
    assert deny["mode"] == "shadow"
