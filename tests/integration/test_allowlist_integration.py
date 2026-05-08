"""Integration: bash_command_validator honors the project + global allowlist."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _write_allowlist(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _is_deny(decision: dict | None) -> bool:
    return decision is not None and decision.get("permissionDecision") == "deny"


def _is_allow(decision: dict | None) -> bool:
    return decision is not None and decision.get("permissionDecision") == "allow"


@pytest.fixture
def allowlist_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``GUARD_DATA_DIR`` at a clean tmp dir; return the dir.

    Tests write their allowlist file to ``<dir>/allowlist.json`` for
    global-scope, or to ``<cwd>/.claude/guard/allowlist.json`` for project
    scope (using the autouse ``monkeypatch.chdir`` they set up themselves).
    """
    home = tmp_path / "guard-home"
    monkeypatch.setenv("GUARD_DATA_DIR", str(home))
    return home


# === Synth matcher: per-rule disable ===


def test_disable_rules_lets_disk_destruction_through(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    cmd = "dd if=/dev/zero of=/dev/sda bs=1M"
    # Sanity: without allowlist, this denies.
    assert _is_deny(decide(cmd))

    _write_allowlist(
        allowlist_home / "allowlist.json", {"disable_rules": ["bash.disk_destruction"]}
    )
    assert _is_allow(decide(cmd))


def test_disable_rules_does_not_affect_other_rules(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    _write_allowlist(
        allowlist_home / "allowlist.json", {"disable_rules": ["bash.disk_destruction"]}
    )
    # Different rule (sudo escalation) should still deny.
    assert _is_deny(decide("sudo su -"))


# === Synth matcher: exact-command override ===


def test_allow_commands_exact_match_unblocks(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    cmd = "dd if=/dev/zero of=/tmp/disk.qcow2 bs=1M count=1"
    assert _is_deny(decide(cmd))

    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "bash.disk_destruction",
                    "command": cmd,
                    "reason": "build a throwaway VM image for the test fixture",
                }
            ]
        },
    )
    decision = decide(cmd)
    assert _is_allow(decision)
    assert "throwaway VM image" in decision["permissionDecisionReason"]


def test_allow_commands_does_not_match_different_command(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "bash.disk_destruction",
                    "command": "dd if=/dev/zero of=/tmp/x.qcow2 bs=1M count=1",
                    "reason": "fixture",
                }
            ]
        },
    )
    # Different operands → not allowlisted, still denies.
    assert _is_deny(decide("dd if=/dev/urandom of=/dev/sda bs=1M"))


def test_allow_commands_wrong_rule_does_not_unblock(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    cmd = "dd if=/dev/zero of=/dev/sda"
    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                # Wrong rule: this matches sudo, not disk_destruction.
                {"rule": "bash.sudo_escalation", "command": cmd, "reason": "x"}
            ]
        },
    )
    assert _is_deny(decide(cmd))


# === ALWAYS_DENY: coarse-grained disable ===


def test_disable_always_deny_lets_literal_through(allowlist_home: Path) -> None:
    """``rm -rf /`` hits the literal ALWAYS_DENY layer first (rule_id ``bash.always_deny``).

    Disabling that one rule_id is the intentional escape hatch — it doesn't
    silently degrade the synthetic-matcher layer that catches non-literal
    catastrophic shapes. A user who reaches for this rule is making a
    deliberate, audited choice; the behaviour matches the documented
    layering and the audit log records the bypass.
    """
    from guard.hooks.bash_command_validator import decide

    cmd = "rm -rf /"
    assert _is_deny(decide(cmd))

    _write_allowlist(allowlist_home / "allowlist.json", {"disable_rules": ["bash.always_deny"]})
    decision = decide(cmd)
    assert _is_allow(decision)
    assert "bash.always_deny" in decision["permissionDecisionReason"]


# === Project allowlist takes effect from cwd ===


def test_project_allowlist_takes_effect(
    allowlist_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard.hooks.bash_command_validator import decide

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    _write_allowlist(
        project / ".claude" / "guard" / "allowlist.json",
        {"disable_rules": ["bash.disk_destruction"]},
    )
    assert _is_allow(decide("dd if=/dev/zero of=/dev/sda bs=1M"))


# === Audit log records the bypass ===


def test_audit_log_records_allowlist_bypass(
    allowlist_home: Path,
    decision_log_env: Path,
) -> None:
    from guard.hooks.bash_command_validator import decide

    cmd = "dd if=/dev/zero of=/dev/sda"
    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "bash.disk_destruction",
                    "command": cmd,
                    "reason": "perf bench fixture: bs1m",
                }
            ]
        },
    )
    decide(cmd)
    text = decision_log_env.read_text(encoding="utf-8")
    assert text  # log file populated
    # The most recent record should be the allow with the allowlist reason.
    last = json.loads(text.strip().splitlines()[-1])
    assert last["decision"] == "allow"
    assert "perf bench fixture: bs1m" in last["reason"]
    assert "rule=bash.disk_destruction" in last["reason"]


# === Other hooks: whole-hook disable + path/command exact-match override ===


def test_protected_files_disabled_by_allowlist(
    allowlist_home: Path,
    decision_log_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from guard.hooks.protected_files import hook

    _write_allowlist(
        allowlist_home / "allowlist.json", {"disable_rules": ["guard.protected_files"]}
    )
    payload = {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/repo/CLAUDE.md",
            "old_string": "x",
            "new_string": "y",
        },
        "session_id": "s1",
    }
    hook(payload)
    # No envelope emitted (Claude Code default-allows).
    out = capsys.readouterr().out
    assert out == ""
    # But the bypass IS in the audit log.
    last = json.loads(decision_log_env.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["decision"] == "pass"
    assert "guard.protected_files" in last["reason"]


def test_protected_files_exact_path_allowlisted(
    allowlist_home: Path,
    decision_log_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from guard.hooks.protected_files import hook

    file_path = "/repo/CLAUDE.md"
    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "guard.protected_files",
                    "command": file_path,
                    "reason": "intentional CLAUDE.md update for the rebrand task",
                }
            ]
        },
    )
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": file_path, "old_string": "x", "new_string": "y"},
        "session_id": "s1",
    }
    hook(payload)
    assert capsys.readouterr().out == ""
    last = json.loads(decision_log_env.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["decision"] == "pass"
    assert "intentional CLAUDE.md update" in last["reason"]


def test_protected_files_exact_path_does_not_match_other_paths(
    allowlist_home: Path,
    decision_log_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from guard.hooks.protected_files import hook

    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {
                    "rule": "guard.protected_files",
                    "command": "/repo/CLAUDE.md",
                    "reason": "x",
                }
            ]
        },
    )
    # Different protected file → still asks.
    payload = {
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/repo/.cursorrules",
            "old_string": "x",
            "new_string": "y",
        },
        "session_id": "s1",
    }
    hook(payload)
    out = capsys.readouterr().out
    # An "ask" envelope was emitted.
    assert "permissionDecision" in out
    assert "ask" in out
