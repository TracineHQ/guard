"""Integration: hooks honor the global ``disable_rules`` and ignore retired config."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests._helpers import LIVE_GUARD

if TYPE_CHECKING:
    from pathlib import Path


def _write_allowlist(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _is_deny(decision: dict | None) -> bool:
    return decision is not None and decision.get("permissionDecision") == "deny"


def _is_allow(decision: dict | None) -> bool:
    return decision is not None and decision.get("permissionDecision") == "allow"


_REGISTRY = str(LIVE_GUARD / "registry.py")
_ALLOWLIST = "/repo/.claude/guard/allowlist.json"


@pytest.fixture
def allowlist_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``GUARD_DATA_DIR`` at a clean tmp dir; return the dir.

    Tests write the global file to ``<dir>/allowlist.json``.
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
    assert decide(cmd) is None


def test_disable_rules_does_not_affect_other_rules(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    _write_allowlist(
        allowlist_home / "allowlist.json", {"disable_rules": ["bash.disk_destruction"]}
    )
    # Different rule (sudo escalation) should still deny.
    assert _is_deny(decide("sudo su -"))


# === ALWAYS_DENY: coarse-grained disable ===


def test_disable_always_deny_leaves_the_other_floor_rules(allowlist_home: Path) -> None:
    """``rm -rf /`` hits the literal ALWAYS_DENY layer first (rule_id ``bash.always_deny``).

    Disabling that one rule_id skips only that layer: the scan goes on, and the
    rm matcher still denies the same command under its own rule id.
    """
    from guard.hooks.bash_command_validator import decide

    cmd = "rm -rf /"
    assert "bash.always_deny" in decide(cmd)["permissionDecisionReason"]

    _write_allowlist(allowlist_home / "allowlist.json", {"disable_rules": ["bash.always_deny"]})
    decision = decide(cmd)
    assert _is_deny(decision)
    assert "bash.dangerous_rm" in decision["permissionDecisionReason"]


# === Retired config grants nothing ===


def test_retired_allow_commands_entry_does_not_unblock(allowlist_home: Path) -> None:
    from guard.hooks.bash_command_validator import decide

    cmd = "dd if=/dev/zero of=/tmp/disk.qcow2 bs=1M count=1"
    _write_allowlist(
        allowlist_home / "allowlist.json",
        {"allow_commands": [{"rule": "bash.disk_destruction", "command": cmd, "reason": "x"}]},
    )
    decision = decide(cmd)
    assert _is_deny(decision)
    assert "allow-command" not in decision["permissionDecisionReason"]


def test_retired_project_allowlist_does_not_take_effect(
    allowlist_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard.hooks.bash_command_validator import decide

    project = tmp_path / "project"
    _write_allowlist(
        project / ".claude" / "guard" / "allowlist.json",
        {"mode": "off", "disable_rules": ["bash.disk_destruction"]},
    )
    monkeypatch.chdir(project)
    assert _is_deny(decide("dd if=/dev/zero of=/dev/sda bs=1M"))


# === Audit log records the bypass ===


def test_audit_log_records_allowlist_bypass(
    allowlist_home: Path,
    decision_log_env: Path,
) -> None:
    from guard.hooks.bash_command_validator import decide

    _write_allowlist(
        allowlist_home / "allowlist.json", {"disable_rules": ["bash.disk_destruction"]}
    )
    decide("dd if=/dev/zero of=/dev/sda")
    last = json.loads(decision_log_env.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["decision"] == "pass"
    assert last["reason"] == "allowlist: rule 'bash.disk_destruction' disabled by user config"


# === Other hooks: whole-hook disable ===


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
        "tool_input": {"file_path": _REGISTRY, "old_string": "x", "new_string": "y"},
        "session_id": "s1",
    }
    hook(payload)
    # No envelope emitted (Claude Code default-allows).
    assert capsys.readouterr().out == ""
    # But the bypass IS in the audit log.
    last = json.loads(decision_log_env.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["decision"] == "pass"
    assert "guard.protected_files" in last["reason"]


def _protected_files_exits_deny(payload: dict, capsys: pytest.CaptureFixture[str]) -> bool:
    from guard.hooks.protected_files import hook

    with pytest.raises(SystemExit) as exc:
        hook(payload)
    return exc.value.code == 2 and '"deny"' in capsys.readouterr().out


def test_retired_exact_path_entry_does_not_unblock_protected_file(
    allowlist_home: Path,
    decision_log_env: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_allowlist(
        allowlist_home / "allowlist.json",
        {
            "allow_commands": [
                {"rule": "guard.protected_files", "command": _REGISTRY, "reason": "x"}
            ]
        },
    )
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": _REGISTRY, "old_string": "x", "new_string": "y"},
        "session_id": "s1",
    }
    assert _protected_files_exits_deny(payload, capsys)


# === Trust root: no allowlist entry can unlock the allowlist itself ===


@pytest.mark.parametrize(
    "doc",
    [
        {"disable_rules": ["guard.protected_files"]},
        {
            "allow_commands": [
                {"rule": "guard.protected_files", "command": _ALLOWLIST, "reason": "x"}
            ]
        },
    ],
    ids=["disable_rules", "retired_allow_commands"],
)
def test_protected_files_allowlist_file_is_unbypassable(
    allowlist_home: Path,
    decision_log_env: Path,
    capsys: pytest.CaptureFixture[str],
    doc: dict,
) -> None:
    """An allowlist that lets agents edit the allowlist grants itself anything."""
    _write_allowlist(allowlist_home / "allowlist.json", doc)
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": _ALLOWLIST, "old_string": "x", "new_string": "y"},
        "session_id": "s1",
    }
    assert _protected_files_exits_deny(payload, capsys)
