# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""credential_check must never pass a command because it crashed on it.

``Path("~128GB/s").expanduser()`` raises (no user named ``128GB``), and a hook
that raises used to pass silently, so a token like that ahead of a credential
read switched the check off for the whole command.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guard.allowlist import add_disable_rule
from guard.hooks import credential_check
from guard.hooks.credential_check import decide, hook


def _is_deny(envelope: dict[str, object] | None) -> bool:
    if envelope is None:
        return False
    spec = envelope.get("hookSpecificOutput")
    return isinstance(spec, dict) and spec.get("permissionDecision") == "deny"


class TestUnknownTildeUser:
    def test_tilde_word_alone_passes(self):
        assert decide("Bash", {"command": 'echo "throughput ~128GB/s"'}) is None

    def test_tilde_word_does_not_hide_a_credential_read(self):
        assert _is_deny(decide("Bash", {"command": 'echo "~128GB/s"; cat ~/.aws/credentials'}))

    def test_tilde_word_in_file_path_input_passes(self):
        assert decide("Read", {"file_path": "~nosuchuser9/notes.txt"}) is None


def _crash(_tool_name: str, _tool_input: dict[str, object]) -> None:
    msg = "boom"
    raise RuntimeError(msg)


def _payload() -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": "ls"}, "session_id": "s1"}


class TestFailClosed:
    """A crash in decide() denies through the normal decision path."""

    def test_crash_denies_and_logs_the_hook(self, monkeypatch, capsys, decision_log_env):
        monkeypatch.setattr(credential_check, "decide", _crash)
        with pytest.raises(SystemExit) as excinfo:
            hook(_payload())
        assert excinfo.value.code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "internal error" in envelope["hookSpecificOutput"]["permissionDecisionReason"]
        records = [json.loads(line) for line in Path(decision_log_env).read_text().splitlines()]
        crash = next(r for r in records if r.get("type") == "internal_error")
        assert crash["hook_id"] == "guard.credential_check"
        assert crash["session_id"] == "s1"
        assert any(r.get("decision") == "deny" for r in records)

    def test_crash_passes_when_rule_is_disabled(self, monkeypatch, capsys, decision_log_env):
        add_disable_rule("guard.credential_check", scope="global")
        monkeypatch.setattr(credential_check, "decide", _crash)
        hook(_payload())
        assert capsys.readouterr().out == ""
