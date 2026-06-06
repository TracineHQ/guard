# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Mode-aware deny floor + home-dir coverage for protected_files (P1).

protected_files historically always emitted ``ask``. In unattended modes
(auto/dontAsk/bypassPermissions) an ``ask`` is a silent bypass -- there is no
human to answer -- so the protected set must DENY there while staying ``ask`` in
interactive modes. Home-dir targets (shell-rc, ~/.local/bin, ~/Library/LaunchAgents,
keys) are derived from the bash validator's sensitive-destination set so the two
gates never drift.
"""

from __future__ import annotations

import json

import pytest

from guard.hooks.protected_files import decide, hook

# Already in PROTECTED_PATTERNS -- a stable anchor for the mode tests.
_PROTECTED = "/repo/.claude/settings.json"
_STRICT_MODES = ["auto", "dontAsk", "bypassPermissions"]
_INTERACTIVE_MODES = ["default", "acceptEdits", "plan"]


def _decision(envelope: dict) -> str:
    return envelope["hookSpecificOutput"]["permissionDecision"]


class TestModeAwareDecide:
    def test_default_mode_asks(self) -> None:
        assert _decision(decide("Edit", {"file_path": _PROTECTED})) == "ask"

    @pytest.mark.parametrize("mode", _INTERACTIVE_MODES)
    def test_interactive_modes_ask(self, mode: str) -> None:
        env = decide("Edit", {"file_path": _PROTECTED}, permission_mode=mode)
        assert _decision(env) == "ask"

    @pytest.mark.parametrize("mode", _STRICT_MODES)
    def test_strict_modes_deny(self, mode: str) -> None:
        env = decide("Edit", {"file_path": _PROTECTED}, permission_mode=mode)
        assert _decision(env) == "deny"

    @pytest.mark.parametrize("mode", _STRICT_MODES + _INTERACTIVE_MODES)
    def test_unprotected_file_returns_none_in_every_mode(self, mode: str) -> None:
        assert decide("Edit", {"file_path": "/repo/src/app.py"}, permission_mode=mode) is None


class TestHookExitsOnDeny:
    """hook() must exit 2 on a strict-mode deny so the block is fail-closed.

    Only exit code 2 is honored under bypassPermissions; a JSON ``deny`` with a
    zero exit is advisory there. The interactive ``ask`` path must NOT exit.
    """

    def test_strict_mode_deny_exits_2_and_emits_deny(self, capsys) -> None:
        payload = {
            "tool_name": "Edit",
            "tool_input": {"file_path": _PROTECTED},
            "permission_mode": "dontAsk",
        }
        with pytest.raises(SystemExit) as exc:
            hook(payload)
        assert exc.value.code == 2
        env = json.loads(capsys.readouterr().out)
        assert _decision(env) == "deny"

    def test_interactive_mode_asks_without_exiting(self, capsys) -> None:
        payload = {
            "tool_name": "Edit",
            "tool_input": {"file_path": _PROTECTED},
            "permission_mode": "default",
        }
        hook(payload)  # must return normally, no SystemExit
        env = json.loads(capsys.readouterr().out)
        assert _decision(env) == "ask"
