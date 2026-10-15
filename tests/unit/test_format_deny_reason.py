# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _format_deny_reason agent-guidance footer."""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import _REQUEST_CONTEXT, _format_deny_reason


@pytest.fixture(autouse=True)
def _reset_request_context() -> None:
    _REQUEST_CONTEXT.pop("permission_mode", None)
    _REQUEST_CONTEXT.pop("lockdown", None)
    yield
    _REQUEST_CONTEXT.pop("permission_mode", None)
    _REQUEST_CONTEXT.pop("lockdown", None)


@pytest.mark.parametrize("mode", ["default", "auto", "dontAsk", "bypassPermissions"])
def test_interactive_footer_in_every_permission_mode(mode: str) -> None:
    _REQUEST_CONTEXT["permission_mode"] = mode
    result = _format_deny_reason("bash.test", "test body")
    assert "explain what this rule protects against" in result


def test_lockdown_footer_present() -> None:
    _REQUEST_CONTEXT["lockdown"] = True
    result = _format_deny_reason("bash.test", "test body")
    assert "guard lockdown is on" in result


@pytest.mark.parametrize(
    "mode", ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"]
)
def test_annunciator_prefix_carries_mode(mode: str) -> None:
    """The deny prefix encodes the active mode so operators can grep transcripts."""
    _REQUEST_CONTEXT["permission_mode"] = mode
    result = _format_deny_reason("bash.example", "body")
    assert f"guard [permission_mode={mode}] denied: bash.example" in result, (
        f"missing annunciator for mode={mode!r}: {result!r}"
    )


def test_annunciator_prefix_via_decide_end_to_end() -> None:
    """End-to-end: decide() threads permission_mode and lockdown through
    _REQUEST_CONTEXT into _format_deny_reason.
    """
    from guard.hooks.bash_command_validator import decide

    strict = decide("flarbnoz --gronk", permission_mode="auto", lockdown=True)
    assert strict is not None
    assert "permission_mode=auto" in strict["permissionDecisionReason"]
    assert "guard lockdown is on" in strict["permissionDecisionReason"]

    interactive = decide("rm -rf /", permission_mode="default")
    assert interactive is not None
    assert "permission_mode=default" in interactive["permissionDecisionReason"]
