# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _format_deny_reason agent-guidance footer."""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import _REQUEST_CONTEXT, _format_deny_reason


@pytest.fixture(autouse=True)
def _reset_request_context() -> None:
    _REQUEST_CONTEXT.pop("permission_mode", None)
    yield
    _REQUEST_CONTEXT.pop("permission_mode", None)


def test_interactive_footer_present() -> None:
    _REQUEST_CONTEXT["permission_mode"] = "default"
    result = _format_deny_reason("bash.test", "test body")
    assert "explain what this rule protects against" in result


def test_strict_footer_present() -> None:
    _REQUEST_CONTEXT["permission_mode"] = "dontAsk"
    result = _format_deny_reason("bash.test", "test body")
    assert "hard fence in strict mode" in result


def test_bypass_permissions_footer_present() -> None:
    _REQUEST_CONTEXT["permission_mode"] = "bypassPermissions"
    result = _format_deny_reason("bash.test", "test body")
    assert "hard fence in strict mode" in result


def test_auto_mode_treated_as_strict() -> None:
    """`auto` is Claude Code's classifier-mediated unattended mode and must
    take the strict footer / default-deny posture."""
    _REQUEST_CONTEXT["permission_mode"] = "auto"
    result = _format_deny_reason("bash.test", "test body")
    assert "hard fence in strict mode" in result


def test_annunciator_prefix_carries_mode() -> None:
    """The deny prefix encodes the active mode so operators can grep transcripts."""
    for mode in ("default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"):
        _REQUEST_CONTEXT["permission_mode"] = mode
        result = _format_deny_reason("bash.example", "body")
        assert f"guard [permission_mode={mode}] denied: bash.example" in result, (
            f"missing annunciator for mode={mode!r}: {result!r}"
        )


def test_annunciator_prefix_via_decide_end_to_end() -> None:
    """End-to-end: decide() with permission_mode=dontAsk yields a deny whose
    reason carries the strict-mode annunciator. Defends against regressions
    that drop _REQUEST_CONTEXT threading from decide() into _format_deny_reason.
    """
    from guard.hooks.bash_command_validator import decide

    strict = decide("flarbnoz --gronk", permission_mode="dontAsk")
    assert strict is not None
    assert "permission_mode=dontAsk" in strict["permissionDecisionReason"]

    interactive = decide("rm -rf /", permission_mode="default")
    assert interactive is not None
    assert "permission_mode=default" in interactive["permissionDecisionReason"]
