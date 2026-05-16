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
