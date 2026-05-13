# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Regression tests for the bash /dev/stdin shell-wrapper bypass (bash.shell_wrapper).

``bash /dev/stdin`` reads an attacker-controlled script from stdin and executes
it. This is semantically equivalent to ``bash -c '...'`` or ``bash <<EOF``:
the body is not statically evaluable. The lookahead in
``_is_shell_wrapper_invocation`` now recognizes stdin-device path tokens so
these shapes are caught before any catalog check.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny

STDIN_DEVICE_DENY = [
    pytest.param("bash /dev/stdin", id="bash-dev-stdin"),
    pytest.param("sh /dev/stdin", id="sh-dev-stdin"),
    pytest.param("zsh /dev/stdin", id="zsh-dev-stdin"),
    pytest.param("bash /dev/fd/0", id="bash-dev-fd-0"),
    pytest.param("sh /dev/fd/0", id="sh-dev-fd-0"),
    pytest.param("bash /proc/self/fd/0", id="bash-proc-self-fd-0"),
    pytest.param("bash -", id="bash-dash"),
    pytest.param("sh -", id="sh-dash"),
    pytest.param("zsh -", id="zsh-dash"),
    # With extra flags before the stdin device
    pytest.param("bash -x /dev/stdin", id="bash-x-dev-stdin"),
    pytest.param("bash -s /dev/stdin", id="bash-s-dev-stdin"),
]


@pytest.mark.parametrize("command", STDIN_DEVICE_DENY)
def test_stdin_device_shell_wrapper_denies(command: str) -> None:
    """Stdin-device shell invocations must deny regardless of content."""
    result = decide(command)
    assert is_deny(result), f"expected deny, got: {result}"


def test_stdin_device_reason_is_shell_wrapper() -> None:
    """The deny reason key should be bash.shell_wrapper."""
    result = decide("bash /dev/stdin")
    assert result is not None
    reason = result.get("permissionDecisionReason", "")
    assert "bash.shell_wrapper" in reason
