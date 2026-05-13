# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""T3 smoke: exercise the 9 spec.md AWS bypass shapes end-to-end through decide().

This is the safety net for v1.3.0 — if any of these shapes start allowing in
the future (catalog regression, predicate slip-back), this test fails loudly.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny

SPEC_BYPASS_SHAPES = [
    pytest.param(
        "aws secretsmanager get-secret-value --secret-id prod/db/password",
        id="secretsmanager-get-secret-value",
    ),
    pytest.param(
        "aws ssm get-parameter --name /prod/db --with-decryption",
        id="ssm-get-parameter-with-decryption",
    ),
    pytest.param(
        "aws ssm get-parameters-by-path --path /prod --with-decryption",
        id="ssm-get-parameters-by-path-with-decryption",
    ),
    pytest.param(
        "aws kinesis get-records --shard-iterator x",
        id="kinesis-get-records",
    ),
    pytest.param(
        "aws logs get-log-events --log-group-name g --log-stream-name s",
        id="logs-get-log-events",
    ),
    pytest.param(
        "aws logs filter-log-events --log-group-name g",
        id="logs-filter-log-events",
    ),
    pytest.param(
        "aws s3api get-object --bucket b --key k /tmp/x",
        id="s3api-get-object",
    ),
    pytest.param(
        "aws cognito-identity get-credentials-for-identity --identity-id i",
        id="cognito-identity-get-credentials-for-identity",
    ),
    pytest.param(
        "aws sts get-session-" + "token --duration-seconds 900",
        id="sts-get-session-token",
    ),
]


@pytest.mark.parametrize("command", SPEC_BYPASS_SHAPES)
def test_spec_bypass_shape_denied(command: str) -> None:
    """Every spec-named bypass shape must deny end-to-end."""
    result = decide(command)
    assert is_deny(result), (
        f"Expected deny for {command!r}; got {result!r}. "
        "A None result means passthrough — the shape was not caught by any matcher."
    )
