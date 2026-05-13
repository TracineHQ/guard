# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
# ruff: noqa: INP001
"""Unit tests for _admin_deny_body override-hint interpolation (Task 1.5)."""

from __future__ import annotations

from guard.hooks.bash_command_validator import _admin_deny_body


def test_secretsmanager_get_secret_value() -> None:
    result = _admin_deny_body("aws", ("secretsmanager", "get-secret-value"))
    assert (
        "add aws:secretsmanager.get-secret-value to GUARD_ADMIN_ALLOW_VERBS to override." in result
    )


def test_ssm_get_parameter() -> None:
    result = _admin_deny_body("aws", ("ssm", "get-parameter"))
    assert "add aws:ssm.get-parameter to GUARD_ADMIN_ALLOW_VERBS to override." in result


def test_s3api_get_object() -> None:
    result = _admin_deny_body("aws", ("s3api", "get-object"))
    assert "add aws:s3api.get-object to GUARD_ADMIN_ALLOW_VERBS to override." in result
