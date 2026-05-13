# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Structural invariants between _admin_specs.py, allowlist.py, and docs."""

from __future__ import annotations

from pathlib import Path

from guard.allowlist import _BASH_MATCHER_RULE_IDS
from guard.hooks._admin_specs import (
    _AWS_READ_ONLY_VERBS,
    _AWS_READ_ONLY_VERBS_BY_SERVICE,
    _AWS_SPEC,
    ADMIN_CLI_SPECS,
    RULE_ID,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_names_unique() -> None:
    names = [s.cli_name for s in ADMIN_CLI_SPECS]
    assert len(names) == len(set(names)), f"duplicate cli_name in ADMIN_CLI_SPECS: {names}"


def test_no_verb_in_both_read_only_and_deny_overrides() -> None:
    for spec in ADMIN_CLI_SPECS:
        overlap = spec.read_only_verbs & spec.deny_overrides
        assert not overlap, f"{spec.cli_name}: verb in both sets: {overlap}"


def test_rule_id_in_bash_matcher_rule_ids() -> None:
    assert RULE_ID in _BASH_MATCHER_RULE_IDS, f"{RULE_ID} missing from _BASH_MATCHER_RULE_IDS"


def test_all_cli_names_in_skill_md() -> None:
    skill_md = (_REPO_ROOT / "SKILL.md").read_text()
    for spec in ADMIN_CLI_SPECS:
        assert spec.cli_name in skill_md, f"{spec.cli_name} missing from SKILL.md — drift risk"


def test_each_spec_has_deny_and_allow_cases() -> None:
    """Each enrolled CLI has at least 3 DENY and 3 ALLOW test param entries."""
    test_file = (_REPO_ROOT / "tests" / "integration" / "test_admin_default_deny.py").read_text()
    for spec in ADMIN_CLI_SPECS:
        count = test_file.count(f'"{spec.cli_name} ')
        assert count >= 3, f"{spec.cli_name}: only {count} test cases (need >=3)"


def test_aws_spec_is_strict_allowlist() -> None:
    """_AWS_SPEC must be a plain strict-allowlist spec (no predicate, no deny overrides)."""
    assert _AWS_SPEC.read_only_predicate is None
    assert _AWS_SPEC.deny_overrides == frozenset()


_KNOWN_BAD_AWS_VERBS: frozenset[tuple[str, str]] = frozenset(
    {
        ("secretsmanager", "get-secret-value"),
        ("secretsmanager", "batch-get-secret-value"),
        ("ssm", "get-parameter"),
        ("ssm", "get-parameters"),
        ("ssm", "get-parameters-by-path"),
        ("ssm", "get-parameter-history"),
        ("ssm", "get-command-invocation"),
        ("ssm", "get-access-token"),
        ("logs", "get-log-events"),
        ("logs", "filter-log-events"),
        ("logs", "get-query-results"),
        ("logs", "start-live-tail"),
        ("logs", "tail"),
        ("s3api", "get-object"),
        ("s3", "presign"),
        ("cognito-identity", "get-credentials-for-identity"),
        ("cognito-idp", "get-tokens-from-refresh-token"),
        ("sts", "get-session-token"),
        ("sts", "get-federation-token"),
        ("sts", "assume-role"),
        ("ecr", "get-login-password"),
        ("ecr", "get-authorization-token"),
        ("ecr", "batch-get-image"),
        ("eks", "get-token"),
        ("lambda", "get-function"),
        ("ec2", "get-password-data"),
        ("ec2", "get-console-output"),
        ("ec2", "get-console-screenshot"),
        ("sqs", "receive-message"),
        ("apigateway", "get-api-key"),
        ("apigateway", "get-api-keys"),
        ("athena", "get-query-results"),
        ("cloudtrail", "get-query-results"),
        ("glue", "get-connection"),
        ("glue", "get-connections"),
        ("glue", "get-entity-records"),
        ("stepfunctions", "get-execution-history"),
        ("stepfunctions", "get-activity-task"),
        ("dynamodb", "get-item"),
        ("dynamodb", "scan"),
        ("dynamodb", "query"),
        ("rds", "download-db-log-file-portion"),
        ("rds", "generate-db-auth-token"),
        ("iam", "get-credential-report"),
        ("iam", "get-ssh-public-key"),
    }
)


def test_aws_catalog_has_every_service_populated() -> None:
    """Every enumerated service must have >=1 entry (catches accidental clearing)."""
    for service, verbs in _AWS_READ_ONLY_VERBS_BY_SERVICE.items():
        assert len(verbs) >= 1, f"AWS catalog service {service!r} is empty"


def test_aws_catalog_excludes_known_bad_verbs() -> None:
    """No bypass-class verb may appear in the catalog."""
    bad_in_allow = _KNOWN_BAD_AWS_VERBS & _AWS_READ_ONLY_VERBS
    assert not bad_in_allow, (
        f"Known-bad AWS verbs sneaked into _AWS_READ_ONLY_VERBS: {sorted(bad_in_allow)}"
    )


def test_aws_catalog_flat_set_matches_per_service_union() -> None:
    """The flat _AWS_READ_ONLY_VERBS must equal union(per-service frozensets)."""
    expected = frozenset().union(*_AWS_READ_ONLY_VERBS_BY_SERVICE.values())
    assert expected == _AWS_READ_ONLY_VERBS
