# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Integration tests for the admin_default_deny matcher (bash.admin_default_deny)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from guard.hooks.bash_command_validator import decide


def _is_deny(result: dict[str, Any] | None) -> bool:
    return result is not None and result.get("permissionDecision") == "deny"


def _is_allow(result: dict[str, Any] | None) -> bool:
    """Passthrough (None) or explicit allow both count as allow."""
    return result is None or result.get("permissionDecision") == "allow"


@pytest.fixture
def _bust_allow_verbs_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the module-level env-var cache before each OVERRIDE test."""
    monkeypatch.setattr("guard.hooks.bash_command_validator._ADMIN_ALLOW_VERBS_CACHE", None)


CLOUD_ADMIN_DENY = [
    # CRIT bypass: AWS IAM escalation
    pytest.param(
        "aws iam attach-user-policy --policy-arn "
        "arn:aws:iam::aws:policy/AdministratorAccess --user-name x",
        id="aws-iam-attach-user-policy",
    ),
    pytest.param("aws iam create-user --user-name evil", id="aws-iam-create-user"),
    pytest.param("aws iam create-access-key --user-name x", id="aws-iam-create-access-key"),
    pytest.param(
        "aws iam add-user-to-group --group-name Admins --user-name x",
        id="aws-iam-add-user-to-group",
    ),
    # CRIT bypass: Azure RBAC
    pytest.param(
        "az role assignment create --assignee x --role Owner",
        id="az-role-assignment-create",
    ),
    # CRIT bypass: GCP IAM
    pytest.param(
        "gcloud projects add-iam-policy-binding proj --member=user:x --role=roles/owner",
        id="gcloud-add-iam-policy-binding",
    ),
    # HIGH bypass: launchctl persistence
    pytest.param("launchctl kickstart -k gui/501/com.evil.persistence", id="launchctl-kickstart"),
    # Additional escalation verbs
    pytest.param("aws ec2 run-instances --image-id ami-xyz", id="aws-ec2-run-instances"),
    pytest.param(
        "aws lambda create-function --function-name f --runtime python3.11 --role r --handler h",
        id="aws-lambda-create",
    ),
    pytest.param(
        "gcloud compute instances create myvm --zone us-central1-a",
        id="gcloud-compute-create",
    ),
    pytest.param(
        "gcloud iam service-accounts create sa --display-name SA",
        id="gcloud-sa-create",
    ),
    pytest.param("gcloud auth print-access-token", id="gcloud-auth-print-access-token"),
    pytest.param(
        "az vm create --resource-group rg --name vm --image UbuntuLTS",
        id="az-vm-create",
    ),
    pytest.param("kubectl apply -f deployment.yaml", id="kubectl-apply"),
    pytest.param("launchctl bootout gui/501 com.example.agent", id="launchctl-bootout"),
    pytest.param("launchctl load /Library/LaunchDaemons/com.evil.plist", id="launchctl-load"),
    # deny-override: credential-issuing get-* verbs
    pytest.param("aws sts get-session-token", id="aws-sts-get-session-token"),
    pytest.param("aws ecr get-login-password", id="aws-ecr-get-login-password"),
    pytest.param("aws ssm start-session --target i-xxx", id="aws-ssm-start-session"),
    # End-of-flags `--` terminator bypass: safe pre-terminator verb must not
    # mask unsafe post-terminator tokens (extractors filter on `t.startswith("-")`
    # which silently drops `--`).
    pytest.param(
        "az account show -- storage blob upload -f /etc/passwd",
        id="az-terminator-bypass",
    ),
    pytest.param(
        "kubectl get pods -- delete deployment myapp",
        id="kubectl-terminator-bypass",
    ),
    pytest.param(
        "gcloud projects list -- iam policy bindings add",
        id="gcloud-terminator-bypass",
    ),
    pytest.param(
        "kubectl auth can-i -- delete pods",
        id="kubectl-multi-positional-terminator-bypass",
    ),
    pytest.param(
        "gcloud auth list -- compute instances create vm",
        id="gcloud-track-prefix-after-terminator",
    ),
]


@pytest.mark.parametrize("command", CLOUD_ADMIN_DENY)
def test_admin_default_deny_denies(command: str) -> None:
    result = decide(command)
    assert _is_deny(result), f"expected deny, got: {result}"


CLOUD_ADMIN_ALLOW = [
    # AWS prefix-predicate coverage
    pytest.param("aws ec2 describe-instances", id="aws-ec2-describe"),
    pytest.param("aws ec2 describe-security-groups", id="aws-ec2-describe-sgs"),
    pytest.param("aws s3 ls s3://my-bucket", id="aws-s3-ls"),
    pytest.param("aws iam list-users", id="aws-iam-list-users"),
    pytest.param("aws iam get-user", id="aws-iam-get-user"),
    pytest.param("aws lambda list-functions", id="aws-lambda-list"),
    # AWS explicit-allow exceptions
    pytest.param("aws logs tail /aws/lambda/fn", id="aws-logs-tail"),
    pytest.param("aws dynamodb scan --table-name t", id="aws-dynamodb-scan"),
    pytest.param(
        "aws iam simulate-principal-policy --policy-source-arn arn:x --action-names s3:GetObject",
        id="aws-iam-simulate",
    ),
    pytest.param(
        "aws cloudformation validate-template --template-body file://t.yaml",
        id="aws-cfn-validate",
    ),
    pytest.param(
        "aws rds generate-db-auth-token --hostname h --port 5432 --username u",
        id="aws-rds-auth-token",
    ),
    # gcloud read-only
    pytest.param("gcloud projects list", id="gcloud-projects-list"),
    pytest.param("gcloud compute instances list", id="gcloud-compute-list"),
    pytest.param(
        "gcloud container clusters get-credentials mycluster --zone us-central1-a",
        id="gcloud-get-credentials",
    ),
    pytest.param("gcloud auth list", id="gcloud-auth-list"),
    pytest.param("gcloud config list", id="gcloud-config-list"),
    pytest.param("gcloud alpha compute instances describe myvm", id="gcloud-alpha-describe"),
    pytest.param("gcloud beta container clusters list", id="gcloud-beta-list"),
    # az read-only
    pytest.param("az account show", id="az-account-show"),
    pytest.param("az vm list", id="az-vm-list"),
    pytest.param("az group list --output table", id="az-group-list"),
    # kubectl read-only
    pytest.param("kubectl get pods", id="kubectl-get-pods"),
    pytest.param("kubectl describe node mynode", id="kubectl-describe"),
    pytest.param("kubectl logs mypod", id="kubectl-logs"),
    pytest.param("kubectl auth can-i create pods", id="kubectl-auth-can-i"),
    pytest.param("kubectl config view", id="kubectl-config-view"),
    pytest.param("kubectl --context prod get pods", id="kubectl-context-flag"),
    pytest.param("kubectl -n kube-system get pods", id="kubectl-namespace-flag"),
    # launchctl read-only
    pytest.param("launchctl list", id="launchctl-list"),
    pytest.param("launchctl print system", id="launchctl-print"),
    pytest.param("launchctl blame gui/501/com.apple.foo", id="launchctl-blame"),
    pytest.param("launchctl version", id="launchctl-version"),
    # non-CLI passthrough
    pytest.param("echo aws iam create-user", id="echo-aws"),
]


@pytest.mark.parametrize("command", CLOUD_ADMIN_ALLOW)
def test_admin_default_deny_allows(command: str) -> None:
    result = decide(command)
    assert _is_allow(result), f"expected allow, got: {result}"


def test_override_allow_commands(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Path 1: allow_commands entry allows specific command."""
    allowlist_data = {
        "allow_commands": [
            {
                "rule": "bash.admin_default_deny",
                "command": "aws ec2 run-instances --image-id ami-xyz",
                "reason": "deploy script",
            }
        ]
    }
    (tmp_path / "allowlist.json").write_text(json.dumps(allowlist_data))
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path))
    result = decide("aws ec2 run-instances --image-id ami-xyz")
    assert _is_allow(result), f"expected allow via allow_commands, got: {result}"


def test_override_disable_rule(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Path 2: disable_rules bypasses the entire matcher."""
    allowlist_data = {"disable_rules": ["bash.admin_default_deny"]}
    (tmp_path / "allowlist.json").write_text(json.dumps(allowlist_data))
    monkeypatch.setenv("GUARD_DATA_DIR", str(tmp_path))
    result = decide("aws iam create-user --user-name evil")
    assert _is_allow(result), f"expected allow via disable_rules, got: {result}"


@pytest.mark.usefixtures("_bust_allow_verbs_cache")
def test_override_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Path 3: GUARD_ADMIN_ALLOW_VERBS adds per-verb allow."""
    monkeypatch.setenv("GUARD_ADMIN_ALLOW_VERBS", "aws:ec2.run-instances")
    result = decide("aws ec2 run-instances --image-id ami-xyz")
    assert _is_allow(result), f"expected allow via env var, got: {result}"


@pytest.mark.usefixtures("_bust_allow_verbs_cache")
def test_override_env_var_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed entries in GUARD_ADMIN_ALLOW_VERBS are skipped silently."""
    monkeypatch.setenv("GUARD_ADMIN_ALLOW_VERBS", "malformed,,aws:ec2.run-instances,")
    result = decide("aws ec2 run-instances --image-id ami-xyz")
    assert _is_allow(result)
    result2 = decide("aws iam create-user --user-name x")
    assert _is_deny(result2), "command not allowed by env var should still deny"


PRECEDENCE_CASES = [
    pytest.param(
        "aws iam delete-user --user-name x",
        "bash.aws_destructive",
        id="aws-iam-delete-user",
    ),
    pytest.param(
        "aws ec2 terminate-instances --instance-ids i-xxx",
        "bash.aws_destructive",
        id="aws-ec2-terminate",
    ),
    pytest.param(
        "kubectl scale --replicas=0 deploy -l app=prod",
        "bash.kubectl_destructive",
        id="kubectl-scale-label-selector",
    ),
]


@pytest.mark.parametrize(("command", "expected_rule"), PRECEDENCE_CASES)
def test_precedence_specific_wins(command: str, expected_rule: str) -> None:
    """Specific destructive matchers fire BEFORE admin_default_deny."""
    result = decide(command)
    assert _is_deny(result), f"expected deny, got: {result}"
    reason = result.get("permissionDecisionReason", "")
    assert expected_rule in reason, f"expected {expected_rule} in reason, got: {reason}"


def test_deny_message_content() -> None:
    """Deny message includes rule_id and all three override paths."""
    result = decide("aws iam attach-user-policy --policy-arn arn:x --user-name y")
    assert _is_deny(result)
    reason = result["permissionDecisionReason"]
    assert "bash.admin_default_deny" in reason
    assert "GUARD_ADMIN_ALLOW_VERBS=aws:" in reason
    assert "guard allowlist allow-command" in reason
    assert "guard allowlist disable-rule" in reason
