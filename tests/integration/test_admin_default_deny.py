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
    # forbidden flag denies (v1.3.0)
    pytest.param("kubectl --context prod get pods", id="kubectl-context-flag-forbidden"),
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
    pytest.param(
        "aws iam simulate-principal-policy --policy-source-arn arn:x --action-names s3:GetObject",
        id="aws-iam-simulate",
    ),
    pytest.param(
        "aws cloudformation validate-template --template-body file://t.yaml",
        id="aws-cfn-validate",
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
    # kubectl-context-flag moved to DENY: --context is now a forbidden flag
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


AWS_CATALOG_ALLOW = [
    pytest.param("aws iam list-users", id="aws-iam-list-users"),
    pytest.param("aws ec2 describe-instances", id="aws-ec2-describe-instances"),
    pytest.param("aws s3 ls", id="aws-s3-ls"),
    pytest.param("aws s3api list-buckets", id="aws-s3api-list-buckets"),
    pytest.param("aws sts get-caller-identity", id="aws-sts-get-caller-identity"),
    pytest.param("aws lambda list-functions", id="aws-lambda-list-functions"),
    pytest.param("aws dynamodb describe-table --table-name t", id="aws-dynamodb-describe-table"),
    pytest.param("aws rds describe-db-instances", id="aws-rds-describe-db-instances"),
    pytest.param("aws cloudformation describe-stacks", id="aws-cfn-describe-stacks"),
    pytest.param("aws cloudwatch describe-alarms", id="aws-cw-describe-alarms"),
    pytest.param("aws logs describe-log-groups", id="aws-logs-describe-log-groups"),
    pytest.param("aws ecs list-clusters", id="aws-ecs-list-clusters"),
    pytest.param("aws eks list-clusters", id="aws-eks-list-clusters"),
    pytest.param("aws ecr describe-repositories", id="aws-ecr-describe-repositories"),
    pytest.param("aws elbv2 describe-load-balancers", id="aws-elbv2-describe-lb"),
    pytest.param("aws elb describe-load-balancers", id="aws-elb-describe-lb"),
    pytest.param("aws route53 list-hosted-zones", id="aws-route53-list-zones"),
    pytest.param("aws sns list-topics", id="aws-sns-list-topics"),
    pytest.param("aws sqs list-queues", id="aws-sqs-list-queues"),
    pytest.param("aws secretsmanager describe-secret --secret-id s", id="aws-sm-describe-secret"),
    pytest.param("aws ssm describe-parameters", id="aws-ssm-describe-parameters"),
    pytest.param("aws kms describe-key --key-id k", id="aws-kms-describe-key"),
    pytest.param("aws apigateway get-rest-apis", id="aws-apigw-get-rest-apis"),
    pytest.param("aws apigatewayv2 get-apis", id="aws-apigwv2-get-apis"),
    pytest.param("aws glue get-databases", id="aws-glue-get-databases"),
    pytest.param("aws athena list-data-catalogs", id="aws-athena-list-catalogs"),
    pytest.param("aws cloudfront list-distributions", id="aws-cf-list-distributions"),
    pytest.param(
        "aws cognito-idp list-user-pools --max-results 10", id="aws-cognito-idp-list-pools"
    ),
    pytest.param(
        "aws cognito-identity list-identity-pools --max-results 10", id="aws-cognito-id-list-pools"
    ),
    pytest.param("aws events list-rules", id="aws-events-list-rules"),
    pytest.param("aws stepfunctions list-state-machines", id="aws-sfn-list-sm"),
    pytest.param("aws organizations describe-organization", id="aws-org-describe-org"),
    pytest.param("aws support describe-cases", id="aws-support-describe-cases"),
    pytest.param("aws pricing describe-services", id="aws-pricing-describe-services"),
    pytest.param("aws servicequotas list-services", id="aws-quotas-list-services"),
    pytest.param("aws cloudtrail describe-trails", id="aws-ct-describe-trails"),
    pytest.param("aws config describe-config-rules", id="aws-config-describe-rules"),
    pytest.param("aws resourcegroupstaggingapi get-resources", id="aws-rgta-get-resources"),
]


@pytest.mark.parametrize("command", AWS_CATALOG_ALLOW)
def test_aws_catalog_allow(command: str) -> None:
    """Every enumerated service has at least one representative read verb that allows."""
    result = decide(command)
    assert _is_allow(result), f"Expected allow for {command}; got {result}"


AWS_CATALOG_DENY = [
    # The 9 named bypass shapes from spec.md
    pytest.param("aws secretsmanager get-secret-value --secret-id s", id="sm-get-secret-value"),
    pytest.param("aws ssm get-parameter --name p --with-decryption", id="ssm-get-parameter-wdec"),
    pytest.param(
        "aws ssm get-parameters --names p1 p2 --with-decryption", id="ssm-get-parameters-wdec"
    ),
    pytest.param(
        "aws ssm get-parameters-by-path --path /p --with-decryption",
        id="ssm-get-parameters-by-path",
    ),
    pytest.param("aws kinesis get-records --shard-iterator x", id="kinesis-get-records"),
    pytest.param(
        "aws logs get-log-events --log-group-name g --log-stream-name s", id="logs-get-log-events"
    ),
    pytest.param("aws logs filter-log-events --log-group-name g", id="logs-filter-log-events"),
    pytest.param("aws s3api get-object --bucket b --key k out", id="s3api-get-object"),
    pytest.param(
        "aws cognito-identity get-credentials-for-identity --identity-id i", id="cogid-get-creds"
    ),
    # Additional EXCLUDE verbs from the catalog
    pytest.param("aws sts get-session-token", id="sts-get-session-token"),
    pytest.param("aws sts get-federation-token --name n", id="sts-get-federation-token"),
    pytest.param("aws sts assume-role --role-arn r --role-session-name s", id="sts-assume-role"),
    pytest.param("aws ecr get-login-password", id="ecr-get-login-password"),
    pytest.param("aws ecr get-authorization-token", id="ecr-get-auth-token"),
    pytest.param(
        "aws ecr batch-get-image --repository-name r --image-ids x", id="ecr-batch-get-image"
    ),
    pytest.param("aws eks get-token --cluster-name c", id="eks-get-token"),
    pytest.param("aws lambda get-function --function-name f", id="lambda-get-function"),
    pytest.param("aws ec2 get-password-data --instance-id i", id="ec2-get-password-data"),
    pytest.param("aws ec2 get-console-output --instance-id i", id="ec2-get-console-output"),
    pytest.param("aws ec2 get-console-screenshot --instance-id i", id="ec2-get-console-screenshot"),
    pytest.param("aws sqs receive-message --queue-url u", id="sqs-receive-message"),
    pytest.param("aws apigateway get-api-key --api-key k --include-value", id="apigw-get-api-key"),
    pytest.param("aws apigateway get-api-keys --include-values", id="apigw-get-api-keys"),
    pytest.param(
        "aws athena get-query-results --query-execution-id q", id="athena-get-query-results"
    ),
    pytest.param("aws logs get-query-results --query-id q", id="logs-get-query-results"),
    pytest.param(
        "aws cloudtrail get-query-results --query-id q --event-data-store eds",
        id="ct-get-query-results",
    ),
    pytest.param("aws glue get-connection --name c", id="glue-get-connection"),
    pytest.param(
        "aws ssm get-command-invocation --command-id c --instance-id i",
        id="ssm-get-command-invocation",
    ),
    pytest.param(
        "aws stepfunctions get-execution-history --execution-arn a", id="sfn-get-execution-history"
    ),
    pytest.param("aws dynamodb get-item --table-name t --key {}", id="dynamodb-get-item"),
    pytest.param("aws dynamodb scan --table-name t", id="dynamodb-scan"),
    pytest.param(
        "aws dynamodb query --table-name t --key-condition-expression x", id="dynamodb-query"
    ),
    pytest.param(
        "aws rds download-db-log-file-portion --db-instance-identifier i --log-file-name f",
        id="rds-download-log",
    ),
    pytest.param(
        "aws rds generate-db-auth-token --hostname h --port 5432 --username u",
        id="rds-gen-auth-token",
    ),
    pytest.param("aws logs start-live-tail --log-group-identifiers g", id="logs-start-live-tail"),
    pytest.param("aws logs tail my-log-group", id="logs-tail"),
    pytest.param(
        "aws secretsmanager batch-get-secret-value --secret-id-list s1 s2", id="sm-batch-get"
    ),
    pytest.param("aws ssm get-parameter-history --name p", id="ssm-get-parameter-history"),
    pytest.param("aws iam get-credential-report", id="iam-get-credential-report"),
    pytest.param(
        "aws iam get-ssh-public-key --user-name u --ssh-public-key-id k --encoding SSH",
        id="iam-get-ssh-pub-key",
    ),
    # Cross-review: missing-from-deny-sweep additions
    pytest.param(
        "aws glue get-entity-records --entity-name e --connection-name c",
        id="glue-get-entity-records",
    ),
    pytest.param("aws ssm get-access-token --access-request-id r", id="ssm-get-access-token"),
    pytest.param(
        "aws stepfunctions get-activity-task --activity-arn a", id="sfn-get-activity-task"
    ),
    pytest.param("aws s3 presign s3://bucket/key --expires-in 604800", id="s3-presign-long-ttl"),
]


@pytest.mark.parametrize("command", AWS_CATALOG_DENY)
def test_aws_catalog_deny(command: str) -> None:
    """Known-bad verbs that match a safe prefix but emit secret material -- must deny."""
    result = decide(command)
    assert _is_deny(result), f"Expected deny for {command}; got {result}"


S3_WRAPPER_ALLOW = [
    pytest.param("aws s3 ls", id="aws-s3-ls"),
    pytest.param("aws s3 ls s3://bucket/prefix/", id="aws-s3-ls-prefix"),
]


S3_WRAPPER_DENY = [
    pytest.param("aws s3 cp s3://b/k /tmp/x", id="aws-s3-cp"),
    pytest.param("aws s3 sync s3://b /tmp/d", id="aws-s3-sync"),
    pytest.param("aws s3 mv s3://b/k s3://b/k2", id="aws-s3-mv"),
    pytest.param("aws s3 rm s3://b/k", id="aws-s3-rm"),
    pytest.param("aws s3 mb s3://newbucket", id="aws-s3-mb"),
    pytest.param("aws s3 rb s3://b", id="aws-s3-rb"),
    pytest.param("aws s3 website s3://b", id="aws-s3-website"),
    pytest.param("aws s3 presign s3://b/k", id="aws-s3-presign"),
]


@pytest.mark.parametrize("command", S3_WRAPPER_ALLOW)
def test_s3_wrapper_allow(command: str) -> None:
    assert _is_allow(decide(command))


@pytest.mark.parametrize("command", S3_WRAPPER_DENY)
def test_s3_wrapper_deny(command: str) -> None:
    assert _is_deny(decide(command))


OVERRIDE_RESCUES = [
    pytest.param("aws:logs.tail", "aws logs tail my-log-group", id="rescue-logs-tail"),
    pytest.param(
        "aws:dynamodb.scan", "aws dynamodb scan --table-name t", id="rescue-dynamodb-scan"
    ),
    pytest.param(
        "aws:ssm.get-parameter",
        "aws ssm get-parameter --name p --with-decryption",
        id="rescue-ssm-get-param",
    ),
]


@pytest.mark.usefixtures("_bust_allow_verbs_cache")
@pytest.mark.parametrize(("override", "command"), OVERRIDE_RESCUES)
def test_override_rescue_allows(
    override: str, command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GUARD_ADMIN_ALLOW_VERBS adds a (service, verb) tuple to the allowlist at runtime."""
    monkeypatch.setenv("GUARD_ADMIN_ALLOW_VERBS", override)
    assert _is_allow(decide(command))


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


@pytest.mark.usefixtures("_bust_allow_verbs_cache")
def test_override_env_var_empty_cli_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entries with an empty CLI half (``:verb``, ``  :verb``) are dropped."""
    monkeypatch.setenv("GUARD_ADMIN_ALLOW_VERBS", ":get,  :list,aws:ec2.run-instances")
    result = decide("aws ec2 run-instances --image-id ami-xyz")
    assert _is_allow(result), "valid entry after empty-CLI entries should still parse"
    # The bare ``:get`` / ``:list`` should not allow anything; an
    # otherwise-denied command must still deny.
    result2 = decide("aws iam delete-user --user-name x")
    assert _is_deny(result2)


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
