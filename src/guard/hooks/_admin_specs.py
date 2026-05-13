# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Admin CLI default-deny specs.

Design: each CLI enrolled here moves from a denylist of dangerous verbs to a
default-deny + read-only allowlist. Verbs NOT in the read-only set are denied;
users override via allow_commands, disable_rules, or GUARD_ADMIN_ALLOW_VERBS.

When to add a new CLI here (v1.2+):
  1. Define verb_extractor (pure fn: list[str] -> tuple[str, ...]).
  2. Define read_only_verbs as frozenset of tuples. For CLIs with uniform
     naming conventions (AWS-style describe-*/get-*/list-*) also write a
     read_only_predicate and deny_overrides frozenset.
  3. Add AdminCliSpec(...) to ADMIN_CLI_SPECS.
  4. Add test cases to tests/integration/test_admin_default_deny.py.
  That is all -- no matcher code changes required.

What does NOT belong here:
  DB clients (mysql, psql) -- no uniform read-only verb set; handled by
  bash.db_cli_destructive.
  ssh/scp/rsync, git, helm, terraform -- mutating workflows dominate; explicit
  denylist approach is more precise.
  See SECURITY.md for threat-model framing.
"""

from __future__ import annotations

from collections.abc import Callable  # noqa: TC003
from dataclasses import dataclass

RULE_ID = "bash.admin_default_deny"


@dataclass(frozen=True)
class AdminCliSpec:
    """Per-CLI configuration for the admin_default_deny matcher. See module docstring."""

    cli_name: str
    read_only_verbs: frozenset[tuple[str, ...]]
    verb_extractor: Callable[[list[str]], tuple[str, ...]]
    read_only_predicate: Callable[[tuple[str, ...]], bool] | None = None
    deny_overrides: frozenset[tuple[str, ...]] = frozenset()
    global_value_flags: frozenset[str] = frozenset()
    global_bare_flags: frozenset[str] = frozenset()
    track_prefixes: frozenset[str] = frozenset()
    # v1.3.0 forbidden-flag layer (all default-empty for back-compat)
    forbidden_flags: frozenset[str] = frozenset()
    forbidden_subcommands: frozenset[tuple[str, ...]] = frozenset()
    known_flags: frozenset[str] = frozenset()
    sensitive_env_vars: frozenset[str] = frozenset()


_GCLOUD_READ_ONLY_VERBS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("info",),
        ("version",),
        ("help",),
        ("config", "get-value"),
        ("config", "list"),
        ("auth", "list"),
        ("projects", "list"),
        ("projects", "describe"),
        ("projects", "get-iam-policy"),
        ("compute", "instances", "list"),
        ("compute", "instances", "describe"),
        ("compute", "networks", "list"),
        ("compute", "networks", "describe"),
        ("container", "clusters", "list"),
        ("container", "clusters", "describe"),
        ("container", "clusters", "get-credentials"),
        ("storage", "ls"),
        ("storage", "cat"),
        ("iam", "service-accounts", "list"),
        ("iam", "service-accounts", "describe"),
        ("iam", "roles", "list"),
        ("iam", "roles", "describe"),
        ("logging", "logs", "list"),
        ("logging", "read"),
        ("pubsub", "topics", "list"),
        ("pubsub", "subscriptions", "list"),
        ("functions", "list"),
        ("functions", "describe"),
        ("run", "services", "list"),
        ("run", "services", "describe"),
    }
)

_AZ_READ_ONLY_VERBS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("account", "show"),
        ("account", "list"),
        ("group", "list"),
        ("group", "show"),
        ("vm", "list"),
        ("vm", "show"),
        ("aks", "list"),
        ("aks", "show"),
        ("network", "vnet", "list"),
        ("network", "vnet", "show"),
        ("ad", "user", "list"),
        ("ad", "user", "show"),
        ("keyvault", "list"),
        ("keyvault", "show"),
        ("storage", "account", "list"),
        ("storage", "account", "show"),
        ("role", "definition", "list"),
        ("policy", "assignment", "list"),
        ("monitor", "log-analytics", "workspace", "list"),
    }
)

_KUBECTL_READ_ONLY_VERBS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("get",),
        ("describe",),
        ("logs",),
        ("top",),
        ("diff",),
        ("events",),
        ("version",),
        ("help",),
        ("api-resources",),
        ("api-versions",),
        ("explain",),
        ("cluster-info",),
        ("auth", "can-i"),
        ("config", "view"),
        ("config", "current-context"),
        ("config", "get-contexts"),
        ("config", "get-clusters"),
    }
)

_LAUNCHCTL_READ_ONLY_VERBS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("list",),
        ("print",),
        ("blame",),
        ("version",),
        ("help",),
        ("dumpstate",),
        ("dumpjpcategory",),
        ("examine",),
        ("procinfo",),
        ("hostinfo",),
    }
)


# Per-service AWS read-only verb catalog (v1.3.0 strict allowlist model).
#
# Each entry maps a service name (as `aws <service> ...`) to a frozenset of
# (service, verb) tuples for the verbs that are read-only AND safe -- they
# do not emit secret material, object bodies, credentials, or similar
# sensitive content.
#
# This catalog is intentionally NOT comprehensive across all of AWS.
# Long-tail services use GUARD_ADMIN_ALLOW_VERBS to extend at runtime.
_AWS_READ_ONLY_VERBS_BY_SERVICE: dict[str, frozenset[tuple[str, str]]] = {
    # excluded: get-credential-report (aids targeting), get-ssh-public-key (key material)
    "iam": frozenset(
        {
            ("iam", "get-access-key-last-used"),
            ("iam", "get-account-authorization-details"),
            ("iam", "get-account-password-policy"),
            ("iam", "get-account-summary"),
            ("iam", "get-context-keys-for-custom-policy"),
            ("iam", "get-context-keys-for-principal-policy"),
            ("iam", "get-group"),
            ("iam", "get-group-policy"),
            ("iam", "get-instance-profile"),
            ("iam", "get-login-profile"),
            ("iam", "get-mfa-device"),
            ("iam", "get-open-id-connect-provider"),
            ("iam", "get-organizations-access-report"),
            ("iam", "get-policy"),
            ("iam", "get-policy-version"),
            ("iam", "get-role"),
            ("iam", "get-role-policy"),
            ("iam", "get-saml-provider"),
            ("iam", "get-server-certificate"),
            ("iam", "get-service-last-accessed-details"),
            ("iam", "get-service-last-accessed-details-with-entities"),
            ("iam", "get-service-linked-role-deletion-status"),
            ("iam", "get-user"),
            ("iam", "get-user-policy"),
            ("iam", "list-access-keys"),
            ("iam", "list-account-aliases"),
            ("iam", "list-attached-group-policies"),
            ("iam", "list-attached-role-policies"),
            ("iam", "list-attached-user-policies"),
            ("iam", "list-entities-for-policy"),
            ("iam", "list-group-policies"),
            ("iam", "list-groups"),
            ("iam", "list-groups-for-user"),
            ("iam", "list-instance-profile-tags"),
            ("iam", "list-instance-profiles"),
            ("iam", "list-instance-profiles-for-role"),
            ("iam", "list-mfa-device-tags"),
            ("iam", "list-mfa-devices"),
            ("iam", "list-open-id-connect-provider-tags"),
            ("iam", "list-open-id-connect-providers"),
            ("iam", "list-policies"),
            ("iam", "list-policies-granting-service-access"),
            ("iam", "list-policy-tags"),
            ("iam", "list-policy-versions"),
            ("iam", "list-role-policies"),
            ("iam", "list-role-tags"),
            ("iam", "list-roles"),
            ("iam", "list-saml-provider-tags"),
            ("iam", "list-saml-providers"),
            ("iam", "list-server-certificate-tags"),
            ("iam", "list-server-certificates"),
            ("iam", "list-service-specific-credentials"),
            ("iam", "list-signing-certificates"),
            ("iam", "list-ssh-public-keys"),
            ("iam", "list-user-policies"),
            ("iam", "list-user-tags"),
            ("iam", "list-users"),
            ("iam", "list-virtual-mfa-devices"),
            ("iam", "simulate-custom-policy"),
            ("iam", "simulate-principal-policy"),
        }
    ),
    # excluded: get-password-data, get-console-output, get-console-screenshot,
    #   get-instance-uefi-data, get-instance-tpm-ek-pub (credential/secret content)
    "ec2": frozenset(
        {
            ("ec2", "describe-account-attributes"),
            ("ec2", "describe-addresses"),
            ("ec2", "describe-addresses-attribute"),
            ("ec2", "describe-availability-zones"),
            ("ec2", "describe-aws-network-performance-metric-subscriptions"),
            ("ec2", "describe-bundle-tasks"),
            ("ec2", "describe-byoip-cidrs"),
            ("ec2", "describe-capacity-reservations"),
            ("ec2", "describe-carrier-gateways"),
            ("ec2", "describe-classic-link-instances"),
            ("ec2", "describe-client-vpn-authorization-rules"),
            ("ec2", "describe-client-vpn-connections"),
            ("ec2", "describe-client-vpn-endpoints"),
            ("ec2", "describe-client-vpn-routes"),
            ("ec2", "describe-client-vpn-target-networks"),
            ("ec2", "describe-coip-pools"),
            ("ec2", "describe-conversion-tasks"),
            ("ec2", "describe-customer-gateways"),
            ("ec2", "describe-dhcp-options"),
            ("ec2", "describe-egress-only-internet-gateways"),
            ("ec2", "describe-elastic-gpus"),
            ("ec2", "describe-export-image-tasks"),
            ("ec2", "describe-export-tasks"),
            ("ec2", "describe-fleet-history"),
            ("ec2", "describe-fleet-instances"),
            ("ec2", "describe-fleets"),
            ("ec2", "describe-flow-logs"),
            ("ec2", "describe-fpga-image-attribute"),
            ("ec2", "describe-fpga-images"),
            ("ec2", "describe-host-reservation-offerings"),
            ("ec2", "describe-host-reservations"),
            ("ec2", "describe-hosts"),
            ("ec2", "describe-iam-instance-profile-associations"),
            ("ec2", "describe-id-format"),
            ("ec2", "describe-identity-id-format"),
            ("ec2", "describe-image-attribute"),
            ("ec2", "describe-images"),
            ("ec2", "describe-import-image-tasks"),
            ("ec2", "describe-import-snapshot-tasks"),
            ("ec2", "describe-instance-attribute"),
            ("ec2", "describe-instance-credit-specifications"),
            ("ec2", "describe-instance-event-notification-attributes"),
            ("ec2", "describe-instance-event-windows"),
            ("ec2", "describe-instance-status"),
            ("ec2", "describe-instance-type-offerings"),
            ("ec2", "describe-instance-types"),
            ("ec2", "describe-instances"),
            ("ec2", "describe-internet-gateways"),
            ("ec2", "describe-ipam-pools"),
            ("ec2", "describe-ipam-scopes"),
            ("ec2", "describe-ipams"),
            ("ec2", "describe-ipv6-pools"),
            ("ec2", "describe-key-pairs"),
            ("ec2", "describe-launch-template-versions"),
            ("ec2", "describe-launch-templates"),
            ("ec2", "describe-local-gateway-route-table-virtual-interface-group-associations"),
            ("ec2", "describe-local-gateway-route-table-vpc-associations"),
            ("ec2", "describe-local-gateway-route-tables"),
            ("ec2", "describe-local-gateway-virtual-interface-groups"),
            ("ec2", "describe-local-gateway-virtual-interfaces"),
            ("ec2", "describe-local-gateways"),
            ("ec2", "describe-managed-prefix-lists"),
            ("ec2", "describe-moving-addresses"),
            ("ec2", "describe-nat-gateways"),
            ("ec2", "describe-network-acls"),
            ("ec2", "describe-network-insights-analyses"),
            ("ec2", "describe-network-insights-paths"),
            ("ec2", "describe-network-interface-attribute"),
            ("ec2", "describe-network-interface-permissions"),
            ("ec2", "describe-network-interfaces"),
            ("ec2", "describe-placement-groups"),
            ("ec2", "describe-prefix-lists"),
            ("ec2", "describe-principal-id-format"),
            ("ec2", "describe-public-ipv4-pools"),
            ("ec2", "describe-regions"),
            ("ec2", "describe-reserved-instances"),
            ("ec2", "describe-reserved-instances-listings"),
            ("ec2", "describe-reserved-instances-modifications"),
            ("ec2", "describe-reserved-instances-offerings"),
            ("ec2", "describe-route-tables"),
            ("ec2", "describe-scheduled-instance-availability"),
            ("ec2", "describe-scheduled-instances"),
            ("ec2", "describe-security-group-references"),
            ("ec2", "describe-security-group-rules"),
            ("ec2", "describe-security-groups"),
            ("ec2", "describe-snapshot-attribute"),
            ("ec2", "describe-snapshots"),
            ("ec2", "describe-spot-fleet-instances"),
            ("ec2", "describe-spot-fleet-request-history"),
            ("ec2", "describe-spot-fleet-requests"),
            ("ec2", "describe-spot-instance-requests"),
            ("ec2", "describe-spot-price-history"),
            ("ec2", "describe-stale-security-groups"),
            ("ec2", "describe-subnets"),
            ("ec2", "describe-tags"),
            ("ec2", "describe-traffic-mirror-filters"),
            ("ec2", "describe-traffic-mirror-sessions"),
            ("ec2", "describe-traffic-mirror-targets"),
            ("ec2", "describe-transit-gateway-attachments"),
            ("ec2", "describe-transit-gateway-route-tables"),
            ("ec2", "describe-transit-gateway-vpc-attachments"),
            ("ec2", "describe-transit-gateways"),
            ("ec2", "describe-volume-attribute"),
            ("ec2", "describe-volume-status"),
            ("ec2", "describe-volumes"),
            ("ec2", "describe-volumes-modifications"),
            ("ec2", "describe-vpc-attribute"),
            ("ec2", "describe-vpc-classic-link"),
            ("ec2", "describe-vpc-classic-link-dns-support"),
            ("ec2", "describe-vpc-endpoint-connections"),
            ("ec2", "describe-vpc-endpoint-service-configurations"),
            ("ec2", "describe-vpc-endpoint-service-permissions"),
            ("ec2", "describe-vpc-endpoint-services"),
            ("ec2", "describe-vpc-endpoints"),
            ("ec2", "describe-vpc-peering-connections"),
            ("ec2", "describe-vpcs"),
            ("ec2", "describe-vpn-connections"),
            ("ec2", "describe-vpn-gateways"),
            ("ec2", "get-launch-template-data"),
            ("ec2", "get-spot-placement-scores"),
            ("ec2", "list-images-in-recycle-bin"),
            ("ec2", "list-snapshots-in-recycle-bin"),
            ("ec2", "list-volumes-in-recycle-bin"),
        }
    ),
    # excluded: get-object (body content), get-object-torrent (enables download)
    "s3api": frozenset(
        {
            ("s3api", "get-bucket-accelerate-configuration"),
            ("s3api", "get-bucket-acl"),
            ("s3api", "get-bucket-analytics-configuration"),
            ("s3api", "get-bucket-cors"),
            ("s3api", "get-bucket-encryption"),
            ("s3api", "get-bucket-intelligent-tiering-configuration"),
            ("s3api", "get-bucket-inventory-configuration"),
            ("s3api", "get-bucket-lifecycle-configuration"),
            ("s3api", "get-bucket-location"),
            ("s3api", "get-bucket-logging"),
            ("s3api", "get-bucket-metrics-configuration"),
            ("s3api", "get-bucket-notification-configuration"),
            ("s3api", "get-bucket-ownership-controls"),
            ("s3api", "get-bucket-policy"),
            ("s3api", "get-bucket-policy-status"),
            ("s3api", "get-bucket-replication"),
            ("s3api", "get-bucket-request-payment"),
            ("s3api", "get-bucket-tagging"),
            ("s3api", "get-bucket-versioning"),
            ("s3api", "get-bucket-website"),
            ("s3api", "get-object-acl"),
            ("s3api", "get-object-attributes"),
            ("s3api", "get-object-legal-hold"),
            ("s3api", "get-object-lock-configuration"),
            ("s3api", "get-object-retention"),
            ("s3api", "get-object-tagging"),
            ("s3api", "get-public-access-block"),
            ("s3api", "head-bucket"),
            ("s3api", "head-object"),
            ("s3api", "list-bucket-analytics-configurations"),
            ("s3api", "list-bucket-intelligent-tiering-configurations"),
            ("s3api", "list-bucket-inventory-configurations"),
            ("s3api", "list-bucket-metrics-configurations"),
            ("s3api", "list-buckets"),
            ("s3api", "list-directory-buckets"),
            ("s3api", "list-multipart-uploads"),
            ("s3api", "list-object-versions"),
            ("s3api", "list-objects"),
            ("s3api", "list-objects-v2"),
            ("s3api", "list-parts"),
        }
    ),
    # excluded: cp, sync, mv, rm, mb, rb, website (content transfer or mutation)
    # excluded: presign (issues a credential-bearing presigned URL granting up to
    #   7-day unauthenticated S3 read; same threat class as sts get-session-token)
    "s3": frozenset(
        {
            ("s3", "ls"),
        }
    ),
    # excluded: assume-role*, get-session-token, get-federation-token
    #   get-delegated-access-token, get-web-identity-token — all credential-issuing
    "sts": frozenset(
        {
            ("sts", "decode-authorization-message"),
            ("sts", "get-access-key-info"),
            ("sts", "get-caller-identity"),
        }
    ),
    # excluded: get-function (source exfil), get-layer-version, get-layer-version-by-arn
    #   (code download), invoke (executes code)
    "lambda": frozenset(
        {
            ("lambda", "get-account-settings"),
            ("lambda", "get-alias"),
            ("lambda", "get-code-signing-config"),
            ("lambda", "get-event-source-mapping"),
            ("lambda", "get-function-code-signing-config"),
            ("lambda", "get-function-concurrency"),
            ("lambda", "get-function-configuration"),
            ("lambda", "get-function-event-invoke-config"),
            ("lambda", "get-function-url-config"),
            ("lambda", "get-layer-version-policy"),
            ("lambda", "get-policy"),
            ("lambda", "get-provisioned-concurrency-config"),
            ("lambda", "get-runtime-management-config"),
            ("lambda", "list-aliases"),
            ("lambda", "list-code-signing-configs"),
            ("lambda", "list-event-source-mappings"),
            ("lambda", "list-function-event-invoke-configs"),
            ("lambda", "list-function-url-configs"),
            ("lambda", "list-functions"),
            ("lambda", "list-functions-by-code-signing-config"),
            ("lambda", "list-layer-versions"),
            ("lambda", "list-layers"),
            ("lambda", "list-provisioned-concurrency-configs"),
            ("lambda", "list-tags"),
            ("lambda", "list-versions-by-function"),
        }
    ),
    # excluded: get-item, batch-get-item, scan, query, transact-get-items
    #   (item/table content; scan+query were incorrectly in v1.2 allowlist),
    #   execute-statement, execute-transaction (PartiQL data access)
    "dynamodb": frozenset(
        {
            ("dynamodb", "describe-backup"),
            ("dynamodb", "describe-continuous-backups"),
            ("dynamodb", "describe-contributor-insights"),
            ("dynamodb", "describe-endpoints"),
            ("dynamodb", "describe-export"),
            ("dynamodb", "describe-global-table"),
            ("dynamodb", "describe-global-table-settings"),
            ("dynamodb", "describe-import"),
            ("dynamodb", "describe-kinesis-streaming-destination"),
            ("dynamodb", "describe-limits"),
            ("dynamodb", "describe-table"),
            ("dynamodb", "describe-table-replica-auto-scaling"),
            ("dynamodb", "describe-time-to-live"),
            ("dynamodb", "get-resource-policy"),
            ("dynamodb", "list-backups"),
            ("dynamodb", "list-contributor-insights"),
            ("dynamodb", "list-exports"),
            ("dynamodb", "list-global-tables"),
            ("dynamodb", "list-imports"),
            ("dynamodb", "list-tables"),
            ("dynamodb", "list-tags-of-resource"),
        }
    ),
    # excluded: download-db-log-file-portion (log content; PII/creds risk),
    #   generate-db-auth-token (credential-equivalent; was in v1.2 allowlist — removed)
    "rds": frozenset(
        {
            ("rds", "describe-account-attributes"),
            ("rds", "describe-blue-green-deployments"),
            ("rds", "describe-certificates"),
            ("rds", "describe-db-cluster-automated-backups"),
            ("rds", "describe-db-cluster-backtracks"),
            ("rds", "describe-db-cluster-endpoints"),
            ("rds", "describe-db-cluster-parameter-groups"),
            ("rds", "describe-db-cluster-parameters"),
            ("rds", "describe-db-cluster-snapshot-attributes"),
            ("rds", "describe-db-cluster-snapshots"),
            ("rds", "describe-db-clusters"),
            ("rds", "describe-db-engine-versions"),
            ("rds", "describe-db-instance-automated-backups"),
            ("rds", "describe-db-instances"),
            ("rds", "describe-db-log-files"),
            ("rds", "describe-db-parameter-groups"),
            ("rds", "describe-db-parameters"),
            ("rds", "describe-db-proxies"),
            ("rds", "describe-db-proxy-endpoints"),
            ("rds", "describe-db-proxy-target-groups"),
            ("rds", "describe-db-proxy-targets"),
            ("rds", "describe-db-recommendations"),
            ("rds", "describe-db-security-groups"),
            ("rds", "describe-db-snapshot-attributes"),
            ("rds", "describe-db-snapshots"),
            ("rds", "describe-db-subnet-groups"),
            ("rds", "describe-engine-default-cluster-parameters"),
            ("rds", "describe-engine-default-parameters"),
            ("rds", "describe-event-categories"),
            ("rds", "describe-event-subscriptions"),
            ("rds", "describe-events"),
            ("rds", "describe-export-tasks"),
            ("rds", "describe-global-clusters"),
            ("rds", "describe-integrations"),
            ("rds", "describe-option-group-options"),
            ("rds", "describe-option-groups"),
            ("rds", "describe-orderable-db-instance-options"),
            ("rds", "describe-pending-maintenance-actions"),
            ("rds", "describe-reserved-db-instances"),
            ("rds", "describe-reserved-db-instances-offerings"),
            ("rds", "describe-source-regions"),
            ("rds", "describe-tenant-databases"),
            ("rds", "describe-valid-db-instance-modifications"),
            ("rds", "list-tags-for-resource"),
        }
    ),
    # excluded: detect-stack-drift (triggers async mutation/inspection job)
    "cloudformation": frozenset(
        {
            ("cloudformation", "describe-account-limits"),
            ("cloudformation", "describe-change-set"),
            ("cloudformation", "describe-change-set-hooks"),
            ("cloudformation", "describe-generated-template"),
            ("cloudformation", "describe-organizations-access"),
            ("cloudformation", "describe-publisher"),
            ("cloudformation", "describe-resource-scan"),
            ("cloudformation", "describe-stack-drift-detection-status"),
            ("cloudformation", "describe-stack-events"),
            ("cloudformation", "describe-stack-instance"),
            ("cloudformation", "describe-stack-resource"),
            ("cloudformation", "describe-stack-resource-drifts"),
            ("cloudformation", "describe-stack-resources"),
            ("cloudformation", "describe-stack-set"),
            ("cloudformation", "describe-stack-set-operation"),
            ("cloudformation", "describe-stacks"),
            ("cloudformation", "describe-type"),
            ("cloudformation", "describe-type-registration"),
            ("cloudformation", "detect-stack-resource-drift"),
            ("cloudformation", "get-generated-template"),
            ("cloudformation", "get-stack-policy"),
            ("cloudformation", "get-template"),
            ("cloudformation", "get-template-summary"),
            ("cloudformation", "list-change-sets"),
            ("cloudformation", "list-exports"),
            ("cloudformation", "list-generated-templates"),
            ("cloudformation", "list-imports"),
            ("cloudformation", "list-resource-scan-related-resources"),
            ("cloudformation", "list-resource-scan-resources"),
            ("cloudformation", "list-resource-scans"),
            ("cloudformation", "list-stack-instances"),
            ("cloudformation", "list-stack-resources"),
            ("cloudformation", "list-stack-set-operation-results"),
            ("cloudformation", "list-stack-set-operations"),
            ("cloudformation", "list-stack-sets"),
            ("cloudformation", "list-stacks"),
            ("cloudformation", "list-type-registrations"),
            ("cloudformation", "list-type-versions"),
            ("cloudformation", "list-types"),
            ("cloudformation", "validate-template"),
        }
    ),
    # no excluded verbs (metrics/alarms are observability, not secrets)
    "cloudwatch": frozenset(
        {
            ("cloudwatch", "describe-alarm-history"),
            ("cloudwatch", "describe-alarms"),
            ("cloudwatch", "describe-alarms-for-metric"),
            ("cloudwatch", "describe-anomaly-detectors"),
            ("cloudwatch", "describe-insight-rules"),
            ("cloudwatch", "get-dashboard"),
            ("cloudwatch", "get-insight-rule-report"),
            ("cloudwatch", "get-metric-data"),
            ("cloudwatch", "get-metric-statistics"),
            ("cloudwatch", "get-metric-stream"),
            ("cloudwatch", "get-metric-widget-image"),
            ("cloudwatch", "list-dashboards"),
            ("cloudwatch", "list-managed-insight-rules"),
            ("cloudwatch", "list-metric-streams"),
            ("cloudwatch", "list-metrics"),
            ("cloudwatch", "list-tags-for-resource"),
        }
    ),
    # excluded: get-log-events, filter-log-events, get-log-record, get-query-results,
    #   start-live-tail, tail (log content; tail was in v1.2 allowlist — removed)
    "logs": frozenset(
        {
            ("logs", "describe-account-policies"),
            ("logs", "describe-deliveries"),
            ("logs", "describe-delivery-destinations"),
            ("logs", "describe-delivery-sources"),
            ("logs", "describe-destinations"),
            ("logs", "describe-export-tasks"),
            ("logs", "describe-field-indexes"),
            ("logs", "describe-index-policies"),
            ("logs", "describe-log-groups"),
            ("logs", "describe-log-streams"),
            ("logs", "describe-metric-filters"),
            ("logs", "describe-queries"),
            ("logs", "describe-query-definitions"),
            ("logs", "describe-resource-policies"),
            ("logs", "describe-subscription-filters"),
            ("logs", "get-data-protection-policy"),
            ("logs", "get-delivery"),
            ("logs", "get-delivery-destination"),
            ("logs", "get-delivery-destination-policy"),
            ("logs", "get-delivery-source"),
            ("logs", "get-log-anomaly-detector"),
            ("logs", "get-log-group-fields"),
            ("logs", "list-anomalies"),
            ("logs", "list-log-anomaly-detectors"),
            ("logs", "list-tags-for-resource"),
        }
    ),
    # no excluded verbs (env var exposure is an IAM concern, not verb-level)
    "ecs": frozenset(
        {
            ("ecs", "describe-capacity-providers"),
            ("ecs", "describe-clusters"),
            ("ecs", "describe-container-instances"),
            ("ecs", "describe-services"),
            ("ecs", "describe-task-definition"),
            ("ecs", "describe-task-sets"),
            ("ecs", "describe-tasks"),
            ("ecs", "get-task-protection"),
            ("ecs", "list-account-settings"),
            ("ecs", "list-attributes"),
            ("ecs", "list-clusters"),
            ("ecs", "list-container-instances"),
            ("ecs", "list-services"),
            ("ecs", "list-services-by-namespace"),
            ("ecs", "list-tags-for-resource"),
            ("ecs", "list-task-definition-families"),
            ("ecs", "list-task-definitions"),
            ("ecs", "list-tasks"),
        }
    ),
    # excluded: get-token (cluster auth token — credential-equivalent)
    "eks": frozenset(
        {
            ("eks", "describe-access-entry"),
            ("eks", "describe-addon"),
            ("eks", "describe-addon-configuration"),
            ("eks", "describe-addon-versions"),
            ("eks", "describe-cluster"),
            ("eks", "describe-cluster-versions"),
            ("eks", "describe-fargate-profile"),
            ("eks", "describe-identity-provider-config"),
            ("eks", "describe-insight"),
            ("eks", "describe-nodegroup"),
            ("eks", "describe-pod-identity-association"),
            ("eks", "describe-update"),
            ("eks", "list-access-entries"),
            ("eks", "list-access-policies"),
            ("eks", "list-addons"),
            ("eks", "list-associated-access-policies"),
            ("eks", "list-clusters"),
            ("eks", "list-fargate-profiles"),
            ("eks", "list-identity-provider-configs"),
            ("eks", "list-insights"),
            ("eks", "list-nodegroups"),
            ("eks", "list-pod-identity-associations"),
            ("eks", "list-tags-for-resource"),
            ("eks", "list-updates"),
        }
    ),
    # excluded: get-authorization-token, get-login-password (auth tokens),
    #   batch-get-image, get-download-url-for-layer (layer/image download)
    "ecr": frozenset(
        {
            ("ecr", "batch-check-layer-availability"),
            ("ecr", "describe-image-replication-status"),
            ("ecr", "describe-image-scan-findings"),
            ("ecr", "describe-images"),
            ("ecr", "describe-pull-through-cache-rules"),
            ("ecr", "describe-registry"),
            ("ecr", "describe-repositories"),
            ("ecr", "get-account-setting"),
            ("ecr", "get-lifecycle-policy"),
            ("ecr", "get-lifecycle-policy-preview"),
            ("ecr", "get-registry-policy"),
            ("ecr", "get-registry-scanning-configuration"),
            ("ecr", "get-repository-policy"),
            ("ecr", "list-images"),
            ("ecr", "list-tags-for-resource"),
        }
    ),
    # no excluded verbs
    "elbv2": frozenset(
        {
            ("elbv2", "describe-account-limits"),
            ("elbv2", "describe-listener-attributes"),
            ("elbv2", "describe-listener-certificates"),
            ("elbv2", "describe-listeners"),
            ("elbv2", "describe-load-balancer-attributes"),
            ("elbv2", "describe-load-balancers"),
            ("elbv2", "describe-rules"),
            ("elbv2", "describe-ssl-policies"),
            ("elbv2", "describe-tags"),
            ("elbv2", "describe-target-group-attributes"),
            ("elbv2", "describe-target-groups"),
            ("elbv2", "describe-target-health"),
            ("elbv2", "describe-trust-store-associations"),
            ("elbv2", "describe-trust-store-revocations"),
            ("elbv2", "describe-trust-stores"),
            ("elbv2", "get-resource-policy"),
        }
    ),
    # no excluded verbs
    "elb": frozenset(
        {
            ("elb", "describe-account-limits"),
            ("elb", "describe-instance-health"),
            ("elb", "describe-load-balancer-attributes"),
            ("elb", "describe-load-balancer-policies"),
            ("elb", "describe-load-balancer-policy-types"),
            ("elb", "describe-load-balancers"),
            ("elb", "describe-tags"),
        }
    ),
    # no excluded verbs
    "route53": frozenset(
        {
            ("route53", "get-account-limit"),
            ("route53", "get-change"),
            ("route53", "get-checker-ip-ranges"),
            ("route53", "get-dnssec"),
            ("route53", "get-geo-location"),
            ("route53", "get-health-check"),
            ("route53", "get-health-check-count"),
            ("route53", "get-health-check-last-failure-reason"),
            ("route53", "get-health-check-status"),
            ("route53", "get-hosted-zone"),
            ("route53", "get-hosted-zone-count"),
            ("route53", "get-hosted-zone-limit"),
            ("route53", "get-query-logging-config"),
            ("route53", "get-reusable-delegation-set"),
            ("route53", "get-reusable-delegation-set-limit"),
            ("route53", "get-traffic-policy"),
            ("route53", "get-traffic-policy-instance"),
            ("route53", "get-traffic-policy-instance-count"),
            ("route53", "list-cidr-blocks"),
            ("route53", "list-cidr-collections"),
            ("route53", "list-cidr-locations"),
            ("route53", "list-geo-locations"),
            ("route53", "list-health-checks"),
            ("route53", "list-hosted-zones"),
            ("route53", "list-hosted-zones-by-name"),
            ("route53", "list-hosted-zones-by-vpc"),
            ("route53", "list-query-logging-configs"),
            ("route53", "list-resource-record-sets"),
            ("route53", "list-reusable-delegation-sets"),
            ("route53", "list-tags-for-resource"),
            ("route53", "list-tags-for-resources"),
            ("route53", "list-traffic-policies"),
            ("route53", "list-traffic-policy-instances"),
            ("route53", "list-traffic-policy-instances-by-hosted-zone"),
            ("route53", "list-traffic-policy-instances-by-policy"),
            ("route53", "list-traffic-policy-versions"),
            ("route53", "list-vpc-association-authorizations"),
            ("route53", "test-dns-answer"),
        }
    ),
    # no excluded verbs
    "sns": frozenset(
        {
            ("sns", "get-data-protection-policy"),
            ("sns", "get-endpoint-attributes"),
            ("sns", "get-platform-application-attributes"),
            ("sns", "get-sms-attributes"),
            ("sns", "get-sms-sandbox-account-status"),
            ("sns", "get-subscription-attributes"),
            ("sns", "get-topic-attributes"),
            ("sns", "list-endpoints-by-platform-application"),
            ("sns", "list-origination-numbers"),
            ("sns", "list-phone-numbers-opted-out"),
            ("sns", "list-platform-applications"),
            ("sns", "list-sms-sandbox-phone-numbers"),
            ("sns", "list-subscriptions"),
            ("sns", "list-subscriptions-by-topic"),
            ("sns", "list-tags-for-resource"),
            ("sns", "list-topics"),
        }
    ),
    # excluded: receive-message (returns queue message payload content)
    "sqs": frozenset(
        {
            ("sqs", "get-queue-attributes"),
            ("sqs", "get-queue-url"),
            ("sqs", "list-dead-letter-source-queues"),
            ("sqs", "list-message-move-tasks"),
            ("sqs", "list-queue-tags"),
            ("sqs", "list-queues"),
        }
    ),
    # excluded: *-secret-value verbs (secret material — core bypass target),
    #   batch-get-secret-value, plus get-random-password (mutating)
    "secretsmanager": frozenset(
        {
            ("secretsmanager", "describe-secret"),
            ("secretsmanager", "get-resource-policy"),
            ("secretsmanager", "list-secret-version-ids"),
            ("secretsmanager", "list-secrets"),
        }
    ),
    # excluded: get-parameter* verbs (decrypted values), get-parameter-history,
    #   command-invocation/automation-execution outputs, start-session (was in v1.2)
    "ssm": frozenset(
        {
            ("ssm", "describe-activations"),
            ("ssm", "describe-association"),
            ("ssm", "describe-association-execution-targets"),
            ("ssm", "describe-association-executions"),
            ("ssm", "describe-automation-executions"),
            ("ssm", "describe-automation-step-executions"),
            ("ssm", "describe-available-patches"),
            ("ssm", "describe-document"),
            ("ssm", "describe-document-permission"),
            ("ssm", "describe-effective-instance-associations"),
            ("ssm", "describe-effective-patches-for-patch-baseline"),
            ("ssm", "describe-instance-associations-status"),
            ("ssm", "describe-instance-information"),
            ("ssm", "describe-instance-patch-states"),
            ("ssm", "describe-instance-patch-states-for-patch-group"),
            ("ssm", "describe-instance-patches"),
            ("ssm", "describe-instance-properties"),
            ("ssm", "describe-inventory-deletions"),
            ("ssm", "describe-maintenance-window-execution-task-invocations"),
            ("ssm", "describe-maintenance-window-execution-tasks"),
            ("ssm", "describe-maintenance-window-executions"),
            ("ssm", "describe-maintenance-window-schedule"),
            ("ssm", "describe-maintenance-window-targets"),
            ("ssm", "describe-maintenance-window-tasks"),
            ("ssm", "describe-maintenance-windows"),
            ("ssm", "describe-maintenance-windows-for-target"),
            ("ssm", "describe-ops-items"),
            ("ssm", "describe-parameters"),
            ("ssm", "describe-patch-baselines"),
            ("ssm", "describe-patch-group-state"),
            ("ssm", "describe-patch-groups"),
            ("ssm", "describe-patch-properties"),
            ("ssm", "describe-sessions"),
            ("ssm", "get-calendar-state"),
            ("ssm", "get-connection-status"),
            ("ssm", "get-default-patch-baseline"),
            ("ssm", "get-document"),
            ("ssm", "get-inventory"),
            ("ssm", "get-inventory-schema"),
            ("ssm", "get-maintenance-window"),
            ("ssm", "get-maintenance-window-execution"),
            ("ssm", "get-maintenance-window-execution-task"),
            ("ssm", "get-maintenance-window-execution-task-invocation"),
            ("ssm", "get-maintenance-window-task"),
            ("ssm", "get-ops-item"),
            ("ssm", "get-ops-metadata"),
            ("ssm", "get-ops-summary"),
            ("ssm", "get-patch-baseline"),
            ("ssm", "get-patch-baseline-for-patch-group"),
            ("ssm", "get-resource-policies"),
            ("ssm", "get-service-setting"),
            ("ssm", "list-association-versions"),
            ("ssm", "list-associations"),
            ("ssm", "list-command-invocations"),
            ("ssm", "list-commands"),
            ("ssm", "list-compliance-items"),
            ("ssm", "list-compliance-summaries"),
            ("ssm", "list-document-metadata-history"),
            ("ssm", "list-document-versions"),
            ("ssm", "list-documents"),
            ("ssm", "list-inventory-entries"),
            ("ssm", "list-nodes"),
            ("ssm", "list-nodes-summary"),
            ("ssm", "list-ops-item-events"),
            ("ssm", "list-ops-item-related-items"),
            ("ssm", "list-ops-metadata"),
            ("ssm", "list-resource-compliance-summaries"),
            ("ssm", "list-resource-data-sync"),
            ("ssm", "list-tags-for-resource"),
        }
    ),
    # excluded: get-parameters-for-import (key import token),
    #   get-public-key (raw key material; aids targeting)
    "kms": frozenset(
        {
            ("kms", "describe-custom-key-stores"),
            ("kms", "describe-key"),
            ("kms", "get-key-policy"),
            ("kms", "get-key-rotation-status"),
            ("kms", "list-aliases"),
            ("kms", "list-grants"),
            ("kms", "list-key-policies"),
            ("kms", "list-key-rotations"),
            ("kms", "list-keys"),
            ("kms", "list-resource-tags"),
            ("kms", "list-retirable-grants"),
        }
    ),
    # excluded: get-api-key, get-api-keys (key values), get-sdk (code download)
    "apigateway": frozenset(
        {
            ("apigateway", "get-account"),
            ("apigateway", "get-authorizer"),
            ("apigateway", "get-authorizers"),
            ("apigateway", "get-client-certificate"),
            ("apigateway", "get-client-certificates"),
            ("apigateway", "get-deployment"),
            ("apigateway", "get-deployments"),
            ("apigateway", "get-documentation-part"),
            ("apigateway", "get-documentation-parts"),
            ("apigateway", "get-documentation-version"),
            ("apigateway", "get-documentation-versions"),
            ("apigateway", "get-domain-name"),
            ("apigateway", "get-domain-names"),
            ("apigateway", "get-export"),
            ("apigateway", "get-gateway-response"),
            ("apigateway", "get-gateway-responses"),
            ("apigateway", "get-integration"),
            ("apigateway", "get-integration-response"),
            ("apigateway", "get-method"),
            ("apigateway", "get-method-response"),
            ("apigateway", "get-model"),
            ("apigateway", "get-model-template"),
            ("apigateway", "get-models"),
            ("apigateway", "get-resource"),
            ("apigateway", "get-resources"),
            ("apigateway", "get-rest-api"),
            ("apigateway", "get-rest-apis"),
            ("apigateway", "get-sdk-type"),
            ("apigateway", "get-sdk-types"),
            ("apigateway", "get-stage"),
            ("apigateway", "get-stages"),
            ("apigateway", "get-tags"),
            ("apigateway", "get-usage"),
            ("apigateway", "get-usage-plan"),
            ("apigateway", "get-usage-plan-key"),
            ("apigateway", "get-usage-plan-keys"),
            ("apigateway", "get-usage-plans"),
            ("apigateway", "get-vpc-link"),
            ("apigateway", "get-vpc-links"),
        }
    ),
    # no excluded verbs (newer marketplace verbs extend via GUARD_ADMIN_ALLOW_VERBS)
    "apigatewayv2": frozenset(
        {
            ("apigatewayv2", "get-api"),
            ("apigatewayv2", "get-api-mapping"),
            ("apigatewayv2", "get-api-mappings"),
            ("apigatewayv2", "get-apis"),
            ("apigatewayv2", "get-authorizer"),
            ("apigatewayv2", "get-authorizers"),
            ("apigatewayv2", "get-deployment"),
            ("apigatewayv2", "get-deployments"),
            ("apigatewayv2", "get-domain-name"),
            ("apigatewayv2", "get-domain-names"),
            ("apigatewayv2", "get-integration"),
            ("apigatewayv2", "get-integration-response"),
            ("apigatewayv2", "get-integration-responses"),
            ("apigatewayv2", "get-integrations"),
            ("apigatewayv2", "get-model"),
            ("apigatewayv2", "get-model-template"),
            ("apigatewayv2", "get-models"),
            ("apigatewayv2", "get-route"),
            ("apigatewayv2", "get-route-response"),
            ("apigatewayv2", "get-route-responses"),
            ("apigatewayv2", "get-routes"),
            ("apigatewayv2", "get-stage"),
            ("apigatewayv2", "get-stages"),
            ("apigatewayv2", "get-tags"),
            ("apigatewayv2", "get-vpc-link"),
            ("apigatewayv2", "get-vpc-links"),
        }
    ),
    # excluded: get-connection*, get-partition*, get-unfiltered-partition*,
    #   get-unfiltered-table-metadata (LF bypass), get-entity-records (data),
    #   get-session, get-statement, list-statements (session/Spark code content)
    "glue": frozenset(
        {
            ("glue", "describe-connection-type"),
            ("glue", "describe-entity"),
            ("glue", "describe-inbound-integrations"),
            ("glue", "describe-integrations"),
            ("glue", "get-blueprint"),
            ("glue", "get-blueprint-run"),
            ("glue", "get-blueprint-runs"),
            ("glue", "get-catalog"),
            ("glue", "get-catalog-import-status"),
            ("glue", "get-catalogs"),
            ("glue", "get-classifier"),
            ("glue", "get-classifiers"),
            ("glue", "get-crawler"),
            ("glue", "get-crawler-metrics"),
            ("glue", "get-crawlers"),
            ("glue", "get-custom-entity-type"),
            ("glue", "get-database"),
            ("glue", "get-databases"),
            ("glue", "get-dataflow-graph"),
            ("glue", "get-dev-endpoint"),
            ("glue", "get-dev-endpoints"),
            ("glue", "get-job"),
            ("glue", "get-job-bookmark"),
            ("glue", "get-job-run"),
            ("glue", "get-job-runs"),
            ("glue", "get-jobs"),
            ("glue", "get-mapping"),
            ("glue", "get-ml-task-run"),
            ("glue", "get-ml-task-runs"),
            ("glue", "get-ml-transform"),
            ("glue", "get-ml-transforms"),
            ("glue", "get-partition-indexes"),
            ("glue", "get-resource-policies"),
            ("glue", "get-resource-policy"),
            ("glue", "get-schema"),
            ("glue", "get-schema-by-definition"),
            ("glue", "get-schema-version"),
            ("glue", "get-security-configuration"),
            ("glue", "get-security-configurations"),
            ("glue", "get-table"),
            ("glue", "get-table-optimizer"),
            ("glue", "get-table-version"),
            ("glue", "get-table-versions"),
            ("glue", "get-tables"),
            ("glue", "get-tags"),
            ("glue", "get-trigger"),
            ("glue", "get-triggers"),
            ("glue", "get-user-defined-function"),
            ("glue", "get-user-defined-functions"),
            ("glue", "get-workflow"),
            ("glue", "get-workflow-run"),
            ("glue", "get-workflow-runs"),
            ("glue", "list-blueprints"),
            ("glue", "list-crawlers"),
            ("glue", "list-crawls"),
            ("glue", "list-custom-entity-types"),
            ("glue", "list-dev-endpoints"),
            ("glue", "list-jobs"),
            ("glue", "list-ml-transforms"),
            ("glue", "list-registries"),
            ("glue", "list-schema-versions"),
            ("glue", "list-schemas"),
            ("glue", "list-sessions"),
            ("glue", "list-triggers"),
            ("glue", "list-workflows"),
        }
    ),
    # excluded: get-query-results (query rows), get-calculation-execution-code (code),
    #   get-session (session state), get-session-endpoint (active session endpoint)
    "athena": frozenset(
        {
            ("athena", "get-calculation-execution"),
            ("athena", "get-calculation-execution-status"),
            ("athena", "get-capacity-assignment-configuration"),
            ("athena", "get-capacity-reservation"),
            ("athena", "get-data-catalog"),
            ("athena", "get-database"),
            ("athena", "get-named-query"),
            ("athena", "get-notebook-metadata"),
            ("athena", "get-prepared-statement"),
            ("athena", "get-query-execution"),
            ("athena", "get-query-runtime-statistics"),
            ("athena", "get-session-status"),
            ("athena", "get-table-metadata"),
            ("athena", "get-work-group"),
            ("athena", "list-application-dpu-sizes"),
            ("athena", "list-calculation-executions"),
            ("athena", "list-capacity-reservations"),
            ("athena", "list-data-catalogs"),
            ("athena", "list-databases"),
            ("athena", "list-engine-versions"),
            ("athena", "list-executors"),
            ("athena", "list-named-queries"),
            ("athena", "list-notebook-metadata"),
            ("athena", "list-notebook-sessions"),
            ("athena", "list-prepared-statements"),
            ("athena", "list-query-executions"),
            ("athena", "list-sessions"),
            ("athena", "list-table-metadata"),
            ("athena", "list-tags-for-resource"),
            ("athena", "list-work-groups"),
        }
    ),
    # no excluded verbs
    "cloudfront": frozenset(
        {
            ("cloudfront", "get-cache-policy"),
            ("cloudfront", "get-cache-policy-config"),
            ("cloudfront", "get-cloud-front-origin-access-identity"),
            ("cloudfront", "get-cloud-front-origin-access-identity-config"),
            ("cloudfront", "get-continuous-deployment-policy"),
            ("cloudfront", "get-continuous-deployment-policy-config"),
            ("cloudfront", "get-distribution"),
            ("cloudfront", "get-distribution-config"),
            ("cloudfront", "get-field-level-encryption"),
            ("cloudfront", "get-field-level-encryption-config"),
            ("cloudfront", "get-field-level-encryption-profile"),
            ("cloudfront", "get-field-level-encryption-profile-config"),
            ("cloudfront", "get-function"),
            ("cloudfront", "get-invalidation"),
            ("cloudfront", "get-key-group"),
            ("cloudfront", "get-key-group-config"),
            ("cloudfront", "get-monitoring-subscription"),
            ("cloudfront", "get-origin-access-control"),
            ("cloudfront", "get-origin-access-control-config"),
            ("cloudfront", "get-origin-request-policy"),
            ("cloudfront", "get-origin-request-policy-config"),
            ("cloudfront", "get-public-key"),
            ("cloudfront", "get-public-key-config"),
            ("cloudfront", "get-realtime-log-config"),
            ("cloudfront", "get-response-headers-policy"),
            ("cloudfront", "get-response-headers-policy-config"),
            ("cloudfront", "get-streaming-distribution"),
            ("cloudfront", "get-streaming-distribution-config"),
            ("cloudfront", "list-cache-policies"),
            ("cloudfront", "list-cloud-front-origin-access-identities"),
            ("cloudfront", "list-conflicting-aliases"),
            ("cloudfront", "list-continuous-deployment-policies"),
            ("cloudfront", "list-distributions"),
            ("cloudfront", "list-distributions-by-cache-policy-id"),
            ("cloudfront", "list-distributions-by-key-group"),
            ("cloudfront", "list-distributions-by-origin-request-policy-id"),
            ("cloudfront", "list-distributions-by-realtime-log-config"),
            ("cloudfront", "list-distributions-by-response-headers-policy-id"),
            ("cloudfront", "list-distributions-by-web-acl-id"),
            ("cloudfront", "list-field-level-encryption-configs"),
            ("cloudfront", "list-field-level-encryption-profiles"),
            ("cloudfront", "list-functions"),
            ("cloudfront", "list-invalidations"),
            ("cloudfront", "list-key-groups"),
            ("cloudfront", "list-origin-access-controls"),
            ("cloudfront", "list-origin-request-policies"),
            ("cloudfront", "list-public-keys"),
            ("cloudfront", "list-realtime-log-configs"),
            ("cloudfront", "list-response-headers-policies"),
            ("cloudfront", "list-streaming-distributions"),
            ("cloudfront", "list-tags-for-resource"),
        }
    ),
    # excluded: get-tokens-from-refresh-token (auth tokens),
    #   list-user-pool-client-secrets (secret values),
    #   admin-initiate-auth, admin-respond-to-auth-challenge (return auth tokens)
    "cognito-idp": frozenset(
        {
            ("cognito-idp", "describe-identity-provider"),
            ("cognito-idp", "describe-managed-login-branding"),
            ("cognito-idp", "describe-managed-login-branding-by-client"),
            ("cognito-idp", "describe-resource-server"),
            ("cognito-idp", "describe-risk-configuration"),
            ("cognito-idp", "describe-user-import-job"),
            ("cognito-idp", "describe-user-pool"),
            ("cognito-idp", "describe-user-pool-client"),
            ("cognito-idp", "describe-user-pool-domain"),
            ("cognito-idp", "get-csv-header"),
            ("cognito-idp", "get-device"),
            ("cognito-idp", "get-group"),
            ("cognito-idp", "get-identity-provider-by-identifier"),
            ("cognito-idp", "get-log-delivery-configuration"),
            ("cognito-idp", "get-signing-certificate"),
            ("cognito-idp", "get-ui-customization"),
            ("cognito-idp", "get-user"),
            ("cognito-idp", "get-user-pool-mfa-config"),
            ("cognito-idp", "list-devices"),
            ("cognito-idp", "list-groups"),
            ("cognito-idp", "list-identity-providers"),
            ("cognito-idp", "list-resource-servers"),
            ("cognito-idp", "list-tags-for-resource"),
            ("cognito-idp", "list-user-import-jobs"),
            ("cognito-idp", "list-user-pool-clients"),
            ("cognito-idp", "list-user-pools"),
            ("cognito-idp", "list-users"),
            ("cognito-idp", "list-users-in-group"),
        }
    ),
    # excluded: get-credentials-for-identity (federated creds — core bypass),
    #   get-open-id-token, get-open-id-token-for-developer-identity (credential tokens)
    "cognito-identity": frozenset(
        {
            ("cognito-identity", "describe-identity"),
            ("cognito-identity", "describe-identity-pool"),
            ("cognito-identity", "get-id"),
            ("cognito-identity", "get-identity-pool-roles"),
            ("cognito-identity", "get-principal-tag-attribute-map"),
            ("cognito-identity", "list-identities"),
            ("cognito-identity", "list-identity-pools"),
            ("cognito-identity", "list-tags-for-resource"),
        }
    ),
    # no excluded verbs (connection credentials masked in describe output)
    "events": frozenset(
        {
            ("events", "describe-api-destination"),
            ("events", "describe-archive"),
            ("events", "describe-connection"),
            ("events", "describe-endpoint"),
            ("events", "describe-event-bus"),
            ("events", "describe-event-source"),
            ("events", "describe-partner-event-source"),
            ("events", "describe-replay"),
            ("events", "describe-rule"),
            ("events", "list-api-destinations"),
            ("events", "list-archives"),
            ("events", "list-connections"),
            ("events", "list-endpoints"),
            ("events", "list-event-buses"),
            ("events", "list-event-sources"),
            ("events", "list-partner-event-source-accounts"),
            ("events", "list-partner-event-sources"),
            ("events", "list-replays"),
            ("events", "list-rule-names-by-target"),
            ("events", "list-rules"),
            ("events", "list-tags-for-resource"),
            ("events", "list-targets-by-rule"),
        }
    ),
    # excluded: get-activity-task (dequeues; side effect),
    #   get-execution-history (step I/O including decrypted params)
    "stepfunctions": frozenset(
        {
            ("stepfunctions", "describe-activity"),
            ("stepfunctions", "describe-execution"),
            ("stepfunctions", "describe-map-run"),
            ("stepfunctions", "describe-state-machine"),
            ("stepfunctions", "describe-state-machine-alias"),
            ("stepfunctions", "describe-state-machine-for-execution"),
            ("stepfunctions", "list-activities"),
            ("stepfunctions", "list-executions"),
            ("stepfunctions", "list-map-runs"),
            ("stepfunctions", "list-state-machine-aliases"),
            ("stepfunctions", "list-state-machine-versions"),
            ("stepfunctions", "list-state-machines"),
            ("stepfunctions", "list-tags-for-resource"),
        }
    ),
    # no excluded verbs (org structure is metadata)
    "organizations": frozenset(
        {
            ("organizations", "describe-account"),
            ("organizations", "describe-create-account-status"),
            ("organizations", "describe-effective-policy"),
            ("organizations", "describe-handshake"),
            ("organizations", "describe-organization"),
            ("organizations", "describe-organizational-unit"),
            ("organizations", "describe-policy"),
            ("organizations", "describe-resource-policy"),
            ("organizations", "list-accounts"),
            ("organizations", "list-accounts-for-parent"),
            ("organizations", "list-aws-service-access-for-organization"),
            ("organizations", "list-children"),
            ("organizations", "list-create-account-status"),
            ("organizations", "list-delegated-administrators"),
            ("organizations", "list-delegated-services-for-account"),
            ("organizations", "list-handshakes-for-account"),
            ("organizations", "list-handshakes-for-organization"),
            ("organizations", "list-organizational-units-for-parent"),
            ("organizations", "list-parents"),
            ("organizations", "list-policies"),
            ("organizations", "list-policies-for-target"),
            ("organizations", "list-roots"),
            ("organizations", "list-tags-for-resource"),
            ("organizations", "list-targets-for-policy"),
        }
    ),
    # no excluded verbs
    "support": frozenset(
        {
            ("support", "describe-attachment"),
            ("support", "describe-cases"),
            ("support", "describe-communications"),
            ("support", "describe-create-case-options"),
            ("support", "describe-services"),
            ("support", "describe-severity-levels"),
            ("support", "describe-supported-languages"),
            ("support", "describe-trusted-advisor-check-refresh-statuses"),
            ("support", "describe-trusted-advisor-check-result"),
            ("support", "describe-trusted-advisor-check-summaries"),
            ("support", "describe-trusted-advisor-checks"),
        }
    ),
    # no excluded verbs
    "pricing": frozenset(
        {
            ("pricing", "describe-services"),
            ("pricing", "get-attribute-values"),
            ("pricing", "get-price-list-file-url"),
            ("pricing", "get-products"),
            ("pricing", "list-price-lists"),
        }
    ),
    # no excluded verbs
    "servicequotas": frozenset(
        {
            ("servicequotas", "get-association-for-service-quota-template"),
            ("servicequotas", "get-aws-default-service-quota"),
            ("servicequotas", "get-requested-service-quota-change"),
            ("servicequotas", "get-service-quota"),
            ("servicequotas", "get-service-quota-increase-request-from-template"),
            ("servicequotas", "list-aws-default-service-quotas"),
            ("servicequotas", "list-requested-service-quota-change-history"),
            ("servicequotas", "list-requested-service-quota-change-history-by-quota"),
            ("servicequotas", "list-service-quota-increase-requests-in-template"),
            ("servicequotas", "list-service-quotas"),
            ("servicequotas", "list-services"),
            ("servicequotas", "list-tags-for-resource"),
        }
    ),
    # excluded: get-query-results (CloudTrail Lake rows; may contain sensitive params)
    "cloudtrail": frozenset(
        {
            ("cloudtrail", "describe-query"),
            ("cloudtrail", "describe-trails"),
            ("cloudtrail", "get-channel"),
            ("cloudtrail", "get-event-data-store"),
            ("cloudtrail", "get-event-selectors"),
            ("cloudtrail", "get-import"),
            ("cloudtrail", "get-insight-selectors"),
            ("cloudtrail", "get-resource-policy"),
            ("cloudtrail", "get-trail"),
            ("cloudtrail", "get-trail-status"),
            ("cloudtrail", "list-channels"),
            ("cloudtrail", "list-event-data-stores"),
            ("cloudtrail", "list-import-failures"),
            ("cloudtrail", "list-imports"),
            ("cloudtrail", "list-public-keys"),
            ("cloudtrail", "list-queries"),
            ("cloudtrail", "list-tags"),
            ("cloudtrail", "list-trails"),
            ("cloudtrail", "lookup-events"),
        }
    ),
    # no excluded verbs (compliance/audit metadata)
    "config": frozenset(
        {
            ("config", "describe-aggregate-compliance-by-config-rules"),
            ("config", "describe-aggregate-compliance-by-conformance-packs"),
            ("config", "describe-aggregation-authorizations"),
            ("config", "describe-compliance-by-config-rule"),
            ("config", "describe-compliance-by-resource"),
            ("config", "describe-config-rule-evaluation-status"),
            ("config", "describe-config-rules"),
            ("config", "describe-configuration-aggregator-sources-status"),
            ("config", "describe-configuration-aggregators"),
            ("config", "describe-configuration-recorder-status"),
            ("config", "describe-configuration-recorders"),
            ("config", "describe-conformance-pack-compliance"),
            ("config", "describe-conformance-pack-status"),
            ("config", "describe-conformance-packs"),
            ("config", "describe-delivery-channel-status"),
            ("config", "describe-delivery-channels"),
            ("config", "describe-organization-config-rule-statuses"),
            ("config", "describe-organization-config-rules"),
            ("config", "describe-organization-conformance-pack-statuses"),
            ("config", "describe-organization-conformance-packs"),
            ("config", "describe-pending-aggregation-requests"),
            ("config", "describe-remediation-configurations"),
            ("config", "describe-remediation-exceptions"),
            ("config", "describe-remediation-execution-status"),
            ("config", "describe-retention-configurations"),
            ("config", "get-aggregate-compliance-details-by-config-rule"),
            ("config", "get-aggregate-config-rule-compliance-summary"),
            ("config", "get-aggregate-conformance-pack-compliance-summary"),
            ("config", "get-aggregate-discovered-resource-counts"),
            ("config", "get-aggregate-resource-config"),
            ("config", "get-compliance-details-by-config-rule"),
            ("config", "get-compliance-details-by-resource"),
            ("config", "get-compliance-summary-by-config-rule"),
            ("config", "get-compliance-summary-by-resource-type"),
            ("config", "get-conformance-pack-compliance-details"),
            ("config", "get-conformance-pack-compliance-summary"),
            ("config", "get-custom-rule-policy"),
            ("config", "get-discovered-resource-counts"),
            ("config", "get-organization-config-rule-detailed-status"),
            ("config", "get-organization-conformance-pack-detailed-status"),
            ("config", "get-organization-custom-rule-policy"),
            ("config", "get-resource-config-history"),
            ("config", "get-resource-evaluation-summary"),
            ("config", "get-status"),
            ("config", "get-stored-query"),
            ("config", "list-aggregate-discovered-resources"),
            ("config", "list-configuration-recorders"),
            ("config", "list-conformance-pack-compliance-scores"),
            ("config", "list-discovered-resources"),
            ("config", "list-resource-evaluations"),
            ("config", "list-stored-queries"),
            ("config", "list-tags-for-resource"),
        }
    ),
    # excluded: start-report-creation (write; triggers async tagging report job)
    "resourcegroupstaggingapi": frozenset(
        {
            ("resourcegroupstaggingapi", "describe-report-creation"),
            ("resourcegroupstaggingapi", "get-compliance-summary"),
            ("resourcegroupstaggingapi", "get-resources"),
            ("resourcegroupstaggingapi", "get-tag-keys"),
            ("resourcegroupstaggingapi", "get-tag-values"),
        }
    ),
}

_AWS_READ_ONLY_VERBS: frozenset[tuple[str, str]] = frozenset().union(
    *_AWS_READ_ONLY_VERBS_BY_SERVICE.values()
)


def _aws_verb(tokens: list[str]) -> tuple[str, ...]:
    """Return (service, verb) from a stripped aws token list."""
    return tuple(tokens[1:3])


def _gcloud_verb(tokens: list[str]) -> tuple[str, ...]:
    """Return all non-flag positionals after the head."""
    return tuple(t for t in tokens[1:] if not t.startswith("-"))


def _az_verb(tokens: list[str]) -> tuple[str, ...]:
    """Return all non-flag positionals after the head."""
    return tuple(t for t in tokens[1:] if not t.startswith("-"))


def _kubectl_verb(tokens: list[str]) -> tuple[str, ...]:
    """Return all non-flag positionals after the head (supports `auth can-i`, `config view`)."""
    return tuple(t for t in tokens[1:] if not t.startswith("-"))


def _launchctl_verb(tokens: list[str]) -> tuple[str, ...]:
    """Return (verb,) — launchctl verb is the first positional."""
    return (tokens[1],) if len(tokens) > 1 else ()


# ---------------------------------------------------------------------------
# v1.3.0 forbidden-flag layer constants
# ---------------------------------------------------------------------------

# AWS
_AWS_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        # CRIT -- endpoint redirect / credential delivery to attacker host
        "--endpoint-url",
        # CRIT -- disables TLS, enables MITM
        "--no-verify-ssl",
        # HIGH -- swaps CA bundle; stealth MITM
        "--ca-bundle",
        # HIGH -- strips SigV4 signing; loses CloudTrail attribution
        "--no-sign-request",
        # HIGH -- profile switching; credential escape hatch
        "--profile",
        # HIGH -- debug dumps Authorization header + response secrets to stderr
        "--debug",
        # HIGH -- overrides entire request body from attacker-controlled file
        "--cli-input-json",
        "--cli-input-yaml",
    }
)

_AWS_SENSITIVE_ENV_VARS: frozenset[str] = frozenset(
    {
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_*",  # service-specific overrides -- prefix match
        "AWS_CA_BUNDLE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_PROFILE",
        # Inline-assignment of literal credentials. Lets an attacker run an
        # allowlisted read verb against a foreign account without touching
        # the local profile chain.
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    }
)

# Known-safe AWS global flags (value-consuming: each consumes next token).
# These are safe to strip before verb extraction.
_AWS_KNOWN_FLAGS: frozenset[str] = frozenset(
    {
        "--region",
        "--output",
        "--query",
        "--color",
        "--cli-binary-format",
        "--page-size",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--no-paginate",
        "--no-cli-pager",
        "--no-cli-auto-prompt",
        "--cli-error-format",
        "--generate-cli-skeleton",
        "--max-results",
        "--starting-token",
    }
)

# gcloud
_GCLOUD_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        # CRIT -- identity switching via service account impersonation
        "--impersonate-service-account",
        # CRIT -- credential file override; replaces auth context entirely
        "--credential-file-override",
        # CRIT -- bearer token injection from file
        "--access-token-file",
        # CRIT -- switches named configuration; bundles all other overrides
        "--configuration",
        # HIGH -- switches active account
        "--account",
        # HIGH -- dumps Authorization: Bearer token to stderr/logs
        "--log-http",
        # HIGH -- loads flags from file, bypassing flag-name checks
        "--flags-file",
    }
)

_GCLOUD_FORBIDDEN_SUBCOMMANDS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("auth", "activate-service-account"),
        ("auth", "login"),
        ("config", "set", "auth/credential_file_override"),
    }
)

_GCLOUD_SENSITIVE_ENV_VARS: frozenset[str] = frozenset(
    {
        "CLOUDSDK_API_ENDPOINT_OVERRIDES_*",  # prefix match
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "CLOUDSDK_CORE_PROJECT",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
    }
)

_GCLOUD_KNOWN_FLAGS: frozenset[str] = frozenset(
    {
        "--project",
        "--format",
        "--verbosity",
        "--quiet",
        "-q",
        "--filter",
        "--limit",
        "--page-size",
        "--sort-by",
        "--uri",
        "--async",
        "--billing-project",
        "--quota-project",
        "--no-user-output-enabled",
        "--user-output-enabled",
    }
)

# az
_AZ_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        # HIGH -- CVE-2023-36052: leaks bearer token to logs
        "--debug",
    }
)

_AZ_FORBIDDEN_SUBCOMMANDS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("rest",),  # full allowlist bypass
        ("cloud", "register"),
        ("cloud", "set"),
        ("cloud", "update"),
        ("login", "--service-principal"),  # subcommand+flag combo
        ("extension", "add"),  # --source <URL> is RCE
        ("config", "set"),  # persistent config injection
        ("logout",),  # auth-state mutation
    }
)

_AZ_SENSITIVE_ENV_VARS: frozenset[str] = frozenset(
    {
        "AZURE_CONFIG_DIR",
        "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION",
        "REQUESTS_CA_BUNDLE",
    }
)

_AZ_KNOWN_FLAGS: frozenset[str] = frozenset(
    {
        "--subscription",
        "--output",
        "-o",
        "--query",
        "--verbose",
        "--only-show-errors",
        "--resource-group",
        "-g",
        "--name",
        "-n",
        "--location",
        "-l",
        "--no-wait",
        "--yes",
        "-y",
    }
)

# kubectl: DENY-class flags moved OUT of the strip lists
_KUBECTL_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        # CRIT -- RBAC impersonation
        "--as",
        "--as-group",
        "--as-uid",
        "--as-user-extra",
        # CRIT -- cluster redirect
        "--server",
        "-s",
        "--cluster",
        # CRIT -- TLS weakening
        "--insecure-skip-tls-verify",
        "--certificate-authority",
        "--tls-server-name",
        # CRIT -- credential swap
        "--token",
        "--client-certificate",
        "--client-key",
        "--kubeconfig",
        # HIGH -- account/context switches
        "--context",
        "--user",
        "--username",
        "--password",
        # MED -- verbosity token leakage (treat all as forbidden in agent context)
        "-v",
        "--v",
    }
)

_KUBECTL_KNOWN_FLAGS: frozenset[str] = frozenset(
    {
        "--namespace",
        "-n",
        "--output",
        "-o",
        "--selector",
        "-l",
        "--field-selector",
        "--request-timeout",
        "--all-namespaces",
        "-A",
        "--show-labels",
        "--sort-by",
        "--no-headers",
        "--ignore-not-found",
        "--warnings-as-errors",
        "--watch",
        "-w",
        "--watch-only",
    }
)

# Safe kubectl global value flags for stripping before verb extraction.
# CRITICAL: DENY-class flags are NOT in this list -- they go to forbidden_flags.
_KUBECTL_GLOBAL_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--namespace",
        "-n",
        "--request-timeout",
        "--cache-dir",
    }
)

_KUBECTL_GLOBAL_BARE_FLAGS: frozenset[str] = frozenset(
    {
        "--warnings-as-errors",
    }
)

_AWS_SPEC = AdminCliSpec(
    cli_name="aws",
    read_only_verbs=_AWS_READ_ONLY_VERBS,
    verb_extractor=_aws_verb,
    # Safe value-consuming global flags (stripped before verb extraction)
    global_value_flags=frozenset(
        {
            "--region",
            "--output",
            "--query",
            "--color",
            "--cli-binary-format",
            "--page-size",
            "--cli-read-timeout",
            "--cli-connect-timeout",
            "--max-results",
            "--starting-token",
        }
    ),
    global_bare_flags=frozenset(
        {
            "--no-paginate",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            "--cli-error-format",
            "--",
        }
    ),
    forbidden_flags=_AWS_FORBIDDEN_FLAGS,
    sensitive_env_vars=_AWS_SENSITIVE_ENV_VARS,
    known_flags=_AWS_KNOWN_FLAGS,
)

_GCLOUD_SPEC = AdminCliSpec(
    cli_name="gcloud",
    read_only_verbs=_GCLOUD_READ_ONLY_VERBS,
    verb_extractor=_gcloud_verb,
    track_prefixes=frozenset({"alpha", "beta"}),
    global_value_flags=frozenset(
        {
            "--project",
            "--format",
            "--verbosity",
            "--billing-project",
            "--quota-project",
        }
    ),
    global_bare_flags=frozenset({"--quiet", "-q", "--help", "-h"}),
    forbidden_flags=_GCLOUD_FORBIDDEN_FLAGS,
    forbidden_subcommands=_GCLOUD_FORBIDDEN_SUBCOMMANDS,
    sensitive_env_vars=_GCLOUD_SENSITIVE_ENV_VARS,
    known_flags=_GCLOUD_KNOWN_FLAGS,
)

_AZ_SPEC = AdminCliSpec(
    cli_name="az",
    read_only_verbs=_AZ_READ_ONLY_VERBS,
    verb_extractor=_az_verb,
    global_value_flags=frozenset(
        {
            "--subscription",
            "--output",
            "-o",
            "--query",
            "--verbose",
            "--only-show-errors",
        }
    ),
    global_bare_flags=frozenset({"--help", "-h"}),
    forbidden_flags=_AZ_FORBIDDEN_FLAGS,
    forbidden_subcommands=_AZ_FORBIDDEN_SUBCOMMANDS,
    sensitive_env_vars=_AZ_SENSITIVE_ENV_VARS,
    known_flags=_AZ_KNOWN_FLAGS,
)

_KUBECTL_SPEC = AdminCliSpec(
    cli_name="kubectl",
    read_only_verbs=_KUBECTL_READ_ONLY_VERBS,
    verb_extractor=_kubectl_verb,
    global_value_flags=_KUBECTL_GLOBAL_VALUE_FLAGS,
    global_bare_flags=_KUBECTL_GLOBAL_BARE_FLAGS,
    forbidden_flags=_KUBECTL_FORBIDDEN_FLAGS,
    known_flags=_KUBECTL_KNOWN_FLAGS,
)

_LAUNCHCTL_SPEC = AdminCliSpec(
    cli_name="launchctl",
    read_only_verbs=_LAUNCHCTL_READ_ONLY_VERBS,
    verb_extractor=_launchctl_verb,
)

ADMIN_CLI_SPECS: tuple[AdminCliSpec, ...] = (
    _AWS_SPEC,
    _GCLOUD_SPEC,
    _AZ_SPEC,
    _KUBECTL_SPEC,
    _LAUNCHCTL_SPEC,
)


def summary_for(cli_name: str) -> str:
    """Return a short comma-joined string of top-level read-only verbs for the deny message.

    For AWS, returns the predicate description (the prefix model). For other CLIs,
    returns the unique top-level verbs (first element of each tuple) joined by commas.
    Falls back to "(none)" for unknown cli_name.
    """
    if cli_name == "aws":
        return "explicit verb catalog; see SECURITY.md"
    for spec in ADMIN_CLI_SPECS:
        if spec.cli_name == cli_name:
            # Top-level verbs only (first element of each tuple), de-duplicated, sorted.
            tops = sorted({t[0] for t in spec.read_only_verbs if t})
            return ", ".join(tops) if tops else "(none)"
    return "(none)"
