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


_AWS_DENY_OVERRIDES: frozenset[tuple[str, ...]] = frozenset(
    {
        ("sts", "get-session-token"),
        ("sts", "get-federation-token"),
        ("ecr", "get-login-password"),
        ("ecr", "get-authorization-token"),
        ("cloudformation", "detect-stack-drift"),
        ("lambda", "invoke"),
        ("ssm", "start-session"),
    }
)

_AWS_READ_ONLY_VERBS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("s3", "ls"),
        ("s3", "presign"),
        ("logs", "tail"),
        ("logs", "filter-log-events"),
        ("logs", "start-live-tail"),
        ("iam", "simulate-principal-policy"),
        ("iam", "simulate-custom-policy"),
        ("cloudformation", "validate-template"),
        ("cloudformation", "detect-stack-resource-drift"),
        ("dynamodb", "query"),
        ("dynamodb", "scan"),
        ("dynamodb", "batch-get-item"),
        ("rds", "generate-db-auth-token"),
        ("ecr", "batch-check-layer-availability"),
    }
)


def _aws_is_read_only(verb_tuple: tuple[str, ...]) -> bool:
    """AWS read-only check: deny-overrides → explicit allowlist → describe-/list-/get- prefix.

    Three-step:
    1. If verb_tuple in _AWS_DENY_OVERRIDES, return False (these match the prefix
       but issue credentials or trigger async jobs -- explicitly NOT read-only).
    2. If verb_tuple in _AWS_READ_ONLY_VERBS, return True (curated exceptions
       that don't fit the predicate but are read-only).
    3. If len(verb_tuple) >= 2 and verb_tuple[1].startswith(("describe-", "list-", "get-")),
       return True (predicate covers the bulk of AWS read-only verbs).
    4. Otherwise, return False.
    """
    if verb_tuple in _AWS_DENY_OVERRIDES:
        return False
    if verb_tuple in _AWS_READ_ONLY_VERBS:
        return True
    return len(verb_tuple) >= 2 and verb_tuple[1].startswith(  # noqa: PLR2004
        ("describe-", "list-", "get-")
    )


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


_AWS_SPEC = AdminCliSpec(
    cli_name="aws",
    read_only_verbs=_AWS_READ_ONLY_VERBS,
    verb_extractor=_aws_verb,
    read_only_predicate=_aws_is_read_only,
    deny_overrides=_AWS_DENY_OVERRIDES,
)

_GCLOUD_SPEC = AdminCliSpec(
    cli_name="gcloud",
    read_only_verbs=_GCLOUD_READ_ONLY_VERBS,
    verb_extractor=_gcloud_verb,
    track_prefixes=frozenset({"alpha", "beta"}),
)

_AZ_SPEC = AdminCliSpec(
    cli_name="az",
    read_only_verbs=_AZ_READ_ONLY_VERBS,
    verb_extractor=_az_verb,
)

_KUBECTL_GLOBAL_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--context",
        "--kubeconfig",
        "--cluster",
        "--user",
        "--namespace",
        "-n",
        "--server",
        "-s",
        "--token",
        "--certificate-authority",
        "--request-timeout",
        "--as",
        "--as-group",
        "--as-uid",
        "-v",
        "--v",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
        "--cache-dir",
        "--password",
        "--username",
    }
)

_KUBECTL_GLOBAL_BARE_FLAGS: frozenset[str] = frozenset(
    {
        "--insecure-skip-tls-verify",
        "--warnings-as-errors",
    }
)

_KUBECTL_SPEC = AdminCliSpec(
    cli_name="kubectl",
    read_only_verbs=_KUBECTL_READ_ONLY_VERBS,
    verb_extractor=_kubectl_verb,
    global_value_flags=_KUBECTL_GLOBAL_VALUE_FLAGS,
    global_bare_flags=_KUBECTL_GLOBAL_BARE_FLAGS,
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
        return "describe-*, list-*, get-* (with exceptions)"
    for spec in ADMIN_CLI_SPECS:
        if spec.cli_name == cli_name:
            # Top-level verbs only (first element of each tuple), de-duplicated, sorted.
            tops = sorted({t[0] for t in spec.read_only_verbs if t})
            return ", ".join(tops) if tops else "(none)"
    return "(none)"
