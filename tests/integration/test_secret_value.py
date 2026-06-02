"""FP-4 complement: literal secret-VALUE detection (``bash.secret_value``).

``credential_leak`` matches credential CLI *names* (``gh auth token``, ``op
read``). This detector matches credential *values* an agent might echo, write,
or embed in a heredoc body. Two arms:

1. High-confidence provider prefixes (``sk-ant-``, ``AKIA...``, ``ghp_...``,
   PEM private-key headers, JWTs) deny anywhere in the command.
2. A high-entropy, mixed-charset value assigned to an env var (``NAME=VALUE``)
   denies via a Shannon-entropy + charset-diversity heuristic.

Pure-hex tokens (git SHAs, md5/sha digests) and low-diversity strings (paths,
flags) must NOT false-positive. The detector scans the RAW command (incl
heredoc bodies / write sinks), so a secret written to a doc is still caught.
Deny is a hard fence (both modes) but allowlist-routable (``bash.secret_value``).
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide


def _denied(result: dict | None) -> bool:
    return result is not None and result.get("permissionDecision") == "deny"


def _not_denied(result: dict | None) -> bool:
    return result is None or result.get("permissionDecision") != "deny"


def _is_secret_value_deny(result: dict | None) -> bool:
    return _denied(result) and "bash.secret_value" in (
        result.get("permissionDecisionReason", "") if result else ""
    )


# === Arm 1: high-confidence provider prefixes deny anywhere ===


class TestSecretValuePrefixesDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "echo sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEf",
            "export AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "echo AKIAIOSFODNN7EXAMPLE",
            "git remote add o https://ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789@github.com/x",
            # literal split so server-side secret scanners do not match the
            # token in source; decide() still receives the joined string
            "echo glpat-" + "aBcDeFgHiJkLmNoPqRs1",
            "curl -H 'Authorization: Bearer xoxb-1234567890-abcdefABCDEF'",
            "echo AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "TOK=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456",
        ],
    )
    def test_known_secret_prefix_denied(self, cmd: str) -> None:
        assert _is_secret_value_deny(decide(cmd)), f"should deny secret value: {cmd!r}"

    def test_pem_private_key_header_denied(self) -> None:
        cmd = "cat > key.pem <<'EOF'\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----\nEOF"
        assert _is_secret_value_deny(decide(cmd)), "PEM private key write must deny"

    def test_secret_in_heredoc_body_denied(self) -> None:
        # The whole point of FP-4: a secret VALUE written to a doc/file via a
        # heredoc is caught even though the credential-name scan ignores bodies.
        cmd = "tee .env <<EOF\nAPI_KEY=sk-ant-api03-ZZZyyyXXXwwwVVVuuuTTTsssRRRqqq0123456789ab\nEOF"
        assert _is_secret_value_deny(decide(cmd)), "secret in heredoc body must deny"

    @pytest.mark.parametrize(
        "cmd",
        [
            # FP-4 B5: the spec carried these as XFAIL ("no value scanner"). The
            # secret-value detector closes that floor — now a real deny.
            "tee docs/leak.md <<'EOF'\nAKIAIOSFODNN7EXAMPLE\nEOF",
            "cat > notes.md <<'EOF'\nsk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\nEOF",
        ],
    )
    def test_real_secret_value_in_writedoc_heredoc_denies(self, cmd: str) -> None:
        assert _is_secret_value_deny(decide(cmd)), f"write-sink heredoc secret must deny: {cmd!r}"


# === Arm 2: high-entropy env assignment denies ===


class TestSecretValueEntropyDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "export SECRET_KEY=Xy9kL2mNp7qR4sT8vW1zA6bC3dE5fG0hJ",
            "API_TOKEN=aB3dEf6GhJ9kLm2nPq5rSt8uVw1xYz4A7bC0dE secret",
            "DATABASE_PASSWORD=p9X2mK7nQ4wZ8vB1cR6tY3uH5jL0aS gunicorn",
        ],
    )
    def test_high_entropy_assignment_denied(self, cmd: str) -> None:
        assert _is_secret_value_deny(decide(cmd)), f"high-entropy assign should deny: {cmd!r}"


# === False-positive floor: ordinary high-entropy-looking args must NOT deny ===


class TestSecretValueNoFalsePositives:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git checkout 3f2a9b8e1d0c4f5a6b7c8d9e0f1a2b3c4d5e6f7a",  # 40-hex SHA
            "git reset --hard a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",  # hex
            "export PATH=/usr/local/bin:/usr/bin:/bin",  # path, has ':'
            "export NODE_OPTIONS=--max-old-space-size=4096",  # flag-ish
            "echo d41d8cd98f00b204e9800998ecf8427e",  # md5 (pure hex)
            "uuidgen && echo 550e8400-e29b-41d4-a716-446655440000",  # uuid
            "pip install requests==2.31.0",
            "docker pull node@sha256:3f2a9b8e1d0c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",  # hex digest
            "git log --oneline -n 20",
            "export GUARD_HOME=/Users/dev/.claude/guard",
        ],
    )
    def test_ordinary_args_not_denied(self, cmd: str) -> None:
        assert _not_denied(decide(cmd)), f"must not false-positive: {cmd!r}"

    @pytest.mark.parametrize(
        "cmd",
        [
            # fp-3: a high-entropy value assigned to a NON-credential-ish name is
            # an identifier/hash/path, not a secret. The entropy arm is gated on
            # the var NAME, so these no longer false-deny.
            "RUN_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 make",
            "OUTPUT=builds/2026-05-30T12-00-00Z-abc123def456 sh",
            "F=/tmp/550e8400-e29b-41d4-a716-446655440000/out cmd",
            "BUILD=9f8e7d6c5b4a39281706f5e4d3c2b1a0 ./run.sh",
        ],
    )
    def test_high_entropy_non_secret_name_not_denied(self, cmd: str) -> None:
        assert _not_denied(decide(cmd)), f"non-secret name must not false-positive: {cmd!r}"


# === Hard fence in strict; allowlist-routable ===


class TestSecretValueStrictAndOverride:
    def test_denies_in_strict_mode(self) -> None:
        assert _is_secret_value_deny(decide("echo AKIAIOSFODNN7EXAMPLE", permission_mode="dontAsk"))

    def test_deny_reason_names_rule_and_override(self) -> None:
        res = decide("echo AKIAIOSFODNN7EXAMPLE")
        reason = res["permissionDecisionReason"]
        assert "bash.secret_value" in reason
        assert "allowlist" in reason
