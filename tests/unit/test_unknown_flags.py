# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Unit tests for _collect_unknown_flags helper."""

from __future__ import annotations

from guard.hooks._admin_specs import _AWS_SPEC, _KUBECTL_SPEC
from guard.hooks.bash_command_validator import _collect_unknown_flags


class TestCollectUnknownFlags:
    def test_bare_unknown_flag_captured(self) -> None:
        result = _collect_unknown_flags(_AWS_SPEC, ["ec2", "describe-instances", "--recursive"])
        assert "--recursive" in result

    def test_fused_unknown_flag_stripped_to_name(self) -> None:
        # --profile=prod -> captured as --profile (which is actually forbidden, test with --no-cli-pager)
        result = _collect_unknown_flags(_AWS_SPEC, ["s3", "ls", "--no-cli-pager=true"])
        # --no-cli-pager is in known_flags, so it should NOT be in unknown
        assert "--no-cli-pager" not in result

    def test_fused_form_unknown_emits_flag_only(self) -> None:
        # A truly unknown fused flag
        result = _collect_unknown_flags(_AWS_SPEC, ["s3", "ls", "--some-unknown-flag=value"])
        assert "--some-unknown-flag" in result
        assert "value" not in str(result)

    def test_value_consuming_flag_value_not_captured(self) -> None:
        # --region us-east-1: us-east-1 should not be captured
        result = _collect_unknown_flags(
            _AWS_SPEC, ["--region", "us-east-1", "ec2", "describe-instances"]
        )
        assert "us-east-1" not in result

    def test_known_flag_not_captured(self) -> None:
        # --no-cli-pager is in _AWS_KNOWN_FLAGS
        result = _collect_unknown_flags(_AWS_SPEC, ["s3", "ls", "--no-cli-pager"])
        assert "--no-cli-pager" not in result

    def test_forbidden_flag_not_captured_as_unknown(self) -> None:
        # --endpoint-url is forbidden, not unknown
        result = _collect_unknown_flags(
            _AWS_SPEC, ["sts", "--endpoint-url", "http://evil", "get-caller-identity"]
        )
        assert "--endpoint-url" not in result

    def test_cap_at_8(self) -> None:
        tokens = [f"--unknown-{i}" for i in range(12)]
        result = _collect_unknown_flags(_AWS_SPEC, tokens)
        assert len(result) == 8

    def test_deduplication(self) -> None:
        tokens = ["--unknown-flag", "--unknown-flag", "--unknown-flag"]
        result = _collect_unknown_flags(_AWS_SPEC, tokens)
        assert result.count("--unknown-flag") == 1

    def test_empty_tokens(self) -> None:
        result = _collect_unknown_flags(_AWS_SPEC, [])
        assert result == []

    def test_no_long_flags(self) -> None:
        result = _collect_unknown_flags(_AWS_SPEC, ["-n", "kube-system", "get", "pods"])
        assert result == []

    def test_short_flags_skipped(self) -> None:
        result = _collect_unknown_flags(
            _KUBECTL_SPEC, ["-n", "kube-system", "get", "pods", "-o", "wide"]
        )
        # Short flags should not appear in unknown_flags
        assert not any(f.startswith("-") and not f.startswith("--") for f in result)

    def test_fused_secret_value_not_leaked(self) -> None:
        # --token=BEARER_TOKEN_VALUE -> only --token captured
        result = _collect_unknown_flags(_AWS_SPEC, ["--some-unknown=SUPER_SECRET_VALUE"])
        assert "SUPER_SECRET_VALUE" not in str(result)
        assert "--some-unknown" in result

    def test_cap_default_is_8(self) -> None:
        tokens = [f"--flag{i}" for i in range(10)]
        result = _collect_unknown_flags(_AWS_SPEC, tokens)
        assert len(result) == 8

    def test_cap_custom(self) -> None:
        tokens = [f"--flag{i}" for i in range(10)]
        result = _collect_unknown_flags(_AWS_SPEC, tokens, cap=3)
        assert len(result) == 3

    def test_region_known_flag_not_in_unknown(self) -> None:
        result = _collect_unknown_flags(
            _AWS_SPEC, ["--region", "us-east-1", "ec2", "describe-instances"]
        )
        assert "--region" not in result
