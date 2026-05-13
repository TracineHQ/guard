# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Branch coverage for small admin-CLI helpers.

These tests target specific untested branches surfaced in the v1.3.0
backlog review: empty-CLI entry in env-var parsing, unknown-flag
passthrough in cloud-flag stripping, non-AWS branches in
summary_for, and the non-dict-item skip in allow_commands.
"""

from __future__ import annotations

from guard.allowlist import _validate_allow_commands
from guard.hooks._admin_specs import ADMIN_CLI_SPECS, summary_for
from guard.hooks.bash_command_validator import _strip_cloud_global_flags


class TestStripCloudGlobalFlagsUnknownFlag:
    def test_unknown_long_flag_skipped_not_consume_value(self) -> None:
        # ``--unknown-flag`` is not in known value/bare flag sets. The skip
        # branch advances by 1 without consuming the next token, so the
        # subsequent path is preserved verbatim.
        tokens = ["aws", "--unknown-flag", "ec2", "describe-instances"]
        out = _strip_cloud_global_flags(
            tokens, value_flags=frozenset({"--region"}), bare_flags=frozenset()
        )
        assert out == ["aws", "ec2", "describe-instances"]

    def test_unknown_flag_followed_by_positional(self) -> None:
        tokens = ["gcloud", "--mystery", "compute", "instances", "list"]
        out = _strip_cloud_global_flags(
            tokens, value_flags=frozenset({"--project"}), bare_flags=frozenset()
        )
        assert out == ["gcloud", "compute", "instances", "list"]

    def test_empty_tokens(self) -> None:
        assert _strip_cloud_global_flags([], frozenset(), frozenset()) == []


class TestValidateAllowCommandsNonDictSkip:
    def test_non_dict_item_skipped(self) -> None:
        # Mixed list: valid entry, a bare string (skipped), another valid.
        raw = [
            {"rule": "bash.x", "command": "ls", "reason": "ok"},
            "not-a-dict",
            42,
            {"rule": "bash.y", "command": "pwd", "reason": "ok"},
        ]
        out = _validate_allow_commands(raw, source="<test>")
        assert len(out) == 2
        assert out[0].rule == "bash.x"
        assert out[1].rule == "bash.y"


class TestSummaryForNonAws:
    def test_non_aws_cli_returns_top_level_verbs(self) -> None:
        non_aws_clis = [s.cli_name for s in ADMIN_CLI_SPECS if s.cli_name != "aws"]
        assert non_aws_clis, "test setup: expected at least one non-AWS spec"
        for cli in non_aws_clis:
            summary = summary_for(cli)
            assert isinstance(summary, str)
            assert summary, f"empty summary for {cli!r}"

    def test_unknown_cli_returns_none_marker(self) -> None:
        assert summary_for("definitely-not-a-cli") == "(none)"
