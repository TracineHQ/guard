# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Integration tests for unknown-flag telemetry and forbidden admin flags."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny, run_hook


class TestUnknownFlagsInteractiveAllow:
    """In interactive mode, unknown flags on allowed admin CLIs are captured in JSONL."""

    def test_known_safe_command_allows(self) -> None:
        # A clean aws command with no unknown flags should allow
        result = decide("aws ec2 describe-instances")
        assert not is_deny(result)

    def test_unknown_flag_allows_in_interactive_mode(self, tmp_path: Path) -> None:
        """Unknown flags on allowed commands are logged but not denied in interactive mode."""
        decisions_path = tmp_path / "decisions.jsonl"
        rc, stdout, stderr = run_hook(
            "bash_command_validator",
            "aws ec2 describe-instances --unknown-extra-flag",
            decisions_path=decisions_path,
        )
        # Should allow (no deny decision)
        if stdout.strip():
            output = json.loads(stdout)
            hso = output.get("hookSpecificOutput", {})
            assert hso.get("permissionDecision") != "deny", f"unexpected deny: {stdout}"

    @pytest.mark.xfail(
        reason=(
            "Interactive-mode admin CLIs route through evaluator-passthrough "
            "when no segment is on SAFE_PREFIXES, so the explicit-allow "
            "branch that attaches `unknown_flags` telemetry never fires. "
            "Keeping this test as xfail so the day "
            "interactive-mode telemetry IS wired, this lights up green and "
            "we delete the marker."
        ),
        strict=True,
    )
    def test_unknown_flags_captured_in_jsonl(self, tmp_path: Path) -> None:
        """Aspirational: unknown flags on interactive-allowed admin commands appear in JSONL."""
        decisions_path = tmp_path / "decisions.jsonl"
        run_hook(
            "bash_command_validator",
            "aws ec2 describe-instances --recursive --human-readable",
            decisions_path=decisions_path,
        )
        assert decisions_path.exists()
        records = [
            json.loads(line) for line in decisions_path.read_text().splitlines() if line.strip()
        ]
        unknown_flag_records = [r for r in records if r.get("unknown_flags")]
        assert unknown_flag_records, f"expected unknown_flags in JSONL, records: {records!r}"
        flags = unknown_flag_records[0]["unknown_flags"]
        assert "--recursive" in flags or "--human-readable" in flags


class TestAdminForbiddenFlag:
    def test_forbidden_flag_denies(self) -> None:
        """Forbidden flags deny with the forbidden-flag reason key."""
        result = decide("aws --endpoint-url=http://evil.com ec2 describe-instances")
        assert is_deny(result), f"expected deny, got: {result}"
        reason = result.get("permissionDecisionReason", "")
        assert "bash.admin_forbidden_flag" in reason
