# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Integration tests for unknown-flag telemetry and forbidden admin flags."""

from __future__ import annotations

import json
from pathlib import Path

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny, run_hook


class TestUnknownFlagsTelemetry:
    """Unknown flags on a passing admin CLI command are captured in JSONL."""

    def test_known_safe_command_passes(self) -> None:
        result = decide("aws ec2 describe-instances")
        assert result is None

    def test_unknown_flag_passes(self, tmp_path: Path) -> None:
        """Unknown flags on a read-only verb are logged, not denied."""
        decisions_path = tmp_path / "decisions.jsonl"
        rc, stdout, stderr = run_hook(
            "bash_command_validator",
            "aws ec2 describe-instances --unknown-extra-flag",
            decisions_path=decisions_path,
        )
        # No deny decision
        if stdout.strip():
            output = json.loads(stdout)
            hso = output.get("hookSpecificOutput", {})
            assert hso.get("permissionDecision") != "deny", f"unexpected deny: {stdout}"

    def test_unknown_flags_captured_in_jsonl(self, tmp_path: Path) -> None:
        """The pass record names the unknown flags, never their values."""
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
