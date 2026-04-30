"""Tests for chrome_safety_validator hook."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.chrome_safety_validator import (
    HAS_CHROME_SAFETY,
    extract_eval_expression,
    extract_profile_arg,
    extract_user_data_dir,
    hook,
)

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "chrome_safety_validator.py"
)


def _run(command, *, autonomous=False, tool_name="Bash"):
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"command": command}})
    env = os.environ.copy()
    if autonomous:
        env["CLAUDE_AUTONOMOUS"] = "1"
    else:
        env.pop("CLAUDE_AUTONOMOUS", None)
    result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
        [sys.executable, str(HOOK_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    out = result.stdout.strip()
    if out:
        envelope = json.loads(out)
        decision = envelope["hookSpecificOutput"]["permissionDecision"]
        reason = envelope["hookSpecificOutput"].get("permissionDecisionReason", "")
    else:
        decision = "passthrough"
        reason = ""
    return decision, reason, result.returncode


class TestImports:
    def test_chrome_safety_validator_imports(self):
        # Top-level import is the contract.
        assert callable(hook)


class TestExtractors:
    def test_extract_eval_double_quoted(self):
        assert extract_eval_expression('chrome eval "document.title"') == "document.title"

    def test_extract_eval_single_quoted(self):
        assert extract_eval_expression("chrome eval 'document.title'") == "document.title"

    def test_extract_eval_unquoted(self):
        assert extract_eval_expression("chrome eval document.title") == "document.title"

    def test_extract_eval_missing(self):
        assert extract_eval_expression("chrome eval") is None

    def test_extract_profile_arg(self):
        assert extract_profile_arg("chrome launch --profile testing") == "testing"

    def test_extract_profile_arg_missing(self):
        assert extract_profile_arg("chrome launch") is None

    def test_extract_user_data_dir_equals(self):
        cmd = "chrome launch --user-data-dir=/var/scratch/x"
        assert extract_user_data_dir(cmd) == "/var/scratch/x"

    def test_extract_user_data_dir_space(self):
        cmd = "chrome launch --user-data-dir /var/scratch/x"
        assert extract_user_data_dir(cmd) == "/var/scratch/x"


class TestProfileIsolation:
    """User-data-dir denial does not require chrome_cli (handled in-hook)."""

    def test_user_data_dir_blocked(self):
        decision, reason, code = _run("chrome launch --user-data-dir=/tmp/chrome-data")
        if HAS_CHROME_SAFETY:
            assert decision == "deny"
            assert code == 2
        else:
            # Without chrome_cli the hook shortcuts to passthrough.
            assert decision == "passthrough"
        if decision == "deny":
            assert "--profile" in reason.lower() or "user-data-dir" in reason.lower()

    def test_user_data_dir_equals_syntax(self):
        decision, _reason, _code = _run(
            "chrome launch --user-data-dir=/home/user/.config/google-chrome"
        )
        if HAS_CHROME_SAFETY:
            assert decision == "deny"


class TestSafeCommandsPassthrough:
    @pytest.mark.parametrize(
        "cmd",
        [
            "chrome tree",
            "chrome status",
            "chrome page",
            "chrome screenshot",
            "chrome launch",
            "chrome stop",
        ],
    )
    def test_safe_commands_passthrough(self, cmd):
        decision, _reason, _code = _run(cmd)
        assert decision == "passthrough"


class TestNonChromePassthrough:
    def test_non_chrome_command(self):
        decision, _, _ = _run("git status")
        assert decision == "passthrough"

    def test_non_bash_tool(self):
        decision, _, _ = _run("chrome eval 'document.cookie'", tool_name="Read")
        assert decision == "passthrough"

    def test_empty_command(self):
        decision, _, _ = _run("")
        assert decision == "passthrough"

    def test_chrome_prefix_only(self):
        decision, _, _ = _run("chrome")
        assert decision == "passthrough"


class TestAutonomousMode:
    @pytest.mark.parametrize(
        "cmd",
        [
            "chrome navigate https://example.com",
            "chrome click button.submit",
            "chrome fill input[name=email] x@y",
            "chrome eval document.title",
            "chrome launch",
            "chrome stop",
        ],
    )
    def test_autonomous_denies_write_commands(self, cmd):
        if not HAS_CHROME_SAFETY:
            pytest.skip("chrome_cli not installed")
        decision, _reason, code = _run(cmd, autonomous=True)
        assert decision == "deny"
        assert code == 2

    def test_autonomous_allows_read_commands(self):
        if not HAS_CHROME_SAFETY:
            pytest.skip("chrome_cli not installed")
        decision, _, _ = _run("chrome tree", autonomous=True)
        assert decision == "passthrough"


class TestDangerousEvalDeniedWhenChromeSafetyAvailable:
    """Eval validation requires the chrome_cli.safety module."""

    def test_chrome_safety_validator_denies_unsafe_input(self):
        if not HAS_CHROME_SAFETY:
            pytest.skip("chrome_cli not installed — cannot validate eval")
        decision, _reason, code = _run('chrome eval "document.cookie"')
        assert decision == "deny"
        assert code == 2

    def test_chrome_safety_validator_allows_safe_input(self):
        # Safe path even without chrome_cli (passthrough).
        decision, _, _ = _run("chrome tree")
        assert decision == "passthrough"


class TestSubprocessSmoke:
    def test_empty_stdin(self):
        result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
            [sys.executable, str(HOOK_PATH)],
            input="",
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_malformed_json(self):
        result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
            [sys.executable, str(HOOK_PATH)],
            input="not json",
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
