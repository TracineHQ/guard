"""Tests for agent_output_guard hook."""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.agent_output_guard import decide, hook

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "agent_output_guard.py"
)


class TestDecide:
    def test_read_agent_output_denied(self):
        result = decide(
            "Read",
            {"file_path": "/private/tmp/claude-501/-Users-dev/abc123/tasks/xyz.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_cat_agent_output_denied(self):
        result = decide(
            "Bash",
            {"command": "cat /private/tmp/claude-501/-Users-dev/abc/tasks/test.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_head_agent_output_denied(self):
        result = decide(
            "Bash",
            {"command": "head -5 /private/tmp/claude-501/proj/sess/tasks/a.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_tail_agent_output_denied(self):
        result = decide(
            "Bash",
            {"command": "tail -1 /private/tmp/claude-501/proj/sess/tasks/a.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_read_normal_file_passes(self):
        assert decide("Read", {"file_path": "/Users/dev/src/main.py"}) is None

    def test_cat_normal_file_passes(self):
        assert decide("Bash", {"command": "cat /Users/dev/src/main.py"}) is None

    def test_non_output_extension_passes(self):
        assert (
            decide(
                "Read",
                {"file_path": "/private/tmp/claude-501/proj/sess/tasks/config.json"},
            )
            is None
        )

    def test_other_tool_passes(self):
        assert decide("Grep", {"pattern": "test"}) is None

    def test_empty_inputs_pass(self):
        assert decide("Read", {}) is None
        assert decide("Bash", {}) is None

    def test_deny_message_is_tool_neutral(self):
        result = decide("Read", {"file_path": "/private/tmp/claude-1/x/tasks/y.output"})
        assert result is not None
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        assert "agent output files" in reason.lower()

    def test_linux_path_read_denied(self):
        """Linux subagent output dir is /tmp/claude-<pid>/... (no /private prefix)."""
        result = decide(
            "Read",
            {"file_path": "/tmp/claude-12345/proj/sess/tasks/abc.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_linux_path_cat_denied(self):
        result = decide(
            "Bash",
            {"command": "cat /tmp/claude-99/proj/sess/tasks/abc.output"},
        )
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_unrelated_dot_output_passes(self):
        """Paths containing .output mid-string outside /tasks/ must not match."""
        assert decide("Read", {"file_path": "/Users/dev/x.output.bak"}) is None
        assert decide("Read", {"file_path": "/var/log/foo.output_old"}) is None


class TestExpandedReaderCoverage:
    """File-reader coverage beyond cat/head/tail."""

    @pytest.mark.parametrize(
        "command",
        [
            "less /private/tmp/claude-1/x/tasks/y.output",
            "bat /private/tmp/claude-1/x/tasks/y.output",
            "more /private/tmp/claude-1/x/tasks/y.output",
            "vim /private/tmp/claude-1/x/tasks/y.output",
            "view /private/tmp/claude-1/x/tasks/y.output",
            "xxd /private/tmp/claude-1/x/tasks/y.output",
            "hexdump /private/tmp/claude-1/x/tasks/y.output",
            "strings /private/tmp/claude-1/x/tasks/y.output",
            "rg foo /private/tmp/claude-1/x/tasks/y.output",
            "grep foo /private/tmp/claude-1/x/tasks/y.output",
            "tac /private/tmp/claude-1/x/tasks/y.output",
            " cat /private/tmp/claude-1/x/tasks/y.output",  # leading space
            "/bin/cat /private/tmp/claude-1/x/tasks/y.output",  # absolute path
        ],
    )
    def test_reader_command_denied(self, command):
        result = decide("Bash", {"command": command})
        assert result is not None
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.parametrize(
        "command",
        [
            # copy / move / network-copy
            "cp /private/tmp/claude-1/x/tasks/y.output /tmp/leak.txt",
            "mv /private/tmp/claude-1/x/tasks/y.output /tmp/leak.txt",
            "scp /tmp/claude-1/x/tasks/y.output user@host:/tmp/",
            "rsync /tmp/claude-1/x/tasks/y.output backup:/tmp/",
            "dd if=/private/tmp/claude-1/x/tasks/y.output of=/tmp/leak",
            # editors
            "nano /private/tmp/claude-1/x/tasks/y.output",
            "emacs /private/tmp/claude-1/x/tasks/y.output",
            # fingerprinting / size-leak
            "wc -l /private/tmp/claude-1/x/tasks/y.output",
            "md5sum /private/tmp/claude-1/x/tasks/y.output",
            "shasum /private/tmp/claude-1/x/tasks/y.output",
            "diff /private/tmp/claude-1/x/tasks/y.output /tmp/other",
            "tee /tmp/leak < /private/tmp/claude-1/x/tasks/y.output",
        ],
    )
    def test_extended_reader_command_denied(self, command):
        result = decide("Bash", {"command": command})
        assert result is not None, f"reader missed: {command!r}"
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestDecideRobustness:
    def test_numeric_file_path(self):
        with contextlib.suppress(TypeError):
            decide("Read", {"file_path": 12345})

    def test_empty_command_string(self):
        assert decide("Bash", {"command": ""}) is None

    def test_missing_file_path_key(self):
        assert decide("Read", {"other_key": "value"}) is None

    def test_missing_command_key(self):
        assert decide("Bash", {"other_key": "value"}) is None


class TestHookFunction:
    def test_agent_output_guard_imports(self):
        # Top-level import is the contract.
        assert callable(hook)

    def test_agent_output_guard_allows_safe_input(self, capsys):
        hook({"tool_name": "Read", "tool_input": {"file_path": "/Users/dev/file.py"}})
        assert capsys.readouterr().out == ""

    def test_agent_output_guard_denies_unsafe_input(self, capsys):
        # Fix #7: deny path now exits 2 — wrap in pytest.raises(SystemExit).
        with pytest.raises(SystemExit) as exc:
            hook(
                {
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/private/tmp/claude-1/proj/sess/tasks/x.output"},
                }
            )
        assert exc.value.code == 2
        out = capsys.readouterr().out
        envelope = json.loads(out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestSubprocess:
    def _run_hook(self, stdin_data):
        return subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=stdin_data,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_empty_stdin(self):
        result = self._run_hook("")
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_malformed_json(self):
        # Malformed JSON fails closed with rc=2 instead of silently passing.
        result = self._run_hook("not json at all")
        assert result.returncode == 2

    def test_json_missing_keys(self):
        result = self._run_hook(json.dumps({"unexpected": "data"}))
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_subprocess_denies_agent_output(self):
        # Fix #7: deny path now exits 2.
        payload = json.dumps(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/private/tmp/claude-1/proj/sess/tasks/x.output"},
            }
        )
        result = self._run_hook(payload)
        assert result.returncode == 2
        envelope = json.loads(result.stdout)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"
