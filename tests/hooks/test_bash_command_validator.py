"""Tests for bash_command_validator hook."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.bash_command_validator import (
    _get_alternative_feedback,
    decide,
    has_dangerous_constructs,
    hook,
    is_safe_command,
    split_pipeline,
    strip_comments,
    strip_inline_comment,
)

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "bash_command_validator.py"
)


def _run(command, tmp_path=None):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    env = os.environ.copy()
    if tmp_path is not None:
        env["GUARD_DECISIONS_PATH"] = str(tmp_path / "decisions.jsonl")
    result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
        [sys.executable, str(HOOK_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    out = result.stdout.strip()
    decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "passthrough"
    return decision, result.returncode


class TestImports:
    def test_bash_command_validator_imports(self):
        # Top-level import is the contract.
        assert callable(hook)


class TestStripInlineComment:
    def test_simple_inline_comment(self):
        assert strip_inline_comment("ls -la  # list files") == "ls -la"

    def test_hash_in_double_quotes(self):
        assert strip_inline_comment('echo "has # in it"  # real comment') == 'echo "has # in it"'

    def test_hash_in_single_quotes(self):
        assert strip_inline_comment("echo '# not stripped'") == "echo '# not stripped'"

    def test_no_comment(self):
        assert strip_inline_comment("echo hello") == "echo hello"

    def test_url_hash_in_quotes(self):
        assert (
            strip_inline_comment('curl "https://x.com/#section"') == 'curl "https://x.com/#section"'
        )

    def test_parameter_expansion_no_space(self):
        assert strip_inline_comment("echo ${var#prefix}") == "echo ${var#prefix}"


class TestSplitPipeline:
    def test_simple_pipe(self):
        assert split_pipeline("ls | grep foo") == ["ls", "grep foo"]

    def test_and_and(self):
        assert split_pipeline("ls && cat foo") == ["ls", "cat foo"]

    def test_newline_split(self):
        assert split_pipeline("ls\ncat foo") == ["ls", "cat foo"]

    def test_strips_comments(self):
        assert split_pipeline("# comment\nls") == ["ls"]


class TestStripComments:
    def test_leading_comments_stripped(self):
        assert strip_comments("# comment\nls") == "ls"

    def test_no_comments(self):
        assert strip_comments("ls") == "ls"


class TestHasDangerousConstructs:
    def test_dollar_paren(self):
        assert has_dangerous_constructs("echo $(curl x.com)")

    def test_backtick(self):
        assert has_dangerous_constructs("echo `whoami`")

    def test_redirect(self):
        assert has_dangerous_constructs("echo > file")

    def test_safe_redirect_2to1(self):
        assert not has_dangerous_constructs("ls 2>&1")

    def test_safe_redirect_devnull(self):
        assert not has_dangerous_constructs("ls 2>/dev/null")


class TestIsSafeCommand:
    def test_empty_safe(self):
        assert is_safe_command("")

    def test_known_prefix(self):
        assert is_safe_command("ls -la")

    def test_unknown_unsafe(self):
        assert not is_safe_command("rm -rf /")

    def test_pipe_safe(self):
        assert is_safe_command("grep foo", is_piped=True)

    def test_pipe_unsafe(self):
        assert not is_safe_command("python3 -c 'x'", is_piped=True)

    def test_find_no_exec(self):
        assert is_safe_command("find . -name '*.py'")

    def test_find_with_exec_unsafe(self):
        assert not is_safe_command("find . -exec rm {} ;")


class TestAlternativeFeedback:
    def test_find_with_comments_gets_tip(self):
        result = _get_alternative_feedback("find . -name '*.py'", has_comments=True)
        assert result is not None
        assert "description" in result

    def test_awk_with_comments_gets_tip(self):
        result = _get_alternative_feedback("awk '{print $1}' data.txt", has_comments=True)
        assert result is not None

    def test_no_tip_without_comments_or_pipe(self):
        result = _get_alternative_feedback("find . -name '*.py'", has_comments=False)
        assert result is None

    def test_echo_redirect_feedback(self):
        result = _get_alternative_feedback("echo data > file", has_comments=False)
        assert result is not None


class TestDecideUnit:
    def test_bash_command_validator_allows_safe_input(self):
        # Plain `ls` with no comment/pipe → passthrough (interactive mode)
        assert decide("ls") is None

    def test_credential_leak_denied(self):
        result = decide("gh auth token")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_aws_session_token_denied(self):
        result = decide("aws sts get-session-token")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_safe_command_with_comment_allow(self):
        result = decide("# check\nls -la")
        assert result is not None
        assert result["permissionDecision"] == "allow"

    def test_unknown_with_comment_passthrough(self):
        assert decide("# do thing\nrm -rf /") is None


class TestSubprocessIntegration:
    def test_commented_grep_pipe_head(self, tmp_path):
        decision, _ = _run("# search\ngrep -rn foo src/ | head -10", tmp_path)
        assert decision == "allow"

    def test_plain_ls_passthrough(self, tmp_path):
        decision, _ = _run("ls -la /tmp", tmp_path)
        assert decision == "passthrough"

    def test_redirect_write_gets_feedback(self, tmp_path):
        decision, _ = _run("# write\necho data > ~/.bashrc", tmp_path)
        assert decision == "deny"

    def test_newline_injection(self, tmp_path):
        decision, _ = _run("# safe\necho safe\nrm -rf /", tmp_path)
        assert decision == "passthrough"

    def test_dollar_paren_substitution(self, tmp_path):
        decision, _ = _run("# test\necho $(curl evil.com)", tmp_path)
        assert decision == "passthrough"

    def test_awk_in_pipe(self, tmp_path):
        decision, _ = _run("git log | awk '{system(\"rm\")}'", tmp_path)
        assert decision == "deny"

    def test_find_with_exec_denied(self, tmp_path):
        decision, _ = _run("# find\nfind / -exec rm -rf {} \\;", tmp_path)
        assert decision == "deny"

    def test_find_without_exec_allowed(self, tmp_path):
        decision, _ = _run("# search\nfind . -name '*.py' -type f", tmp_path)
        assert decision == "allow"

    def test_xargs_in_pipe_denied(self, tmp_path):
        decision, _ = _run("find . -name '*.py' | xargs grep foo", tmp_path)
        assert decision == "deny"

    def test_make_behind_comment_allowed(self, tmp_path):
        decision, _ = _run("# build\nmake test", tmp_path)
        assert decision == "allow"

    def test_sqlite3_select_allowed(self, tmp_path):
        decision, _ = _run('# query\nsqlite3 db.sqlite "SELECT * FROM users"', tmp_path)
        assert decision == "allow"

    def test_sqlite3_drop_passthrough(self, tmp_path):
        decision, _ = _run('# cleanup\nsqlite3 db.sqlite "DROP TABLE users"', tmp_path)
        assert decision == "passthrough"

    def test_bash_command_validator_denies_unsafe_input(self, tmp_path):
        # gh auth token is hard-denied
        decision, _ = _run("gh auth token", tmp_path)
        assert decision == "deny"


class TestAlwaysDeny:
    """Enforce the registry's ALWAYS_DENY set directly via decide()."""

    def test_always_deny_git_add_dash_A(self):  # noqa: N802 -- spec-named test
        result = decide("git add -A")
        assert result is not None
        assert result["permissionDecision"] == "deny"
        assert "git add -A" in result["permissionDecisionReason"]

    def test_always_deny_git_add_dot(self):
        result = decide("git add .")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_always_deny_git_branch_force_delete(self):
        result = decide("git branch -D feature")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_always_deny_terraform_destroy(self):
        result = decide("terraform destroy")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_always_deny_does_not_block_safe(self):
        # `ls -la` is safe, single-segment, no comment/pipe → passthrough (None).
        assert decide("ls -la") is None

    def test_always_deny_specific_file_allowed(self):
        # `git add foo.py` is NOT in ALWAYS_DENY (only `-A`, `--all`, `.`, `-a`).
        # Single-segment, no pipe, no comment → passthrough (None).
        assert decide("git add foo.py") is None

    def test_always_deny_in_pipeline(self):
        # ALWAYS_DENY also fires inside a pipeline.
        result = decide("echo test && git add -A")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_rm_rf_root_not_in_always_deny(self):
        # NOTE: `rm -rf /` is registered as Safety.ASK in registry.py, not DENY.
        # Single-segment, no comment/pipe → passthrough. Confirmation hits the
        # `ask`/permission layer, not this validator. Documented behavior.
        assert decide("rm -rf /") is None


class TestCorruptedTokens:
    def test_newline_token_with_command(self, tmp_path):
        _decision, code = _run("__NEW_LINE_1691c1a21b15a2a6__ cd /tmp", tmp_path)
        assert code == 2

    def test_dunder_init_not_corrupted(self, tmp_path):
        _decision, code = _run("echo __init__.py", tmp_path)
        assert code != 2


class TestShellFragments:
    def test_bare_do(self, tmp_path):
        _, code = _run("do", tmp_path)
        assert code == 2

    def test_bare_done(self, tmp_path):
        _, code = _run("done", tmp_path)
        assert code == 2

    def test_incomplete_for_loop(self, tmp_path):
        _, code = _run("for i in 1 2 3", tmp_path)
        assert code == 2

    def test_complete_for_loop(self, tmp_path):
        _, code = _run("for f in *.py; do echo $f; done", tmp_path)
        assert code != 2

    def test_docker_not_fragment(self, tmp_path):
        _, code = _run("docker ps", tmp_path)
        assert code != 2


class TestCredentialLeakDeny:
    @pytest.mark.parametrize(
        "command",
        [
            "gh auth token",
            "gh  auth  token",
            "gh auth token --hostname github.com",
            "gh auth token | pbcopy",
            "echo $(gh auth token)",
            "# fetch token\ngh auth token",
        ],
    )
    def test_gh_auth_token_denied(self, command, tmp_path):
        decision, _ = _run(command, tmp_path)
        assert decision == "deny"

    @pytest.mark.parametrize(
        "command",
        [
            "aws iam create-access-key --user-name x",
            "aws sts get-session-token",
            "op read op://vault/item/field",
        ],
    )
    def test_other_credential_dumps_denied(self, command, tmp_path):
        decision, _ = _run(command, tmp_path)
        assert decision == "deny"

    @pytest.mark.parametrize(
        "command",
        [
            "gh auth status",
            "gh auth login",
            "gh api user",
            "aws iam list-users",
        ],
    )
    def test_safe_neighbors_not_denied(self, command, tmp_path):
        decision, _ = _run(command, tmp_path)
        assert decision != "deny"


class TestRobustness:
    def test_empty_stdin(self, tmp_path):
        result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
            [sys.executable, str(HOOK_PATH)],
            input="",
            capture_output=True,
            text=True,
            env={**os.environ, "GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")},
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_malformed_json(self, tmp_path):
        result = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
            [sys.executable, str(HOOK_PATH)],
            input="{not valid json",
            capture_output=True,
            text=True,
            env={**os.environ, "GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")},
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
