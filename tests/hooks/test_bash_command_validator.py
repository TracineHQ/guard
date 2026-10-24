# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for bash_command_validator hook."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.hooks.bash_command_validator import (
    _QUOTED_NEWLINE,
    _arithmetic_end,
    _canonicalize,
    _get_alternative_feedback,
    _joined_readings,
    _mark_quoted_newlines,
    _strip_exec_wrapper,
    _strip_runner_prefix,
    decide,
    get_credential_leak_deny,
    has_dangerous_constructs,
    hook,
    is_safe_command,
    split_pipeline,
    strip_comments,
    strip_inline_comment,
)
from guard.registry import (
    ALWAYS_DENY,
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


class TestMarkQuotedNewlines:
    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            pytest.param("awk '\n{ print $4 }' f", "awk '\ue000{ print $4 }' f", id="single"),
            pytest.param('git commit -m "a\n\nb"', 'git commit -m "a\ue000\ue000b"', id="double"),
            pytest.param('echo "a \\"b\nc\\" d"', 'echo "a \\"b\ue000c\\" d"', id="escaped-quote"),
            pytest.param('echo "${HOME}\n"', 'echo "${HOME}\ue000"', id="plain-param"),
            pytest.param("x=$(jq '\n.a' f)\nls", "x=$(jq '\ue000.a' f)\nls", id="substitution"),
            pytest.param("echo 'a\r\nb'", "echo 'a\r\ue000b'", id="carriage-return"),
            pytest.param(
                "echo \"a\\\nb\" 'c\nd'", "echo \"ab\" 'c\ue000d'", id="continuation-in-double"
            ),
        ],
    )
    def test_marks_newlines_inside_quotes(self, command, expected):
        assert _mark_quoted_newlines(command) == expected

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("ls\ncat foo", id="none-quoted"),
            pytest.param("echo 'a\\'\nrm -rf /\necho '", id="backslash-in-single-quotes"),
            pytest.param("echo a\\'b\nrm -rf /\necho '", id="escaped-quote-outside"),
            pytest.param("cat <<EOF\nit's\nEOF\nrm -rf /\necho 'x", id="heredoc"),
            pytest.param("echo hi # it's\nrm -rf /\necho '", id="comment"),
            pytest.param("ls (#i)'\n'\nrm -rf /\necho '", id="hash-after-paren"),
            pytest.param("echo $'\\''\nrm -rf /\necho '", id="ansi-c"),
            pytest.param("echo \"$'\" 'a\nb' ; rm -rf /", id="ansi-c-in-double-quotes"),
            pytest.param("echo '\ue000a\nb'", id="sentinel-in-input"),
            pytest.param("echo \"$(echo ')')\n\"", id="substitution-in-double-quotes"),
            pytest.param('echo "`date`\n"', id="backtick"),
            pytest.param("echo \"${x:-'}'}\n\"", id="param-operator"),
            pytest.param("alias q=\"'\"\nq echo '\nrm -rf /\n'", id="alias"),
            pytest.param("echo 'open\n", id="unterminated"),
        ],
    )
    def test_leaves_unmarked_or_unreadable_commands_alone(self, command):
        assert _mark_quoted_newlines(command) is None

    @pytest.mark.parametrize(
        ("command", "comments", "expected"),
        [
            pytest.param(
                "echo 'a\nb' ; rm -rf / # x",
                True,
                f"echo 'a{_QUOTED_NEWLINE}b' ; rm -rf / # x",
                id="trailing-comment",
            ),
            pytest.param(
                "# it's\necho 'a\nb'",
                True,
                f"# it's\necho 'a{_QUOTED_NEWLINE}b'",
                id="comment-skipped",
            ),
            pytest.param(
                "# it's\necho 'a\nb'",
                False,
                f"# it's{_QUOTED_NEWLINE}echo 'a\nb'",
                id="comment-read-as-text",
            ),
            pytest.param(
                "echo 'a\nb alias'", True, f"echo 'a{_QUOTED_NEWLINE}b alias'", id="alias"
            ),
            pytest.param(
                "echo ${x:-y} 'a\nb'", True, f"echo ${{x:-y}} 'a{_QUOTED_NEWLINE}b'", id="param"
            ),
            pytest.param(
                "echo $'a\\'b\nc'", True, f"echo $'a\\'b{_QUOTED_NEWLINE}c'", id="ansi-c-quote"
            ),
            pytest.param(
                "echo `date` 'a\nb'", True, f"echo `date` 'a{_QUOTED_NEWLINE}b'", id="tick"
            ),
            pytest.param(
                "cat <<EOF 'a\nb'", True, f"cat <<EOF 'a{_QUOTED_NEWLINE}b'", id="heredoc-operator"
            ),
            pytest.param(
                "cat <<EOF\nit's\nEOF\necho 'a\nb'",
                True,
                f"cat <<EOF\nit's\nEOF\necho 'a{_QUOTED_NEWLINE}b'",
                id="heredoc-body-skipped",
            ),
            pytest.param(
                "cat <<-EOF\n\tit's\n\tEOF\necho 'a\nb'",
                False,
                f"cat <<-EOF\n\tit's\n\tEOF\necho 'a{_QUOTED_NEWLINE}b'",
                id="heredoc-tab-stripped-delimiter",
            ),
            pytest.param(
                "cat <<A <<'B'\n'\nA\n\"\nB\necho 'a\nb'",
                True,
                f"cat <<A <<'B'\n'\nA\n\"\nB\necho 'a{_QUOTED_NEWLINE}b'",
                id="two-heredocs-on-a-line",
            ),
            pytest.param(
                "cat <<<it\necho 'a\nb'",
                True,
                f"cat <<<it\necho 'a{_QUOTED_NEWLINE}b'",
                id="here-string-is-not-a-heredoc",
            ),
            pytest.param("echo 'open\nline", True, f"echo 'open{_QUOTED_NEWLINE}line", id="open"),
            pytest.param(
                f"echo 'a\nb{_QUOTED_NEWLINE}'", True, f"echo 'a{_QUOTED_NEWLINE}b '", id="sentinel"
            ),
        ],
    )
    def test_best_effort_reading_reads_past_what_the_exact_walk_gives_up_on(
        self, command, comments, expected
    ):
        assert _mark_quoted_newlines(command, comments=comments) == expected

    @pytest.mark.parametrize(
        ("operator", "delimiter"),
        [
            pytest.param("<<EOF", "EOF", id="bare"),
            pytest.param("<<END-X", "END-X", id="bare-hyphen"),
            pytest.param("<<END.X", "END.X", id="bare-dot"),
            pytest.param("<<-END.X", "END.X", id="dash-dot"),
            pytest.param("<<'EOF'", "EOF", id="single"),
            pytest.param('<<"EOF"', "EOF", id="double"),
            pytest.param("<<'END-X'", "END-X", id="single-hyphen"),
            pytest.param('<<"END-X"', "END-X", id="double-hyphen"),
            pytest.param("<<-'END-X'", "END-X", id="dash-single-hyphen"),
            pytest.param("<<'EOF.md'", "EOF.md", id="single-dot"),
            pytest.param("<<'MY EOF'", "MY EOF", id="single-space"),
            pytest.param("<< 'EOF'", "EOF", id="space-before-delimiter"),
            pytest.param("<<\\EOF", "EOF", id="backslash"),
        ],
    )
    @pytest.mark.parametrize("comments", [True, False])
    def test_best_effort_reading_skips_a_heredoc_body_whatever_its_delimiter(
        self, operator, delimiter, comments
    ):
        indent = "\t" if operator.startswith("<<-") else ""
        head = f"cat {operator}\n{indent}it's\n{indent}{delimiter}\n"
        assert _mark_quoted_newlines(f"{head}echo 'a\nb'", comments=comments) == (
            f"{head}echo 'a{_QUOTED_NEWLINE}b'"
        )

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("echo $((1<<n)) $((x << y))\necho 'a\nb'", id="arithmetic-expansion"),
            pytest.param("((n = 1<<k))\necho 'a\nb'", id="arithmetic-command"),
        ],
    )
    def test_best_effort_reading_does_not_take_a_shift_for_a_heredoc(self, command):
        marked = _mark_quoted_newlines(command, comments=True)
        assert marked == command.replace("'a\nb'", f"'a{_QUOTED_NEWLINE}b'")

    @pytest.mark.parametrize(
        ("text", "end"),
        [
            pytest.param("((n++)) # c", 7, id="command"),
            pytest.param("$((1<<n)) x", 9, id="expansion"),
            pytest.param("(( (a)+(b) )) x", 13, id="inner-parens-balance"),
            pytest.param("x ((n++))", -1, id="not-a-command-start"),
            pytest.param("((echo a) ; ls)", -1, id="subshells"),
            pytest.param("$((echo a) ; ls)", -1, id="expansion-that-is-a-substitution"),
            pytest.param("((echo 'a)) b'))", -1, id="quote"),
            pytest.param("((echo `x`))", -1, id="backtick"),
            pytest.param("((echo a\nb))", -1, id="newline"),
            pytest.param("((n++)", -1, id="unclosed"),
        ],
    )
    def test_arithmetic_end_follows_bash_on_where_the_parens_close(self, text, end):
        assert _arithmetic_end(text, 0) == end

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param(
                "((echo 'a\nb') ; rm -rf /) ; ((n++)) # c", id="subshells-then-arithmetic"
            ),
            pytest.param("((echo 'a\nb') ; rm -rf /) # c", id="subshells"),
            pytest.param("n=$((x<<y)) ; echo 'a\nb' ; rm -rf / # c", id="shift-then-quote"),
            pytest.param(
                "(( n <<= 2 )) ; echo 'a\nb' ; rm -rf / # c", id="shift-command-then-quote"
            ),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_command_after_parens_and_a_quote_is_denied(self, command, mode):
        assert _is_deny(decide(command, permission_mode=mode)), command

    def test_a_substitution_read_as_arithmetic_is_denied_in_default(self):
        # Auto mode leaves a command inside ``$(...)`` to the classifier, as on main.
        command = "x=$((cd /tmp; echo 'a\nb') ; rm -rf / ) ; y=$((1)) # c"
        assert _is_deny(decide(command))

    def test_best_effort_reading_marks_a_newline_inside_nested_subshells(self):
        command = "((echo 'a\nb') ; ls) ; ((n++)) # c"
        assert _mark_quoted_newlines(command, comments=True) == (
            f"((echo 'a{_QUOTED_NEWLINE}b') ; ls) ; ((n++)) # c"
        )

    @pytest.mark.parametrize("comments", [True, False])
    def test_best_effort_reading_still_needs_a_quoted_newline(self, comments):
        assert _mark_quoted_newlines("echo a\nls 'b' # c", comments=comments) is None
        assert _mark_quoted_newlines("echo 'a b'", comments=comments) is None


class TestQuotedBraces:
    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            pytest.param("grep -E 'a{1,2}' f", "grep -E 'a{1,2}' f", id="single"),
            pytest.param('grep -E "a{1,2}" f', 'grep -E "a{1,2}" f', id="double"),
            pytest.param("echo '{a,b}' {c,d}", "echo '{a,b}' c d", id="quoted-then-bare"),
            pytest.param('echo {c,d} "{a,b}"', 'echo c d "{a,b}"', id="bare-then-quoted"),
            pytest.param("echo {a,'b c'} x", "echo a 'b c' x", id="quoted-alternative"),
            pytest.param("echo 'a  b' {c,d}", "echo 'a  b' c d", id="quoted-spaces-kept"),
            pytest.param("echo 'x{1,2}'{c,d}", "echo 'x{1,2}'c 'x{1,2}'d", id="quote-before-group"),
            pytest.param("echo 'it'\\''s {a,b}'", "echo 'it'\\''s {a,b}'", id="apostrophe-idiom"),
            pytest.param('echo \\{a,b\\} \\"{c,d}', 'echo \\{a,b\\} \\"c \\"d', id="escaped"),
            pytest.param(
                'echo "${name}[0-9]{1,2} x" {c,d}',
                'echo "${name}[0-9]{1,2} x" c d',
                id="plain-parameter-in-double",
            ),
            pytest.param('echo "$HOME/{a,b}"', 'echo "$HOME/{a,b}"', id="expansion-in-double"),
            pytest.param("echo '' {c,d}", "echo '' c d", id="empty-quotes"),
        ],
    )
    def test_quoted_braces_stay_literal(self, command, expected):
        assert _canonicalize(command) == expected

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            pytest.param("echo '{a,b} {c,d}", "echo 'a 'b c d", id="unterminated-single"),
            pytest.param('echo "{a,b} {c,d}', 'echo "a "b c d', id="unterminated-double"),
            pytest.param('echo "$(echo {a,b})" x', 'echo "$(echo a)" b)" x', id="substitution"),
            pytest.param(
                "echo \"${x:-a}\" '{a,b}'", "echo \"${x:-a}\" 'a' 'b'", id="parameter-word"
            ),
            pytest.param("echo `echo '{a,b}'`", "echo `echo 'a'` 'b'`", id="backtick"),
            pytest.param(
                "echo '\ue001' '{a,b}'", "echo '\ue001' 'a' 'b'", id="open-marker-in-input"
            ),
            pytest.param(
                "echo '\ue002' '{a,b}'", "echo '\ue002' 'a' 'b'", id="close-marker-in-input"
            ),
        ],
    )
    def test_unreadable_quoting_is_expanded_as_before(self, command, expected):
        assert _canonicalize(command) == expected

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param(
                "grep -c -E -e '^\\[ft\\] f(3[4-9][0-9][0-9]|[4-9][0-9]{3}) guest' build/out.txt",
                id="repeat-count",
            ),
            pytest.param(
                "grep -c -E -e '^\\[ft\\] f(3[4-9][0-9][0-9]|[4-9][0-9]{3}) guest +([2-9][0-9]"
                "|[0-9]{3,})\\.' build/out.txt",
                id="open-ended-count",
            ),
            pytest.param(
                "git -C /tmp/repo log --format='%s' -n 300 "
                '| grep -nE "\\b[A-Z][0-9]{1,2}[a-z]?\\b|[Tt]ask [0-9]"',
                id="range-then-alternation",
            ),
            pytest.param("grep -E 'x{1,2}|[Tt]ask' f", id="single-quotes"),
            pytest.param("grep -E 'x{1,2}|[Tt]ask' f | wc -l", id="piped"),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_braces_in_quoted_regex_do_not_split_the_command(self, command, mode):
        result = decide(command, permission_mode=mode)
        assert not _is_deny(result), f"quoted braces split the command: {command!r}"

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param(
                "git -C /tmp/repo log --format=%s -n 300 "
                "| grep -nE \\b[A-Z][0-9]{1,2}[a-z]?\\b|[Tt]ask [0-9]",
                id="unquoted-alternation",
            ),
            pytest.param("grep -E x{1,2}|[Tt]ask f", id="unquoted-range"),
            pytest.param("grep -E x{3,}|[Tt]ask f", id="unquoted-open-ended"),
            pytest.param("grep -E 'x{1,2}' f; [Tt]ask {1,2}", id="glob-head-after-quoted-group"),
            pytest.param("echo ok | {r,r}m -rf /", id="brace-head"),
            pytest.param("echo '{a,b}' ; {r,r}m -rf /", id="brace-head-after-quoted-group"),
            pytest.param('echo "{a,b}" && {r,r}m -rf /', id="brace-head-after-double"),
            pytest.param("rm -rf /{etc,usr}", id="brace-operand"),
            pytest.param("rm -rf '/tmp/x{1,2}' /{etc,usr}", id="brace-operand-after-quoted-group"),
        ],
    )
    def test_unquoted_braces_still_expand_and_deny(self, command):
        assert _is_deny(decide(command)), f"unquoted brace shape not denied: {command!r}"

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("true $'\\x27';{r,r}m -rf /;true $'\\x27'", id="hex-single-quote"),
            pytest.param("true $'\\'';{r,r}m -rf /;true $'\\''", id="escaped-single-quote"),
            pytest.param("true $'\\x22';{r,r}m -rf /;true $'\\x22'", id="hex-double-quote"),
            pytest.param("bash -c \"true $'\\x27';{r,r}m -rf /;true $'\\x27'\"", id="in-bash-c"),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_ansi_c_quote_does_not_hide_a_brace_built_head(self, command, mode):
        # Decoding ``$'\x27'`` leaves a bare quote bash never saw; reading it as
        # a real quote would set the real ``{r,r}m`` aside as quoted text.
        assert _is_deny(decide(command, permission_mode=mode)), command

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            pytest.param("echo '{a,b}' $'\\x27'", "echo 'a' 'b' '", id="decodes-to-single-quote"),
            pytest.param("echo '{a,b}' $'\\x22'", "echo 'a' 'b' \"", id="decodes-to-double-quote"),
            pytest.param("echo '{a,b}' $'\\\\'", "echo 'a' 'b' \\", id="decodes-to-backslash"),
            pytest.param("echo '{a,b}' $'x", "echo 'a' 'b' $'x", id="unterminated"),
            pytest.param("echo \"$'\\x27'\" '{a,b}'", "echo \"'\" 'a' 'b'", id="inside-double"),
        ],
    )
    def test_an_ansi_c_quote_that_decodes_to_a_quote_expands_every_group(self, command, expected):
        assert _canonicalize(command) == expected

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            pytest.param("echo '{a,b}' $'x'", "echo '{a,b}' x", id="plain"),
            pytest.param("echo '{a,b}' $'a\\nb'", "echo '{a,b}' a\nb", id="newline-escape"),
            pytest.param("echo '{a,b}$' x", "echo '{a,b}$' x", id="ending-a-single-quoted-word"),
        ],
    )
    def test_other_ansi_c_quotes_leave_quoted_braces_alone(self, command, expected):
        assert _canonicalize(command) == expected

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("grep -nE '^[0-9]{1,2} x|[Tt]ask$' notes.md", id="grep-anchor"),
            pytest.param("rg -n '^v[0-9]{1,3}\\.[0-9]+ |[Rr]eadme$' CHANGELOG.md", id="rg-anchor"),
            pytest.param("sed -nE '/^[0-9]{3,} |[Tt]odo$/p' notes.md", id="sed-anchor"),
            pytest.param(
                "grep -nE \"[0-9]{1,2} x|[Tt]ask\" notes.md && printf $'done\\n'", id="ansi"
            ),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_a_dollar_anchor_does_not_bring_the_brace_false_positive_back(self, command, mode):
        assert not _is_deny(decide(command, permission_mode=mode)), command


class TestQuotedNewlinesTheExactWalkCannotRead:
    """The line split reads the line after a multi-line quote as inside it.

    Where ``_mark_quoted_newlines`` gives up, guard also reads the command with
    its quoted newlines joined and denies if either reading denies.
    """

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("echo 'a\nb' ; rm -rf / # x", id="trailing-comment"),
            pytest.param("# note\necho 'a\nb' ; rm -rf /", id="leading-comment"),
            pytest.param("# it's\necho 'a\nb' ; rm -rf /", id="apostrophe-in-comment"),
            pytest.param("echo 'a\nb alias' ; rm -rf /", id="alias-in-quotes"),
            pytest.param("echo 'a\nb' ; rm -rf / ; echo ${x:-y}", id="parameter-operator"),
            pytest.param("echo 'a\nb' ; rm -rf / ; echo $'x'", id="ansi-c"),
            pytest.param("echo 'a\nb' ; rm -rf / ; cat <<EOF\nx\nEOF", id="heredoc"),
            pytest.param(
                "cat <<EOF\nit's\nEOF\necho 'a\nb' ; rm -rf /", id="apostrophe-in-heredoc"
            ),
            pytest.param("echo `date` 'a\nb' ; rm -rf /", id="backtick"),
            pytest.param(
                "echo 'a\nb' ; cat <<'EOF'\n\"x\nEOF\nrm -rf /", id="heredoc-operator-after-quote"
            ),
            pytest.param(
                "echo `date` 'a\nb' # it's\necho 'alias\nz' && cat <<'EOF'\n\"x\nEOF\n"
                "echo 'it\ns' ; rm -rf / # x",
                id="heredoc-after-comment-and-quotes",
            ),
            pytest.param('echo "a\nb" ; rm -rf / # x', id="double-quoted"),
            pytest.param(f"echo 'a\nb{_QUOTED_NEWLINE}' ; rm -rf / # x", id="sentinel-in-input"),
            pytest.param("bash -c \"echo 'a\nb' ; rm -rf / # x\"", id="in-bash-c"),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_command_after_the_quote_is_denied(self, command, mode):
        assert _is_deny(decide(command, permission_mode=mode)), command

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("cat <<'EOF'\nit's\nEOF\necho 'a\nb' ; rm -rf /", id="single-quoted"),
            pytest.param("cat <<\"EOF\"\nit's\nEOF\necho 'a\nb' ; rm -rf /", id="double-quoted"),
            pytest.param("cat <<-EOF\n\tit's\n\tEOF\necho 'a\nb' ; rm -rf /", id="dash"),
            pytest.param("cat <<-'EOF'\n\tit's\n\tEOF\necho 'a\nb' ; rm -rf /", id="dash-quoted"),
            pytest.param("cat <<'END-X'\nbody\nEND-X\necho 'a\nb' ; rm -rf /", id="hyphen"),
            pytest.param(
                "cat <<'END-X'\nit's\nEND-X\necho 'a\nb' ; rm -rf /", id="hyphen-apostrophe"
            ),
            pytest.param(
                "cat <<\"END-X\"\nit's\nEND-X\necho 'a\nb' ; rm -rf /", id="hyphen-double"
            ),
            pytest.param("cat <<END-X\nbody\nEND-X\necho 'a\nb' ; rm -rf /", id="hyphen-bare"),
            pytest.param("cat <<END-X\nbody\nEND-X\necho 'a\nb' ; rm -rf ~", id="hyphen-bare-home"),
            pytest.param("cat <<END.X\nbody\nEND.X\necho 'a\nb' ; rm -rf /", id="dot-bare"),
            pytest.param("cat <<'EOF.md'\nit's\nEOF.md\necho 'a\nb' ; rm -rf /", id="dot-quoted"),
            pytest.param("cat <<\\EOF\nit's\nEOF\necho 'a\nb' ; rm -rf /", id="backslash"),
            pytest.param("cat <<'MY EOF'\nit's\nMY EOF\necho 'a\nb' ; rm -rf /", id="space"),
            pytest.param(
                "cat <<-'END-X'\n\tit's\n\tEND-X\necho 'a\nb' ; rm -rf /", id="dash-hyphen"
            ),
            pytest.param(
                "cat <<'END-X'\nit's\nEND-X\necho 'a\nb' ; {r,r}m -rf /", id="hyphen-brace"
            ),
            pytest.param(
                "cat <<'END-X'\nit's\nEND-X\necho 'a\nb' ; rm -rf / # x", id="hyphen-comment"
            ),
            pytest.param("cat <<A <<'B-1'\nit's\nA\nx\nB-1\necho 'a\nb' ; rm -rf /", id="two"),
            pytest.param("echo $((1<<n))\necho 'a\nb' ; rm -rf / # x", id="shift"),
            pytest.param(
                "bash -c \"cat <<'END-X'\nit's\nEND-X\necho 'a\nb' ; rm -rf /\"", id="in-bash-c"
            ),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_command_after_a_heredoc_and_a_quote_is_denied(self, command, mode):
        assert _is_deny(decide(command, permission_mode=mode)), command

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param(
                "cat > notes.md <<'END-NOTES'\nrm -rf / is denied; don't retry it\nEND-NOTES",
                id="hyphen",
            ),
            pytest.param(
                "cat > notes.md <<\\EOF\nrm -rf / is denied; don't retry it\nEOF", id="backslash"
            ),
            pytest.param(
                'cat > notes.md <<"END-NOTES"\nNote: rm -rf / is blocked; it\'s a floor rule\n'
                "END-NOTES",
                id="double-quoted",
            ),
            pytest.param(
                "cat > notes.md <<'EOF'\nrm -rf / is denied; don't retry it\nEOF", id="plain"
            ),
            pytest.param(
                "cat > notes.md <<END.MD\nIt's a note; rm -rf / is denied\nEND.MD", id="dot"
            ),
            pytest.param(
                "cat > notes.md <<-'END-NOTES'\n\trm -rf / is denied; don't retry it\n\tEND-NOTES",
                id="dash",
            ),
            pytest.param(
                "cat > notes.md <<'END-NOTES'\nrm -rf / is denied; don't retry it\nEND-NOTES\n"
                "echo 'a\nb' # x",
                id="then-a-quoted-newline",
            ),
        ],
    )
    def test_a_written_heredoc_body_that_names_a_dangerous_command_is_not_denied_in_auto(
        self, command
    ):
        # Default mode denies the ``>`` redirect itself (bash.dangerous_construct).
        assert not _is_deny(decide(command, permission_mode="auto")), command

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param(
                "cat <<'END-NOTES'\nrm -rf / is denied; don't retry it\nEND-NOTES", id="a"
            ),
            pytest.param("cat <<\\EOF\nrm -rf / is denied; don't retry it\nEOF", id="backslash"),
            pytest.param('cat <<"END-NOTES"\nrm -rf / is denied\nEND-NOTES', id="double-quoted"),
            pytest.param("cat <<END.MD\nIt's a note; rm -rf / is denied\nEND.MD", id="dot"),
            pytest.param(
                "cat <<'END-NOTES'\nrm -rf / is denied; don't retry it\nEND-NOTES\necho 'a\nb' # x",
                id="then-a-quoted-newline",
            ),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_a_heredoc_body_that_names_a_dangerous_command_is_not_denied(self, command, mode):
        assert not _is_deny(decide(command, permission_mode=mode)), command

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("echo 'a\nb' # x", id="trailing-comment"),
            pytest.param("# note\necho 'a\nb'", id="leading-comment"),
            pytest.param("# it's\nls\necho 'a\nb'", id="apostrophe-in-comment"),
            pytest.param('git commit -m "fix\n\nbody" # note', id="commit-message"),
            pytest.param("cat <<'EOF'\nit's here\nrm -rf /\nEOF", id="heredoc-body-is-data"),
            pytest.param("echo ${x:-y} 'a\nb'", id="parameter-operator"),
            pytest.param(
                "cat <<'EOF'\nit's here\nrm -rf /\nEOF\necho 'a\nb' # x", id="heredoc-then-quote"
            ),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_harmless_commands_are_not_denied(self, command, mode):
        assert not _is_deny(decide(command, permission_mode=mode)), command

    def test_joined_readings(self):
        def texts(command):
            return [marked for marked, _delimiters in _joined_readings(command)]

        assert texts("# it's\necho 'a\nb'") == [
            f"# it's\necho 'a{_QUOTED_NEWLINE}b'",
            f"# it's{_QUOTED_NEWLINE}echo 'a\nb'",
        ]
        assert texts("echo a\nls") == []
        assert texts("echo 'a\nb' # x") == [f"echo 'a{_QUOTED_NEWLINE}b' # x"]


class TestShellRunWrappers:
    """``watch``, ``script -c`` and ``parallel`` run their command through a shell."""

    @pytest.mark.parametrize(
        ("tokens", "inner"),
        [
            pytest.param(["watch", "-n", "1", "rm -rf /"], "rm -rf /", id="n-separate"),
            pytest.param(["watch", "-n1", "ls"], "ls", id="n-attached"),
            pytest.param(["watch", "-n", "1", "-d", "ls"], "ls", id="n-then-d"),
            pytest.param(["watch", "--interval", "2", "ls"], "ls", id="interval-separate"),
            pytest.param(["watch", "--interval=2", "ls"], "ls", id="interval-attached"),
            pytest.param(["watch", "-q", "3", "ls"], "ls", id="q-separate"),
            pytest.param(["watch", "--equexit", "3", "ls"], "ls", id="equexit-separate"),
            pytest.param(["watch", "-tn", "1", "ls"], "ls", id="cluster-ending-in-n"),
            pytest.param(["watch", "-tn1", "ls"], "ls", id="cluster-with-attached-value"),
            pytest.param(["watch", "-d", "ls"], "ls", id="d-takes-no-separate-value"),
            pytest.param(["watch", "-d=cumulative", "ls"], "ls", id="d-attached-value"),
            pytest.param(["watch", "--differences", "ls"], "ls", id="differences-takes-none"),
            pytest.param(["watch", "-n", "1", "--", "ls"], "ls", id="terminator"),
        ],
    )
    def test_watch_flag_values_are_skipped(self, tokens, inner):
        assert _strip_exec_wrapper(tokens) == inner

    @pytest.mark.parametrize(
        ("command", "inner"),
        [
            pytest.param("script -c 'rm -rf /' /dev/null", "rm -rf /", id="c-first"),
            pytest.param("script -qc 'echo a; rm -rf /' /dev/null", "echo a; rm -rf /", id="qc"),
            pytest.param("script -q -c 'rm -rf /' /dev/null", "rm -rf /", id="q-then-c"),
            pytest.param("script /dev/null -c 'rm -rf /'", "rm -rf /", id="file-first"),
            pytest.param("script -c 'rm -rf /'", "rm -rf /", id="no-file"),
            pytest.param("script --command 'rm -rf /' /dev/null", "rm -rf /", id="long"),
            pytest.param(
                "script -q --command='echo a; rm -rf /' /dev/null",
                "echo a; rm -rf /",
                id="long-equals",
            ),
            pytest.param("script --command='rm -rf /'", "rm -rf /", id="long-equals-last"),
            pytest.param("script --comm 'rm -rf /' /dev/null", "rm -rf /", id="long-abbreviated"),
            pytest.param("script --c='rm -rf /'", "rm -rf /", id="long-shortest"),
            pytest.param("script -q /dev/null rm -rf /", "rm -rf /", id="bsd"),
            pytest.param("script /dev/null rm -rf /", "rm -rf /", id="bsd-no-options"),
            pytest.param("script -F /dev/null rm -rf /", "rm -rf /", id="bsd-flush"),
            pytest.param("script -qF /dev/null rm -rf /", "rm -rf /", id="bsd-cluster-ending-in-F"),
            pytest.param(
                "script -Fq /dev/null rm -rf /", "rm -rf /", id="bsd-cluster-with-F-first"
            ),
            pytest.param("script -aF out.log rm -rf ~", "rm -rf ~", id="bsd-append-flush"),
            pytest.param("script -t 0 /dev/null rm -rf ~", "rm -rf ~", id="bsd-time"),
            pytest.param(
                "script -qt 0 /dev/null rm -rf ~", "rm -rf ~", id="bsd-cluster-ending-in-t"
            ),
            pytest.param("script -t0 /dev/null ls", "ls", id="bsd-time-attached"),
            pytest.param("script -q -- /dev/null rm -rf /", "rm -rf /", id="bsd-end-of-options"),
            pytest.param("script /dev/null echo 'a b'", "echo 'a b'", id="bsd-quoted-word"),
            pytest.param("script /dev/null echo *", "echo *", id="bsd-glob-stays-bare"),
            pytest.param("script -q /dev/null make test", "make test", id="bsd-harmless"),
            pytest.param("parallel -j 2 'rm -rf {}' ::: /", "rm -rf /", id="jobs-separate"),
            pytest.param("parallel -j2 'rm -rf {}' ::: /", "rm -rf /", id="jobs-attached"),
            pytest.param("parallel --jobs 2 -k 'rm -rf {}' ::: /", "rm -rf /", id="long-and-bare"),
            pytest.param("parallel rm -rf {} ::: /", "rm -rf /", id="placeholder-word"),
            pytest.param("parallel rm -rf ::: /", "rm -rf /", id="args-appended"),
            pytest.param("parallel 'rm -rf {1}' ::: /", "rm -rf /", id="numbered-placeholder"),
            pytest.param(
                "parallel 'mv {} {//}/{/.}.bak' ::: a/b.txt",
                "mv a/b.txt a/b.bak",
                id="every-placeholder-kind",
            ),
            pytest.param("parallel 'rm -rf {//}' ::: ./build", "rm -rf .", id="dirname-dot"),
            pytest.param("parallel 'rm -rf {//}' ::: /etc", "rm -rf /", id="dirname-root"),
            pytest.param("parallel 'rm -rf {1//}' ::: ./build", "rm -rf .", id="dirname-numbered"),
            pytest.param("parallel 'mkdir {//}' ::: file", "mkdir .", id="dirname-no-slash"),
            pytest.param("parallel 'echo {//}' ::: a/b/", "echo a", id="dirname-trailing-slash"),
            pytest.param(
                "parallel 'cp {} out/{/}' ::: src/a.txt", "cp src/a.txt out/a.txt", id="basename"
            ),
            pytest.param(
                "parallel 'convert {} {.}.png' ::: a.jpg", "convert a.jpg a.png", id="no-extension"
            ),
            pytest.param("parallel 'rm -rf {.}' ::: /", "rm -rf /", id="no-extension-root"),
            pytest.param(
                "parallel 'echo {2/.}' ::: d/a.b.c", "echo a.b", id="numbered-basename-no-ext"
            ),
            pytest.param(
                "parallel 'echo {#}' ::: a", "echo {#} a", id="job-number-is-not-an-argument"
            ),
            pytest.param(
                "parallel -j 2 'echo a ; rm -rf {} # x' ::: /",
                "echo a ; rm -rf / # x",
                id="placeholder-before-comment",
            ),
            pytest.param(
                "parallel \"bash -c 'rm -rf {}'\" ::: /", "bash -c 'rm -rf /'", id="nested-quotes"
            ),
            pytest.param("parallel 'rm -rf {}' ::: a /", "rm -rf a ; rm -rf /", id="every-arg"),
            pytest.param("parallel --tmpdir /tmp 'rm -rf {}' ::: /", "rm -rf /", id="tmpdir"),
            pytest.param("parallel --nice 10 'rm -rf {}' ::: /", "rm -rf /", id="nice"),
            pytest.param("parallel --env FOO 'rm -rf {}' ::: /", "rm -rf /", id="env"),
            pytest.param("parallel --tagstring x 'rm -rf {}' ::: /", "rm -rf /", id="tagstring"),
            pytest.param("parallel -J prof 'rm -rf {}' ::: /", "rm -rf /", id="profile"),
            pytest.param("parallel --memfree 1G 'rm -rf {}' ::: /", "rm -rf /", id="memfree"),
            pytest.param("parallel --bar --dry-run -kq echo {} ::: a", "echo a", id="bare-flags"),
            pytest.param("parallel -kj 2 echo {} ::: a", "echo a", id="cluster-ending-in-j"),
            pytest.param(
                "parallel --newflag 'rm -rf {}' ::: /",
                "rm -rf / ; /",
                id="unknown-flag-without-value-or-with-one",
            ),
            pytest.param(
                "parallel --newflag x 'rm -rf {}' ::: /",
                "x rm -rf / ; rm -rf /",
                id="unknown-flag-with-a-value",
            ),
            pytest.param("parallel ::: 'rm -rf /'", "rm -rf /", id="args-are-commands"),
            pytest.param("parallel ::: 'echo a' 'rm -rf /'", "echo a ; rm -rf /", id="two-args"),
            pytest.param("parallel -j 2 ::: 'rm -rf /'", "rm -rf /", id="jobs-then-args"),
        ],
    )
    def test_script_and_parallel_commands_are_found(self, command, inner):
        assert _strip_runner_prefix(command) == inner

    @pytest.mark.parametrize(
        "command",
        [
            "parallel :::",
            "parallel -j 2",
            "script -q",
            "script -a session.log",
            "script -q /dev/null",
            "script -F /dev/null",
            "script -t 5 session.log",
            "script session.log -x",
        ],
    )
    def test_nothing_to_run(self, command):
        assert _strip_runner_prefix(command) is None

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("watch -n 1 'rm -rf /'", id="watch-n"),
            pytest.param("watch -n 1 rm -rf /", id="watch-n-unquoted"),
            pytest.param("watch -n 1 'rm -rf /; echo a'", id="watch-n-first-of-two"),
            pytest.param("watch -n1 'echo a; rm -rf /'", id="watch-n-attached-second"),
            pytest.param("watch -q 3 'rm -rf /'", id="watch-q"),
            pytest.param("watch --interval 2 'rm -rf /'", id="watch-interval"),
            pytest.param("watch -tn 1 'rm -rf /'", id="watch-cluster"),
            pytest.param("watch -d 'rm -rf /'", id="watch-d"),
            pytest.param("script -c 'rm -rf /' /dev/null", id="script-c"),
            pytest.param("script -qc 'echo a; rm -rf /' /dev/null", id="script-qc"),
            pytest.param("parallel -j 2 'rm -rf {}' ::: /", id="parallel-j"),
            pytest.param("parallel -j 2 'echo a; rm -rf {}' ::: /", id="parallel-j-second"),
            pytest.param("parallel ::: 'rm -rf /'", id="parallel-args"),
            pytest.param("parallel ::: 'echo a' 'rm -rf /'", id="parallel-second-arg"),
            pytest.param("script --command 'rm -rf /' /dev/null", id="script-command"),
            pytest.param(
                "script -q --command='echo a; rm -rf /' /dev/null", id="script-command-equals"
            ),
            pytest.param("script --comm='rm -rf /'", id="script-command-abbreviated"),
            pytest.param("parallel --tmpdir /tmp 'rm -rf {}' ::: /", id="parallel-tmpdir"),
            pytest.param("parallel --nice 10 'rm -rf {}' ::: /", id="parallel-nice"),
            pytest.param("parallel --env FOO 'rm -rf {}' ::: /", id="parallel-env"),
            pytest.param("parallel --tagstring x 'rm -rf {}' ::: /", id="parallel-tagstring"),
            pytest.param("parallel -J prof 'rm -rf {}' ::: /", id="parallel-profile"),
            pytest.param("parallel --memfree 1G 'rm -rf {}' ::: /", id="parallel-memfree"),
            pytest.param("parallel --newflag 'rm -rf {}' ::: /", id="parallel-unknown-bare"),
            pytest.param("parallel --newflag x 'rm -rf {}' ::: /", id="parallel-unknown-value"),
            pytest.param("parallel -j 2 'echo a ; rm -rf {} # x' ::: /", id="parallel-comment"),
            pytest.param("parallel \"bash -c 'rm -rf {}'\" ::: /", id="parallel-nested-bash-c"),
            pytest.param("parallel 'rm -rf {}' ::: a /", id="parallel-every-arg"),
            pytest.param("parallel 'rm -rf {//}' ::: ./build", id="parallel-dirname-dot"),
            pytest.param("parallel 'rm -rf {//}' ::: /etc", id="parallel-dirname-root"),
            pytest.param("parallel 'rm -rf {1//}' ::: ./build", id="parallel-dirname-numbered"),
            pytest.param("script -q /dev/null rm -rf /", id="script-bsd"),
            pytest.param("script /dev/null rm -rf /", id="script-bsd-no-options"),
            pytest.param("script -F /dev/null rm -rf /", id="script-bsd-flush"),
            pytest.param("script -qF /dev/null rm -rf /", id="script-bsd-quiet-flush"),
            pytest.param("script -aF out.log rm -rf ~", id="script-bsd-append-flush"),
            pytest.param("script -t 0 /dev/null rm -rf ~", id="script-bsd-time"),
            pytest.param("script -q /dev/null sh -c 'echo a; rm -rf /'", id="script-bsd-sh-c"),
            pytest.param("script -q /dev/null bash -c 'rm -rf /'", id="script-bsd-bash-c"),
            pytest.param("parallel 'echo \"a\nb\" ; rm -rf {} # x' ::: /", id="parallel-newline"),
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_dangerous_command_is_denied(self, command, mode):
        assert _is_deny(decide(command, permission_mode=mode)), command

    @pytest.mark.parametrize(
        "command",
        [
            "watch -n 1 'ls -la'",
            "watch -d ls",
            "watch --interval=2 ls",
            "script -qc 'ls' /dev/null",
            "script --command 'ls' /dev/null",
            "script -q --command=ls /dev/null",
            "parallel -j 2 'echo {}' ::: a b",
            "parallel --tmpdir /tmp 'echo {}' ::: a b",
            "parallel --bar gzip {} ::: *.log",
            "parallel --newflag gzip {} ::: a b",
            "parallel -kj 2 echo {} ::: a b",
            "parallel 'echo a ; echo {} # x' ::: b",
            "parallel 'rm -rf {}/node_modules' ::: packages/a packages/b",
            "parallel -j8 'rm -rf {}' ::: build dist .cache",
            "parallel 'convert {} {.}.png' ::: a.jpg b.jpg",
            "parallel 'cp {} out/{/}' ::: src/a.txt src/b.txt",
            "parallel 'mkdir -p out/{//}' ::: a/b/c.txt",
            "script -q /dev/null make test",
            "script -F /dev/null make test",
            "script -t 5 session.log",
            "script -a session.log",
            "script -q session.log",
        ],
    )
    @pytest.mark.parametrize("mode", ["default", "auto"])
    def test_harmless_command_is_not_denied(self, command, mode):
        assert not _is_deny(decide(command, permission_mode=mode)), command


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

    def test_xargs_read_only_pipe_advisory(self, tmp_path):
        # FP-3: `xargs grep` is a read; the tool-preference nudge is advisory,
        # not a hard deny (a destructive `xargs rm -rf /` still denies via the
        # always-deny matcher — see test_fp3_course_correction.py).
        decision, _ = _run("find . -name '*.py' | xargs grep foo", tmp_path)
        assert decision != "deny"

    def test_make_behind_comment_allowed(self, tmp_path):
        decision, _ = _run("# build\nmake test", tmp_path)
        assert decision == "allow"

    def test_sqlite3_select_allowed(self, tmp_path):
        decision, _ = _run('# query\nsqlite3 db.sqlite "SELECT * FROM users"', tmp_path)
        assert decision == "allow"

    def test_sqlite3_drop_denied(self, tmp_path):
        decision, _ = _run('# cleanup\nsqlite3 db.sqlite "DROP TABLE users"', tmp_path)
        assert decision == "deny"

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


# === Quoted-whitespace bypass ===
# Smuggling internal whitespace inside quoted tokens used to fold into a
# single shlex token (``python3  -c``) that the literal ``python3 -c`` deny
# prefix could not match.


from tests._helpers import is_deny as _is_deny


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
    # Sort so xdist workers collect parametrize cases in a stable order.
    for prefix in sorted(ALWAYS_DENY):
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


# === Interpreter boundary: script / module runs pass, inline code denies ===


@pytest.mark.parametrize(
    "cmd",
    [
        "uv run python tools/dev.py frog-run g1-claims",
        "uv run python tools/dev.py frog-run g1",
        "python3 scripts/x.py --flag",
        "uv run python -m pytest",
        "python -m pip install -e .",
        "python3 x.py -c cfg",
    ],
)
def test_interpreter_script_and_module_runs_not_denied_in_enforce(cmd):
    assert not _is_deny(decide(cmd)), f"script/module run denied: {cmd!r}"


@pytest.mark.parametrize(
    "cmd",
    [
        "cd tools && uv run python dev.py frog-run g1",
        "ls && python3 scripts/x.py --flag",
    ],
)
def test_interpreter_script_run_in_sequence_passes_through(cmd):
    # The `uv run python` safe prefix must not turn a script run into an
    # explicit allow: guard stays out of it and Claude Code decides.
    assert decide(cmd) is None, cmd


@pytest.mark.parametrize(
    "cmd",
    [
        "python3 -c 'print(1)'",
        "uv run python - <<'EOF'\nimport os\nprint(1)\nEOF",
        "node -e 'console.log(1)'",
        "node -p 'process.version'",
        "php -r 'echo 1;'",
        "perl -pe 's/a/b/' f",
        "python3 -Ic 'import os'",
        "python3 <<EOF\nprint(1)\nEOF",
        "python3 0<<EOF\nprint(1)\nEOF",
        "python3 < x.py",
        "python -m timeit 'code'",
    ],
)
def test_interpreter_inline_code_denied_in_enforce(cmd):
    assert _is_deny(decide(cmd)), f"inline code not denied: {cmd!r}"


@pytest.mark.parametrize(
    "cmd",
    [
        "uv run python - <<'EOF'\nimport os\nEOF",
        "node -p 'process.version'",
        "php -r 'echo 1;'",
        "perl -pe 's/a/b/' f",
        "python3 -Ic 'import os'",
        "python3 <<EOF\nprint(1)\nEOF",
        "python -m timeit 'code'",
    ],
)
def test_interpreter_inline_code_deny_names_the_rule(cmd):
    # Shapes with no always-deny literal must land on the interpreter rule,
    # whose reason steers to writing a script file.
    reason = decide(cmd)["permissionDecisionReason"]
    assert "bash.dangerous_interpreter" in reason, reason
    assert "script file" in reason, reason


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
    # Should NOT be a deny envelope: passthrough to Claude Code's own prompt.
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
# Sort so xdist workers collect the parametrize set in a stable order
# (ALWAYS_DENY is a frozenset — unsorted iteration breaks --dist=loadgroup).
def _git_always_deny_literals():
    return sorted(p for p in ALWAYS_DENY if p.startswith("git "))


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


class TestCredentialLeakExecutionPosition:
    """credential-leak must fire only when a credential CLI is in execution
    position, not when its name appears inside a quoted argument / interpreter
    -c body / heredoc body (a string-literal mention, not a live invocation).
    """

    @pytest.mark.parametrize(
        "command",
        [
            'chrome --tab 2 fill "#x" "an agent runs gh auth token to dump creds"',
            'echo "to rotate: op read op://vault/item"',
            "python3 -c 'help = \"run gh auth token then aws sts get-session-token\"'",
        ],
    )
    def test_quoted_mention_not_flagged(self, command):
        assert get_credential_leak_deny(command) is None, command

    @pytest.mark.parametrize(
        "command",
        [
            "gh auth token",
            "aws sts get-session-token",
            "op read op://vault/item/field",
            "export TOKEN=$(gh auth token)",
            # B4: bare unquoted prose, no heredoc -> mask leaves it visible.
            "echo gh auth token",
        ],
    )
    def test_exec_position_still_flagged(self, command):
        assert get_credential_leak_deny(command) is not None, command

    @pytest.mark.parametrize(
        "command",
        [
            "tee docs/runbook.md <<'EOF'\nTo rotate, run gh auth token and paste the value.\nEOF",
            "cat > runbook.md <<EOF\nFor temp creds run aws sts get-session-token here.\nEOF",
            "cat <<EOF > notes.txt\nUse op read op://vault/item to fetch the secret.\nEOF",
            "tee -a docs/SECURITY.md <<'EOF'\nNever paste the output of gh auth token into a PR.\nEOF",
            "tee docs/aws.md <<-'EOF'\n\tDo not run aws iam create-access-key in CI.\n\tEOF",
            "cat > playbook.md <<'EOF'\nStep 1: gh auth token. Step 2: op read op://v/i.\nEOF",
            "tee docs/x.md <<'EOF'\nThe EOFENDING note: run gh auth token only locally.\nEOF",
        ],
    )
    def test_writedoc_heredoc_body_not_flagged(self, command):
        # Write/doc-sink heredoc bodies are blanked by the mask, so a credential
        # CLI named in the prose is not read as a live invocation.
        assert get_credential_leak_deny(command) is None, command

    @pytest.mark.parametrize(
        "command",
        [
            "bash <<EOF\ngh auth token\nEOF",
            "sh <<'EOF'\naws sts get-session-token\nEOF",
            "cat <<EOF | sh\nop read op://vault/item\nEOF",
            'eval "$(cat <<EOF\ngh auth token\nEOF\n)"',
        ],
    )
    def test_evalsink_heredoc_body_still_flagged(self, command):
        # Eval/shell-sink heredoc bodies are NEVER blanked, so the credential CLI
        # stays in execution position and the leak deny still fires.
        assert get_credential_leak_deny(command) is not None, command

    @pytest.mark.parametrize(
        ("command", "expect_flagged"),
        [
            ("tee doc.md <<-'EOF'\n\trun gh auth token\n\tEOF", False),
            ("bash <<-EOF\n\tgh auth token\n\tEOF", True),
            ("tee a.md <<'EOF'\ngh auth token\nEOF", False),
            ("tee a.md <<EOF\ngh auth token\nEOF", False),
            ("tee out.md <<'A' <<'B'\ngh auth token\nA\nop read op://v/i\nB", False),
            ("cat <<EOF > x.md | sh\ngh auth token\nEOF", True),
            ("tee n.md <<'END'\nEND_OF_SECTION mentions gh auth token here\nEND", False),
            ("gh auth token | tee log.md <<'EOF'\nnotes\nEOF", True),
            ("tee f.md <<'EOF'\nnotes\nEOF\n$(gh auth token)", True),
            ("tee f.md <<'EOF'\ngh auth token", True),
            ("mycmd <<'EOF'\ngh auth token\nEOF", True),
        ],
    )
    def test_heredoc_masking_edge_cases(self, command, expect_flagged):
        result = get_credential_leak_deny(command)
        if expect_flagged:
            assert result is not None, command
        else:
            assert result is None, command
