# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: validate Bash commands with comments and pipes.

Handles two cases that glob-based permission patterns cannot:

1. Commands prefixed with ``#`` comment lines (agents add these for clarity).
2. Piped commands where each segment is individually safe.

Logic:

- Strip leading comment lines from the command.
- Split on pipes (``|``), logical operators (``&&``, ``||``), semicolons,
  and newlines.
- Reject any segment with output redirects (``>``, ``>>``), command
  substitution (``$()``, backticks), or dangerous flags
  (``-exec``, ``system()``, ``/e``).
- Check each segment against known-safe command prefixes.
- If all segments are safe → allow. If any segment is unknown → pass through
  (let normal permissions handle it). Returns deny only for known dangerous
  patterns (credential leaks, corrupted tokens, dangerous alternatives).

Exit codes:
- ``0`` — allow (with JSON ``permissionDecision``) or pass through (no output)
- ``2`` — hard deny (corrupted tokens, shell fragments, credential leaks)
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from datetime import UTC, datetime
from typing import Any, Literal

from guard._utils import (
    GUARD_AUTONOMOUS_QUEUE_PATH,
    _log_debug,
    append_jsonl,
    is_autonomous_mode,
    log_decision,
    safe_main,
    sanitize_for_stderr,
)
from guard.registry import (
    ALWAYS_DENY,
    AUTONOMOUS_FEEDBACK,
    COMMANDS,
    DANGEROUS_INTERPRETERS,
    DANGEROUS_RM_OPERANDS,
    DANGEROUS_SHELL_WRAPPERS,
    GIT_CONFIG_EXEC_SINK_GLOBS,
    GIT_CONFIG_EXEC_SINKS,
    INTERPRETER_EVAL_FLAGS,
    INTERPRETER_RUNNER_WRAPPERS,
    PLAIN_RUNNER_PREFIXES,
    SAFE_PIPE_COMMANDS,
    SAFE_PREFIXES,
    Safety,
)

_HOOK_ID = "guard.bash_command_validator"

# Corrupted internal tokens — always a bug, never valid user input
CORRUPTED_TOKEN = re.compile(r"__NEW_LINE_[0-9a-f]+__")

# Commands that print live credentials/tokens to stdout. Always deny — once
# the value lands in the agent transcript it can leak downstream.
CREDENTIAL_LEAK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bgh\s+auth\s+token\b"), "gh auth token"),
    (re.compile(r"\baws\s+iam\s+create-access-key\b"), "aws iam create-access-key"),
    (re.compile(r"\baws\s+sts\s+get-session-token\b"), "aws sts get-session-token"),
    (re.compile(r"\bop\s+read\b"), "op read (1Password)"),
]

# Bare shell keywords that are never valid as standalone commands
SHELL_FRAGMENTS: frozenset[str] = frozenset(
    {"do", "done", "then", "else", "fi", "elif", "esac", "in"}
)

# Commands that, when piped into a shell, form the classic ``curl ... | sh``
# RCE pattern. Denied unconditionally regardless of mode. Anything that
# produces bytes followed by ``| <shell>`` is always a deliberate RCE in an
# agent context — the producer set is intentionally broad (B5).
_PIPE_SHELL_CMDS: frozenset[str] = frozenset(DANGEROUS_SHELL_WRAPPERS)


_SPEC_DECISION_MAP: dict[str, Literal["allow", "deny", "ask", "pass"]] = {
    "allow": "allow",
    "deny": "deny",
    "ask": "ask",
    "passthrough": "pass",
}


def _log_local(command: str, decision: str, reason: str) -> None:
    """Append a decision row to the JSONL log. Best-effort, never raises.

    Thin wrapper that maps the local decision strings (``passthrough`` etc.)
    onto the spec writer in ``guard._utils.log_decision``.
    """
    spec_decision = _SPEC_DECISION_MAP.get(decision, "pass")
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name="Bash",
        decision=spec_decision,
        reason=reason,
        command_excerpt=command,
        session_id=os.environ.get("CLAUDE_SESSION_ID", ""),
    )


# Commands safe only when they don't contain specific dangerous flags.
CONDITIONAL_SAFE: dict[str, set[str]] = {
    "find": {"-exec", "-execdir", "-delete", "-ok", "-okdir"},
    "make": set(),
    "echo": set(),
    "printf": set(),
}


def _is_sqlite3_safe(segment: str) -> bool:
    """Return ``True`` if a sqlite3 command is read-only (SELECT only)."""
    upper = segment.upper()
    write_keywords = {"DROP", "INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "ATTACH"}
    return all(kw not in upper for kw in write_keywords)


# Patterns indicating dangerous shell constructs within a command segment.
DANGEROUS_PATTERNS = re.compile(
    r"(?:"
    r"\$\("  # Command substitution $(...)
    r"|`"  # Backtick substitution `...`
    r"|<\("  # Process substitution <(...)
    r"|>\("  # Process substitution >(...)
    r"|<<<"  # Here-string redirection (B4 — input is attacker-supplied)
    r"|>\s*\S"  # Output redirect > file (but not 2>&1)
    r"|>>"  # Append redirect >> file
    r")"
)

# Commands with safe alternatives — surface actionable feedback.
ALWAYS_FEEDBACK: dict[str, str] = {
    "find": "Use the Glob tool instead of find (avoids -exec injection risk)",
    "xargs": "Use the Glob tool + Read tool instead of piping through xargs",
    "awk": "Use the Grep tool or python3 for text extraction instead of awk",
    "sed": "Use the Edit tool for file modifications instead of sed",
    "tee": "Use the Write tool instead of tee for file creation",
}
REDIRECT_FEEDBACK: dict[str, str] = {
    "echo": "Use the Write tool to create files instead of echo with redirects",
    "printf": "Use the Write tool to create files instead of printf with redirects",
}

# Safe redirect patterns that should NOT trigger the dangerous check
SAFE_REDIRECTS = re.compile(r"(?:2>&1|2>/dev/null|>/dev/null)")


def strip_comments(command: str) -> str:
    """Remove leading comment lines from a command."""
    lines = command.split("\n")
    result: list[str] = []
    found_code = False
    for line in lines:
        stripped = line.strip()
        if not found_code and (stripped.startswith("#") or stripped == ""):
            continue
        found_code = True
        result.append(line)
    return "\n".join(result).strip()


def strip_inline_comment(line: str) -> str:
    """Remove inline ``# comment`` from a bash command line."""
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "\\" and in_double:
            i += 1
        elif (
            c == "#" and not in_single and not in_double and (i == 0 or line[i - 1] in (" ", "\t"))
        ):
            return line[:i].rstrip()
        i += 1
    return line


def _split_on_operators(line: str) -> list[str]:  # noqa: C901 -- single-pass quote-aware lexer; splitting harms readability
    """Split a single (no-newline) line on ``|``/``||``/``&&``/``;`` outside quotes.

    Ignores operator characters that appear inside single- or double-quoted
    strings so an attacker cannot smuggle a deny-list-evading prefix by
    embedding ``;`` inside a quoted argument (F1 family).
    """
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        c = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if c == "'" and not in_double:
            in_single = not in_single
            buf.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            buf.append(c)
            i += 1
            continue
        if c == "\\" and in_double:
            # preserve escape sequence
            buf.append(c)
            if nxt:
                buf.append(nxt)
                i += 2
                continue
            i += 1
            continue
        if not in_single and not in_double:
            if c == "|" and nxt == "|":
                segments.append("".join(buf))
                buf = []
                i += 2
                continue
            if c == "&" and nxt == "&":
                segments.append("".join(buf))
                buf = []
                i += 2
                continue
            if c in {"|", ";"}:
                segments.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    if buf:
        segments.append("".join(buf))
    return segments


_GROUP_OPEN_RE = re.compile(r"^[!(){}\s]+")
_GROUP_CLOSE_RE = re.compile(r"[;){}!\s]+$")


def _strip_group_wrappers(segment: str) -> str:
    """Strip leading ``(`` / ``{`` / ``!`` and trailing ``)`` / ``}`` (B4).

    ``( rm -rf / )`` and ``{ rm -rf /; }`` are subshell / brace groups. After
    pipeline splitting the segments are ``( rm -rf /`` etc.; stripping the
    surrounding tokens lets the head become ``rm`` and the existing matchers
    fire.

    Leading ``!`` is the bash logical-not prefix: ``! rm -rf /`` runs the
    command and inverts its exit code.
    """
    s = segment
    while True:
        prev = s
        s = _GROUP_OPEN_RE.sub("", s)
        s = _GROUP_CLOSE_RE.sub("", s)
        if s == prev:
            return s


def split_pipeline(command: str) -> list[str]:
    """Split a command into segments on pipe/operator/newline boundaries.

    Operator splitting is quote-aware so semicolons / pipes embedded inside
    quoted strings are preserved (closes the F1 family of bypasses where
    ``python3'  '-c '1; __import__(...)'`` was being torn at the ``;``).

    Each split segment also has subshell-paren / brace-group / leading-bang
    wrappers stripped (B4) so ``( rm -rf / )`` and ``{ rm -rf /; }`` and
    ``! rm -rf /`` are evaluated against the deny matchers.
    """
    segments: list[str] = []
    for line in command.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = strip_inline_comment(stripped)
        if not stripped:
            continue
        for part in _split_on_operators(stripped):
            piece = _strip_group_wrappers(part.strip())
            if piece:
                segments.append(piece)
    return segments


def has_dangerous_constructs(segment: str) -> bool:
    """Return ``True`` if a segment contains dangerous shell constructs."""
    masked = SAFE_REDIRECTS.sub("", segment)
    return bool(DANGEROUS_PATTERNS.search(masked))


def _matches_prefix(segment: str, prefixes: frozenset[str]) -> bool:
    """Return ``True`` if ``segment`` is exactly or prefixed by any in ``prefixes``."""
    return any(segment == p or segment.startswith(p + " ") for p in prefixes)


def _is_conditional_safe(segment: str, base_cmd: str) -> bool:
    """Return ``True`` if a CONDITIONAL_SAFE command lacks dangerous flags."""
    dangerous_flags = CONDITIONAL_SAFE[base_cmd]
    if not dangerous_flags:
        return True
    return all(token not in dangerous_flags for token in segment.split())


_INTERPRETER_BASE_CMDS: frozenset[str] = frozenset({"python", "python3", "node"})


def _is_safe_interpreter(segment: str) -> bool:
    """Return ``True`` for known-safe interpreter invocations.

    Bare ``python`` / ``python3`` / ``node`` would, on a flat prefix match,
    permit ``python -c '...'`` / ``node -e '...'`` and similar RCE primitives.
    This classifier mirrors ``_is_safe_env``: only forms with no flags or a
    single read-only ``--version`` / ``-V`` / ``-v`` flag are accepted.

    Safe forms:

    - bare interpreter (``python``, ``node``)
    - version probes: ``python --version``, ``python -V``, ``python3 -V``,
      ``node --version``, ``node -v``

    Rejected forms (return ``False``):

    - ``python -c ...`` / ``-m ...`` / ``-`` (stdin) / ``--eval`` / ``-e``
    - any flag form not on the version-probe allowlist — including ``-m``,
      because module execution allows arbitrary code paths
    """
    tokens = segment.split()
    if not tokens or tokens[0] not in _INTERPRETER_BASE_CMDS:
        return False
    if len(tokens) == 1:
        return True
    base = tokens[0]
    rest = tokens[1:]
    # Tighter rule: any flag => deny unless it's a known version probe.
    version_flags_python: frozenset[str] = frozenset({"--version", "-V"})
    version_flags_node: frozenset[str] = frozenset({"--version", "-v"})
    if base in {"python", "python3"}:
        return len(rest) == 1 and rest[0] in version_flags_python
    # node
    return len(rest) == 1 and rest[0] in version_flags_node


def _is_safe_base_cmd(segment: str) -> bool:
    """Check if ``segment``'s base command is conditionally or specially safe."""
    tokens = segment.split()
    base_cmd = tokens[0] if tokens else ""
    if base_cmd in CONDITIONAL_SAFE:
        return _is_conditional_safe(segment, base_cmd)
    if base_cmd == "sqlite3":
        return _is_sqlite3_safe(segment)
    if base_cmd == "env":
        return _is_safe_env(segment)
    if base_cmd in _INTERPRETER_BASE_CMDS:
        return _is_safe_interpreter(segment)
    return False


# Regex matching a shell variable assignment of the form ``KEY=VALUE``. Used
# by ``_is_safe_env`` to skip past env-var assignments to find the wrapped
# command. Keys must be valid identifiers; values are unrestricted (we delegate
# command safety to the recursive safe-prefix check).
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _is_safe_env(segment: str) -> bool:
    """Return ``True`` for known-safe ``env`` invocations.

    Forms accepted:

    - bare ``env`` (just print the environment) → safe
    - ``env K=V K=V ...`` (no wrapped command) → safe
    - ``env K=V K=V ... safe_command [args...]`` → safe iff the wrapped
      command's prefix is on ``SAFE_PREFIXES`` and is *not* itself ``env``
      (recursion cap = 1; ``env env ...`` is rejected to bound cost).

    Forms rejected (return ``False``):

    - any flag starting with ``-`` (``env -i``, ``env -u FOO``, ``env -S ...``)
      because these change shell semantics and ``env -i`` is the canonical
      way to wrap an RCE.
    """
    tokens = segment.split()
    if not tokens or tokens[0] != "env":
        return False
    if len(tokens) == 1:
        return True
    rest = tokens[1:]
    # Reject any flag form unconditionally — env -i / -u / -S are the bypass.
    if rest[0].startswith("-"):
        return False
    # Skip over K=V assignments to reach the wrapped command.
    i = 0
    while i < len(rest) and _ENV_ASSIGN_RE.match(rest[i]):
        i += 1
    if i == len(rest):
        # `env K=V` with no wrapped command — safe (just sets env then exits)
        return True
    return _is_safe_env_inner(rest[i:])


def _is_safe_env_inner(inner_tokens: list[str]) -> bool:
    """Return ``True`` if the wrapped command under ``env K=V ...`` is safe."""
    inner_base = inner_tokens[0]
    # No nested env — keep this single-level to bound recursion cost.
    if inner_base == "env":
        return False
    inner = " ".join(inner_tokens)
    if has_dangerous_constructs(inner):
        return False
    if _matches_prefix(inner, SAFE_PREFIXES):
        return True
    # Allow CONDITIONAL_SAFE / sqlite3 wrapped under env too.
    if inner_base in CONDITIONAL_SAFE:
        return _is_conditional_safe(inner, inner_base)
    if inner_base == "sqlite3":
        return _is_sqlite3_safe(inner)
    return False


def is_safe_command(segment: str, *, is_piped: bool = False, autonomous: bool = False) -> bool:  # noqa: PLR0911 -- public entry point with intentional early-return safety checks
    """Return ``True`` if a segment matches a known-safe prefix.

    Public entry point — safe to call from outside ``decide()``. Applies the
    full canonicalization + synthetic-deny pipeline so external callers do
    not need to know about ``_canonicalize`` / ``_match_always_deny`` /
    ``_match_synthetic_deny`` themselves.

    In autonomous mode, git segments are NOT deferred to git_c_validator —
    we must evaluate them here so the strict default-deny path can fire.
    """
    if not segment:
        return True
    # Apply the same canonicalization the top-level dispatcher uses, so any
    # caller is protected from line-continuation / unicode whitespace bypasses.
    segment = _canonicalize(segment).strip()
    if not segment:
        return True
    if has_dangerous_constructs(segment):
        return False
    # ALWAYS_DENY and synthetic-deny matchers must veto regardless of pipe
    # context: a piped ``rm -rf /`` is not made safe by being on the right
    # side of a pipe.
    if _match_always_deny(segment) is not None:
        return False
    if _match_synthetic_deny(segment) is not None:
        return False
    if is_piped:
        return _matches_prefix(segment, SAFE_PIPE_COMMANDS)
    # In interactive mode, defer git segments to git_c_validator. In autonomous
    # mode, fall through so SAFE_PREFIXES (e.g. `git status`, `git log`) is
    # consulted directly — anything not on the read-only allowlist is denied.
    if not autonomous and (segment.startswith("git ") or segment == "git"):
        return True
    if _matches_prefix(segment, SAFE_PREFIXES):
        return True
    return _is_safe_base_cmd(segment)


def _get_alternative_feedback(
    segment: str, *, has_comments: bool, is_piped: bool = False
) -> str | None:
    """Return actionable feedback if a segment has a known safer alternative."""
    if not segment:
        return None

    tokens = segment.split()
    base_cmd = tokens[0] if tokens else ""

    if (has_comments or is_piped) and base_cmd in ALWAYS_FEEDBACK:
        tip = (
            " Tip: use the Bash tool's 'description' parameter for context instead of comments."
            if has_comments
            else ""
        )
        return ALWAYS_FEEDBACK[base_cmd] + tip

    if base_cmd in REDIRECT_FEEDBACK:
        masked = SAFE_REDIRECTS.sub("", segment)
        has_redirect = bool(re.search(r">\s*\S|>>", masked))
        if has_redirect:
            return REDIRECT_FEEDBACK[base_cmd]

    return None


CREDENTIAL_LEAK_FEEDBACK: dict[str, str] = {
    "gh auth token": (
        "Safer alternatives:\n"
        "  - One-off: in your real shell, run `export GH_TOKEN=$(gh auth token)` "
        "before launching the agent, then use `$GH_TOKEN` here.\n"
        "  - Repeated/containers: use `gh-token-run <cmd> ... --env-file {ENVFILE} ...` "
        "(writes a 600-perm temp env-file, runs the command, deletes the file).\n"
        "  - Best: use `gh api` / `gh pr` / `gh issue` directly — no token "
        "extraction needed."
    ),
    "aws iam create-access-key": (
        "Use a pre-existing access key from `~/.aws/credentials` or set "
        "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in your shell before launching "
        "the agent. Never have the agent generate fresh credentials."
    ),
    "aws sts get-session-token": (
        "Set AWS session credentials in your shell env before launching the agent, "
        "or rely on the default credential provider chain (`aws s3 ls` etc. work "
        "without explicit token extraction)."
    ),
    "op read (1Password)": (
        "Set the secret in your shell env via `export VAR=$(op read op://...)` "
        "before launching the agent, then reference `$VAR` here."
    ),
}


# Lookup table mapping ALWAYS_DENY prefixes -> CommandRule.reason for richer messages.
_ALWAYS_DENY_REASONS: dict[str, str] = {
    cmd.prefix: cmd.reason for cmd in COMMANDS if cmd.safety == Safety.DENY
}


def _normalize_segment(segment: str) -> str:
    r"""Return a whitespace/quote-normalized form of ``segment``.

    Defeats three prefix-matching bypasses:

    - quoting (``"rm" -rf /`` → ``rm -rf /``)
    - extra whitespace (``rm  -rf  /`` / ``rm\t-rf\t/`` → ``rm -rf /``)
    - quoted whitespace inside a single token (``python3'  '-c`` becomes one
      shlex token ``python3  -c`` with internal whitespace; collapsing every
      token's internal whitespace folds it back to ``python3 -c``)

    Falls back to a raw whitespace split when ``shlex`` cannot parse the
    fragment (e.g. unbalanced quotes).
    """
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return " ".join(segment.split())
    # Collapse internal whitespace per token so quoted-whitespace fragments
    # (``python3'  '-c``) match the literal ``python3 -c`` deny prefix.
    flat = [re.sub(r"\s+", " ", t.strip()) for t in tokens if t]
    return " ".join(flat)


# === Pre-deny canonicalization helpers (F2, F5, F6) ===

# Unicode whitespace classes that should fold to ASCII space.
# Spelled with \u escapes so the file itself contains no ambiguous unicode
# whitespace characters (avoids ruff RUF001 noise on the catch-list).
# Covered: NBSP (U+00A0), OGHAM SPACE (U+1680), EN QUAD..HAIR SPACE
# (U+2000-U+200A), LINE/PARA SEPARATOR (U+2028-U+2029), NARROW NBSP (U+202F),
# MEDIUM MATHEMATICAL SPACE (U+205F), IDEOGRAPHIC SPACE (U+3000).
_UNICODE_WS_RE = re.compile("[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]")


def _canonicalize(command: str) -> str:
    r"""Fold POSIX line continuations and unicode whitespace to ASCII space.

    Applied at the top of ``decide()`` so downstream pipeline-split and
    normalization operate on a canonical form. Defeats:

    - ``rm \\\n-rf /`` (backslash-newline continuation)
    - ``rm\xa0-rf\xa0/`` (NBSP) and similar unicode whitespace bypasses
    """
    command = command.replace("\\\n", " ")
    return _UNICODE_WS_RE.sub(" ", command)


# Regex matching a shell variable assignment of the form ``KEY=VALUE``.
_SEG_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _strip_env_prefix(normalized: str) -> str | None:
    """If segment starts with ``env K=V K=V ...``, return the rest.

    Returns ``None`` if the segment doesn't begin with bare ``env`` followed
    by zero or more ``KEY=VAL`` assignments. ``env -i`` / ``env --`` and
    other flag forms are NOT stripped — they fall through to the existing
    ``_is_safe_env`` / ``env -i`` ALWAYS_DENY paths.
    """
    tokens = normalized.split()
    if not tokens or tokens[0] != "env":
        return None
    i = 1
    while i < len(tokens) and _SEG_ENV_ASSIGN_RE.match(tokens[i]):
        i += 1
    if i == 1:
        # No K=V assignments — bare `env` or `env <flag>`. Don't strip.
        return None
    if i == len(tokens):
        # `env K=V` with no wrapped command — nothing to strip to.
        return None
    return " ".join(tokens[i:])


# Global git options that take a value either as the next token (``-C path``,
# ``-c k=v``) or fused (``--git-dir=...``). Stripped before ALWAYS_DENY match
# so ``git -C /tmp add -A`` is denied like ``git add -A``.
_GIT_GLOBAL_VALUE_FLAGS: frozenset[str] = frozenset({"-C", "-c"})
_GIT_GLOBAL_FUSED_PREFIXES: tuple[str, ...] = (
    "--git-dir=",
    "--work-tree=",
    "--namespace=",
    "--super-prefix=",
    "--exec-path=",
)
_GIT_GLOBAL_FUSED_NAMES: frozenset[str] = frozenset(
    {
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--exec-path",
    }
)


def _strip_git_global_options(normalized: str) -> str | None:
    """If segment starts with ``git`` + global options, return canonical form.

    Returns ``None`` for non-git segments. Otherwise walks past leading global
    options (``-C path``, ``-c k=v``, ``--git-dir=...``, ``--work-tree=...``,
    ``--namespace=...``, ``--super-prefix=...``, ``--exec-path=...``) to the
    subcommand. The returned form is ``git <subcommand> <rest>``.
    """
    tokens = normalized.split()
    if not tokens or tokens[0] != "git":
        return None
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _GIT_GLOBAL_VALUE_FLAGS:
            # consume flag + value, but only if a value is actually present
            # (don't swallow the next token past EOL on a malformed
            # ``git --git-dir add -A`` — that should still match ``git add -A``)
            if i + 1 >= len(tokens):
                break
            i += 2
            continue
        if tok.startswith(_GIT_GLOBAL_FUSED_PREFIXES):
            i += 1
            continue
        if tok in _GIT_GLOBAL_FUSED_NAMES:
            # `--git-dir path` (separate value form) — same EOL guard.
            if i + 1 >= len(tokens):
                break
            i += 2
            continue
        break
    if i == 1:
        return None  # no global options stripped
    return "git " + " ".join(tokens[i:]) if i < len(tokens) else "git"


# === Runner / shell-wrapper prefix stripping (B1) ===

# Shell-wrapper -c style flags that pass the next argument as a script body.
_SHELL_C_FLAGS_RE = re.compile(r"^-[a-zA-Z]*c$")

# Runners that take the form ``<runner> [<int>] <command>`` (timeout takes a
# duration; nice/ionice take optional ``-n N`` / ``-c N``).
_TIMING_RUNNERS: frozenset[str] = frozenset({"timeout", "nice", "ionice"})


def _shlex_tokens(segment: str) -> list[str]:
    """Tokenize ``segment`` via shlex, falling back to whitespace split."""
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _strip_runner_prefix(segment: str) -> str | None:  # noqa: C901, PLR0911, PLR0912, PLR0915 -- linear strip dispatch; extracting helpers harms readability
    """Strip a leading runner / shell-wrapper prefix from ``segment``.

    Returns the remainder (still bash-shaped) so the deny matchers can be
    re-applied to the inner command. Returns ``None`` when no recognised
    prefix is present.

    Handles:

    - shell wrappers with ``-c``/``-lc``/``-eic``: ``bash -c "rm -rf /"`` →
      ``rm -rf /``. Basename match so ``/bin/sh -c`` works too. Tokenization
      is shlex-aware so the quoted payload comes through as a single arg.
    - ``sudo`` (with optional ``-E``/``-H``/``-u USER`` flags). Recurses so
      ``sudo bash -c "..."`` peels both wrappers.
    - plain runners: ``command``, ``exec``, ``time``, ``nohup``, ``setsid``,
      ``unbuffer``, ``busybox``, ``toybox``.
    - ``timeout 5 cmd``, ``nice -n 10 cmd``, ``ionice -c 3 cmd``.
    - ``xargs ... cmd``, ``parallel ... cmd ::: <args>``.
    - ``script /dev/null -c "..."``.
    """
    tokens = _shlex_tokens(segment)
    if not tokens:
        return None
    head = _basename(tokens[0])

    # Shell wrappers with -c / -lc / -eic and so on. Find the first -c-style
    # flag (no equals form for shells) and return the next token (which is
    # the literal payload thanks to shlex tokenization).
    if head in DANGEROUS_SHELL_WRAPPERS:
        for i in range(1, len(tokens)):
            if _SHELL_C_FLAGS_RE.match(tokens[i]):
                if i + 1 < len(tokens):
                    return tokens[i + 1]
                return None
            if not tokens[i].startswith("-"):
                # Inline script arg (busybox-style ``sh script.sh``) — not RCE.
                return None
        return None

    # ``sudo`` — skip its own flag block. Recurse so wrapped shells peel too.
    if head == "sudo":
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-E", "-H", "-S", "-i", "-s", "-n", "--"):
                i += 1
                continue
            if tok in ("-u", "-g") and i + 1 < len(tokens):
                i += 2
                continue
            break
        if i < len(tokens):
            # Re-quote so a recursive call sees the same token boundaries
            # (otherwise ``sudo bash -c "rm -rf /"`` collapses to a single
            # whitespace blob and the inner shell-wrapper detector misses).
            requoted = " ".join(shlex.quote(t) for t in tokens[i:])
            deeper = _strip_runner_prefix(requoted)
            return deeper if deeper is not None else requoted
        return None

    # Plain pre-execution wrappers (no flag block).
    if head in PLAIN_RUNNER_PREFIXES and len(tokens) > 1:
        return " ".join(tokens[1:])

    # `timeout 5 cmd`, `timeout 5s cmd`, `nice -n 10 cmd`, `ionice -c 3 cmd`.
    if head in _TIMING_RUNNERS:
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-n", "-c", "-p", "-s") and i + 1 < len(tokens):
                i += 2
                continue
            if tok.startswith("-"):
                i += 1
                continue
            # First non-flag token is either the duration (``5``) or the
            # command itself. Heuristic: if it's purely numeric / ends in a
            # time suffix, treat as duration and skip; otherwise it's the cmd.
            if head == "timeout" and re.match(r"^\d+(?:\.\d+)?[smhd]?$", tok):
                i += 1
                continue
            break
        if i < len(tokens):
            return " ".join(tokens[i:])
        return None

    # `xargs [-I{}] [-n N] cmd`. Skip flags; first non-flag is the command.
    if head == "xargs":
        i = 1
        while i < len(tokens) and tokens[i].startswith("-"):
            tok = tokens[i]
            # ``-I{}`` is fused; ``-I {}`` is split.
            if tok in ("-I", "-n", "-P", "-d", "-s", "-L") and i + 1 < len(tokens):
                i += 2
                continue
            i += 1
        if i < len(tokens):
            return " ".join(tokens[i:])
        return None

    # ``parallel [flags] cmd ::: args``. Skip flags; cmd runs until ``:::``.
    # Args after ``:::`` ARE the operands the command runs against, so append
    # them to the inner command (substituting ``{}`` if present, otherwise
    # appending) so the deny matchers see ``rm -rf /``, not ``rm -rf {}``.
    if head == "parallel":
        i = 1
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 1
        if i >= len(tokens):
            return None
        end = i
        while end < len(tokens) and tokens[end] != ":::":
            end += 1
        cmd_tokens = tokens[i:end]
        if not cmd_tokens:
            return None
        args = tokens[end + 1 :] if end < len(tokens) else []
        if not args:
            return " ".join(cmd_tokens)
        # Substitute ``{}`` placeholder with the first arg (treat each arg as
        # an iteration; we only need to detect the dangerous shape).
        substituted = [args[0] if t == "{}" else t for t in cmd_tokens]
        if "{}" not in cmd_tokens:
            substituted = substituted + args
        return " ".join(substituted)

    # ``script /dev/null -c "..."``. Treat like a shell wrapper after the
    # output-file argument.
    if head == "script" and len(tokens) >= 4:  # noqa: PLR2004 -- shape: script <file> -c <cmd>
        # tokens: script <output> -c <cmd...>
        for i in range(2, len(tokens) - 1):
            if _SHELL_C_FLAGS_RE.match(tokens[i]):
                return tokens[i + 1] if i + 1 < len(tokens) else None
        return None

    return None


# === F3 — non-canonical interpreter detection ===

# Compile a regex that matches each registry-listed interpreter basename with
# an optional version suffix (``python3.11``). The set is the source of truth
# (registry.DANGEROUS_INTERPRETERS); this regex is just an indexing form.
_INTERPRETER_BASENAME_RE = re.compile(
    r"^(?:" + "|".join(re.escape(name) for name in sorted(DANGEROUS_INTERPRETERS)) + r")"
    r"(?:\d+(?:\.\d+)?)?$"
)


def _basename(path: str) -> str:
    # os.path.basename works on shell tokens (no platform-Path semantics).
    return os.path.basename(path)  # noqa: PTH119 -- string-token basename, not a real path object


_UVX_MIN_TOKENS = 2  # `uvx <interpreter>`
_PIPX_RUN_MIN_TOKENS = 3  # `pipx run <interpreter>`


def _interpreter_uses_eval_flag(tokens: list[str]) -> bool:
    """Return True if any subsequent token is an eval flag (``-c``, ``-e`` ...).

    Treats clustered short flags carefully — the eval flags are short single
    letters but we only honour exact-token matches so ``-cv`` (not real)
    won't trip. ``deno`` uses bare ``eval`` subcommand which we accept.
    """
    return any(tok in INTERPRETER_EVAL_FLAGS for tok in tokens[1:])


def _is_dangerous_interpreter(normalized: str) -> bool:
    """Return True if the segment invokes an interpreter with an eval flag.

    Detects:
    - bare interpreter binaries with version suffix or absolute path:
      ``python3.11 -c``, ``/usr/bin/python3 -c``, ``nodejs -e``, ``bun -e``,
      ``deno eval``, ``pypy3 -c``
    - runner wrappers: ``uvx python -c``, ``pipx run python -c``
    """
    tokens = normalized.split()
    if not tokens:
        return False

    # Wrapper runners — examine the wrapped command tail. Both wrappers are
    # registered in INTERPRETER_RUNNER_WRAPPERS for visibility, but each has
    # a slightly different surface (uvx <tool>, pipx run <tool>).
    head = _basename(tokens[0])
    if head in INTERPRETER_RUNNER_WRAPPERS:
        if head == "uvx" and len(tokens) >= _UVX_MIN_TOKENS:
            return _is_dangerous_interpreter(" ".join(tokens[1:]))
        if head == "pipx" and len(tokens) >= _PIPX_RUN_MIN_TOKENS and tokens[1] == "run":
            return _is_dangerous_interpreter(" ".join(tokens[2:]))

    if not _INTERPRETER_BASENAME_RE.match(head):
        return False
    return _interpreter_uses_eval_flag(tokens)


# === F4 — dangerous rm shapes ===


def _rm_is_recursive(flags: list[str]) -> bool:
    """Return True if the rm flag list implies recursive deletion."""
    for f in flags:
        if f == "--recursive":
            return True
        if f.startswith("--"):
            continue
        if not f.startswith("-"):
            continue
        # short flag cluster like -rf, -fr, -Rf, -rfv
        cluster = f[1:]
        if "r" in cluster.lower() or "R" in cluster:
            return True
    return False


def _is_dangerous_rm(normalized: str) -> bool:
    """Return True for catastrophic rm shapes that ALWAYS_DENY literals miss.

    Catches:
    - ``rm -r -f /``, ``rm --recursive --force /``
    - ``rm -rf /*``, ``rm -rf "/"``, ``rm -rf ~``
    - ``rm -rf .`` / ``rm -rf ./`` (cwd-dependent — unsafe under agent)

    The ``-f``/``--force`` flag is intentionally NOT required: ``rm -r /`` is
    just as catastrophic as ``rm -rf /`` once it hits a non-empty subtree. The
    recursive check is the sole trigger; the registry's ALWAYS_DENY literals
    keep their own ``-f`` requirement for prefix-matched messaging.
    """
    tokens = normalized.split()
    if not tokens or _basename(tokens[0]) != "rm":
        return False
    flags = [t for t in tokens[1:] if t.startswith("-")]
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    if not _rm_is_recursive(flags):
        return False
    return any(op in DANGEROUS_RM_OPERANDS for op in operands)


def _candidate_forms(segment: str) -> list[str]:
    """Return all canonical forms of ``segment`` that matchers should consider.

    A single attacker-supplied segment may need to be evaluated under several
    "peelings" before the deny matchers fire:

    - normalized (quote/whitespace-folded)
    - normalized + ``env K=V ...`` prefix stripped (F2)
    - normalized + leading git global options stripped (F5)
    - runner / shell wrapper prefix stripped (B1: ``bash -c "..."``,
      ``sudo``, ``timeout 5 ...`` etc.). The runner strip uses shlex
      tokenization on the RAW segment so quoted payloads survive.

    Returning the list lets ``_match_always_deny`` and ``_match_synthetic_deny``
    iterate the same set without duplicating the strip logic.
    """
    forms: list[str] = []
    normalized = _normalize_segment(segment)
    forms.append(normalized)
    env_stripped = _strip_env_prefix(normalized)
    if env_stripped is not None:
        forms.append(_normalize_segment(env_stripped))
    git_stripped = _strip_git_global_options(normalized)
    if git_stripped is not None:
        forms.append(git_stripped)
    # Runner strip operates on the raw segment so ``bash -c "rm -rf /"``
    # yields a single inner token "rm -rf /" (preserving the payload), not
    # the post-shlex-collapsed form which would lose the quote boundary.
    runner_stripped = _strip_runner_prefix(segment)
    if runner_stripped is not None:
        forms.append(_normalize_segment(runner_stripped))
    return forms


def _match_always_deny(segment: str) -> str | None:
    """Return the longest ALWAYS_DENY prefix matching ``segment`` or ``None``.

    Iterates ``_candidate_forms(segment)`` so quote / whitespace / env-prefix
    / git-global-option / runner-wrapper bypasses cannot evade the registry's
    deny set.
    """
    if not segment:
        return None
    for form in _candidate_forms(segment):
        match = _match_always_deny_literal(form)
        if match is not None:
            return match
    return None


def _match_always_deny_literal(normalized: str) -> str | None:
    """Pure literal prefix lookup against ALWAYS_DENY (no canonicalization)."""
    matches = [p for p in ALWAYS_DENY if normalized == p or normalized.startswith(p + " ")]
    if not matches:
        return None
    return max(matches, key=len)


# Synthetic deny-prefix labels for fixes that don't add ALWAYS_DENY literals.
_SYNTH_INTERPRETER_DENY = "<dangerous interpreter>"
_SYNTH_RM_DENY = "<dangerous rm>"
_SYNTH_GIT_CONFIG_DENY = "<git config injection>"
_SYNTH_VAR_EXPAND_DENY = "<variable-expanded head>"
_SYNTH_SHELL_WRAPPER_DENY = "<shell-wrapper invocation>"

_SYNTH_DENY_REASONS: dict[str, str] = {
    _SYNTH_INTERPRETER_DENY: (
        "Interpreter eval flag detected (python/node/bun/deno/pypy variant with "
        "-c/-e/--eval/eval). These re-exec arbitrary code and are denied "
        "regardless of binary suffix or absolute path."
    ),
    _SYNTH_RM_DENY: (
        "Recursive rm against a top-level / cwd / home operand. This shape "
        "(any of /, /*, ~, $HOME, ., ./, *) is catastrophic and is denied "
        "regardless of flag ordering."
    ),
    _SYNTH_GIT_CONFIG_DENY: (
        "git config injection: a config key on the command line is a "
        "command-execution sink (alias.*, core.pager, core.editor, "
        "*.cmd / *.clean / *.smudge, gpg.program, etc.). These keys cause "
        "git internals to exec arbitrary commands; rewrite without -c."
    ),
    _SYNTH_VAR_EXPAND_DENY: (
        "Variable-expanded head token cannot be statically evaluated. "
        "Rewrite the command without indirection (``$VAR cmd`` is not safe "
        "to validate; use the literal command name)."
    ),
    _SYNTH_SHELL_WRAPPER_DENY: (
        "Shell-wrapper invocation (``bash -c '...'``, ``sh -lc '...'``, "
        "``zsh -c '...'``, ``sudo bash -c ...``, ``script /dev/null -c ...``). "
        "These re-enter the shell with attacker-controlled script bodies and "
        "are not allowed in agent contexts. Run the underlying command directly."
    ),
}


def _normalize_git_config_key(key: str) -> str:
    """Lower-case + collapse internal whitespace for git config-key matching."""
    return re.sub(r"\s+", "", key).lower()


def _git_config_key_is_sink(key: str) -> bool:
    """Return True if a git config key is a command-execution sink (B2)."""
    norm = _normalize_git_config_key(key)
    if norm in GIT_CONFIG_EXEC_SINKS:
        return True
    return any(
        norm.startswith(prefix) and (suffix == "" or norm.endswith(suffix))
        for prefix, suffix in GIT_CONFIG_EXEC_SINK_GLOBS
    )


def _is_git_config_injection(normalized: str) -> bool:  # noqa: C901 -- linear scan of -c key=value tokens, branches mirror flag forms
    """Return True for ``git -c <sink>=<v>`` or ``git config <sink> ...`` (B2).

    The bypass: ``git -c alias.x='!rm -rf /' x`` — git executes the alias as
    a shell command. Same for ``core.pager=!rm`` and ``mergetool.foo.cmd``.
    Detect any ``-c key=value`` global option (or ``--config-env``-style
    variants) where ``key`` matches a known exec sink, plus ``git config``
    direct sets.
    """
    tokens = normalized.split()
    if not tokens or tokens[0] != "git":
        return False
    # Walk tokens looking for ``-c key=value`` shapes anywhere in the
    # command, including before and after the subcommand.
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-c" and i + 1 < len(tokens):
            kv = tokens[i + 1]
            if "=" in kv:
                k = kv.split("=", 1)[0]
                if _git_config_key_is_sink(k):
                    return True
            i += 2
            continue
        if tok.startswith("-c") and "=" in tok[2:]:
            # Fused form ``-c key=val`` — rare but handle.
            kv = tok[2:]
            k = kv.split("=", 1)[0]
            if _git_config_key_is_sink(k):
                return True
            i += 1
            continue
        i += 1
    # ``git config <key> <value>`` — direct config write.
    sub_idx = next((j for j, t in enumerate(tokens[1:], start=1) if not t.startswith("-")), None)
    if sub_idx is not None and tokens[sub_idx] == "config":
        # Skip past ``config`` flag block to first non-flag token.
        j = sub_idx + 1
        while j < len(tokens) and tokens[j].startswith("-"):
            j += 1
        if j < len(tokens) and _git_config_key_is_sink(tokens[j]):
            return True
    return False


_VAR_HEAD_RE = re.compile(r"^\$[A-Za-z_{]")


def _has_var_expanded_head(normalized: str) -> bool:
    """Return True if the head token starts with an unquoted ``$`` (B3).

    ``R=rm; $R -rf /`` becomes, after pipeline split on ``;``, two segments,
    the second of which is ``$R -rf /``. The head token is ``$R``. There is
    no legitimate use of a bare ``$VAR`` as the command name in agent input
    (the value is attacker-controlled and cannot be statically evaluated).
    """
    tokens = normalized.split(maxsplit=1)
    if not tokens:
        return False
    return bool(_VAR_HEAD_RE.match(tokens[0]))


def _is_shell_wrapper_invocation(segment: str) -> bool:
    """Return True if any token sequence in ``segment`` matches ``<shell> -c``.

    The mere presence of a shell wrapper with a ``-c``-style script body is
    denied in agent contexts: the script body is attacker-controlled and the
    shell silently re-interprets quoting / expansion / pipelines that the
    static validator cannot reason about. Walks all tokens so wrappers buried
    behind ``sudo`` / ``script /dev/null`` / ``time`` etc. are still caught.
    """
    tokens = _shlex_tokens(segment)
    for i, tok in enumerate(tokens):
        if _basename(tok) in DANGEROUS_SHELL_WRAPPERS:
            # Look ahead for a -c-style flag among the next few tokens (a
            # shell wrapper followed by a -c flag is the bypass).
            for j in range(i + 1, min(i + 4, len(tokens))):
                if _SHELL_C_FLAGS_RE.match(tokens[j]):
                    return True
                if not tokens[j].startswith("-"):
                    break
    return False


def _match_synthetic_deny(segment: str) -> str | None:  # noqa: PLR0911 -- linear matcher chain; each early-return represents a distinct synthetic deny class
    """Return a synthetic-deny label if matchers fire, else ``None``.

    Covers F3 (non-canonical interpreters), F4 (dangerous rm shapes), and the
    git config-injection sinks (B2). Iterates ``_candidate_forms(segment)``
    so env / git / runner-wrapper bypasses are evaluated against the same
    matchers as their bare forms.
    """
    if not segment:
        return None
    forms = _candidate_forms(segment)
    for cand in forms:
        if _is_dangerous_interpreter(cand):
            return _SYNTH_INTERPRETER_DENY
        if _is_dangerous_rm(cand):
            return _SYNTH_RM_DENY
    # Git config-injection (B2). The git canonicalization is done on the
    # normalized form (no env / runner peeling needed for this matcher).
    if _is_git_config_injection(forms[0]):
        return _SYNTH_GIT_CONFIG_DENY
    # Variable-expanded head token (B3). Same: the raw normalized form is
    # what matters; runner stripping would just hide the ``$VAR`` head.
    if _has_var_expanded_head(forms[0]):
        return _SYNTH_VAR_EXPAND_DENY
    # Shell-wrapper invocations (B1). Deny outright regardless of payload.
    if _is_shell_wrapper_invocation(segment):
        return _SYNTH_SHELL_WRAPPER_DENY
    return None


def _expand_runner_payload_segments(seg: str) -> list[str]:
    """Expand a shell-wrapper invocation's inner payload into pipeline segments.

    ``bash -c "rm -rf /; other"`` has operators inside the payload that the
    outer split missed. Re-split the inner payload as a fresh pipeline so the
    matchers see each inner sub-segment.

    Returns the empty list when ``seg`` doesn't start with a shell wrapper.
    """
    tokens = seg.split()
    if not tokens or _basename(tokens[0]) not in DANGEROUS_SHELL_WRAPPERS:
        return []
    inner = _strip_runner_prefix(seg)
    if inner is None:
        return []
    # Re-canonicalize and re-split the inner payload as a fresh pipeline.
    inner_canon = _canonicalize(inner)
    return split_pipeline(inner_canon)


def _get_always_deny(segments: list[str]) -> dict[str, str] | None:
    """Return a deny envelope if any segment hits the ALWAYS_DENY set, else ``None``.

    Checks both registry literals (via ``_match_always_deny``) and synthetic
    matchers for non-canonical interpreter binaries (F3) and catastrophic rm
    shapes (F4) that the literal list cannot cover exhaustively. For shell-
    wrapper invocations (``bash -c "..."``), recursively re-evaluates the
    inner payload as a full pipeline.
    """
    queue: list[str] = list(segments)
    seen: set[str] = set()
    while queue:
        seg = queue.pop(0)
        if seg in seen:
            continue
        seen.add(seg)
        prefix = _match_always_deny(seg)
        if prefix is not None:
            rule_reason = _ALWAYS_DENY_REASONS.get(prefix)
            reason = (
                f"Blocked: `{prefix}` is on the always-deny list ({rule_reason})."
                if rule_reason
                else f"Blocked: `{seg[:80]}` is on the always-deny list."
            )
            return _deny(reason)
        synth = _match_synthetic_deny(seg)
        if synth is not None:
            reason = f"Blocked: `{seg[:80]}` — {_SYNTH_DENY_REASONS[synth]}"
            return _deny(reason)
        # B1: shell-wrapper recursion. ``bash -c "rm -rf /; other"`` has
        # operators inside the payload that the outer split missed.
        queue.extend(_expand_runner_payload_segments(seg))
    return None


# === Autonomous-mode strict safety net ===
# When CLAUDE_AUTONOMOUS=1, there is no human at the prompt to answer a
# permission ask. Anything not on the safe-prefix allowlist is denied with
# either an AUTONOMOUS_FEEDBACK message (if the prefix is registered) or a
# generic default-deny.

DEFAULT_AUTONOMOUS_DENY = (
    "This command is not on the safe-prefix allowlist. In autonomous mode "
    "(CLAUDE_AUTONOMOUS=1) guard default-denies anything not explicitly safe. "
    "If this is a known-safe command, add a rule to guard's registry."
)


def get_autonomous_deny(segment: str) -> dict[str, str]:
    """Return a deny envelope for an autonomous-mode segment.

    Matches the segment against ``AUTONOMOUS_FEEDBACK`` (longest prefix wins).
    Normalizes via ``_normalize_segment`` so quoting/whitespace cannot bypass
    a feedback rule. Falls back to ``DEFAULT_AUTONOMOUS_DENY`` on no match.
    """
    normalized = _normalize_segment(segment)
    for prefix, feedback in sorted(AUTONOMOUS_FEEDBACK.items(), key=lambda kv: -len(kv[0])):
        if normalized == prefix or normalized.startswith(prefix + " "):
            return _deny(feedback)
    return _deny(DEFAULT_AUTONOMOUS_DENY)


def queue_denied_command(command: str) -> None:
    """Best-effort append a denied command to the autonomous review queue.

    The queue is a JSONL file at ``GUARD_AUTONOMOUS_QUEUE_PATH``; a human can
    review it after the session ends. I/O failures are swallowed by
    ``append_jsonl`` — the hook must never block on logging.
    """
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "command": command[:500],
        "session_id": os.environ.get("CLAUDE_SESSION_ID", ""),
    }
    append_jsonl(GUARD_AUTONOMOUS_QUEUE_PATH, entry)
    _log_debug(f"queue_denied_command: appended to {GUARD_AUTONOMOUS_QUEUE_PATH}")


def get_credential_leak_deny(command: str) -> dict[str, str] | None:
    """Return a deny dict for commands that print live credentials, else ``None``."""
    for pattern, label in CREDENTIAL_LEAK_PATTERNS:
        if pattern.search(command):
            advice = CREDENTIAL_LEAK_FEEDBACK.get(label, "")
            reason = (
                f"Blocked: `{label}` would print a live credential to the "
                "agent transcript (logged, cached, possibly leaked downstream)."
            )
            if advice:
                reason = reason + "\n\n" + advice
            return {
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
    return None


def _allow(reason: str) -> dict[str, str]:
    return {"permissionDecision": "allow", "permissionDecisionReason": reason}


def _deny(reason: str) -> dict[str, str]:
    return {"permissionDecision": "deny", "permissionDecisionReason": reason}


def _evaluate_segments(
    command: str,
    segments: list[str],
    *,
    has_comments: bool,
) -> dict[str, str] | None:
    """Walk every segment; return decision dict or ``None`` for passthrough."""
    for i, segment in enumerate(segments):
        if is_safe_command(segment, is_piped=(i > 0)):
            continue
        feedback = _get_alternative_feedback(segment, has_comments=has_comments, is_piped=(i > 0))
        if feedback:
            _log_local(command, "deny", feedback)
            return _deny(feedback)
        _log_local(command, "passthrough", f"unknown segment: {segment[:80]}")
        return None

    reason = "All command segments are read-only/safe"
    _log_local(command, "allow", reason)
    return _allow(reason)


def decide(command: str) -> dict[str, str] | None:  # noqa: PLR0911 -- top-level dispatcher with intentional early-return branches
    """Decide whether to allow a bash command. ``None`` means passthrough."""
    # F6: fold POSIX line continuations and unicode whitespace before any
    # other processing so downstream pipeline split / normalization sees a
    # canonical ASCII form.
    command = _canonicalize(command)

    leak = get_credential_leak_deny(command)
    if leak is not None:
        _log_local(command, "deny", "credential-leak")
        return leak

    cleaned = strip_comments(command)
    segments = split_pipeline(cleaned) if cleaned else []
    if not segments:
        return None

    deny = _get_always_deny(segments)
    if deny is not None:
        _log_local(command, "deny", "always-deny")
        return deny

    # === Pre-evaluation: dangerous-construct deny in BOTH modes ===
    # ``$(...)``, backticks, and process substitution are exfil/RCE primitives
    # regardless of pipeline depth or interactive/autonomous context. Likewise,
    # CONDITIONAL_SAFE base commands with denied flags (``find -exec``, etc.)
    # must deny even for single-segment commands where the segment-walk would
    # otherwise short-circuit to passthrough.
    pre_deny = _pre_evaluate_dangerous(command, segments)
    if pre_deny is not None:
        return pre_deny

    # === Autonomous mode: strict default-deny ===
    # Subagents and other driven-agent contexts have no human at the prompt.
    # Anything not explicitly on the safe-prefix allowlist is denied here so
    # the agent gets a structured rejection (with feedback) instead of a
    # silent passthrough that would otherwise hang waiting for permission.
    if is_autonomous_mode():
        return _evaluate_autonomous(command, segments)

    has_comments = command.strip() != cleaned
    has_pipes = len(segments) > 1

    if not has_comments and not has_pipes:
        _log_local(command, "passthrough", "no match")
        return None

    return _evaluate_segments(command, segments, has_comments=has_comments)


def _is_pipe_to_shell(segments: list[str]) -> bool:
    """Detect any ``<producer> | <shell>`` pipeline.

    The segments list is what ``split_pipeline`` produced — already split on
    pipe boundaries — so consecutive entries represent producer/consumer
    pairs. Returns ``True`` whenever any segment feeds directly into one of
    DANGEROUS_SHELL_WRAPPERS — that pattern is RCE in an agent context
    regardless of which encoder/decoder/fetcher is on the producing side
    (curl, wget, base64, xxd, openssl, printf, echo, python -c, ...).
    """
    if len(segments) < 2:  # noqa: PLR2004 -- "two segments minimum to form a producer|consumer pair"
        return False
    for i in range(len(segments) - 1):
        producer = segments[i].strip()
        consumer = segments[i + 1].strip()
        if not producer or not consumer:
            continue
        cons_token = _basename(consumer.split(maxsplit=1)[0])
        if cons_token in _PIPE_SHELL_CMDS:
            return True
    return False


_PIPE_TO_SHELL_REASON = (
    "Blocked: piping any output directly into a shell (sh/bash/zsh/...) is a "
    "classic remote-code-execution pattern (curl|sh, echo cm0...|base64 -d|sh, "
    "xxd -r -p|bash, etc.). There is no legitimate use of this shape in an "
    "agent context. Write the output to a file first, inspect it, then run "
    "it explicitly if you really mean to."
)


def _pre_evaluate_dangerous(command: str, segments: list[str]) -> dict[str, str] | None:
    r"""Pre-deny passes that fire in both interactive and autonomous mode.

    These checks run BEFORE the autonomous strict-mode path and BEFORE the
    interactive ``no comments / no pipes -> passthrough`` short-circuit. They
    catch bypasses that the segment walk used to miss for bare commands:
    ``find . -exec rm {} \;`` and ``cat $(rm -rf /)`` would otherwise return
    ``None`` (passthrough) on a single-segment, no-comment input.

    Returns a deny envelope if any segment hits a dangerous-construct or a
    CONDITIONAL_SAFE-with-denied-flag pattern. Returns ``None`` to defer to
    the normal evaluator.
    """
    if _is_pipe_to_shell(segments):
        _log_local(command, "deny", "pipe-to-shell")
        return _deny(_PIPE_TO_SHELL_REASON)
    for segment in segments:
        if has_dangerous_constructs(segment):
            reason = (
                f"Blocked: `{segment[:80]}` contains a dangerous shell "
                "construct ($(...), backticks, or process substitution). "
                "These are exfil/RCE primitives and are denied in both "
                "interactive and autonomous mode."
            )
            _log_local(command, "deny", "dangerous-construct")
            return _deny(reason)
        tokens = segment.split()
        base_cmd = tokens[0] if tokens else ""
        if base_cmd in CONDITIONAL_SAFE and not _is_conditional_safe(segment, base_cmd):
            denied_flags = sorted(CONDITIONAL_SAFE[base_cmd])
            reason = (
                f"Blocked: `{base_cmd}` was invoked with a denied flag "
                f"(any of {denied_flags}). These flags allow arbitrary "
                "command execution and are not permitted."
            )
            _log_local(command, "deny", f"{base_cmd}-denied-flag")
            return _deny(reason)
    return None


def _matches_autonomous_feedback(segment: str) -> bool:
    """Return True if the segment matches an AUTONOMOUS_FEEDBACK prefix.

    AUTONOMOUS_FEEDBACK entries are commands that need explicit human approval
    in driven-agent contexts, so they must NOT be allowed by SAFE_PREFIXES
    coverage (e.g. `git branch -d` falls under the broader `git branch` safe
    prefix, but is registered separately as feedback-required).

    Normalizes via ``_normalize_segment`` so quoting/whitespace bypasses are
    closed (``"git" add -A`` matches the ``git add`` ASK rule).
    """
    normalized = _normalize_segment(segment)
    for prefix in AUTONOMOUS_FEEDBACK:
        if normalized == prefix or normalized.startswith(prefix + " "):
            return True
    return False


def _evaluate_autonomous(command: str, segments: list[str]) -> dict[str, str]:
    """Walk every segment under autonomous strict-mode rules.

    Returns deny on first non-safe segment (with optional AUTONOMOUS_FEEDBACK
    message), or allow if every segment is on the safe-prefix allowlist.

    AUTONOMOUS_FEEDBACK matches take priority over SAFE_PREFIXES — a command
    explicitly registered as feedback-required is denied even if a broader
    safe prefix would otherwise cover it.
    """
    for i, segment in enumerate(segments):
        if not _matches_autonomous_feedback(segment) and is_safe_command(
            segment, is_piped=(i > 0), autonomous=True
        ):
            continue
        result = get_autonomous_deny(segment)
        reason = result["permissionDecisionReason"]
        _log_local(command, "deny", reason)
        queue_denied_command(command)
        return result
    reason = "All command segments are safe (autonomous mode)"
    _log_local(command, "allow", reason)
    return _allow(reason)


_LOOP_RE = re.compile(r"^(for|while)\s+")


def _hard_deny_check(command: str) -> None:
    """Exit 2 if the command contains a corrupted token or bare shell fragment."""
    if CORRUPTED_TOKEN.search(command):
        sys.stderr.write(
            f"BLOCKED: corrupted internal token in command: {sanitize_for_stderr(command)}\n"
        )
        sys.exit(2)

    cleaned = strip_comments(command)
    if not cleaned:
        return
    stripped = cleaned.strip()
    if stripped in SHELL_FRAGMENTS:
        sys.stderr.write(f"BLOCKED: bare shell fragment: {sanitize_for_stderr(stripped)}\n")
        sys.exit(2)
    if _LOOP_RE.match(stripped) and "; do" not in stripped and "\ndo" not in stripped:
        sys.stderr.write(f"BLOCKED: incomplete loop (no body): {sanitize_for_stderr(stripped)}\n")
        sys.exit(2)


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command:
        return

    _hard_deny_check(command)

    decision = decide(command)
    if decision is None:
        return

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            **decision,
        }
    }
    sys.stdout.write(json.dumps(output))
    if decision.get("permissionDecision") == "deny":
        sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
