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

# HTTP-fetch CLIs that, when piped into a shell, form the classic
# ``curl ... | sh`` RCE pattern. Denied unconditionally regardless of mode.
_HTTP_FETCH_CMDS: frozenset[str] = frozenset({"curl", "wget", "fetch", "http", "httpie", "https"})
_PIPE_SHELL_CMDS: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "fish", "ksh", "ash"})


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


def split_pipeline(command: str) -> list[str]:
    """Split a command into segments on pipe/operator/newline boundaries."""
    segments: list[str] = []
    for line in command.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = strip_inline_comment(stripped)
        if not stripped:
            continue
        parts = re.split(r"\s*(?:\|(?!\|)|\|\||&&|;)\s*", stripped)
        segments.extend(p.strip() for p in parts if p.strip())
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


def is_safe_command(segment: str, *, is_piped: bool = False, autonomous: bool = False) -> bool:
    """Return ``True`` if a segment matches a known-safe prefix.

    In autonomous mode, git segments are NOT deferred to git_c_validator —
    we must evaluate them here so the strict default-deny path can fire.
    """
    if not segment:
        return True
    if has_dangerous_constructs(segment):
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

    Defeats two prefix-matching bypasses:

    - quoting (``"rm" -rf /`` → ``rm -rf /``)
    - extra whitespace (``rm  -rf  /`` / ``rm\t-rf\t/`` → ``rm -rf /``)

    Falls back to a raw whitespace split when ``shlex`` cannot parse the
    fragment (e.g. unbalanced quotes).
    """
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return " ".join(segment.split())
    return " ".join(tokens)


def _match_always_deny(segment: str) -> str | None:
    """Return the longest ALWAYS_DENY prefix matching ``segment`` or ``None``.

    Normalizes via ``_normalize_segment`` before prefix-matching so quoting
    and whitespace bypasses (``"rm" -rf /``, ``rm  -rf  /``) cannot evade
    the registry's deny set.
    """
    if not segment:
        return None
    normalized = _normalize_segment(segment)
    matches = [p for p in ALWAYS_DENY if normalized == p or normalized.startswith(p + " ")]
    if not matches:
        return None
    return max(matches, key=len)


def _get_always_deny(segments: list[str]) -> dict[str, str] | None:
    """Return a deny envelope if any segment hits the ALWAYS_DENY set, else ``None``."""
    for seg in segments:
        prefix = _match_always_deny(seg)
        if prefix is None:
            continue
        rule_reason = _ALWAYS_DENY_REASONS.get(prefix)
        reason = (
            f"Blocked: `{prefix}` is on the always-deny list ({rule_reason})."
            if rule_reason
            else f"Blocked: `{seg[:80]}` is on the always-deny list."
        )
        return _deny(reason)
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
    """Detect ``curl|wget|... | sh|bash|...`` pipelines.

    The segments list is what ``split_pipeline`` produced — already split on
    pipe boundaries — so consecutive entries represent producer/consumer pairs.
    Returns ``True`` if any HTTP-fetch segment feeds directly into a shell
    interpreter segment.
    """
    if len(segments) < 2:  # noqa: PLR2004 -- "two segments minimum to form a producer|consumer pair"
        return False
    for i in range(len(segments) - 1):
        producer = segments[i].strip()
        consumer = segments[i + 1].strip()
        if not producer or not consumer:
            continue
        prod_token = producer.split(maxsplit=1)[0]
        cons_token = consumer.split(maxsplit=1)[0]
        if prod_token in _HTTP_FETCH_CMDS and cons_token in _PIPE_SHELL_CMDS:
            return True
    return False


_PIPE_TO_SHELL_REASON = (
    "Blocked: piping HTTP fetch output (curl/wget/...) directly into a shell "
    "(sh/bash/zsh/...) is a classic remote-code-execution pattern with no "
    "legitimate use in an agent context. Download to a file first, inspect "
    "it, then run it explicitly if you really mean to."
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
