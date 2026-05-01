# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: deny any tool call that targets an agent output file.

Agent output transcripts are large JSONL files that waste context when read
directly. The path itself is the dangerous signal — what command would read,
copy, or fingerprint it doesn't matter. This hook rejects any ``tool_input``
shape (string/dict/list/nested) that contains a path matching the agent
output pattern, regardless of which tool or verb is invoked.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from guard._utils import (
    all_paths_in,
    all_strings_in,
    emit_pretooluse_decision,
    log_decision,
    safe_main,
)

_HOOK_ID = "guard.agent_output_guard"

# Matches agent output file paths produced by Claude Code subagent runs.
# macOS form:   /private/tmp/claude-<pid>/.../tasks/<id>.output
# Linux form:   /tmp/claude-<pid>/.../tasks/<id>.output
# The pid slot accepts digits AND glob metacharacters (``*``, ``?``) so a
# bypass like ``cat /private/tmp/claude-*/proj/sess/tasks/*.output`` —
# which expands to a real agent transcript at runtime — is still caught.
# The negative-lookahead trailing class ensures ``.output.bak``,
# ``.output_old``, ``.output2`` etc. do NOT match — only the bare
# ``.output`` filename (or one followed by a non-identifier char such as
# ``"`` or whitespace) is the actual agent transcript.
AGENT_OUTPUT_PATTERN = re.compile(
    r"/(?:private/)?tmp/claude-[\d*?]+/.*/tasks/.*\.output(?![A-Za-z0-9_])"
)

# Detects a working directory inside an agent-output session tree. Used to
# resolve cwd-relative reads (``cat tasks/abc.output`` while cwd is
# ``/private/tmp/claude-1234/proj/sess``) into absolute paths before the
# main pattern check runs.
_AGENT_CWD_RE = re.compile(r"^/(?:private/)?tmp/claude-[\d*?]+/")

_DENY_REASON = (
    "Direct reads on agent output files are not allowed — "
    "they are large JSONL transcripts that waste context. "
    "Use the appropriate query CLI for this data:\n"
    "  - list recent agent runs\n"
    "  - show a formatted summary by id\n"
    "  - fall back to the raw JSONL only when explicitly required"
)


def _cwd_is_agent_session(cwd: str | None) -> bool:
    """Return True if ``cwd`` is inside a Claude Code agent-output session tree."""
    if not cwd:
        return False
    return bool(_AGENT_CWD_RE.match(cwd))


def _join_cwd(cwd: str, token: str) -> str:
    """Join ``cwd`` with a relative ``token``, preserving any glob metacharacters."""
    if token.startswith("/"):
        return token
    cleaned = token.removeprefix("./")
    return f"{cwd.rstrip('/')}/{cleaned}"


def decide(
    tool_name: str,
    tool_input: dict[str, Any],
    cwd: str | None = None,
) -> dict[str, Any] | None:
    """Return a deny envelope if any path-like token names an agent output file.

    The path is the dangerous signal — verb-agnostic. We scan every
    string contained anywhere in ``tool_input`` (covers ``Read.file_path``,
    ``Glob.pattern``, ``Grep.path``, ``MultiEdit.file_path``, ``WebFetch.url``
    with ``file://`` scheme, etc.) plus the raw Bash command string as a
    fallback for compound shapes (heredocs, redirects, process-sub) where
    token extraction may fragment unexpectedly.

    When ``cwd`` is itself inside an agent-output session tree
    (``/private/tmp/claude-<pid>/...`` or ``/tmp/claude-<pid>/...``), every
    relative path token is also re-checked with ``cwd`` prepended so that
    payloads like ``cat tasks/abc.output`` (with cwd inside the session)
    are caught.
    """
    in_agent_cwd = _cwd_is_agent_session(cwd)

    if _scan_extracted_paths(tool_input, cwd, in_agent_cwd=in_agent_cwd):
        return emit_pretooluse_decision("deny", _DENY_REASON)

    if _scan_raw_strings(tool_input):
        return emit_pretooluse_decision("deny", _DENY_REASON)

    if tool_name == "Bash" and _scan_bash_command(tool_input, cwd, in_agent_cwd=in_agent_cwd):
        return emit_pretooluse_decision("deny", _DENY_REASON)

    return None


def _scan_extracted_paths(
    tool_input: dict[str, Any], cwd: str | None, *, in_agent_cwd: bool
) -> bool:
    """Match the agent-output regex against each path token in tool_input."""
    for raw in all_paths_in(tool_input):
        if AGENT_OUTPUT_PATTERN.search(raw):
            return True
        if in_agent_cwd and cwd is not None and not raw.startswith("/"):
            joined = _join_cwd(cwd, raw)
            if AGENT_OUTPUT_PATTERN.search(joined):
                return True
    return False


def _scan_raw_strings(tool_input: dict[str, Any]) -> bool:
    r"""Whole-string fallback: catches glob-bearing paths that path extraction fragments.

    ``all_paths_in`` uses ``_PATH_LIKE_RE`` which excludes glob metacharacters,
    so e.g. ``/private/tmp/claude-*/tasks/x.output`` would be fragmented. The
    pattern's ``[\d*?]+`` pid slot still matches if we regex-search the full
    string.
    """
    return any(AGENT_OUTPUT_PATTERN.search(s) for s in all_strings_in(tool_input))


def _scan_bash_command(tool_input: dict[str, Any], cwd: str | None, *, in_agent_cwd: bool) -> bool:
    """Bash-specific extras: full-command regex + cwd-relative token check."""
    cmd = tool_input.get("command", "")
    if not isinstance(cmd, str):
        return False
    if AGENT_OUTPUT_PATTERN.search(cmd):
        return True
    if not (in_agent_cwd and cwd is not None):
        return False
    # Whitespace-split the command and join each non-flag/non-absolute token
    # with cwd, so payloads like ``cat tasks/abc.output`` (with cwd inside the
    # session) match the absolute-path pattern.
    for tok in cmd.split():
        stripped = tok.strip("'\"`")
        if not stripped or stripped.startswith(("/", "-")):
            continue
        if AGENT_OUTPUT_PATTERN.search(_join_cwd(cwd, stripped)):
            return True
    return False


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    cwd = payload.get("cwd")
    cwd_str = cwd if isinstance(cwd, str) else None
    envelope = decide(tool_name, tool_input, cwd=cwd_str)
    if envelope is None:
        return  # Passthrough

    command_excerpt: str | None = None
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if isinstance(cmd, str):
            command_excerpt = cmd
    elif tool_name == "Read":
        fp = tool_input.get("file_path", "")
        if isinstance(fp, str):
            command_excerpt = fp
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name if isinstance(tool_name, str) else None,
        decision="deny",
        reason=_DENY_REASON,
        command_excerpt=command_excerpt,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd_str,
    )
    sys.stdout.write(json.dumps(envelope))
    sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
