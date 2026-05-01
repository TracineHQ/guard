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

from guard._utils import all_paths_in, emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.agent_output_guard"

# Matches agent output file paths produced by Claude Code subagent runs.
# macOS form:   /private/tmp/claude-<pid>/.../tasks/<id>.output
# Linux form:   /tmp/claude-<pid>/.../tasks/<id>.output
# The negative-lookahead trailing class ensures ``.output.bak``,
# ``.output_old``, ``.output2`` etc. do NOT match — only the bare
# ``.output`` filename (or one followed by a non-identifier char such as
# ``"`` or whitespace) is the actual agent transcript.
AGENT_OUTPUT_PATTERN = re.compile(
    r"/(?:private/)?tmp/claude-\d+/.*/tasks/.*\.output(?![A-Za-z0-9_])"
)

_DENY_REASON = (
    "Direct reads on agent output files are not allowed — "
    "they are large JSONL transcripts that waste context. "
    "Use the appropriate query CLI for this data:\n"
    "  - list recent agent runs\n"
    "  - show a formatted summary by id\n"
    "  - fall back to the raw JSONL only when explicitly required"
)


def decide(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any] | None:
    """Return a deny envelope if any path-like token names an agent output file.

    The path is the dangerous signal — verb-agnostic. We scan every
    string contained anywhere in ``tool_input`` (covers ``Read.file_path``,
    ``Glob.pattern``, ``Grep.path``, ``MultiEdit.file_path``, ``WebFetch.url``
    with ``file://`` scheme, etc.) plus the raw Bash command string as a
    fallback for compound shapes (heredocs, redirects, process-sub) where
    token extraction may fragment unexpectedly.
    """
    for raw in all_paths_in(tool_input):
        if AGENT_OUTPUT_PATTERN.search(raw):
            return emit_pretooluse_decision("deny", _DENY_REASON)

    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if isinstance(cmd, str) and AGENT_OUTPUT_PATTERN.search(cmd):
            return emit_pretooluse_decision("deny", _DENY_REASON)

    return None


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    envelope = decide(tool_name, tool_input)
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
    cwd = payload.get("cwd")
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name if isinstance(tool_name, str) else None,
        decision="deny",
        reason=_DENY_REASON,
        command_excerpt=command_excerpt,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd if isinstance(cwd, str) else None,
    )
    sys.stdout.write(json.dumps(envelope))
    sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
