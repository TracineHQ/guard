# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: deny direct reads on agent output JSONL files.

Agent output transcripts can be large and waste context when read directly.
This hook blocks ``Read`` and ``Bash(cat|head|tail)`` calls that target paths
matching the typical agent output pattern, instructing the agent to use a
dedicated query CLI instead.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.agent_output_guard"

# Matches agent output file paths produced by Claude Code subagent runs.
# macOS form:   /private/tmp/claude-<pid>/.../tasks/<id>.output
# Linux form:   /tmp/claude-<pid>/.../tasks/<id>.output
# Anchored at end so we don't false-match unrelated paths containing
# ``.output`` mid-string.
AGENT_OUTPUT_PATTERN = re.compile(r"/(?:private/)?tmp/claude-\d+/.*/tasks/.*\.output\b")

_DENY_REASON = (
    "Direct reads on agent output files are not allowed — "
    "they are large JSONL transcripts that waste context. "
    "Use the appropriate query CLI for this data:\n"
    "  - list recent agent runs\n"
    "  - show a formatted summary by id\n"
    "  - fall back to the raw JSONL only when explicitly required"
)


def decide(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any] | None:
    """Return a deny envelope if the call targets an agent output file."""
    if tool_name == "Read":
        path = tool_input.get("file_path", "")
        if isinstance(path, str) and AGENT_OUTPUT_PATTERN.search(path):
            return emit_pretooluse_decision("deny", _DENY_REASON)

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if (
            isinstance(command, str)
            and re.match(r"^(cat|head|tail)\s", command)
            and AGENT_OUTPUT_PATTERN.search(command)
        ):
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
