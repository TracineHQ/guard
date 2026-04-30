# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: force ASK on edits to security-critical hook files.

Matches ``Edit`` and ``Write`` ``tool_input.file_path`` against a small set of
protected path patterns. If matched, the hook emits an ``ask`` permission
decision so a human must confirm. It never blocks — its only job is to ensure
changes to the hook infrastructure are surfaced for review.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.protected_files"

# Files that define security policy for all Claude Code sessions.
# Changes to these affect every repo and every agent.
PROTECTED_PATTERNS: list[str] = [
    "guard/hooks/bash_command_validator.py",
    "guard/hooks/git_c_validator.py",
    "guard/hooks/credential_check.py",
    "guard/hooks/protected_files.py",
    "guard/hooks/commit_message_validator.py",
    "guard/hooks/agent_output_guard.py",
    "guard/hooks/chrome_safety_validator.py",
    "guard/hooks/subagent_scope.py",
    "guard/registry.py",
    "guard/_utils.py",
    # Claude Code harness configuration — these are the ASK-gate that
    # decides whether guard hooks even fire. Edits must surface for review.
    ".claude/settings.json",
    ".claude/settings.local.json",
    # Backwards-compat patterns for repos that vendor the original layout
    "hooks/command_registry.py",
    "hooks/bash_command_validator.py",
    "hooks/git_c_validator.py",
    "hooks/credential_check.py",
    "hooks/generate_settings.py",
    "hooks/_hook_utils.py",
    "hooks/protected_files.py",
    "hooks/commit_message_validator.py",
    "hooks/agent_output_guard.py",
]


def is_protected(file_path: str) -> str | None:
    """Return the matched protected pattern for ``file_path``, else ``None``."""
    if not file_path:
        return None
    try:
        resolved = Path(file_path).resolve()
    except (ValueError, OSError):
        return None

    resolved_str = str(resolved)
    for pattern in PROTECTED_PATTERNS:
        # Match /<...>/pattern to avoid false positives like /not_<...>/file.py
        if (
            resolved_str.endswith(pattern)
            and len(resolved_str) > len(pattern)
            and resolved_str[-(len(pattern) + 1)] == "/"
        ):
            return pattern
    return None


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if tool_name not in ("Edit", "Write"):
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return
    file_path = tool_input.get("file_path", "")
    if not isinstance(file_path, str) or not file_path:
        return

    matched = is_protected(file_path)
    if matched is None:
        return

    reason = f"Protected file: {matched} — confirm edit"
    envelope = emit_pretooluse_decision("ask", reason)
    cwd = payload.get("cwd")
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name,
        decision="ask",
        reason=reason,
        command_excerpt=file_path,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd if isinstance(cwd, str) else None,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
