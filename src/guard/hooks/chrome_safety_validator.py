# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: validate Chrome CLI commands for sensitive data access.

Intercepts ``chrome eval`` and ``chrome fetch`` invocations and uses the
shared ``chrome_cli.safety`` patterns (when available) to keep the hook
in lock-step with the CLI. Also enforces profile isolation by blocking
direct ``--user-data-dir`` arguments on ``chrome launch``.

When ``chrome_cli`` is not installed the hook degrades to silent
passthrough — settings.json ``ask`` rules still apply.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from guard._utils import emit_pretooluse_decision, is_autonomous_mode, log_decision, safe_main

_HOOK_ID = "guard.chrome_safety_validator"

try:
    from chrome_cli.safety import (  # type: ignore[import-not-found]  # optional dep, see HAS_CHROME_SAFETY
        validate_eval_expression,
        validate_profile_name,
        validate_user_data_dir,
    )

    HAS_CHROME_SAFETY = True
except ImportError:
    HAS_CHROME_SAFETY = False

# Minimum tokens after splitting to find a JS expression: ``chrome eval <expr>``
_CHROME_EVAL_MIN_PARTS = 3
# Minimum length for a quoted JS expression (``""`` or ``''``)
_CHROME_QUOTED_MIN = 2
# Minimum tokens after splitting to identify a chrome subcommand
_CHROME_SUBCOMMAND_MIN_PARTS = 2

# Commands that require human confirmation in autonomous mode
_AUTONOMOUS_DENY: dict[str, str] = {
    "launch": "Chrome launch requires confirmation. Queue for session end.",
    "stop": "Chrome stop requires confirmation. Queue for session end.",
    "navigate": "Navigation requires confirmation. Describe what to navigate to.",
    "click": "Click requires confirmation. Describe the interaction.",
    "fill": "Form fill requires confirmation. Describe what to fill.",
    "eval": "JS eval requires human review. Describe the intent.",
    "wait": "Wait requires confirmation.",
    "fetch": "Fetch requires human review. The browser session may contain credentials.",
    "open": "Tab open requires confirmation.",
    "close": "Tab close requires confirmation.",
    "reload": "Tab reload requires confirmation.",
}


def extract_eval_expression(command: str) -> str | None:
    """Extract the JS expression from a ``chrome eval`` command, or ``None``."""
    rest = command.split(None, 2)
    if len(rest) < _CHROME_EVAL_MIN_PARTS:
        return None

    expr = rest[2]

    if len(expr) >= _CHROME_QUOTED_MIN and (
        (expr[0] == '"' and expr[-1] == '"') or (expr[0] == "'" and expr[-1] == "'")
    ):
        expr = expr[1:-1]

    return expr or None


def extract_profile_arg(command: str) -> str | None:
    """Extract the ``--profile`` value from a ``chrome launch`` command."""
    match = re.search(r"--profile\s+(\S+)", command)
    return match.group(1) if match else None


def extract_user_data_dir(command: str) -> str | None:
    """Extract ``--user-data-dir`` from a ``chrome launch`` command, or ``None``."""
    match = re.search(r"--user-data-dir[=\s]+(\S+)", command)
    return match.group(1) if match else None


def _decide_eval(command: str) -> dict[str, Any] | None:
    """Validate a ``chrome eval`` command."""
    expr = extract_eval_expression(command)
    if expr is None:
        return emit_pretooluse_decision(
            "deny",
            'No expression provided. Usage: chrome eval "<expression>"',
        )
    if HAS_CHROME_SAFETY:
        is_safe, message = validate_eval_expression(expr)
        if not is_safe:
            return emit_pretooluse_decision("deny", message)
    return None


def _decide_launch(command: str) -> dict[str, Any] | None:
    """Validate a ``chrome launch`` command."""
    user_data_dir = extract_user_data_dir(command)
    if user_data_dir:
        if HAS_CHROME_SAFETY:
            valid, reason = validate_user_data_dir(user_data_dir)
            if not valid:
                return emit_pretooluse_decision("deny", reason)
        return emit_pretooluse_decision(
            "deny",
            (
                "Direct --user-data-dir is blocked. Use --profile NAME instead. "
                "chrome-cli manages profile directories under "
                "~/.chrome-cli/profiles/."
            ),
        )

    profile = extract_profile_arg(command)
    if profile and HAS_CHROME_SAFETY:
        valid, reason = validate_profile_name(profile)
        if not valid:
            return emit_pretooluse_decision("deny", reason)
    return None


def decide(command: str) -> dict[str, Any] | None:
    """Decide whether a chrome command is safe.

    Returns a decision envelope from ``emit_pretooluse_decision`` or ``None``
    for passthrough.
    """
    parts = command.split(None, 2)
    if len(parts) < _CHROME_SUBCOMMAND_MIN_PARTS:
        return None

    subcommand = parts[1]

    # Autonomous mode: deny write-tier commands
    if is_autonomous_mode() and subcommand in _AUTONOMOUS_DENY:
        return emit_pretooluse_decision("deny", _AUTONOMOUS_DENY[subcommand])

    if subcommand == "eval":
        return _decide_eval(command)
    if subcommand == "fetch":
        return None
    if subcommand == "launch":
        return _decide_launch(command)
    return None


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point.

    The autonomous-mode deny table at module top is hook-local data, so it
    fires regardless of whether the optional ``chrome_cli`` package is
    installed. Only the eval-validation path (``validate_eval_expression``)
    is gated on ``HAS_CHROME_SAFETY``; everything else (autonomous deny,
    user-data-dir block) works with stdlib only.
    """
    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command.startswith("chrome "):
        return

    envelope = decide(command)
    if envelope is None:
        return

    hso = envelope.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision")
    cwd = payload.get("cwd")
    if decision in ("allow", "deny", "ask"):
        log_decision(
            hook_id=_HOOK_ID,
            event="PreToolUse",
            tool_name="Bash",
            decision=decision,
            reason=hso.get("permissionDecisionReason", ""),
            command_excerpt=command,
            session_id=str(payload.get("session_id", "")),
            cwd=cwd if isinstance(cwd, str) else None,
        )
    sys.stdout.write(json.dumps(envelope))
    if decision == "deny":
        sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
