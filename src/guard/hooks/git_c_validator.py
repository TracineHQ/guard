# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: validate ``git -C <path>`` commands.

Allows read-only git subcommands invoked with ``-C <path>``, denies
destructive ones, and asks for unknown subcommands. Works at any path depth
(bypasses the glob ``*`` vs ``/`` limitation in permission rules).

IMPORTANT: this hook only evaluates a single, operator-free command.
If the input contains shell operators (``&&``, ``||``, ``;``, ``|``) it
declines to auto-allow because ``shlex`` cannot reliably parse those
boundaries — fallthrough lets the normal permission system handle them.
"""

from __future__ import annotations

import json
import shlex
import sys
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.git_c_validator"

# Read-only git subcommands — safe to auto-allow
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "branch",
        "remote",
        "blame",
        "rev-parse",
        "describe",
        "tag",
        "ls-files",
        "ls-tree",
        "grep",
        "stash",
        "shortlog",
        "cat-file",
        "rev-list",
        "name-rev",
        "for-each-ref",
        "reflog",
        "count-objects",
        "fsck",
        "verify-pack",
    }
)

# Destructive subcommands — hard deny with -C
DENIED_SUBCOMMANDS: frozenset[str] = frozenset({"clean", "reset"})

# Stash sub-subcommands that are destructive
DENIED_STASH_ACTIONS: frozenset[str] = frozenset({"pop", "drop", "clear"})

# Flags that consume the next argument (so we don't misidentify it as a subcommand)
FLAGS_WITH_ARGS: frozenset[str] = frozenset(
    {
        "-c",
        "--git-dir",
        "--work-tree",
        "-C",
    }
)

# Length of "-C" prefix for inline ``-C/path`` (no space) form
_DASH_C_PREFIX_LEN = 2

_SHELL_OPERATOR_CHARS: frozenset[str] = frozenset({"|", ";"})


def has_shell_operators(command: str) -> bool:
    """Return ``True`` if the command contains an unquoted shell operator."""
    try:
        shlex.split(command)
    except ValueError:
        return True

    in_quote = False
    quote_char: str | None = None
    i = 0
    while i < len(command):
        c = command[i]
        if not in_quote:
            if c in ('"', "'"):
                in_quote = True
                quote_char = c
            elif (
                c == "&" and i + 1 < len(command) and command[i + 1] == "&"
            ) or c in _SHELL_OPERATOR_CHARS:
                return True
        elif c == quote_char and (i == 0 or command[i - 1] != "\\"):
            in_quote = False
            quote_char = None
        i += 1
    return False


def parse_git_c_command(
    command: str,
) -> tuple[str | None, str | None, list[str]]:
    """Extract ``(path, subcommand, remaining_args)`` from a ``git -C`` call."""
    try:
        parts = shlex.split(command)
    except ValueError:
        return None, None, []

    if not parts or parts[0] != "git":
        return None, None, []

    i = 1
    path: str | None = None
    while i < len(parts):
        if parts[i] == "-C" and i + 1 < len(parts):
            path = parts[i + 1]
            i += 2
        elif parts[i].startswith("-C") and len(parts[i]) > _DASH_C_PREFIX_LEN:
            path = parts[i][_DASH_C_PREFIX_LEN:]
            i += 1
        elif parts[i] in FLAGS_WITH_ARGS and i + 1 < len(parts):
            i += 2
        elif parts[i].startswith("-"):
            i += 1
        else:
            return path, parts[i], parts[i + 1 :]

    return path, None, []


_CONFIG_READ_FLAGS: frozenset[str] = frozenset(
    {"--get", "--list", "-l", "--get-all", "--get-regexp"}
)


def _decide_config(remaining: list[str]) -> dict[str, Any]:
    """Decide a ``git -C ... config ...`` invocation."""
    if remaining and remaining[0] in _CONFIG_READ_FLAGS:
        return emit_pretooluse_decision("allow", "git -C: 'config' with read-only flag")
    return _ask_envelope("git -C: 'config' write requires confirmation")


def _decide_stash(remaining: list[str]) -> dict[str, Any] | None:
    """Decide a ``git -C ... stash <action>`` invocation, or fall through."""
    if not remaining:
        return None
    action = remaining[0]
    if action in DENIED_STASH_ACTIONS:
        return emit_pretooluse_decision("deny", f"git -C: 'stash {action}' is destructive")
    if action in ("list", "show"):
        return emit_pretooluse_decision("allow", f"git -C: 'stash {action}' is read-only")
    return None


def _classify_subcommand(subcommand: str, remaining: list[str]) -> dict[str, Any]:
    """Classify a parsed subcommand into an allow/deny/ask envelope."""
    if subcommand == "config":
        return _decide_config(remaining)
    if subcommand == "stash":
        stash_decision = _decide_stash(remaining)
        if stash_decision is not None:
            return stash_decision
    if subcommand in DENIED_SUBCOMMANDS:
        return emit_pretooluse_decision(
            "deny", f"git -C: '{subcommand}' is destructive and blocked"
        )
    if subcommand in ALLOWED_SUBCOMMANDS:
        return emit_pretooluse_decision("allow", f"git -C: '{subcommand}' is read-only")
    return _ask_envelope(f"git -C: '{subcommand}' is not in the allow list")


_COMMIT_HEAD_TOKENS = 3  # ['git', 'commit', <at least one more arg>]


def _is_reuse_token(tok: str, idx: int, parts: list[str]) -> bool:
    """Return True iff ``tok`` at position ``idx`` requests prior-message reuse."""
    if tok == "-C" and idx + 1 < len(parts):
        return True
    if tok.startswith("-C") and len(tok) > _DASH_C_PREFIX_LEN and not tok.startswith("--"):
        return True
    if tok == "--reuse-message" and idx + 1 < len(parts):
        return True
    return tok.startswith("--reuse-message=")


def _is_commit_reuse(command: str) -> bool:
    """Return ``True`` if the command silently reuses a prior commit message.

    Matches ``git commit -C <ref>`` and ``git commit --reuse-message=<ref>``.
    These let an agent append to history without authoring a new message,
    which defeats the audit trail commit_message_validator is meant to enforce.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if len(parts) < _COMMIT_HEAD_TOKENS or parts[0] != "git" or parts[1] != "commit":
        return False
    return any(_is_reuse_token(tok, i, parts) for i, tok in enumerate(parts[2:], start=2))


def decide(command: str) -> dict[str, Any] | None:
    """Return a permission envelope, or ``None`` to fall through."""
    if has_shell_operators(command):
        return None
    if _is_commit_reuse(command):
        return emit_pretooluse_decision(
            "deny",
            "git commit -C / --reuse-message: silent commit-message reuse is blocked",
        )
    path, subcommand, remaining = parse_git_c_command(command)
    if path is None or subcommand is None:
        return None
    return _classify_subcommand(subcommand, remaining)


def _ask_envelope(reason: str) -> dict[str, Any]:
    """Return an ``ask`` envelope via the modern PreToolUse helper."""
    return emit_pretooluse_decision("ask", reason)


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command", "")
    if not isinstance(command, str) or ("git -C" not in command and "git commit" not in command):
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
