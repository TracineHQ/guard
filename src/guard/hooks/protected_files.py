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
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.protected_files"

_CP_MV_INSTALL_MIN_OPERANDS = 2  # need both <src> and <dst>

# Files that define security policy for all Claude Code sessions.
# Changes to these affect every repo and every agent.
PROTECTED_PATTERNS: list[str] = [
    "guard/hooks/bash_command_validator.py",
    "guard/hooks/git_c_validator.py",
    "guard/hooks/credential_check.py",
    "guard/hooks/protected_files.py",
    "guard/hooks/commit_message_validator.py",
    "guard/hooks/agent_output_guard.py",
    "guard/hooks/subagent_scope.py",
    "guard/registry.py",
    "guard/_utils.py",
    # Claude Code harness configuration — these are the ASK-gate that
    # decides whether guard hooks even fire. Edits must surface for review.
    ".claude/settings.json",
    ".claude/settings.local.json",
    # Compatibility patterns for users who installed earlier hook scripts
    # under ``~/.claude/hooks/`` rather than via the plugin layout.
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


# Bash redirect / file-write commands and their target-extracting regex / token
# index. Used by ``_bash_targets_protected`` as a best-effort second line of
# defense — the primary path is the Edit/Write tool guard above.
_BASH_REDIRECT_RE = re.compile(r"(?:^|\s)>>?\s*(\S+)")
_BASH_DD_OF_RE = re.compile(r"(?:^|\s)of=(\S+)")


def _bash_target_paths(command: str) -> list[str]:
    """Return likely write-target paths from a bash command.

    Best-effort: scans for output redirects (``>``, ``>>``), ``tee``,
    ``cp``, ``mv``, ``ln -sf``, ``install``, and ``dd of=`` targets.
    Used as a backup when an agent uses ``Bash`` to write to a protected
    path that the Edit/Write hooks would otherwise miss.
    """
    targets: list[str] = []
    targets.extend(_BASH_REDIRECT_RE.findall(command))
    targets.extend(_BASH_DD_OF_RE.findall(command))
    try:
        tokens = shlex.split(command)
    except ValueError:
        return targets
    if not tokens:
        return targets

    # Look for ``tee``, ``cp``, ``mv``, ``ln``, ``install`` anywhere in the
    # token stream — pipelines like ``echo x | tee /path`` mean the head
    # token isn't the writer. We don't try to be exhaustive about flags;
    # just skip past any ``-x``-shaped argument right after the verb.
    write_verbs = {"tee", "cp", "mv", "install", "ln"}
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        if head not in write_verbs:
            continue
        rest = tokens[i + 1 :]
        if head == "tee":
            targets.extend(t for t in rest if not t.startswith("-"))
        elif head in {"cp", "mv", "install"}:
            non_flag = [t for t in rest if not t.startswith("-")]
            if len(non_flag) >= _CP_MV_INSTALL_MIN_OPERANDS:
                targets.append(non_flag[-1])
        elif head == "ln":
            non_flag = [t for t in rest if not t.startswith("-")]
            if non_flag:
                targets.append(non_flag[-1])

    # In-place editors: ``sed -i``, ``perl -i`` / ``-pi`` / ``-Pi``,
    # ``awk -i inplace`` / ``gawk -i inplace``. Each rewrites its file
    # operands without going through redirect / cp shapes.
    targets.extend(_inplace_editor_targets(tokens))
    return targets


def _has_inplace_flag(flags: list[str]) -> bool:
    """Return True if any token in ``flags`` is or contains a ``-i`` form."""
    for f in flags:
        if not f.startswith("-") or f.startswith("--"):
            continue
        # Short-flag cluster like ``-pi``, ``-iE``, ``-i.bak``.
        body = f[1:].split(".", 1)[0]
        if "i" in body:
            return True
    return False


def _inplace_editor_targets(tokens: list[str]) -> list[str]:
    """Extract write targets from ``sed -i`` / ``perl -i`` / ``awk -i inplace``."""
    out: list[str] = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        if head == "sed" and _has_inplace_flag([t for t in rest if t.startswith("-")]):
            out.extend(t for t in rest if not t.startswith("-"))
        elif head == "perl" and _has_inplace_flag([t for t in rest if t.startswith("-")]):
            # perl: skip the `-e <script>` token after the script body
            non_flag = [t for t in rest if not t.startswith("-")]
            if non_flag:
                out.extend(non_flag[1:])  # drop the script body, keep file operands
        elif head in {"awk", "gawk"}:
            # gawk uses ``-i inplace`` (two tokens); skip the script body too
            for j, t in enumerate(rest[:-1]):
                if t == "-i" and rest[j + 1] == "inplace":
                    non_flag = [x for x in rest[j + 2 :] if not x.startswith("-")]
                    if non_flag:
                        out.extend(non_flag[1:])
                    break
    return out


def _bash_first_protected_match(command: str) -> str | None:
    """Return the first protected pattern matched by a bash write target."""
    for target in _bash_target_paths(command):
        matched = is_protected(target)
        if matched is not None:
            return matched
    return None


_FILE_PATH_TOOLS: frozenset[str] = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    matched: str | None = None
    excerpt = ""

    if tool_name in _FILE_PATH_TOOLS:
        # NotebookEdit uses ``notebook_path``; the others use ``file_path``.
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if not isinstance(file_path, str) or not file_path:
            return
        matched = is_protected(file_path)
        excerpt = file_path
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not command:
            return
        matched = _bash_first_protected_match(command)
        excerpt = command
    else:
        return

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
        command_excerpt=excerpt,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd if isinstance(cwd, str) else None,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
