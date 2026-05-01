# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: ask before touching known credential files.

When ``Edit``/``Write`` targets — or a ``Bash`` command references — a known
credential file (``~/.aws/credentials``, ``~/.ssh/id_*``, ``.env``, ``*.pem``,
``*.key``, etc.), emit an ``ask`` decision so the user can confirm intent
before the agent reads or modifies the file.

This module also exposes a permissions-audit utility
(``check_file_permissions`` / ``check_all``) for future diagnostic-CLI use.
The audit utility is independent of the hook entry point.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.credential_check"

# === Permissions-audit utility (used by the future diagnostic CLI) ===

CREDENTIAL_FILES: list[Path] = [
    Path.home() / ".claude" / "credentials" / "auth0.json",
    Path.home() / ".claude" / ".credentials.json",
]

MAX_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600

_GROUP_OTHER_MASK = (
    stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
)


def check_file_permissions(path: Path) -> tuple[bool, str]:
    """Check if a credential file has safe permissions.

    Args:
        path: Path to the credential file.

    Returns:
        ``(is_safe, message)`` — ``is_safe`` is True for missing files or
        files restricted to the owner; False if any group/other bit is set.
    """
    if not path.exists():
        return True, f"{path}: does not exist (ok)"

    mode = path.stat().st_mode
    file_perms = mode & 0o777

    if file_perms & _GROUP_OTHER_MASK:
        return (
            False,
            (
                f"{path}: permissions {oct(file_perms)} — "
                f"group/other access detected. Run: chmod 600 {path}"
            ),
        )

    return True, f"{path}: permissions {oct(file_perms)} (ok)"


def check_all() -> list[tuple[bool, str]]:
    """Check all known credential files."""
    return [check_file_permissions(p) for p in CREDENTIAL_FILES]


# === PreToolUse hook entry point ===

# Glob-like patterns indicating sensitive credential files. Matched against
# the file's absolute path (``~`` expanded).
_HOME = str(Path.home())

_CREDENTIAL_PATH_LITERALS: tuple[str, ...] = (
    f"{_HOME}/.aws/credentials",
    f"{_HOME}/.aws/config",
    f"{_HOME}/.netrc",
    f"{_HOME}/.config/gh/hosts.yml",
)

# Regex matching paths that look like credential material. Patterns:
# - ~/.ssh/id_<anything> (private keys)
# - any *.pem / *.key file
# - .env / .env.<suffix> at any directory depth
_CREDENTIAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"^{re.escape(_HOME)}/\.ssh/id_[A-Za-z0-9_]+(?:\.pub)?$"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"(?:^|/)\.env(?:\.[A-Za-z0-9_.-]+)?$"),
]

# Substrings to look for inside Bash commands. We scan command tokens for any
# of these to flag indirect access (cat ~/.aws/credentials etc.).
_BASH_CREDENTIAL_HINTS: tuple[str, ...] = (
    "/.aws/credentials",
    "/.aws/config",
    "/.netrc",
    "/.ssh/id_",
    ".pem",
    ".key",
    "/.config/gh/hosts.yml",
)

_ASK_REASON = (
    "Credential file access — confirm intent. "
    "Touching credential material (AWS/SSH/.env/*.pem/*.key/etc.) requires "
    "an explicit human OK so a misrouted edit can't leak secrets."
)


def _expand(path: str) -> str:
    """Expand ``~`` and resolve ``..`` segments lexically (no FS lookup)."""
    expanded = str(Path(path).expanduser())
    # normpath without resolving symlinks — we don't want filesystem-dependent
    # behaviour here; the goal is pure lexical match on user intent.
    try:
        return str(Path(expanded).resolve())
    except OSError:
        return expanded


def _path_is_credential(file_path: str) -> bool:
    """Return True if ``file_path`` resolves to a known credential file."""
    if not file_path:
        return False
    expanded = _expand(file_path)
    if expanded in _CREDENTIAL_PATH_LITERALS:
        return True
    return any(p.search(expanded) for p in _CREDENTIAL_PATH_PATTERNS)


def _bash_touches_credential(command: str) -> bool:
    """Return True if a bash command appears to reference a credential file."""
    if not command:
        return False
    expanded_command = command.replace("~", _HOME)
    return any(hint in expanded_command for hint in _BASH_CREDENTIAL_HINTS)


def decide(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any] | None:
    """Return an ``ask`` envelope when a credential file is being touched."""
    if tool_name in ("Edit", "Write"):
        file_path = tool_input.get("file_path", "")
        if isinstance(file_path, str) and _path_is_credential(file_path):
            return emit_pretooluse_decision("ask", _ASK_REASON)
        return None

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, str) and _bash_touches_credential(command):
            return emit_pretooluse_decision("ask", _ASK_REASON)
        return None

    return None


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if tool_name not in ("Edit", "Write", "Bash"):
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    envelope = decide(tool_name, tool_input)
    if envelope is None:
        return

    excerpt: str | None = None
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if isinstance(cmd, str):
            excerpt = cmd
    else:
        fp = tool_input.get("file_path", "")
        if isinstance(fp, str):
            excerpt = fp

    cwd = payload.get("cwd")
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name,
        decision="ask",
        reason=_ASK_REASON,
        command_excerpt=excerpt,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd if isinstance(cwd, str) else None,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
