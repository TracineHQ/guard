# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: enforce file-level scope on Edit/Write.

When ``<cwd>/.claude/subagent-scope.json`` is present with schema::

    {
      "task": "Task 2.1: ...",
      "allowed": ["pkg/src/pkg/stats.py", "pkg/tests/test_*.py", "pkg/tests/"]
    }

any ``Edit`` or ``Write`` whose target ``file_path`` does not match an entry
in ``allowed`` is denied. Missing or malformed scope files cause silent
passthrough so hook errors never block work.

Pattern semantics:

- Trailing slash (``pkg/tests/``) → recursive directory match.
- Glob chars (``*``, ``?``, ``[``) → ``fnmatch`` against the relative path.
- Plain path → exact suffix match anchored on a ``/`` boundary.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.subagent_scope"


def load_scope(cwd: str) -> dict[str, Any] | None:
    """Return the parsed scope dict, or ``None`` if absent/invalid."""
    if not cwd:
        return None
    scope_path = Path(cwd) / ".claude" / "subagent-scope.json"
    if not scope_path.exists():
        return None
    try:
        data = json.loads(scope_path.read_text())
    except (json.JSONDecodeError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    allowed = data.get("allowed")
    if not isinstance(allowed, list):
        return None
    return data


def _resolve_paths(file_path: str, cwd: str) -> tuple[str, str]:
    """Return ``(abs_path, rel_path)``. ``rel_path`` falls back to ``abs_path``."""
    try:
        abs_path = str(Path(file_path).resolve())
    except (ValueError, OSError):
        abs_path = file_path
    try:
        cwd_resolved = str(Path(cwd).resolve())
    except (ValueError, OSError):
        cwd_resolved = cwd
    try:
        rel_path = str(Path(abs_path).relative_to(cwd_resolved))
    except ValueError:
        rel_path = abs_path
    return abs_path, rel_path


def _matches_dir(pattern: str, abs_path: str, rel_path: str) -> bool:
    """Recursive directory match for a trailing-slash pattern."""
    return (
        rel_path.startswith(pattern)
        or f"/{pattern}" in f"/{rel_path}/"
        or f"/{pattern}" in f"{abs_path}/"
    )


def _matches_glob(pattern: str, abs_path: str, rel_path: str) -> bool:
    """Glob-match against the relative path, falling back to absolute path."""
    return fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(abs_path, f"*/{pattern}")


def _matches_plain(pattern: str, abs_path: str, rel_path: str) -> bool:
    """Exact suffix match on a ``/``-boundary."""
    return rel_path == pattern or abs_path.endswith(f"/{pattern}")


def _matches_pattern(pattern: str, abs_path: str, rel_path: str) -> bool:
    """Dispatch a single allowlist pattern against ``abs_path`` / ``rel_path``."""
    if pattern.endswith("/"):
        return _matches_dir(pattern, abs_path, rel_path)
    if any(c in pattern for c in "*?["):
        return _matches_glob(pattern, abs_path, rel_path)
    return _matches_plain(pattern, abs_path, rel_path)


def is_allowed(file_path: str, cwd: str, allowed: list[Any]) -> bool:
    """Check if ``file_path`` matches any pattern in ``allowed``."""
    abs_path, rel_path = _resolve_paths(file_path, cwd)
    return any(
        isinstance(pattern, str) and pattern and _matches_pattern(pattern, abs_path, rel_path)
        for pattern in allowed
    )


def _extract_file_and_cwd(payload: dict[str, Any]) -> tuple[str, str] | None:
    """Return ``(file_path, cwd)`` if both present and well-typed, else ``None``."""
    if payload.get("tool_name") not in ("Edit", "Write"):
        return None

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return None
    file_path = tool_input.get("file_path", "")
    cwd = payload.get("cwd", "")
    if not isinstance(file_path, str) or not file_path:
        return None
    if not isinstance(cwd, str) or not cwd:
        return None
    return file_path, cwd


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    parsed = _extract_file_and_cwd(payload)
    if parsed is None:
        return
    file_path, cwd = parsed

    scope = load_scope(cwd)
    if scope is None:
        return

    allowed_raw = scope.get("allowed", [])
    if not isinstance(allowed_raw, list) or is_allowed(file_path, cwd, allowed_raw):
        return

    task = scope.get("task", "current task")
    allowed_list = "\n".join(f"  - {p}" for p in allowed_raw if isinstance(p, str))
    reason = (
        f"Out of scope for {task}. This file is not in the allowed list.\n"
        f"Allowed files/patterns:\n{allowed_list}\n"
        f"If you need to modify other files, the task scope needs updating."
    )
    envelope = emit_pretooluse_decision("deny", reason)
    tool_name = payload.get("tool_name", "")
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name if isinstance(tool_name, str) else None,
        decision="deny",
        reason=reason,
        command_excerpt=file_path,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
