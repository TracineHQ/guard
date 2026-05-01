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


def _resolve_paths(file_path: str, cwd: str) -> tuple[str, str, bool]:
    """Return ``(abs_path, rel_path, inside_cwd)``.

    ``inside_cwd`` is ``True`` when ``abs_path`` is the same as ``cwd`` or a
    descendant of it. When ``False`` the file is somewhere else on disk and
    relative-path patterns must NOT match (closes the "endswith /pattern"
    bypass that matched anywhere on the filesystem).

    On any resolution error we fall back to the raw input strings and treat
    the path as outside cwd.
    """
    try:
        abs_path = str(Path(file_path).resolve())
    except (ValueError, OSError):
        abs_path = file_path
    try:
        cwd_resolved = str(Path(cwd).resolve())
    except (ValueError, OSError):
        cwd_resolved = cwd
    inside_cwd = False
    try:
        rel_path = str(Path(abs_path).relative_to(cwd_resolved))
        inside_cwd = True
    except ValueError:
        rel_path = abs_path
    return abs_path, rel_path, inside_cwd


def _matches_dir(pattern: str, rel_path: str, *, inside_cwd: bool) -> bool:
    """Recursive directory match for a trailing-slash pattern.

    Anchored against ``rel_path`` only when the file is inside cwd. Patterns
    that look like absolute paths (``/abs/dir/``) match the absolute form.
    """
    if pattern.startswith("/"):
        # Absolute pattern — match against absolute path is fine.
        return rel_path.startswith(pattern.lstrip("/")) if not inside_cwd else False
    if not inside_cwd:
        return False
    # Strip trailing slash for normalised comparison: "pkg/tests/" ~ "pkg/tests"
    base = pattern.rstrip("/")
    return rel_path == base or rel_path.startswith(base + "/")


def _matches_glob(pattern: str, abs_path: str, rel_path: str, *, inside_cwd: bool) -> bool:
    """Glob-match against the relative path only (when inside cwd).

    Absolute glob patterns (starting with ``/``) match the absolute path.
    """
    if pattern.startswith("/"):
        return fnmatch.fnmatch(abs_path, pattern)
    if not inside_cwd:
        return False
    return fnmatch.fnmatch(rel_path, pattern)


def _matches_plain(pattern: str, abs_path: str, rel_path: str, *, inside_cwd: bool) -> bool:
    """Plain-path match anchored to cwd.

    Strict matching: relative patterns must equal the relative path or be a
    directory ancestor of it. Absolute patterns match the absolute path
    exactly. (Earlier versions fell through to a filesystem-wide
    ``abs_path.endswith("/" + pattern)`` check, which is no longer used.)
    """
    if pattern.startswith("/"):
        return abs_path == pattern
    if not inside_cwd:
        return False
    return rel_path == pattern or rel_path.startswith(pattern + "/")


def _matches_pattern(pattern: str, abs_path: str, rel_path: str, *, inside_cwd: bool) -> bool:
    """Dispatch a single allowlist pattern against ``abs_path`` / ``rel_path``."""
    if pattern.endswith("/"):
        return _matches_dir(pattern, rel_path, inside_cwd=inside_cwd)
    if any(c in pattern for c in "*?["):
        return _matches_glob(pattern, abs_path, rel_path, inside_cwd=inside_cwd)
    return _matches_plain(pattern, abs_path, rel_path, inside_cwd=inside_cwd)


def is_allowed(file_path: str, cwd: str, allowed: list[Any]) -> bool:
    """Check if ``file_path`` matches any pattern in ``allowed``."""
    abs_path, rel_path, inside_cwd = _resolve_paths(file_path, cwd)
    return any(
        isinstance(pattern, str)
        and pattern
        and _matches_pattern(pattern, abs_path, rel_path, inside_cwd=inside_cwd)
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
    sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
