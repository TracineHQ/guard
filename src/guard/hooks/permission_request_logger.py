# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PermissionRequest hook: observe permission prompts and log them.

Claude Code fires PermissionRequest when it is about to surface a permission
dialog to the user (interactive permission_modes only -- never in
``dontAsk`` / ``bypassPermissions``). This hook never blocks, never replies:
it appends a ``permission_request`` JSONL record so operators can see what
Claude Code prompted the user about, and exits 0 with empty stdout so the
prompt proceeds normally.

The decision-log gets a third record ``type`` (``decision``,
``internal_error``, and now ``permission_request``). Existing consumers that
ignore unknown ``type`` values continue to work; ``guard noisy`` joins on
``type`` to surface prompt-frequency alongside denies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from guard._utils import log_permission_request, safe_main
from guard.allowlist import load_allowlist


def hook(payload: dict[str, Any]) -> None:
    """Entry point for the PermissionRequest event; logs and returns without blocking."""
    tool_name = payload.get("tool_name", "")
    if not isinstance(tool_name, str) or not tool_name:
        return

    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    session_id = str(payload.get("session_id") or "")
    cwd_raw = payload.get("cwd")
    cwd = cwd_raw if isinstance(cwd_raw, str) else None
    permission_mode_raw = payload.get("permission_mode")
    permission_mode = permission_mode_raw if isinstance(permission_mode_raw, str) else None
    tool_use_id_raw = payload.get("tool_use_id")
    tool_use_id = tool_use_id_raw if isinstance(tool_use_id_raw, str) else None

    effective_mode = load_allowlist(Path(cwd) if cwd else None).mode
    # off: short-circuit. Don't write rows, don't compute anything.
    if effective_mode == "off":
        return

    log_permission_request(
        session_id=session_id,
        tool_name=tool_name,
        tool_input=tool_input,
        tool_use_id=tool_use_id,
        permission_mode=permission_mode,
        cwd=cwd,
        mode=effective_mode,
    )


if __name__ == "__main__":
    safe_main(hook)
