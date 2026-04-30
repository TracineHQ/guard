# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Disk-based storage for oversized tool responses."""

from __future__ import annotations

import json
import time

from guard._utils import (
    OUTPUT_RETENTION_HOURS,
    OUTPUT_STORE_DIR,
    OUTPUT_TRUNCATION_THRESHOLD,
)

PREVIEW_LENGTH = 200


def maybe_store_output(session_id: str, event_id: int, response: object) -> str | None:
    """Store oversized response to disk if it exceeds threshold.

    Returns summary message with file reference if stored, None otherwise.
    """
    if response is None:
        return None
    if not session_id or "/" in session_id or ".." in session_id:
        return None
    try:
        serialized = json.dumps(response)
    except (TypeError, ValueError):
        return None
    if len(serialized) < OUTPUT_TRUNCATION_THRESHOLD:
        return None
    try:
        session_dir = OUTPUT_STORE_DIR / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        output_file = session_dir / f"{event_id}.json"
        output_file.write_text(serialized)
    except OSError:
        return None
    preview = serialized[:PREVIEW_LENGTH]
    return f"[Truncated: {preview}...] Full output saved to {output_file}"


def cleanup_old_outputs() -> None:
    """Delete output directories older than ``OUTPUT_RETENTION_HOURS``."""
    try:
        if not OUTPUT_STORE_DIR.exists():
            return
        cutoff = time.time() - (OUTPUT_RETENTION_HOURS * 3600)
        for session_dir in OUTPUT_STORE_DIR.iterdir():
            if not session_dir.is_dir():
                continue
            try:
                if session_dir.stat().st_mtime < cutoff:
                    for f in session_dir.iterdir():
                        f.unlink(missing_ok=True)
                    session_dir.rmdir()
            except OSError:
                continue
    except OSError:
        pass
