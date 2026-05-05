"""Render a plain-text status report for the guard installation.

The ``guard --status`` command (``python -m guard status``) is an information-only
tool. Every step is wrapped to fail open with a partial report rather than
crash, and the caller always exits 0.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guard import __version__

KNOWN_ENV_VARS = (
    "CLAUDE_AUTONOMOUS",
    "GUARD_DECISIONS_PATH",
    "GUARD_AUTONOMOUS_QUEUE_PATH",
    "GUARD_DEBUG",
    "GUARD_DATA_DIR",
)

DEFAULT_DECISIONS_PATH = str(Path("~/.claude/guard-decisions.jsonl").expanduser())

INSTALL_HINT = "No hooks wired up - run `/plugin install guard@TracineHQ` in Claude Code."


def _hooks_dir() -> Path:
    """Return the directory containing shipped hook modules."""
    return Path(__file__).parent / "hooks"


def _list_known_hooks() -> list[str]:
    """Return the sorted list of guard.hooks.<name> modules shipped with the package."""
    try:
        hooks_dir = _hooks_dir()
        return sorted(
            p.stem
            for p in hooks_dir.glob("*.py")
            if p.stem != "__init__" and not p.stem.startswith("_")
        )
    except OSError:
        return []


def _settings_paths() -> list[Path]:
    """Return candidate settings.json paths, in priority order."""
    paths = [Path.home() / ".claude" / "settings.json"]
    cwd_settings = Path.cwd() / ".claude" / "settings.json"
    if cwd_settings.exists():
        paths.append(cwd_settings)
    return paths


def _read_settings(path: Path) -> dict[str, Any] | None:
    """Read and parse a settings.json file, returning None on any failure."""
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _discover_wired_hooks(settings_files: list[Path]) -> list[tuple[str, str, str]]:
    """Walk PreToolUse entries and pull out (hook_name, matcher, source_file).

    Looks for ``guard.hooks.<NAME>`` (importable) or
    ``guard/hooks/<NAME>.py`` (module path) in each command string.
    """
    found: list[tuple[str, str, str]] = []
    for settings_path in settings_files:
        data = _read_settings(settings_path)
        if data is None:
            continue
        try:
            pretooluse = data.get("hooks", {}).get("PreToolUse", [])
        except AttributeError:
            continue
        if not isinstance(pretooluse, list):
            continue
        for entry in pretooluse:
            if not isinstance(entry, dict):
                continue
            matcher = str(entry.get("matcher", ""))
            for hk in entry.get("hooks", []) or []:
                if not isinstance(hk, dict):
                    continue
                cmd = str(hk.get("command", ""))
                name = _extract_hook_name(cmd)
                if name:
                    found.append((name, matcher, str(settings_path)))
    return found


def _take_identifier(text: str) -> str:
    """Take a leading identifier (alnum + underscore) from text."""
    out = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            break
    return "".join(out)


def _extract_hook_name(cmd: str) -> str | None:
    """Pull out the hook NAME from a command string, if any.

    Recognises the plugin form (``guard.hooks.NAME`` /
    ``guard/hooks/NAME.py``) and the legacy hand-installed form
    (``~/.claude/hooks/NAME.py``) when NAME matches a shipped guard hook.
    """
    for marker in ("guard.hooks.", "guard/hooks/"):
        idx = cmd.find(marker)
        if idx < 0:
            continue
        rest = cmd[idx + len(marker) :].removesuffix(".py")
        name = _take_identifier(rest)
        if name:
            return name
    # Legacy form: any /hooks/NAME.py where NAME is a known guard hook
    legacy_marker = "/hooks/"
    idx = cmd.rfind(legacy_marker)
    if idx >= 0:
        rest = cmd[idx + len(legacy_marker) :].removesuffix(".py")
        name = _take_identifier(rest)
        if name and name in set(_list_known_hooks()):
            return name
    return None


def _format_log_section(decisions_path: str) -> list[str]:
    """Build the JSONL log section lines."""
    lines = [f"Decision log: {decisions_path}"]
    try:
        path = Path(decisions_path)
        if not path.exists():
            lines.append("  (file does not exist yet)")
            return lines
        stat = path.stat()
        size = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(timespec="seconds")
        lines.append(f"  exists: yes  size: {size} bytes  modified: {mtime}")
    except OSError as exc:
        lines.append(f"  (could not stat: {exc})")
    return lines


def _format_recent_decisions(decisions_path: str, limit: int = 3) -> list[str]:
    """Tail the JSONL log and render the last ``limit`` decisions."""
    lines = ["Recent decisions:"]
    try:
        path = Path(decisions_path)
        if not path.exists():
            lines.append("  No decisions logged yet.")
            return lines
        with path.open(encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-limit:]
    except OSError as exc:
        lines.append(f"  (could not read log: {exc})")
        return lines
    if not tail:
        lines.append("  No decisions logged yet.")
        return lines
    for raw in tail:
        try:
            rec = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            lines.append(f"  (unparsable line) {raw.strip()[:80]}")
            continue
        ts = str(rec.get("timestamp", "?"))
        decision = str(rec.get("decision", "?"))
        hook_id = str(rec.get("hook_id", "?"))
        reason = str(rec.get("reason", ""))[:80]
        lines.append(f"  {ts} {decision} {hook_id}: {reason}")
    return lines


def _format_hooks_section(known: list[str], wired: list[tuple[str, str, str]]) -> list[str]:
    """Render the hook discovery section."""
    wired_names = {name for name, _matcher, _src in wired}
    lines = ["Known hooks:"]
    for name in known:
        marker = "[wired]" if name in wired_names else "[not wired]"
        lines.append(f"  {marker} {name}")
    if wired:
        lines.append("")
        lines.append("Wired entries (from settings.json):")
        for name, matcher, src in wired:
            lines.append(f"  - {name}  matcher={matcher!r}  source={src}")
    return lines


def _format_env_section() -> list[str]:
    """Render the env-vars-in-effect section."""
    lines = ["Environment:"]
    for var in KNOWN_ENV_VARS:
        val = os.environ.get(var)
        lines.append(f"  {var}={val!r}" if val is not None else f"  {var}=(unset)")
    return lines


def render_status() -> str:
    """Build the full plain-text status report.

    Defensive at every step: each section is wrapped so a failure produces a
    short diagnostic line rather than aborting the whole report. The caller
    is expected to always exit 0.
    """
    out: list[str] = [f"guard {__version__}", ""]

    decisions_path = os.environ.get("GUARD_DECISIONS_PATH", DEFAULT_DECISIONS_PATH)

    try:
        out.extend(_format_log_section(decisions_path))
    except Exception as exc:  # noqa: BLE001 -- defensive: status must not crash
        out.append(f"  (log section failed: {exc})")
    out.append("")

    settings_paths = _settings_paths()
    existing_settings = [p for p in settings_paths if p.exists()]
    try:
        wired = _discover_wired_hooks(existing_settings)
    except Exception as exc:  # noqa: BLE001 -- defensive
        wired = []
        out.append(f"(hook discovery failed: {exc})")

    if not existing_settings or not wired:
        out.append(INSTALL_HINT)
        out.append("")

    try:
        known = _list_known_hooks()
        out.extend(_format_hooks_section(known, wired))
    except Exception as exc:  # noqa: BLE001 -- defensive
        out.append(f"(hook listing failed: {exc})")
    out.append("")

    try:
        out.extend(_format_recent_decisions(decisions_path))
    except Exception as exc:  # noqa: BLE001 -- defensive
        out.append(f"(recent decisions failed: {exc})")
    out.append("")

    try:
        out.extend(_format_env_section())
    except Exception as exc:  # noqa: BLE001 -- defensive
        out.append(f"(env section failed: {exc})")

    return "\n".join(out) + "\n"
