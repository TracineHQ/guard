"""Project + global allowlist for guard rules and exact commands.

Two override knobs, both read from JSON files:

1. **disable_rules** — a list of ``rule_id`` strings (e.g.
   ``"bash.disk_destruction"``, ``"guard.protected_files"``). When a hook is
   about to deny / ask under one of these rule_ids, it falls through to
   allow instead. Useful when a matcher fires repeatedly on legitimate
   project workflows.
2. **allow_commands** — a list of ``{rule, command, reason}`` entries. When
   a deny/ask is about to fire under ``rule`` AND the original input string
   exactly equals ``command``, the decision is downgraded to allow. The
   ``reason`` is included in the audit-log record so every bypass is
   traceable to a written justification.

Resolution order:

- Global file at ``~/.claude/guard/allowlist.json`` (overridable via
  ``GUARD_DATA_DIR``).
- Project file at ``<cwd>/.claude/guard/allowlist.json``.

The two are merged into a single effective allowlist — both
``disable_rules`` are unioned and both ``allow_commands`` lists are
concatenated. Project entries are listed first so they're easy to spot in
``guard allowlist list`` output, but match priority is irrelevant: any
rule on either list disables, any matching command on either list allows.

Files are parsed with ``json.loads``; malformed top-level shape raises
``AllowlistError``. Individual entries that fail validation are dropped
with a warning emitted to stderr — the goal is to keep guard running even
if a user's allowlist is partially broken (the worst-case fallback is
"matcher fires", which is the safe direction).
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guard._utils import GUARD_HOME

PROJECT_ALLOWLIST_RELPATH = Path(".claude") / "guard" / "allowlist.json"


class AllowlistError(ValueError):
    """Raised when an allowlist file is structurally invalid (not a JSON object)."""


@dataclass(frozen=True)
class AllowEntry:
    """A single ``{rule, command, reason}`` allow_commands entry."""

    rule: str
    command: str
    reason: str
    source: str = "?"  # "global" / "project" / file path — for diagnostic display


@dataclass(frozen=True)
class Allowlist:
    """Effective merged allowlist (union of global and project entries)."""

    disable_rules: frozenset[str] = field(default_factory=frozenset)
    allow_commands: tuple[AllowEntry, ...] = ()
    sources: tuple[Path, ...] = ()  # files actually read (for diagnostics)

    def is_rule_disabled(self, rule_id: str) -> bool:
        """True if ``rule_id`` is in ``disable_rules``."""
        return rule_id in self.disable_rules

    def find_command(self, rule_id: str, command: str) -> AllowEntry | None:
        """Return the first ``allow_commands`` entry matching ``rule_id`` and exact ``command``.

        ``command`` is compared with exact string equality (after .strip() on
        both sides) — no canonicalisation, no brace expansion. The user
        opted into a specific command, not a shape.
        """
        cmd = command.strip()
        for e in self.allow_commands:
            if e.rule == rule_id and e.command.strip() == cmd:
                return e
        return None


def _validate_disable_rules(raw: Any, source: str) -> list[str]:  # noqa: ANN401 -- JSON value is genuinely Any
    if raw is None:
        return []
    if not isinstance(raw, list):
        _warn(f"{source}: 'disable_rules' must be a list of strings; ignoring")
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            out.append(item)
        else:
            _warn(f"{source}: skipping non-string disable_rules entry: {item!r}")
    return out


def _validate_allow_commands(raw: Any, source: str) -> list[AllowEntry]:  # noqa: ANN401 -- JSON value is genuinely Any
    if raw is None:
        return []
    if not isinstance(raw, list):
        _warn(f"{source}: 'allow_commands' must be a list of objects; ignoring")
        return []
    out: list[AllowEntry] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            _warn(f"{source}: allow_commands[{idx}] is not an object; skipping")
            continue
        rule = item.get("rule")
        command = item.get("command")
        reason = item.get("reason")
        if not isinstance(rule, str) or not rule:
            _warn(f"{source}: allow_commands[{idx}] missing 'rule'; skipping")
            continue
        if not isinstance(command, str) or not command:
            _warn(f"{source}: allow_commands[{idx}] missing 'command'; skipping")
            continue
        if not isinstance(reason, str) or not reason:
            _warn(f"{source}: allow_commands[{idx}] missing 'reason'; skipping")
            continue
        out.append(AllowEntry(rule=rule, command=command, reason=reason, source=source))
    return out


def _warn(msg: str) -> None:
    """Emit a single-line warning to stderr (best-effort, never raises)."""
    with contextlib.suppress(OSError):
        sys.stderr.write(f"guard: allowlist: {msg}\n")
        sys.stderr.flush()


def _load_one(path: Path, source_label: str) -> tuple[list[str], list[AllowEntry]]:
    """Parse one allowlist file. Returns ``([], [])`` if missing or unreadable."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        _warn(f"{path}: invalid JSON: {exc}; ignoring file")
        return [], []
    if not isinstance(data, dict):
        _warn(f"{path}: top-level must be an object; ignoring file")
        return [], []
    rules = _validate_disable_rules(data.get("disable_rules"), source_label)
    cmds = _validate_allow_commands(data.get("allow_commands"), source_label)
    return rules, cmds


def global_allowlist_path() -> Path:
    """Return the path of the global allowlist file (may not exist).

    Reads ``GUARD_DATA_DIR`` from the environment at call time so test
    fixtures that point it at a tmp dir post-import take effect (the
    module-level ``GUARD_HOME`` is fixed at import time and would
    otherwise cache the real ``~/.claude/guard``).
    """
    env_dir = os.environ.get("GUARD_DATA_DIR")
    base = Path(env_dir) if env_dir else GUARD_HOME
    return base / "allowlist.json"


def project_allowlist_path(cwd: Path | None = None) -> Path:
    """Return the path of the project allowlist file rooted at ``cwd`` (may not exist)."""
    base = cwd if cwd is not None else Path.cwd()
    return base / PROJECT_ALLOWLIST_RELPATH


def hook_bypass_reason(allowlist: Allowlist, hook_id: str, excerpt: str) -> str | None:
    """Return an audit-log ``reason`` string if the hook should bypass, else ``None``.

    Convenience helper for hooks whose only rule_id is the hook_id itself
    (e.g. ``protected_files``, ``git_c_validator``). For each such hook,
    two allowlist mechanisms apply:

    1. ``disable_rules: ["<hook_id>"]`` — mute the whole hook.
    2. ``allow_commands: [{rule: "<hook_id>", command: "...", reason: ...}]``
       — mute when the file path / command excerpt matches exactly.

    Callers log a ``decision="pass"`` record with the returned string and
    skip emitting an envelope, letting Claude Code default-allow.
    """
    if allowlist.is_rule_disabled(hook_id):
        return f"allowlist: rule '{hook_id}' disabled by user config"
    entry = allowlist.find_command(hook_id, excerpt)
    if entry is not None:
        return f"allowlist: {entry.reason} (rule={hook_id})"
    return None


def load_allowlist(cwd: Path | None = None) -> Allowlist:
    """Load and merge the global + project allowlists.

    Order in the returned ``allow_commands`` tuple: project entries first,
    then global entries, preserving file order within each. Match priority
    is irrelevant for correctness (find_command returns the first hit),
    but project-first keeps ``guard allowlist list`` predictable.

    Missing files are silently skipped. Malformed files emit a warning to
    stderr and contribute nothing.
    """
    sources: list[Path] = []
    project_path = project_allowlist_path(cwd)
    project_rules, project_cmds = _load_one(project_path, "project")
    if project_path.exists():
        sources.append(project_path)

    global_path = global_allowlist_path()
    global_rules, global_cmds = _load_one(global_path, "global")
    if global_path.exists():
        sources.append(global_path)

    return Allowlist(
        disable_rules=frozenset(project_rules) | frozenset(global_rules),
        allow_commands=(*project_cmds, *global_cmds),
        sources=tuple(sources),
    )
