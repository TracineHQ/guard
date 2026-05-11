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

# Bash matcher rule_ids — fine-grained, one per matcher function. Keep in
# sync with the matchers in ``bash_command_validator.py``. The whole-hook
# rule_ids of the other hooks are appended below from
# ``hook_registry.disable_hook_ids()`` so there's exactly one place that
# enumerates hook ids — the registry.
_BASH_MATCHER_RULE_IDS: tuple[str, ...] = (
    # Bash: ALWAYS_DENY layer (coarse).
    "bash.always_deny",
    # Bash: synthetic matchers (fine-grained, one per matcher func).
    "bash.aws_destructive",
    "bash.aws_s3_destructive",
    "bash.az_destructive",
    "bash.cargo_remote_install",
    "bash.chmod_dangerous",
    "bash.chmod_sensitive_target",
    "bash.chmod_setuid",
    "bash.credential_leak",
    "bash.dangerous_env_sink",
    "bash.dangerous_interpreter",
    "bash.dangerous_rm",
    "bash.db_cli_destructive",
    "bash.disk_destruction",
    "bash.dns_exfil",
    "bash.dropdb_or_mysqladmin",
    "bash.env_split_string",
    "bash.eval_builtin",
    "bash.exec_wrapper",
    "bash.function_definition",
    "bash.gcloud_destructive",
    "bash.gem_remote_install",
    "bash.gh_api_destructive",
    "bash.git_config_injection",
    "bash.git_force_refspec",
    "bash.git_submodule_add",
    "bash.git_worktree_add",
    "bash.glob_head",
    "bash.go_remote_install",
    "bash.gpg_secret_delete",
    "bash.helm_remote_install",
    "bash.iac_destruction",
    "bash.kernel_module_load",
    "bash.kubectl_destructive",
    "bash.mongo_destructive",
    "bash.network_policy_wipe",
    "bash.npm_url_install",
    "bash.npx_remote",
    "bash.persistence",
    "bash.pip_install_url",
    "bash.pipe_to_interpreter",
    "bash.process_attach",
    "bash.remote_shell_wrapper",
    "bash.sensitive_write",
    "bash.shell_wrapper",
    "bash.sudo_escalation",
    "bash.trap_exploit",
    "bash.var_expanded_head",
    "bash.wrapper_stacking",
)


def _build_known_rule_ids() -> tuple[str, ...]:
    """Bash matcher ids + whole-hook disable ids, in stable display order."""
    # Local import to avoid a load-order cycle: hooks import this module for
    # ``hook_bypass_reason`` / ``load_allowlist``; the registry doesn't,
    # but importing it at module load would still surface as
    # ``allowlist -> hook_registry -> guard.hooks.<x>`` if anyone ever
    # extended the registry to do eager imports.
    from guard.hooks._registry import disable_hook_ids  # noqa: PLC0415

    return _BASH_MATCHER_RULE_IDS + disable_hook_ids()


# All known rule_ids users can put on ``disable_rules`` / ``allow_commands.rule``.
# Sourced from the bash matcher list above plus the registry's whole-hook
# disable ids. Sorted for deterministic CLI output.
KNOWN_RULE_IDS: tuple[str, ...] = _build_known_rule_ids()


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


# === Mutation API (CLI helpers) ===
#
# Each mutation reads the file, edits in-memory, writes back atomically. The
# format is human-friendly: 2-space indent, sorted keys at the top level,
# trailing newline. Files don't have to exist before mutation — they're
# created on first add. Empty after a remove? We leave the empty document
# rather than delete the file so users can git-track its presence.


_ALLOWLIST_FILE_TEMPLATE: dict[str, list[Any]] = {
    "disable_rules": [],
    "allow_commands": [],
}


def _read_raw(path: Path) -> dict[str, Any]:
    """Read+parse an allowlist file. Returns an empty template if absent."""
    if not path.exists():
        return {"disable_rules": [], "allow_commands": []}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {"disable_rules": [], "allow_commands": []}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {"disable_rules": [], "allow_commands": []}
    if not isinstance(data, dict):
        return {"disable_rules": [], "allow_commands": []}
    rules = data.get("disable_rules") or []
    cmds = data.get("allow_commands") or []
    return {
        "disable_rules": list(rules) if isinstance(rules, list) else [],
        "allow_commands": list(cmds) if isinstance(cmds, list) else [],
    }


def _write_raw(path: Path, doc: dict[str, Any]) -> None:
    """Atomically write the doc with mode 0o600 inside a 0o700 parent dir."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def add_disable_rule(rule_id: str, *, scope: str = "project", cwd: Path | None = None) -> bool:
    """Add ``rule_id`` to the chosen scope's ``disable_rules``.

    Returns ``True`` if the rule was added, ``False`` if it was already
    present (idempotent).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id in rules:
        return False
    rules.append(rule_id)
    _write_raw(path, doc)
    return True


def remove_disable_rule(rule_id: str, *, scope: str = "project", cwd: Path | None = None) -> bool:
    """Remove ``rule_id`` from the chosen scope's ``disable_rules``.

    Returns ``True`` if the rule was removed, ``False`` if it wasn't
    present (idempotent).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id not in rules:
        return False
    doc["disable_rules"] = [r for r in rules if r != rule_id]
    _write_raw(path, doc)
    return True


def add_allow_command(
    *,
    rule: str,
    command: str,
    reason: str,
    scope: str = "project",
    cwd: Path | None = None,
) -> bool:
    """Add an exact-command override to the chosen scope's ``allow_commands``.

    Returns ``True`` if added, ``False`` if an entry with the same
    ``(rule, command)`` already exists (idempotent — does not update the
    reason; remove first to change a reason).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    cmds: list[Any] = doc["allow_commands"]
    for e in cmds:
        if isinstance(e, dict) and e.get("rule") == rule and e.get("command") == command:
            return False
    cmds.append({"rule": rule, "command": command, "reason": reason})
    _write_raw(path, doc)
    return True


def remove_allow_command(
    *,
    rule: str,
    command: str,
    scope: str = "project",
    cwd: Path | None = None,
) -> bool:
    """Remove an exact-command override matching ``(rule, command)``.

    Returns ``True`` if removed, ``False`` if no matching entry was found.
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    cmds: list[Any] = doc["allow_commands"]
    new = [
        e
        for e in cmds
        if not (isinstance(e, dict) and e.get("rule") == rule and e.get("command") == command)
    ]
    if len(new) == len(cmds):
        return False
    doc["allow_commands"] = new
    _write_raw(path, doc)
    return True


def _resolve_scope_path(scope: str, cwd: Path | None) -> Path:
    if scope == "global":
        return global_allowlist_path()
    if scope == "project":
        return project_allowlist_path(cwd)
    msg = f"unknown scope {scope!r} (expected 'global' or 'project')"
    raise ValueError(msg)


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
