"""Guard's global config: the mode and the rules the user turned off.

One JSON file, ``~/.claude/guard/allowlist.json`` (overridable via
``GUARD_DATA_DIR``), with two keys:

1. **mode**: ``enforce`` (default), ``shadow``, ``off`` or ``lockdown``.
2. **disable_rules**: a list of ``rule_id`` strings (e.g.
   ``"bash.disk_destruction"``, ``"guard.protected_files"``). When a hook is
   about to deny under one of these rule_ids, it falls through to allow
   instead.

The file keeps its old name and stays part of guard's trust root, so agents
can't write it.

Retired: ``allow_commands`` (exact-command exemptions) and project files at
``<cwd>/.claude/guard/allowlist.json``. Guard ignores both and says so once
per process on stderr.

The file is parsed with ``json.loads``; malformed JSON or a non-object
top-level shape is logged as a stderr warning and the file is ignored.
Individual entries that fail validation are dropped with a warning; the
worst-case fallback is "matcher fires", which is the safe direction.
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
from typing import Any, Literal, cast

from guard._utils import GUARD_HOME, log_decision, read_permission_mode, sanitize_for_stderr
from guard.registry import auto_pass_reason, is_deferred_to_auto

# ``lockdown`` is ``enforce`` plus strict default-deny for bash and the
# extended protected-file list. It is opt-in only: Claude Code's
# ``permission_mode`` never switches it on.
Mode = Literal["enforce", "shadow", "off", "lockdown"]
_VALID_MODES: frozenset[str] = frozenset(("enforce", "shadow", "off", "lockdown"))
_DEFAULT_MODE: Mode = "enforce"

# Where project allowlists used to live. Only looked at to warn that they're ignored.
_RETIRED_PROJECT_RELPATH = Path(".claude") / "guard" / "allowlist.json"

# Bash matcher rule_ids — fine-grained, one per matcher function. Keep in
# sync with the matchers in ``bash_command_validator.py``. The whole-hook
# rule_ids of the other hooks are appended below from
# ``hook_registry.disable_hook_ids()`` so there's exactly one place that
# enumerates hook ids — the registry.
_BASH_MATCHER_RULE_IDS: tuple[str, ...] = (
    # Bash: ALWAYS_DENY layer (coarse).
    "bash.always_deny",
    # Bash: synthetic matchers (fine-grained, one per matcher func).
    "bash.admin_default_deny",
    "bash.admin_forbidden_flag",
    "bash.admin_forbidden_subcommand",
    "bash.admin_sensitive_env_override",
    "bash.admin_unknown_flag_strict",
    "bash.aws_destructive",
    "bash.aws_s3_destructive",
    "bash.az_destructive",
    "bash.cargo_remote_install",
    "bash.chmod_dangerous",
    "bash.chmod_sensitive_target",
    "bash.chmod_setuid",
    "bash.command_too_long",
    "bash.conditional_denied_flag",
    "bash.credential_leak",
    "bash.dangerous_construct",
    "bash.dangerous_env_sink",
    "bash.dangerous_interpreter",
    "bash.dangerous_rm",
    "bash.db_cli_destructive",
    "bash.disk_destruction",
    "bash.dns_exfil",
    "bash.dropdb_or_mysqladmin",
    "bash.env_split_string",
    "bash.escalation_shell",
    "bash.eval_builtin",
    "bash.exec_wrapper",
    "bash.fs_attr_sensitive",
    "bash.function_definition",
    "bash.gcloud_destructive",
    "bash.gem_remote_install",
    "bash.gh_api_destructive",
    "bash.git_config_injection",
    "bash.git_force_push",
    "bash.git_read_exec",
    "bash.git_ref_mutation",
    "bash.git_force_refspec",
    "bash.git_submodule_add",
    "bash.git_worktree_add",
    "bash.glob_head",
    "bash.go_remote_install",
    "bash.gpg_secret_delete",
    "bash.helm_remote_install",
    "bash.host_control",
    "bash.iac_destruction",
    "bash.kernel_module_load",
    "bash.kubectl_destructive",
    "bash.mongo_destructive",
    "bash.network_policy_wipe",
    "bash.npm_url_install",
    "bash.npx_remote",
    "bash.persistence",
    "bash.pip_install_url",
    "bash.process_attach",
    "bash.process_tree_kill",
    "bash.registry_config",
    "bash.remote_shell_wrapper",
    "bash.secret_egress",
    "bash.secret_value",
    "bash.sensitive_write",
    "bash.shell_wrapper",
    "bash.strict_default_deny",
    "bash.strict_feedback",
    "bash.sudo_escalation",
    "bash.tool_alternative",
    "bash.trap_exploit",
    "bash.use_corpus_harness",
    "bash.var_expanded_head",
    "bash.wrapper_stacking",
)


def _build_known_rule_ids() -> tuple[str, ...]:
    """Bash matcher ids + whole-hook disable ids, in registration order."""
    # Local import to avoid a load-order cycle: hooks import this module for
    # ``apply_decision`` / ``load_allowlist``; the registry doesn't,
    # but importing it at module load would still surface as
    # ``allowlist -> guard.hooks._registry -> guard.hooks.<x>`` if anyone
    # ever extended the registry to do eager imports.
    from guard.hooks._registry import disable_hook_ids  # noqa: PLC0415 -- lazy: avoid cycle

    return _BASH_MATCHER_RULE_IDS + disable_hook_ids()


# All known rule_ids users can put on ``disable_rules``. Sourced from the
# bash matcher list above plus the registry's whole-hook disable ids. Order
# is bash-matcher declaration order followed by registry-order whole-hook
# ids, stable across runs given the same source.
KNOWN_RULE_IDS: tuple[str, ...] = _build_known_rule_ids()


@dataclass(frozen=True)
class Allowlist:
    """Effective config read from the global file."""

    disable_rules: frozenset[str] = field(default_factory=frozenset)
    sources: tuple[Path, ...] = ()  # files actually read (for diagnostics)
    mode: Mode = _DEFAULT_MODE  # enforce | shadow | off | lockdown

    def is_rule_disabled(self, rule_id: str) -> bool:
        """True if ``rule_id`` is in ``disable_rules``."""
        return rule_id in self.disable_rules


def _validate_mode(raw: Any, source: str) -> Mode | None:  # noqa: ANN401 -- JSON value is genuinely Any
    """Return a valid Mode or None (None means "key absent / invalid; skip")."""
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in _VALID_MODES:
        _warn(f"{source}: 'mode' must be one of {sorted(_VALID_MODES)}; ignoring (got {raw!r})")
        return None
    return cast("Mode", raw)


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


def _warn(msg: str) -> None:
    """Emit a single-line warning to stderr (best-effort, never raises)."""
    with contextlib.suppress(OSError):
        sys.stderr.write(f"guard: allowlist: {msg}\n")
        sys.stderr.flush()


# One stderr line per retired note per process: several hooks call
# ``load_allowlist`` more than once per run.
_WARNED_RETIRED: set[str] = set()


def _warn_retired(note: str) -> None:
    if note in _WARNED_RETIRED:
        return
    _WARNED_RETIRED.add(note)
    _warn(f"{note} is retired and ignored; see guard's CHANGELOG")


def _load_global(path: Path) -> tuple[list[str], Mode | None, bool]:
    """Parse the global file: ``(disable_rules, mode, has allow_commands)``.

    Returns ``([], None, False)`` if missing or unreadable.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], None, False
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        _warn(f"{path}: invalid JSON: {exc}; ignoring file")
        return [], None, False
    if not isinstance(data, dict):
        _warn(f"{path}: top-level must be an object; ignoring file")
        return [], None, False
    rules = _validate_disable_rules(data.get("disable_rules"), "global")
    mode = _validate_mode(data.get("mode"), "global")
    return rules, mode, "allow_commands" in data


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


def retired_project_file(cwd: Path | None = None) -> Path | None:
    """Return the retired project allowlist under ``cwd`` if one exists, else None."""
    path = (cwd if cwd is not None else Path.cwd()) / _RETIRED_PROJECT_RELPATH
    if not path.is_file():
        return None
    try:
        if path.samefile(global_allowlist_path()):
            return None  # with cwd = HOME the project path is the global file itself
    except OSError:
        pass
    return path


def hook_bypass_reason(allowlist: Allowlist, hook_id: str) -> str | None:
    """Return an audit-log ``reason`` if ``hook_id`` is in ``disable_rules``, else ``None``.

    For hooks whose only rule_id is the hook_id itself (e.g.
    ``protected_files``, ``git_c_validator``). Callers log a
    ``decision="pass"`` record with the returned string and skip emitting an
    envelope, letting Claude Code default-allow.
    """
    if allowlist.is_rule_disabled(hook_id):
        return f"allowlist: rule '{hook_id}' disabled by user config"
    return None


def apply_decision(  # noqa: PLR0913 -- hook id, payload, envelope, excerpt + policy flags
    hook_id: str,
    payload: dict[str, Any],
    envelope: dict[str, Any],
    excerpt: str,
    *,
    trust_root: bool = False,
    overridable: bool = True,
    rule: str | None = None,
) -> None:
    """Log a hook's decision and hand it to Claude Code, honoring guard mode.

    ``off`` emits nothing and ``shadow`` logs a deny without emitting it,
    except for ``trust_root`` decisions (guard's own files), which hold in
    every mode. ``hook_id`` in ``disable_rules`` turns the decision into a
    logged pass unless ``overridable`` is False. In Claude Code's ``auto``
    permission mode (outside lockdown) a deny whose tier key (``rule``, else
    ``hook_id``) is a STEER rule becomes a logged pass with no output; FLOOR
    denies are unchanged. A deny exits 2.
    """
    allowlist = load_allowlist()
    hso = envelope["hookSpecificOutput"]
    decision = hso["permissionDecision"]
    if allowlist.mode == "off" and not trust_root:
        return
    tool_name = payload.get("tool_name")
    cwd = payload.get("cwd")
    permission_mode = read_permission_mode(payload)
    record: dict[str, Any] = {
        "hook_id": hook_id,
        "event": "PreToolUse",
        "tool_name": tool_name if isinstance(tool_name, str) else None,
        "command_excerpt": excerpt,
        "session_id": str(payload.get("session_id", "")),
        "cwd": cwd if isinstance(cwd, str) else None,
        "permission_mode": permission_mode,
        "mode": allowlist.mode,
    }
    bypass = hook_bypass_reason(allowlist, hook_id) if overridable else None
    if bypass is not None:
        log_decision(decision="pass", reason=bypass, **record)
        return
    tier_key = rule or hook_id
    if decision == "deny" and is_deferred_to_auto(
        tier_key, permission_mode, lockdown=allowlist.mode == "lockdown"
    ):
        log_decision(decision="pass", reason=auto_pass_reason(tier_key), **record)
        return
    log_decision(decision=decision, reason=hso["permissionDecisionReason"], **record)
    if decision == "deny" and allowlist.mode == "shadow" and not trust_root:
        return
    sys.stdout.write(json.dumps(envelope))
    if decision == "deny":
        sys.exit(2)


# === Mutation API (CLI helpers) ===
#
# Each mutation reads the global file, edits in-memory, writes back
# atomically. The format is human-friendly: 2-space indent, trailing
# newline. The file doesn't have to exist before mutation; it's created on
# first write. Keys guard doesn't manage are passed through untouched.


def _read_raw(path: Path) -> dict[str, Any]:
    """Read+parse the global file. Returns an empty template if absent or unreadable.

    Only ``disable_rules`` is normalised; every other top-level field is
    passed through verbatim so a mutation doesn't strip ``mode``.
    """
    empty: dict[str, Any] = {"disable_rules": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    rules = data.get("disable_rules") or []
    doc = dict(data)
    doc["disable_rules"] = list(rules) if isinstance(rules, list) else []
    return doc


def _write_raw(path: Path, doc: dict[str, Any]) -> None:
    """Atomically write the doc with mode 0o600 inside a 0o700 parent dir."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def add_disable_rule(rule_id: str) -> bool:
    """Add ``rule_id`` to the global ``disable_rules``.

    Returns ``True`` if the rule was added, ``False`` if it was already
    present (idempotent).
    """
    path = global_allowlist_path()
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id in rules:
        return False
    rules.append(rule_id)
    _write_raw(path, doc)
    return True


def remove_disable_rule(rule_id: str) -> bool:
    """Remove ``rule_id`` from the global ``disable_rules``.

    Returns ``True`` if the rule was removed, ``False`` if it wasn't
    present (idempotent).
    """
    path = global_allowlist_path()
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id not in rules:
        return False
    doc["disable_rules"] = [r for r in rules if r != rule_id]
    _write_raw(path, doc)
    return True


def set_mode(value: Mode) -> Mode | None:
    """Write ``mode`` to the global file.

    Returns the previous mode value (``None`` if absent / default).
    """
    path = global_allowlist_path()
    doc = _read_raw(path)
    previous = doc.get("mode")
    prev_validated = _validate_mode(previous, "global") if previous is not None else None
    doc["mode"] = value
    _write_raw(path, doc)
    return prev_validated


def load_allowlist(cwd: Path | None = None) -> Allowlist:
    """Load the global file.

    A missing file means defaults. A malformed one emits a warning to stderr
    and contributes nothing. ``cwd`` is only checked for a retired project
    file, which is reported once per process and otherwise ignored, like
    ``allow_commands`` in the global file.
    """
    global_path = global_allowlist_path()
    rules, mode, has_allow_commands = _load_global(global_path)
    if has_allow_commands:
        _warn_retired(f"allow_commands in {sanitize_for_stderr(str(global_path), max_len=400)}")
    project = retired_project_file(cwd)
    if project is not None:
        _warn_retired(f"project allowlist {sanitize_for_stderr(str(project), max_len=400)}")
    return Allowlist(
        disable_rules=frozenset(rules),
        sources=(global_path,) if global_path.exists() else (),
        mode=mode or _DEFAULT_MODE,
    )
