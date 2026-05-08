"""Stdlib-only ``guard`` CLI — read-side queries against the JSONL log.

Subcommands:

- ``guard status`` — effective config, log location, line count, last record.
- ``guard noisy [--since 7d] [--limit 10]`` — top N hit rules grouped by
  ``(hook_id, decision)``.
- ``guard silent [--since 30d]`` — rules that haven't fired in N days,
  cross-referenced against the full set of (hook_id, decision) pairs ever
  seen in the log.
- ``guard trace <session-id>`` — every record for a single session,
  chronological.
- ``guard test "<command>"`` — invokes ``decide()`` on each relevant hook
  in-process; no log access, no subprocess.
- ``guard diff`` — effective merged config (stub: built-in defaults only;
  user/project layers land in a future task).

Output: structured JSON by default; pretty-printed when stdout is a TTY.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guard import __version__
from guard._utils import GUARD_DECISIONS_PATH
from guard.allowlist import (
    KNOWN_RULE_IDS,
    _resolve_scope_path,
    add_allow_command,
    add_disable_rule,
    load_allowlist,
    remove_allow_command,
    remove_disable_rule,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

# === since-parser ===

_SINCE_RE = re.compile(r"^\s*(\d+)\s*([dhm])\s*$")


def parse_since(text: str) -> timedelta:
    """Parse ``Nd`` / ``Nh`` / ``Nm`` into a ``timedelta``.

    Raises ``ValueError`` on unrecognised input.
    """
    m = _SINCE_RE.match(text)
    if not m:
        msg = f"invalid --since value: {text!r} (expected e.g. 7d, 12h, 30m)"
        raise ValueError(msg)
    n, unit = int(m.group(1)), m.group(2)
    if unit == "d":
        return timedelta(days=n)
    if unit == "h":
        return timedelta(hours=n)
    return timedelta(minutes=n)


def _parse_ts(rec: dict[str, Any]) -> datetime | None:
    """Best-effort parse of the record's timestamp field. Returns ``None`` on failure."""
    raw = rec.get("timestamp") or rec.get("ts")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        # 3.11+ accepts trailing Z directly; older guard records always have Z.
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


# === JSONL reader ===


class JsonlReader:
    """Yield parsed records from the JSONL log with optional filters.

    Malformed lines are skipped silently — the log is observational and the
    CLI must tolerate partial corruption (PIPE_BUF interleaving on shorter
    platforms, manual edits, etc.).
    """

    def __init__(self, path: str | Path) -> None:
        """Hold the JSONL log path."""
        self.path = Path(path)

    def exists(self) -> bool:
        """Return True if the log file exists."""
        return self.path.exists()

    def iter_records(  # noqa: C901 -- linear filter ladder; one branch per filter.
        self,
        *,
        since: datetime | None = None,
        hook_id: str | None = None,
        decision: str | None = None,
        tool_name: str | None = None,
        session_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield records matching the supplied filters."""
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(rec, dict):
                    continue
                # Skip a redirect pointer (single-line marker, see JSONL_FORMAT.md §1.1).
                if "redirect" in rec and len(rec) == 1:
                    continue
                if hook_id is not None and rec.get("hook_id") != hook_id:
                    continue
                if decision is not None and rec.get("decision") != decision:
                    continue
                if tool_name is not None and rec.get("tool_name") != tool_name:
                    continue
                if session_id is not None and rec.get("session_id") != session_id:
                    continue
                if since is not None:
                    ts = _parse_ts(rec)
                    if ts is None or ts < since:
                        continue
                yield rec

    def line_count(self) -> int:
        """Return the number of non-empty lines in the log."""
        if not self.path.exists():
            return 0
        try:
            with self.path.open(encoding="utf-8", errors="replace") as fh:
                return sum(1 for line in fh if line.strip())
        except OSError:
            return 0

    def last_record(self) -> dict[str, Any] | None:
        """Return the last parseable record, or ``None`` if the log is empty."""
        last: dict[str, Any] | None = None
        for rec in self.iter_records():
            last = rec
        return last


# === Effective log path ===


def effective_log_path() -> str:
    """Return the resolved log path: env override or default."""
    return os.environ.get("GUARD_DECISIONS_PATH", GUARD_DECISIONS_PATH)


# === Subcommand implementations ===
#
# Each subcommand returns ``(payload, pretty)`` — payload is the structured
# JSON-serialisable dict, pretty is the human-readable text. ``main()`` picks
# one based on the ``--json`` flag (or stdout TTY heuristic).


def _has_plugin_cache(home: Path) -> bool:
    """True if ``~/.claude/plugins/cache/guard[@version]`` exists."""
    root = home / ".claude" / "plugins" / "cache"
    if not root.exists():
        return False
    try:
        return any(
            e.is_dir() and (e.name == "guard" or e.name.startswith("guard@"))
            for e in root.iterdir()
        )
    except OSError:
        return False


def _settings_reference_guard(home: Path) -> bool:
    """True if a user-scope settings file mentions a guard hook script."""
    for name in ("settings.json", "settings.local.json"):
        try:
            text = (home / ".claude" / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "guard/hooks/" in text or "guard.bash_command_validator" in text:
            return True
    return False


def _log_has_guard_records() -> bool:
    """True if the JSONL log contains any record with ``hook_id`` starting with ``guard.``."""
    reader = JsonlReader(effective_log_path())
    if not reader.exists():
        return False
    try:
        for rec in reader.iter_records():
            hook_id = rec.get("hook_id")
            if isinstance(hook_id, str) and hook_id.startswith("guard."):
                return True
    except OSError:
        return False
    return False


def _check_wiring(home: Path | None = None) -> dict[str, Any]:
    """Inspect the local Claude Code config for evidence guard's hooks are wired.

    Returns a dict with three signals plus an aggregate boolean. The signals
    are deliberately independent so a partial install (e.g. plugin cached
    but settings not merged yet) still surfaces useful information.

    - ``plugin_cache_present``: true if ``~/.claude/plugins/cache/guard``
      exists, suggesting the plugin was installed via the marketplace.
    - ``settings_references_guard``: true if any user-scope settings file
      (``~/.claude/settings.json`` or ``settings.local.json``) contains a
      string referencing a guard hook script. Picks up both plugin-merged
      configs and hand-rolled settings.
    - ``log_has_guard_records``: true if the JSONL log contains at least
      one record from a ``guard.*`` hook_id, proving guard has actually
      run end-to-end.
    """
    if home is None:
        home = Path.home()
    signals: dict[str, Any] = {
        "plugin_cache_present": _has_plugin_cache(home),
        "settings_references_guard": _settings_reference_guard(home),
        "log_has_guard_records": _log_has_guard_records(),
    }
    signals["active"] = any(signals.values())
    return signals


def cmd_status() -> tuple[dict[str, Any], str]:
    """Effective config + wiring check + log location + line count + last record."""
    path = effective_log_path()
    reader = JsonlReader(path)
    line_count = reader.line_count()
    last = reader.last_record()
    last_ts = (last or {}).get("timestamp") if last else None
    wiring = _check_wiring()

    payload: dict[str, Any] = {
        "version": __version__,
        "active": wiring["active"],
        "wiring": {k: v for k, v in wiring.items() if k != "active"},
        "log_path": path,
        "log_exists": reader.exists(),
        "line_count": line_count,
        "last_record_timestamp": last_ts,
        "mode": "enforce",
        "schema_version": 1,
    }

    def tick(*, ok: bool) -> str:
        return "yes" if ok else "no"

    lines = [
        f"guard {__version__}",
        f"active: {tick(ok=wiring['active'])}",
        f"  plugin cache:        {tick(ok=wiring['plugin_cache_present'])}",
        f"  settings reference:  {tick(ok=wiring['settings_references_guard'])}",
        f"  log has guard rec:   {tick(ok=wiring['log_has_guard_records'])}",
        "mode: enforce  (config-driven shadow/off lands in a future release)",
        f"log: {path}",
        f"  exists: {tick(ok=reader.exists())}",
        f"  records: {line_count}",
        f"  last: {last_ts or '(none)'}",
    ]
    if not wiring["active"]:
        lines.extend(
            [
                "",
                "guard is installed but does not appear to be wired into Claude Code.",
                "  install:  /plugin marketplace add TracineHQ/guard",
                "            /plugin install guard",
                "  verify:   restart Claude Code, then run `guard status` again.",
            ]
        )
    return payload, "\n".join(lines) + "\n"


def cmd_noisy(since: timedelta | None, limit: int) -> tuple[dict[str, Any], str]:
    """Top N rules by hit count, grouped by ``(hook_id, decision)``."""
    cutoff = datetime.now(UTC) - since if since is not None else None
    reader = JsonlReader(effective_log_path())
    counts: Counter[tuple[str, str]] = Counter()
    samples: dict[tuple[str, str], str] = {}
    total = 0
    for rec in reader.iter_records(since=cutoff):
        key = (str(rec.get("hook_id", "?")), str(rec.get("decision", "?")))
        counts[key] += 1
        total += 1
        if key not in samples:
            samples[key] = str(rec.get("command_excerpt") or rec.get("reason", ""))[:80]

    top = counts.most_common(limit)
    payload: dict[str, Any] = {
        "since": _since_repr(since),
        "total_records": total,
        "top": [
            {
                "hook_id": h,
                "decision": d,
                "count": c,
                "sample": samples.get((h, d), ""),
            }
            for (h, d), c in top
        ],
    }

    lines = [
        f"Top {len(top)} rules by hit count (since {_since_repr(since)}, total {total} records):",
    ]
    if not top:
        lines.append("  (no records)")
    else:
        for (h, d), c in top:
            sample = samples.get((h, d), "")
            sample_display = f"  {sample!r}" if sample else ""
            lines.append(f"  {c:>5}  {h}  {d}{sample_display}")
    return payload, "\n".join(lines) + "\n"


def cmd_silent(since: timedelta) -> tuple[dict[str, Any], str]:
    """List ``(hook_id, decision)`` pairs that haven't appeared in N days.

    Heuristic: build the FULL set of pairs ever seen in the log; build the
    set of pairs seen in the recency window; the difference is "silent".
    Rules that have NEVER fired don't appear here — they were never noisy
    to begin with.
    """
    cutoff = datetime.now(UTC) - since
    reader = JsonlReader(effective_log_path())
    all_pairs: set[tuple[str, str]] = set()
    recent_pairs: set[tuple[str, str]] = set()
    last_seen: dict[tuple[str, str], str] = {}
    for rec in reader.iter_records():
        key = (str(rec.get("hook_id", "?")), str(rec.get("decision", "?")))
        all_pairs.add(key)
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            prev = last_seen.get(key)
            if prev is None or ts > prev:
                last_seen[key] = ts
        parsed = _parse_ts(rec)
        if parsed is not None and parsed >= cutoff:
            recent_pairs.add(key)

    silent = sorted(all_pairs - recent_pairs)
    payload: dict[str, Any] = {
        "since": _since_repr(since),
        "silent": [
            {"hook_id": h, "decision": d, "last_seen": last_seen.get((h, d))} for (h, d) in silent
        ],
    }

    lines = [
        f"Rules that have not fired in {_since_repr(since)} "
        f"(but have fired at some point in this log):",
    ]
    if not silent:
        lines.append("  (all known rules have fired recently)")
    else:
        for h, d in silent:
            ls = last_seen.get((h, d), "(unknown)")
            lines.append(f"  {h}  {d}  last_seen={ls}")
    return payload, "\n".join(lines) + "\n"


def cmd_trace(session_id: str) -> tuple[dict[str, Any], str]:
    """Print every record matching ``session_id``, chronological."""
    reader = JsonlReader(effective_log_path())
    records = list(reader.iter_records(session_id=session_id))
    records.sort(key=lambda r: str(r.get("timestamp", "")))
    payload: dict[str, Any] = {
        "session_id": session_id,
        "count": len(records),
        "records": records,
    }
    lines = [f"Session {session_id}: {len(records)} record(s)"]
    if not records:
        lines.append("  (no records found)")
    else:
        for rec in records:
            ts = rec.get("timestamp", "?")
            decision = rec.get("decision", "?")
            hook_id = rec.get("hook_id", "?")
            reason = str(rec.get("reason", ""))[:80]
            lines.append(f"  {ts}  {decision:<5}  {hook_id}  {reason}")
    return payload, "\n".join(lines) + "\n"


def cmd_test(command: str) -> tuple[dict[str, Any], str]:
    """Invoke each hook's ``decide()`` directly on the given command.

    No log access, no subprocess. Hooks that decline to decide on this shape
    are reported as ``passthrough``.
    """
    results: list[dict[str, Any]] = list(_test_specs(command))
    payload: dict[str, Any] = {"command": command, "results": results}
    lines = [f"guard test: {command!r}"]
    for r in results:
        decision = r.get("decision") or "passthrough"
        reason = r.get("reason") or ""
        lines.append(f"  {r['hook_id']:<35}  {decision:<11}  {reason[:80]}")
    return payload, "\n".join(lines) + "\n"


def _test_specs(command: str) -> Iterable[dict[str, Any]]:
    """Yield ``{hook_id, decision, reason}`` dicts from each Bash-relevant decide()."""
    # Lazy imports — keep the CLI's import cost low and isolate hook bugs from
    # subcommands that don't need them.
    from guard.hooks import (  # noqa: PLC0415 -- deferred to keep CLI cold-start fast
        bash_command_validator,
        commit_message_validator,
        git_c_validator,
    )

    for hook_id, fn in (
        ("guard.bash_command_validator", bash_command_validator.decide),
        ("guard.git_c_validator", git_c_validator.decide),
        ("guard.commit_message_validator", commit_message_validator.decide),
    ):
        try:
            envelope = fn(command)
        except Exception as exc:  # noqa: BLE001 -- hook isolation
            yield {
                "hook_id": hook_id,
                "decision": "error",
                "reason": f"{type(exc).__name__}: {exc}",
            }
            continue
        if envelope is None:
            yield {"hook_id": hook_id, "decision": "passthrough", "reason": ""}
            continue
        # Both decide-shapes — modern (envelope) and legacy (flat dict).
        hso = envelope.get("hookSpecificOutput") if isinstance(envelope, dict) else None
        if isinstance(hso, dict):
            decision = hso.get("permissionDecision", "?")
            reason = hso.get("permissionDecisionReason", "")
        elif isinstance(envelope, dict):
            decision = envelope.get("permissionDecision", "?")
            reason = envelope.get("permissionDecisionReason", "")
        else:
            decision = "?"
            reason = ""
        yield {"hook_id": hook_id, "decision": decision, "reason": reason}


def cmd_diff() -> tuple[dict[str, Any], str]:
    """Show the effective merged config.

    Stub for v1.1: just the built-in defaults. User / project config layers
    land in a future task; this command will then expand to a 3-way merge view.
    """
    payload: dict[str, Any] = {
        "layers": [
            {
                "name": "builtin",
                "config": {
                    "mode": "enforce",
                    "decisions_path": effective_log_path(),
                    "schema_version": 1,
                    "hooks": [
                        "guard.bash_command_validator",
                        "guard.git_c_validator",
                        "guard.commit_message_validator",
                        "guard.credential_check",
                        "guard.protected_files",
                        "guard.agent_output_guard",
                        "guard.subagent_scope",
                    ],
                },
            },
        ],
        "note": "user/project config layers land in a future task",
    }
    lines = [
        "Effective merged config (built-in only; user/project layers land later):",
        "  mode: enforce",
        f"  decisions_path: {effective_log_path()}",
        "  schema_version: 1",
        "  hooks:",
        *[f"    - {h}" for h in payload["layers"][0]["config"]["hooks"]],
    ]
    return payload, "\n".join(lines) + "\n"


def cmd_migrate_log(
    log_path_override: str | None,
    *,
    dry_run: bool,
    backup: bool,
) -> tuple[dict[str, Any], str]:
    """Rewrite the JSONL log in place to v1, in one shot."""
    from guard.migrate_log import migrate_file  # noqa: PLC0415

    target = Path(log_path_override) if log_path_override else Path(effective_log_path())
    report = migrate_file(target, dry_run=dry_run, backup=backup)
    payload = {
        "path": str(target),
        "dry_run": report.dry_run,
        "total_lines": report.total_lines,
        "already_v1": report.already_v1,
        "promoted_v1_0": report.promoted_v1_0,
        "promoted_v0": report.promoted_v0,
        "unrecognized": report.unrecognized,
        "invalid_json": report.invalid_json,
        "blank": report.blank,
        "backup_path": str(report.backup_path) if report.backup_path else None,
        "samples_unrecognized": report.samples_unrecognized,
    }
    label = "would migrate" if dry_run else "migrated"
    lines = [
        f"{label}: {target}",
        f"  total lines:    {report.total_lines}",
        f"  already v1:     {report.already_v1}",
        f"  promoted v1.0:  {report.promoted_v1_0}",
        f"  promoted v0:    {report.promoted_v0}",
        f"  unrecognized:   {report.unrecognized}",
        f"  invalid JSON:   {report.invalid_json}",
        f"  blank lines:    {report.blank}",
    ]
    if report.backup_path:
        lines.append(f"  backup:         {report.backup_path}")
    if report.samples_unrecognized:
        lines.append("  samples (unrecognized):")
        lines.extend(f"    {sample}" for sample in report.samples_unrecognized)
    return payload, "\n".join(lines) + "\n"


# === Helpers ===


def _since_repr(since: timedelta | None) -> str:
    if since is None:
        return "all time"
    seconds = int(since.total_seconds())
    days, rem = divmod(seconds, 86400)
    if days and rem == 0:
        return f"{days}d"
    hours, rem = divmod(seconds, 3600)
    if hours and rem == 0:
        return f"{hours}h"
    minutes = seconds // 60
    return f"{minutes}m"


# === guard allowlist ===


def cmd_allowlist_list() -> tuple[dict[str, Any], str]:
    """Show effective merged allowlist (project + global)."""
    al = load_allowlist()
    payload = {
        "disable_rules": sorted(al.disable_rules),
        "allow_commands": [
            {"rule": e.rule, "command": e.command, "reason": e.reason, "source": e.source}
            for e in al.allow_commands
        ],
        "sources": [str(p) for p in al.sources],
    }
    if not al.disable_rules and not al.allow_commands:
        pretty = "allowlist: empty (no project or global allowlist file present)\n"
    else:
        lines = ["allowlist (effective merged view):"]
        if al.disable_rules:
            lines.append("  disable_rules:")
            lines.extend(f"    - {r}" for r in sorted(al.disable_rules))
        if al.allow_commands:
            lines.append("  allow_commands:")
            for e in al.allow_commands:
                lines.append(f"    - rule:    {e.rule}")
                lines.append(f"      command: {e.command}")
                lines.append(f"      reason:  {e.reason}")
                lines.append(f"      source:  {e.source}")
        if al.sources:
            lines.append("  sources:")
            lines.extend(f"    - {p}" for p in al.sources)
        pretty = "\n".join(lines) + "\n"
    return payload, pretty


def cmd_allowlist_rules() -> tuple[dict[str, Any], str]:
    """List all known rule_ids you can put on disable_rules / allow_commands.rule."""
    payload = {"rules": list(KNOWN_RULE_IDS)}
    pretty = "known rule_ids:\n" + "\n".join(f"  {r}" for r in KNOWN_RULE_IDS) + "\n"
    return payload, pretty


def cmd_allowlist_disable_rule(rule_id: str, *, scope: str) -> tuple[dict[str, Any], str]:
    """Add ``rule_id`` to ``disable_rules`` in the chosen scope. Idempotent."""
    if rule_id not in KNOWN_RULE_IDS:
        msg = (
            f"unknown rule_id {rule_id!r}; run `guard allowlist rules` for the full list. "
            "(The allowlist will still accept it — guard does not gate on this — but typos "
            "won't fire any matcher and you'll get false confidence.)"
        )
        sys.stderr.write(f"guard: warning: {msg}\n")
    added = add_disable_rule(rule_id, scope=scope)
    path = _resolve_scope_path(scope, None)
    payload = {"rule_id": rule_id, "scope": scope, "added": added, "path": str(path)}
    verb = "added" if added else "already present"
    pretty = f"disable_rules: {rule_id} {verb} ({scope}: {path})\n"
    return payload, pretty


def cmd_allowlist_enable_rule(rule_id: str, *, scope: str) -> tuple[dict[str, Any], str]:
    """Remove ``rule_id`` from ``disable_rules`` in the chosen scope. Idempotent."""
    removed = remove_disable_rule(rule_id, scope=scope)
    path = _resolve_scope_path(scope, None)
    payload = {"rule_id": rule_id, "scope": scope, "removed": removed, "path": str(path)}
    verb = "removed" if removed else "not present"
    pretty = f"disable_rules: {rule_id} {verb} ({scope}: {path})\n"
    return payload, pretty


def cmd_allowlist_allow_command(
    *, rule: str, command: str, reason: str, scope: str
) -> tuple[dict[str, Any], str]:
    """Add an exact-command override entry to ``allow_commands``. Idempotent."""
    added = add_allow_command(rule=rule, command=command, reason=reason, scope=scope)
    path = _resolve_scope_path(scope, None)
    payload = {
        "rule": rule,
        "command": command,
        "reason": reason,
        "scope": scope,
        "added": added,
        "path": str(path),
    }
    verb = "added" if added else "already present"
    pretty = f"allow_commands: {rule!r} + {command!r} {verb} ({scope}: {path})\n"
    return payload, pretty


def cmd_allowlist_remove_command(
    *, rule: str, command: str, scope: str
) -> tuple[dict[str, Any], str]:
    """Remove the matching ``allow_commands`` entry. Idempotent."""
    removed = remove_allow_command(rule=rule, command=command, scope=scope)
    path = _resolve_scope_path(scope, None)
    payload = {
        "rule": rule,
        "command": command,
        "scope": scope,
        "removed": removed,
        "path": str(path),
    }
    verb = "removed" if removed else "not present"
    pretty = f"allow_commands: {rule!r} + {command!r} {verb} ({scope}: {path})\n"
    return payload, pretty


_ALLOWLIST_DISPATCH: dict[str, str] = {
    "list": "cmd_allowlist_list",
    "rules": "cmd_allowlist_rules",
}


def _dispatch_allowlist(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> tuple[dict[str, Any], str] | None:
    """Dispatch the ``guard allowlist <sub>`` subcommands. ``None`` means help-shown."""
    allow_cmd = getattr(args, "allow_cmd", None)
    scope = _resolve_scope(args)
    if allow_cmd in _ALLOWLIST_DISPATCH:
        fn = globals()[_ALLOWLIST_DISPATCH[allow_cmd]]
        return fn()  # type: ignore[no-any-return]
    if allow_cmd == "disable-rule":
        return cmd_allowlist_disable_rule(args.rule_id, scope=scope)
    if allow_cmd == "enable-rule":
        return cmd_allowlist_enable_rule(args.rule_id, scope=scope)
    if allow_cmd == "allow-command":
        return cmd_allowlist_allow_command(
            rule=args.rule, command=args.command, reason=args.reason, scope=scope
        )
    if allow_cmd == "remove-command":
        return cmd_allowlist_remove_command(rule=args.rule, command=args.command, scope=scope)
    parser.parse_args(["allowlist", "--help"])
    return None


# === argparse wiring ===


def _version_string() -> str:
    """Multi-line ``--version`` payload — name, version, install path, repo URL.

    Mirrors `gh --version`. Concrete install path makes bug reports
    self-identifying (which wheel? editable? site-packages?).
    """
    install_dir = str(Path(__file__).resolve().parent)
    return (
        f"guard {__version__}\ntracine-guard from {install_dir}\nhttps://github.com/TracineHQ/guard"
    )


class _RawVersionAction(argparse.Action):
    """Print ``--version`` text verbatim (preserves newlines).

    argparse's built-in ``version`` action runs the string through
    ``HelpFormatter._fill_text`` which collapses newlines to spaces.
    We want a multi-line ``gh --version``-style block, so emit raw.
    """

    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: str = argparse.SUPPRESS,
        version: str = "",
        help: str = "show program's version number and exit",  # noqa: A002 -- argparse contract
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )
        self._version = version

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        del namespace, values, option_string
        sys.stdout.write(self._version + "\n")
        parser.exit(0)


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    """Add a mutually-exclusive ``--global`` / ``--project`` flag pair (default: project)."""
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--global",
        dest="scope_global",
        action="store_true",
        help="Apply to ~/.claude/guard/allowlist.json (overridable via $GUARD_DATA_DIR).",
    )
    g.add_argument(
        "--project",
        dest="scope_project",
        action="store_true",
        help="Apply to <cwd>/.claude/guard/allowlist.json (default).",
    )


def _resolve_scope(args: argparse.Namespace) -> str:
    return "global" if getattr(args, "scope_global", False) else "project"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guard",
        description="guard read-side CLI: query the JSONL decision log.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output even when stdout is a TTY.",
    )
    parser.add_argument(
        "--version",
        action=_RawVersionAction,
        version=_version_string(),
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser(
        "status",
        help="Show installation status, log location, and last record.",
        epilog=(
            "Examples:\n"
            "  guard status              # current install + last record\n"
            "  guard --json status | jq  # pipeable for scripting"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_noisy = sub.add_parser(
        "noisy",
        help="Top N rules by hit count, grouped by (hook_id, decision).",
        epilog=(
            "Examples:\n"
            "  guard noisy --since 24h --limit 20\n"
            "  guard --json noisy --since 7d | jq -s 'group_by(.hook_id)'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_noisy.add_argument("--since", default="7d", help="Time window: Nd/Nh/Nm (default: 7d).")
    p_noisy.add_argument("--limit", type=int, default=10, help="Max entries (default: 10).")

    p_silent = sub.add_parser(
        "silent",
        help=(
            "Rules that haven't fired in --since but HAVE fired at some point. "
            "Heuristic: full set of (hook_id, decision) pairs ever seen, minus "
            "the set seen in the recency window."
        ),
        epilog=("Examples:\n  guard silent --since 30d  # rules that fired before but not lately"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_silent.add_argument("--since", default="30d", help="Time window: Nd/Nh/Nm (default: 30d).")

    p_trace = sub.add_parser(
        "trace",
        help="Print every record for a session, chronological.",
        epilog=("Examples:\n  guard trace abc123def456  # session_id from `guard status`"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_trace.add_argument("session_id", help="Session id from the log.")

    p_test = sub.add_parser(
        "test",
        help="In-process invocation of each hook's decide() on the given command.",
        epilog=(
            "Examples:\n"
            "  guard test 'rm -rf /'           # preview which hook denies it\n"
            "  guard test 'git -C /tmp status' # check git_c_validator behavior"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_test.add_argument("command", help="Bash command to test.")

    sub.add_parser(
        "diff",
        help=(
            "Show effective merged config. v1.1 stub: built-in defaults only; "
            "user/project layers land later."
        ),
        epilog=("Examples:\n  guard diff  # effective config (built-in defaults today)"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p_allow = sub.add_parser(
        "allowlist",
        help="Manage the project + global allowlist (disable_rules / allow_commands).",
        epilog=(
            "Examples:\n"
            "  guard allowlist list\n"
            "  guard allowlist rules\n"
            "  guard allowlist disable-rule bash.disk_destruction --project\n"
            "  guard allowlist enable-rule bash.disk_destruction --project\n"
            "  guard allowlist allow-command --rule bash.disk_destruction \\\n"
            '    --command "dd if=/dev/zero of=/tmp/x.qcow2 bs=1M count=1" \\\n'
            '    --reason "build VM image fixture"\n'
            "  guard allowlist remove-command --rule bash.disk_destruction \\\n"
            '    --command "dd if=/dev/zero of=/tmp/x.qcow2 bs=1M count=1"'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_allow_sub = p_allow.add_subparsers(dest="allow_cmd")
    p_allow_sub.add_parser("list", help="Show effective merged allowlist (project + global).")
    p_allow_sub.add_parser("rules", help="List all known rule_ids you can put on the allowlist.")

    p_disable = p_allow_sub.add_parser("disable-rule", help="Add a rule_id to disable_rules.")
    p_disable.add_argument("rule_id", help="The rule id to disable, e.g. 'bash.disk_destruction'.")
    _add_scope_args(p_disable)

    p_enable = p_allow_sub.add_parser("enable-rule", help="Remove a rule_id from disable_rules.")
    p_enable.add_argument("rule_id", help="The rule id to re-enable.")
    _add_scope_args(p_enable)

    p_acmd = p_allow_sub.add_parser("allow-command", help="Add an exact-command override.")
    p_acmd.add_argument("--rule", required=True, help="The rule_id this override targets.")
    p_acmd.add_argument(
        "--command",
        required=True,
        help="Exact command string (compared with .strip()-equality at decide time).",
    )
    p_acmd.add_argument("--reason", required=True, help="Written justification (audit-logged).")
    _add_scope_args(p_acmd)

    p_rcmd = p_allow_sub.add_parser("remove-command", help="Remove an exact-command override.")
    p_rcmd.add_argument("--rule", required=True)
    p_rcmd.add_argument("--command", required=True)
    _add_scope_args(p_rcmd)

    p_migrate = sub.add_parser(
        "migrate-log",
        help=(
            "One-shot rewrite of the JSONL log to schema v1. "
            "Idempotent — re-running on an already-v1 log is a no-op."
        ),
        epilog=(
            "RECOMMENDED: pause Claude Code sessions before running. "
            "Guard's writer takes O_APPEND on the existing inode; if a hook "
            "fires during migration, that record may land on the orphaned "
            "inode and be lost on the atomic replace. The default backup "
            "(.bak.<UTC-timestamp>) is your safety net."
        ),
    )
    p_migrate.add_argument(
        "--path",
        default=None,
        help=(
            "Override log path (default: $GUARD_DECISIONS_PATH or ~/.claude/guard-decisions.jsonl)."
        ),
    )
    p_migrate.add_argument(
        "--dry-run",
        action="store_true",
        help="Report counts without writing.",
    )
    p_migrate.add_argument(
        "--no-backup",
        dest="backup",
        action="store_false",
        default=True,
        help="Skip writing a sibling .bak.<timestamp> file (not recommended).",
    )

    return parser


def _emit(payload: dict[str, Any], pretty: str, *, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json.dumps(payload, default=str) + "\n")
    else:
        sys.stdout.write(pretty)


def main(argv: list[str] | None = None) -> int:  # noqa: C901 -- linear command-dispatch ladder, one branch per subcommand
    """CLI entry point. Returns the exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Default to JSON output when piped, pretty when on a TTY.
    as_json = bool(args.json) or not sys.stdout.isatty()

    cmd = args.cmd
    if cmd is None:
        parser.print_help(sys.stderr)
        return 2

    try:
        if cmd == "status":
            payload, pretty = cmd_status()
        elif cmd == "noisy":
            since = parse_since(args.since)
            payload, pretty = cmd_noisy(since, max(1, int(args.limit)))
        elif cmd == "silent":
            since = parse_since(args.since)
            payload, pretty = cmd_silent(since)
        elif cmd == "trace":
            payload, pretty = cmd_trace(args.session_id)
        elif cmd == "test":
            payload, pretty = cmd_test(args.command)
        elif cmd == "diff":
            payload, pretty = cmd_diff()
        elif cmd == "migrate-log":
            payload, pretty = cmd_migrate_log(
                args.path,
                dry_run=bool(args.dry_run),
                backup=bool(args.backup),
            )
        elif cmd == "allowlist":
            dispatched = _dispatch_allowlist(args, parser)
            if dispatched is None:
                return 0
            payload, pretty = dispatched
        else:
            parser.print_help()
            return 0
    except (ValueError, FileNotFoundError, OSError) as exc:
        sys.stderr.write(f"guard: {exc}\n")
        return 2

    _emit(payload, pretty, as_json=as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
