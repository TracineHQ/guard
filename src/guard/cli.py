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


def cmd_status() -> tuple[dict[str, Any], str]:
    """Effective config + log location + line count + last record timestamp."""
    path = effective_log_path()
    reader = JsonlReader(path)
    line_count = reader.line_count()
    last = reader.last_record()
    last_ts = (last or {}).get("timestamp") if last else None

    payload: dict[str, Any] = {
        "version": __version__,
        "log_path": path,
        "log_exists": reader.exists(),
        "line_count": line_count,
        "last_record_timestamp": last_ts,
        "mode": "enforce",  # hardcoded for v1.1; config-driven later.
        "schema_version": 1,
    }

    lines = [
        f"guard {__version__}",
        "mode: enforce  (config-driven shadow/off lands in a future release)",
        f"log: {path}",
        f"  exists: {'yes' if reader.exists() else 'no'}",
        f"  records: {line_count}",
        f"  last: {last_ts or '(none)'}",
    ]
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


# === argparse wiring ===


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
        action="version",
        version=f"guard {__version__}",
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="Show installation status, log location, and last record.")

    p_noisy = sub.add_parser(
        "noisy", help="Top N rules by hit count, grouped by (hook_id, decision)."
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
    )
    p_silent.add_argument("--since", default="30d", help="Time window: Nd/Nh/Nm (default: 30d).")

    p_trace = sub.add_parser("trace", help="Print every record for a session, chronological.")
    p_trace.add_argument("session_id", help="Session id from the log.")

    p_test = sub.add_parser(
        "test", help="In-process invocation of each hook's decide() on the given command."
    )
    p_test.add_argument("command", help="Bash command to test.")

    sub.add_parser(
        "diff",
        help=(
            "Show effective merged config. v1.1 stub: built-in defaults only; "
            "user/project layers land later."
        ),
    )

    p_migrate = sub.add_parser(
        "migrate-log",
        help=(
            "One-shot rewrite of the JSONL log to schema v1. "
            "Idempotent — re-running on an already-v1 log is a no-op."
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


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Default to JSON output when piped, pretty when on a TTY.
    as_json = bool(args.json) or not sys.stdout.isatty()

    cmd = args.cmd
    if cmd is None:
        parser.print_help()
        return 0

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
