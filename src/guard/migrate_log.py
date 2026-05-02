"""One-shot migration of guard's JSONL decision log to schema v1.

This is internal cleanup, not a long-term legacy-compat layer. During pre-v1.1
development the log went through three shapes; this module promotes records to
the v1 contract documented in `docs/JSONL_FORMAT.md` so the writer / reader
stay strict and consumers (e.g. the convo indexer) don't need fallback paths.

Shape table (see ``docs/JSONL_FORMAT.md`` §3 for the v1 spec):

- **v1**: has ``v: 1`` — passthrough.
- **v1.0**: ``schema_version: 1``, v1 fields, missing ``v``/``mode`` —
  inject ``v: 1`` and ``mode: "enforce"``.
- **v0**: has ``ts``/``command``/``base_cmd`` — infer
  hook_id/event/tool_name, normalize the decision verb.
- **other**: unrecognized JSON or unparsable — preserve as-is, count for
  the report.

Future schema bumps follow this same pattern: a small dedicated module + CLI
subcommand that rewrites the log in place. We do NOT bake legacy fallback
into the v1 reader.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

# v0 → v1 inference constants. The v0 shape was bash-only and pre-dated the
# multi-hook refactor, so every v0 record is a bash_command_validator decision.
_V0_HOOK_ID = "guard.bash_command_validator"
_V0_EVENT = "PreToolUse"
_V0_TOOL_NAME = "Bash"

_DECISION_RENAMES: dict[str, str] = {
    # `passthrough` was the v0 verb; v1 uses `pass` for the same outcome
    # (rule examined the command, took no action, allowed it through).
    "passthrough": "pass",
}

_MAX_UNRECOGNIZED_SAMPLES = 3

_REQUIRED_V1_FIELDS = (
    "v",
    "schema_version",
    "mode",
    "timestamp",
    "hook_id",
    "event",
    "decision",
    "reason",
    "session_id",
)
_VALID_V1_DECISIONS = frozenset({"allow", "deny", "ask", "defer", "pass"})


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """Summary of a single migration run."""

    total_lines: int = 0
    already_v1: int = 0
    promoted_v1_0: int = 0
    promoted_v0: int = 0
    unrecognized: int = 0
    invalid_json: int = 0
    blank: int = 0
    backup_path: Path | None = None
    output_path: Path | None = None
    dry_run: bool = False
    samples_unrecognized: list[str] = field(default_factory=list)


def _normalize_timestamp(ts: str) -> str:
    """Normalize an ISO-8601 timestamp string to the v1 spec form (`Z` suffix).

    The v0 writer emitted ``+00:00``; v1 mandates a single ``Z`` suffix with
    microsecond precision. We rewrite ``+00:00`` → ``Z`` and pass through
    anything that's already in the right shape. If parsing fails, we leave
    the value unchanged — the strict reader will reject it loudly later.
    """
    if ts.endswith("+00:00"):
        return ts[: -len("+00:00")] + "Z"
    return ts


def _is_v1(obj: dict[str, Any]) -> bool:
    return obj.get("v") == 1


def _is_v1_0_shape(obj: dict[str, Any]) -> bool:
    """v1.0 records have all v1 fields except `v` and `mode`."""
    if "v" in obj or "mode" in obj:
        return False
    if obj.get("schema_version") != 1:
        return False
    return all(field in obj for field in ("hook_id", "event", "decision", "reason", "timestamp"))


def _is_v0_shape(obj: dict[str, Any]) -> bool:
    """v0 records use `ts`/`command` + bash-validator-only fields."""
    return "ts" in obj and "command" in obj


def _promote_v1_0(obj: dict[str, Any]) -> dict[str, Any]:
    """Promote a v1.0-shape record to v1 by injecting `v` and `mode`."""
    out = dict(obj)
    out["v"] = 1
    out["mode"] = "enforce"
    return out


def _promote_v0(obj: dict[str, Any]) -> dict[str, Any]:
    """Promote a v0-shape record to v1 with inferred hook_id / event / tool_name."""
    decision = obj.get("decision", "")
    decision = _DECISION_RENAMES.get(decision, decision)

    return {
        "v": 1,
        "schema_version": 1,
        "mode": "enforce",
        "timestamp": _normalize_timestamp(str(obj.get("ts", ""))),
        "hook_id": _V0_HOOK_ID,
        "event": _V0_EVENT,
        "tool_name": _V0_TOOL_NAME,
        "decision": decision,
        "reason": str(obj.get("reason", "")),
        "command_excerpt": str(obj.get("command", "")),
        "session_id": str(obj.get("session_id", "")),
    }


def _is_valid_v1(obj: dict[str, Any]) -> bool:
    """Cheap sanity check after promotion: required fields present, decision in set."""
    if not all(field in obj for field in _REQUIRED_V1_FIELDS):
        return False
    return obj.get("decision") in _VALID_V1_DECISIONS


def _ensure_newline(line: str) -> str:
    if not line:
        return ""
    return line if line.endswith("\n") else line + "\n"


def _classify_and_promote(obj: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Return ``(category, promoted_record_or_None)`` for one parsed object.

    None ``promoted`` means the original line should be preserved as-is.
    """
    if _is_v1(obj):
        return "v1", None
    if _is_v1_0_shape(obj):
        promoted = _promote_v1_0(obj)
        if _is_valid_v1(promoted):
            return "v1_0", promoted
        return "unrecognized", None
    if _is_v0_shape(obj):
        promoted = _promote_v0(obj)
        if _is_valid_v1(promoted):
            return "v0", promoted
        return "unrecognized", None
    return "unrecognized", None


def _migrate_one(line: str) -> tuple[str, str]:
    """Migrate a single line. Returns ``(category, output_line)``.

    `category` is one of: ``v1``, ``v1_0``, ``v0``, ``unrecognized``,
    ``invalid_json``, ``blank``. The output_line is always newline-terminated
    when non-empty (matches the writer's atomic-append contract).
    """
    if not line.strip():
        return "blank", _ensure_newline(line)
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return "invalid_json", _ensure_newline(line)
    if not isinstance(obj, dict):
        return "unrecognized", _ensure_newline(line)
    category, promoted = _classify_and_promote(obj)
    if promoted is None:
        return category, _ensure_newline(line)
    return category, json.dumps(promoted, separators=(",", ":")) + "\n"


def migrate_file(
    path: Path,
    *,
    dry_run: bool = False,
    backup: bool = True,
) -> MigrationReport:
    """Migrate `path` in place. Returns a `MigrationReport`.

    Algorithm:
    1. Stream the source file line-by-line, classify and rewrite each record.
    2. Buffer output in a sibling `<path>.migrating` file.
    3. If `dry_run`, discard the staging file and return counts only.
    4. Otherwise, copy the original to `<path>.bak.<UTC-timestamp>` (when
       `backup=True`), then `os.replace` the staging file onto the original.
    5. On any exception, the staging file is removed; the original is
       untouched (atomic-replace either fully succeeds or never happens).
    """
    if not path.exists():
        msg = f"guard log not found: {path}"
        raise FileNotFoundError(msg)

    counts: dict[str, int] = {
        "v1": 0,
        "v1_0": 0,
        "v0": 0,
        "unrecognized": 0,
        "invalid_json": 0,
        "blank": 0,
    }
    samples_unrecognized: list[str] = []
    total = 0

    staging = path.with_name(path.name + ".migrating")
    try:
        with (
            path.open("r", encoding="utf-8") as src,
            staging.open(
                "w",
                encoding="utf-8",
            ) as dst,
        ):
            for line in src:
                total += 1
                category, out = _migrate_one(line)
                counts[category] += 1
                if (
                    category == "unrecognized"
                    and len(samples_unrecognized) < _MAX_UNRECOGNIZED_SAMPLES
                ):
                    samples_unrecognized.append(line.rstrip("\n")[:200])
                dst.write(out)

        if dry_run:
            staging.unlink(missing_ok=True)
            return MigrationReport(
                total_lines=total,
                already_v1=counts["v1"],
                promoted_v1_0=counts["v1_0"],
                promoted_v0=counts["v0"],
                unrecognized=counts["unrecognized"],
                invalid_json=counts["invalid_json"],
                blank=counts["blank"],
                samples_unrecognized=samples_unrecognized,
                dry_run=True,
            )

        backup_path: Path | None = None
        if backup:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = path.with_name(f"{path.name}.bak.{stamp}")
            shutil.copy2(path, backup_path)

        staging.replace(path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise

    return MigrationReport(
        total_lines=total,
        already_v1=counts["v1"],
        promoted_v1_0=counts["v1_0"],
        promoted_v0=counts["v0"],
        unrecognized=counts["unrecognized"],
        invalid_json=counts["invalid_json"],
        blank=counts["blank"],
        samples_unrecognized=samples_unrecognized,
        backup_path=backup_path,
        output_path=path,
    )
