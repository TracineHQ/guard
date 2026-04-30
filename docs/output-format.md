# guard JSONL decision log — output format v1

**Status:** stable contract. Breaking changes require schema version bump.
**Audience:** consumers of `~/.claude/guard-decisions.jsonl` (notably TracineHQ/convo).
**Specifies:** path, format, schema, writer guarantees, consumer responsibilities.

## 1. Path

- Canonical writer path: `~/.claude/guard-decisions.jsonl`
- User-scope, persistent across sessions. The writer expands `~` at runtime via `os.path.expanduser`.
- Override for testing: env var `GUARD_DECISIONS_PATH`. Integration tests redirect this to `tmp_path`.
- The writer **never** derives the path from `${CLAUDE_PLUGIN_ROOT}` — the plugin cache is wipeable, and decision history must survive plugin reinstalls.

## 2. Format

- Newline-delimited JSON (NDJSON / JSONL): one record per line, UTF-8 encoded, terminated by a single `\n`.
- Records are single-line — no pretty-printing, no embedded newlines. Aligns with the OpenTelemetry file-exporter convention.
- Each record is bounded to **4096 bytes** (the Linux `O_APPEND` atomicity envelope, `PIPE_BUF`). Writers MUST truncate to fit; see §5.

## 3. Schema v1 fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | int | yes | starts at `1`; bumped on breaking change |
| `timestamp` | string (ISO-8601 UTC, microsecond precision, suffix `Z`) | yes | e.g. `"2026-04-29T14:32:11.123456Z"` |
| `hook_id` | string | yes | namespaced: `guard.<hook_module>` (e.g. `guard.bash_command_validator`) |
| `event` | string | yes | matches Claude Code event names (`PreToolUse`, `PostToolUse`) |
| `tool_name` | string \| null | yes for PreToolUse/PostToolUse | `Bash`, `Edit`, etc. |
| `decision` | enum string | yes | one of `allow`, `deny`, `ask`, `defer`, `pass` |
| `reason` | string | yes | human-readable; ≤ 1024 chars |
| `command_excerpt` | string \| null | optional | truncated to 4096 chars; only set for Bash-related decisions |
| `session_id` | string | yes | from Claude Code stdin |
| `cwd` | string | optional | from Claude Code stdin |

## 4. `schema_version` semantics

- Monotonic int. Currently `1`.
- **Additive changes** (new optional fields) keep the version.
- **Breaking changes** (rename, removal, type change, semantic change) require a version bump.
- Consumers (notably convo) MUST quarantine records with unknown `schema_version` and log a warning. Consumers MUST NOT crash on unknown versions.

## 5. Atomic-append writer policy

- File opened with `O_WRONLY | O_APPEND | O_CREAT`.
- Each record is emitted as a **single `os.write(fd, buf)` syscall**. On Linux, `O_APPEND` writes ≤ `PIPE_BUF` (4096 bytes) are atomic with respect to concurrent appenders.
- No `fsync` per write. Decisions are observational, not transactional; durability is best-effort.
- Records bounded to 4096 bytes total (including trailing `\n`). The writer truncates fields in this priority order to fit:
  1. `command_excerpt` truncated first.
  2. `reason` truncated next, if still over budget.
  3. `decision`, `hook_id`, `schema_version`, `timestamp` are **never** truncated.
- Truncation is suffix-marked with the literal string `…[truncated]` so consumers can detect it.

## 6. Rotation policy

- **Writer (guard) does NOT rotate.** It appends indefinitely.
- **Consumer (convo) owns retention, rotation, and compaction.** Consumers are expected to tail-and-trim, ship to a durable store, or apply their own age/size policies.
- A future v1.1 may ship a manual `guard-doctor truncate` CLI subcommand for operators. v1 ships no automatic rotation.

## 7. Examples

```json
{"schema_version":1,"timestamp":"2026-04-29T14:32:11.123456Z","hook_id":"guard.bash_command_validator","event":"PreToolUse","tool_name":"Bash","decision":"allow","reason":"Read-only command","command_excerpt":"ls -la","session_id":"abc-123","cwd":"/home/alice/project"}
{"schema_version":1,"timestamp":"2026-04-29T14:32:12.987654Z","hook_id":"guard.bash_command_validator","event":"PreToolUse","tool_name":"Bash","decision":"deny","reason":"git add -A is denied: stages all files indiscriminately","command_excerpt":"git add -A","session_id":"abc-123","cwd":"/home/alice/project"}
{"schema_version":1,"timestamp":"2026-04-29T14:32:13.456789Z","hook_id":"guard.protected_files","event":"PreToolUse","tool_name":"Edit","decision":"ask","reason":"Edit to .env requires user confirmation","command_excerpt":null,"session_id":"abc-123","cwd":"/home/alice/project"}
```

## 8. Versioning

- This document is the canonical spec for `schema_version: 1`.
- A future `schema_version: 2` will ship as a separate file `docs/output-format-v2.md` with a migration note pointing back here. v1 will remain authoritative for the v1 wire format.

## 9. Reference implementation

- Canonical writer: `src/guard/_utils.py`.
- Helper `emit_pretooluse_decision(decision, reason, ...)` constructs the PreToolUse return envelope; the JSONL append is performed elsewhere in the same module.
- The constant `GUARD_DECISIONS_PATH` is the source of truth for the writer path.

## See also

- `00-design-decisions.md` (private planning notes) for rationale on schema choices.
- Reference implementation: `src/guard/_utils.py`.
