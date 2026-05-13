# guard JSONL decision log — format spec

**Status:** stable contract. Breaking changes require a `v` bump.
**Audience:** any consumer that tails or imports the decision log
(observability pipelines, audit tools, the built-in `guard` CLI, the `convo`
indexer).
**Specifies:** path, format, schema, writer guarantees, consumer responsibilities.

This document supersedes `docs/output-format.md` for schema v1.1 and onwards.
The earlier document is preserved for reference; the field set is a strict
superset.

## 1. Path discovery

- Canonical writer path: `~/.claude/guard-decisions.jsonl`
- User-scope, persistent across sessions. The writer expands `~` at runtime.
- Override via `GUARD_DECISIONS_PATH`. The plugin's integration tests redirect
  this to a `tmp_path`; production consumers should respect it too.
- The writer **never** derives the path from `${CLAUDE_PLUGIN_ROOT}` — the
  plugin cache is wipeable, and decision history must survive plugin reinstalls.

### 1.1 Pointer protocol (redirect)

If `GUARD_DECISIONS_PATH` is set, all real records go to the override path.
External consumers that only know the default location SHOULD treat a
single-line file at the default path of the form:

```json
{"redirect":"/absolute/path/to/real.jsonl"}
```

as a pointer and follow the `redirect` value. The contract:

- A redirect pointer is a JSONL file with **exactly one line** that parses to a
  JSON object containing a single `redirect` key (string, absolute path).
- Consumers MUST follow at most one hop (no chains).
- Consumers MUST tolerate the absence of a redirect pointer (it is optional).

**Status:** the redirect pointer WRITE is not implemented in v1.1; this
section is the contract. Consumers can opt-in by reading the env var directly
(`GUARD_DECISIONS_PATH`) until the writer ships the pointer.

## 2. Format

- Newline-delimited JSON (NDJSON / JSONL): one record per line, UTF-8 encoded,
  terminated by a single `\n`.
- Records are single-line — no pretty-printing, no embedded newlines. Aligns
  with the OpenTelemetry file-exporter convention.
- Each record is bounded to **4096 bytes** (the Linux `O_APPEND` atomicity
  envelope, `PIPE_BUF`). Writers MUST truncate to fit; see §5.

## 3. Schema v1 fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `v` | int | yes | schema version, currently `1`. Short alias of `schema_version`. |
| `schema_version` | int | yes | long form, kept for backward compatibility |
| `mode` | enum string | yes | one of `"enforce"`, `"shadow"`, `"off"` |
| `timestamp` | string (ISO-8601 UTC, microsecond precision, `Z` suffix) | yes | e.g. `"2026-04-29T14:32:11.123456Z"` |
| `hook_id` | string | yes | namespaced: `guard.<hook_module>` (e.g. `guard.bash_command_validator`) |
| `event` | string | yes | matches Claude Code event names (`PreToolUse`, `PostToolUse`) |
| `tool_name` | string \| null | yes for PreToolUse/PostToolUse | `Bash`, `Edit`, etc. |
| `decision` | enum string | yes | one of `allow`, `deny`, `ask`, `defer`, `pass` |
| `reason` | string | yes | human-readable; ≤ 1024 chars |
| `command_excerpt` | string \| null | optional | truncated to 4096 chars; only set for Bash-related decisions |
| `session_id` | string | yes | from Claude Code stdin |
| `cwd` | string | optional | from Claude Code stdin |
| `unknown_flags` | array of strings | optional | long flags an admin CLI verb matcher could not classify against the spec's `known_flags`; capped at 8 entries. Populated only on `bash.admin_*` decisions and when the offending segment is for a CLI with a known-flags spec (currently: AWS). |

### 3.1 Mode semantics

`mode` records the effective enforcement posture **at decision time**:

- `"enforce"` — guard's decision is the authoritative outcome for the user.
- `"shadow"` — guard computed a decision but did not enforce it (decision is
  observational only; useful for testing new rules without breaking flows).
- `"off"` — the hook ran but is functionally disabled; decisions are
  passthrough.

For v1.1, `mode` is hardcoded to `"enforce"`. Config-driven shadow/off lands
in a later release; the field is present now so consumers don't have to add
support later.

### 3.2 Path discovery for consumers

Consumers SHOULD resolve the log path in this order:

1. `GUARD_DECISIONS_PATH` env var, if set.
2. `~/.claude/guard-decisions.jsonl` (default).
3. If the default file is exactly one line and parses as `{"redirect": "<path>"}`,
   follow it (one hop only).

## 4. Schema versioning rules

- `v` (and `schema_version`) is a monotonic int, currently `1`.
- **Additive changes** (new optional fields) keep the version.
- **Breaking changes** (rename, removal, type change, semantic change) bump
  `v`. Any consumer relying on a renamed/removed field MUST add migration
  code before processing records with the new `v`.
- Consumers MUST tolerate **unknown fields** without erroring. Pin the fields
  you read; ignore the rest.
- Consumers MUST tolerate **unknown `v` values**: quarantine the record, log a
  warning, do not crash.
- Records emitted before `v` was added (legacy records) MAY be treated as
  `v: 0` for triage purposes. Best-effort parse, no hard requirements.

## 5. Atomic-append writer policy

- File opened with `O_WRONLY | O_APPEND | O_CREAT`.
- Each record is emitted as a **single `os.write(fd, buf)` syscall**. On
  Linux, `O_APPEND` writes ≤ `PIPE_BUF` (4096 bytes) are atomic with respect
  to concurrent appenders.
- No `fsync` per write. Decisions are observational, not transactional;
  durability is best-effort.
- Records bounded to 4096 bytes total (including trailing `\n`). The writer
  truncates fields in this priority order to fit:
  1. `command_excerpt` truncated first.
  2. `reason` truncated next, if still over budget.
  3. `v`, `schema_version`, `mode`, `decision`, `hook_id`, `timestamp` are
     **never** truncated.
- Truncation is suffix-marked with the literal string `…[truncated]` so
  consumers can detect it.
- On any `OSError` (full disk, missing parent dir, EACCES) the writer fails
  silently — guard's "guardrails not walls" contract: a logging failure must
  never block legitimate work.

## 6. Rotation policy

- **Writer (guard) does NOT rotate.** It appends indefinitely.
- **Consumers own retention, rotation, and compaction.** Tail-and-trim, ship
  to a durable store, or apply your own age/size policies.

## 7. Examples

```json
{"v":1,"schema_version":1,"mode":"enforce","timestamp":"2026-04-29T14:32:11.123456Z","hook_id":"guard.bash_command_validator","event":"PreToolUse","tool_name":"Bash","decision":"allow","reason":"Read-only command","command_excerpt":"ls -la","session_id":"abc-123","cwd":"/home/alice/project"}
{"v":1,"schema_version":1,"mode":"enforce","timestamp":"2026-04-29T14:32:12.987654Z","hook_id":"guard.bash_command_validator","event":"PreToolUse","tool_name":"Bash","decision":"deny","reason":"git add -A is denied: stages all files indiscriminately","command_excerpt":"git add -A","session_id":"abc-123","cwd":"/home/alice/project"}
{"v":1,"schema_version":1,"mode":"enforce","timestamp":"2026-04-29T14:32:13.456789Z","hook_id":"guard.protected_files","event":"PreToolUse","tool_name":"Edit","decision":"ask","reason":"Edit to .env requires user confirmation","session_id":"abc-123","cwd":"/home/alice/project"}
```

## 8. Reference implementation

- Writer: `src/guard/_utils.py` — `log_decision()` and `append_jsonl()`.
- Built-in reader: `src/guard/cli.py` — the `guard` CLI (`guard noisy`,
  `guard silent`, `guard trace`, `guard status`, `guard test`, `guard diff`).
- Path constant: `GUARD_DECISIONS_PATH` in `src/guard/_utils.py`.

## 9. See also

- `docs/output-format.md` — the v1.0 spec (superseded by this document).
- `README.md` — top-level guard documentation.
