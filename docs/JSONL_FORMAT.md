# guard JSONL decision log — format spec

**Status:** stable contract. Breaking changes require a `v` bump.
**Audience:** any consumer that tails or imports the decision log
(observability pipelines, audit tools, the built-in `guard` CLI, the `convo`
indexer).
**Specifies:** path, format, schema, writer guarantees, consumer responsibilities.

This document is the canonical spec. `docs/output-format.md` is a stub
that points back here; older links should update to point at this file.

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
| `type` | enum string | optional | record-shape discriminator. Defaults to `"decision"` when absent. Currently one of `"decision"`, `"internal_error"`, or `"permission_request"` (§3.4, §3.5). Consumers MUST filter on `type` to avoid blending non-decision records into decision tallies. |
| `mode` | enum string | yes (decision) | one of `"enforce"`, `"shadow"`, `"off"`. Set per-record from the resolved allowlist mode (project > global > default `"enforce"`). `"shadow"` decisions are logged but not enforced; `"off"` short-circuits the hook and emits no record. |
| `timestamp` | string (ISO-8601 UTC, microsecond precision, `Z` suffix) | yes | e.g. `"2026-04-29T14:32:11.123456Z"` |
| `hook_id` | string | yes (decision) | namespaced: `guard.<hook_module>` (e.g. `guard.bash_command_validator`) |
| `event` | string | yes (decision) | matches Claude Code event names (`PreToolUse`, `PostToolUse`) |
| `tool_name` | string \| null | yes for PreToolUse/PostToolUse | `Bash`, `Edit`, etc. |
| `decision` | enum string | yes (decision) | one of `allow`, `deny`, `ask`, `defer`, `pass` |
| `permission_mode` | enum string \| null | optional | Claude Code `permission_mode` at decision time (`default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`). Threaded from the PreToolUse payload; populated for Bash decisions. |
| `reason` | string | yes (decision) | human-readable; ≤ 1024 chars. Secret-shapes are redacted at write time. |
| `command_excerpt` | string \| null | optional | truncated to 4096 chars; only set for Bash-related decisions. Secret-shapes are redacted at write time. |
| `session_id` | string | yes (decision) | from Claude Code stdin |
| `cwd` | string | optional | from Claude Code stdin |
| `unknown_flags` | array of strings | optional | long flags an admin CLI verb matcher could not classify against the spec's `known_flags`; capped at 8 entries. Populated only on `bash.admin_*` decisions and when the offending segment is for a CLI with a known-flags spec (currently: AWS). |

### 3.1 Mode semantics

`mode` records the effective enforcement posture **at decision time**:

- `"enforce"` — guard's decision is the authoritative outcome for the user.
- `"shadow"` — guard computed a decision but did not enforce it (decision is
  observational only; useful for testing new rules without breaking flows).
- `"off"` — the hook ran but is functionally disabled; decisions are
  passthrough.

As of v1.4.0, the writer emits the resolved allowlist mode on every
decision record (default `"enforce"`). Operators flip mode with
`guard mode <enforce|shadow|off> [--project|--global]`, which writes a
top-level `"mode"` field into `.claude/guard/allowlist.json`. Project
beats global beats the default. `"shadow"` is useful for testing a new
rule against real sessions without blocking: the writer still logs
`decision: "deny"` with `mode: "shadow"`, but the hook exits 0 with an
empty stdout so Claude Code's normal permission flow takes over.

### 3.2 Path discovery for consumers

Consumers SHOULD resolve the log path in this order:

1. `GUARD_DECISIONS_PATH` env var, if set.
2. `~/.claude/guard-decisions.jsonl` (default).
3. If the default file is exactly one line and parses as `{"redirect": "<path>"}`,
   follow it (one hop only).

### 3.3 `rule_id` taxonomy

Deny records surface a stable `rule_id` in the `reason` field (between
the `denied:` prefix and the human-readable body), e.g. `guard
[permission_mode=default] denied: bash.always_deny. ...`. Consumers
filtering or grouping decisions should key on `rule_id`, not the
human-readable body (which may evolve).

Top-level categories:

| Prefix | Origin | Examples |
|---|---|---|
| `bash.always_deny` | literal `ALWAYS_DENY` registry hits | `git push --force`, `rm -rf /` |
| `bash.<synth>` | synthetic-deny predicates (one rule_id per predicate) | `bash.dangerous_rm`, `bash.git_config_injection`, `bash.git_force_push`, `bash.kubectl_destructive`, `bash.gh_api_destructive`, `bash.disk_destruction`, etc. The active list lives next to the `_PER_FORM_MATCHERS` tuple in `bash_command_validator.py`. |
| `bash.admin_*` | admin-CLI flag-spec violations (default / interactive mode) | `bash.admin_default_deny`, `bash.admin_forbidden_subcommand`, `bash.admin_forbidden_flag`, `bash.admin_sensitive_env_override` |
| `bash.admin_unknown_flag_strict` | strict mode (`auto`/`dontAsk`/`bypassPermissions`) blocks an admin CLI invocation that carries flags outside the spec's `known_flags` set | strict-only |
| `bash.strict_feedback` / `bash.strict_default_deny` | strict-mode default-deny for non-admin commands not on the allowlist | strict-only |
| `bash.command_too_long` | command exceeded `_COMMAND_LENGTH_CAP` after canonicalization | DoS guard |

`git_c_validator` decisions do not carry a `rule_id`; the deny `reason` is
self-describing (`"git -C: 'reset' is destructive and blocked"`,
`"git -c <key>=<value>: command-line override of core.hooksPath / ..."`).
Group git-C decisions on `hook_id == "guard.git_c_validator"`.

Strict-mode rule_ids (`bash.admin_unknown_flag_strict`,
`bash.command_too_long`, `bash.strict_default_deny`,
`bash.strict_feedback`) are eligible for allowlist override; see
`guard allowlist allow-command <rule_id> '<command>' --reason '...'`.

### 3.4 `internal_error` records

When a hook raises an uncaught exception, the guard process catches it and
appends an `internal_error` record before re-raising. These records share
`v`, `schema_version`, `timestamp`, and `session_id` with decisions but
carry a different shape:

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | always `"internal_error"` for this record shape |
| `exc_class` | string | yes | exception class name (e.g. `"ValueError"`) |
| `exc_msg` | string | yes | exception message, secret-shape-redacted, ≤ 1024 chars |
| `traceback_hash` | string | yes | `sha256:<hex>` of the traceback. Same crash collapses to the same hash so consumers can group recurrences without storing full tracebacks. |
| `session_id` | string \| null | yes | from Claude Code stdin if available |

Consumers tallying decisions MUST filter on `type == "decision"` (or absent)
so crash records don't pollute counters. The bundled `guard trace <session>`
surfaces `internal_error` records inline; `guard status` aggregates them as
`internal_errors_total`.

### 3.5 `permission_request` records

Claude Code emits a `PermissionRequest` hook event when it is about to
show the user a permission dialog (interactive permission modes only --
never in `dontAsk` / `bypassPermissions`). Guard observes these events
and appends a `permission_request` record. The hook never blocks: the
record is observation-only, and the prompt proceeds normally.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | always `"permission_request"` for this record shape |
| `v` / `schema_version` | int | yes | schema version (currently `1`) |
| `mode` | string | yes | guard's effective mode at request time (`"enforce"` / `"shadow"` / `"off"`); `"off"` short-circuits before logging |
| `timestamp` | string | yes | ISO-8601 UTC with microsecond precision |
| `session_id` | string | yes | Claude Code session id |
| `tool_name` | string | yes | tool about to be invoked (`"Bash"`, `"Edit"`, `"mcp__server__tool"`, ...) |
| `tool_input_excerpt` | string | yes | JSON-stringified `tool_input`, secret-shape-redacted, ≤ 4096 chars |
| `tool_use_id` | string | optional | unique id Claude Code assigns to the call, if present in the payload |
| `permission_mode` | string | optional | Claude Code permission mode string, if present in the payload |
| `cwd` | string | optional | working directory, if present in the payload |

`guard noisy` includes `permission_request` rows by default under the
synthetic bucket `(hook_id="permission_request", decision="<tool_name>")`
so operators see prompt frequency alongside deny frequency. Pass
`--no-prompts` to revert to decisions-only.

## 4. Schema versioning rules

- `v` (and `schema_version`) is a monotonic int, currently `1`.
- **Additive changes** (new optional fields) keep the version.
- **Breaking changes** (rename, removal, type change, semantic change) bump
  `v`. Any consumer relying on a renamed/removed field MUST add migration
  code before processing records with the new `v`.
- Consumers MUST tolerate **unknown fields** without erroring. Pin the fields
  you read; ignore the rest.
- Consumers MUST tolerate **unknown `v` values**: skip the record and emit a
  stderr warning (one line per unknown `v` is sufficient), do not crash. The
  bundled `JsonlReader` implements this; downstream consumers SHOULD match.
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
- Built-in reader: `src/guard/cli.py` — the `guard` CLI (`guard status`,
  `guard healthcheck`, `guard noisy`, `guard silent`, `guard trace`,
  `guard test`, `guard diff`, `guard allowlist *`, `guard migrate-log`).
- Path constant: `GUARD_DECISIONS_PATH` in `src/guard/_utils.py`.

## 9. See also

- `docs/output-format.md` — the v1.0 spec (superseded by this document).
- `README.md` — top-level guard documentation.
