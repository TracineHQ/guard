---
name: guard
description: Configure guard's safety hooks (env vars, log path, individual disable).
when_to_use: When the user asks to enable/disable a guard hook, change the decision log path, set advisory mode, or troubleshoot guard's output.
---

# Guard configuration

Guard is a safety-hook plugin for Claude Code. It runs before tool calls and writes
decisions to `~/.claude/guard-decisions.jsonl`.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `CLAUDE_AUTONOMOUS` | Set to `1` for strict default-deny in subagents / driven runs | unset (interactive mode) |
| `GUARD_DECISIONS_PATH` | Override the JSONL decision-log path | `~/.claude/guard-decisions.jsonl` |
| `GUARD_AUTONOMOUS_QUEUE_PATH` | Override the autonomous-deny queue path | `~/.claude/guard-autonomous-queue.jsonl` |
| `GUARD_DEBUG` | Set to `1` to emit per-hook debug to stderr | unset |
| `GUARD_DATA_DIR` | Override the directory containing guard's data files | `~/.claude/guard` |
| `GUARD_PROTECTED_EXTRA` | Comma-separated extra patterns for `protected_files`. See below. | unset |

## Extending protected_files patterns

`protected_files` ships with a built-in pattern list (`.git/hooks`, `.claude/settings.json`, `CLAUDE.md`, etc.). Projects with their own kill-switch / doctrine paths can extend that list two ways without forking:

1. **Env var** `GUARD_PROTECTED_EXTRA="bin,standards,dispatch"` — comma-separated. Whitespace trimmed; blank entries skipped.
2. **Project file** `.claude/guard-protected.txt` (rooted at the working directory):
   ```
   # tracine-ops doctrine paths
   bin
   standards
   dispatch
   CLAUDE.md
   SECURITY.md
   ```
   One pattern per line; `#` starts a comment to end of line; blank lines OK.

When **both** are set, the file wins (more deliberate artifact). Pattern syntax matches the built-in list — segment match for directory names (last segment with no `.`), suffix match for files. No new grammar.

The patterns resolve at hook-call time, so live edits take effect on the next tool call without restarting Claude Code.

## Disabling individual hooks

Remove the hook's entry from `~/.claude/settings.json` PreToolUse, or comment out the corresponding line in `<plugin>/hooks/hooks.json` if you forked.

## Log inspection

Install the read-side CLI from PyPI for ergonomic queries:

```
pipx install tracine-guard
```

Then:
- `guard status` — log location and last record summary.
- `guard noisy --since 24h` — top rules by hit count in a time window.
- `guard silent --since 7d` — rules that fired historically but not recently.
- `guard trace <session_id>` — chronological dump for one session.

Without the CLI, the log is plain JSONL and works with anything that reads stdin: `tail -f ~/.claude/guard-decisions.jsonl | jq`.

See `docs/output-format.md` for the JSONL schema (v1).

## Reporting issues

See `SECURITY.md` for vulnerability reports. For non-security bugs, open an issue at <https://github.com/TracineHQ/guard/issues>.
