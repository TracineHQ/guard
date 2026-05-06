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
