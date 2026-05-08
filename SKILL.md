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

## Allowlist (per-rule disable + per-command override)

When guard's default policy is too strict for a specific command or file, the allowlist lets you turn off a rule by id, or allow one exact command, without forking the plugin.

### File locations

Both files use the same JSON schema; the project file wins on per-rule conflicts.

- **Project**: `.claude/guard/allowlist.json` (rooted at the working directory — committable to the repo).
- **Global**: `~/.claude/guard/allowlist.json` (per-user, applies to every project).

### Schema

```json
{
  "disable_rules": ["bash.disk_destruction"],
  "allow_commands": [
    {
      "rule": "guard.protected_files",
      "command": "/repo/CLAUDE.md",
      "reason": "intentional CLAUDE.md update for the rebrand task"
    }
  ]
}
```

- `disable_rules` — list of rule ids that bypass entirely. Use `guard allowlist rules` to see all known ids. The bash hook uses ids like `bash.disk_destruction`, `bash.git_history_destruction`. Other hooks use the hook id itself (`guard.protected_files`, `guard.commit_message_validator`, etc.).
- `allow_commands` — exact-string match. The `command` is matched against the bash command (for `bash_command_validator`) or the file path (for `protected_files`). `reason` is required and gets logged on every bypass.

### CLI

```
guard allowlist list                                 # show effective merged config
guard allowlist rules                                # all known rule ids
guard allowlist disable-rule <rule-id> --reason "..."
guard allowlist enable-rule <rule-id>
guard allowlist allow-command <rule-id> <command> --reason "..."
guard allowlist remove-command <rule-id> <command>
```

All mutation commands take `--scope project|global` (default: `project`).

### Trust-root: un-overridable protections

Three paths under `protected_files` are NOT allowlist-bypassable. Even with `disable_rules: ["guard.protected_files"]` or an exact-path `allow_commands` entry, edits to these always go through ASK:

- `.claude/guard/allowlist.json` — the allowlist itself (writes here would let an attacker grant themselves further overrides).
- `.claude/settings.json`, `.claude/settings.local.json` — Claude Code wiring (writes here could remove guard's hooks entirely).

Other protected files (your `CLAUDE.md`, `.cursorrules`, etc.) are user-overridable through the normal mechanisms.

### Audit trail

Every allowlist bypass is logged as a `decision="pass"` record with the bypass reason, so you can grep the audit log to see which rules were silenced and why.

## Disabling individual hooks entirely

Prefer the allowlist (above) when you only need to silence a specific rule or command. To remove a whole hook from the harness, delete its entry from `~/.claude/settings.json` PreToolUse, or comment out the corresponding line in `<plugin>/hooks/hooks.json` if you forked.

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
