---
name: guard
description: Configure guard's safety hooks and explain what each hook catches — bash command validation (rm -rf, force-push, interpreter eval, shell wrappers, pipe-to-shell), git safety (-c config injection, core.hooksPath/attributesFile, destructive flags), credential scanning, commit-message rules, protected files, agent output, subagent scope.
when_to_use: When the user asks to enable/disable a guard hook, change the decision log path, switch guard mode (enforce / shadow / off / lockdown), troubleshoot guard's output, or asks "why did guard block X" / "what does <hook> catch".
---

# Guard configuration

Guard is a safety-hook plugin for Claude Code. It runs before tool calls and writes
decisions to `~/.claude/guard-decisions.jsonl`.

## What hooks catch

`docs/dangerous-commands.md` and `docs/hooks-reference.md` are the
authoritative references. Quick map:

- `bash_command_validator` — `rm -rf` against `/`, `/*`, `~`, `$HOME`;
  force-push (`--force`, `-f`, `--force-with-lease`, `+refspec`); inline
  interpreter code (`python -c`, `node -e`/`-p`, `perl -pe`, `php -r`,
  `python - <<EOF`, `pypy`, `bun`, `deno`, plus runner wrappers
  `uvx`/`pipx`/`uv run`; script and `-m` module runs are left to Claude
  Code's permission flow); shell wrappers (`bash -c`, `sh -lc`); `eval`/`source`/`.`;
  dangerous env-var sinks (`GIT_SSH_COMMAND`, `LD_PRELOAD`, etc.); pipe-to-shell
  (`curl ... | sh`); credential leaks (`gh auth token`, `aws sts get-session-token`);
  **admin-CLI default-deny** for `aws`, `gcloud`, `az`, `kubectl`, `launchctl` —
  only verbs whose `(service, verb)` tuple is in the read-only catalog pass;
  everything else denies with `bash.admin_default_deny`. AWS uses the
  strict-allowlist model (no prefix shortcut); see SECURITY.md for the
  decision tree. Override per-command via `allow_commands`, per-rule via
  `disable_rules`, or per-verb via
  `GUARD_ADMIN_ALLOW_VERBS=aws:ec2.run-instances,gcloud:functions.deploy`.
- `git_c_validator` — `git -c core.hooksPath=...` and `core.attributesFile=...`
  denied regardless of value; `git -c alias.x='!cmd'` and other config-exec
  sinks; `git commit -C <ref>` and `--reuse-message` (silent message reuse);
  destructive flags under `git -C` (`branch -d/-D/-m`, `tag -d`, `remote
  remove/rename/set-url`).
- `commit_message_validator` — AI-attribution trailers in commit messages
  (`Co-Authored-By: Claude`, `Generated with Claude Code`); also denies
  opaque message sources (`-F <stream>`, `--file=-`, paths outside cwd).
- `credential_check` — secret patterns in Edit/Write/Bash payloads.
- `protected_files` — Edit/Write (and Bash writes) to guard's own hook code,
  `.claude/guard/allowlist.json` and `.claude/subagent-scope.json`; lockdown
  adds `.git/hooks`, `CLAUDE.md`, `.cursorrules`, MCP config and
  `.aws/config` (extensible via `GUARD_PROTECTED_EXTRA` and
  `.claude/guard-protected.txt`). Reads never trip it.
- `agent_output_guard` — denies tool calls whose input references a Claude
  Code subagent transcript (`/tmp/claude-<uid>/.../tasks/<id>.output` that
  links into `subagents/` or holds transcript JSONL), or a wildcard under
  `tasks/`. Background Bash command output in the same directory stays
  readable.
- `subagent_scope` — file edits outside the declared `.claude/subagent-scope.json` allowlist.

## Deny, never ask

Guard never emits an `ask`. Every block is a deny whose reason steers the
agent: what was blocked, why, and what to do instead (usually stop and tell
the user, with the command or `guard allowlist` override they can run).

## Modes

`guard mode <enforce|shadow|off|lockdown>` (project by default, `--global`
for the per-user file). Every hook honors it.

- `enforce` (default) -- deny what matches, pass the rest through.
- `shadow` -- log would-be denies with `mode: "shadow"`; only trust-root denies block.
- `off` -- hooks go quiet, except edits to guard's own code and allowlist.
- `lockdown` -- opt-in strict default-deny for driven or unattended agents.
  Any Bash command not on the safe-prefix allowlist is denied with a
  `STRICT_FEEDBACK` message, and `protected_files` adds its lockdown list.
  Claude Code's `permission_mode` (`auto`, `dontAsk`, `bypassPermissions`)
  never turns it on.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GUARD_DECISIONS_PATH` | Override the JSONL decision-log path | `~/.claude/guard-decisions.jsonl` |
| `GUARD_STRICT_DENY_QUEUE_PATH` | Override the strict-deny queue path | `~/.claude/guard-strict-deny-queue.jsonl` |
| `GUARD_DEBUG` | Set to `1` to emit per-hook debug to stderr | unset |
| `GUARD_DATA_DIR` | Override the directory containing guard's data files | `~/.claude/guard` |
| `GUARD_PROTECTED_EXTRA` | Comma-separated extra patterns for `protected_files`. See below. | unset |
| `GUARD_ADMIN_ALLOW_VERBS` | Per-verb allow for `bash.admin_default_deny`; format `<cli>:<service>.<verb>,<cli>:<service>.<verb>` (e.g. `aws:logs.tail,gcloud:functions.deploy`) | unset |

## Extending protected_files patterns

`protected_files` ships with a built-in pattern list (guard's own code and allowlist, plus `.git/hooks`, `CLAUDE.md` and friends under lockdown). Projects with their own kill-switch / doctrine paths can extend that list two ways without forking:

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

If the file exists, it is the source of truth — the env var is ignored. If the file is absent, the env var is read. Pattern syntax matches the built-in list — segment match for directory names (last segment with no `.`), suffix match for files. No new grammar.

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
      "command": "/repo/src/guard/registry.py",
      "reason": "intentional registry update for the release"
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
guard allowlist disable-rule <rule-id>
guard allowlist enable-rule <rule-id>
guard allowlist allow-command --rule <rule-id> --command "<cmd>" --reason "..."
guard allowlist remove-command --rule <rule-id> --command "<cmd>"
```

Mutation commands write to the project allowlist by default. Pass `--global` to write the per-user file at `~/.claude/guard/allowlist.json` instead (or `--project` to be explicit; the two flags are mutually exclusive).

### Trust-root: un-overridable protections

`.claude/guard/allowlist.json` is NOT allowlist-bypassable. Even with `disable_rules: ["guard.protected_files"]` or an exact-path `allow_commands` entry, agent edits to it are denied: an allowlist that lets agents edit the allowlist grants itself anything. Edit it yourself or through `guard allowlist`.

Guard's own hook code and `.claude/subagent-scope.json` stay protected in every mode, `off` included, but you can allowlist them like any other protected file.

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
- `guard healthcheck` — synthesise a known-deny payload and assert deny (exit 0 = healthy; suitable for CI gates and cron monitors).
- `guard noisy --since 24h` — top rules by hit count in a time window.
- `guard silent --since 30d` — rules that fired historically but not recently.
- `guard trace <session_id>` — chronological dump for one session.
- `guard test "<command>"` — in-process invocation of every bash-surface hook against one or more commands.
- `guard diff` — effective merged config (stub).
- `guard migrate-log` — one-shot rewrite of the JSONL log to schema v1 (idempotent; writes a sibling `.bak.<timestamp>` by default).

Without the CLI, the log is plain JSONL and works with anything that reads stdin: `tail -f ~/.claude/guard-decisions.jsonl | jq`.

See `docs/output-format.md` for the JSONL schema (v1).

## Reporting issues

See `SECURITY.md` for vulnerability reports. For non-security bugs, open an issue at <https://github.com/TracineHQ/guard/issues>.
