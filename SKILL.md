---
name: guard
description: Configure guard's safety hooks and explain what each hook catches — bash command validation (rm -rf, force-push, interpreter eval, shell wrappers, pipe-to-shell), git safety (-c config injection, core.hooksPath/attributesFile, destructive flags), credential scanning, commit-message rules, protected files, agent output, subagent scope.
when_to_use: When the user asks to enable/disable a guard hook, change the decision log path, switch guard mode (enforce / shadow / off), troubleshoot guard's output, or asks "why did guard block X" / "what does <hook> catch".
---

# Guard configuration

Guard is a safety-hook plugin for Claude Code. It runs before tool calls and writes
decisions to `~/.claude/guard-decisions.jsonl`.

## What hooks catch

`docs/dangerous-commands.md` and `docs/hooks-reference.md` are the
authoritative references. Quick map:

- `bash_command_validator` — `rm -rf` against `/`, `/*`, `~`, `$HOME`;
  force-push (`--force`, `-f`, `--force-with-lease`, `+refspec`, `--mirror`);
  inline programs guard can't read (`python3 -c "$CODE"`, a program piped
  in or evaluating stdin; a literal `python3 -c '...'` passes); a `bash -c`
  string guard can't read (empty, `{}`, `"$X"`); `eval`; pipe-to-shell
  (`curl ... | sh`); credential leaks (`gh auth token`, `aws sts get-session-token`);
  payloads hidden in `$(...)`, `bash -c` strings, function bodies and `trap`
  handlers, each checked as a command;
  **admin-CLI default-deny** for `aws`, `gcloud`, `az`, `kubectl`, `launchctl` —
  only verbs whose `(service, verb)` tuple is in the read-only catalog pass;
  everything else denies with `bash.admin_default_deny`. AWS uses the
  strict-allowlist model (no prefix shortcut); see SECURITY.md for the
  decision tree. Override per-rule via `disable_rules`, or per-verb via
  `GUARD_ADMIN_ALLOW_VERBS=aws:ec2.run-instances,gcloud:functions.deploy`.
- `git_c_validator` — `git -c core.hooksPath=...` and `core.attributesFile=...`
  denied regardless of value; `git -C` read verbs that run a program or write
  a file (`log --output=`, `fetch --upload-pack` / `--exec` / `ext::`).
- `commit_message_validator` — AI-attribution trailers in commit messages
  (`Co-Authored-By: Claude`, `Generated with Claude Code`); also denies
  opaque message sources (`-F <stream>`, `--file=-`, paths outside cwd).
- `credential_check` — secret patterns in Edit/Write/Bash payloads.
- `protected_files` — Edit/Write (and Bash writes) to guard's own hook code,
  meaning the install that's running (matched by real path, so a clone or
  worktree of guard's source stays editable),
  `.claude/guard/allowlist.json` and `.claude/subagent-scope.json`
  (extensible via `GUARD_PROTECTED_EXTRA` and
  `.claude/guard-protected.txt`). Reads never trip it.
- `agent_output_guard` — denies tool calls whose input references a Claude
  Code subagent transcript (`/tmp/claude-<uid>/.../tasks/<id>.output` that
  links into `subagents/` or holds transcript JSONL), or a wildcard under
  `tasks/`. Background Bash command output in the same directory stays
  readable.
- `subagent_scope` — file edits outside the declared `.claude/subagent-scope.json` allowlist.

## Deny, never ask, never allow

Guard never emits an `ask` or an `allow`. Every block is a deny whose reason
tells the agent what was blocked, why, and what to do instead (usually stop
and tell the user, with the command or `guard allowlist` override they can
run). Everything else gets no decision from guard and goes on to Claude
Code's own permission step, auto mode's classifier included.

## Modes

`guard mode <enforce|shadow|off>` writes `~/.claude/guard/allowlist.json`.
Every hook honors it.

- `enforce` (default) -- deny what matches, pass the rest through.
- `shadow` -- log would-be denies with `mode: "shadow"`; only trust-root denies block.
- `off` -- hooks go quiet, except edits to the running guard's code and allowlist.

`lockdown` is retired: an allowlist that still names it warns once and runs
as `enforce`.

Claude Code's `permission_mode` (`default`, `auto`, `acceptEdits`, ...) is
logged and never changes a decision. The rules are in
`docs/dangerous-commands.md`.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GUARD_DECISIONS_PATH` | Override the JSONL decision-log path | `~/.claude/guard-decisions.jsonl` |
| `GUARD_DEBUG` | Set to `1` to emit per-hook debug to stderr | unset |
| `GUARD_DATA_DIR` | Override the directory containing guard's data files | `~/.claude/guard` |
| `GUARD_PROTECTED_EXTRA` | Comma-separated extra patterns for `protected_files`. See below. | unset |
| `GUARD_ADMIN_ALLOW_VERBS` | Verbs `bash.admin_default_deny` lets pass; format `<cli>:<service>.<verb>,<cli>:<service>.<verb>` (e.g. `aws:logs.tail,gcloud:functions.deploy`) | unset |

## Extending protected_files patterns

`protected_files` ships with a built-in pattern list (the running guard's code and allowlist). Projects with their own kill-switch / doctrine paths can extend that list two ways without forking:

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

Both apply: the file's patterns and the env var's add up, so a repo's file can't drop yours. Pattern syntax matches the built-in list: segment match for directory names (last segment with no `.`), suffix match for files. No new grammar.

The patterns resolve at hook-call time, so live edits take effect on the next tool call without restarting Claude Code.

## Allowlist (per-rule disable)

One per-user file, `~/.claude/guard/allowlist.json` (`GUARD_DATA_DIR` moves it), with two keys:

```json
{
  "mode": "enforce",
  "disable_rules": ["bash.disk_destruction"]
}
```

- `mode`: see [Modes](#modes).
- `disable_rules`: rule ids that never deny. `guard allowlist rules` lists them. The bash hook uses ids like `bash.disk_destruction`; other hooks use the hook id itself (`guard.protected_files`, `guard.commit_message_validator`, etc.).

There is no per-command exemption, and a repo can't change `mode` or `disable_rules`. A rule that blocks legitimate work is a bug in the rule: fix the rule, or report it, instead of exempting the command.

### Retired keys

Older versions also read `allow_commands` (exact-command exemptions) and a per-repo `.claude/guard/allowlist.json`. Guard ignores both now; they grant nothing. The first time a hook process meets one it prints a line to stderr naming it. Delete the key or the file to quiet it.

### CLI

```
guard allowlist list                     # disabled rules and the file they come from
guard allowlist rules                    # all known rule ids
guard allowlist disable-rule <rule-id>
guard allowlist enable-rule <rule-id>
```

Both mutations write the global file.

### Trust-root: un-overridable protections

`.claude/guard/allowlist.json` is NOT allowlist-bypassable. Even with `disable_rules: ["guard.protected_files"]`, agent edits to it are denied: an allowlist that lets agents edit the allowlist grants itself anything. Edit it yourself or through `guard allowlist` / `guard mode`.

The running guard's code and `.claude/subagent-scope.json` stay protected in every mode, `off` included. `disable_rules: ["guard.protected_files"]` lifts that along with the rest of the hook.

### Audit trail

Every disabled-rule bypass is logged with a reason naming the rule, so you can grep the audit log to see which rules were silenced.

## Disabling individual hooks entirely

Prefer `disable_rules` (above) when you only need to silence one rule. To remove a whole hook from the harness, delete its entry from `~/.claude/settings.json` PreToolUse, or comment out the corresponding line in `<plugin>/hooks/hooks.json` if you forked.

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
