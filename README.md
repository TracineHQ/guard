# guard

Stdlib-only safety hooks for Claude Code.
Every decision is logged to JSONL — query and trace in place with `guard status|noisy|silent|trace`.

[![CI](https://img.shields.io/github/actions/workflow/status/TracineHQ/guard/ci.yml?branch=main&label=CI)](https://github.com/TracineHQ/guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)

```
$ rm -rf /
guard: deny - rm -rf against /, /*, ~, $HOME, ., or ./ is catastrophic.
```

Guardrails not walls: guard catches the obvious foot-guns at the Claude Code hook layer so a stray tool call doesn't turn into a bad day. It is defense-in-depth, not a security boundary.

## What it does

| Hook | What it catches |
|---|---|
| bash_command_validator | dangerous shell commands (rm -rf, eval/source, env-var hijack, shell-wrapper bypass) + admin-CLI default-deny for `aws`/`gcloud`/`az`/`kubectl`/`launchctl` (only read-only verbs pass) |
| git_c_validator | `git -C path` traversal, `git -c key=value` config injection, `git commit -C` silent message reuse |
| credential_check | hardcoded credentials in tool inputs |
| commit_message_validator | AI-attribution trailers (`Co-Authored-By: Claude…`) and missing/file-backed commit messages |
| agent_output_guard | reads of subagent transcript files (`/tmp/claude-<pid>/.../tasks/*.output`) |
| protected_files | edits to user-marked protected files |
| subagent_scope | file edits outside the declared `.claude/subagent-scope.json` allowlist |

## Install

Inside Claude Code:

```
/plugin marketplace add TracineHQ/plugins
/plugin install guard@tracine
```

This installs guard from the unified [TracineHQ plugin catalog](https://github.com/TracineHQ/plugins). The same marketplace also hosts [convo](https://github.com/TracineHQ/convo); once the marketplace is registered you can install either with one command.

Standalone alternative (skip the catalog and install guard directly from this repo):

```
/plugin marketplace add TracineHQ/guard
/plugin install guard@tracinehq
```

`TracineHQ/guard` is the GitHub `owner/repo` shorthand for the marketplace source. `guard@tracinehq` is the `<plugin>@<marketplace>` reference Claude Code uses to install. To pin a specific tag:

```
/plugin marketplace add TracineHQ/guard#v1.3.0
```

### Requirements

- Claude Code v2.0.0+ (plugins entered public beta on 2025-10-09)
- Python 3.11+ available on `python3` PATH (no third-party dependencies)
- POSIX shell environment (Linux, macOS, WSL). Windows is not supported in v1 — the matchers target POSIX shell shapes (`rm -rf`, `cat ~/.aws/credentials`, process substitution) and offer no meaningful protection against PowerShell or `cmd.exe` equivalents. CI runs on `ubuntu-latest` and `macos-latest`.

### Optional: power-user CLI

The marketplace install above wires up the safety hooks. To query the decision log without `tail | jq`, install the read-side CLI from PyPI:

```
pipx install tracine-guard
```

Then `guard status` shows the log location and last record, `guard noisy --since 24h` ranks rules by hit count, `guard trace <session_id>` dumps a chronological view, and `guard silent` lists rules that fired historically but not recently. Query subcommands are read-only against `~/.claude/guard-decisions.jsonl`; `guard allowlist *` writes to your allowlist file (project or `--global`). The two install paths complement each other; they aren't alternatives.

## Configuration

Guard reads a small set of environment variables. See [SKILL.md](SKILL.md) for the canonical descriptions and defaults.

Strict default-deny activates from Claude Code's `permission_mode` field in
PreToolUse hook input (no env var). The strict modes are `auto` (Anthropic's
classifier-mediated unattended mode), `dontAsk`, and `bypassPermissions` --
all three imply "no human at the prompt." Other modes (`default`, `plan`,
`acceptEdits`) use advisory evaluation.

**Requirements:** Claude Code that emits `permission_mode` on PreToolUse
payloads (current Claude Code releases do; older builds default to advisory
since the field is absent). For one minor cycle, a deprecated
`CLAUDE_AUTONOMOUS=1` env var fallback escalates to `dontAsk` with a stderr
warning -- remove the env var before the next minor release.

**Healthcheck:** `guard healthcheck` exits 0 on healthy, non-zero on
failure. Suitable for CI gates and cron-based monitors.

| Variable | Purpose |
|---|---|
| `GUARD_DECISIONS_PATH` | Override the JSONL decision-log path |
| `GUARD_STRICT_DENY_QUEUE_PATH` | Override the strict-deny queue path |
| `GUARD_DEBUG` | Emit per-hook debug to stderr |
| `GUARD_DATA_DIR` | Override guard's data directory |
| `GUARD_PROTECTED_EXTRA` | Comma-separated extra protected glob patterns (fallback when `~/.claude/guard-protected.txt` is absent) |
| `GUARD_ADMIN_ALLOW_VERBS` | Per-verb allow for `bash.admin_default_deny`; format `<cli>:<verb.path>,<cli>:<verb.path>` (e.g. `aws:ec2.run-instances,gcloud:functions.deploy`) |

**Catalog model (AWS):** the admin matcher uses an explicit `(service, verb)` allowlist for `aws`. Verbs not in the catalog deny by default. To rescue a long-tail verb without a code change, set `GUARD_ADMIN_ALLOW_VERBS="aws:<service>.<verb>"` (see [SECURITY.md](SECURITY.md) for the decision tree and the list of deliberately-excluded verbs).

To disable an individual hook, remove its entry from `~/.claude/settings.json` PreToolUse, or comment the line in `hooks/hooks.json` if you forked the plugin.

## What it doesn't do

- Not a security boundary. A determined attacker who controls input to Claude Code can bypass any client-side hook.
- Defense-in-depth, not an exclusive safety mechanism.
- Logs decisions for observability; doesn't enforce server-side.

## Output log

Every decision is appended to `~/.claude/guard-decisions.jsonl` (NDJSON, one record per line). The schema is stable and documented in [docs/JSONL_FORMAT.md](docs/JSONL_FORMAT.md).

Tail and pretty-print:

```
tail -f ~/.claude/guard-decisions.jsonl | jq
```

Or use the built-in `guard` CLI for read-side queries:

```
guard status               # installation status + log location + line count
guard noisy --since 7d     # top hit rules in the last week
guard silent --since 30d   # rules that haven't fired in 30 days
guard trace <session-id>   # all records for a single session
guard test "<command>"     # what would each hook decide?
guard diff                 # effective merged config (stub)
```

## Development

```
just check
```

Runs lint, typecheck, and tests. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, test tiers, and commit conventions.

## Known limitations

Guard is defense-in-depth, not a security boundary. The validators trade exhaustive coverage for low false-positive rates and stdlib-only portability, which means a determined attacker who controls Claude Code's input can bypass any client-side hook. Pattern-matching is conservative on purpose: rules deny shapes that have a clear safer alternative and pass shapes that are ambiguous. For the threat model, the disclosure process, and a list of areas guard explicitly does not cover, see [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
