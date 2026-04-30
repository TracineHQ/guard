# guard

Stdlib-only safety hooks for Claude Code.

[![CI](https://img.shields.io/github/actions/workflow/status/tracinehq/guard/ci.yml?branch=main&label=CI)](https://github.com/tracinehq/guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)

Guardrails not walls: guard catches the obvious foot-guns at the Claude Code hook layer so a stray tool call doesn't turn into a bad day. It is defense-in-depth, not a security boundary.

## What it does

| Hook | What it catches |
|---|---|
| bash_command_validator | dangerous shell commands (rm -rf, fork bombs, ...) |
| git_c_validator | `git commit -C` (silent message reuse) |
| credential_check | hardcoded credentials in tool inputs |
| commit_message_validator | malformed/missing commit messages |
| agent_output_guard | oversized raw-data reads in subagent output |
| chrome_safety_validator | dangerous chrome operations (auth-required tabs) |
| protected_files | edits to user-marked protected files |
| subagent_scope | subagent edits outside declared scope |

## Install

```
/plugin marketplace add tracinehq/guard
/plugin install guard@tracinehq
```

`tracinehq/guard` is the GitHub `owner/repo` shorthand for the marketplace source. `guard@tracinehq` is the `<plugin>@<marketplace>` reference Claude Code uses to install. To pin a specific tag:

```
/plugin marketplace add tracinehq/guard#v1.0.0
```

### Requirements

- Claude Code v2.0.0+ (plugins entered public beta on 2025-10-09)
- Python 3.11+ available on `python3` PATH (no third-party dependencies)

## Configuration

Guard reads a small set of environment variables. See [SKILL.md](SKILL.md) for the canonical descriptions and defaults.

| Variable | Purpose |
|---|---|
| `CLAUDE_AUTONOMOUS` | Strict default-deny in subagents / driven runs |
| `GUARD_DECISIONS_PATH` | Override the JSONL decision-log path |
| `GUARD_AUTONOMOUS_QUEUE_PATH` | Override the autonomous-deny queue path |
| `GUARD_DEBUG` | Emit per-hook debug to stderr |
| `GUARD_DATA_DIR` | Override guard's data directory |

To disable an individual hook, remove its entry from `~/.claude/settings.json` PreToolUse, or comment the line in `hooks/hooks.json` if you forked the plugin.

## What it doesn't do

- Not a security boundary. A determined attacker who controls input to Claude Code can bypass any client-side hook.
- Defense-in-depth, not an exclusive safety mechanism.
- Logs decisions for observability; doesn't enforce server-side.

## Output log

Every decision is appended to `~/.claude/guard-decisions.jsonl` (NDJSON, one record per line). The schema is stable and documented in [docs/output-format.md](docs/output-format.md).

Tail and pretty-print:

```
tail -f ~/.claude/guard-decisions.jsonl | jq
```

## Optional dependencies

- `chrome_cli` — when installed, `chrome_safety_validator` uses its shared safety patterns for richer `chrome eval` / `chrome fetch` checks. Without it, the hook degrades gracefully and `ask` rules in settings still apply.

## Development

```
just check
```

Runs lint, typecheck, and tests. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, test tiers, and commit conventions.

## License

Apache 2.0 — see [LICENSE](LICENSE).
