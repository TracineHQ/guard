# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-04-30

First stable release. Guard ships seven stdlib-only `PreToolUse` hooks that
sit between Claude Code and the tool surface, denying high-risk actions
before they reach the host. The hook contract, decision-log schema, and
autonomous-mode behavior are now considered stable for the 1.x line.

### Added

- `bash_command_validator` — denies dangerous shell shapes (rm -rf,
  fork bombs, curl|sh, interpreter `-c` eval, runner-prefix bypasses).
- `git_c_validator` — blocks `git -c <key>=<val>` injection of executable
  config keys (alias.\*, core.pager, core.editor, filter.\*).
- `credential_check` — scans tool inputs for API keys, tokens, private
  keys, and provider-specific secret shapes before they leave the agent.
- `commit_message_validator` — rejects commit messages that leak
  AI-tool attribution markers (Co-Authored-By footers, generated-with
  notices, named tool branding).
- `agent_output_guard` — denies direct reads of dispatched-subagent
  output transcripts so context is preserved for the orchestrator.
- `protected_files` — forces an ASK confirmation on edits to guard's
  own validator files and to the Claude Code settings files that
  govern hook activation.
- `subagent_scope` — restricts what a dispatched subagent can read or
  modify based on a per-task allowlist.
- JSONL decision log (schema v1) at `~/.claude/guard-decisions.jsonl`
  for after-the-fact audit of every allow/deny.
- Autonomous-mode strict default-deny: when `CLAUDE_AUTONOMOUS=1` is set
  the hooks switch to fail-closed semantics for ambiguous inputs.

### Security

- Defense-in-depth posture: each hook is independent, and a deny from
  any hook short-circuits the tool call. See [SECURITY.md](SECURITY.md)
  for the threat model and reporting policy.
- Mitigates the class of agent-confusion bypasses tracked under
  CVE-2025-59356 by validating the literal command shape rather than
  trusting model-emitted intent.

[Unreleased]: https://github.com/tracinehq/guard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/tracinehq/guard/releases/tag/v1.0.0
