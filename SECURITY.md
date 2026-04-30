# Security policy

## Supported versions

The latest minor release receives security fixes. The v1.0.x line is the
current supported series.

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Use GitHub Private Vulnerability Reporting:

> <https://github.com/tracinehq/guard/security/advisories/new>

Please include:

- A description of the issue and its impact.
- Reproduction steps (commands, inputs, environment).
- Affected version (`/plugin list` inside Claude Code).
- Contact info for follow-up.

## Response targets

- **Acknowledgement:** within 72 hours of report.
- **High-severity fix:** within 30 days of triage.
- **Coordinated disclosure:** roughly a 7-day public-update window after the
  fix lands, to give users time to upgrade before details become public.

## Threat model

Guard runs as a PreToolUse hook. Its inputs are attacker-influenceable: a
malicious prompt, an MCP tool response, or a poisoned `CLAUDE.md` in a repo
the user opens can drive the tool calls guard sees.

The validators are written with that in mind:

- Guard receives attacker-influenceable JSON (malicious prompts, MCP tools,
  repo CLAUDE.md drive tool calls).
- Validators MUST not eval/exec/shell-out input verbatim.
- Bounded JSON parse size (~1 MiB stdin cap).
- Path operations restricted to read-only inside `~/.claude/`.
- Regex compiled with no nested quantifiers (ReDoS resistance).

## CVE-2025-59356 reference

Claude Code's hooks system was the subject of CVE-2025-59356, a hook-RCE
issue where a malicious project-side hook config could execute on project
open. Anthropic fixed this at the Claude Code platform level via a trust
dialog. Guard inherits that protection. Guard's validators are themselves
hardened against malicious tool inputs to avoid being a foothold.

## Guardrails, not walls

Guard is defense-in-depth, not a security boundary. A motivated attacker
who controls Claude Code's input can bypass any client-side hook, and a
motivated user can disable any hook in settings. Treat guard's decision log
as an observability signal, not an enforcement guarantee. Server-side
controls (CI policy, branch protection, secret scanners) remain the
authoritative line of defense.
