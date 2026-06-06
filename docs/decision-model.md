# How guard decides

A mental model for *why* a command was allowed, asked, or denied -- and which
override fits. If you hit a deny and want the fastest correct next step, jump to
[Responding to a deny](#responding-to-a-deny).

## Two layers, in order

Every Bash command passes guard first, then Claude Code's own permission system.
Guard's verdict decides whether Claude Code's layer even runs:

| Guard returns | Claude Code then | Command runs? |
|---|---|---|
| **deny** | nothing -- hard stop | no |
| **ask** | prompts the human | only if approved |
| **allow** | auto-approves (skips its own prompt) | yes |
| **passthrough** | applies its *own* allow/ask/deny rules + mode | depends on Claude Code |

The thing people miss: **passthrough is not "run."** It means guard abstains and
Claude Code's native rules take over -- which for an un-allowlisted command
usually asks the human.

## Permission modes: strict vs interactive

Guard reads Claude Code's `permission_mode` from the hook payload and splits it
two ways:

- **Strict** -- `auto`, `dontAsk`, `bypassPermissions`. No human at the prompt.
  Guard runs **default-deny**: anything not explicitly recognized as safe is
  denied, because there is no one to ask.
- **Interactive** -- `default`, `plan`, `acceptEdits`. A human is reachable.
  Guard is advisory: it denies the genuinely dangerous, asks on elevated risk,
  and otherwise passes through to Claude Code's prompt.

So the *same* command can pass through in interactive mode and default-deny in
strict mode. The friction surface is the allow side, not the deny matchers.

## The decision tiers

`decide()` runs these top to bottom; first hit wins. "Floor" means it denies in
**both** modes.

| Tier | What it catches | Interactive | Strict |
|---|---|---|---|
| Credential leak / secret value | `gh auth token`, inline secrets | deny | deny |
| **Floor: always-deny** | `rm -rf /`, interpreter-exec, shell wrappers, git config injection | **deny** | **deny** |
| Dangerous construct | `$(...)`, backticks, redirect to sensitive paths | deny | deny |
| Elevated-risk **ask tier** | host control, registry redirection, non-sudo escalation | **ask** | deny |
| Strict default-deny | everything not on a safe-prefix | (skip) | **deny** |
| Interactive fall-through | no match | passthrough | (skip) |

Two consequences worth internalizing:

- The **floor is above the ask tier.** No permission mode turns a floor deny into
  an "are you sure?" -- switching to `acceptEdits` will not make it ask.
- The **ask tier only exists in interactive mode.** In strict mode those same
  shapes deny (no human to ask).

## Three kinds of deny

1. **Floor** -- denies in both modes, by capability. `rm -rf /`,
   interpreter-exec, shell wrappers. Not "are you sure?" -- a refusal.
2. **Default-deny** -- strict mode only. The command is not *known dangerous*,
   it's just not on the safe list and there's no human to confirm. Re-run
   interactively, or register it.
3. **Ask** -- interactive only. Surfaced to the human; not blocked.

## Why interpreter-exec is a floor

Guard sees the command line, never the script's bytes. `python3 deploy.py` could
do anything -- and an agent can *write* `deploy.py` first, then run it past every
command-level matcher. So an interpreter running an opaque payload is
RCE-equivalent, and it's a floor deny rather than an ASK. This covers eval flags
(`-c`/`-e`), arbitrary `-m <module>` (a small stdin/stdout-only set like
`json.tool` / `venv` is exempt), bare script paths, and the wrapped runners
(`uv run python x.py`, `uvx python -c ...`).

## Overrides: which knob for which situation

| Knob | Scope | Safe? | Use when |
|---|---|---|---|
| `disable_rules` | a whole rule id | blunt -- turns the rule off everywhere | a matcher is wrong for your whole project |
| `allow_commands` | one **exact** command string | exact-match, so it can't drift | a specific, fixed command you re-run verbatim |
| **`trusted_scripts`** (`guard trust-script`) | a script's **bytes** | content-pinned | a vetted script you re-run with varying operands |
| safe-prefix (registry) | a first-party read-only tool | derived + tested | (maintainers only -- not user config) |

`allow_commands` is exact, so it does **not** cover a script you run with
different arguments each time (`scan.py email-1.md`, then `scan.py email-2.md`).
That is what `trusted_scripts` is for.

Both `allow_commands` and `trusted_scripts` are explicit human grants, so they
work in strict mode too. The allowlist files (`.claude/guard/allowlist.json`,
project + global) are themselves protected: writes to them route through ASK and
can't be allowlisted away.

## Trusted scripts (content-pinning)

For a script you've read and re-use, a human content-pins it:

```
guard trust-script scripts/scan.py --reason "weekly inbox scan"
```

This records the sha256 of the file's *current* bytes. Then:

- `python3 scripts/scan.py <anything>` is allowed -- operands vary freely,
  because the **script** is pinned, not the command line.
- Editing the script changes its hash and **revokes** the trust automatically;
  re-pin after you've re-read it.
- Eval forms (`python3 -c '...'`) and `-m <module>` have no file to pin, so they
  are never trust-rescuable.
- Granting is a human action. The command is not on any safe-prefix (so an
  unattended agent default-denies it) and the trust store is a protected file
  (so an agent can't write the grant directly). Trust to specific bytes is the
  only override that is both safe *and* survives varying operands.

## Responding to a deny

For agents that just got a deny:

- **Floor / interpreter deny in interactive mode** -- don't retry variants and
  don't reach for `disable_rules`. If it's a vetted script you re-run, tell the
  human the exact `guard trust-script <path> --reason '...'` to run, explain what
  the rule protects against, and wait for them to grant it.
- **Strict mode** -- you can't override unattended. Surface the deny (with the
  suggested `guard trust-script` line if it's a script) for the operator's later
  review, and move on.
- **Ask** -- it's already going to the human. Explain why guard flagged it,
  prefer a safer form if one accomplishes the goal, and let them answer.

The deny message itself names the rule id and the override that fits. Read it
before acting -- it is the fastest path, and it is mode-aware.
