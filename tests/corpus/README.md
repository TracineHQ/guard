# Bash-matcher fixture corpus

This directory is the **single source of truth** for command shapes guard's bash
matcher must classify a particular way. One row = one fixture. Two consumers read
these same files through `guard._corpus`:

- **`guard corpus`**: the CLI runner. It loads every `*.jsonl` here, runs
  `decide()` over each row in one process, and exits non-zero on any mismatch.
  Agents (and humans) run this instead of spraying ad-hoc `guard test '<cmd>'`
  strings, which are lost the moment the shell call returns.
- **`tests/integration/test_corpus_fp_rate.py`** — the CI fence. It parametrizes
  over the same rows and enforces a 0% false-positive / false-negative ratchet.

The harness is wired into both gates so a bad fixture cannot merge:

- **CI** runs a dedicated `Bash-matcher fixture corpus` job (`uv run guard corpus`)
  on every push and PR, alongside the full pytest suite.
- **pre-commit** runs `guard corpus` whenever a `tests/corpus/*.jsonl` fixture or
  the bash matcher / registry / corpus engine changes.

A newly found bypass or false positive becomes a one-line row here and both the
runner and CI pick it up automatically. No code change needed to add a case.

## Row format

```json
{"command": "<bash command>", "expected": "allow|deny", "mode": "default|auto", "source": "curated|adversarial|convo:session", "note": "why this row exists"}
```

| Field | Required | Meaning |
|---|---|---|
| `command` | yes | The exact bash command string fed to `decide()`. |
| `expected` | yes | The decision class guard must reach: `allow` or `deny`. |
| `mode` | no (default `default`) | Passed to `decide()` as the Claude Code permission mode. It is recorded, never acted on: every mode gets the same decision. |
| `source` | no | Provenance: `curated` (hand-written), `adversarial` (found by a sweep), `convo:session` (seeded from real usage). |
| `note` | no | One line on why the row exists / what it guards against. |

`expected` collapses guard's envelope: `deny` is a deny, and `allow` means guard
gave no decision, so Claude Code's own permission step decides. Guard never
allows or asks.

Rows are adjudicated against guard's shipped policy: your allowlist never
changes an outcome, and a corpus run writes nothing to the
decision log.

Blank lines and `#` comment lines are ignored.

## Files

Threat-category file names are **organization only** — the runner always
evaluates every file. Rows are self-describing via `expected`/`mode`.

| File | Covers |
|---|---|
| `allow.jsonl` | Real dev commands guard must NOT deny (FP ratchet, seeded from session history). |
| `deny.jsonl` | Dangerous-floor commands guard must deny in every mode (FN ratchet). |
| `escalation.jsonl` | Non-sudo privilege escalation (`su`, `doas`, `pkexec`, `runuser`, `setpriv`, `machinectl shell`). Elevated-risk tier: denied in every mode. |
| `host_control.jsonl` | Host power / runlevel control (`reboot`, `shutdown`, `systemctl poweroff`, `init 0`, `systemctl isolate <power>.target`). Elevated-risk tier: denied in every mode. |
| `registry.jsonl` | Package-registry / index redirection (`npm config set registry`, `pip config set global.index-url`). Elevated-risk tier: denied in every mode. |
| `fs_attr.jsonl` | Filesystem-attribute tampering on sensitive paths (`chown`/`chgrp`/`chattr`/`setfacl`). Both-mode hard deny. |
| `secret_egress.jsonl` | Credential-file network egress (`curl -T ~/.ssh/id_rsa`, `nc < key`). Both-mode hard deny. |
| `crossexam.jsonl` | Adversarial cross-examination findings -- the default append target for `guard corpus add`. Grows append-only as new bypasses / FPs are found. |
| `auto.jsonl` | Rows run in Claude Code `auto` permission mode: floor shapes (including payloads hidden in a substitution, a function body or a `-c` string) deny, and shapes off the floor pass. |

## Adding a fixture

Preferred -- let the harness write and adjudicate the row in one step:

```
guard corpus add '<command>' --expect deny --note 'what it guards against'
guard corpus add '<command>' --expect deny --file deny.jsonl      # route to a category file
```

`add` only accepts a **bare** filename under `tests/corpus` (default
`crossexam.jsonl`) -- no custom paths, no scratch JSON. It is idempotent (an
identical row is a no-op) and refuses a conflicting `(command, mode)` that is
already classified differently, so the corpus can never hold two contradictory
rows. The command is run through `decide()` immediately; `ok` is true only when
the live decision matches `--expect`.

A row meant to fail today (a known gap you are about to fix) is still written:
it lands as a failing fixture that drives the fix, and `guard corpus` stays the
gate that confirms the whole corpus is green before you ship.

By hand: append a JSON row to the file matching its threat category and run
`guard corpus` to confirm.
