# guard -- agent working notes

Conventions for any agent (or human) doing dev work in this repo. Terse by design.

## Testing & coverage doctrine (read first)

guard's behavior is fenced by a **fixture corpus that is meant to GROW**. Every
bypass, false positive, or edge case you find becomes a permanent fixture row, so
coverage compounds and a fixed bug can never silently come back.

**If you probe guard's decision on a command, you leave a fixture row behind.**
That is the rule. A probe with no persisted row is wasted work.

- **Never use `guard test '<cmd>'` for coverage work.** It is ephemeral (lost the
  moment the shell returns) and is blocked in strict mode. It exists only for a
  throwaway human glance, never as the way you validate or explore behavior.

- **Probe and lock in one step** with the harness -- it adjudicates the row
  against live `decide()` AND persists it under `tests/corpus/`:
  ```
  guard corpus add '<cmd>' --expect deny  --note 'what it guards against'
  guard corpus add '<cmd>' --expect allow --mode auto        # strict-mode case
  guard corpus add '<cmd>' --expect deny  --file deny.jsonl  # route to a category file
  ```

- **Confirm the whole corpus is green:** `guard corpus` (exits non-zero on any
  mismatch). CI and pre-commit run it on every push and on fixture/matcher edits.

- **A row meant to fail today is still written.** A known gap you are about to fix
  lands as a failing fixture that drives the fix; `guard corpus` is the gate that
  confirms the corpus is green before you ship.

- **Dangerous payloads go through the CLI directly.** `guard corpus add '<cmd>'`
  is INERT -- the payload is adjudicated in-process and never handed to a shell --
  so the registration is allowed even when `<cmd>` is something the floor denies
  (`python -c ...`, `gh auth token`, `curl ... | sh`). Register the deny-fixture
  the normal way; no special handling needed.

- **The one exception -- forms that would execute before guard runs.** A
  registration is NOT inert (and so still hits the floor) if the command line has
  shell substitution (`$(...)`, backticks, `${...}`, `<(...)`), a chain (`;`,
  `&&`, `||`, a real `|`), or a redirect OUTSIDE the payload quotes. Those cannot
  be added from the shell -- append the JSON row directly to the matching
  `tests/corpus/*.jsonl` file with Write/Edit, then run `guard corpus`.

Row format and the file-to-threat-category map live in `tests/corpus/README.md`.
That directory is the single source of truth for "what guard must classify how."

## Hooks run from source

The live hooks run from `src/guard/hooks/`. `~/develop/claude-skills/hooks` is a
stale fork, not the source -- make changes here.

## Style & tooling

- No em-dashes in committed content; use `--`.
- Lint/typecheck: `uv run ruff check --fix` -> `uv run ruff format` -> `uv run mypy`.
- `CHANGELOG.md` is generated on release; never hand-edit it.
