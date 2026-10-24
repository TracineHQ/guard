# Local development

Two separate things run guard from your machine. Don't conflate them.

## 1. The live hook (always from source)

Claude Code invokes the PreToolUse hooks through `guard-runner.sh`, which sets
`PYTHONPATH` to this checkout. The hook that actually gates your commands runs
from `src/guard/hooks/` -- edit a matcher and the next tool call uses it. No
install step, no binary.

## 2. The `guard` CLI (corpus, test, status, allowlist)

The diagnostic CLI is a separate entry point (`guard = "guard.cli:main"` in
`pyproject.toml`). It is NOT installed by default. `uv sync` only puts it in
`.venv/bin/guard`, which is not on `PATH`. For a bare `guard` to run THIS
checkout, link it as the binary:

```bash
# Local-linked dev install: `guard` on PATH, editable against this source.
uv tool install --editable /Users/dev/develop/guard --force
```

`--editable` means source edits are reflected with no reinstall. After this,
`guard corpus` runs from the local tree. Re-run the install only after a
dependency change (a new entry in `pyproject.toml`), not after ordinary source
edits.

### Official vs local

End users install the published package, which puts `guard` on `PATH` the same
way:

```bash
uv tool install guard          # PyPI release
# or via the plugin marketplace (see README)
```

The editable local install shadows that with your working tree. `uv tool list`
shows what is installed; `which guard` shows the linked path.

## Running checks

```bash
guard corpus          # adjudicate every tests/corpus/*.jsonl fixture (strict-safe)
just test             # full pytest suite (uv run pytest, from the repo root)
just check            # lint + typecheck + test
```

`guard corpus` is the fast behavioral fence: it runs every fixture command
through `decide()` and asserts the classification. Add a row under
`tests/corpus/` rather than probing ad-hoc with `guard test '<cmd>'`: a row
keeps checking the command on every run.
