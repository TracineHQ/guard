# Contributing

Thanks for your interest in guard. A few guidelines keep the project focused.

## Open an issue first

For non-trivial changes — new hooks, registry additions, behavior changes —
open an issue at <https://github.com/tracinehq/guard/issues> before sending a
PR. Small fixes (typos, tightening a regex, doc edits) can go straight to a
PR.

## Dev setup

```
uv sync --all-extras
```

This pulls dev dependencies (ruff, mypy, pytest). Guard itself is stdlib-only
at runtime; the dev tooling is the only third-party code in the tree.

## Run checks

```
just check
```

This is equivalent to:

```
uv run ruff check .
uv run mypy src/
uv run pytest
```

CI runs the same checks as a backstop.

## Pre-commit (optional)

```
uv run pre-commit install
```

Installs local hooks so lint/format runs at commit time. Optional — CI is
authoritative.

## Test tiers

- **T1 — unit.** Pure Python, no I/O, no subprocess. Most validator logic
  lives here. Fast (sub-second).
- **T2 — integration.** Hook scripts invoked as subprocesses with crafted
  stdin. Verifies the JSON envelope contract and the JSONL decision log.
- **T3 — E2E plugin install.** A smoke test that installs the plugin into a
  scratch Claude Code config and asserts the hooks fire. See
  `tests/integration/test_plugin_e2e.py` and `just test-e2e`.

## Commit messages

Short imperative subject, plain English. Reference an issue if applicable.
No type prefixes, no co-author trailers unless the change is genuinely
co-authored.

Examples:

```
Tighten env -i deny pattern
Fix ReDoS in commit_message_validator regex
Add docs/anti-patterns
```

## Code style

- ruff + mypy strict — zero warnings.
- Type annotations on every public function (this is part of the contract).
- Stdlib only at runtime; third-party imports are dev-only.
- Don't refactor surrounding code. Keep diffs minimal.

## License header

Every new `.py` file under `src/` carries:

```
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
```

Existing files already carry these — match the pattern when adding new
modules.
