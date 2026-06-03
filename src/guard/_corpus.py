# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Shared fixture-corpus engine for guard's bash matcher.

The corpus (``tests/corpus/*.jsonl``) is the single source of truth for the
command shapes guard must classify a particular way. One row is one fixture::

    {"command": "...", "expected": "allow|ask|deny", "mode": "default|auto|...",
     "note": "...", "source": "..."}

Both consumers read THIS module, so the fixtures are never duplicated:

* ``guard corpus`` -- a whitelisted, strict-mode-safe CLI runner that adjudicates
  every fixture in one process and reports mismatches. Agents run it instead of
  spraying ad-hoc ``guard test '<cmd>'`` strings (which lose the case the moment
  the shell call returns).
* ``tests/integration/test_corpus_fp_rate.py`` -- the CI fence that parametrizes
  over the same rows.

A newly discovered bypass or false positive becomes a one-line fixture row, and
both the runner and CI pick it up automatically. Threat-category file names
(``escalation.jsonl`` etc.) are organization only -- the runner always evaluates
every file; rows are self-describing via ``expected``/``mode``.

Performance: ``decide()`` is microseconds per row; the real wall-clock cost is
interpreter startup. The efficiency lever is therefore batching the whole corpus
into ONE ``guard corpus`` process (vs one ``guard test`` per command), not
threading -- so this engine iterates in-process and stays simple.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from guard.hooks.bash_command_validator import decide

if TYPE_CHECKING:
    from collections.abc import Iterable

# Decision classes a fixture's ``expected`` (and decide()'s actual) collapse to.
ALLOW = "allow"
ASK = "ask"
DENY = "deny"
_DECISIONS = frozenset({ALLOW, ASK, DENY})


@dataclass(frozen=True)
class CorpusRow:
    """One fixture: a command + the decision guard must reach in a given mode."""

    command: str
    expected: str
    mode: str
    note: str
    source: str
    file: str  # corpus filename the row came from, for failure attribution


@dataclass(frozen=True)
class CorpusFailure:
    """A row whose adjudicated decision differed from ``expected``."""

    row: CorpusRow
    actual: str


@dataclass
class CorpusReport:
    """Aggregate outcome of evaluating a corpus."""

    total: int = 0
    passed: int = 0
    failures: list[CorpusFailure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


def default_corpus_dir() -> Path:
    """Locate ``tests/corpus`` in the guard source tree.

    ``guard corpus`` is a development / CI harness: it expects a guard source
    tree, where fixtures live under ``tests/corpus``. Resolve in two steps so the
    harness works whether guard is imported editable OR from a wheel while run
    from a checkout -- the install-smoke CI job installs the built wheel into a
    venv, then runs the full suite (incl. the FP/FN ratchet) from the repo root
    to fence the *shipped* matcher, not just the source:

    1. package-relative -- correct for an editable / source install, where this
       module sits at ``<repo>/src/guard/_corpus.py``;
    2. a walk up from the current directory -- finds the checkout's corpus when
       guard itself is installed elsewhere (site-packages).

    Neither is a user-supplied path knob; both are fixed source-tree lookups. A
    pip-installed guard with no checkout in scope yields the package-relative
    path, which won't exist, so ``load_corpus`` raises a clear error rather than
    silently passing on an empty corpus.
    """
    pkg_relative = Path(__file__).resolve().parents[2] / "tests" / "corpus"
    if pkg_relative.is_dir():
        return pkg_relative
    cwd = Path.cwd().resolve()
    for base in (cwd, *cwd.parents):
        candidate = base / "tests" / "corpus"
        if candidate.is_dir():
            return candidate
    return pkg_relative


def load_corpus() -> list[CorpusRow]:
    """Load every ``*.jsonl`` row under ``tests/corpus``.

    The corpus is a fixed, in-tree fixture set: there is no custom-directory
    knob. Blank and ``#`` comment lines are skipped. ``mode`` defaults to
    ``default``. Raises ``FileNotFoundError`` if the directory is missing and
    ``ValueError`` on a malformed row or an unknown ``expected`` value, so a typo
    fails loudly instead of silently dropping a fixture.
    """
    root = default_corpus_dir()
    if not root.is_dir():
        msg = f"corpus directory not found: {root}"
        raise FileNotFoundError(msg)
    rows: list[CorpusRow] = []
    for path in sorted(root.glob("*.jsonl")):
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                msg = f"{path.name}:{lineno}: invalid JSON: {exc}"
                raise ValueError(msg) from exc
            expected = rec.get("expected")
            if expected not in _DECISIONS:
                msg = (
                    f"{path.name}:{lineno}: 'expected' must be one of "
                    f"{sorted(_DECISIONS)}, got {expected!r}"
                )
                raise ValueError(msg)
            rows.append(
                CorpusRow(
                    command=rec["command"],
                    expected=expected,
                    mode=rec.get("mode", "default"),
                    note=rec.get("note", ""),
                    source=rec.get("source", ""),
                    file=path.name,
                )
            )
    return rows


def classify(result: dict[str, str] | None) -> str:
    """Map a ``decide()`` envelope to its decision class (allow/ask/deny).

    ``None`` (interactive passthrough) and an explicit allow envelope both mean
    "not blocked" -> ``allow``.
    """
    if result is None:
        return ALLOW
    decision = result.get("permissionDecision", ALLOW)
    return decision if decision in _DECISIONS else ALLOW


def evaluate(rows: Iterable[CorpusRow]) -> CorpusReport:
    """Adjudicate each row through ``decide()`` and collect mismatches."""
    report = CorpusReport()
    for row in rows:
        report.total += 1
        actual = classify(decide(row.command, permission_mode=row.mode))
        if actual == row.expected:
            report.passed += 1
        else:
            report.failures.append(CorpusFailure(row=row, actual=actual))
    return report


def run_corpus() -> CorpusReport:
    """Load + evaluate the whole corpus. Convenience for the CLI runner."""
    return evaluate(load_corpus())


@dataclass(frozen=True)
class AppendOutcome:
    """Result of ``append_row``: the row, its live decision, and what was written."""

    row: CorpusRow
    actual: str
    added: bool  # False when an identical row already existed (idempotent no-op)

    @property
    def matched(self) -> bool:
        return self.actual == self.row.expected


def _resolve_corpus_file(file: str) -> Path:
    """Resolve a BARE corpus filename under ``tests/corpus``.

    The corpus is a fixed fixture set, so ``add`` may only target a file inside
    ``tests/corpus``. A path separator, ``.``/``..``, an absolute path, or a
    non-``.jsonl`` name is rejected: the harness can never be pointed at an
    arbitrary location (no custom paths, no scratch JSON).
    """
    if file != Path(file).name or file in {"", ".", ".."}:
        msg = f"corpus file must be a bare name under tests/corpus, not a path: {file!r}"
        raise ValueError(msg)
    if not file.endswith(".jsonl"):
        msg = f"corpus file must end in .jsonl: {file!r}"
        raise ValueError(msg)
    return default_corpus_dir() / file


def append_row(  # noqa: PLR0913 -- one keyword per corpus row field; matches the fixture schema
    command: str,
    expected: str,
    *,
    mode: str = "default",
    note: str = "",
    source: str = "",
    file: str = "crossexam.jsonl",
) -> AppendOutcome:
    """Append one fixture row to ``tests/corpus/<file>`` and adjudicate it.

    The durable replacement for /tmp scratch fixtures: a newly found bypass or
    false positive becomes a permanent regression row in one step. Idempotent --
    an identical ``(command, mode, expected)`` row already in the corpus is a
    no-op. A ``(command, mode)`` already classified with a DIFFERENT ``expected``
    is a conflict and raises, so the corpus can never hold two contradictory
    fixtures. Returns the row, ``decide()``'s live decision, and whether a line
    was written.
    """
    if expected not in _DECISIONS:
        msg = f"'expected' must be one of {sorted(_DECISIONS)}, got {expected!r}"
        raise ValueError(msg)
    path = _resolve_corpus_file(file)
    src = source or path.stem
    row = CorpusRow(
        command=command, expected=expected, mode=mode, note=note, source=src, file=path.name
    )
    actual = classify(decide(command, permission_mode=mode))
    for existing in load_corpus():
        if existing.command == command and existing.mode == mode:
            if existing.expected == expected:
                return AppendOutcome(row=row, actual=actual, added=False)
            msg = (
                f"conflict: corpus already classifies {command!r} (mode {mode}) as "
                f"{existing.expected!r} in {existing.file}; refusing to add {expected!r}"
            )
            raise ValueError(msg)
    record = {
        "command": command,
        "expected": expected,
        "mode": mode,
        "source": src,
        "note": note,
    }
    line = json.dumps(record, ensure_ascii=False)
    existing_text = path.read_text(encoding="utf-8") if path.exists() else ""
    sep = "" if (not existing_text or existing_text.endswith("\n")) else "\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(sep + line + "\n")
    return AppendOutcome(row=row, actual=actual, added=True)
