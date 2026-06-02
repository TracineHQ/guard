# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Corpus-driven classification fence for the bash matcher.

Every row under ``tests/corpus/*.jsonl`` is a command + the decision guard MUST
reach in a given mode -- recorded as ``{command, expected, mode, source, note}``.
The ``allow``/``deny`` files are the original false-positive / false-negative
ratchets (seeded from real convo session history); the threat-category files
(``escalation.jsonl``, ``host_control.jsonl``, ...) add the ``ask`` tier and its
sibling hard denies. A probe of "does guard classify this right?" becomes a
permanent row here instead of a throwaway ``guard test`` string.

This module and the ``guard corpus`` CLI both read the SAME rows through
``guard._corpus`` -- one source of truth, two consumers (CI fence + agent
harness). Three layers:

- per-row parametrized cases name the exact offending command on failure;
- an FP ratchet: no ``allow`` row may be denied (legit dev work stays unblocked);
- an FN ratchet: no ``deny`` row may leak (the dangerous floor holds).

Both ratchets start at 0.0 -- a code change that breaks either fails CI here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from guard._corpus import ALLOW, DENY, classify, load_corpus
from guard.hooks.bash_command_validator import decide

if TYPE_CHECKING:
    from guard._corpus import CorpusRow

_ROWS = load_corpus()

_FP_THRESHOLD = 0.0


def _row_id(row: CorpusRow) -> str:
    return f"{row.file}:{row.mode}:{row.command[:40]}"


def _actual(row: CorpusRow) -> str:
    return classify(decide(row.command, permission_mode=row.mode))


def test_corpus_is_non_empty() -> None:
    assert _ROWS, "no corpus rows loaded from tests/corpus/*.jsonl"


@pytest.mark.parametrize("row", _ROWS, ids=[_row_id(r) for r in _ROWS])
def test_corpus_row_classified_as_expected(row: CorpusRow) -> None:
    actual = _actual(row)
    assert actual == row.expected, (
        f"[{row.mode}] {row.file} (source={row.source or '?'}): {row.command!r} "
        f"expected {row.expected}, got {actual}. {row.note}"
    )


def test_allow_corpus_fp_rate_under_threshold() -> None:
    allow_rows = [r for r in _ROWS if r.expected == ALLOW]
    denied = [r for r in allow_rows if _actual(r) == DENY]
    rate = len(denied) / len(allow_rows) if allow_rows else 0.0
    assert rate <= _FP_THRESHOLD, (
        f"false-positive rate {rate:.1%} exceeds {_FP_THRESHOLD:.1%}; "
        "offenders: " + ", ".join(f"[{r.mode}] {r.command!r}" for r in denied)
    )


def test_deny_corpus_fn_rate_under_threshold() -> None:
    deny_rows = [r for r in _ROWS if r.expected == DENY]
    leaked = [r for r in deny_rows if _actual(r) != DENY]
    rate = len(leaked) / len(deny_rows) if deny_rows else 0.0
    assert rate <= _FP_THRESHOLD, (
        f"false-negative rate {rate:.1%} exceeds {_FP_THRESHOLD:.1%}; "
        "leaked: " + ", ".join(f"[{r.mode}] {r.command!r}" for r in leaked)
    )
