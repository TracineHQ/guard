# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""``guard corpus add`` -- the durable replacement for /tmp scratch fixtures.

A found bypass or false positive becomes a permanent regression row in one step:
the case is written into a bare ``tests/corpus`` file and adjudicated through
``decide()``. These tests pin the append semantics (validation, idempotency,
conflict refusal, path rejection) and the CLI payload, redirecting the corpus
dir to a tmp path so no real fixture file is mutated.
"""

from __future__ import annotations

import json

import pytest

from guard import _corpus
from guard.cli import cmd_corpus_add


@pytest.fixture
def corpus_dir(tmp_path, monkeypatch):
    """Point the corpus engine at an isolated dir for the duration of a test.

    A dedicated subdir (not ``tmp_path`` itself) so the autouse decisions-log
    isolation -- which drops ``guard-decisions.jsonl`` in ``tmp_path`` -- does
    not pollute the globbed corpus.
    """
    cdir = tmp_path / "corpus"
    cdir.mkdir()
    monkeypatch.setattr(_corpus, "default_corpus_dir", lambda: cdir)
    return cdir


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_append_row_writes_and_adjudicates(corpus_dir) -> None:
    outcome = _corpus.append_row("ls -la", "allow", note="benign read")
    assert outcome.added is True
    assert outcome.actual == "allow"
    assert outcome.matched is True

    rows = _lines(corpus_dir / "crossexam.jsonl")
    assert rows == [
        {
            "command": "ls -la",
            "expected": "allow",
            "mode": "default",
            "source": "crossexam",  # defaults to the file stem
            "note": "benign read",
        }
    ]


def test_append_row_records_mismatch_but_still_writes(corpus_dir) -> None:
    """A not-yet-fixed bypass lands as a failing row that drives the fix."""
    outcome = _corpus.append_row("ls -la", "deny", note="pretend bypass")
    assert outcome.added is True
    assert outcome.actual == "allow"
    assert outcome.matched is False
    assert len(_lines(corpus_dir / "crossexam.jsonl")) == 1


def test_append_row_is_idempotent(corpus_dir) -> None:
    first = _corpus.append_row("ls -la", "allow")
    second = _corpus.append_row("ls -la", "allow")
    assert first.added is True
    assert second.added is False
    assert len(_lines(corpus_dir / "crossexam.jsonl")) == 1, "duplicate must not be re-written"


def test_append_row_conflict_refused(corpus_dir) -> None:
    _corpus.append_row("ls -la", "allow")
    with pytest.raises(ValueError, match="conflict"):
        _corpus.append_row("ls -la", "deny")
    assert len(_lines(corpus_dir / "crossexam.jsonl")) == 1, "conflicting row must not be written"


def test_append_row_appends_to_existing_file_without_clobber(corpus_dir) -> None:
    _corpus.append_row("ls -la", "allow")
    _corpus.append_row("pwd", "allow")
    rows = _lines(corpus_dir / "crossexam.jsonl")
    assert [r["command"] for r in rows] == ["ls -la", "pwd"]


def test_append_row_rejects_bad_expected(corpus_dir) -> None:
    with pytest.raises(ValueError, match="expected"):
        _corpus.append_row("ls -la", "maybe")


@pytest.mark.parametrize("bad", ["../evil.jsonl", "sub/x.jsonl", "/etc/x.jsonl", ".", ".."])
def test_append_row_rejects_path_shaped_file(corpus_dir, bad: str) -> None:
    with pytest.raises(ValueError, match="bare name"):
        _corpus.append_row("ls -la", "allow", file=bad)


def test_append_row_rejects_non_jsonl_file(corpus_dir) -> None:
    with pytest.raises(ValueError, match=r"end in \.jsonl"):
        _corpus.append_row("ls -la", "allow", file="notes.txt")


def test_append_row_custom_source_and_file(corpus_dir) -> None:
    outcome = _corpus.append_row("pwd", "allow", source="manual", file="allow.jsonl")
    assert outcome.row.file == "allow.jsonl"
    rows = _lines(corpus_dir / "allow.jsonl")
    assert rows[0]["source"] == "manual"


def test_cmd_corpus_add_matched_is_ok(corpus_dir) -> None:
    payload, pretty = cmd_corpus_add("ls -la", expected="allow")
    assert payload["ok"] is True
    assert payload["matched"] is True
    assert payload["added"] is True
    assert payload["actual"] == "allow"
    assert payload["file"] == "crossexam.jsonl"
    assert "OK" in pretty


def test_cmd_corpus_add_mismatch_not_ok_but_written(corpus_dir) -> None:
    payload, pretty = cmd_corpus_add("ls -la", expected="deny")
    assert payload["ok"] is False
    assert payload["matched"] is False
    assert payload["added"] is True, "the row is still written so it becomes a regression fixture"
    assert "MISMATCH" in pretty
    assert len(_lines(corpus_dir / "crossexam.jsonl")) == 1
