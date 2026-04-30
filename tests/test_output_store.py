"""Tests for guard._output_store."""
# ruff: noqa: TC002, TC003

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from guard import _output_store


class TestOutputStore:
    def test_small_response_not_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Under threshold: returns None, no dir created."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 100)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        result = _output_store.maybe_store_output("sess-1", 1, "short")
        assert result is None
        assert not (tmp_path / "outputs").exists()

    def test_large_response_stored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Over threshold: returns truncation message, file exists."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        result = _output_store.maybe_store_output("sess-1", 42, "x" * 100)
        assert result is not None
        assert "[Truncated:" in result
        assert (tmp_path / "outputs" / "sess-1" / "42.json").exists()

    def test_stored_file_contains_full_response(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stored file has complete untruncated response."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        big = {"key": "v" * 500}
        _output_store.maybe_store_output("sess-2", 7, big)

        content = json.loads((tmp_path / "outputs" / "sess-2" / "7.json").read_text())
        assert content == big

    def test_summary_includes_preview_and_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Summary message includes first chars and file path."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        result = _output_store.maybe_store_output("sess-3", 5, "abcdefghijklmnopqrstuvwxyz" * 10)
        assert result is not None
        assert "abcdefghij" in result
        assert "sess-3" in result
        assert "5.json" in result

    def test_cleanup_removes_old_outputs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Old dirs deleted, new dirs kept."""
        store_dir = tmp_path / "outputs"
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", store_dir)
        monkeypatch.setattr(_output_store, "OUTPUT_RETENTION_HOURS", 1)

        old_dir = store_dir / "old-sess"
        old_dir.mkdir(parents=True)
        old_file = old_dir / "1.json"
        old_file.write_text("{}")
        old_mtime = time.time() - 3700  # >1 hour ago
        os.utime(old_dir, (old_mtime, old_mtime))

        new_dir = store_dir / "new-sess"
        new_dir.mkdir(parents=True)
        (new_dir / "2.json").write_text("{}")

        _output_store.cleanup_old_outputs()

        assert not old_dir.exists()
        assert new_dir.exists()

    def test_store_handles_write_error_gracefully(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad path returns None, no crash."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        # File where dir is expected
        blocker = tmp_path / "blocked"
        blocker.write_text("i am a file")
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", blocker)

        result = _output_store.maybe_store_output("sess-x", 1, "x" * 100)
        assert result is None

    def test_none_response_not_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """None input returns None."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        result = _output_store.maybe_store_output("sess-1", 1, None)
        assert result is None

    def test_path_traversal_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Session IDs with path traversal components are rejected."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        assert _output_store.maybe_store_output("../../etc", 1, "x" * 100) is None
        assert _output_store.maybe_store_output("foo/bar", 1, "x" * 100) is None
        assert _output_store.maybe_store_output("", 1, "x" * 100) is None

    def test_non_serializable_response(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-JSON-serializable response returns None."""
        monkeypatch.setattr(_output_store, "OUTPUT_TRUNCATION_THRESHOLD", 10)
        monkeypatch.setattr(_output_store, "OUTPUT_STORE_DIR", tmp_path / "outputs")

        result = _output_store.maybe_store_output("sess-1", 1, {1, 2, 3})
        assert result is None
