# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for the ``guard integrity`` CLI (build + verify the integrity manifest).

``build`` records a root-owned manifest + canonical copies of a protected set;
``verify`` is a non-healing diagnostic that reports per-file drift. The healing
itself lives in the dependency-free ``bin/guard-sentinel`` SessionStart hook,
which consumes the same manifest format (cross-checked in the integration suite).
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def test_build_writes_manifest_and_canonical(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    content = b'{"permissions": {}}\n'
    live = tmp_path / "settings.json"
    live.write_bytes(content)
    root = tmp_path / "iroot"

    payload, _pretty = cmd_integrity_build(root, [live])

    assert payload["count"] == 1
    entry = payload["entries"][0]
    assert entry["path"] == str(live)
    assert entry["sha256"] == hashlib.sha256(content).hexdigest()

    # The canonical copy is the verbatim known-good bytes.
    canon = root / "canonical" / entry["canonical"]
    assert canon.read_bytes() == content

    # Manifest line is exactly "<sha256>  <canonical_relname>  <live_abs_path>"
    # (two-space separated, path last) so bin/guard-sentinel can read it.
    line = (root / "manifest").read_text().strip()
    assert line == f"{entry['sha256']}  {entry['canonical']}  {live}"


def test_canonical_relname_is_space_free_for_spaced_paths(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    live = tmp_path / "Application Support" / "managed-settings.json"
    live.parent.mkdir(parents=True)
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"

    payload, _ = cmd_integrity_build(root, [live])

    canon = payload["entries"][0]["canonical"]
    assert " " not in canon  # must stay the space-free middle manifest column


def test_build_distinguishes_same_basename_in_different_dirs(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    a = tmp_path / "a" / "config"
    b = tmp_path / "b" / "config"
    a.parent.mkdir()
    b.parent.mkdir()
    a.write_bytes(b"A\n")
    b.write_bytes(b"B\n")
    root = tmp_path / "iroot"

    payload, _ = cmd_integrity_build(root, [a, b])

    names = {e["canonical"] for e in payload["entries"]}
    assert len(names) == 2  # same basename, distinct canonical relnames


def test_verify_reports_clean_then_drift(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build, cmd_integrity_verify

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"
    cmd_integrity_build(root, [live])

    payload, _ = cmd_integrity_verify(root)
    assert payload["ok"] is True
    assert payload["entries"][0]["status"] == "clean"

    live.write_bytes(b"PWNED\n")  # tamper, but canonical is still good
    payload2, _ = cmd_integrity_verify(root)
    assert payload2["ok"] is False
    assert payload2["entries"][0]["status"] == "drift"  # healable by the sentinel


def test_verify_reports_tamper_when_canonical_is_poisoned(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build, cmd_integrity_verify

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"
    payload, _ = cmd_integrity_build(root, [live])
    canon = root / "canonical" / payload["entries"][0]["canonical"]

    live.write_bytes(b"PWNED\n")
    canon.write_bytes(b"ALSO_PWNED\n")  # both off the anchor -> unhealable

    payload2, _ = cmd_integrity_verify(root)
    assert payload2["ok"] is False
    assert payload2["entries"][0]["status"] == "tamper"


def test_main_build_then_verify_exit_codes(tmp_path: Path) -> None:
    from guard.cli import main

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"

    assert main(["integrity", "build", "--root", str(root), str(live)]) == 0
    assert main(["integrity", "verify", "--root", str(root)]) == 0  # clean

    live.write_bytes(b"PWNED\n")
    assert main(["integrity", "verify", "--root", str(root)]) == 1  # drift -> nonzero
