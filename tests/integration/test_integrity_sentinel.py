# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Integration tests for the integrity sentinel (``bin/guard-sentinel``).

The sentinel is a dependency-free POSIX-sh SessionStart hook. It verifies each
protected file against a root-owned manifest and self-heals from a root-owned
canonical copy. Tests drive it against a temp ``GUARD_INTEGRITY_ROOT`` so no
root privilege is required.

Trust model: the manifest's sha256 is the anchor. A live file must match it; a
heal restores the live file from the canonical copy (which must itself match the
anchor, so a poisoned canonical can never heal a file to a bad state).
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

SENTINEL = Path(__file__).resolve().parents[2] / "bin" / "guard-sentinel"


def _add_entry(root: Path, live: Path, canonical_content: bytes, canon_name: str = "hook") -> None:
    """Append one integrity entry: a canonical copy + a manifest line for ``live``.

    The manifest hash is taken from ``canonical_content`` (the known-good bytes).
    Column order: <sha256>  <canonical_relname>  <live_abs_path>. The live path is
    last so a path containing spaces stays intact; the relname is kept space-free.
    """
    canonical = root / "canonical"
    canonical.mkdir(parents=True, exist_ok=True)
    (canonical / canon_name).write_bytes(canonical_content)
    digest = hashlib.sha256(canonical_content).hexdigest()
    with (root / "manifest").open("a") as fh:
        fh.write(f"{digest}  {canon_name}  {live}\n")


def _build_root(root: Path, live: Path, canonical_content: bytes) -> None:
    """Write a one-entry integrity root (manifest + canonical) for ``live``."""
    _add_entry(root, live, canonical_content)


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(SENTINEL)],  # noqa: S607 -- PATH-resolved `sh` is the portable entry point
        env={"GUARD_INTEGRITY_ROOT": str(root), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )


def test_reports_clean_when_live_matches_manifest(tmp_path: Path) -> None:
    good = b"echo guard\n"
    live = tmp_path / "hook"
    live.write_bytes(good)
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)

    result = _run(root)

    assert result.returncode == 0, result.stderr
    assert "clean" in result.stdout.lower()


def test_heals_modified_live_file_from_canonical(tmp_path: Path) -> None:
    good = b"echo guard\n"
    live = tmp_path / "hook"
    live.write_bytes(b"echo PWNED\n")  # tampered: hash no longer matches the anchor
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)  # canonical + manifest carry the good bytes

    result = _run(root)

    assert result.returncode == 0, result.stderr
    assert live.read_bytes() == good  # restored from canonical
    assert "heal" in result.stdout.lower()


def test_refuses_to_heal_from_poisoned_canonical(tmp_path: Path) -> None:
    good = b"echo guard\n"
    live = tmp_path / "hook"
    live.write_bytes(b"echo PWNED\n")  # tampered live
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)
    # Poison the canonical so it no longer matches the manifest anchor:
    (root / "canonical" / "hook").write_bytes(b"echo ALSO_PWNED\n")

    result = _run(root)

    combined = (result.stdout + result.stderr).lower()
    assert live.read_bytes() == b"echo PWNED\n"  # NOT healed to the poisoned copy
    assert result.returncode != 0  # unhealable tamper is a loud (non-blocking) signal
    assert "tamper" in combined


def test_heals_deleted_live_file(tmp_path: Path) -> None:
    good = b"echo guard\n"
    live = tmp_path / "hook"  # never written: simulates a removed/deleted hook
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)

    result = _run(root)

    assert result.returncode == 0, result.stderr
    assert live.read_bytes() == good  # restored even though it was missing
    assert "heal" in result.stdout.lower()


def test_heals_live_path_containing_a_space(tmp_path: Path) -> None:
    # macOS protected targets live under `Application Support` -- the live path
    # has a space, so the manifest's variable-length path field must be last.
    good = b"echo guard\n"
    live_dir = tmp_path / "Application Support" / "ClaudeCode"
    live_dir.mkdir(parents=True)
    live = live_dir / "managed-settings.json"
    live.write_bytes(b"echo PWNED\n")  # tampered
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)

    result = _run(root)

    assert result.returncode == 0, result.stderr
    assert live.read_bytes() == good  # path with a space still heals cleanly


def test_reports_cleanly_when_canonical_is_missing(tmp_path: Path) -> None:
    good = b"echo guard\n"
    live = tmp_path / "hook"
    live.write_bytes(b"echo PWNED\n")  # tampered, and nothing to heal from
    root = tmp_path / "integrity-root"
    _build_root(root, live, good)
    (root / "canonical" / "hook").unlink()  # canonical copy is gone entirely

    result = _run(root)

    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0  # unhealable: loud signal
    assert live.read_bytes() == b"echo PWNED\n"  # never healed from a non-existent copy
    assert "canonical" in combined  # names the missing canonical
    assert "no such file" not in combined  # handled cleanly, not via a crashing hash


def test_processes_all_entries_when_one_is_unhealable(tmp_path: Path) -> None:
    good = b"echo guard\n"
    root = tmp_path / "integrity-root"

    clean_live = tmp_path / "clean"
    clean_live.write_bytes(good)  # already matches the anchor
    _add_entry(root, clean_live, good, canon_name="clean")

    heal_live = tmp_path / "heal"
    heal_live.write_bytes(b"echo DRIFT\n")  # healable from a good canonical
    _add_entry(root, heal_live, good, canon_name="heal")

    tamper_live = tmp_path / "tamper"
    tamper_live.write_bytes(b"echo PWNED\n")  # unhealable: poisoned canonical
    _add_entry(root, tamper_live, good, canon_name="tamper")
    (root / "canonical" / "tamper").write_bytes(b"echo ALSO_PWNED\n")

    result = _run(root)

    combined = (result.stdout + result.stderr).lower()
    assert heal_live.read_bytes() == good  # healable entry was restored...
    assert clean_live.read_bytes() == good  # ...clean entry untouched...
    assert tamper_live.read_bytes() == b"echo PWNED\n"  # ...unhealable left as-is
    assert result.returncode != 0  # one unhealable entry => overall failure
    assert "heal" in combined  # healable outcome reported...
    assert "tamper" in combined  # ...alongside the tamper outcome


def test_errors_clearly_when_manifest_is_missing(tmp_path: Path) -> None:
    root = tmp_path / "integrity-root"
    root.mkdir()  # root exists but was never built -- no manifest

    result = _run(root)

    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0
    assert "manifest" in combined  # clean advisory, not a raw shell redirect error


def test_cli_built_manifest_is_healed_by_the_sentinel(tmp_path: Path) -> None:
    # End-to-end: the Python `guard integrity build` writer and the sh sentinel
    # reader must agree on the manifest format -- including a path with a space.
    from guard.cli import cmd_integrity_build

    good = b"echo guard\n"
    live = tmp_path / "Application Support" / "ClaudeCode" / "managed-settings.json"
    live.parent.mkdir(parents=True)
    live.write_bytes(good)
    root = tmp_path / "integrity-root"

    cmd_integrity_build(root, [live])  # build the manifest + canonical the Python way
    live.write_bytes(b"echo PWNED\n")  # an agent rewrites the protected file

    result = _run(root)  # the dependency-free sh sentinel restores it

    assert result.returncode == 0, result.stderr
    assert live.read_bytes() == good
