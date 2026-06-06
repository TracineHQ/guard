# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Build and verify the guard integrity manifest.

The manifest is the trust anchor consumed by ``bin/guard-sentinel`` (a
dependency-free POSIX-sh SessionStart hook). One entry per line,
whitespace-separated:

    <sha256>  <canonical_relname>  <live_abs_path>

The live path is the LAST field so a path containing spaces (e.g. macOS
"Application Support") stays intact; the canonical relname is kept space-free.

``build`` is run as root to (re)create the root-owned manifest plus canonical
copies of the protected set. ``verify`` is a non-healing diagnostic. The healing
itself lives in the sh sentinel so it runs even when guard's Python is broken.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterable

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

VerifyStatus = Literal["clean", "drift", "tamper"]


@dataclass(frozen=True)
class BuildEntry:
    path: str
    sha256: str
    canonical: str


@dataclass(frozen=True)
class VerifyEntry:
    path: str
    status: VerifyStatus


def _sha256(path: Path) -> str | None:
    """Hex digest of ``path``'s bytes, or ``None`` if it cannot be read."""
    try:
        data = path.read_bytes()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return None
    return hashlib.sha256(data).hexdigest()


def canonical_relname(live: Path) -> str:
    """A space-free, collision-resistant canonical filename for ``live``.

    Basename plus a short hash of the full path: readable, yet distinct for two
    files that share a basename in different directories. Space-free so it can
    sit in the manifest's middle column.
    """
    digest = hashlib.sha256(str(live).encode()).hexdigest()[:12]
    base = _UNSAFE.sub("_", live.name) or "file"
    return f"{base}.{digest}"


def _manifest_line(sha: str, canon: str, live: Path) -> str:
    return f"{sha}  {canon}  {live}\n"


def build(root: Path, files: Iterable[Path]) -> list[BuildEntry]:
    """Write canonical copies + the manifest for ``files`` under ``root``.

    The manifest is written atomically (temp + ``Path.replace``). Canonical copies
    for the given paths are (over)written; the manifest is fully rewritten.
    """
    canonical_dir = root / "canonical"
    canonical_dir.mkdir(parents=True, exist_ok=True)

    entries: list[BuildEntry] = []
    lines: list[str] = []
    for live in files:
        data = live.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        canon = canonical_relname(live)
        (canonical_dir / canon).write_bytes(data)
        entries.append(BuildEntry(path=str(live), sha256=sha, canonical=canon))
        lines.append(_manifest_line(sha, canon, live))

    manifest = root / "manifest"
    tmp = manifest.with_name(manifest.name + ".tmp")
    tmp.write_text("".join(lines))
    tmp.replace(manifest)  # atomic swap into place
    return entries


def verify(root: Path) -> list[VerifyEntry]:
    """Non-healing check of each manifest entry against the anchor.

    - ``clean``  -- live matches the anchor.
    - ``drift``  -- live differs but the canonical still matches (the sentinel
      can heal it).
    - ``tamper`` -- the canonical is missing or also off the anchor (unhealable).
    """
    manifest = root / "manifest"
    results: list[VerifyEntry] = []
    for raw in manifest.read_text().splitlines():
        line = raw.strip()
        if not line:
            continue
        want, canon, live = line.split(None, 2)  # path last -> spaces preserved
        if _sha256(Path(live)) == want:
            results.append(VerifyEntry(path=live, status="clean"))
            continue
        healable = _sha256(root / "canonical" / canon) == want
        results.append(VerifyEntry(path=live, status="drift" if healable else "tamper"))
    return results
