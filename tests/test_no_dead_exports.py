"""Guard against orphaned registry exports.

When a "deny set" or "rule list" is defined in registry.py but no hook imports it,
that's almost always a bug — the rule is being silently bypassed.

This test enumerates suspicious public exports of `guard.registry` and verifies each
appears at least once in `src/guard/hooks/**/*.py`.
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

from guard import registry

REPO = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO / "src" / "guard" / "hooks"

# Naming heuristic: any uppercase-snake-case name that ends with a "set" or "rules" word.
# These are the things we expect hooks to consume.
SUSPICIOUS_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*(_DENY|_RULES|_FEEDBACK|_PATTERNS|_PREFIXES)$")


def _public_module_attrs(module) -> list[str]:
    return [name for name in dir(module) if not name.startswith("_")]


def _candidate_exports() -> list[str]:
    return [
        name
        for name in _public_module_attrs(registry)
        if SUSPICIOUS_NAME_RE.match(name) and not inspect.ismodule(getattr(registry, name))
    ]


def _grep_hooks_dir(symbol: str) -> list[Path]:
    """Return list of hook files mentioning the symbol (string match, no AST)."""
    matches: list[Path] = []
    for py in HOOKS_DIR.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        text = py.read_text(encoding="utf-8")
        if re.search(rf"\b{re.escape(symbol)}\b", text):
            matches.append(py)
    return matches


def test_registry_has_candidate_exports() -> None:
    """Sanity: there are publishable rule sets to check.

    If this fires, the heuristic missed everything — update SUSPICIOUS_NAME_RE.
    """
    assert _candidate_exports(), (
        "No registry exports matched the suspicious-name heuristic. "
        "Update SUSPICIOUS_NAME_RE if registry naming changed."
    )


def test_no_orphaned_registry_exports() -> None:
    """Each suspicious registry export must be referenced by at least one hook."""
    orphans: dict[str, str] = {}
    for name in _candidate_exports():
        matches = _grep_hooks_dir(name)
        if not matches:
            orphans[name] = (
                f"registry.{name} is defined but no hook in src/guard/hooks/ reads it. "
                f"This is almost always a bug — the rule is being bypassed."
            )
    assert not orphans, (
        "Orphaned registry exports detected:\n"
        + "\n".join(f"  - {k}: {v}" for k, v in orphans.items())
    )
