# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Guard against orphaned exports.

When a "deny set" or "rule list" is defined in `registry.py` (or an
uppercase-snake-case constant in `_utils.py`) but no hook imports it, that's
almost always a bug — the rule is being silently bypassed.

This test enumerates suspicious public exports of `guard.registry` and
`guard._utils` and verifies each appears at least once in
`src/guard/hooks/**/*.py`.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from guard import _utils, registry

REPO = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO / "src" / "guard" / "hooks"

# Naming heuristic for registry rule sets.
SUSPICIOUS_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*(_DENY|_RULES|_FEEDBACK|_PATTERNS|_PREFIXES)$")

# Naming heuristic for _utils constants: any UPPER_SNAKE name (publicly
# exported, i.e. no leading underscore).
UTILS_CONSTANT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

# `_utils` constants that are wired into the hooks indirectly (read by
# `_utils.py` itself, e.g. via append_jsonl / parse_hook_input). These are
# not orphans even though no hook references them by name.
UTILS_INTERNAL_ALLOW: frozenset[str] = frozenset(
    {
        "GUARD_HOME",  # storage root, used by env-driven config
        # Read inside log_decision() / append_jsonl() within _utils itself,
        # not by hooks directly — so it's "live" but not greppable.
        "GUARD_DECISIONS_PATH",
        "LOOP_DETECTION_THRESHOLD",
        "LOOP_DETECTION_WINDOW_MINUTES",
        "CONTEXT_BUDGET_WARN_BYTES",
        "CONTEXT_BUDGET_HARD_BYTES",
        # Re-exports / typing imports
        "TYPE_CHECKING",
        "UTC",
    }
)


def _public_module_attrs(module) -> list[str]:
    return [name for name in dir(module) if not name.startswith("_")]


def _candidate_exports() -> list[str]:
    return [
        name
        for name in _public_module_attrs(registry)
        if SUSPICIOUS_NAME_RE.match(name) and not inspect.ismodule(getattr(registry, name))
    ]


def _utils_constant_exports() -> list[str]:
    """Return uppercase-snake-case publicly named constants exported from _utils."""
    candidates: list[str] = []
    for name in _public_module_attrs(_utils):
        if not UTILS_CONSTANT_RE.match(name):
            continue
        value = getattr(_utils, name)
        if inspect.ismodule(value) or callable(value):
            continue
        if name in UTILS_INTERNAL_ALLOW:
            continue
        candidates.append(name)
    return candidates


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
    assert not orphans, "Orphaned registry exports detected:\n" + "\n".join(
        f"  - {k}: {v}" for k, v in orphans.items()
    )


def test_no_orphaned_utils_constants() -> None:
    """Public uppercase constants in _utils must be read by at least one hook."""
    orphans: dict[str, str] = {}
    for name in _utils_constant_exports():
        matches = _grep_hooks_dir(name)
        if not matches:
            orphans[name] = (
                f"_utils.{name} is defined but no hook reads it. "
                f"Either delete it or document why it's exported."
            )
    assert not orphans, "Orphaned _utils constants detected:\n" + "\n".join(
        f"  - {k}: {v}" for k, v in orphans.items()
    )
