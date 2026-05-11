# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for the hook registry — the single source of truth for guard hooks.

Two responsibilities:

1. **Structural correctness** — the registry's adapter shape, its filter
   helpers, and the consumer points (``cmd_test``, ``cmd_diff``,
   ``allowlist.KNOWN_RULE_IDS``) all agree on the same hook list.
2. **Drift prevention** — walk ``src/guard/hooks/*.py``, find every
   ``_HOOK_ID`` constant, and assert every one is in the registry. This is
   the test that catches the next time someone adds a hook and forgets to
   wire it into ``guard test`` (the original bug).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from guard.allowlist import KNOWN_RULE_IDS
from guard.hooks._registry import (
    REGISTERED_HOOKS,
    all_hook_ids,
    bash_surface_hooks,
    disable_hook_ids,
    hooks_for_surface,
)

HOOKS_DIR = Path(__file__).resolve().parent.parent / "src" / "guard" / "hooks"


# === Structural ===


def test_registry_is_non_empty() -> None:
    assert REGISTERED_HOOKS, "registry is empty — every hook should be listed"


def test_every_hook_id_is_unique() -> None:
    ids = [h.id for h in REGISTERED_HOOKS]
    assert len(ids) == len(set(ids)), f"duplicate hook ids in registry: {ids}"


def test_every_hook_has_at_least_one_surface() -> None:
    for spec in REGISTERED_HOOKS:
        assert spec.surfaces, f"{spec.id}: surfaces must be non-empty"


def test_every_hook_id_starts_with_guard_prefix() -> None:
    for spec in REGISTERED_HOOKS:
        assert spec.id.startswith("guard."), f"{spec.id}: hook id convention is 'guard.<name>'"


def test_all_hook_ids_returns_declaration_order() -> None:
    # all_hook_ids() must be ordered (callers display it; instability would
    # surface as flaky snapshot tests in cmd_diff consumers).
    expected = tuple(h.id for h in REGISTERED_HOOKS)
    assert all_hook_ids() == expected


# === Surface filters ===


def test_bash_surface_hooks_contains_all_expected() -> None:
    # The original bug was bash_surface_hooks() only returning three hooks
    # because cmd_test had been hand-maintained. Pin the expected set here
    # so a future deletion is loud rather than silent.
    expected = {
        "guard.bash_command_validator",
        "guard.git_c_validator",
        "guard.commit_message_validator",
        "guard.credential_check",
        "guard.protected_files",
        "guard.agent_output_guard",
    }
    actual = {h.id for h in bash_surface_hooks()}
    assert actual == expected, (
        f"bash_surface_hooks() drift: missing={expected - actual}, unexpected={actual - expected}"
    )


def test_subagent_scope_is_not_bash_surface() -> None:
    # Negative pin: subagent_scope is Task-only. If it ever shows up under
    # Bash, either the spec is wrong or the surface taxonomy has shifted.
    assert "guard.subagent_scope" not in {h.id for h in bash_surface_hooks()}


def test_hooks_for_surface_matches_membership() -> None:
    for spec in REGISTERED_HOOKS:
        for surface in spec.surfaces:
            assert spec in hooks_for_surface(surface)


# === Allowlist consumer ===


def test_disable_hook_ids_subset_of_all_hook_ids() -> None:
    assert set(disable_hook_ids()).issubset(set(all_hook_ids()))


def test_known_rule_ids_contains_every_disable_hook_id() -> None:
    # KNOWN_RULE_IDS is what the CLI shows the user as valid disable rule
    # names. Every hook with supports_disable_hook=True must appear.
    for hook_id in disable_hook_ids():
        assert hook_id in KNOWN_RULE_IDS, (
            f"{hook_id}: supports whole-hook disable but missing from allowlist.KNOWN_RULE_IDS"
        )


# === Drift guard: file walker ===

_HOOK_ID_LITERAL = re.compile(r'^_HOOK_ID\s*=\s*"([^"]+)"', re.MULTILINE)


def _hook_ids_from_source() -> set[str]:
    """Scrape every ``_HOOK_ID = "..."`` constant under src/guard/hooks/.

    This is the ground truth — if a module declares a hook id, the registry
    must list it. Otherwise consumers like cmd_test will silently miss it.
    """
    found: set[str] = set()
    for path in sorted(HOOKS_DIR.glob("*.py")):
        if path.name == "__init__.py" or path.name.startswith("_"):
            # Skip __init__ and the registry itself (no hook lives there).
            continue
        text = path.read_text(encoding="utf-8")
        for m in _HOOK_ID_LITERAL.finditer(text):
            found.add(m.group(1))
    return found


def test_every_source_hook_id_is_in_registry() -> None:
    declared = _hook_ids_from_source()
    registered = set(all_hook_ids())
    missing = declared - registered
    assert not missing, (
        f"hooks/*.py declares {sorted(missing)} but the registry does not "
        f"list them. Add a HookSpec in src/guard/hooks/_registry.py."
    )


def test_every_registered_hook_corresponds_to_a_source_file() -> None:
    declared = _hook_ids_from_source()
    registered = set(all_hook_ids())
    orphan = registered - declared
    assert not orphan, (
        f"registry lists {sorted(orphan)} but no src/guard/hooks/*.py "
        f"defines a matching _HOOK_ID. Stale registry entry?"
    )


# === Adapter contract ===


@pytest.mark.parametrize("spec", REGISTERED_HOOKS, ids=lambda s: s.id)
def test_adapter_accepts_normalised_payload(spec: object) -> None:
    """Every adapter must accept ``(tool_name, tool_input)`` without raising.

    Empty/no-match input — adapters should return None, not crash. Catches
    accidental ``tool_input.get("command")`` -> AttributeError when caller
    passes a dict that doesn't have the expected keys.
    """
    # Synthetic harmless input for whichever surfaces the hook handles.
    payloads = [
        ("Bash", {"command": ""}),
        ("Write", {"file_path": ""}),
        ("Read", {"file_path": ""}),
        ("Edit", {"file_path": ""}),
        ("Task", {"description": ""}),
    ]
    for tool_name, tool_input in payloads:
        # Don't care about the return value — only that no exception escapes.
        # Mypy can't narrow `spec` to HookSpec via parametrize; the runtime
        # check is sufficient here.
        result = spec.decide(tool_name, tool_input)  # type: ignore[attr-defined]
        assert result is None or isinstance(result, dict)
