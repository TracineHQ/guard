# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Smoke tests for guard.registry."""

from __future__ import annotations

from guard.registry import (
    ALWAYS_DENY,
    COMMANDS,
    SAFE_PREFIXES,
    STRICT_FEEDBACK,
    CommandRule,
    Safety,
    get_rules_by_category,
    get_rules_by_safety,
)


def _lookup(command: str) -> CommandRule | None:
    """Find the longest-prefix rule that matches the given command string."""
    matches = [r for r in COMMANDS if command == r.prefix or command.startswith(r.prefix + " ")]
    if not matches:
        return None
    return max(matches, key=lambda r: len(r.prefix))


# === Smoke ===


def test_registry_imports_ok() -> None:
    assert COMMANDS, "COMMANDS rule list must be non-empty"
    assert SAFE_PREFIXES, "SAFE_PREFIXES must be non-empty"
    assert ALWAYS_DENY, "ALWAYS_DENY must be non-empty"


def test_safety_enum_values() -> None:
    assert Safety.ALLOW.value == "allow"
    assert Safety.ASK.value == "ask"
    assert Safety.DENY.value == "deny"


# === Lookup behaviour ===


def test_lookup_known_dangerous() -> None:
    """`git add -A` is registered as a DENY."""
    rule = _lookup("git add -A")
    assert rule is not None
    assert rule.safety is Safety.DENY


def test_lookup_known_safe() -> None:
    """`git status` is allowed (read-only)."""
    rule = _lookup("git status")
    assert rule is None or rule.safety is Safety.ALLOW


def test_lookup_unknown_returns_none() -> None:
    """Unknown commands fall through (no rule)."""
    assert _lookup("totally-fake-command-xyz") is None


def test_always_deny_contains_git_add_all() -> None:
    assert "git add -A" in ALWAYS_DENY
    assert "git add ." in ALWAYS_DENY
    assert "terraform destroy" in ALWAYS_DENY


def test_safe_prefixes_contains_git_read() -> None:
    assert "git status" in SAFE_PREFIXES
    assert "git log" in SAFE_PREFIXES


def test_strict_feedback_only_for_ask_rules() -> None:
    for prefix, msg in STRICT_FEEDBACK.items():
        rule = next(r for r in COMMANDS if r.prefix == prefix)
        assert rule.safety is Safety.ASK
        assert msg, f"feedback for {prefix!r} must be non-empty"


def test_get_rules_by_safety() -> None:
    deny_rules = get_rules_by_safety(Safety.DENY)
    assert deny_rules
    assert all(r.safety is Safety.DENY for r in deny_rules)


def test_get_rules_by_category() -> None:
    git_read = get_rules_by_category("git-read")
    assert git_read
    assert all(r.category == "git-read" for r in git_read)
