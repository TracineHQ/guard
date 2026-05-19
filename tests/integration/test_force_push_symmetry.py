# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Force-push denylist symmetry.

Background: a 2026-05-07 finding flagged that ``git push --force-with-lease``
was denied but plain ``git push -f`` slipped through. The registry now lists
every force-push form explicitly (``--force``, ``-f``, ``--force-with-lease``,
``--force-if-includes``, ``--mirror``), but the literal-prefix matcher only
fires when the flag sits directly after ``git push``. A common amend-then-push
shape puts the flag at the end (``git push origin main -f``) -- the synth-deny
matcher ``_is_git_force_push`` covers that positional drift.

These tests pin both halves so the asymmetry can't regress silently.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide

FORCE_PUSH_CASES = [
    # Flag directly after ``git push`` (literal-prefix DENY)
    "git push -f",
    "git push --force",
    "git push --force-with-lease",
    "git push --force-if-includes",
    "git push --mirror",
    "git push -f origin main",
    "git push --force origin main",
    "git push --force-with-lease origin main",
    # ``--force-with-lease=<ref>`` attached-value variant
    "git push --force-with-lease=main origin main",
    # Flag at end, past the remote / refspec positionals (synth-deny:
    # bash.git_force_push). This is exactly the amend-then-push convenience
    # vector that the 2026-05-07 finding called out.
    "git push origin main -f",
    "git push origin main --force",
    "git push origin main --force-with-lease",
    "git push origin main --force-if-includes",
    "git push origin main --mirror",
    # ``--force-with-lease=<ref>`` attached-value, flag-at-end.
    "git push origin main --force-with-lease=main",
]


@pytest.mark.parametrize("command", FORCE_PUSH_CASES)
def test_force_push_variant_is_denied(command: str) -> None:
    """Every documented force-push shape must produce a deny envelope."""
    result = decide(command)
    assert result is not None, f"force-push not denied: {command!r}"
    assert result.get("permissionDecision") == "deny", (
        f"force-push not denied: {command!r}; got {result!r}"
    )
    reason = result.get("permissionDecisionReason", "")
    # Every force-push deny -- whether routed via the literal-prefix
    # ``bash.always_deny`` path or the synth-deny ``bash.git_force_push``
    # path -- must surface a rule_id the user can disable / allowlist on.
    assert any(rule_id in reason for rule_id in ("bash.always_deny", "bash.git_force_push")), (
        f"deny reason missing expected rule_id: {reason!r}"
    )


# Non-force pushes must continue to pass through (no over-block regression).
NON_FORCE_PUSH_CASES = [
    "git push",
    "git push origin",
    "git push origin main",
    "git push --tags",
    "git push --set-upstream origin main",
    "git push -u origin main",
]


@pytest.mark.parametrize("command", NON_FORCE_PUSH_CASES)
def test_non_force_push_not_denied(command: str) -> None:
    """Bare ``git push`` and non-force variants must NOT be denied."""
    result = decide(command)
    if result is None:
        return  # passthrough is fine
    assert result.get("permissionDecision") != "deny", (
        f"non-force push wrongly denied: {command!r}; got {result!r}"
    )
