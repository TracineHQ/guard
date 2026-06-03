# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Systematic ref/config-write coverage over guard's git allow surface.

Instead of discovering ref-write bypasses one adversarial finding at a time,
this bounds the surface and enumerates it. Every bypass of this class has the
same shape: a git prefix that guard ALLOW-lists as read-only, but which has a
write subform (``git branch <name>`` creates a ref, ``git worktree add -b``
creates a branch, ``git remote add`` writes config, ``git log --output=`` writes
a file). That set is finite and DERIVABLE from guard's own allow-list.

Two layers, both derived so they cannot drift:

1. ``test_allow_surface_is_classified`` -- a completeness guard. It reads the
   git subcommands guard allow-lists (from ``SAFE_PREFIXES``) and asserts every
   one is explicitly classified as write-bearing, pure-read, or file-write.
   Adding a new ``CommandRule("git <sub>", Safety.ALLOW, ...)`` without
   classifying it here fails this test -- you cannot silently widen the allow
   surface and reintroduce a hole.

2. ``test_write_subforms_denied`` -- the matrix. For each write-bearing prefix
   it GENERATES the write subforms from the predicate's own flag-sets
   (``_GIT_BRANCH_MUTATING_FLAGS`` etc.), wraps each in every git-global form
   (bare, ``-C /p``, fused ``-C/p``, ``-c k=v``, ``--no-pager``), and asserts a
   deny in BOTH modes. This closes both axes at once -- which subform AND how it
   is wrapped -- so a new mutating flag or a stripper regression (e.g. the fused
   ``-C/path`` bypass) is caught mechanically.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from guard.registry import (
    _GIT_BRANCH_MUTATING_FLAGS,
    _GIT_REMOTE_WRITE_ACTIONS,
    _GIT_TAG_MUTATING_FLAGS,
    SAFE_PREFIXES,
)
from tests._helpers import is_deny

# --- Layer 1: the allow surface, derived + classified -----------------------

# git subcommands guard ALLOW-lists (tokens[1] of every "git ..." SAFE_PREFIX).
GIT_ALLOW_SUBCOMMANDS: frozenset[str] = frozenset(
    p.split()[1] for p in SAFE_PREFIXES if p.split()[0] == "git" and len(p.split()) >= 2
)

# Prefixes with a ref/config/exec WRITE subform reachable under the allow prefix.
# Each must have a generator below and is deny-tested across the wrapper matrix.
WRITE_BEARING: frozenset[str] = frozenset(
    {"branch", "tag", "remote", "worktree", "diff", "log", "show", "grep"}
)
# Genuinely read-only as allow-listed: no ref/config/exec write subform reachable
# via the bare prefix (e.g. "git config --get" is allow-listed, "git config k v"
# is NOT a SAFE_PREFIX and default-denies; "git stash list/show" are read).
PURE_READ: frozenset[str] = frozenset(
    {
        "status",
        "blame",
        "rev-parse",
        "describe",
        "ls-files",
        "stash",
        "config",
        "shortlog",
        "rev-list",
        "name-rev",
    }
)
# Writes the working tree (file rename) but NOT a ref or remote config -- a
# deliberate "git-write-safe" allow, out of this test's ref/config scope.
FILE_WRITE_OUT_OF_SCOPE: frozenset[str] = frozenset({"mv"})

_CLASSIFIED = WRITE_BEARING | PURE_READ | FILE_WRITE_OUT_OF_SCOPE


def test_allow_surface_is_classified() -> None:
    """Every allow-listed git subcommand is explicitly classified.

    Fails when a new ``CommandRule("git <sub>", Safety.ALLOW, ...)`` lands
    without an entry above -- forcing the author to declare whether it has a
    write subform (and add it to the matrix) rather than silently widening the
    allow surface.
    """
    unclassified = GIT_ALLOW_SUBCOMMANDS - _CLASSIFIED
    assert not unclassified, (
        f"new git allow-listed subcommand(s) {sorted(unclassified)} are not "
        f"classified in test_git_write_coverage. Add each to WRITE_BEARING "
        f"(with a generator + deny coverage), PURE_READ, or FILE_WRITE_OUT_OF_SCOPE."
    )
    stale = _CLASSIFIED - GIT_ALLOW_SUBCOMMANDS - {"diff", "log", "show", "grep"}
    # diff/log/show/grep are allow-listed via SAFE_PREFIXES too; guard against a
    # classification entry for a subcommand that is no longer allow-listed.
    assert not (stale - GIT_ALLOW_SUBCOMMANDS), (
        f"classification lists {sorted(stale)} but they are no longer allow-listed"
    )


# --- Layer 2: the write-subform x wrapper x mode matrix ----------------------


def _branch_subforms() -> list[str]:
    forms = [f"branch {flag} zzzref" for flag in sorted(_GIT_BRANCH_MUTATING_FLAGS)]
    forms.append("branch newref12345")  # bare positional = ref creation
    return forms


def _tag_subforms() -> list[str]:
    forms = [f"tag {flag} v99tag" for flag in sorted(_GIT_TAG_MUTATING_FLAGS)]
    forms.append("tag newtag12345")
    return forms


def _remote_subforms() -> list[str]:
    return [f"remote {action} rname http://x/y" for action in sorted(_GIT_REMOTE_WRITE_ACTIONS)]


def _worktree_subforms() -> list[str]:
    return ["worktree add -b nb12345 /tmp/wt main", "worktree add -B nb12345 /tmp/wt"]


def _difflike_subforms(sub: str) -> list[str]:
    return [f"{sub} --output=/tmp/guardx", f"{sub} --ext-diff"]


def _grep_subforms() -> list[str]:
    return ["grep --open-files-in-pager=id pat", "grep -Oid pat"]


def _all_subforms() -> list[str]:
    forms: list[str] = []
    forms += _branch_subforms()
    forms += _tag_subforms()
    forms += _remote_subforms()
    forms += _worktree_subforms()
    for sub in ("diff", "log", "show"):
        forms += _difflike_subforms(sub)
    forms += _grep_subforms()
    return forms


# Global-option wrappers inserted between ``git`` and the subcommand. The deny
# floors run on the canonical (global-stripped) form, so a stripper that misses
# any of these is a bypass -- this is exactly how fused ``-C/path`` leaked.
_WRAPPERS: dict[str, str] = {
    "bare": "git {rest}",
    "dash_C_spaced": "git -C /tmp {rest}",
    "dash_C_fused": "git -C/tmp {rest}",
    "dash_c_config": "git -c core.pager=cat {rest}",
    "no_pager": "git --no-pager {rest}",
    "env_prefix": "env GIT_PAGER=cat git {rest}",
}

_MATRIX: list[tuple[str, str, str]] = [
    (wrap_name, wrap_tpl.format(rest=rest), mode)
    for rest in _all_subforms()
    for wrap_name, wrap_tpl in _WRAPPERS.items()
    for mode in ("auto", "default")
]


@pytest.mark.parametrize(
    ("wrapper", "command", "mode"),
    _MATRIX,
    ids=[f"{w}:{m}:{c}" for w, c, m in _MATRIX],
)
def test_write_subforms_denied(wrapper: str, command: str, mode: str) -> None:
    """Every git write subform denies in both modes under every global wrapper."""
    res = decide(command, permission_mode=mode)
    assert is_deny(res), (
        f"[{mode}] wrapper={wrapper} guard FAILED to deny a git ref/config/exec "
        f"write: {command!r} -> {res!r}"
    )
