# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Git read verbs coerced into running a program or writing a file deny.

``git log --output=`` writes a file, ``git diff --ext-diff`` runs the
configured diff driver and ``git grep -O`` opens matches in a program. Each
subform is wrapped in every git global-option form (bare, ``-C /p``, fused
``-C/p``, ``-c k=v``, ``--no-pager``, an ``env`` prefix) and must deny, so a
stripper regression (the fused ``-C/path`` bypass) is caught mechanically.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny


def _difflike_subforms(sub: str) -> list[str]:
    return [f"{sub} --output=/tmp/guardx", f"{sub} --ext-diff"]


def _all_subforms() -> list[str]:
    forms: list[str] = []
    for sub in ("diff", "log", "show"):
        forms += _difflike_subforms(sub)
    forms += ["grep --open-files-in-pager=id pat", "grep -Oid pat"]
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

_MATRIX: list[tuple[str, str]] = [
    (wrap_name, wrap_tpl.format(rest=rest))
    for rest in _all_subforms()
    for wrap_name, wrap_tpl in _WRAPPERS.items()
]


@pytest.mark.parametrize(
    ("wrapper", "command"),
    _MATRIX,
    ids=[f"{w}:{c}" for w, c in _MATRIX],
)
def test_exec_subforms_denied(wrapper: str, command: str) -> None:
    """Every git exec / file-write subform denies under every global wrapper."""
    res = decide(command)
    assert is_deny(res), f"wrapper={wrapper} guard FAILED to deny {command!r} -> {res!r}"
