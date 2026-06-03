# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Harness steering: redirect ad-hoc ``guard test '<cmd>'`` probes to the corpus.

The steer is the enforcement arm of the corpus harness. Checking how guard
classifies a command should leave a DURABLE artifact -- a ``tests/corpus`` row
adjudicated by ``guard corpus`` -- not an ephemeral ``guard test`` shell call
that the next agent redoes. So inside a guard source checkout, ad-hoc
``guard test`` denies in both modes with a redirect (``bash.use_corpus_harness``).

It self-scopes: a pip-installed guard (no ``tests/``) never sees it, so an
end user trying ``guard test`` is untouched. These tests pin both the probe
detection and the dev-tree gate.
"""

from __future__ import annotations

import pytest

from guard.hooks import bash_command_validator as bcv
from guard.hooks.bash_command_validator import decide
from tests._helpers import is_deny

_PROBES = [
    "guard test 'ls -la'",
    "uv run guard test 'rm -rf /'",
    "uvx guard test 'su'",
    "guard --json test 'x'",
    "uv run guard --json test 'a b c'",
    "guard test --mode auto 'reboot'",
    "timeout 5 guard test 'su'",
]

_NOT_PROBES = [
    "guard corpus",
    "uv run guard corpus",
    "guard --json corpus",
    "guard status",
    "guard test --help",
    "guard test --mode auto",  # flag-only, no positional command
    "echo guard test foo",  # guard is not the command head
    "guards test 'x'",  # not the guard binary
]


@pytest.mark.parametrize("command", _PROBES)
def test_probe_detected(command: str) -> None:
    # _guard_test_probe sees one segment; _candidate_forms handles the timeout wrapper.
    assert any(bcv._guard_test_probe(form) for form in bcv._candidate_forms(command))  # noqa: SLF001


@pytest.mark.parametrize("command", _NOT_PROBES)
def test_non_probe_not_detected(command: str) -> None:
    assert not any(bcv._guard_test_probe(form) for form in bcv._candidate_forms(command))  # noqa: SLF001


@pytest.mark.parametrize("mode", ["default", "auto"])
@pytest.mark.parametrize("command", ["guard test 'ls'", "uv run guard test 'rm -rf /'"])
def test_steers_in_dev_tree(command: str, mode: str) -> None:
    # pytest runs from a source checkout, so the dev-tree gate is naturally True.
    assert bcv._is_guard_dev_tree() is True  # noqa: SLF001
    result = decide(command, permission_mode=mode)
    assert is_deny(result)
    assert "bash.use_corpus_harness" in result["permissionDecisionReason"]


@pytest.mark.parametrize("mode", ["default", "auto"])
def test_no_steer_outside_dev_tree(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """With no corpus on disk (pip install), guard test is never steered."""
    monkeypatch.setattr(bcv, "_is_guard_dev_tree", lambda: False)
    result = decide("guard test 'ls -la'", permission_mode=mode)
    reason = (result or {}).get("permissionDecisionReason", "")
    assert "bash.use_corpus_harness" not in reason
    if mode == "auto":
        # still whitelisted as a read-only subcommand -> auto-allow, not denied
        assert not is_deny(result)


def test_corpus_runner_never_steered() -> None:
    result = decide("uv run guard corpus", permission_mode="auto")
    assert not is_deny(result)
