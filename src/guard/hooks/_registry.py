# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Single source of truth for the guard hook surface.

Before this module existed, four sites maintained their own hand-written
hook lists:

* ``cli.cmd_test`` — hardcoded tuple of three ``(id, decide)`` pairs.
* ``cli.cmd_diff`` — hardcoded list of seven hook id strings.
* ``allowlist.KNOWN_RULE_IDS`` — hardcoded tuple of four whole-hook
  disable ids.
* Each hook module's ``_HOOK_ID`` literal.

Those lists drifted: ``cmd_test`` was missing three hooks (``credential_check``,
``agent_output_guard``, ``protected_files``) that genuinely act on ``Bash``
tool input, which meant ``guard test "<command>"`` silently skipped them and
gave callers a misleadingly green answer.

This module fixes that by providing a single registry. New hooks add one
``HookSpec`` here and every consumer picks them up automatically.

Why a per-entry adapter:
    The seven hook ``decide()`` functions have three different signatures
    (``(command)``, ``(command, cwd)``, ``(tool_name, tool_input)``).
    Forcing every caller to branch on hook id would just re-create the
    drift problem at the call sites. The adapter normalises every hook to
    one shape — ``(tool_name, tool_input) -> envelope | None`` — so callers
    iterate the registry blindly.

Why imports are lazy inside the adapters:
    Importing every hook module at registry import time would inflate
    ``guard`` CLI cold start (each hook pulls in ``registry.py``'s
    multi-thousand-line COMMANDS table plus regex compilation). Adapters
    do the import on first call instead, matching the lazy-import idiom
    that ``cmd_test`` and ``cmd_diff`` already used. The registry itself
    stays pure-data so ``allowlist.py`` can import it without forcing the
    hook modules to load.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

# Public type alias for the normalised adapter shape.
HookDecide = Callable[[str, Mapping[str, Any]], dict[str, Any] | None]


# Tool surfaces a hook can act on. Mirrors Claude Code PreToolUse tool names
# but kept as a free-form str to avoid coupling to a closed set — new tool
# names appear in Claude Code regularly and we don't want this enum to
# silently miss them.
#
# Conventional values currently used:
#   "Bash"             — Bash tool command string
#   "Write" / "Edit"   — file-mutation tools (file_path key)
#   "Read"             — file-read tools (file_path key)
#   "Task"             — subagent dispatch
SURFACE_BASH = "Bash"
SURFACE_WRITE = "Write"
SURFACE_EDIT = "Edit"
SURFACE_READ = "Read"
SURFACE_TASK = "Task"


@dataclass(frozen=True)
class HookSpec:
    """Registry entry for one guard hook.

    Attributes:
        id: Stable hook identifier (e.g. ``"guard.bash_command_validator"``).
            This is what appears in the audit log, in the allowlist's
            ``disable_rules``, and in user-facing ``guard diff`` output.
        surfaces: The Claude Code tool names this hook acts on. Used by
            ``bash_surface_hooks()`` and similar filters so callers can ask
            "which hooks would I want to test against a Bash command".
        decide: Normalised entry point. Always accepts
            ``(tool_name, tool_input)`` — adapters in this module convert
            from each hook's native signature.
        supports_disable_hook: True when the hook honours allowlist
            ``disable_rules`` containing its own ``hook_id``. False for
            hooks where whole-hook disable is intentionally not offered:
            ``bash_command_validator`` (per-matcher rule_ids are the
            disable surface — disabling the whole hook would mute every
            bash matcher at once, which is rarely what users want), and
            hooks that don't currently consult the allowlist at all
            (``agent_output_guard``, ``subagent_scope``).
    """

    id: str
    surfaces: frozenset[str]
    decide: HookDecide
    supports_disable_hook: bool = False


# ---------------------------------------------------------------------------
# Adapters
#
# Each adapter is small on purpose. They serve as the only place that knows
# how to convert from a hook's native decide() signature to the standard
# (tool_name, tool_input) -> envelope shape. Lazy imports keep CLI cold
# start fast (see module docstring).
# ---------------------------------------------------------------------------


def _command_from_bash(tool_name: str, tool_input: Mapping[str, Any]) -> str | None:
    """Return the bash command string when the tool is Bash, else None.

    Shared helper for the three hooks whose decide() takes only ``command``.
    Centralising the type check here avoids three near-identical fragments.
    """
    if tool_name != SURFACE_BASH:
        return None
    cmd = tool_input.get("command")
    return cmd if isinstance(cmd, str) else None


def _bash_command_validator_decide(
    tool_name: str, tool_input: Mapping[str, Any]
) -> dict[str, Any] | None:
    cmd = _command_from_bash(tool_name, tool_input)
    if cmd is None:
        return None
    from guard.hooks import bash_command_validator  # noqa: PLC0415

    return bash_command_validator.decide(cmd)


def _git_c_validator_decide(tool_name: str, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
    cmd = _command_from_bash(tool_name, tool_input)
    if cmd is None:
        return None
    from guard.hooks import git_c_validator  # noqa: PLC0415

    return git_c_validator.decide(cmd)


def _commit_message_validator_decide(
    tool_name: str, tool_input: Mapping[str, Any]
) -> dict[str, Any] | None:
    cmd = _command_from_bash(tool_name, tool_input)
    if cmd is None:
        return None
    from guard.hooks import commit_message_validator  # noqa: PLC0415

    return commit_message_validator.decide(cmd)


def _credential_check_decide(
    tool_name: str, tool_input: Mapping[str, Any]
) -> dict[str, Any] | None:
    from guard.hooks import credential_check  # noqa: PLC0415

    # credential_check already takes (tool_name, tool_input) natively — no
    # shape conversion needed. The wrapper exists only to defer the import.
    return credential_check.decide(tool_name, dict(tool_input))


def _agent_output_guard_decide(
    tool_name: str, tool_input: Mapping[str, Any]
) -> dict[str, Any] | None:
    from guard.hooks import agent_output_guard  # noqa: PLC0415

    return agent_output_guard.decide(tool_name, dict(tool_input))


def _protected_files_decide(tool_name: str, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
    from guard.hooks import protected_files  # noqa: PLC0415

    # ``protected_files.decide()`` is the pure decision logic shared with the
    # production hook entry point — no I/O, no allowlist consultation.
    return protected_files.decide(tool_name, dict(tool_input))


def _subagent_scope_decide(tool_name: str, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
    # subagent_scope is event-driven (Task tool with a scope manifest) and
    # not test-meaningful through a synthetic payload. Returns None so the
    # registry can list it for ``guard diff`` while ``guard test`` reports
    # passthrough.
    del tool_name, tool_input
    return None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


REGISTERED_HOOKS: tuple[HookSpec, ...] = (
    HookSpec(
        id="guard.bash_command_validator",
        surfaces=frozenset({SURFACE_BASH}),
        decide=_bash_command_validator_decide,
        # Per-matcher rule_ids are the disable surface, not the hook id.
        supports_disable_hook=False,
    ),
    HookSpec(
        id="guard.git_c_validator",
        surfaces=frozenset({SURFACE_BASH}),
        decide=_git_c_validator_decide,
        supports_disable_hook=True,
    ),
    HookSpec(
        id="guard.commit_message_validator",
        surfaces=frozenset({SURFACE_BASH}),
        decide=_commit_message_validator_decide,
        supports_disable_hook=True,
    ),
    HookSpec(
        id="guard.credential_check",
        # Acts on Bash command strings (tar/cp/scp source paths) AND
        # Write/Edit file paths (touching ``.aws/credentials`` directly).
        surfaces=frozenset({SURFACE_BASH, SURFACE_WRITE, SURFACE_EDIT, SURFACE_READ}),
        decide=_credential_check_decide,
        supports_disable_hook=True,
    ),
    HookSpec(
        id="guard.protected_files",
        # Bash (rm/cp/mv against protected paths) + file-write tools.
        surfaces=frozenset({SURFACE_BASH, SURFACE_WRITE, SURFACE_EDIT}),
        decide=_protected_files_decide,
        supports_disable_hook=True,
    ),
    HookSpec(
        id="guard.agent_output_guard",
        # Scans every tool input for paths inside an agent-session tree;
        # also re-checks the raw Bash command string.
        surfaces=frozenset({SURFACE_BASH, SURFACE_WRITE, SURFACE_EDIT, SURFACE_READ}),
        decide=_agent_output_guard_decide,
        supports_disable_hook=False,
    ),
    HookSpec(
        id="guard.subagent_scope",
        surfaces=frozenset({SURFACE_TASK}),
        decide=_subagent_scope_decide,
        supports_disable_hook=False,
    ),
)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def hooks_for_surface(surface: str) -> tuple[HookSpec, ...]:
    """Return hooks that act on the given tool surface (e.g. ``"Bash"``)."""
    return tuple(h for h in REGISTERED_HOOKS if surface in h.surfaces)


def bash_surface_hooks() -> tuple[HookSpec, ...]:
    """Return hooks that act on Bash tool input.

    Used by ``guard test "<command>"`` so the CLI fans out to every hook
    that could plausibly fire on a bash command, not just the three that
    happened to be wired by hand.
    """
    return hooks_for_surface(SURFACE_BASH)


def all_hook_ids() -> tuple[str, ...]:
    """Return every registered hook id, in declaration order."""
    return tuple(h.id for h in REGISTERED_HOOKS)


def disable_hook_ids() -> tuple[str, ...]:
    """Return hook ids that honour whole-hook disable via the allowlist."""
    return tuple(h.id for h in REGISTERED_HOOKS if h.supports_disable_hook)


# ---------------------------------------------------------------------------
# Re-exports
# ---------------------------------------------------------------------------

__all__ = (
    "REGISTERED_HOOKS",
    "SURFACE_BASH",
    "SURFACE_EDIT",
    "SURFACE_READ",
    "SURFACE_TASK",
    "SURFACE_WRITE",
    "HookDecide",
    "HookSpec",
    "all_hook_ids",
    "bash_surface_hooks",
    "disable_hook_ids",
    "hooks_for_surface",
)
