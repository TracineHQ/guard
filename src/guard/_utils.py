"""Shared utilities for Claude Code guard hooks.

Provides:
- Rotating log handler for hook debugging
- Circuit breaker to skip hooks after repeated failures
- Skill state tracking for active session skills
- Standard stdin parsing and PreToolUse decision helpers
- JSONL decision logging at ``~/.claude/guard-decisions.jsonl``

Usage in hooks::

    from guard._utils import (
        check_circuit,
        get_hook_logger,
        record_failure,
        record_success,
    )

    def main() -> None:
        if not check_circuit("session_hook"):
            return  # Circuit open, skip

        logger = get_hook_logger("session_hook")
        try:
            # ... hook logic
            record_success("session_hook")
        except Exception:
            record_failure("session_hook")
            logger.exception("Hook failed")
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Callable

# Storage locations
TOOLKIT_HOME = Path(os.environ.get("GUARD_DATA_DIR", str(Path.home() / ".claude" / "guard")))
LOG_DIR = TOOLKIT_HOME / "logs"
CIRCUIT_FILE = TOOLKIT_HOME / ".hook_circuit.json"
SKILL_STATE_DIR = TOOLKIT_HOME / ".skill_state"

# Decision JSONL log (env-overridable for tests)
GUARD_DECISIONS_PATH = os.environ.get(
    "GUARD_DECISIONS_PATH", str(Path("~/.claude/guard-decisions.jsonl").expanduser())
)

# Circuit breaker settings
MAX_FAILURES = 3
RESET_TIMEOUT_SECONDS = 300  # 5 minutes


def _env_int(name: str, default: int) -> int:
    """Parse int from environment variable, falling back to default on miss/invalid."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _log_debug(msg: str) -> None:
    """Emit a debug line to stderr when ``GUARD_DEBUG=1``."""
    if os.environ.get("GUARD_DEBUG") == "1":
        sys.stderr.write(f"[guard] {msg}\n")


# Loop detection settings
LOOP_DETECTION_THRESHOLD = _env_int("GUARD_LOOP_THRESHOLD", 3)
LOOP_DETECTION_WINDOW_MINUTES = _env_int("GUARD_LOOP_WINDOW", 10)

# Context budget settings
CONTEXT_BUDGET_WARN_BYTES = _env_int("GUARD_CONTEXT_WARN", 500_000)
CONTEXT_BUDGET_HARD_BYTES = _env_int("GUARD_CONTEXT_HARD", 1_000_000)

# Output truncation settings
OUTPUT_TRUNCATION_THRESHOLD = _env_int("GUARD_OUTPUT_TRUNCATION", 50_000)
OUTPUT_STORE_DIR = Path(os.environ.get("GUARD_OUTPUT_DIR", str(TOOLKIT_HOME / "outputs")))
OUTPUT_RETENTION_HOURS = _env_int("GUARD_OUTPUT_RETENTION", 24)


def get_hook_logger(name: str) -> logging.Logger:
    """Get a logger for hook debugging.

    Logs are written to ``$GUARD_DATA_DIR/logs/hooks.log`` with rotation.

    Args:
        name: Hook name (e.g., ``session_hook``, ``session_start_hook``).

    Returns:
        Configured logger instance.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"hook.{name}")

    # Only add handler if not already configured
    if not logger.handlers:
        handler = RotatingFileHandler(
            LOG_DIR / "hooks.log",
            maxBytes=1_000_000,  # 1MB
            backupCount=3,
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

    return logger


def check_circuit(hook_name: str = "") -> bool:
    """Check if a specific hook should execute.

    Returns ``True`` if the circuit is closed (hook should run) or ``False`` if
    the circuit is open (hook should skip).

    After ``MAX_FAILURES`` consecutive failures for this hook, its circuit
    opens for ``RESET_TIMEOUT_SECONDS``. Other hooks are unaffected.
    """
    if not CIRCUIT_FILE.exists():
        return True

    try:
        data = json.loads(CIRCUIT_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return True

    hook_data = data.get(hook_name, {}) if isinstance(data, dict) else {}
    failures = int(hook_data.get("failures", 0))
    last_failure = float(hook_data.get("last_failure", 0))

    if failures >= MAX_FAILURES:
        return time.time() - last_failure > RESET_TIMEOUT_SECONDS
    return True


def record_success(hook_name: str = "") -> None:
    """Record a successful hook execution.

    Removes this hook's entry from the circuit breaker state. Other hooks'
    state is preserved.
    """
    try:
        if not CIRCUIT_FILE.exists():
            return
        data = json.loads(CIRCUIT_FILE.read_text())
        if hook_name in data:
            del data[hook_name]
        if data:
            CIRCUIT_FILE.write_text(json.dumps(data))
        else:
            CIRCUIT_FILE.unlink()
    except (json.JSONDecodeError, OSError):
        pass


def record_failure(hook_name: str = "") -> None:
    """Record a failed hook execution for a specific hook.

    Increments this hook's failure count. After ``MAX_FAILURES``, only this
    hook's circuit opens.
    """
    try:
        data: dict[str, Any] = {}
        if CIRCUIT_FILE.exists():
            with contextlib.suppress(json.JSONDecodeError):
                data = json.loads(CIRCUIT_FILE.read_text())

        hook_data = data.get(hook_name, {"failures": 0, "last_failure": 0})
        hook_data["failures"] = hook_data.get("failures", 0) + 1
        hook_data["last_failure"] = time.time()
        data[hook_name] = hook_data

        CIRCUIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        CIRCUIT_FILE.write_text(json.dumps(data))
    except OSError:
        pass


SKILL_STATE_MAX_AGE_SECONDS = 3600  # 1 hour


def get_active_skill(session_id: str) -> str | None:
    """Read the current active skill from a session state file.

    Returns ``None`` if no state file exists, the file is stale (>1 hour),
    or it is unreadable.
    """
    state_path = SKILL_STATE_DIR / f"{session_id}.json"
    if not state_path.exists():
        return None
    try:
        mtime = state_path.stat().st_mtime
        if time.time() - mtime > SKILL_STATE_MAX_AGE_SECONDS:
            state_path.unlink(missing_ok=True)
            return None
        state = json.loads(state_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    skill_name = state.get("skill_name") if isinstance(state, dict) else None
    if isinstance(skill_name, str):
        return skill_name
    return None


def set_active_skill(session_id: str, skill_name: str) -> None:
    """Set the active skill for a session via a state file."""
    SKILL_STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_path = SKILL_STATE_DIR / f"{session_id}.json"
    state = {
        "skill_name": skill_name,
        "started_at": datetime.now(UTC).isoformat(),
    }
    with contextlib.suppress(OSError):
        state_path.write_text(json.dumps(state))


def clear_active_skill(session_id: str) -> None:
    """Clear the active skill state file for a session."""
    state_path = SKILL_STATE_DIR / f"{session_id}.json"
    with contextlib.suppress(OSError):
        state_path.unlink(missing_ok=True)


# === Shared Hook Utilities ===
# Standard patterns for stdin parsing, decision output, and error handling.
# All hooks should use these instead of reimplementing the boilerplate.


def parse_hook_input() -> dict[str, Any] | None:
    """Read and parse the stdin JSON payload.

    Returns the parsed dict on success, or ``None`` on any error (empty
    stdin, invalid JSON, IO error). Hooks should return silently
    (passthrough) when this returns ``None``.
    """
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def make_decision(decision: str, reason: str) -> str:
    """Build a ``hookSpecificOutput`` JSON string for PreToolUse decisions.

    Args:
        decision: ``"allow"``, ``"deny"``, or ``"ask"``.
        reason: Human-readable explanation.

    Returns:
        JSON string ready to print to stdout.
    """
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(output)


def emit_pretooluse_decision(
    decision: Literal["allow", "deny"],
    reason: str,
    *,
    updated_input: dict[str, Any] | None = None,
    additional_context: str | None = None,
) -> dict[str, Any]:
    """Build a PreToolUse decision envelope per DD-16/R3.

    Args:
        decision: ``"allow"`` or ``"deny"``.
        reason: Human-readable rationale surfaced to the user/agent.
        updated_input: Optional rewritten tool input merged into the envelope.
        additional_context: Optional extra context string for the agent.

    Returns:
        Decision envelope ready to ``json.dumps`` to stdout.
    """
    envelope: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if updated_input is not None:
        envelope["hookSpecificOutput"]["updatedInput"] = updated_input
    if additional_context is not None:
        envelope["hookSpecificOutput"]["additionalContext"] = additional_context
    return envelope


def safe_main(hook_fn: Callable[[dict[str, Any]], None]) -> None:
    """Wrap a hook function with stdin parsing and exception handling.

    Reads stdin JSON, calls ``hook_fn(payload)``. If stdin is invalid or
    ``hook_fn`` raises, exits silently (passthrough). Hooks should never
    block on errors.

    Args:
        hook_fn: Callable that takes a dict payload. May call
            ``sys.exit(2)`` for hard deny, or ``print(make_decision(...))``
            for decisions. No return value is required for passthrough.
    """
    try:
        payload = parse_hook_input()
        if payload is None:
            return
        hook_fn(payload)
    except SystemExit:
        raise  # Allow sys.exit() from hook_fn
    except Exception:  # noqa: BLE001, S110 -- silent passthrough is the design contract
        pass  # Silent passthrough on any error
