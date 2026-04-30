"""Contract: every registry.ALWAYS_DENY entry must be enforced by bash_command_validator.

If a future change orphans ALWAYS_DENY (or any specific entry), this test fires.
Auto-parametrized — adding a Safety.DENY rule to registry.py automatically adds a case.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.registry import ALWAYS_DENY  # type: ignore[import-not-found]

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "src" / "guard" / "hooks" / "bash_command_validator.py"


def _run_hook(command: str) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO / "src")
    proc = subprocess.run(  # noqa: S603 -- explicit interpreter, fixed path
        [sys.executable, str(HOOK)],
        input=json.dumps(
            {
                "session_id": "wiring-test",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "hook_event_name": "PreToolUse",
                "cwd": str(REPO),
            }
        ),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


@pytest.mark.parametrize("denied_prefix", sorted(ALWAYS_DENY))
def test_always_deny_entry_is_enforced(denied_prefix: str) -> None:
    """Each ALWAYS_DENY prefix in the registry must produce a deny when fed to the validator."""
    rc, stdout, stderr = _run_hook(denied_prefix)
    # Either exit 2 (legacy deny exit) OR stdout has hookSpecificOutput.permissionDecision == "deny"
    if stdout.strip():
        envelope = json.loads(stdout)
        decision = envelope.get("hookSpecificOutput", {}).get("permissionDecision")
        assert decision == "deny", (
            f"ALWAYS_DENY entry {denied_prefix!r} did NOT deny — got {decision!r}. "
            f"Registry export is orphaned in bash_command_validator.decide(). "
            f"stdout={stdout[:300]} stderr={stderr[:200]}"
        )
    else:
        assert rc == 2, (
            f"ALWAYS_DENY entry {denied_prefix!r} fell through (rc={rc}, no stdout). "
            f"Registry export is orphaned in bash_command_validator.decide(). "
            f"stderr={stderr[:300]}"
        )


def test_always_deny_set_is_nonempty() -> None:
    """Sanity: the registry actually publishes some always-deny rules.

    If this fires, the registry was emptied — investigate before assuming the wiring works.
    """
    assert ALWAYS_DENY, "registry.ALWAYS_DENY is empty — cannot verify wiring"
