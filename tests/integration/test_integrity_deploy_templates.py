# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Drift guards for the out-of-band monitor's OS-integration templates.

The macOS LaunchDaemon and the Linux/WSL systemd units must keep referencing the
monitor entry point and the env-var contract it reads (``GUARD_INTEGRITY_ROOT``).
These tests pin that wiring so a renamed script or env var fails here instead of
silently shipping a daemon that never runs the check.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
MONITOR_NAME = "guard-integrity-monitor"


def test_launchd_plist_is_valid_and_wired() -> None:
    plist_path = DEPLOY / "com.tracinehq.guard-integrity.plist"
    with plist_path.open("rb") as fh:
        plist = plistlib.load(fh)

    assert plist["Label"] == "com.tracinehq.guard-integrity"
    args = plist["ProgramArguments"]
    assert any(a.endswith(MONITOR_NAME) for a in args), args
    assert "GUARD_INTEGRITY_ROOT" in plist["EnvironmentVariables"]
    assert isinstance(plist["StartInterval"], int)
    assert plist["StartInterval"] > 0  # periodic, not one-shot
    assert plist["RunAtLoad"] is True


def test_systemd_service_runs_the_monitor() -> None:
    service = (DEPLOY / "guard-integrity.service").read_text()
    assert "ExecStart=" in service
    assert MONITOR_NAME in service
    assert "GUARD_INTEGRITY_ROOT" in service  # env contract the monitor requires
    assert "Type=oneshot" in service


def test_systemd_timer_is_periodic_and_enabled() -> None:
    timer = (DEPLOY / "guard-integrity.timer").read_text()
    assert "OnUnitActiveSec=" in timer  # recurring, not a single shot
    assert "WantedBy=timers.target" in timer  # enableable
