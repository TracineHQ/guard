# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Integration tests for the out-of-band integrity monitor (``bin/guard-integrity-monitor``).

The monitor is what a root LaunchDaemon (macOS) or systemd timer (Linux/WSL)
runs on a schedule, independent of Claude Code hooks (which fail OPEN). It reuses
the same ``bin/guard-sentinel`` heal logic and appends a timestamped advisory
line to an append-only log, so tampering is reverted and recorded even between
agent sessions. Tests drive it against a temp root -- no root privilege required.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

MONITOR = Path(__file__).resolve().parents[2] / "bin" / "guard-integrity-monitor"


def _run_monitor(root: Path, log: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {"GUARD_INTEGRITY_ROOT": str(root), "PATH": "/usr/bin:/bin"}
    if log is not None:
        env["GUARD_INTEGRITY_LOG"] = str(log)
    return subprocess.run(
        ["sh", str(MONITOR)],  # noqa: S607 -- PATH-resolved `sh` is the portable entry point
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_monitor_logs_a_clean_run(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"
    cmd_integrity_build(root, [live])

    result = _run_monitor(root)

    assert result.returncode == 0, result.stderr
    log_text = (root / "monitor.log").read_text()
    assert "clean" in log_text
    assert "rc=0" in log_text


def test_monitor_heals_tampering_and_records_it(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    good = b"good\n"
    live = tmp_path / "settings.json"
    live.write_bytes(good)
    root = tmp_path / "iroot"
    cmd_integrity_build(root, [live])

    live.write_bytes(b"PWNED\n")  # an agent rewrites the protected file between sessions
    result = _run_monitor(root)

    assert result.returncode == 0, result.stderr
    assert live.read_bytes() == good  # the root daemon restored it out of band
    assert "healed" in (root / "monitor.log").read_text()


def test_monitor_records_unhealable_tamper_with_nonzero_rc(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"
    payload, _ = cmd_integrity_build(root, [live])
    canon = root / "canonical" / payload["entries"][0]["canonical"]

    live.write_bytes(b"PWNED\n")
    canon.write_bytes(b"ALSO_PWNED\n")  # both off the anchor -> unhealable

    result = _run_monitor(root)

    assert result.returncode != 0
    log_text = (root / "monitor.log").read_text()
    assert "tamper" in log_text.lower()  # sentinel emits "TAMPER"
    assert "rc=0" not in log_text  # the nonzero exit is recorded in the line


def test_monitor_log_line_is_timestamped_and_appends(tmp_path: Path) -> None:
    from guard.cli import cmd_integrity_build

    live = tmp_path / "settings.json"
    live.write_bytes(b"good\n")
    root = tmp_path / "iroot"
    cmd_integrity_build(root, [live])
    log = tmp_path / "audit.log"

    _run_monitor(root, log=log)
    _run_monitor(root, log=log)  # second run must append, not overwrite

    lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2  # append-only
    for ln in lines:
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ", ln), ln
