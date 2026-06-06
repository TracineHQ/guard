# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Trusted-script (content-pinned interpreter-exec override) behavior in decide().

A ``dangerous_interpreter`` deny on a bare-script-path form is rescued to ALLOW
when the script file's sha256 matches a ``trusted_scripts`` allowlist entry for
its resolved path. The pin is on the script's *bytes*, not the command line, so
operands vary freely; editing the script revokes the trust. Eval/``-m`` forms
have no script file and are never rescued.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from guard.hooks.bash_command_validator import decide

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    script_name: str = "scan.py",
    content: str = "print('ok')\n",
    trust: bool = True,
    trust_sha: str | None = None,
) -> Path:
    """Write a script under an isolated project cwd and (optionally) trust it.

    Returns the project dir (cwd). The autouse ``_isolate_guard_env`` fixture
    keeps the global allowlist empty; the project allowlist lives at
    ``cwd/.claude/guard/allowlist.json``.
    """
    project = tmp_path / "proj"
    project.mkdir()
    script = project / script_name
    script.write_text(content, encoding="utf-8")
    monkeypatch.chdir(project)
    if trust:
        sha = trust_sha if trust_sha is not None else _sha(content)
        path = str(script.resolve())
        al = project / ".claude" / "guard" / "allowlist.json"
        al.parent.mkdir(parents=True, exist_ok=True)
        al.write_text(
            json.dumps(
                {"trusted_scripts": [{"path": path, "sha256": sha, "reason": "vetted helper"}]}
            ),
            encoding="utf-8",
        )
    return project


def test_trusted_script_allowed_interactive(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    d = decide("python3 scan.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "allow"


def test_trusted_script_allowed_strict(tmp_path, monkeypatch):
    """A human-vetted, content-pinned script is an explicit allow — it works
    even in unattended/strict mode, like an allow_commands entry."""
    _setup(tmp_path, monkeypatch)
    d = decide("python3 scan.py", permission_mode="dontAsk")
    assert d is not None
    assert d["permissionDecision"] == "allow"


def test_untrusted_script_denied(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, trust=False)
    d = decide("python3 scan.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"
    assert "dangerous_interpreter" in d["permissionDecisionReason"]


def test_modified_script_denied(tmp_path, monkeypatch):
    """File edited after the pin → sha mismatch → deny (trust is byte-specific)."""
    stale = _sha("old bytes\n")
    _setup(tmp_path, monkeypatch, content="new payload\n", trust_sha=stale)
    d = decide("python3 scan.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_varying_operands_still_allowed(tmp_path, monkeypatch):
    """The pin is on the script, not the command line: different data args
    (the case exact allow_commands could not cover) still allow."""
    _setup(tmp_path, monkeypatch)
    a = decide("python3 scan.py email-1.md", permission_mode="default")
    b = decide("python3 scan.py email-2.md --json", permission_mode="default")
    assert a is not None
    assert a["permissionDecision"] == "allow"
    assert b is not None
    assert b["permissionDecision"] == "allow"


def test_eval_form_never_trusted(tmp_path, monkeypatch):
    """``-c`` has no script file to pin; a present trust entry must not rescue it."""
    _setup(tmp_path, monkeypatch)
    d = decide("python3 -c 'import os'", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_module_form_never_trusted(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    d = decide("python3 -m http.server", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_wrapped_uv_run_python_trusted(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    d = decide("uv run python scan.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "allow"


def test_piped_trusted_script_denied(tmp_path, monkeypatch):
    """Trust is honored only for a single segment — a pipeline still denies."""
    _setup(tmp_path, monkeypatch)
    d = decide("python3 scan.py | cat", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_nonexistent_script_denied(tmp_path, monkeypatch):
    """A missing file can't be hashed → never trusted → deny (fail-safe)."""
    _setup(tmp_path, monkeypatch)
    d = decide("python3 ghost.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_bun_script_not_trusted_v1(tmp_path, monkeypatch):
    """bun/deno's subcommand surface is excluded from trust in v1 — a path-form
    bun script stays denied even with a trust entry (fail-safe boundary)."""
    _setup(tmp_path, monkeypatch, script_name="scan.ts", content="console.log(1)\n")
    d = decide("bun scan.ts", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_deny_message_points_at_trust_script(tmp_path, monkeypatch):
    """A bare-script deny must offer the safe, scalable override (trust-script),
    naming the script — not just the blunt disable-rule. This is the tier-0 fix
    for the churn loop."""
    _setup(tmp_path, monkeypatch, trust=False)
    d = decide("python3 scan.py", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"
    reason = d["permissionDecisionReason"]
    assert "guard trust-script" in reason
    assert "scan.py" in reason


def test_eval_deny_message_omits_trust_script(tmp_path, monkeypatch):
    """An eval form has no file to pin, so the message must NOT dangle a
    trust-script suggestion the human can't act on."""
    _setup(tmp_path, monkeypatch, trust=False)
    d = decide("python3 -c 'import os'", permission_mode="default")
    assert d is not None
    assert d["permissionDecision"] == "deny"
    assert "guard trust-script" not in d["permissionDecisionReason"]


def test_agent_cannot_self_trust_in_strict(tmp_path, monkeypatch):
    """The trust-grant command is not on any safe-prefix, so an unattended agent
    can't run `guard trust-script` to grant itself trust — it default-denies in
    strict mode. (Granting is a human action; the trust store is a protected file.)"""
    _setup(tmp_path, monkeypatch, trust=False)
    d = decide("guard trust-script scan.py --reason pwn", permission_mode="dontAsk")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_agent_cannot_self_untrust_in_strict(tmp_path, monkeypatch):
    """`untrust-script` mutates the trust store too — it must also be off the
    safe-prefix and default-deny for an unattended agent."""
    _setup(tmp_path, monkeypatch, trust=False)
    d = decide("guard untrust-script scan.py", permission_mode="dontAsk")
    assert d is not None
    assert d["permissionDecision"] == "deny"


def test_repin_after_edit_allows_again(tmp_path, monkeypatch):
    """Full recovery round-trip: a trusted script, edited (deny via sha mismatch),
    is re-pinned to its new bytes and allows again — with operands still free."""
    from guard.allowlist import add_trusted_script

    project = _setup(tmp_path, monkeypatch, content="new payload\n", trust_sha=_sha("old bytes\n"))
    # Edited bytes don't match the stale pin → deny.
    assert decide("python3 scan.py", permission_mode="default")["permissionDecision"] == "deny"

    # Human re-reads and re-pins the current bytes.
    resolved = str((project / "scan.py").resolve())
    add_trusted_script(
        path=resolved,
        sha256=_sha("new payload\n"),
        reason="re-vetted",
        scope="project",
        cwd=project,
    )

    assert decide("python3 scan.py", permission_mode="default")["permissionDecision"] == "allow"
    # Operands still vary freely after re-pin.
    assert (
        decide("python3 scan.py a b --json", permission_mode="default")["permissionDecision"]
        == "allow"
    )
