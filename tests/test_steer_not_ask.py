# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Guard never asks: every flagged call is a deny that steers the agent.

Also covers the posture that goes with it:

- read-only tools never trip ``protected_files``;
- ``.claude/settings*.json`` are not guard's to protect;
- the default protected list is guard's own trust root; git-exec, agent
  instruction, MCP and cloud-profile files are protected only in lockdown;
- strict default-deny is opt-in via ``guard mode lockdown`` and never
  switched on by Claude Code's ``permission_mode``;
- ``guard mode off`` silences every hook except the trust root, and
  ``shadow`` logs without blocking.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

import pytest

from guard.hooks import (
    agent_output_guard,
    bash_command_validator,
    commit_message_validator,
    credential_check,
    git_c_validator,
    protected_files,
    subagent_scope,
)

SRC = Path(__file__).resolve().parent.parent / "src" / "guard"
# Built at runtime so this source never holds a literal agent-output path
# (the installed agent_output_guard denies any tool call that contains one).
_AGENT_OUTPUT_FILE = str(Path("/private/tmp/claude-501/s/tasks") / ("a." + "output"))


def _set_mode(mode: str) -> None:
    path = Path(os.environ["GUARD_DATA_DIR"]) / "allowlist.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mode": mode}), encoding="utf-8")


def _decision(envelope: dict[str, Any] | None) -> str | None:
    if envelope is None:
        return None
    hso = envelope.get("hookSpecificOutput", envelope)
    return hso.get("permissionDecision")


def _require(envelope: dict[str, Any] | None) -> dict[str, Any]:
    assert envelope is not None
    return envelope


def _reason(envelope: dict[str, Any]) -> str:
    hso = envelope.get("hookSpecificOutput", envelope)
    return str(hso.get("permissionDecisionReason", ""))


def _assert_steer(envelope: dict[str, Any] | None) -> str:
    """A steer is a deny whose reason tells the agent what to do instead."""
    assert _decision(envelope) == "deny", envelope
    assert envelope is not None
    reason = _reason(envelope)
    assert "confirm" not in reason.lower(), reason
    assert "—" not in reason, f"em dash in reason: {reason!r}"
    return reason


def _run_hook(module: Any, payload: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> str:
    """Run a hook; a deny exits 2, anything else returns normally."""
    code = 0
    try:
        module.hook(payload)
    except SystemExit as exc:
        code = exc.code
    assert code in (0, 2)
    return capsys.readouterr().out


def _payload(tool_name: str, tool_input: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "session_id": "steer-test",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": str(Path.cwd()),
        **extra,
    }


# === No asks anywhere ===


def test_no_source_emits_an_ask() -> None:
    pattern = re.compile(r'emit_pretooluse_decision\(\s*"ask"|"permissionDecision":\s*"ask"')
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


# === protected_files ===


@pytest.mark.parametrize(
    "rel",
    [
        "src/guard/hooks/bash_command_validator.py",
        "src/guard/registry.py",
        "src/guard/_utils.py",
        ".claude/guard/allowlist.json",
        ".claude/subagent-scope.json",
    ],
)
def test_trust_root_edit_is_a_steering_deny(tmp_path: Path, rel: str) -> None:
    envelope = protected_files.decide("Edit", {"file_path": str(tmp_path / rel)})
    reason = _assert_steer(envelope)
    assert "tell the user" in reason.lower()


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Read", {"file_path": "/repo/src/guard/_utils.py"}),
        ("Read", {"file_path": "/repo/.claude/guard/allowlist.json"}),
        ("Grep", {"pattern": "def ", "path": "/repo/src/guard/hooks/protected_files.py"}),
        ("Glob", {"pattern": "*.py", "path": "/repo/src/guard/hooks"}),
        ("LS", {"path": "/repo/.git/hooks"}),
        ("NotebookRead", {"notebook_path": "/repo/src/guard/registry.py"}),
    ],
)
def test_read_only_tools_never_trip(tool_name: str, tool_input: dict[str, Any]) -> None:
    assert protected_files.decide(tool_name, tool_input) is None
    assert protected_files.decide(tool_name, tool_input, lockdown=True) is None


@pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
def test_settings_files_are_not_protected(tmp_path: Path, name: str) -> None:
    target = {"file_path": str(tmp_path / ".claude" / name)}
    assert protected_files.decide("Edit", target) is None
    assert protected_files.decide("Edit", target, lockdown=True) is None


@pytest.mark.parametrize(
    "rel",
    [
        "CLAUDE.md",
        ".git/config",
        ".git/hooks/pre-commit",
        ".gitmodules",
        ".claude/mcp.json",
        ".aws/config",
    ],
)
def test_extended_list_is_lockdown_only(tmp_path: Path, rel: str) -> None:
    target = {"file_path": str(tmp_path / rel)}
    assert protected_files.decide("Write", target) is None
    _assert_steer(protected_files.decide("Write", target, lockdown=True))


def test_interpreter_read_of_protected_path_passes() -> None:
    cmd = "python3 -c \"print(open('src/guard/_utils.py').read())\""
    assert protected_files.decide("Bash", {"command": cmd}) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "python3 -c \"open('src/guard/_utils.py','w').write('')\"",
        "python3 -c \"import pathlib; pathlib.Path('src/guard/registry.py').write_text('')\"",
        "node -e \"require('fs').writeFileSync('src/guard/_utils.py','')\"",
        "ruby -e \"File.write('src/guard/_utils.py','')\"",
    ],
)
def test_interpreter_write_to_protected_path_denies(cmd: str) -> None:
    _assert_steer(protected_files.decide("Bash", {"command": cmd}))


def test_oversized_eval_body_still_denies() -> None:
    body = "x" * (1024 * 1024 + 1)
    _assert_steer(protected_files.decide("Bash", {"command": f"python3 -c '{body}'"}))


@pytest.mark.parametrize("rel", ["src/guard/_utils.py", ".claude/guard/allowlist.json"])
@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_trust_root_holds_in_off_and_shadow(
    tmp_path: Path, mode: str, rel: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_mode(mode)
    out = _run_hook(protected_files, _payload("Edit", {"file_path": str(tmp_path / rel)}), capsys)
    _assert_steer(json.loads(out))


def test_mode_off_skips_extra_patterns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARD_PROTECTED_EXTRA", "secrets.toml")
    target = _payload("Edit", {"file_path": str(tmp_path / "secrets.toml")})
    _set_mode("enforce")
    _assert_steer(json.loads(_run_hook(protected_files, target, capsys)))
    _set_mode("off")
    assert _run_hook(protected_files, target, capsys) == ""


def test_lockdown_mode_protects_extended_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _payload("Edit", {"file_path": str(tmp_path / "CLAUDE.md")})
    assert _run_hook(protected_files, target, capsys) == ""
    _set_mode("lockdown")
    _assert_steer(json.loads(_run_hook(protected_files, target, capsys)))


# === credential_check ===


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Read", {"file_path": "~/.aws/credentials"}),
        ("Bash", {"command": "cat .env"}),
        ("Bash", {"command": "cp ~/.ssh/id_ed25519 /tmp/k"}),
    ],
)
def test_credential_access_is_a_steering_deny(tool_name: str, tool_input: dict[str, Any]) -> None:
    _assert_steer(credential_check.decide(tool_name, tool_input))


# === git -C validator ===


def test_git_c_config_write_steers_to_cd() -> None:
    reason = _assert_steer(git_c_validator.decide("git -C /repo config user.name bob"))
    assert "cd " in reason


def test_git_c_unknown_subcommand_steers_to_cd() -> None:
    reason = _assert_steer(git_c_validator.decide("git -C /repo frobnicate --x"))
    assert "cd /repo && git frobnicate" in reason


# === commit_message_validator ===


@pytest.fixture
def ai_git_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commit_message_validator, "_ai_email_in_git_config", lambda _cwd: "noreply@anthropic.com"
    )


@pytest.mark.usefixtures("ai_git_identity")
def test_ai_identity_is_a_steering_deny(tmp_path: Path) -> None:
    envelope = commit_message_validator.decide("git commit -m 'Fix parser'", cwd=str(tmp_path))
    reason = _assert_steer(envelope)
    assert "tell the user" in reason.lower()


# === bash: strict default-deny is lockdown-only ===


@pytest.mark.parametrize("permission_mode", ["auto", "dontAsk", "bypassPermissions"])
@pytest.mark.parametrize("cmd", ["flarbnoz --gronk", "typst compile resume.typ", "terraform plan"])
def test_permission_mode_never_enables_strict(cmd: str, permission_mode: str) -> None:
    assert bash_command_validator.decide(cmd, permission_mode=permission_mode) is None


def test_bash_hook_lockdown_comes_from_guard_mode(capsys: pytest.CaptureFixture[str]) -> None:
    payload = _payload("Bash", {"command": "flarbnoz --gronk"}, permission_mode="auto")
    assert _run_hook(bash_command_validator, payload, capsys) == ""
    _set_mode("lockdown")
    assert _decision(json.loads(_run_hook(bash_command_validator, payload, capsys))) == "deny"


# === mode honored by every hook ===


_OFF_CASES = [
    (credential_check, _payload("Read", {"file_path": "~/.aws/credentials"})),
    (git_c_validator, _payload("Bash", {"command": "git -C /repo config user.name bob"})),
    (bash_command_validator, _payload("Bash", {"command": "reboot"})),
    (agent_output_guard, _payload("Read", {"file_path": _AGENT_OUTPUT_FILE})),
]


@pytest.mark.parametrize(
    ("module", "payload"),
    [_OFF_CASES[-1], (subagent_scope, _payload("Edit", {"file_path": "/elsewhere/x.py"}))],
)
def test_allowlist_cannot_silence_agent_output_or_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """These hooks never consulted the allowlist; a hand-edited entry doesn't change that."""
    scope = tmp_path / ".claude" / "subagent-scope.json"
    scope.parent.mkdir()
    scope.write_text(json.dumps({"task": "t", "allowed": ["src/a.py"]}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    payload = {**payload, "cwd": str(tmp_path)}
    allowlist = Path(os.environ["GUARD_DATA_DIR"]) / "allowlist.json"
    allowlist.parent.mkdir(parents=True, exist_ok=True)
    rules = ["guard.agent_output_guard", "guard.subagent_scope"]
    allowlist.write_text(json.dumps({"disable_rules": rules}), encoding="utf-8")
    assert _decision(json.loads(_run_hook(module, payload, capsys))) == "deny"


@pytest.mark.parametrize(("module", "payload"), _OFF_CASES)
def test_mode_off_silences_hook(
    module: Any,
    payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _decision(json.loads(_run_hook(module, payload, capsys))) == "deny"
    _set_mode("off")
    assert _run_hook(module, payload, capsys) == ""


@pytest.mark.parametrize(("module", "payload"), _OFF_CASES)
def test_mode_shadow_logs_without_blocking(
    module: Any,
    payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _set_mode("shadow")
    assert _run_hook(module, payload, capsys) == ""
    log = Path(os.environ["GUARD_DECISIONS_PATH"])
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert any(r.get("decision") == "deny" and r.get("mode") == "shadow" for r in records)


@pytest.mark.usefixtures("ai_git_identity")
def test_mode_off_silences_commit_identity_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = _payload("Bash", {"command": "git commit -m 'Fix parser'"}, cwd=str(tmp_path))
    assert _decision(json.loads(_run_hook(commit_message_validator, payload, capsys))) == "deny"
    _set_mode("off")
    assert _run_hook(commit_message_validator, payload, capsys) == ""


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_subagent_scope_honors_mode(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    scope = tmp_path / ".claude" / "subagent-scope.json"
    scope.parent.mkdir()
    scope.write_text(json.dumps({"task": "t", "allowed": ["src/a.py"]}), encoding="utf-8")
    payload = _payload("Edit", {"file_path": str(tmp_path / "src" / "b.py")}, cwd=str(tmp_path))
    assert _decision(json.loads(_run_hook(subagent_scope, payload, capsys))) == "deny"
    _set_mode(mode)
    assert _run_hook(subagent_scope, payload, capsys) == ""
    log = Path(os.environ["GUARD_DECISIONS_PATH"])
    shadow_logged = any(
        json.loads(line).get("mode") == "shadow"
        for line in log.read_text(encoding="utf-8").splitlines()
    )
    assert shadow_logged == (mode == "shadow")


# === override hints are real commands ===


@pytest.mark.parametrize(
    "envelope",
    [
        protected_files.decide("Edit", {"file_path": "/repo/src/guard/registry.py"}),
        protected_files.decide("Bash", {"command": "cp /tmp/x /repo/src/guard/registry.py"}),
        bash_command_validator.decide("rm -rf /"),
        bash_command_validator.decide("flarbnoz --gronk", lockdown=True),
    ],
)
def test_override_hints_parse(envelope: dict[str, Any] | None) -> None:
    """Every ``guard allowlist ...`` a deny suggests must parse with the real CLI."""
    from guard import cli

    hints = re.findall(r"`(guard allowlist [^`]+)`", _reason(_require(envelope)))
    assert hints
    parser = cli._build_parser()  # noqa: SLF001 -- the CLI's own parser
    for hint in hints:
        parser.parse_args(shlex.split(hint)[1:])


# === lockdown is a guard mode ===


def test_guard_mode_accepts_lockdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from guard import cli
    from guard.allowlist import load_allowlist

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    assert cli.main(["--json", "mode", "lockdown"]) == 0
    assert load_allowlist(project).mode == "lockdown"


# === write-target extraction stays inside each command ===


@pytest.mark.parametrize(
    "cmd",
    [
        "sed -i '' 's/a/b/' src/cli.py && sed -n 1,30p src/guard/_utils.py",
        "sed -i 's/a/b/' notes.txt || cat src/guard/registry.py",
        "perl -pi -e 's/a/b/' notes.txt | head src/guard/_utils.py",
    ],
)
def test_inplace_editor_operands_stop_at_control_operators(cmd: str) -> None:
    assert protected_files.decide("Bash", {"command": cmd}) is None


def test_inplace_edit_after_control_operator_still_denies() -> None:
    cmd = "cat notes.txt && sed -i 's/a/b/' src/guard/_utils.py"
    _assert_steer(protected_files.decide("Bash", {"command": cmd}))
