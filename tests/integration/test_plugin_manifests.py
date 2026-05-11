# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Plugin manifest integrity + self-containment.

Verifies the plugin's manifests JSON-parse, declare the right shape, and
all hook command paths resolve to existing files inside the plugin root.
This is the wire contract — Claude Code will refuse to load a plugin that
fails any of these.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def test_plugin_json_parses_and_pins_version() -> None:
    data = json.loads((REPO / ".claude-plugin" / "plugin.json").read_text())
    assert data["name"] == "guard"
    assert data["version"] == "1.0.0", "version must be pinned"
    assert data["license"] == "Apache-2.0"
    # plugin.json must NOT reference ./hooks/hooks.json. Claude Code's plugin
    # loader auto-loads that path; an explicit reference triggers a
    # duplicate-load error and the plugin reports Status: failed to load.
    # The standard location is the contract -- only add a "hooks" field here
    # if you ship ADDITIONAL hook files outside hooks/hooks.json.
    assert "hooks" not in data, (
        'plugin.json must not redeclare hooks="./hooks/hooks.json"; '
        "the standard path is auto-loaded by Claude Code."
    )


def test_marketplace_json_parses_and_has_one_plugin() -> None:
    data = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    assert data["name"] == "tracinehq"
    assert len(data["plugins"]) == 1
    plugin = data["plugins"][0]
    assert plugin["name"] == "guard"
    assert plugin["source"] == "./"


def test_hooks_json_parses() -> None:
    data = json.loads((REPO / "hooks" / "hooks.json").read_text())
    assert "PreToolUse" in data["hooks"]


def test_every_hook_command_resolves_to_existing_file() -> None:
    data = json.loads((REPO / "hooks" / "hooks.json").read_text())
    pattern = re.compile(r"\$\{CLAUDE_PLUGIN_ROOT\}(/[\S]+)")
    for matcher_block in data["hooks"]["PreToolUse"]:
        for hook in matcher_block["hooks"]:
            cmd = hook["command"]
            m = pattern.search(cmd)
            assert m, f"command does not reference CLAUDE_PLUGIN_ROOT: {cmd}"
            relative = m.group(1).lstrip("/")
            target = REPO / relative
            assert target.exists(), f"hook command target missing: {target}"
            assert target.is_file(), f"hook command target is not a file: {target}"


def test_no_path_traversal_in_hooks_json() -> None:
    raw = (REPO / "hooks" / "hooks.json").read_text()
    assert "../" not in raw, "path traversal forbidden — plugin must be self-contained"


def test_no_symlinks_under_src() -> None:
    src = REPO / "src"
    bad: list[str] = [str(path.relative_to(REPO)) for path in src.rglob("*") if path.is_symlink()]
    assert not bad, f"symlinks found under src/: {bad}"


def test_skill_md_exists_with_frontmatter() -> None:
    text = (REPO / "SKILL.md").read_text()
    assert text.startswith("---\n"), "SKILL.md must start with frontmatter"
    assert "name: guard" in text
    assert "description:" in text


@pytest.mark.parametrize(
    "hook_name",
    [
        "bash_command_validator",
        "git_c_validator",
        "credential_check",
        "commit_message_validator",
        "agent_output_guard",
        "subagent_scope",
        "protected_files",
    ],
)
def test_each_validator_referenced_in_hooks_json(hook_name: str) -> None:
    """Every shipped validator must be wired into hooks.json — no orphan hooks."""
    raw = (REPO / "hooks" / "hooks.json").read_text()
    assert f"src/guard/hooks/{hook_name}.py" in raw, (
        f"{hook_name} exists in src/ but is not wired in hooks/hooks.json"
    )


def test_no_hook_command_outside_plugin_root() -> None:
    """Every command path must stay inside the plugin root after ${CLAUDE_PLUGIN_ROOT} expansion."""
    data = json.loads((REPO / "hooks" / "hooks.json").read_text())
    for matcher_block in data["hooks"]["PreToolUse"]:
        for hook in matcher_block["hooks"]:
            cmd = hook["command"]
            assert "../" not in cmd
            assert "/Users/" not in cmd
            assert "/home/" not in cmd
            # CLAUDE_PLUGIN_ROOT is the only allowed root marker
            assert "${CLAUDE_PLUGIN_ROOT}" in cmd
