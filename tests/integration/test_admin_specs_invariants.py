# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Structural invariants between _admin_specs.py, allowlist.py, and docs."""

from __future__ import annotations

from pathlib import Path

from guard.allowlist import _BASH_MATCHER_RULE_IDS
from guard.hooks._admin_specs import ADMIN_CLI_SPECS, RULE_ID

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_names_unique() -> None:
    names = [s.cli_name for s in ADMIN_CLI_SPECS]
    assert len(names) == len(set(names)), f"duplicate cli_name in ADMIN_CLI_SPECS: {names}"


def test_no_verb_in_both_read_only_and_deny_overrides() -> None:
    for spec in ADMIN_CLI_SPECS:
        overlap = spec.read_only_verbs & spec.deny_overrides
        assert not overlap, f"{spec.cli_name}: verb in both sets: {overlap}"


def test_rule_id_in_bash_matcher_rule_ids() -> None:
    assert RULE_ID in _BASH_MATCHER_RULE_IDS, f"{RULE_ID} missing from _BASH_MATCHER_RULE_IDS"


def test_all_cli_names_in_skill_md() -> None:
    skill_md = (_REPO_ROOT / "SKILL.md").read_text()
    for spec in ADMIN_CLI_SPECS:
        assert spec.cli_name in skill_md, f"{spec.cli_name} missing from SKILL.md — drift risk"


def test_each_spec_has_deny_and_allow_cases() -> None:
    """Each enrolled CLI has at least 3 DENY and 3 ALLOW test param entries."""
    test_file = (_REPO_ROOT / "tests" / "integration" / "test_admin_default_deny.py").read_text()
    for spec in ADMIN_CLI_SPECS:
        count = test_file.count(f'"{spec.cli_name} ')
        assert count >= 3, f"{spec.cli_name}: only {count} test cases (need >=3)"
