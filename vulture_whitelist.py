"""Vulture whitelist — symbols that vulture flags as dead but are live in production.

Each entry references a symbol vulture cannot see being used. Run vulture with:

    uv run --with vulture vulture src/guard tests vulture_whitelist.py --min-confidence 80

Comments explain WHY the symbol is referenced outside vulture's static view.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
# ruff: noqa: B018
# mypy: ignore-errors

from guard import _utils
from guard.hooks import (
    agent_output_guard,
    bash_command_validator,
    commit_message_validator,
    credential_check,
    git_c_validator,
    protected_files,
    subagent_scope,
)

# --- Hook entry points ---
# Every hook module exposes `hook()` as the Claude Code subprocess entry point
# (wired via hooks/hooks.json -> guard.hooks.<module>:hook). Claude Code spawns
# the hook script and pipes JSON over stdin; vulture cannot see those callers.
# `decide()` is the pure-function core that tests import and call directly via
# subprocess; it is also the documented extension point for downstream users.
agent_output_guard.hook
agent_output_guard.decide
bash_command_validator.hook
bash_command_validator.decide
commit_message_validator.hook
commit_message_validator.decide
credential_check.hook
credential_check.decide
git_c_validator.hook
git_c_validator.decide
protected_files.hook
subagent_scope.hook

# --- Shared utility entry point ---
# `safe_main()` is the boilerplate wrapper each hook module's `if __name__ == "__main__"`
# block invokes. Vulture sees the import but not the runtime dispatch.
_utils.safe_main

# --- Public _utils constants ---
# These are env-driven config knobs documented in docs/output-format.md and
# guarded by tests/test_no_dead_exports.py. They are read inside _utils itself
# (e.g. via append_jsonl / log_decision) and by hook modules indirectly through
# the helpers that close over them — vulture's static pass cannot follow that.
_utils.GUARD_HOME
_utils.LOOP_DETECTION_THRESHOLD
_utils.LOOP_DETECTION_WINDOW_MINUTES
_utils.CONTEXT_BUDGET_WARN_BYTES
_utils.CONTEXT_BUDGET_HARD_BYTES

# --- Public decision builder ---
# `make_decision()` is exercised only by subprocess-based tests in
# tests/test_utils.py (the test body builds a Python source string and execs
# it in a child interpreter). Vulture sees the def but not the string-embedded
# call sites.
_utils.make_decision

# --- Test parametrize id args ---
# `description` is consumed by @pytest.mark.parametrize as the human-readable
# id (`id=d` in the param list) but never referenced in the test body. Pytest
# reads it via the function signature; vulture sees an unused argument.
description = None
description

# --- Pytest side-effect fixtures ---
# These fixtures activate their behavior via test-function parameters that
# pytest injects but the test body never references — vulture sees an unused
# variable. The fixtures live in tests/conftest.py.
strict_env = None
strict_env
decision_log_env = None
decision_log_env
