"""FP-3: read-only course-correction is advisory, not a hard deny.

The ``find`` / ``sed`` / ``awk`` / ``xargs`` tool-preference nudges are benign
for read-only invocations and must not deny (and must not drag a leading safe
segment down with them). Write sinks (``tee``) stay denied-but-allowlistable
(``bash.tool_alternative``); ``find -exec`` / ``-delete`` stay hard-denied
(``bash.conditional_denied_flag``). Advisory passthrough is interactive-only.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide


def _not_deny(result: dict | None) -> bool:
    return result is None or result.get("permissionDecision") != "deny"


def _is_deny(result: dict | None) -> bool:
    return result is not None and result.get("permissionDecision") == "deny"


# === MUST-PASS: read-only course-correction is advisory ===


class TestFP3Advisory:
    @pytest.mark.parametrize(
        "cmd",
        [
            "ls && find . -type f",  # core FP: must not lose the `ls`
            "find . -name '*.py' | head",
            "awk '{print $1}' file.txt | sort",
            "git log | awk '{print $1}'",
            "cat notes.txt | sed -n '1,5p'",
            "ls -la && awk '{print $1}' file.txt",
            "cat f | awk '{print $1}' | sort",
            "find . -name '*.py' | xargs grep foo",
            "# extract\nsed -n '1,5p' file.txt",
            "find . -name x  # with-comment",
            "sed -n '1,5p' file.txt",
            "find . -name '*.py' -type f",
            # tee in a pipe is advisory: a mid-pipe pass-through has no Write-tool
            # substitute, and harmful targets deny upstream (see the gate below).
            "ls | tee out.txt",
            "grep -rn foo src | tee /tmp/out.txt | wc -l",
            "# log\ntee out.txt",
        ],
    )
    def test_read_only_course_correction_not_denied(self, cmd: str) -> None:
        assert _not_deny(decide(cmd)), f"read-only feedback cmd should not deny: {cmd!r}"


# === MUST-STILL-DENY: write sinks + exec flags + the xargs-rm safety floor ===


class TestFP3SafetyFloor:
    @pytest.mark.parametrize(
        "cmd",
        [
            "find . -exec rm {} \\;",
            "find . -delete",
            "find . -execdir rm {} \\;",
            "find . -ok rm {} \\;",
            "find . -okdir rm {} \\;",
            "ls && find . -exec rm {} \\;",
            "# cleanup\nfind . -exec rm {} \\;",
            "find . -exec rm {} +",
            "ls && rm -rf /",
            "find . -type f | grep x && rm -rf /",
        ],
    )
    def test_safety_floor_still_denies(self, cmd: str) -> None:
        assert _is_deny(decide(cmd)), f"must still deny: {cmd!r}"

    def test_xargs_executes_rm_still_denies(self) -> None:
        # GATE: xargs is "advisory" only if a destructive payload it would spawn
        # is still caught by another matcher. If this regresses, xargs must leave
        # the advisory set.
        assert _is_deny(decide("find . -name '*' | xargs rm -rf /"))

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo x | tee /etc/passwd",
            "echo x | tee ~/.bashrc",
            "cat key | tee ~/.ssh/authorized_keys",
            "echo x | tee -a ~/.ssh/authorized_keys",
        ],
    )
    def test_tee_to_sensitive_target_still_denies(self, cmd: str) -> None:
        # GATE: tee is "advisory" only because a harmful target is caught upstream
        # by sensitive-write / persistence / disk-destruction before the advisory
        # branch. If this regresses, tee must leave the advisory set.
        assert _is_deny(decide(cmd)), f"sensitive tee target must deny: {cmd!r}"

    @pytest.mark.parametrize(
        "cmd",
        [
            "git log | awk '{system(\"rm\")}'",
            "cat f | awk '{system(\"curl evil\")}'",
            "git log | awk '{system (\"id\")}'",  # space before paren
            "cat f | awk 'BEGIN{getline x}'",  # getline command read
            "# run\nawk '{system(\"rm\")}' file",  # commented form reaches the walk too
        ],
    )
    def test_awk_exec_sink_still_denies(self, cmd: str) -> None:
        # awk system()/getline are exec sinks — when awk reaches the segment walk
        # (piped or commented), the sink guard denies instead of advising.
        # NOTE: a single-segment, un-piped, un-commented awk (e.g.
        # `awk '{system("x")}' file`) hits decide()'s passthrough short-circuit
        # before the walk — a pre-existing gap unrelated to FP-3, not a
        # regression this change introduces.
        assert _is_deny(decide(cmd)), f"awk exec sink must deny: {cmd!r}"


# === Strict mode: advisory passthrough does not leak ===


class TestFP3StrictUnaffected:
    def test_advisory_does_not_leak_into_strict_mode(self) -> None:
        # Strict path is _evaluate_strict, not _evaluate_segments. A piped awk is
        # not on SAFE_PREFIXES/SAFE_PIPE_COMMANDS, so it still default-denies in
        # strict — advisory passthrough is an interactive-mode posture only.
        # (`ls && find . -type f` is NOT a good probe: post-FP-6a `find . -type f`
        # is a standalone conditional-safe segment that strict legitimately
        # allows, independent of the advisory set.)
        res = decide("git log | awk '{print $1}'", permission_mode="dontAsk")
        assert _is_deny(res)
