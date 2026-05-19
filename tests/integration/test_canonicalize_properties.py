# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Property-based invariants for canonicalization / normalization helpers.

These functions sit on the hot path between attacker-controlled input and the
matcher dispatch. Each property here is a structural invariant that, if broken,
would expose a class of bypass shapes (idempotence failure means peeling once
versus twice produces different match candidates; quote-handling failure means
``echo "foo;bar"`` could split where it shouldn't; brace-expansion bound
failure resurrects the DoS shape closed by the v1.4.0 cap).

Tests run on the live helpers — no mocks. Hypothesis shrinks any counterexample
to the minimal failing input.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from guard.hooks.bash_command_validator import (
    _BRACE_EXPANSION_TOKEN_CAP,
    _canonicalize,
    _expand_braces_in_line,
    _normalize_segment,
    strip_inline_comment,
)

# Ascii printables minus newline (we test single-line shapes; multi-line
# handling lives in the segment splitter).
_PRINTABLE = st.characters(
    min_codepoint=0x20,
    max_codepoint=0x7E,
    blacklist_characters=("\n", "\r"),
)
_LINE = st.text(alphabet=_PRINTABLE, min_size=0, max_size=200)


@given(line=_LINE)
@settings(max_examples=200, deadline=None)
def test_canonicalize_idempotent(line: str) -> None:
    """``_canonicalize(_canonicalize(x)) == _canonicalize(x)`` for all inputs.

    Idempotence is the invariant that lets ``decide()`` peel a segment once
    without worrying that a second peel would yield a different match
    candidate. A regression here means an attacker can craft inputs that
    fold differently depending on how many times the pipeline runs.
    """
    once = _canonicalize(line)
    twice = _canonicalize(once)
    assert once == twice, f"non-idempotent: {line!r} -> {once!r} -> {twice!r}"


@given(line=_LINE)
@settings(max_examples=200, deadline=None)
def test_normalize_segment_converges_under_bounded_iteration(line: str) -> None:
    """``_normalize_segment`` reaches a fixed point within a few iterations.

    Not strictly idempotent: shlex peels one layer of backslash escaping per
    pass (``\\\\0`` -> ``\\0`` -> ``0``), so a deeply escaped input may
    take several iterations to stabilize. The safety property the matcher
    pipeline depends on is *termination*: the candidate-forms fixpoint
    loop must converge so matchers see a finite set of forms. Verify
    convergence within a generous cap.
    """
    cap = 16
    current = line
    for _ in range(cap):
        nxt = _normalize_segment(current)
        if nxt == current:
            return
        current = nxt
    pytest.fail(f"did not converge within {cap} iterations starting from {line!r}")


@given(
    pre=st.text(alphabet=_PRINTABLE, min_size=0, max_size=50),
    payload=st.text(alphabet=_PRINTABLE, min_size=0, max_size=50),
    post=st.text(alphabet=_PRINTABLE, min_size=0, max_size=50),
    quote=st.sampled_from(("'", '"')),
)
@settings(max_examples=300, deadline=None)
def test_strip_inline_comment_preserves_quoted_hash(
    pre: str, payload: str, post: str, quote: str
) -> None:
    """A ``#`` inside a quoted string must NOT trigger comment stripping.

    Construct ``<pre> <quote>...#...<quote> <post>`` and assert the quoted
    segment survives. We can't assert exact byte equality (the input itself
    may contain comment-triggering sequences in ``pre`` or ``post``), but
    the quoted body containing ``#`` must appear in the output unmodified.
    """
    # Strip raw quote chars from payload so the synthesized quoted region
    # is unambiguous (Hypothesis would otherwise generate inputs where the
    # payload itself contains the closing quote).
    payload_clean = payload.replace(quote, "")
    if "#" not in payload_clean:
        payload_clean = payload_clean + "#" + payload_clean
    # Strip BOTH quote chars from ``pre`` -- a stray opposite-kind quote
    # would open its own quoted region and swallow the synthesized one,
    # invalidating the test's premise that the synthesized region is the
    # active quote context at the ``#``. Internal ``#`` in pre is also
    # stripped for the same reason (don't terminate the line before our
    # quoted region appears).
    pre_clean = pre.replace("'", "").replace('"', "").replace("#", "")
    quoted = f"{quote}{payload_clean}{quote}"
    line = f"{pre_clean}{quoted} {post}"
    stripped = strip_inline_comment(line)
    assert quoted in stripped, (
        f"quoted hash dropped: input={line!r} stripped={stripped!r} quoted={quoted!r}"
    )


@given(line=_LINE)
@settings(max_examples=200, deadline=None)
def test_strip_inline_comment_idempotent(line: str) -> None:
    """Stripping twice equals stripping once."""
    once = strip_inline_comment(line)
    twice = strip_inline_comment(once)
    assert once == twice


@given(
    n_alts=st.integers(min_value=1, max_value=8),
    n_groups=st.integers(min_value=1, max_value=4),
    alt_len=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=100, deadline=None)
def test_expand_braces_token_cap_holds(n_alts: int, n_groups: int, alt_len: int) -> None:
    """For any small-shape brace blowup, expanded tokens stay under 2x the cap.

    Direct test of the ``_BRACE_EXPANSION_TOKEN_CAP`` guard. The 2x slack
    is the existing tolerance in ``test_expand_braces_bound_holds_for_any_
    blowup_shape``; preserved here so we test the same invariant from a
    different (smaller) shape space.
    """
    alt = "a" * alt_len
    group = "{" + ",".join([alt] * n_alts) + "}"
    line = group * n_groups
    expanded = _expand_braces_in_line(line)
    assert len(expanded.split()) <= _BRACE_EXPANSION_TOKEN_CAP * 2
