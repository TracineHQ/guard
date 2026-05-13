"""Synthetic regression fixture for no-prefix-predicate-in-readonly.

This file intentionally violates the strict-allowlist invariant by
defining a prefix-based read-only predicate. The semgrep rules in
.semgrep/rules/ MUST flag this file. The test in
tests/static/test_semgrep_rules.py asserts the violation is caught.

DO NOT use this pattern in production code -- it is the v1.2 bypass
class that v1.3 closes. See docs/plan/strict-aws-allowlist/spec.md.
"""

# This module is NOT imported anywhere. It exists purely for semgrep.

# Synthetic stand-in for src/guard/hooks/_admin_specs.py to keep
# the fixture self-contained. The path scoping in the rule must
# be relaxed at test time (see test_semgrep_rules.py for how).


def _aws_is_read_only(verb_tuple: tuple[str, ...]) -> bool:
    """Returns True if the verb looks safe based on prefix."""
    return len(verb_tuple) >= 2 and verb_tuple[1].startswith(  # MUST FLAG
        ("describe-", "list-", "get-")
    )
