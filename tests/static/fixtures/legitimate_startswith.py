"""Synthetic negative fixture for no-prefix-predicate-in-readonly.

These call sites use .startswith() for legitimate purposes
(flag detection, comment stripping). The semgrep rule must NOT
flag them. The test in tests/static/test_semgrep_rules.py runs
semgrep on this file and asserts ZERO findings.
"""


def _strip_flags(tokens: list[str]) -> list[str]:
    """Drop flag-shaped tokens (legitimate use of .startswith)."""
    return [t for t in tokens if not t.startswith("-")]


def _is_comment_line(line: str) -> bool:
    """Detect comment lines (legitimate)."""
    return line.lstrip().startswith("#")


def _is_glob_head(token: str) -> bool:
    """Detect glob-head (legitimate; not a read-only predicate)."""
    return token.startswith("*")
