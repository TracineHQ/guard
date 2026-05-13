"""Regression tests for .semgrep/rules/.

Requires semgrep to be installed (skipped locally if absent; CI installs it).
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[2]
RULES_DIR = REPO_ROOT / ".semgrep" / "rules"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
HOOKS_DIR = REPO_ROOT / "src" / "guard" / "hooks"

SEMGREP = shutil.which("semgrep")


def _run(target: Path) -> dict:
    """Run semgrep --json against *target* using all rules. Returns parsed output."""
    result = subprocess.run(
        [
            SEMGREP,
            "scan",
            "--config",
            str(RULES_DIR),
            "--json",
            str(target),
        ],
        capture_output=True,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "results": [],
            "_raw_stdout": result.stdout.decode(),
            "_raw_stderr": result.stderr.decode(),
        }


@pytest.mark.skipif(SEMGREP is None, reason="semgrep not installed")
def test_positive_fixture_fires() -> None:
    """Rule must flag the prefix-predicate violation fixture."""
    output = _run(FIXTURES_DIR / "prefix_predicate_violation.py")
    findings = output.get("results", [])
    assert len(findings) >= 1, (
        "Expected at least one semgrep finding on prefix_predicate_violation.py, got zero.\n"
        f"stdout: {output}"
    )


@pytest.mark.skipif(SEMGREP is None, reason="semgrep not installed")
def test_negative_fixture_is_clean() -> None:
    """Rule must NOT flag legitimate .startswith() usages."""
    output = _run(FIXTURES_DIR / "legitimate_startswith.py")
    findings = output.get("results", [])
    assert findings == [], (
        "Expected zero semgrep findings on legitimate_startswith.py, got:\n"
        + json.dumps(findings, indent=2)
    )


@pytest.mark.skipif(SEMGREP is None, reason="semgrep not installed")
def test_live_hooks_are_clean() -> None:
    """Live codebase under src/guard/hooks/ must produce zero findings."""
    output = _run(HOOKS_DIR)
    findings = output.get("results", [])
    assert findings == [], "semgrep found violations in src/guard/hooks/:\n" + json.dumps(
        findings, indent=2
    )
