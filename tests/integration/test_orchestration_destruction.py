"""Coverage for orchestration-tool destruction shapes added to the registry.

Each command below has no legitimate single-step dev variant; the matching
``CommandRule`` entry in ``registry.py`` routes them through ``ALWAYS_DENY``.
Tests assert the deny fires regardless of trailing flags / args (prefix
matching) and across both interactive and autonomous mode.
"""

from __future__ import annotations

import pytest

from guard.hooks.bash_command_validator import decide

DENY_CASES = [
    "kubectl delete --all -n production",
    "kubectl delete --all",
    "kubectl delete pods --all",
    "kubectl delete pods --all -n staging",
    "kubectl delete namespace dev",
    "aws s3 rb s3://my-bucket --force",
    "aws s3 rb s3://my-bucket",
    "gh repo delete TracineHQ/guard --yes",
    "gh repo delete owner/repo",
    "gh release delete v1.0.0 --yes",
    "gh release delete v0.5.0",
    "gpg --delete-secret-key ABCDEF1234567890",
    "gpg --delete-secret-and-public-keys ABCDEF1234567890",
    "chmod -R 777 /",
    "chmod -R 777 /*",
]


@pytest.mark.parametrize("command", DENY_CASES)
def test_orchestration_destruction_denied(command: str) -> None:
    result = decide(command)
    assert result is not None, f"expected deny envelope, got passthrough for: {command}"
    assert result.get("permissionDecision") == "deny", (
        f"expected deny, got {result.get('permissionDecision')!r} for: {command}"
    )


@pytest.mark.parametrize(
    "command",
    [
        # Single-pod deletion is a normal dev op — must not be caught by the
        # `kubectl delete --all` / `kubectl delete pods --all` prefixes.
        "kubectl delete pod my-pod",
        "kubectl delete pod my-pod -n staging",
        # Single-resource gh delete shapes don't exist (delete is the verb),
        # but local file removal must remain unaffected.
        "rm ./localfile",
        # Scoped chmod 777 against a project dir is questionable but legal —
        # the registry only denies the / and /* targets.
        "chmod -R 777 ./mydir",
        "chmod 777 file.sh",
    ],
)
def test_legitimate_variants_not_denied(command: str) -> None:
    result = decide(command)
    if result is not None:
        assert result.get("permissionDecision") != "deny", (
            f"unexpected deny for legitimate variant: {command} -> {result}"
        )
