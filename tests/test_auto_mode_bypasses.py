# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Regression rows for auto-mode floor bypasses found in adversarial review.

Each command below performs a FLOOR action (``rm -rf ~``, a force push, an exec
sink write, a secret read, ...) through a shape that a STEER rule used to cover.
Skipping that STEER rule in ``auto`` must not let the floor action through, so
every row has to deny in ``auto`` and in ``default``.
"""

from __future__ import annotations

import pytest

from guard.hooks import bash_command_validator as bcv
from tests._helpers import is_deny

# Each row is a real floor action hidden behind a STEER shape.
BYPASSES: list[str] = [
    # 1. env flags hid the wrapped command.
    "env -i rm -rf ~",
    "env -i git push --force origin main",
    "env -i python3 -c 'import os'",
    "env -i sudo -s",
    "timeout 5 env -i rm -rf /",
    "env -u FOO rm -rf ~",
    "env -- rm -rf ~",
    "env --unset=FOO rm -rf ~",
    "env -C /tmp rm -rf ~",
    "env -iu FOO rm -rf ~",
    "sudo env -i rm -rf /",
    # 2. A variable or glob command head hides the command.
    "R=rm; $R -rf ~",
    "$SHELL -c 'rm -rf ~'",
    "/bin/r? -rf ~",
    "/usr/bin/g[i]t push --force origin main",
    "read -r c <<< 'rm -rf ~'; $c",
    '"$@" rm -rf ~',
    "$1 -rf ~",
    # 3. Shell -c bodies.
    "bash -c -- 'rm -rf ~'",
    "sh -c '\"$@\"' _ rm -rf ~",
    "bash -c \"$0\" 'rm -rf ~'",
    "X='rm -rf ~'; bash -c \"$X\"",
    "echo 'rm -rf ~' | xargs -0 -I{} bash -c '{}'",
    "bash -o pipefail -c 'rm -rf ~'",
    "bash +o history -c 'rm -rf ~'",
    # 4. trap with an option terminator.
    "trap -- 'rm -rf ~' EXIT",
    # 5. A shell reading a here-string or process substitution on stdin.
    "{ bash; } <<< 'rm -rf ~'",
    "(bash) <<< 'rm -rf ~'",
    "{ sh; } < <(echo 'rm -rf ~')",
    "exec 3<<< 'rm -rf ~'; sh <&3",
    "(sh) < <(echo 'rm -rf ~')",
    # 6. Remote and namespace payloads.
    "nsenter -t 1 -m rm -rf /",
    "ssh host -- rm -rf /",
    "ssh -B en0 host 'rm -rf /'",
    "docker container exec c rm -rf /",
    "docker compose exec web rm -rf /",
    "ssh -- host rm -rf /",
    # 7. Unfiltered find deletes from the working tree, its parent or home.
    "find .. -delete",
    "find ${HOME} -delete",
    "find /Users/dev -delete",
    "find .. -exec rm -rf {} +",
    "find . -delete",
    "find ../.. -delete",
    # 8. awk running a command.
    "cat x | awk '{system(\"rm -rf ~\")}'",
    "awk 'BEGIN{system(\"rm -rf ~\")}'",
    "awk 'BEGIN{print | \"rm -rf ~\"}'",
    "awk 'BEGIN{\"rm -rf ~\" | getline x}'",
    "awk 'BEGIN{print |& \"rm -rf ~\"}'",
    "awk '{system($0)}' cmds.txt",
    "awk -F: '{print | \"sh\"}' f",
    # 9. Redirects into git exec sinks and the clobber form.
    "printf '[core]\\n\\thooksPath = /tmp/h\\n' >> .git/config",
    "echo 'rm -rf ~' > .git/hooks/pre-commit",
    "printf '[alias]\\n\\tx = !sh\\n' >> ~/.gitconfig",
    "echo x >> ~/.config/git/config",
    "echo x >> sub/.git/hooks/post-checkout",
    "echo x >| ~/.bashrc",
    # admin_default_deny is FLOOR: secret reads, IAM grants, public access, ...
    "aws secretsmanager get-secret-value --secret-id prod/db",
    "aws ssm get-parameter --name /prod/db --with-decryption",
    "gcloud secrets versions access latest --secret=db",
    "az keyvault secret show --vault-name v --name db",
    "aws iam attach-user-policy --user-name u --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "gcloud projects add-iam-policy-binding p --member=user:x@example.com --role=roles/owner",
    "aws s3api put-bucket-acl --bucket b --acl public-read",
    "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0",
    "gcloud iam service-accounts keys create key.json --iam-account sa@p.iam.gserviceaccount.com",
    "aws s3 mv s3://b/ s3://c/ --recursive",
    "kubectl scale deployment web --replicas=0",
    # git config writes to exec sinks, in every spelling.
    "git config --file .git/config core.hooksPath /tmp/h",
    "git config -f .git/config alias.x '!rm -rf ~'",
    "git config --type path core.hooksPath /tmp/h",
    "git config set core.hooksPath /tmp/h",
    "git config --show-scope core.hooksPath /tmp/h",
]

# Ordinary work the fixes must not start denying in auto mode.
STILL_PASSES_IN_AUTO: list[str] = [
    "env -i PATH=/usr/bin make",
    "env -u DEBUG make test",
    "bash -o pipefail -c 'make test'",
    "bash -c -- 'ls -la'",
    "bash -c 'echo $HOME'",
    "sh -c 'cd \"$1\" && make' _ dir",
    "bash -c 'for f in *.py; do wc -l \"$f\"; done'",
    "trap -- 'echo done' EXIT",
    "find . -name '*.pyc' -delete",
    "find .. -type d -name __pycache__ -exec rm -rf {} +",
    "awk 'BEGIN{system(\"date\")}'",
    "awk '{print $1}' data.txt",
    "awk '/a|b/ {print $1}' data.txt",
    "awk '{print $1 | \"sort -u\"}' data.txt",
    "python3 script.py <<< 'input data'",
    "find build -delete",
    "echo x > .git/config.bak",
    "git config --global --get core.hooksPath",
    "ssh host -- make test",
    "docker container exec c ls /app",
    "echo hi >| notes.txt",
    "echo x >> .gitignore",
    "git config --get core.hooksPath",
    "git config --list",
    "git config get core.hooksPath",
    "git config user.name",
]

GIT_CONFIG_READS: list[str] = [
    "git config --get core.hooksPath",
    "git config --list",
    "git config get core.hooksPath",
    "git config --get-all alias.x",
    "git config core.hooksPath",
]


@pytest.mark.parametrize("permission_mode", ["auto", "default"])
@pytest.mark.parametrize("command", BYPASSES)
def test_floor_action_denies(command: str, permission_mode: str) -> None:
    assert is_deny(bcv.decide(command, permission_mode=permission_mode))


@pytest.mark.parametrize("command", BYPASSES)
def test_floor_action_denies_in_lockdown(command: str) -> None:
    assert is_deny(bcv.decide(command, permission_mode="auto", lockdown=True))


@pytest.mark.parametrize("command", STILL_PASSES_IN_AUTO)
def test_ordinary_work_still_passes_in_auto(command: str) -> None:
    assert bcv.decide(command, permission_mode="auto") is None


@pytest.mark.parametrize("command", GIT_CONFIG_READS)
def test_git_config_read_is_not_injection(command: str) -> None:
    assert not is_deny(bcv.decide(command))


@pytest.mark.parametrize(
    "command",
    [
        "git config core.hooksPath /tmp/h",
        "git config --global alias.x '!sh'",
        "git config --add core.pager less",
        "git config --get core.hooksPath --replace-all x",
    ],
)
def test_git_config_sink_write_still_denies(command: str) -> None:
    assert is_deny(bcv.decide(command))


def _reason(command: str, permission_mode: str = "auto") -> str:
    result = bcv.decide(command, permission_mode=permission_mode)
    assert result is not None
    return result["permissionDecisionReason"]


def test_opaque_shell_string_names_the_shape() -> None:
    reason = _reason("bash -c 'cd /tmp && \"$1\" --version' _ git")
    assert "bash.var_expanded_head" in reason or "named by an expansion" in reason
    reason = _reason("bash -c ''")
    assert "bash.shell_wrapper" in reason
    reason = _reason("echo ls | xargs -I{} bash -c '{}'")
    assert "bash.shell_wrapper" in reason
    assert "placeholder" in reason


def test_awk_runtime_command_is_an_executed_construct() -> None:
    reason = _reason("awk '{system($0)}' cmds.txt", permission_mode="default")
    assert "bash.dangerous_construct" in reason
    assert "built at run time" in reason


def test_awk_with_too_many_commands_denies_without_checking_each() -> None:
    program = " ".join(f'system("echo {n}");' for n in range(40))
    assert is_deny(bcv.decide(f"awk 'BEGIN{{{program}}}'", permission_mode="auto"))


def test_git_sink_redirect_names_the_target() -> None:
    reason = _reason("echo 'rm -rf ~' > .git/hooks/pre-commit")
    assert "`.git/hooks/pre-commit`" in reason
