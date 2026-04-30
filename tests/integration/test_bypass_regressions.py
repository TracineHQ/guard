"""Regression tests for verified shell-validator bypasses (F1-F7).

Each assertion pins a previously-confirmed passthrough (``decide`` returning
``None``) that must now produce a deny envelope. Removing any fix re-breaks
the matching test.
"""

from __future__ import annotations

from guard.hooks.bash_command_validator import decide


def _is_deny(result):
    return (
        result is not None
        and isinstance(result, dict)
        and result.get("permissionDecision") == "deny"
    )


def test_f1_quoted_whitespace_python_dash_c() -> None:
    res = decide("python3'  '-c '1; __import__(\"os\").system(\"id\")'")
    assert res is not None
    assert _is_deny(res)


def test_f2_env_kv_prefix_python_dash_c() -> None:
    res = decide('env FOO=1 python3 -c "import os; os.system(\\"id\\")"')
    assert res is not None
    assert _is_deny(res)


def test_f3_python311_dash_c() -> None:
    res = decide('python3.11 -c "print(1)"')
    assert res is not None
    assert _is_deny(res)


def test_f3_nodejs_dash_e() -> None:
    res = decide('nodejs -e "1"')
    assert res is not None
    assert _is_deny(res)


def test_f3_bun_dash_e() -> None:
    res = decide('bun -e "1"')
    assert res is not None
    assert _is_deny(res)


def test_f3_deno_eval() -> None:
    res = decide('deno eval "1"')
    assert res is not None
    assert _is_deny(res)


def test_f4_rm_split_recursive_force_root() -> None:
    res = decide("rm -r -f /")
    assert res is not None
    assert _is_deny(res)


def test_f4_rm_long_form_recursive_force_root() -> None:
    res = decide("rm --recursive --force /")
    assert res is not None
    assert _is_deny(res)


def test_f5_git_git_dir_work_tree_add_all() -> None:
    res = decide("git --git-dir=/tmp/.git --work-tree=/tmp add -A")
    assert res is not None
    assert _is_deny(res)


def test_f5_git_dash_c_add_all() -> None:
    res = decide("git -C /tmp add -A")
    assert res is not None
    assert _is_deny(res)


def test_f6_nbsp_rm_rf_root() -> None:
    res = decide("rm\xa0-rf\xa0/")
    assert res is not None
    assert _is_deny(res)
