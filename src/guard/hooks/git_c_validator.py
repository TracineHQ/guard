# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: deny ``git -C`` / ``git -c`` shapes that run code.

Two shapes deny: a ``-c`` override of ``core.hooksPath`` /
``core.attributesFile`` (the next subcommand loads hooks from the override
target), and a ``git -C <path>`` read verb coerced into running a program or
writing a file (``log --output=``, ``grep --open-files-in-pager``, ``fetch
--upload-pack``). Everything else gets no decision, so Claude Code's own
checks decide.

IMPORTANT: this hook only evaluates a single, operator-free command. If the
input contains shell operators (``&&``, ``||``, ``;``, ``|``) it gives no
decision because ``shlex`` cannot reliably parse those boundaries; the bash
validator checks compound commands.
"""

from __future__ import annotations

import shlex
from typing import Any

from guard._utils import emit_pretooluse_decision, safe_main
from guard.allowlist import apply_decision
from guard.registry import git_read_exec_violation

_HOOK_ID = "guard.git_c_validator"

# Flags that consume the next argument (so we don't misidentify it as a subcommand)
FLAGS_WITH_ARGS: frozenset[str] = frozenset(
    {
        "-c",
        "--git-dir",
        "--work-tree",
        "-C",
    }
)

# Length of "-C" prefix for inline ``-C/path`` (no space) form
_DASH_C_PREFIX_LEN = 2

_SHELL_OPERATOR_CHARS: frozenset[str] = frozenset({"|", ";"})


def has_shell_operators(command: str) -> bool:
    """Return ``True`` if the command contains an unquoted shell operator."""
    try:
        shlex.split(command)
    except ValueError:
        return True

    in_quote = False
    quote_char: str | None = None
    i = 0
    while i < len(command):
        c = command[i]
        if not in_quote:
            if c in ('"', "'"):
                in_quote = True
                quote_char = c
            elif (
                c == "&" and i + 1 < len(command) and command[i + 1] == "&"
            ) or c in _SHELL_OPERATOR_CHARS:
                return True
        elif c == quote_char and (i == 0 or command[i - 1] != "\\"):
            in_quote = False
            quote_char = None
        i += 1
    return False


def parse_git_c_command(
    command: str,
) -> tuple[str | None, str | None, list[str]]:
    """Extract ``(path, subcommand, remaining_args)`` from a ``git -C`` call."""
    try:
        parts = shlex.split(command)
    except ValueError:
        return None, None, []

    if not parts or parts[0] != "git":
        return None, None, []

    i = 1
    path: str | None = None
    while i < len(parts):
        if parts[i] == "-C" and i + 1 < len(parts):
            path = parts[i + 1]
            i += 2
        elif parts[i].startswith("-C") and len(parts[i]) > _DASH_C_PREFIX_LEN:
            path = parts[i][_DASH_C_PREFIX_LEN:]
            i += 1
        elif parts[i] in FLAGS_WITH_ARGS and i + 1 < len(parts):
            i += 2
        elif parts[i].startswith("-"):
            i += 1
        else:
            return path, parts[i], parts[i + 1 :]

    return path, None, []


# ``git fetch`` options whose value may follow as a separate token.
_FETCH_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--depth",
        "--deepen",
        "--shallow-since",
        "--shallow-exclude",
        "-j",
        "--jobs",
        "--filter",
        "--negotiation-tip",
        "-o",
        "--server-option",
        "--recurse-submodules-default",
        "--submodule-prefix",
    }
)


def _fetch_exec_flag(remaining: list[str]) -> str | None:
    """The ``git fetch`` argument that runs a program, else ``None``.

    ``--upload-pack`` / ``--exec`` name a program to run and an ``ext::``
    remote runs a command.
    """
    skip_value = False
    for arg in remaining:
        if skip_value:
            skip_value = False
            continue
        flag = arg.split("=", 1)[0]
        if flag in {"--upload-pack", "--exec"} or arg.startswith("ext::"):
            return flag
        if arg.startswith("-"):
            skip_value = arg in _FETCH_VALUE_FLAGS
    return None


def _classify_subcommand(subcommand: str, remaining: list[str]) -> dict[str, Any] | None:
    """Deny envelope for a ``git -C`` read verb coerced into exec or a file write."""
    if subcommand == "fetch":
        flag = _fetch_exec_flag(remaining)
        if flag is None:
            return None
        return emit_pretooluse_decision(
            "deny", f"git -C: 'fetch {flag}' runs a program and is blocked"
        )
    # Read-only subcommands coerced into a file write or external-program exec
    # (git log --output=, git grep --open-files-in-pager). RCE-class -> deny.
    exec_violation = git_read_exec_violation(subcommand, remaining)
    if exec_violation is None:
        return None
    return emit_pretooluse_decision(
        "deny",
        f"git -C: '{subcommand} {exec_violation}' writes a file or execs and is blocked",
    )


# ``-c key=value`` paths-config keys whose value would point the next git
# subcommand at attacker-controlled hooks/attributes. There is no legitimate
# reason to override these via the command line — repo-local hooks live in
# ``.git/hooks/``, repo attributes live in ``.gitattributes``, and any
# permanent override goes through ``git config``. Treat any ``-c`` override
# of these keys as malicious regardless of value: relative-path traversal
# (``../``) AND absolute paths (``/tmp/evil``) are equally dangerous.
_DANGEROUS_PATHS_CONFIG_KEYS: frozenset[str] = frozenset(
    {"core.hookspath", "core.attributesfile"},
)


def _normalize_config_key(key: str) -> str:
    """Lowercase and strip whitespace for git config-key matching."""
    return key.strip().lower()


def _check_dangerous_kv(kv: str) -> tuple[str, str] | None:
    """Return ``(key, value)`` if ``kv`` overrides a dangerous paths-config key."""
    if "=" not in kv:
        return None
    key, value = kv.split("=", 1)
    if _normalize_config_key(key) in _DANGEROUS_PATHS_CONFIG_KEYS:
        return key, value
    return None


def _has_dangerous_paths_config(command: str) -> tuple[str, str] | None:
    """Return ``(key, value)`` if a ``-c`` paths-config override is present.

    Matches all four argv shapes git accepts:
    - ``-c key=value``                  (canonical, two tokens)
    - ``-c=key=value``                  (single-token form)
    - ``-ckey=value``                   (fused short-flag form)
    - ``--config-env=key=ENVVAR``       (env-indirect override; we deny on key alone)

    The fused form (``-ccore.hooksPath=/tmp/evil``) was the original bypass:
    a per-token ``parts[i] == "-c"`` walk would skip it entirely. Now we
    handle the fused form first, then fall through to the multi-token forms.
    Denies any value, not just traversal — absolute paths to attacker-controlled
    locations bypass a traversal-only check. The next git subcommand in the
    same invocation would load hooks/attributes from the override target.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0] != "git":
        return None
    i = 1
    while i < len(parts):
        tok = parts[i]
        # Canonical: -c <key=value>
        if tok == "-c" and i + 1 < len(parts):
            hit = _check_dangerous_kv(parts[i + 1])
            if hit is not None:
                return hit
            i += 2
            continue
        # Equals form: -c=key=value (rare but valid)
        if tok.startswith("-c=") and len(tok) > len("-c="):
            hit = _check_dangerous_kv(tok[len("-c=") :])
            if hit is not None:
                return hit
            i += 1
            continue
        # Fused short flag: -ccore.hooksPath=/tmp/evil
        if tok.startswith("-c") and len(tok) > 2 and "=" in tok:
            hit = _check_dangerous_kv(tok[2:])
            if hit is not None:
                return hit
            i += 1
            continue
        # Long-form env override: --config-env=key=ENVVAR
        if tok.startswith("--config-env="):
            payload = tok[len("--config-env=") :]
            # payload is key=ENVVAR; take the key half and check it.
            if "=" in payload:
                env_key = payload.split("=", 1)[0]
                if _normalize_config_key(env_key) in _DANGEROUS_PATHS_CONFIG_KEYS:
                    return env_key, "<env-indirect>"
            i += 1
            continue
        if tok == "--config-env" and i + 1 < len(parts):
            payload = parts[i + 1]
            if "=" in payload:
                env_key = payload.split("=", 1)[0]
                if _normalize_config_key(env_key) in _DANGEROUS_PATHS_CONFIG_KEYS:
                    return env_key, "<env-indirect>"
            i += 2
            continue
        i += 1
    return None


def decide(command: str) -> dict[str, Any] | None:
    """Return a deny envelope, or ``None`` to fall through."""
    if has_shell_operators(command):
        return None
    dangerous = _has_dangerous_paths_config(command)
    if dangerous is not None:
        key, value = dangerous
        return emit_pretooluse_decision(
            "deny",
            (
                f"git -c {key}={value}: command-line override of "
                "core.hooksPath / core.attributesFile is a known exploit "
                "shape — the next git subcommand would load hooks or "
                "attributes from the override target. No legitimate use "
                "for this at the CLI; use `git config` for permanent "
                "settings or `.git/hooks/` for repo-local hooks."
            ),
        )
    path, subcommand, remaining = parse_git_c_command(command)
    if path is None or subcommand is None:
        return None
    return _classify_subcommand(subcommand, remaining)


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return
    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command:
        return
    # Token-aware gate: any `git` invocation with a `-C`/`-c` global option
    # (in any of its argv shapes — bare, fused, equals, --config-env) reaches
    # `decide()`. A substring gate ("git -c " with trailing space) would skip
    # the fused form `git -ccore.hooksPath=...`.
    try:
        head = shlex.split(command)
    except ValueError:
        head = command.split()
    if not head or head[0] != "git":
        return
    if not any(t.startswith(("-C", "-c", "--config-env")) for t in head[1:]):
        return

    envelope = decide(command)
    if envelope is not None:
        apply_decision(_HOOK_ID, payload, envelope, command)


if __name__ == "__main__":
    safe_main(hook)
