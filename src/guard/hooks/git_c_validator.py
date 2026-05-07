# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: validate ``git -C <path>`` commands.

Allows read-only git subcommands invoked with ``-C <path>``, denies
destructive ones, and asks for unknown subcommands. Works at any path depth
(bypasses the glob ``*`` vs ``/`` limitation in permission rules).

IMPORTANT: this hook only evaluates a single, operator-free command.
If the input contains shell operators (``&&``, ``||``, ``;``, ``|``) it
declines to auto-allow because ``shlex`` cannot reliably parse those
boundaries — fallthrough lets the normal permission system handle them.
"""

from __future__ import annotations

import json
import shlex
import sys
from typing import Any

from guard._utils import emit_pretooluse_decision, log_decision, safe_main

_HOOK_ID = "guard.git_c_validator"

# Read-only git subcommands — safe to auto-allow
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "branch",
        "remote",
        "blame",
        "rev-parse",
        "describe",
        "tag",
        "ls-files",
        "ls-tree",
        "grep",
        "stash",
        "shortlog",
        "cat-file",
        "rev-list",
        "name-rev",
        "for-each-ref",
        "reflog",
        "count-objects",
        "fsck",
        "verify-pack",
    }
)

# Destructive subcommands — hard deny with -C
DENIED_SUBCOMMANDS: frozenset[str] = frozenset({"clean", "reset"})

# Subcommands that are read-only by default but become destructive with these
# flags. ``branch -D feature`` deletes a branch; ``tag -d v1`` deletes a tag;
# ``remote remove origin`` removes a remote. The presence of any flag in the
# matching set on the otherwise-allowed subcommand flips the decision to deny.
_DESTRUCTIVE_SUBCOMMAND_FLAGS: dict[str, frozenset[str]] = {
    "branch": frozenset({"-d", "-D", "-m", "-M", "--delete", "--move", "--force"}),
    "tag": frozenset({"-d", "--delete"}),
    "remote": frozenset({"remove", "rm", "rename", "set-url"}),
}

# Stash sub-subcommands that are destructive
DENIED_STASH_ACTIONS: frozenset[str] = frozenset({"pop", "drop", "clear"})

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


_CONFIG_READ_FLAGS: frozenset[str] = frozenset(
    {"--get", "--list", "-l", "--get-all", "--get-regexp"}
)


def _decide_config(remaining: list[str]) -> dict[str, Any]:
    """Decide a ``git -C ... config ...`` invocation."""
    if remaining and remaining[0] in _CONFIG_READ_FLAGS:
        return emit_pretooluse_decision("allow", "git -C: 'config' with read-only flag")
    return _ask_envelope("git -C: 'config' write requires confirmation")


def _decide_stash(remaining: list[str]) -> dict[str, Any] | None:
    """Decide a ``git -C ... stash <action>`` invocation, or fall through."""
    if not remaining:
        return None
    action = remaining[0]
    if action in DENIED_STASH_ACTIONS:
        return emit_pretooluse_decision("deny", f"git -C: 'stash {action}' is destructive")
    if action in ("list", "show"):
        return emit_pretooluse_decision("allow", f"git -C: 'stash {action}' is read-only")
    return None


def _has_destructive_subcommand_flag(subcommand: str, remaining: list[str]) -> str | None:
    """Return the destructive flag/operand that flips an allowed subcommand to deny."""
    flags = _DESTRUCTIVE_SUBCOMMAND_FLAGS.get(subcommand)
    if not flags:
        return None
    for tok in remaining:
        if tok in flags:
            return tok
    return None


def _classify_subcommand(subcommand: str, remaining: list[str]) -> dict[str, Any]:
    """Classify a parsed subcommand into an allow/deny/ask envelope."""
    if subcommand == "config":
        return _decide_config(remaining)
    if subcommand == "stash":
        stash_decision = _decide_stash(remaining)
        if stash_decision is not None:
            return stash_decision
    if subcommand in DENIED_SUBCOMMANDS:
        return emit_pretooluse_decision(
            "deny", f"git -C: '{subcommand}' is destructive and blocked"
        )
    destructive_flag = _has_destructive_subcommand_flag(subcommand, remaining)
    if destructive_flag is not None:
        return emit_pretooluse_decision(
            "deny",
            f"git -C: '{subcommand} {destructive_flag}' is destructive and blocked",
        )
    if subcommand in ALLOWED_SUBCOMMANDS:
        return emit_pretooluse_decision("allow", f"git -C: '{subcommand}' is read-only")
    return _ask_envelope(f"git -C: '{subcommand}' is not in the allow list")


_COMMIT_HEAD_TOKENS = 3  # ['git', 'commit', <at least one more arg>]


def _is_reuse_token(tok: str, idx: int, parts: list[str]) -> bool:
    """Return True iff ``tok`` at position ``idx`` requests prior-message reuse."""
    if tok == "-C" and idx + 1 < len(parts):
        return True
    if tok.startswith("-C") and len(tok) > _DASH_C_PREFIX_LEN and not tok.startswith("--"):
        return True
    if tok == "--reuse-message" and idx + 1 < len(parts):
        return True
    return tok.startswith("--reuse-message=")


def _skip_git_global_flags(parts: list[str]) -> int:
    """Return the index of the first non-global-flag token after ``git``.

    Walks past ``-C <path>``, ``-c <key=val>``, ``--git-dir <path>``,
    ``--work-tree <path>``, ``--namespace <ns>``, ``--exec-path``, ``-p``,
    etc. so that ``git -C /tmp commit -C HEAD`` parses as the ``commit`` shape.
    """
    if not parts or parts[0] != "git":
        return 0
    i = 1
    n = len(parts)
    consume_next = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
    while i < n:
        tok = parts[i]
        if tok in consume_next and i + 1 < n:
            i += 2
            continue
        if "=" in tok and tok.split("=", 1)[0] in {"--git-dir", "--work-tree", "--namespace"}:
            i += 1
            continue
        if tok.startswith("-") and not tok.startswith("--"):
            # Bundled short flags / inline -C/path form are global.
            i += 1
            continue
        if tok.startswith("--") and tok != "--":
            # Long-form valueless global flags (--no-pager, --bare, --paginate).
            i += 1
            continue
        break
    return i


def _is_commit_reuse(command: str) -> bool:
    """Return ``True`` if the command silently reuses a prior commit message.

    Matches ``git commit -C <ref>`` and ``git commit --reuse-message=<ref>``,
    including when a ``-C <path>`` / ``--git-dir <path>`` global flag prefixes
    the ``commit`` subcommand. These let an agent append to history without
    authoring a new message, which defeats the audit trail commit_message_validator
    is meant to enforce.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    sub_idx = _skip_git_global_flags(parts)
    if sub_idx >= len(parts) or parts[sub_idx] != "commit":
        return False
    rest = parts[sub_idx + 1 :]
    return any(_is_reuse_token(tok, i, rest) for i, tok in enumerate(rest))


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
    """Return a permission envelope, or ``None`` to fall through."""
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
    if _is_commit_reuse(command):
        return emit_pretooluse_decision(
            "deny",
            "git commit -C / --reuse-message: silent commit-message reuse is blocked",
        )
    path, subcommand, remaining = parse_git_c_command(command)
    if path is None or subcommand is None:
        return None
    return _classify_subcommand(subcommand, remaining)


def _ask_envelope(reason: str) -> dict[str, Any]:
    """Return an ``ask`` envelope via the modern PreToolUse helper."""
    return emit_pretooluse_decision("ask", reason)


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
    # (in any of its argv shapes — bare, fused, equals, --config-env) or a
    # `git commit` subcommand reaches `decide()`. The previous substring
    # gate ("git -c " with trailing space) skipped the fused form
    # `git -ccore.hooksPath=...`, leaving the new fused-form parser dead.
    try:
        head = shlex.split(command)
    except ValueError:
        head = command.split()
    if not head or head[0] != "git":
        return
    rest = head[1:]
    has_config_or_dir_flag = any(t.startswith(("-C", "-c", "--config-env")) for t in rest)
    if not has_config_or_dir_flag and "commit" not in rest:
        return

    envelope = decide(command)
    if envelope is None:
        return

    hso = envelope.get("hookSpecificOutput", {})
    decision = hso.get("permissionDecision")
    cwd = payload.get("cwd")
    if decision in ("allow", "deny", "ask"):
        log_decision(
            hook_id=_HOOK_ID,
            event="PreToolUse",
            tool_name="Bash",
            decision=decision,
            reason=hso.get("permissionDecisionReason", ""),
            command_excerpt=command,
            session_id=str(payload.get("session_id", "")),
            cwd=cwd if isinstance(cwd, str) else None,
        )
    sys.stdout.write(json.dumps(envelope))
    if decision == "deny":
        sys.exit(2)


if __name__ == "__main__":
    safe_main(hook)
