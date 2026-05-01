# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: ask before any tool touches a credential file.

Universal path scanner: every path-like token in ``tool_input`` is extracted
(regardless of ``tool_name``) and checked against credential matchers. ASK
fires on any hit.

Closes the bypass where ``Read({"file_path": "~/.aws/credentials"})`` was
allowed silently because the previous implementation only fired on
``Edit``/``Write``/``Bash``.

Tiers of detection (v1):

- Tier 1: direct path through every tool — Edit, Write, Read, Bash readers,
  WebFetch with ``file://``, Glob, Grep, MultiEdit, NotebookEdit
- Tier 2: copy-source shadow — ``cp/mv/dd/install/rsync/scp/tar`` with a
  credential file as source
- Tier 3: var indirection — reader head + ``$VAR``/``${VAR}`` arg (cannot
  resolve statically, ASK to be safe)
- Tier 4: symlink resolution via ``Path.resolve()`` (already handled in
  ``_candidate_paths``)
- Tier 6: heuristic match on filename keywords / sensitive extensions

This module also exposes a permissions-audit utility
(``check_file_permissions`` / ``check_all``) for diagnostic-CLI use; that
utility is independent of the hook entry point.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

from guard._utils import (
    all_paths_in,
    emit_pretooluse_decision,
    log_decision,
    safe_main,
    token_basename,
)

_HOOK_ID = "guard.credential_check"

# === Permissions-audit utility (used by the future diagnostic CLI) ===

CREDENTIAL_FILES: list[Path] = [
    Path.home() / ".claude" / "credentials" / "auth0.json",
    Path.home() / ".claude" / ".credentials.json",
]

MAX_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600

_GROUP_OTHER_MASK = (
    stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
)


def check_file_permissions(path: Path) -> tuple[bool, str]:
    """Check if a credential file has safe permissions.

    Args:
        path: Path to the credential file.

    Returns:
        ``(is_safe, message)`` — ``is_safe`` is True for missing files or
        files restricted to the owner; False if any group/other bit is set.
    """
    if not path.exists():
        return True, f"{path}: does not exist (ok)"

    mode = path.stat().st_mode
    file_perms = mode & 0o777

    if file_perms & _GROUP_OTHER_MASK:
        return (
            False,
            (
                f"{path}: permissions {oct(file_perms)} — "
                f"group/other access detected. Run: chmod 600 {path}"
            ),
        )

    return True, f"{path}: permissions {oct(file_perms)} (ok)"


def check_all() -> list[tuple[bool, str]]:
    """Check all known credential files."""
    return [check_file_permissions(p) for p in CREDENTIAL_FILES]


# === PreToolUse hook entry point ===

_HOME = str(Path.home())

_CREDENTIAL_PATH_LITERALS: tuple[str, ...] = (
    f"{_HOME}/.aws/credentials",
    f"{_HOME}/.aws/config",
    f"{_HOME}/.netrc",
    f"{_HOME}/.config/gh/hosts.yml",
)

# Regexes matching paths that look like credential material.
# Apply to the lexically-resolved candidate paths (see ``_candidate_paths``).
_CREDENTIAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"^{re.escape(_HOME)}/\.ssh/id_[A-Za-z0-9_]+(?:\.pub)?$"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"(?:^|/)\.env(?:\.[A-Za-z0-9_.-]+)?$"),
    # Whole-directory credential stores (anywhere on path)
    re.compile(r"/\.aws(?:/|$)"),
    re.compile(r"/\.ssh(?:/|$)"),
    re.compile(r"/\.gnupg(?:/|$)"),
    re.compile(r"/\.kube/config(?:$|/)"),
    re.compile(r"/\.docker/config\.json$"),
    re.compile(r"/\.config/gh/hosts\.yml$"),
    re.compile(r"/\.netrc$"),
]

# Tier 6: heuristic match on filename keywords + sensitive extensions.
# Only the basename is matched (case-insensitive); paths are ignored to keep
# false positives bounded (a "key" in a directory name like /tmp/keystore/x.txt
# wouldn't trigger).
_HEURISTIC_NAME_RE = re.compile(
    r"(?i)(?:secret|token|password|credential|api[_-]?key|bearer|"
    r"\bpat\b|\bkey\b)"
)
_HEURISTIC_EXTENSIONS: frozenset[str] = frozenset(
    {".pem", ".p12", ".pfx", ".kdbx", ".gpg", ".asc", ".jks", ".p8", ".ppk"}
)

# Tier 2: copy-source shadow — file-copy tools where a credential path in
# source position should ASK at copy time (so the cp itself is gated, not
# only a later read of the destination).
_COPY_HEAD_VERBS: frozenset[str] = frozenset({"cp", "mv", "install", "rsync", "scp"})

# Tier 3: reader heads where a $VAR / ${VAR} argument cannot be resolved
# statically — ASK because the variable may point at a credential file.
_READER_HEAD_VERBS: frozenset[str] = frozenset(
    {
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "sed",
        "awk",
        "grep",
        "rg",
        "xxd",
        "od",
        "hexdump",
        "strings",
        "view",
        "vim",
        "vi",
        "nano",
        "emacs",
        "bat",
        "tee",
    }
)

# Tier 3 helper: matches a bare ``$VAR``, ``${VAR}``, or a token starting with
# either form followed by a path segment. We ASK on any of these because we
# can't resolve the variable.
_VAR_ARG_RE = re.compile(
    r"(?:^|[^\\])(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9])"
)

_ASK_REASON = (
    "Credential file access — confirm intent. "
    "Touching credential material (AWS/SSH/.env/*.pem/*.key/etc.) requires "
    "an explicit human OK so a misrouted edit can't leak secrets."
)
_ASK_REASON_COPY = (
    "Credential file copy — confirm intent. A credential file appears as a "
    "copy source (cp/mv/dd/install/rsync/scp/tar). ASK so an unintended "
    "copy of secrets is gated by a human."
)
_ASK_REASON_VAR = (
    "Reader command with variable argument — cannot resolve statically. "
    "If the variable expands to a credential file (e.g. $HOME/.aws/credentials), "
    "the contents would leak into the agent transcript. Confirm intent."
)


def _expand(path: str) -> str:
    """Expand ``~`` and resolve ``..`` segments lexically (no FS lookup).

    Falls back to the lexical form if ``Path.resolve()`` raises ``OSError``.
    """
    expanded = str(Path(path).expanduser())
    try:
        return str(Path(expanded).resolve())
    except OSError:
        return expanded


def _candidate_paths(path: str) -> list[str]:
    """Return both the resolved and lexical-normalized forms of ``path``.

    ``Path.resolve()`` follows symlinks: on macOS ``/tmp/../Users/dev/.ssh/id_rsa``
    resolves to ``/private/Users/dev/.ssh/id_rsa`` because ``/tmp`` is a symlink
    to ``/private/tmp``. The credential matchers anchor on ``$HOME`` (``/Users/dev``)
    so the resolved form misses. Match against both to close that gap.
    """
    out: list[str] = []
    if not path:
        return out
    resolved = _expand(path)
    out.append(resolved)
    lexical = os.path.normpath(str(Path(path).expanduser()))
    if lexical != resolved:
        out.append(lexical)
    if resolved.startswith("/private/"):
        out.append(resolved[len("/private") :])
    return out


def _path_is_credential(file_path: str) -> bool:
    """Return True if ``file_path`` resolves to a known credential file."""
    if not file_path:
        return False
    for candidate in _candidate_paths(file_path):
        if candidate in _CREDENTIAL_PATH_LITERALS:
            return True
        if any(p.search(candidate) for p in _CREDENTIAL_PATH_PATTERNS):
            return True
    return False


def _is_heuristic_credential(file_path: str) -> bool:
    """Tier 6: filename-keyword / sensitive-extension heuristic.

    Case-insensitive on the basename only — directory portions don't trigger
    so a normal file inside a ``keystore/`` directory doesn't false-match.
    """
    if not file_path:
        return False
    for candidate in _candidate_paths(file_path):
        base = token_basename(candidate)
        if not base:
            continue
        # Sensitive extensions (use Path.suffix on the basename string).
        if Path(base).suffix.lower() in _HEURISTIC_EXTENSIONS:
            return True
        # Filename keywords
        if _HEURISTIC_NAME_RE.search(base):
            return True
    return False


def _tokenize(command: str) -> list[str]:
    """Tokenize a Bash command, falling back to whitespace split on parse error."""
    try:
        return shlex.split(command)
    except ValueError:
        return command.strip().split()


def _tar_is_create(tokens: list[str]) -> bool:
    """Return True if ``tar`` arg list indicates create mode (``c[fz]?`` or ``-c``)."""
    for tok in tokens[1:]:
        if not tok.startswith("-"):
            return "c" in tok
        if tok in ("-c", "--create"):
            return True
    return False


def _is_credential_copy_source(command: str) -> bool:
    """Tier 2: detect a credential path in source position of a copy verb.

    Recognises ``cp/mv/install/rsync/scp`` (last positional arg is dest, so
    every other path token is a source), ``dd if=<src>``, and ``tar c[fz]?``
    (create mode — every non-flag token is treated as a potential source).
    """
    if not command.strip():
        return False
    tokens = _tokenize(command)
    if not tokens:
        return False
    head = token_basename(tokens[0])

    if head in _COPY_HEAD_VERBS:
        positional = [t for t in tokens[1:] if not t.startswith("-")]
        sources = positional[:-1] if len(positional) > 1 else positional
        return any(_hits_credential(s) for s in sources)

    if head == "dd":
        return any(
            _hits_credential(tok[len("if=") :]) for tok in tokens[1:] if tok.startswith("if=")
        )

    if head == "tar" and _tar_is_create(tokens):
        return any(_hits_credential(t) for t in tokens[1:] if not t.startswith("-"))

    return False


def _is_reader_with_var_arg(command: str) -> bool:
    """Tier 3: reader head + ``$VAR`` / ``${VAR}`` arg.

    Returns True for commands like ``cat $P``, ``sed -i $CRED_PATH``,
    ``head ${SECRET_FILE}``. We can't resolve the variable statically, so
    ASK — false positives here are cheap (user clicks through), false
    negatives leak credentials.
    """
    if not command.strip():
        return False
    tokens = _tokenize(command)
    if not tokens:
        return False
    head = token_basename(tokens[0])

    # Stdin redirection: ``< $VAR`` is also a read.
    has_stdin_var = any(
        prev == "<" and _VAR_ARG_RE.search(tok) for prev, tok in itertools.pairwise(tokens)
    )
    if has_stdin_var:
        return True

    if head not in _READER_HEAD_VERBS:
        return False
    return any(_VAR_ARG_RE.search(tok) for tok in tokens[1:])


def _hits_credential(path: str) -> bool:
    """Tier 1 + Tier 6: literal credential match or heuristic match."""
    return _path_is_credential(path) or _is_heuristic_credential(path)


def _decide_bash(command: str) -> dict[str, Any] | None:
    """Bash-specific tiers: bare-name credential tokens, copy-source, var-indirection."""
    if not command:
        return None
    # Tokenize and run each token through the credential matcher — catches
    # bare-name shapes (``cat .env``) that don't contain a path separator
    # and so escape the path-like regex.
    for tok in _tokenize(command):
        if not tok or tok.startswith("-"):
            continue
        if _hits_credential(tok):
            return emit_pretooluse_decision("ask", _ASK_REASON)
    if _is_credential_copy_source(command):
        return emit_pretooluse_decision("ask", _ASK_REASON_COPY)
    if _is_reader_with_var_arg(command):
        return emit_pretooluse_decision("ask", _ASK_REASON_VAR)
    return None


def decide(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any] | None:
    """Return an ``ask`` envelope when a credential file is being touched.

    Universal scanner: every path-like token in ``tool_input`` is extracted
    and checked, regardless of ``tool_name``. Bash-specific tier-2 (copy
    source) and tier-3 (variable indirection) logic still gates only on
    ``Bash`` because their semantics are command-specific.
    """
    if not isinstance(tool_input, dict):
        return None

    # Tier 1 + Tier 4 + Tier 6: any path-like token in any field
    for raw in all_paths_in(tool_input):
        if _hits_credential(raw):
            return emit_pretooluse_decision("ask", _ASK_REASON)

    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if isinstance(cmd, str):
            return _decide_bash(cmd)

    return None


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    if not isinstance(tool_name, str):
        return

    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    envelope = decide(tool_name, tool_input)
    if envelope is None:
        return

    excerpt: str | None = None
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if isinstance(cmd, str):
            excerpt = cmd
    else:
        fp = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        if isinstance(fp, str):
            excerpt = fp

    cwd = payload.get("cwd")
    reason = envelope["hookSpecificOutput"]["permissionDecisionReason"]
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name,
        decision="ask",
        reason=reason,
        command_excerpt=excerpt,
        session_id=str(payload.get("session_id", "")),
        cwd=cwd if isinstance(cwd, str) else None,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
