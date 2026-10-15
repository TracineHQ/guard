# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: deny any tool call that touches a credential file.

Universal path scanner: every path-like token in ``tool_input`` is extracted
(regardless of ``tool_name``) and checked against credential matchers. Any
hit is denied with a reason that steers the agent to the tool's own auth or
to the user.

Closes the bypass where ``Read({"file_path": "~/.aws/credentials"})`` was
allowed silently because the previous implementation only fired on
``Edit``/``Write``/``Bash``.

Tiers of detection (v1):

- Tier 1: direct path through every tool — Edit, Write, Read, Bash readers,
  WebFetch with ``file://``, Glob, Grep, MultiEdit, NotebookEdit
- Tier 2: copy-source shadow — ``cp/mv/dd/install/rsync/scp/tar`` with a
  credential file as source
- Tier 4: symlink resolution via ``Path.resolve()`` (already handled in
  ``_candidate_paths``)
- Tier 6: heuristic match on filename keywords / sensitive extensions

This module also exposes a permissions-audit utility
(``check_file_permissions`` / ``check_all``) for diagnostic-CLI use; that
utility is independent of the hook entry point.
"""

from __future__ import annotations

import os
import re
import shlex
import stat
from pathlib import Path
from typing import Any

from guard._utils import (
    all_paths_in,
    emit_pretooluse_decision,
    safe_main,
    token_basename,
)
from guard.allowlist import apply_decision

_HOOK_ID = "guard.credential_check"

# === Permissions-audit utility (used by the future diagnostic CLI) ===

CREDENTIAL_FILES: list[Path] = [
    Path.home() / ".claude" / "credentials" / "auth0.json",
    Path.home() / ".claude" / ".credentials.json",
]

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
    r"\bpat\b|\bkey\b|"
    # Token-prefixed filenames (provider-issued PATs / publishable keys).
    # Anchored so they don't false-match a substring inside an unrelated word.
    r"(?:^|[^A-Za-z0-9])(?:gh_|glpat[_-]|npm_|sk_|pk_live_))"
)
_HEURISTIC_EXTENSIONS: frozenset[str] = frozenset(
    {".pem", ".p12", ".pfx", ".kdbx", ".gpg", ".asc", ".jks", ".p8", ".ppk"}
)

# Tier 2: copy-source shadow — file-copy tools where a credential path in
# source position is denied at copy time (so the cp itself is gated, not
# only a later read of the destination).
_COPY_HEAD_VERBS: frozenset[str] = frozenset({"cp", "mv", "install", "rsync", "scp"})

_DENY_REASON = (
    "Credential file access blocked. Touching credential material "
    "(AWS/SSH/.env/*.pem/*.key/etc.) puts secrets in the transcript. Let the "
    "tool use its own auth (aws, gh, ssh read their credentials themselves), "
    "or ask the user for the specific non-secret value you need."
)
_DENY_REASON_COPY = (
    "Credential file copy blocked. A credential file appears as a copy source "
    "(cp/mv/dd/install/rsync/scp/tar). Don't duplicate secrets: point the tool "
    "that needs them at the original path, or tell the user what you're "
    "setting up."
)
# Write-class tools whose credential subject is the DESTINATION path, not paths
# mentioned in the content body (see ``decide``).
_WRITE_TOOLS: frozenset[str] = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})


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

    ``Path.resolve()`` follows symlinks: on macOS ``/tmp/../Users/<user>/.ssh/id_rsa``
    resolves to ``/private/Users/<user>/.ssh/id_rsa`` because ``/tmp`` is a symlink
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


def _has_sensitive_extension(file_path: str) -> bool:
    """Tier 6a: basename carries a sensitive extension (.pem/.p12/.gpg/...)."""
    if not file_path:
        return False
    for candidate in _candidate_paths(file_path):
        base = token_basename(candidate)
        if base and Path(base).suffix.lower() in _HEURISTIC_EXTENSIONS:
            return True
    return False


def _is_heuristic_credential(file_path: str) -> bool:
    """Tier 6: sensitive extension OR credential filename keyword.

    Case-insensitive on the basename only — directory portions don't trigger
    so a normal file inside a ``keystore/`` directory doesn't false-match.

    The filename-keyword arm is intentionally NOT applied to tokens pulled out
    of a Bash command string (see ``_hits_credential_strict``): in a shell
    command a ``secret``/``token``/``key`` token is almost always a grep
    pattern, a source filename, or a subcommand argument that merely mentions
    the word, not a credential file being read.
    """
    if not file_path:
        return False
    if _has_sensitive_extension(file_path):
        return True
    for candidate in _candidate_paths(file_path):
        base = token_basename(candidate)
        if base and _HEURISTIC_NAME_RE.search(base):
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
        return any(_hits_credential_strict(s) for s in sources)

    if head == "dd":
        return any(
            _hits_credential_strict(tok[len("if=") :])
            for tok in tokens[1:]
            if tok.startswith("if=")
        )

    if head == "tar" and _tar_is_create(tokens):
        return any(_hits_credential_strict(t) for t in tokens[1:] if not t.startswith("-"))

    return False


def _hits_credential(path: str) -> bool:
    """Tier 1 + Tier 6: literal credential match or heuristic match."""
    return _path_is_credential(path) or _is_heuristic_credential(path)


def _hits_credential_strict(path: str) -> bool:
    """Bash-context matcher: credential path or sensitive extension only.

    Excludes the filename-keyword heuristic, which over-fires on grep
    patterns / source filenames / subcommand args that merely *mention* a
    credential keyword. Path- and extension-based signals remain
    (``~/.aws/credentials``, ``.env``, ``*.pem``).
    """
    return _path_is_credential(path) or _has_sensitive_extension(path)


def _decide_bash(command: str) -> dict[str, Any] | None:
    """Bash-specific tiers: bare-name credential tokens and copy-source."""
    if not command:
        return None
    # Tokenize and run each token through the credential matcher — catches
    # bare-name shapes (``cat .env``) that don't contain a path separator
    # and so escape the path-like regex.
    for tok in _tokenize(command):
        if not tok or tok.startswith("-"):
            continue
        if _hits_credential_strict(tok):
            return emit_pretooluse_decision("deny", _DENY_REASON)
    if _is_credential_copy_source(command):
        return emit_pretooluse_decision("deny", _DENY_REASON_COPY)
    return None


def decide(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any] | None:
    """Return a ``deny`` envelope when a credential file is being touched.

    Universal scanner: every path-like token in ``tool_input`` is extracted
    and checked, regardless of ``tool_name``. The Bash-specific tier-2
    (copy source) check gates only on ``Bash`` because its semantics are
    command-specific.
    """
    if not isinstance(tool_input, dict):
        return None

    is_bash = tool_name == "Bash"

    # Write-class tools: the credential subject is the file being WRITTEN, not
    # paths merely mentioned in the body. A doc / test fixture / source file that
    # references ~/.ssh or ~/.aws is not touching the credential, so scanning the
    # content would deny every such edit -- a false positive that buries the
    # real signal. Check only the destination path: writing TO a credential file
    # still denies; credential MATERIAL in the body is the secret-value detector's
    # job (it matches key contents, not path mentions).
    if tool_name in _WRITE_TOOLS:
        for field in ("file_path", "notebook_path"):
            target = tool_input.get(field, "")
            if isinstance(target, str) and _hits_credential(target):
                return emit_pretooluse_decision("deny", _DENY_REASON)
        return None

    # Tier 1 + Tier 4 + Tier 6: any path-like token in any field. For Bash the
    # tokens come from a command string, where the filename-keyword heuristic
    # over-fires on grep patterns / args — use the path+extension matcher only.
    for raw in all_paths_in(tool_input):
        hit = _hits_credential_strict(raw) if is_bash else _hits_credential(raw)
        if hit:
            return emit_pretooluse_decision("deny", _DENY_REASON)

    if is_bash:
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

    field = "command" if tool_name == "Bash" else "file_path"
    excerpt = tool_input.get(field) or tool_input.get("notebook_path") or ""
    apply_decision(_HOOK_ID, payload, envelope, excerpt if isinstance(excerpt, str) else "")


if __name__ == "__main__":
    safe_main(hook)
