"""Shared safe-I/O primitives for guard hooks.

Hooks occasionally need to read user-supplied paths during the
PreToolUse decision (``commit_message_validator`` reads ``-F <path>``;
``protected_files`` reads ``patch -i <diff>``). Reading those paths
naively is risky: an attacker-controlled path can point at
``/etc/passwd``, ``/proc/self/mem``, ``~/.ssh/id_rsa``, a FIFO that
hangs the read, or an attacker-swapped symlink. The primitives here
combine four defenses:

1. **Stream-shape detection** (``looks_like_stream_path``) — refuses
   ``/dev/stdin``, ``/dev/fd/*``, ``/proc/self/fd/*``, character/FIFO
   /block devices.
2. **Scope restriction** (``is_under_cwd_or_temp``) — only the hook's
   reported working directory and standard temp roots are readable.
3. **Sensitive-target denylist** (``is_sensitive_read_target``) —
   ``/etc``, ``/proc``, ``/sys``, ``/var/log``, ``/var/db``, ``/root``,
   ``/boot``, ``/dev``, plus ``~/.ssh``, ``~/.aws``, ``~/.gnupg`` etc.
4. **O_NOFOLLOW + size cap** (``open_safe``) — refuses to follow a
   final-segment symlink (TOCTOU between ``resolve()`` and ``open()``)
   and bounds the read so a multi-GB file can't soft-DoS the hook.

These primitives are ``commit_message_validator``-derived; that file
keeps its ``OUT_OF_SCOPE_SENTINEL`` / ``STREAM_FILE_SENTINEL`` return
contract for backward compatibility, but composes the underlying
checks from this module.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import os
import stat
from pathlib import Path

# Stream-shape detection.

_STREAM_LITERAL_PATHS: frozenset[str] = frozenset({"/dev/stdin", "/dev/null", "/dev/fd/0", "-"})
_STREAM_PATH_PREFIXES: tuple[str, ...] = ("/dev/fd/", "/proc/self/fd/")


def looks_like_stream_path(path: str) -> bool:
    """Return True for stdin / fd / FIFO / character or block device paths.

    These cannot be pre-read reliably (a FIFO hangs; a fd reference is
    ephemeral; ``/dev/stdin`` differs across the resolved-vs-original
    path forms). Caller treats this as "refuse to pre-read" rather
    than attempting a read.
    """
    if path in _STREAM_LITERAL_PATHS:
        return True
    if path.startswith(_STREAM_PATH_PREFIXES):
        return True
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    if real in _STREAM_LITERAL_PATHS or real.startswith(_STREAM_PATH_PREFIXES):
        return True
    try:
        st = os.stat(real)  # noqa: PTH116 -- stat for st_mode classification
    except OSError:
        return False
    mode = st.st_mode
    return bool(stat.S_ISCHR(mode) or stat.S_ISFIFO(mode) or stat.S_ISBLK(mode))


# Scope restriction.

_TEMP_PREFIXES: tuple[str, ...] = (
    "/tmp/",  # noqa: S108 -- standard temp prefixes for scope check, not file creation
    "/var/folders/",  # macOS user temp
    "/var/tmp/",  # noqa: S108
    "/private/tmp/",  # macOS realpath form
    "/private/var/folders/",
    "/private/var/tmp/",
)


def is_under_cwd_or_temp(resolved: Path, cwd: str | None) -> bool:
    """Return True if ``resolved`` is under ``cwd`` or a standard temp root.

    Pre-reading user-supplied paths must be scope-restricted so an
    agent cannot use ``-F /etc/passwd``-style tricks to disclose
    arbitrary file contents through the hook's logging pipeline. Temp
    is allowed because agents commonly stage commit bodies / patches
    there before invoking the tool.
    """
    try:
        resolved_str = str(resolved)
    except (ValueError, OSError):
        return False
    if any(resolved_str.startswith(p) or resolved_str == p.rstrip("/") for p in _TEMP_PREFIXES):
        return True
    if cwd:
        try:
            cwd_resolved = Path(cwd).resolve()
        except (ValueError, OSError):
            return False
        try:
            resolved.relative_to(cwd_resolved)
        except ValueError:
            return False
        return True
    return False


# Sensitive-target denylist.

_SENSITIVE_READ_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/proc/",
    "/sys/",
    "/var/log/",
    "/var/db/",
    "/var/run/secrets/",  # k8s service-account tokens, secrets-store CSI mounts
    "/var/lib/kubelet/",  # node-level kubelet state, pod tokens
    "/private/etc/",
    "/private/var/log/",
    "/private/var/db/",
    "/private/var/run/secrets/",
    "/private/var/lib/kubelet/",
    "/root/",
    "/boot/",
    "/dev/",
)
_SENSITIVE_HOME_TAILS: tuple[str, ...] = (
    ".ssh/",
    ".aws/",
    ".gnupg/",
    ".config/gh/",
    ".config/sops/",  # SOPS age/PGP key material
    ".kube/",
    ".docker/config.json",
    ".netrc",
    ".pgpass",
    ".npmrc",  # npm auth tokens (_authToken, _password)
    ".pypirc",  # PyPI / TestPyPI upload tokens
    ".bash_history",  # may contain inline secrets / kubeconfig dumps
    ".zsh_history",
)


def is_sensitive_read_target(resolved: Path) -> bool:
    """Return True if ``resolved`` falls under a content-disclosure-sensitive root.

    Even paths that legitimately sit under cwd may symlink into
    ``/etc/passwd``, ``~/.ssh/id_rsa``, etc. The check operates on the
    already-resolved path so symlink redirects are followed BEFORE
    classification.
    """
    resolved_str = str(resolved)
    if any(resolved_str.startswith(p) for p in _SENSITIVE_READ_PREFIXES):
        return True
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        return False
    try:
        rel = resolved.relative_to(home)
    except ValueError:
        return False
    rel_str = str(rel)
    return any(rel_str.startswith(t) or rel_str == t.rstrip("/") for t in _SENSITIVE_HOME_TAILS)


# Combined safe-read.


def open_safe(resolved: Path, max_bytes: int) -> bytes | None:
    """Open ``resolved`` with O_NOFOLLOW, read up to ``max_bytes + 1``, return bytes or None.

    Returns:
        - ``None`` if open or read fails (file missing, EMLINK on a
          symlink, permissions, etc.).
        - ``bytes`` of length up to ``max_bytes`` on success.
        - ``bytes`` of length ``max_bytes + 1`` when the file was
          larger than the cap (caller decides: truncate-and-use or
          refuse). Reading one extra byte lets the caller distinguish
          "fits exactly" from "overflowed".

    Caller is responsible for the scope/stream/sensitive checks BEFORE
    calling this — ``open_safe`` is the final I/O primitive, not a
    full safety policy. Pair with ``looks_like_stream_path``,
    ``is_under_cwd_or_temp``, and ``is_sensitive_read_target``.
    """
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            return fh.read(max_bytes + 1)
    except OSError:
        return None


def safe_read_text_capped(  # noqa: PLR0911 -- linear refusal ladder is clearer than nested if/else
    path: str | Path,
    *,
    cwd: str | None,
    max_bytes: int,
) -> str | None:
    """Read ``path`` as UTF-8 text, applying the full safety policy.

    One-shot composition of all four primitives — convenient for hooks
    that just want "read this user-supplied path if it's safe to read,
    otherwise None". Does NOT distinguish failure modes (stream,
    out-of-scope, sensitive, missing, too-big all collapse to
    ``None``); use the individual primitives if your caller needs to
    log a different reason for each.

    Returns the decoded text on success (errors='replace'), or
    ``None`` if any check refuses or the I/O fails. A file larger
    than ``max_bytes`` returns ``None`` (the caller cannot know
    whether the content tail mattered, so we refuse rather than
    silently truncate).
    """
    raw_path = str(path)
    if not raw_path:
        return None
    if looks_like_stream_path(raw_path):
        return None
    p = Path(raw_path).expanduser()
    if not p.is_absolute() and cwd:
        p = Path(cwd) / p
    if looks_like_stream_path(str(p)):
        return None
    if not p.exists():
        return None
    try:
        resolved = p.resolve()
    except (ValueError, OSError):
        return None
    if is_sensitive_read_target(resolved):
        return None
    if not is_under_cwd_or_temp(resolved, cwd):
        return None
    raw = open_safe(resolved, max_bytes)
    if raw is None or len(raw) > max_bytes:
        return None
    return raw.decode("utf-8", errors="replace")
