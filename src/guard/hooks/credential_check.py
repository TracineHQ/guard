# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Credential file permission validator.

Checks that sensitive credential files have owner-only (0600) permissions.
Group/other access on these files is treated as a misconfiguration.
"""

from __future__ import annotations

import stat
from pathlib import Path

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
