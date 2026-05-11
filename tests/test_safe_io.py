# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for ``guard._safe_io`` primitives.

Indirectly exercised through ``commit_message_validator`` and
``protected_files`` integration tests, but the sensitive-target denylist
and home-tail extensions deserve direct coverage so a regression in the
list doesn't go silent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from guard._safe_io import is_sensitive_read_target, open_safe

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


# === System sensitive prefixes ===


def test_var_run_secrets_is_sensitive() -> None:
    """k8s service-account tokens / secrets-store CSI mounts."""
    from pathlib import Path

    assert is_sensitive_read_target(Path("/var/run/secrets/kubernetes.io/token"))


def test_var_lib_kubelet_is_sensitive() -> None:
    """Node-level kubelet state — pod tokens, kubeconfig."""
    from pathlib import Path

    assert is_sensitive_read_target(Path("/var/lib/kubelet/pods/x/volumes/secret/token"))


def test_private_var_run_secrets_is_sensitive_macos() -> None:
    """macOS realpath form of ``/var/run/secrets/``."""
    from pathlib import Path

    assert is_sensitive_read_target(Path("/private/var/run/secrets/x/token"))


# === Home-tail extensions ===


def test_bash_history_is_sensitive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Shell history may contain inline secrets / kubeconfig dumps."""
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert is_sensitive_read_target(tmp_path / ".bash_history")


def test_zsh_history_is_sensitive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert is_sensitive_read_target(tmp_path / ".zsh_history")


def test_npmrc_is_sensitive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """npm auth tokens (``//registry.npmjs.org/:_authToken=...``)."""
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert is_sensitive_read_target(tmp_path / ".npmrc")


def test_pypirc_is_sensitive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """PyPI / TestPyPI upload tokens."""
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert is_sensitive_read_target(tmp_path / ".pypirc")


def test_config_sops_dir_is_sensitive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """SOPS age/PGP key material under ``~/.config/sops/``."""
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert is_sensitive_read_target(tmp_path / ".config" / "sops" / "age" / "keys.txt")


# === Negative case: similarly-named non-sensitive paths still pass ===


def test_unrelated_dotfile_in_home_is_not_sensitive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A user's own scratch file under home isn't sensitive — only the
    enumerated tails (``.ssh``, ``.aws``, history files, etc.) are.
    """
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    assert not is_sensitive_read_target(tmp_path / "scratch.txt")
    assert not is_sensitive_read_target(tmp_path / "Documents" / "notes.md")


# === open_safe: O_NOFOLLOW symlink refusal ===


def test_open_safe_refuses_to_follow_symlink(tmp_path: Path) -> None:
    """``open_safe`` uses ``O_NOFOLLOW`` — opening a symlink raises ELOOP
    and returns ``None`` rather than reading the target.

    This is the TOCTOU / symlink-attack guard. A regression that dropped
    the flag (or swapped ``os.open`` for ``Path.read_text``) would
    silently follow links into ``/etc/passwd``, ``~/.ssh/id_rsa``, etc.
    during commit-message / protected-files reads.
    """
    real = tmp_path / "real.txt"
    real.write_bytes(b"sensitive-content")
    link = tmp_path / "link.txt"
    link.symlink_to(real)

    # Sanity: reading the real file works.
    assert open_safe(real, max_bytes=1024) == b"sensitive-content"
    # The symlink is refused — no following.
    assert open_safe(link, max_bytes=1024) is None


def test_open_safe_returns_none_when_file_missing(tmp_path: Path) -> None:
    """Missing files return ``None`` rather than raising."""
    assert open_safe(tmp_path / "does_not_exist", max_bytes=1024) is None


def test_open_safe_returns_overflow_marker(tmp_path: Path) -> None:
    """When the file exceeds ``max_bytes`` the result is one byte longer
    so the caller can detect overflow without a second stat call."""
    f = tmp_path / "big.txt"
    f.write_bytes(b"x" * 100)
    result = open_safe(f, max_bytes=50)
    assert result is not None
    assert len(result) == 51  # max_bytes + 1 == overflow signal
