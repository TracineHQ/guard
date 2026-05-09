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

from guard._safe_io import is_sensitive_read_target

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
