# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for ``guard._safe_io`` primitives.

Indirectly exercised through ``commit_message_validator`` and
``protected_files`` integration tests, but the sensitive-target denylist
and home-tail extensions deserve direct coverage so a regression in the
list doesn't go silent.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from guard._safe_io import is_sensitive_read_target, open_safe

if TYPE_CHECKING:
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


# === looks_like_stream_path ===


def test_looks_like_stream_path_literal_stdin() -> None:
    from guard._safe_io import looks_like_stream_path

    assert looks_like_stream_path("/dev/stdin")
    assert looks_like_stream_path("/dev/null")
    assert looks_like_stream_path("/dev/fd/0")
    assert looks_like_stream_path("-")


def test_looks_like_stream_path_prefix_match() -> None:
    from guard._safe_io import looks_like_stream_path

    assert looks_like_stream_path("/dev/fd/12")
    assert looks_like_stream_path("/proc/self/fd/3")


def test_looks_like_stream_path_regular_file(tmp_path: Path) -> None:
    """A normal file on disk is NOT a stream path."""
    from guard._safe_io import looks_like_stream_path

    f = tmp_path / "ordinary.txt"
    f.write_text("hi")
    assert looks_like_stream_path(str(f)) is False


def test_looks_like_stream_path_realpath_oserror_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``os.path.realpath`` raising ``OSError`` collapses to ``False``."""
    import os as os_mod

    from guard import _safe_io

    def boom(_path: str) -> str:
        msg = "realpath failed"
        raise OSError(msg)

    monkeypatch.setattr(os_mod.path, "realpath", boom)
    assert _safe_io.looks_like_stream_path("/some/weird/path") is False


def test_looks_like_stream_path_stat_oserror_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stat failure after resolving (e.g. ENOENT race) collapses to ``False``."""
    from guard import _safe_io

    def boom_stat(_path: str) -> object:
        msg = "stat denied"
        raise OSError(msg)

    monkeypatch.setattr(_safe_io.os, "stat", boom_stat)
    assert _safe_io.looks_like_stream_path("/etc/hostname") is False


def test_looks_like_stream_path_fifo_is_stream(tmp_path: Path) -> None:
    """A FIFO on disk classifies as a stream (cannot pre-read reliably)."""
    import os as os_mod

    from guard._safe_io import looks_like_stream_path

    fifo = tmp_path / "p.fifo"
    os_mod.mkfifo(str(fifo))
    assert looks_like_stream_path(str(fifo))


def test_looks_like_stream_path_resolved_to_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Realpath that resolves to ``/dev/stdin`` is classified as stream."""
    from guard import _safe_io

    def fake_realpath(_path: str) -> str:
        return "/dev/stdin"

    monkeypatch.setattr(_safe_io.os.path, "realpath", fake_realpath)
    assert _safe_io.looks_like_stream_path("/some/symlink")


# === is_under_cwd_or_temp ===


def test_is_under_cwd_or_temp_temp_prefix(tmp_path: Path) -> None:
    from guard._safe_io import is_under_cwd_or_temp

    assert is_under_cwd_or_temp(Path("/tmp/foo.txt"), cwd=None)
    assert is_under_cwd_or_temp(Path("/private/tmp/foo.txt"), cwd=None)


def test_is_under_cwd_or_temp_no_cwd_no_temp() -> None:
    """A non-temp path with no cwd is refused."""
    from guard._safe_io import is_under_cwd_or_temp

    assert is_under_cwd_or_temp(Path("/srv/data/foo.txt"), cwd=None) is False


def test_is_under_cwd_or_temp_under_cwd(tmp_path: Path) -> None:
    from guard._safe_io import is_under_cwd_or_temp

    (tmp_path / "f.txt").write_text("x")
    assert is_under_cwd_or_temp((tmp_path / "f.txt").resolve(), cwd=str(tmp_path)) is True


def test_is_under_cwd_or_temp_under_cwd_outside_temp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the cwd-success return-True branch with the temp shortcut disabled."""
    from guard import _safe_io

    monkeypatch.setattr(_safe_io, "_TEMP_PREFIXES", ())
    assert _safe_io.is_under_cwd_or_temp(Path("/srv/work/sub/a.txt"), cwd="/srv/work") is True


def test_is_under_cwd_or_temp_outside_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    """A path outside the cwd subtree is refused.

    Disables the temp-prefix shortcut so the cwd-relative branch is the one
    actually under test (tmp_path on macOS sits under ``/private/var/folders``
    which is one of the temp prefixes).
    """
    from guard import _safe_io

    monkeypatch.setattr(_safe_io, "_TEMP_PREFIXES", ())
    assert _safe_io.is_under_cwd_or_temp(Path("/etc/passwd"), cwd="/srv/work") is False


def test_is_under_cwd_or_temp_cwd_resolve_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failure resolving the cwd collapses to ``False``."""
    from guard import _safe_io

    monkeypatch.setattr(_safe_io, "_TEMP_PREFIXES", ())

    real_resolve = Path.resolve

    def boom(self: Path, *args: object, **kwargs: object) -> Path:
        if str(self) == "/bogus-cwd":
            msg = "resolve denied"
            raise OSError(msg)
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", boom)
    assert _safe_io.is_under_cwd_or_temp(Path("/srv/data/f.txt"), cwd="/bogus-cwd") is False


# === safe_read_text_capped: composition of all checks ===


def test_safe_read_text_capped_empty_path() -> None:
    from guard._safe_io import safe_read_text_capped

    assert safe_read_text_capped("", cwd=None, max_bytes=1024) is None


def test_safe_read_text_capped_stream_path_refused() -> None:
    from guard._safe_io import safe_read_text_capped

    assert safe_read_text_capped("/dev/stdin", cwd=None, max_bytes=1024) is None


def test_safe_read_text_capped_relative_join_becomes_stream() -> None:
    """A relative path that, joined with cwd, lands on ``/dev/stdin`` is refused."""
    from guard._safe_io import safe_read_text_capped

    assert safe_read_text_capped("stdin", cwd="/dev", max_bytes=1024) is None


def test_safe_read_text_capped_relative_resolves_under_cwd(tmp_path: Path) -> None:
    """A relative path is joined under ``cwd`` and read normally."""
    from guard._safe_io import safe_read_text_capped

    (tmp_path / "msg.txt").write_text("hello commit", encoding="utf-8")
    out = safe_read_text_capped("msg.txt", cwd=str(tmp_path), max_bytes=1024)
    assert out == "hello commit"


def test_safe_read_text_capped_missing_file_returns_none(tmp_path: Path) -> None:
    from guard._safe_io import safe_read_text_capped

    assert safe_read_text_capped(tmp_path / "nope.txt", cwd=str(tmp_path), max_bytes=1024) is None


def test_safe_read_text_capped_sensitive_target_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resolved path that classifies as sensitive yields ``None``."""
    from guard._safe_io import safe_read_text_capped

    # Point home at tmp_path, then create a fake ``.ssh/id_rsa`` underneath.
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    sensitive = tmp_path / ".ssh" / "id_rsa"
    sensitive.parent.mkdir()
    sensitive.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert safe_read_text_capped(sensitive, cwd=str(tmp_path), max_bytes=1024) is None


def test_safe_read_text_capped_out_of_scope_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real file outside cwd / temp is refused.

    Disables the temp-prefix shortcut so the cwd-scope branch is the one
    under test — tmp_path on macOS lives inside ``/private/var/folders/``
    which would otherwise short-circuit to True.
    """
    from guard import _safe_io

    monkeypatch.setattr(_safe_io, "_TEMP_PREFIXES", ())
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    cwd = tmp_path / "work"
    cwd.mkdir()
    target = outside_root / "x.txt"
    target.write_text("nope")
    assert _safe_io.safe_read_text_capped(target, cwd=str(cwd), max_bytes=1024) is None


def test_safe_read_text_capped_too_big_returns_none(tmp_path: Path) -> None:
    """Files larger than ``max_bytes`` are refused, not silently truncated."""
    from guard._safe_io import safe_read_text_capped

    f = tmp_path / "big.txt"
    f.write_bytes(b"x" * 500)
    assert safe_read_text_capped(f, cwd=str(tmp_path), max_bytes=50) is None


def test_safe_read_text_capped_resolve_failure_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``Path.resolve`` failure between ``exists`` and the resolved check yields ``None``."""
    from guard import _safe_io

    f = tmp_path / "x.txt"
    f.write_text("hello")

    real_resolve = Path.resolve

    def boom(self: Path, *args: object, **kwargs: object) -> Path:
        if self == f:
            msg = "resolve denied"
            raise OSError(msg)
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", boom)
    assert _safe_io.safe_read_text_capped(f, cwd=str(tmp_path), max_bytes=1024) is None


def test_open_safe_read_oserror_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ``OSError`` from the read step (post-open) collapses to ``None``."""
    from guard import _safe_io

    f = tmp_path / "f.txt"
    f.write_text("hello")

    real_fdopen = _safe_io.os.fdopen

    class FakeFile:
        def __enter__(self) -> FakeFile:  # noqa: PYI034 -- test fake; never subclassed
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def read(self, _n: int) -> bytes:
            msg = "read denied"
            raise OSError(msg)

    def fake_fdopen(fd: int, mode: str) -> FakeFile:
        # Still close the underlying fd so we don't leak.
        try:
            real = real_fdopen(fd, mode)
            real.close()
        except OSError:
            pass
        return FakeFile()

    monkeypatch.setattr(_safe_io.os, "fdopen", fake_fdopen)
    assert _safe_io.open_safe(f, max_bytes=1024) is None


def test_is_sensitive_read_target_home_oserror_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``Path.home()`` raises, the home-tail check short-circuits to ``False``."""
    from guard import _safe_io

    def boom(_cls: type) -> Path:
        msg = "no home"
        raise RuntimeError(msg)

    monkeypatch.setattr(Path, "home", classmethod(boom))
    assert _safe_io.is_sensitive_read_target(Path("/srv/data/foo")) is False
