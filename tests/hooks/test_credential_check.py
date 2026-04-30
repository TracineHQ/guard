"""Tests for credential file permission checker."""

from __future__ import annotations

from guard.hooks.credential_check import (
    check_all,
    check_file_permissions,
)


class TestCheckFilePermissions:
    def test_nonexistent_file_is_safe(self, tmp_path):
        safe, msg = check_file_permissions(tmp_path / "nonexistent.json")
        assert safe
        assert "does not exist" in msg

    def test_600_is_safe(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o600)
        safe, _ = check_file_permissions(f)
        assert safe

    def test_644_is_unsafe(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o644)
        safe, msg = check_file_permissions(f)
        assert not safe
        assert "group/other" in msg

    def test_666_is_unsafe(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o666)
        safe, _ = check_file_permissions(f)
        assert not safe

    def test_400_is_safe(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o400)
        safe, _ = check_file_permissions(f)
        assert safe

    def test_640_is_unsafe(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o640)
        safe, _ = check_file_permissions(f)
        assert not safe

    def test_message_includes_fix_command(self, tmp_path):
        f = tmp_path / "creds.json"
        f.write_text('{"key": "val"}')
        f.chmod(0o644)
        _, msg = check_file_permissions(f)
        assert "chmod 600" in msg


class TestCheckAll:
    def test_returns_list_of_tuples(self):
        results = check_all()
        assert isinstance(results, list)
        for is_safe, msg in results:
            assert isinstance(is_safe, bool)
            assert isinstance(msg, str)


class TestImports:
    def test_check_credential_imports(self):
        # The top-level import is the contract; this asserts the symbol is callable.
        assert callable(check_file_permissions)
