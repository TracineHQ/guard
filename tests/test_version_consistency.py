"""Single-source-of-truth check for the package version.

``guard.__version__`` reads from installed package metadata (the dist built
from ``pyproject.toml``). These assertions catch drift between the code-side
constant, ``pyproject.toml``, and ``.claude-plugin/plugin.json``.

The marketplace catalog version (``.claude-plugin/marketplace.json`` →
``metadata.version``) is intentionally decoupled — a marketplace can list
multiple plugins and bumps independently of any one plugin. The check below
asserts they happen to match for v1.0.x as a smoke test only.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import guard

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_version_matches_package() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["version"] == guard.__version__


def test_plugin_manifest_version_matches_package() -> None:
    plugin = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["version"] == guard.__version__


def test_marketplace_version_matches_for_v1_0_x() -> None:
    # Smoke check only — see module docstring for why the marketplace
    # catalog version is semantically decoupled from the plugin version.
    marketplace = json.loads((REPO_ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert marketplace["metadata"]["version"] == guard.__version__
