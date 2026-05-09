# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Guard — stdlib-only safety hooks plugin for Claude Code."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tracine-guard")
except PackageNotFoundError:  # source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
