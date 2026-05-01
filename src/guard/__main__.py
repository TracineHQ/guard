"""Entry point for ``python -m guard``."""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import argparse
import sys

from guard._status import render_status


def main(argv: list[str] | None = None) -> int:
    """Parse argv and dispatch to a subcommand."""
    parser = argparse.ArgumentParser(prog="python -m guard")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("status", help="Show guard installation status and recent decisions.")
    args = parser.parse_args(argv)
    if args.cmd == "status":
        sys.stdout.write(render_status())
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
