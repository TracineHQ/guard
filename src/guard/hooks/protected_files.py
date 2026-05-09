# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: force ASK on edits to security-critical hook files.

Matches ``Edit`` and ``Write`` ``tool_input.file_path`` against a small set of
protected path patterns. If matched, the hook emits an ``ask`` permission
decision so a human must confirm. It never blocks — its only job is to ensure
changes to the hook infrastructure are surfaced for review.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from guard._safe_io import safe_read_text_capped
from guard._utils import all_paths_in, emit_pretooluse_decision, log_decision, safe_main
from guard.allowlist import hook_bypass_reason, load_allowlist

_HOOK_ID = "guard.protected_files"

_CP_MV_INSTALL_MIN_OPERANDS = 2  # need both <src> and <dst>

# macOS APFS (default) and Windows NTFS are case-insensitive: ``.Claude``
# and ``.claude`` resolve to the same on-disk file. Pattern matching must
# normalise case there or an attacker can edit ``.Claude/CLAUDE.md`` and
# evade ``is_protected``. Linux ext4/xfs are case-sensitive and we keep
# strict matching there to avoid spurious matches on legitimate
# distinct-case directories.
_CASE_INSENSITIVE_FS = sys.platform in ("darwin", "win32")


def _normcase(s: str) -> str:
    return s.lower() if _CASE_INSENSITIVE_FS else s


# Trust-root patterns whose protection MUST NOT be allowlist-bypassable.
# An attacker (or a confused agent) who lands one ASK-approved write to the
# allowlist file, then sets ``disable_rules: ["guard.protected_files"]``,
# would silence every subsequent edit to every protected file — including
# subsequent edits to the allowlist itself. The same applies to
# ``.claude/settings*.json`` (the wiring that decides whether guard's hooks
# fire at all). For these, the allowlist override is intentionally refused;
# the user always sees an ASK. Other protected files (their CLAUDE.md, etc.)
# remain user-overridable through the normal allowlist mechanisms.
_UN_OVERRIDABLE_PATTERNS: frozenset[str] = frozenset(
    {
        ".claude/guard/allowlist.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
    }
)

# Files that define security policy for all Claude Code sessions.
# Changes to these affect every repo and every agent.
PROTECTED_PATTERNS: list[str] = [
    "guard/hooks/bash_command_validator.py",
    "guard/hooks/git_c_validator.py",
    "guard/hooks/credential_check.py",
    "guard/hooks/protected_files.py",
    "guard/hooks/commit_message_validator.py",
    "guard/hooks/agent_output_guard.py",
    "guard/hooks/subagent_scope.py",
    "guard/registry.py",
    "guard/_utils.py",
    # Claude Code harness configuration — these are the ASK-gate that
    # decides whether guard hooks even fire. Edits must surface for review.
    ".claude/settings.json",
    ".claude/settings.local.json",
    # Subagent scope file — a subagent rewriting its own scope is a TOCTOU
    # bypass of subagent_scope.py. Force ASK on edits.
    ".claude/subagent-scope.json",
    # Compatibility patterns for users who installed earlier hook scripts
    # under ``~/.claude/hooks/`` rather than via the plugin layout.
    "hooks/command_registry.py",
    "hooks/bash_command_validator.py",
    "hooks/git_c_validator.py",
    "hooks/credential_check.py",
    "hooks/generate_settings.py",
    "hooks/_hook_utils.py",
    "hooks/protected_files.py",
    "hooks/commit_message_validator.py",
    "hooks/agent_output_guard.py",
    # Git infrastructure: a write to .git/hooks/ replaces the repo's own
    # hook scripts, which run on every commit/push. .git/config holds
    # exec sinks (core.hooksPath, alias.* w/ !shell). .gitmodules can
    # auto-fetch attacker-controlled submodule URLs whose own hooks fire
    # during init. .git/info/attributes overrides .gitattributes (filter.*
    # exec sinks). All of these turn a "harmless" write into RCE.
    ".git/hooks",
    ".git/config",
    ".git/info/attributes",
    ".git/info/exclude",
    ".gitmodules",
    ".gitattributes",
    # Agent-config poisoning surface. Writes to these files reshape future
    # agent behavior across every subsequent session — the lowest-friction
    # LLM-on-LLM persistence vector. Force ASK on every edit so the human
    # sees a behavior-change attempt before it lands.
    # User-global instructions (every session reads these). Listed BEFORE
    # the project-level patterns so the more specific suffix wins the
    # first-match iteration.
    ".claude/CLAUDE.md",
    ".aider.conf.yml.user",
    # Project-level instructions read by Claude Code / Cursor / Aider.
    "CLAUDE.md",
    ".cursorrules",
    ".cursor/rules",
    ".aider.conf.yml",
    ".continue/config.json",
    # MCP server registrations — adding one mounts new tools into the
    # agent's capability surface.
    ".claude/mcp_servers",
    ".claude/mcp.json",
    # Cloud profile selection. ``~/.aws/config`` sets the default profile
    # the agent later assumes; flipping it from "personal" to "prod-admin"
    # is a privilege-escalation primitive that bypasses every shell matcher.
    ".aws/config",
    # Guard's own allowlist file — an agent that can write here grants
    # itself overrides. The ``protected_files`` ASK forces human review.
    ".claude/guard/allowlist.json",
]


# === Project-local pattern extension ===
#
# Two override knobs let downstream projects extend ``PROTECTED_PATTERNS``
# without forking. Both are stdlib-only and resolve at call time so test
# fixtures (and live env edits) take effect without a module reload.
#
# 1. ``GUARD_PROTECTED_EXTRA`` env var — comma-separated list of extra
#    patterns. Empty entries are skipped, surrounding whitespace trimmed.
# 2. ``.claude/guard-protected.txt`` file (rooted at cwd) — one pattern
#    per line; ``#`` starts a comment to end of line; blank lines OK.
#
# When both are present the FILE wins (it is the more deliberate
# artifact; env can be set system-wide for unrelated reasons). Patterns
# use the same syntax ``is_protected()`` already understands — suffix
# match for file patterns (any segment containing ``.``), segment match
# for directory patterns (last segment with no ``.``). No new grammar.

_GUARD_PROTECTED_ENV = "GUARD_PROTECTED_EXTRA"
_GUARD_PROTECTED_FILE_RELPATH = Path(".claude") / "guard-protected.txt"
# Caps on the project-extension file: anything bigger is either a mistake
# or an attempt to soft-DoS ``is_protected``'s per-call iteration. Enforced
# at parse time; a poisoned file simply yields ``[]`` rather than blowing
# up the hook.
_GUARD_PROTECTED_FILE_MAX_BYTES = 64 * 1024  # 64 KiB
_GUARD_PROTECTED_FILE_MAX_PATTERNS = 256


def _read_extra_patterns_from_env() -> list[str]:
    raw = os.environ.get(_GUARD_PROTECTED_ENV, "")
    if not raw:
        return []
    out: list[str] = []
    for entry in raw.split(","):
        s = entry.strip()
        if s:
            out.append(s)
    return out


def _read_extra_patterns_from_file(cwd: Path | None = None) -> list[str]:
    base = cwd if cwd is not None else Path.cwd()
    text = safe_read_text_capped(
        base / _GUARD_PROTECTED_FILE_RELPATH,
        cwd=str(base),
        max_bytes=_GUARD_PROTECTED_FILE_MAX_BYTES,
    )
    if text is None:
        return []
    # Reject corrupt files: ``safe_read_text_capped`` decodes with
    # ``errors='replace'`` for resilience, but a guard-protected file with
    # any non-UTF-8 bytes is corrupt — yield no extras rather than silently
    # treating the replacement character as part of a pattern.
    if "�" in text:
        return []
    out: list[str] = []
    for raw_line in text.splitlines():
        # Strip ``#`` comments + surrounding whitespace; skip blank lines.
        line = raw_line.split("#", 1)[0].strip()
        if line:
            out.append(line)
            if len(out) >= _GUARD_PROTECTED_FILE_MAX_PATTERNS:
                break
    return out


def _extra_patterns(cwd: Path | None = None) -> list[str]:
    """Return the file-then-env extension patterns (file precedence).

    Resolves at call time. If a ``.claude/guard-protected.txt`` file is
    readable, returns the patterns parsed from it (empty list if the
    file exists but is empty after comment-stripping). Otherwise falls
    back to the ``GUARD_PROTECTED_EXTRA`` env var. Returns ``[]`` when
    both are absent.
    """
    base = cwd if cwd is not None else Path.cwd()
    file_path = base / _GUARD_PROTECTED_FILE_RELPATH
    if file_path.exists():
        return _read_extra_patterns_from_file(base)
    return _read_extra_patterns_from_env()


def _effective_patterns(cwd: Path | None = None) -> tuple[str, ...]:
    """Return the merged pattern tuple: built-in defaults + project extras.

    Project-extra patterns are appended AFTER the built-ins so the
    first-match iteration in ``is_protected()`` favours specific
    built-in suffixes (e.g. ``.claude/CLAUDE.md`` before ``CLAUDE.md``)
    while still letting the project add its own.
    """
    return (*PROTECTED_PATTERNS, *_extra_patterns(cwd))


def is_protected(file_path: str) -> str | None:
    """Return the matched protected pattern for ``file_path``, else ``None``.

    A pattern matches if ``file_path`` either:
    - ends with the pattern (file-pattern match: ``.git/config`` matches
      ``/repo/.git/config``)
    - is contained as a path SEGMENT (directory-pattern match: ``.git/hooks``
      matches ``/repo/.git/hooks/pre-commit``)

    Directory-pattern matching is restricted to patterns whose last segment
    contains no ``.`` — file patterns (``.git/config``, ``.gitattributes``)
    only fire on the suffix form, so a path like ``/tmp/x/.git/config/extra``
    or ``tools/.gitattributes/templates/foo`` does NOT trigger.
    """
    if not file_path:
        return None
    try:
        resolved = Path(file_path).resolve()
    except (ValueError, OSError):
        return None

    resolved_lc = _normcase(str(resolved))
    for pattern in _effective_patterns():
        pat_lc = _normcase(pattern)
        # Exact-suffix match (file pattern).
        if (
            resolved_lc.endswith(pat_lc)
            and len(resolved_lc) > len(pat_lc)
            and resolved_lc[-(len(pat_lc) + 1)] == "/"
        ):
            return pattern  # original-case pattern goes to the deny message
        # Directory-pattern match: only for patterns whose last segment has
        # no ``.`` (i.e. is a directory name, not a file name).
        last_segment = pattern.rsplit("/", 1)[-1]
        if "." not in last_segment and "/" + pat_lc + "/" in resolved_lc:
            return pattern
    return None


def is_protected_parent_dir(dir_path: str) -> str | None:
    """Return the matched protected pattern when ``dir_path`` is an ancestor.

    Used for write shapes that target a directory rather than a file (e.g.
    ``tar -xf foo.tar -C <dir>``). If any protected pattern's directory
    prefix is a child of ``dir_path``, an extraction into ``dir_path`` could
    overwrite the protected file.
    """
    if not dir_path:
        return None
    try:
        resolved = Path(dir_path).resolve()
    except (ValueError, OSError):
        return None

    resolved_lc = _normcase(str(resolved).rstrip("/"))
    for pattern in _effective_patterns():
        # ``pattern`` is the suffix path of a protected file. An extraction
        # into ``resolved_str`` could write to ``<resolved_str>/<tail>`` for
        # some suffix ``tail``. We consider the dir risky if it sits anywhere
        # along the protected pattern's directory chain — checking each
        # progressively shallower prefix catches both a deep extraction
        # (``-C <repo>/src/guard/hooks/``) and a shallow one
        # (``-C <repo>/src/`` extracting an archive that contains
        # ``guard/hooks/...``).
        parts = pattern.split("/")
        for j in range(1, len(parts)):
            prefix = _normcase("/".join(parts[:j]))
            if resolved_lc.endswith("/" + prefix):
                return pattern
    return None


# Bash redirect / file-write commands and their target-extracting regex / token
# index. Used by ``bash_write_targets`` as a best-effort second line of
# defense — the primary path is the Edit/Write tool guard above.
_BASH_REDIRECT_RE = re.compile(r"(?:^|\s)>>?\s*(\S+)")
_BASH_DD_OF_RE = re.compile(r"(?:^|\s)of=(\S+)")


def bash_write_targets(command: str) -> list[str]:
    """Return likely write-target paths from a bash command.

    Best-effort: scans for output redirects (``>``, ``>>``), ``tee``,
    ``cp``, ``mv``, ``ln -sf``, ``install``, and ``dd of=`` targets, plus
    in-place editor flags (``sed -i``, ``perl -i``, ``awk -i inplace``).

    Public so other hooks (notably ``subagent_scope``) can reuse the same
    write-target enumerator instead of duplicating the bash-shape parsing.
    """
    targets: list[str] = []
    targets.extend(_BASH_REDIRECT_RE.findall(command))
    targets.extend(_BASH_DD_OF_RE.findall(command))
    try:
        tokens = shlex.split(command)
    except ValueError:
        return targets
    if not tokens:
        return targets

    # Look for ``tee``, ``cp``, ``mv``, ``ln``, ``install`` anywhere in the
    # token stream — pipelines like ``echo x | tee /path`` mean the head
    # token isn't the writer. We don't try to be exhaustive about flags;
    # just skip past any ``-x``-shaped argument right after the verb.
    write_verbs = {"tee", "cp", "mv", "install", "ln"}
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        if head not in write_verbs:
            continue
        rest = tokens[i + 1 :]
        if head == "tee":
            targets.extend(t for t in rest if not t.startswith("-"))
        elif head in {"cp", "mv", "install"}:
            non_flag = [t for t in rest if not t.startswith("-")]
            if len(non_flag) >= _CP_MV_INSTALL_MIN_OPERANDS:
                targets.append(non_flag[-1])
        elif head == "ln":
            non_flag = [t for t in rest if not t.startswith("-")]
            if non_flag:
                targets.append(non_flag[-1])

    # In-place editors: ``sed -i``, ``perl -i`` / ``-pi`` / ``-Pi``,
    # ``awk -i inplace`` / ``gawk -i inplace``. Each rewrites its file
    # operands without going through redirect / cp shapes.
    targets.extend(_inplace_editor_targets(tokens))

    # Truncators / patchers / archive extractors. Each rewrites or creates
    # files at a path argument that doesn't go through ``>`` / ``cp`` /
    # ``tee`` / in-place editor shapes.
    targets.extend(_truncate_patch_tar_targets(tokens))

    # Ex / vim batch-mode editors: ``ex -sc <cmd> <target>``, ``vim -es ...``.
    # The trailing non-flag positional is the file the script writes back.
    targets.extend(_ex_vim_targets(tokens))

    # Patch via stdin redirect: ``patch < diff``. Read the diff body and
    # extract ``--- a/<path>`` / ``+++ b/<path>`` lines as candidate
    # targets. Best-effort — if the diff isn't readable we skip silently.
    targets.extend(_patch_diff_targets(tokens, command))

    # ``find <root> ... -exec <cmd> ... \;`` — when ``<root>`` itself sits
    # under a protected path, the doctrine path is implicit in ``{}``
    # substitutions invisible to argv inspection. Conservative-but-safe
    # rule: emit ``<root>`` as a candidate target. ``is_protected`` then
    # decides if the whole command should ASK.
    targets.extend(_find_exec_targets(tokens))

    # Per-interpreter eval-flag map: ``python -c '...'``, ``php -r '...'``,
    # etc. Scan the eval-string body for literal protected-pattern
    # substrings (best-effort; dynamically-constructed paths cannot be
    # resolved statically and fall through to the Edit/Write tool guard).
    targets.extend(_interpreter_eval_targets(tokens))
    return targets


def _truncate_patch_tar_targets(tokens: list[str]) -> list[str]:
    """Extract write targets from ``truncate``, ``patch``, and ``tar -x ... -C``."""
    out: list[str] = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        if head == "truncate":
            # ``truncate -s 0 file [file ...]`` — every non-flag positional
            # arg is a write target. Skip the value of ``-s`` / ``--size``.
            out.extend(_positional_args_skipping_value(rest, {"-s", "--size", "-r", "--reference"}))
        elif head == "patch":
            # ``patch <path> [opts...]`` — the first non-flag positional is
            # the file to be patched. Other shapes (``patch -p1 < x.diff``)
            # don't expose a path arg, so we skip them.
            for t in rest:
                if t.startswith("-"):
                    continue
                out.append(t)
                break
        elif head == "tar":
            extract_dir = _tar_extract_dir(rest)
            if extract_dir is not None:
                out.append(extract_dir)
    return out


def _positional_args_skipping_value(tokens: list[str], flags_with_value: set[str]) -> list[str]:
    """Yield non-flag positional args, skipping the value after a ``flags_with_value`` flag."""
    out: list[str] = []
    skip_next = False
    for t in tokens:
        if skip_next:
            skip_next = False
            continue
        if t in flags_with_value:
            skip_next = True
            continue
        if t.startswith("-"):
            # Inline ``--size=0`` etc. — no value to skip
            continue
        out.append(t)
    return out


def _tar_is_extract(tokens: list[str]) -> bool:
    """Return True if ``tar`` arg list indicates extract mode (``x[fz]?`` or ``--extract``).

    Recognises three forms:
    - GNU long: ``--extract`` / ``--get``
    - Short flag(s): ``-x``, ``-xf``, ``-xzf``, ``-xvf`` (any short cluster
      starting with ``-`` and containing ``x``). Mode-bundle clusters that
      do NOT contain ``x`` (``-cf``, ``-czf``, ``-tvf``) are not extract.
    - Legacy bundle (no leading ``-``): the FIRST token is the mode bundle,
      e.g. ``tar xf foo.tar`` or ``tar cz foo.tar``. We inspect only that
      first token; later positional tokens are file/path args.
    """
    if not tokens:
        return False
    first = tokens[0]
    if not first.startswith("-"):
        # Legacy mode bundle.
        return "x" in first
    for tok in tokens:
        if tok in ("-x", "--extract", "--get"):
            return True
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1 and "x" in tok[1:]:
            return True
    return False


def _tar_extract_dir(rest: list[str]) -> str | None:
    """Return the ``-C <dir>`` / ``--directory=<dir>`` target for a ``tar -x...``, else ``None``."""
    if not _tar_is_extract(rest):
        return None
    for i, tok in enumerate(rest):
        if tok in ("-C", "--directory") and i + 1 < len(rest):
            return rest[i + 1]
        if tok.startswith("--directory="):
            return tok[len("--directory=") :]
    return None


def _has_inplace_flag(flags: list[str]) -> bool:
    """Return True if any token in ``flags`` is or contains a ``-i`` form."""
    for f in flags:
        if not f.startswith("-") or f.startswith("--"):
            continue
        # Short-flag cluster like ``-pi``, ``-iE``, ``-i.bak``.
        body = f[1:].split(".", 1)[0]
        if "i" in body:
            return True
    return False


def _inplace_editor_targets(tokens: list[str]) -> list[str]:
    """Extract write targets from ``sed -i`` / ``perl -i`` / ``awk -i inplace``."""
    out: list[str] = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        if head == "sed" and _has_inplace_flag([t for t in rest if t.startswith("-")]):
            out.extend(t for t in rest if not t.startswith("-"))
        elif head == "perl" and _has_inplace_flag([t for t in rest if t.startswith("-")]):
            # perl: skip the `-e <script>` token after the script body
            non_flag = [t for t in rest if not t.startswith("-")]
            if non_flag:
                out.extend(non_flag[1:])  # drop the script body, keep file operands
        elif head in {"awk", "gawk"}:
            # gawk uses ``-i inplace`` (two tokens); skip the script body too
            for j, t in enumerate(rest[:-1]):
                if t == "-i" and rest[j + 1] == "inplace":
                    non_flag = [x for x in rest[j + 2 :] if not x.startswith("-")]
                    if non_flag:
                        out.extend(non_flag[1:])
                    break
    return out


def _ex_vim_targets(tokens: list[str]) -> list[str]:
    """Extract write targets from ``ex -sc <cmd> <target>`` / ``vim -es ...``.

    ``ex`` and ``vim -es`` (silent batch mode) are scriptable editors that
    commit changes via ``:wq`` style commands. The trailing positional
    after the script is the file. Vim variants:

    - ``ex -sc 'wq' /tmp/file``        → ``/tmp/file``
    - ``vim -es -c 'wq' /tmp/file``    → ``/tmp/file``
    - ``vim -es +wq /tmp/file``        → ``/tmp/file``
    - ``vim /tmp/file``                → not extracted (interactive mode;
      no batch script committing)
    """
    out: list[str] = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        if head == "ex":
            # ``ex -sc <cmd> <target>`` — silent batch. Skip flag values.
            out.extend(_ex_positionals(rest))
            continue
        if head in {"vim", "nvim"}:
            # Only treat as write when a batch-mode flag is present:
            # ``-es`` / ``-Es`` / ``-eS`` / ``--script`` / ``--headless``
            # (nvim), or the ``-e -s`` two-token spelling. Bare
            # ``vim <file>`` is interactive and is skipped.
            has_batch_short = any(
                t in {"-es", "-Es", "-eS", "--script", "--headless"} for t in rest
            )
            has_batch_split = "-e" in rest and "-s" in rest
            if not (has_batch_short or has_batch_split):
                continue
            out.extend(_ex_positionals(rest))
    return out


def _ex_positionals(rest: list[str]) -> list[str]:
    """Yield non-flag positional args, skipping the value after a ``-c``/``-S`` flag.

    ``ex -sc 'wq' file`` → after ``-sc`` the next token is the script,
    skipped. ``vim -es -c 'wq' file`` → ``-c <script>`` pair handled.
    ``+wq`` is itself a flag-shaped token (starts with ``+``), so it is
    skipped without consuming a separate value.
    """
    out: list[str] = []
    skip_next = False
    for t in rest:
        if skip_next:
            skip_next = False
            continue
        if t in {"-c", "-S", "--cmd", "-T", "--servername"}:
            skip_next = True
            continue
        if t.startswith(("-", "+")):
            # ``-sc`` is a fused short cluster; ``+wq`` is a vim ex-cmd.
            # Both are non-positional; do not consume.
            continue
        out.append(t)
    return out


_DIFF_PATH_RE = re.compile(r"^[+-]{3}\s+([ab]/)?(\S+)", re.MULTILINE)


def _resolve_diff_path(tokens: list[str], command: str) -> str | None:
    """Locate the diff file from ``-i <diff>`` / ``--input=<diff>`` / ``< <diff>``."""
    for i, tok in enumerate(tokens):
        if tok == "-i" and i + 1 < len(tokens):
            return tokens[i + 1]
        if tok.startswith("--input="):
            return tok[len("--input=") :]
    m = re.search(r"(?:^|\s)<\s*(\S+)", command)
    if m:
        return m.group(1)
    return None


_PATCH_DIFF_MAX_BYTES = 256 * 1024  # 256 KiB cap on diff reads


def _patch_diff_targets(tokens: list[str], command: str) -> list[str]:
    """Extract paths named inside a unified diff fed to ``patch``.

    Three shapes:
    - ``patch -i diff.patch [<target>]`` — diff path is the ``-i`` value.
    - ``patch <target> < diff``         — single-file patch, target is positional.
    - ``patch < diff``                  — diff comes via stdin redirect; multiple targets in body.

    Reads the diff file via ``safe_read_text_capped`` (cwd/temp scope,
    O_NOFOLLOW, sensitive-target denylist, 256 KiB cap) and scans for
    ``--- a/<path>`` / ``+++ b/<path>`` headers. Lines starting with
    ``--- /dev/null`` (the ``a/`` side of an "added" file) are skipped —
    only the destination side names a real target. Best-effort: if the
    diff isn't readable or fails any safety check, returns ``[]``.
    """
    if not any(tok.rsplit("/", 1)[-1] == "patch" for tok in tokens):
        return []
    diff_path = _resolve_diff_path(tokens, command)
    if diff_path is None:
        return []
    diff_text = safe_read_text_capped(
        diff_path,
        cwd=os.getcwd(),  # noqa: PTH109 -- need a string for the safe-IO API
        max_bytes=_PATCH_DIFF_MAX_BYTES,
    )
    if diff_text is None:
        return []
    out: list[str] = []
    for _prefix, path in _DIFF_PATH_RE.findall(diff_text):
        if path in ("/dev/null", "dev/null"):
            continue
        out.append(path)
    return out


_FIND_WRITE_FLAGS: frozenset[str] = frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"})


def _find_exec_targets(tokens: list[str]) -> list[str]:
    r"""Return write targets for ``find <root> -exec ... \;`` and ``-fprint <file>``.

    Two write surfaces:

    - ``-exec`` / ``-execdir``: the doctrine path appears at runtime via
      ``{}`` substitution, not literal text in argv. Conservative rule:
      emit the search root so ``is_protected(<root>)`` decides. ``find
      <root>`` without ``-exec`` is read-only.
    - ``-fprint <file>`` / ``-fprintf <file> <fmt>`` / ``-fls <file>`` /
      ``-fprint0 <file>``: ``find`` writes its own output to ``<file>``,
      truncating it. Emit ``<file>`` directly — the write target is in
      argv and there is no need to fall back to the root.
    """
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        if head != "find":
            continue
        rest = tokens[i + 1 :]
        out: list[str] = []
        # -fprint/-fls/-fprintf <file>: token immediately after the flag is
        # the write target. -fprintf takes <file> THEN <format>, so the
        # file is still the next token (the format is two tokens later).
        for j, flag in enumerate(rest):
            if flag in _FIND_WRITE_FLAGS and j + 1 < len(rest):
                out.append(rest[j + 1])
        if any(t in {"-exec", "-execdir"} for t in rest):
            # Search root: the first non-flag, non-expression token after
            # ``find``. ``find . -name ...`` → ``.``;
            # ``find /etc -exec ...`` → ``/etc``.
            root = next(
                (t for t in rest if not t.startswith("-") and not t.startswith("(")),
                ".",  # ``find -exec ...`` (no explicit root) defaults to cwd
            )
            out.append(root)
        return out
    return []


# Per-interpreter eval-flag map. Each entry is ``(basename_set, flag_set)``.
# When a tokenized command has ``<binary>`` matching the basename set and a
# subsequent token in the flag set, the next token is the eval body.
_INTERPRETER_EVAL_FLAG_MAP: tuple[tuple[frozenset[str], frozenset[str]], ...] = (
    (frozenset({"python", "python3"}), frozenset({"-c"})),
    (frozenset({"node", "nodejs", "deno", "bun"}), frozenset({"-e", "--eval", "-c"})),
    (frozenset({"perl", "ruby"}), frozenset({"-e"})),
    (frozenset({"php"}), frozenset({"-r"})),
)


# Hard cap on the eval-body substring scan. Bodies up to this size are
# scanned end-to-end; beyond it we refuse to scan and instead emit a
# sentinel target so ``protected_files`` falls through to ASK rather
# than silently truncating and missing a literal pattern past the cap.
# 1 MiB covers any realistic inline script; an attacker padding past it
# pays the price of a forced ASK.
_EVAL_BODY_SCAN_MAX_BYTES = 1024 * 1024
# Sentinel target emitted on overflow. Has to literally end with a
# protected pattern so ``is_protected`` fires; ``CLAUDE.md`` is the
# shortest universally-protected suffix.
_EVAL_BODY_OVERFLOW_SENTINEL = "CLAUDE.md"


def _interpreter_eval_targets(tokens: list[str]) -> list[str]:
    """Scan an interpreter's ``-c`` / ``-e`` / ``-r`` eval body for literal protected paths.

    Best-effort static scan: looks for any ``_effective_patterns()`` entry
    appearing as a substring inside the eval body and emits each match
    as a candidate target. ``open('/.git/config','w')`` therefore yields
    ``/.git/config``; ``shutil.copy(src, dst)`` where ``dst`` is a
    runtime variable yields nothing (the static matcher cannot solve
    that — the existing Edit/Write tool gate is the right defense).

    Bodies up to ``_EVAL_BODY_SCAN_MAX_BYTES`` (1 MiB) are scanned
    end-to-end; over that we emit ``_EVAL_BODY_OVERFLOW_SENTINEL`` so
    ``protected_files`` ASKs instead of silently dropping content past
    the cap.
    """
    out: list[str] = []
    patterns = _effective_patterns()
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        # Strip a trailing version suffix to the base interpreter name:
        # ``python3.11`` → ``python``, ``node20`` → ``node``. The base
        # name is what ``_INTERPRETER_EVAL_FLAG_MAP`` keys are matched
        # against, so ``python3.11 -c ...`` is recognised even though
        # ``python3.11`` itself isn't in any binset.
        head_versionless = re.sub(r"^(python|node|deno|bun)[\d.]+$", r"\1", head)
        for binset, flagset in _INTERPRETER_EVAL_FLAG_MAP:
            if head not in binset and head_versionless not in binset:
                continue
            rest = tokens[i + 1 :]
            for j, flag in enumerate(rest):
                if flag in flagset and j + 1 < len(rest):
                    body = rest[j + 1]
                    if len(body) > _EVAL_BODY_SCAN_MAX_BYTES:
                        out.append(_EVAL_BODY_OVERFLOW_SENTINEL)
                    else:
                        out.extend(pat for pat in patterns if pat in body)
                    break
            break
    return out


def _bash_first_protected_match(command: str) -> str | None:
    """Return the first protected pattern matched by a bash write target."""
    for target in bash_write_targets(command):
        matched = is_protected(target)
        if matched is not None:
            return matched

    # Tar extract-dir is a directory write target — check whether it sits
    # anywhere on a protected file's directory chain (an extraction there
    # could overwrite the protected file).
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        if head != "tar":
            continue
        extract_dir = _tar_extract_dir(tokens[i + 1 :])
        if extract_dir is None:
            continue
        matched = is_protected_parent_dir(extract_dir)
        if matched is not None:
            return matched
    return None


def _fallthrough_first_protected_match(tool_input: dict[str, Any]) -> str | None:
    """Scan every path-like token in ``tool_input`` against ``is_protected``.

    Defense-in-depth: any tool we don't have an explicit handler for is run
    through the universal path scanner. If a future tool (or an existing one
    invoked with an unexpected payload shape) targets a protected file, we
    surface ASK rather than miss it.
    """
    for token in all_paths_in(tool_input):
        matched = is_protected(token)
        if matched is not None:
            return matched
    return None


_FILE_PATH_TOOLS: frozenset[str] = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})


def _excerpt_for_fallthrough(tool_input: dict[str, Any]) -> str:
    """Return a short, human-readable excerpt for a fallthrough match."""
    for token in all_paths_in(tool_input):
        return token
    return ""


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    matched: str | None = None
    excerpt = ""

    if tool_name in _FILE_PATH_TOOLS:
        # NotebookEdit uses ``notebook_path``; the others use ``file_path``.
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if not isinstance(file_path, str) or not file_path:
            return
        matched = is_protected(file_path)
        excerpt = file_path
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not command:
            return
        matched = _bash_first_protected_match(command)
        excerpt = command
    else:
        # Defense-in-depth: any other tool shape gets the universal path
        # scanner. Catches shapes we haven't enumerated explicitly (e.g.
        # Glob/Grep with a write semantic, future tools) without us having
        # to keep the matcher list in lockstep with the tool taxonomy.
        matched = _fallthrough_first_protected_match(tool_input)
        if matched is None:
            return
        excerpt = _excerpt_for_fallthrough(tool_input)

    if matched is None:
        return

    cwd_val = payload.get("cwd")
    cwd_str = cwd_val if isinstance(cwd_val, str) else None
    session_id = str(payload.get("session_id", ""))

    # Trust-root protections are NOT allowlist-bypassable: writes to the
    # allowlist itself or to ``.claude/settings*.json`` always go through
    # ASK regardless of any ``disable_rules`` / ``allow_commands`` entry.
    if matched not in _UN_OVERRIDABLE_PATTERNS:
        bypass = hook_bypass_reason(load_allowlist(), _HOOK_ID, excerpt)
        if bypass is not None:
            log_decision(
                hook_id=_HOOK_ID,
                event="PreToolUse",
                tool_name=tool_name,
                decision="pass",
                reason=bypass,
                command_excerpt=excerpt,
                session_id=session_id,
                cwd=cwd_str,
            )
            return

    reason = f"Protected file: {matched} — confirm edit"
    envelope = emit_pretooluse_decision("ask", reason)
    log_decision(
        hook_id=_HOOK_ID,
        event="PreToolUse",
        tool_name=tool_name,
        decision="ask",
        reason=reason,
        command_excerpt=excerpt,
        session_id=session_id,
        cwd=cwd_str,
    )
    sys.stdout.write(json.dumps(envelope))


if __name__ == "__main__":
    safe_main(hook)
