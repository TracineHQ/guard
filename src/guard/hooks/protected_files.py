# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: deny agent writes to guard's trust root.

Matches write-shaped tool calls (``Edit`` / ``Write`` / ``MultiEdit`` /
``NotebookEdit`` paths and Bash write targets) against protected path
patterns. ``guard allowlist`` / ``guard mode`` writes
count as allowlist writes. A match is denied with a reason that tells the
agent to take the change to the user. Other tools never match.

The default list is guard's own trust root: the install these hooks run
from, its allowlist and the subagent scope file. The install is matched by
real path and inode: everything under the ``src/`` directory ``run-hook``
puts first on ``sys.path`` (the package alone for a wheel install), plus
``bin/run-hook`` and ``hooks/hooks.json``. A clone or worktree of guard's
source is ordinary code an agent may edit. ``guard mode lockdown`` adds
git-exec, agent-instruction, MCP and cloud-profile files. Projects add
patterns via ``GUARD_PROTECTED_EXTRA`` and ``.claude/guard-protected.txt``.
``guard mode off`` keeps only the trust root; ``shadow`` logs other matches
without blocking.
"""

from __future__ import annotations

import functools
import itertools
import os
import re
import shlex
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, NamedTuple

from guard._bash_lex import (
    _EXPANSION_LIMIT,
    _expand_word,
    _expanded_substitutions,
    _Heredoc,
    _lex,
    _split_segments,
    _substitute,
    _target_paths,
)
from guard._safe_io import safe_read_text_capped
from guard._utils import emit_pretooluse_decision, safe_main
from guard.allowlist import apply_decision, load_allowlist

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

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
    """Fold ``s`` the way a case-insensitive volume compares names.

    ``casefold`` covers what ``lower`` misses (long s is ``s``, the ``st``
    ligature is ``st``) and NFD matches composed and decomposed accents. Live code is
    compared by inode as well, so this only has to be close for it.
    """
    if not _CASE_INSENSITIVE_FS:
        return s
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", s).casefold())


# Trust-root patterns whose protection MUST NOT be allowlist-bypassable.
# An agent that lands one write to the allowlist file can set
# ``disable_rules: ["guard.protected_files"]`` and silence every later check,
# including checks on the allowlist itself. Other protected files stay
# user-overridable through the normal allowlist mechanisms.
_UN_OVERRIDABLE_PATTERNS: frozenset[str] = frozenset({".claude/guard/allowlist.json"})

# The guard install these hooks are running from, keyed on its real path so
# only the running copy is protected: a clone or worktree of guard's source
# does nothing until someone runs it. ``bin/run-hook`` puts ``<root>/src``
# first on ``sys.path``, so a module dropped anywhere in it can shadow one
# guard imports: the whole directory is live, with the launcher and the
# plugin's hook registrations. A wheel install keys on the package alone.
_LIVE_PACKAGE = Path(__file__).resolve().parents[1]
_SOURCE_LAYOUT = _LIVE_PACKAGE.parent.name == "src"
_LIVE_TREE: tuple[str, ...] = (
    (
        str(_LIVE_PACKAGE.parent),
        str(_LIVE_PACKAGE.parents[1] / "bin" / "run-hook"),
        str(_LIVE_PACKAGE.parents[1] / "hooks" / "hooks.json"),
    )
    if _SOURCE_LAYOUT
    else (str(_LIVE_PACKAGE),)
)
# Directories the unknown part of a path could stand for (``$DIR/_utils.py``).
_LIVE_DIRS: tuple[Path, ...] = (
    (_LIVE_PACKAGE.parent, _LIVE_PACKAGE) if _SOURCE_LAYOUT else (_LIVE_PACKAGE,)
)
# Spellings that name the live tree from inside a path guard can't resolve
# or a script body: ``guard/<an existing child>``, ``src/guard``,
# ``bin/run-hook``, ``hooks/hooks.json``.
_PKG_CHILD_RE = re.compile(rf"(?<![\w.-]){re.escape(_LIVE_PACKAGE.name)}/([\w.-]+)")
_LIVE_ANCHORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    tuple(
        (entry, re.compile(rf"(?<![\w.-]){re.escape(rel)}(?![\w.-])"))
        for entry, rel in zip(
            _LIVE_TREE,
            (f"src/{_LIVE_PACKAGE.name}", "bin/run-hook", "hooks/hooks.json"),
            strict=True,
        )
    )
    if _SOURCE_LAYOUT
    else ()
)

# Guard's own trust root: the install that enforces policy, the allowlist that
# configures it, and the subagent scope file it enforces. Protected in every
# guard mode, ``off`` included: a session that rewrites these while guard is
# off changes what runs when the user turns guard back on.
PROTECTED_PATTERNS: list[str] = [
    *_LIVE_TREE,
    # Subagent scope file: a subagent rewriting its own scope is a TOCTOU
    # bypass of subagent_scope.py.
    ".claude/subagent-scope.json",
    # Compatibility patterns for users who installed earlier hook scripts
    # under ``~/.claude/hooks/`` rather than via the plugin layout.
    ".claude/hooks/command_registry.py",
    ".claude/hooks/bash_command_validator.py",
    ".claude/hooks/git_c_validator.py",
    ".claude/hooks/credential_check.py",
    ".claude/hooks/generate_settings.py",
    ".claude/hooks/_hook_utils.py",
    ".claude/hooks/protected_files.py",
    ".claude/hooks/commit_message_validator.py",
    ".claude/hooks/agent_output_guard.py",
    # Guard's own allowlist file: an agent that can write here grants itself
    # overrides.
    ".claude/guard/allowlist.json",
]

# Added by ``guard mode lockdown``. Writes to these turn a "harmless" file
# edit into code execution or reshape what every later session does, so a
# locked-down machine keeps agents off them entirely.
LOCKDOWN_PATTERNS: list[str] = [
    # Git infrastructure: a write to .git/hooks/ replaces the repo's own
    # hook scripts, which run on every commit/push. .git/config holds
    # exec sinks (core.hooksPath, alias.* w/ !shell). .gitmodules can
    # auto-fetch attacker-controlled submodule URLs whose own hooks fire
    # during init. .git/info/attributes overrides .gitattributes (filter.*
    # exec sinks).
    ".git/hooks",
    ".git/config",
    ".git/info/attributes",
    ".git/info/exclude",
    ".gitmodules",
    ".gitattributes",
    # Agent-config poisoning surface: these reshape future agent behavior
    # across every later session. User-global instructions are listed BEFORE
    # the project-level patterns so the more specific suffix wins the
    # first-match iteration.
    ".claude/CLAUDE.md",
    ".aider.conf.yml.user",
    "CLAUDE.md",
    ".cursorrules",
    ".cursor/rules",
    ".aider.conf.yml",
    ".continue/config.json",
    # MCP server registrations: adding one mounts new tools into the
    # agent's capability surface.
    ".claude/mcp_servers",
    ".claude/mcp.json",
    # Cloud profile selection. ``~/.aws/config`` sets the default profile
    # the agent later assumes; flipping it is a privilege-escalation
    # primitive that bypasses every shell matcher.
    ".aws/config",
]


# === Project-local pattern extension ===
#
# Two override knobs let downstream projects extend the protected list
# without forking. Both are stdlib-only and resolve at call time so test
# fixtures (and live env edits) take effect without a module reload.
#
# 1. ``GUARD_PROTECTED_EXTRA`` env var — comma-separated list of extra
#    patterns. Empty entries are skipped, surrounding whitespace trimmed.
# 2. ``.claude/guard-protected.txt`` file (rooted at cwd) — one pattern
#    per line; ``#`` starts a comment to end of line; blank lines OK.
#
# Both apply when both are present: a repo's file can add to the user's
# env patterns but never drop them. Patterns
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
    """Return the extension patterns: the project file's, then the env var's.

    Resolves at call time. Duplicates are dropped; an empty, corrupt or
    missing ``.claude/guard-protected.txt`` adds nothing and leaves
    ``GUARD_PROTECTED_EXTRA`` in force.
    """
    base = cwd if cwd is not None else Path.cwd()
    found = [*_read_extra_patterns_from_file(base), *_read_extra_patterns_from_env()]
    return list(dict.fromkeys(found))


def _effective_patterns(cwd: Path | None = None, *, mode: str = "enforce") -> tuple[str, ...]:
    """Return the pattern tuple for a guard ``mode``.

    ``off`` keeps only the trust root. ``lockdown`` adds
    ``LOCKDOWN_PATTERNS``. Every mode but ``off`` appends the project
    extras AFTER the built-ins so the first-match iteration in
    ``is_protected()`` favours the built-in suffixes (the trust root first,
    so a trust-root match is never reported as an overridable one).
    """
    if mode == "off":
        return tuple(PROTECTED_PATTERNS)
    lockdown = LOCKDOWN_PATTERNS if mode == "lockdown" else []
    return (*PROTECTED_PATTERNS, *lockdown, *_extra_patterns(cwd))


def _stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except (OSError, ValueError):
        return None


def _resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except (OSError, ValueError, RuntimeError):
        return None


def _exists(path: Path) -> bool:
    return _stat(path) is not None


def _is_file(path: Path) -> bool:
    found = _stat(path)
    return found is not None and stat.S_ISREG(found.st_mode)


def _walk(root: Path) -> list[Path]:
    try:
        return [root, *root.rglob("*")] if root.is_dir() else [root]
    except OSError:
        return [root]


@functools.cache
def _inode_map(entries: tuple[str, ...], scope: str) -> dict[tuple[int, int], str]:
    """Map ``(st_dev, st_ino)`` to the live entry it belongs to.

    ``scope`` is ``"entries"`` (each entry itself), ``"files"`` (everything
    under each entry, to spot a hard link to a live file) or ``"ancestors"``
    (each directory holding an entry).
    """
    ids: dict[tuple[int, int], str] = {}
    for entry in entries:
        root = Path(entry)
        paths: Iterable[Path]
        if scope == "entries":
            paths = (root,)
        elif scope == "ancestors":
            paths = root.parents
        else:
            paths = _walk(root)
        for path in paths:
            found = _stat(path)
            if found is not None:
                ids.setdefault((found.st_dev, found.st_ino), entry)
    return ids


def _live_entry(path: Path, *, ancestors: bool = False) -> str | None:
    """Return the live-tree entry a resolved ``path`` is in, else ``None``.

    Names are compared folded, then inodes: a spelling the volume folds
    (a long s in ``src``) passes through a live directory on the way up, and
    a hard link to a live file shares its inode. With ``ancestors``, a
    directory that holds the live tree matches too (``rm -r``, ``mv``).
    """
    folded = _normcase(str(path))
    for entry in _LIVE_TREE:
        live = _normcase(entry)
        if folded == live or folded.startswith(live + "/"):
            return entry
        if ancestors and live.startswith(folded.rstrip("/") + "/"):
            return entry
    found = _stat(path)
    if found is not None:
        key = (found.st_dev, found.st_ino)
        if ancestors and key in _inode_map(_LIVE_TREE, "ancestors"):
            return _inode_map(_LIVE_TREE, "ancestors")[key]
        if stat.S_ISREG(found.st_mode) and found.st_nlink > 1:
            linked = _inode_map(_LIVE_TREE, "files").get(key)
            if linked is not None:
                return linked
    entries = _inode_map(_LIVE_TREE, "entries")
    for parent in (path, *path.parents):
        found = _stat(parent)
        if found is not None and (found.st_dev, found.st_ino) in entries:
            return entries[found.st_dev, found.st_ino]
    return None


def _has_live(patterns: Sequence[str]) -> bool:
    return any(pattern in _LIVE_TREE for pattern in patterns)


def _pattern_match(resolved_lc: str, patterns: Sequence[str]) -> str | None:
    """Return the first suffix or segment pattern ``resolved_lc`` matches."""
    for pattern in patterns:
        if pattern in _LIVE_TREE:
            continue
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


def is_protected(file_path: str, patterns: Sequence[str] | None = None) -> str | None:
    """Return the matched protected pattern for ``file_path``, else ``None``.

    A pattern matches if ``file_path`` either:
    - is in guard's live tree (an absolute real path; see ``_live_entry``)
    - ends with the pattern (file-pattern match: ``.git/config`` matches
      ``/repo/.git/config``)
    - is contained as a path SEGMENT (directory-pattern match: ``.git/hooks``
      matches ``/repo/.git/hooks/pre-commit``)

    Directory-pattern matching is restricted to patterns whose last segment
    contains no ``.`` — file patterns (``.git/config``, ``.gitattributes``)
    only fire on the suffix form, so a path like ``/tmp/x/.git/config/extra``
    or ``tools/.gitattributes/templates/foo`` does NOT trigger.

    ``patterns`` defaults to the ``enforce`` set (trust root + extras).
    """
    if not file_path:
        return None
    resolved = _resolve(Path(file_path))
    if resolved is None:
        return None
    active = patterns if patterns is not None else _effective_patterns()
    if _has_live(active):
        live = _live_entry(resolved)
        if live is not None:
            return live
    return _pattern_match(_normcase(str(resolved)), active)


def is_protected_parent_dir(dir_path: str, patterns: Sequence[str] | None = None) -> str | None:
    """Return the matched protected pattern when ``dir_path`` is an ancestor.

    Used for write shapes that target a directory rather than a file (e.g.
    ``tar -xf foo.tar -C <dir>``). If any protected pattern's directory
    prefix is a child of ``dir_path``, an extraction into ``dir_path`` could
    overwrite the protected file.
    """
    if not dir_path:
        return None
    resolved = _resolve(Path(dir_path))
    if resolved is None:
        return None
    active = patterns if patterns is not None else _effective_patterns()
    if _has_live(active):
        # Live tree: an extraction into it, or anywhere above it, can overwrite it.
        live = _live_entry(resolved, ancestors=True)
        if live is not None:
            return live

    resolved_lc = _normcase(str(resolved).rstrip("/"))
    for pattern in active:
        if pattern in _LIVE_TREE:
            continue
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


class _Hit(NamedTuple):
    """A protected pattern, and the text in the tool input that matched it."""

    pattern: str
    text: str


# Bash redirect / file-write commands and their target-extracting regex / token
# index. Used by ``bash_write_targets`` as a best-effort second line of
# defense — the primary path is the Edit/Write tool guard above.
_BASH_REDIRECT_RE = re.compile(r"(?:^|[\s&\d])>>?\|?\s*(\S+)")
_BASH_DD_OF_RE = re.compile(r"(?:^|\s)of=(\S+)")


_OPEN_BRACKETS_RE = re.compile(r"^(?:\$?\()+")


def _unbracket(word: str) -> str:
    """Drop an unbalanced bracket glued to a word: ``(cd``, ``$(cp``, ``x)``, a lone backtick."""
    if ")" not in word:
        word = _OPEN_BRACKETS_RE.sub("", word)
    if "(" not in word:
        word = word.rstrip(")")
    if word.count("`") == 1:
        word = word.strip("`")
    return word


def _tokens(segment: str) -> list[str]:
    """Return one command's words, with glued subshell brackets dropped.

    Raises ``ValueError`` on unbalanced quotes, like ``shlex.split``.
    """
    words = (_unbracket(word) for word in shlex.split(segment))
    return [word for word in words if word]


def _split_commands(command: str) -> list[list[str]]:
    """Tokenize ``command`` one command at a time. Raises ``ValueError`` on bad quotes."""
    return [tokens for seg in _split_segments(command) if (tokens := _tokens(seg))]


# A redirect word: the operator, then the target when it's glued on.
_REDIRECT_OP_RE = re.compile(r"^\d*(&>>?|>>?\|?|<<<|<<-?|<>|<&|<)(.*)$")
_FD_DUP_RE = re.compile(r"^&?(?:\d+|-)$")


def _split_redirects(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Split redirect words off ``tokens``: ``(arguments, output targets)``.

    ``cp a b 2>/dev/null`` copies to ``b``, and ``> "x"`` writes ``x``.
    """
    args: list[str] = []
    outs: list[str] = []
    pending = ""
    for tok in tokens:
        if pending:
            if pending == "out" and not _FD_DUP_RE.match(tok):
                outs.append(tok)
            pending = ""
            continue
        match = _REDIRECT_OP_RE.match(tok)
        if match is None:
            args.append(tok)
            continue
        operator, target = match.groups()
        writes = ">" in operator
        if not target:
            pending = "out" if writes else "in"
        elif writes and not _FD_DUP_RE.match(target):
            outs.append(target.removeprefix("&"))
    return args, outs


def _regex_write_targets(text: str) -> list[str]:
    """Redirect and ``dd of=`` targets found in raw text (``x>/path``, ``of=/path``)."""
    found = [*_BASH_REDIRECT_RE.findall(text), *_BASH_DD_OF_RE.findall(text)]
    return [target.strip("'\"") for target in found]


def bash_write_targets(command: str, patterns: Sequence[str] | None = None) -> list[str]:
    """Return likely write-target paths from a bash command.

    Best-effort: scans for output redirects (``>``, ``>>``, ``>|``, ``&>``),
    ``tee``, ``touch``, ``cp``, ``mv``, ``ln -sf``, ``install``, and ``dd
    of=`` targets, plus in-place editor flags (``sed -i``, ``perl -i``,
    ``awk -i inplace``). Each command between control operators is scanned
    on its own.

    ``patterns`` is the protected list the interpreter-eval scan looks for
    (defaults to the ``enforce`` set).

    Public so other hooks (notably ``subagent_scope``) can reuse the same
    write-target enumerator instead of duplicating the bash-shape parsing.
    """
    try:
        commands = [(seg, _tokens(seg)) for seg in _split_segments(command)]
    except ValueError:
        return _regex_write_targets(command)
    targets: list[str] = []
    for segment, tokens in commands:
        targets.extend(_regex_write_targets(segment))
        targets.extend(_command_write_targets(tokens, segment))
        targets.extend(hit.pattern for hit in _interpreter_eval_targets(tokens, patterns))
    return targets


def _command_write_targets(tokens: list[str], command: str) -> list[str]:
    """Write targets for one command's tokens (no control operators inside).

    An interpreter's eval body is scanned on its own
    (``_interpreter_eval_targets``).
    """
    tokens, targets = _split_redirects(tokens)

    # Look for ``tee``, ``cp``, ``mv``, ``ln``, ``install`` anywhere in the
    # command: wrappers like ``sudo tee /path`` mean the head token isn't
    # the writer. We don't try to be exhaustive about flags;
    # just skip past any ``-x``-shaped argument right after the verb.
    write_verbs = {"tee", "touch", "cp", "mv", "install", "ln"}
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        if head not in write_verbs:
            continue
        rest = tokens[i + 1 :]
        if head in {"tee", "touch"}:
            targets.extend(t for t in rest if not t.startswith("-"))
        elif head in {"cp", "mv", "install"}:
            dest, _ = _dest_and_sources(rest)
            if dest is not None:
                targets.append(dest)
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
    # decides if the whole command is denied.
    targets.extend(_find_exec_targets(tokens))
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
_FIND_EXEC_FLAGS: frozenset[str] = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
# Programs that only read the files find hands them.
_FIND_READ_ONLY: frozenset[str] = frozenset(
    {"basename", "cat", "cmp", "diff", "dirname", "du", "echo", "egrep", "false", "fgrep"}
    | {"file", "grep", "head", "hexdump", "jq", "ls", "md5", "md5sum", "od", "printf"}
    | {"readlink", "realpath", "rg", "sha1sum", "sha256sum", "shasum", "sort", "stat"}
    | {"strings", "tail", "test", "true", "uniq", "wc", "xxd"}
)


def _find_exec_targets(tokens: list[str]) -> list[str]:
    r"""Return write targets for ``find <root> -exec ... \;`` and ``-fprint <file>``.

    Two write surfaces:

    - ``-exec`` / ``-execdir`` / ``-ok`` / ``-okdir`` / ``-delete``: the
      doctrine path appears at runtime via ``{}`` substitution, not literal
      text in argv. Conservative rule: emit the search root so
      ``is_protected(<root>)`` decides. ``find <root>`` without them, or
      with only read-only programs after ``-exec``, is read-only.
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
        runs = [
            rest[j + 1].rsplit("/", 1)[-1] for j, t in enumerate(rest[:-1]) if t in _FIND_EXEC_FLAGS
        ]
        if "-delete" in rest or any(r not in _FIND_READ_ONLY for r in runs):
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
# sentinel target so ``protected_files`` denies rather than silently
# truncating and missing a literal pattern past the cap. 1 MiB covers any
# realistic inline script; an attacker padding past it gets a deny.
_EVAL_BODY_SCAN_MAX_BYTES = 1024 * 1024
# Sentinel target emitted on overflow. Has to be a trust-root path so
# ``is_protected`` fires in every guard mode.
_EVAL_BODY_OVERFLOW_SENTINEL = str(_LIVE_PACKAGE / "_utils.py")

# An eval body that only reads (``print(open('CLAUDE.md').read())``) is not a
# write. A protected path in the body counts only next to something that could
# write: a write/append open mode, a write/delete/move call, a shell-out, or
# code built at runtime. Plain substring match, so it fails closed.
_EVAL_WRITE_INTENT_RE = re.compile(
    r"['\"][rbt]*[wax+][rbt+]*['\"]|>|write|append|unlink|remove|rename|replace|rmtree|copy|"
    r"move|touch|truncate|symlink|chmod|O_(?:WRONLY|RDWR|CREAT)|system|exec|spawn|popen|"
    r"subprocess|eval|compile|__import__|FileUtils|`|delete|put_contents|\+<|\b(?:cp|rm)(?:Sync)?\b"
)


def _eval_body_targets(body: str, active: Sequence[str], dirs: Sequence[Path]) -> list[_Hit]:
    """Protected patterns a write-shaped interpreter body names, with the text naming each."""
    if len(body) > _EVAL_BODY_SCAN_MAX_BYTES:
        return [_Hit(_EVAL_BODY_OVERFLOW_SENTINEL, "")]
    if not _EVAL_WRITE_INTENT_RE.search(body):
        return []
    out = [_Hit(pat, pat) for pat in active if pat not in _LIVE_TREE and pat in body]
    live = _text_names_live(body, dirs) if _has_live(active) else None
    return out if live is None else [*out, live]


def _interpreter_eval_targets(
    tokens: list[str],
    patterns: Sequence[str] | None = None,
    dirs: Sequence[Path] | None = None,
) -> list[_Hit]:
    """Scan an interpreter's ``-c`` / ``-e`` / ``-r`` eval body for literal protected paths.

    Best-effort static scan. When the body shows write intent
    (``_EVAL_WRITE_INTENT_RE``), every protected pattern appearing as a
    substring is emitted as a candidate target, so
    ``open('/.git/config','w')`` yields ``.git/config``. Guard's live tree
    counts when a path in the body resolves into it, or when a fragment
    code could join onto anything (``'/guard/_utils.py'``) names a live
    file or spells the tree package-relative. A read-only body yields
    nothing. ``shutil.copy(src, dst)``
    where ``dst`` is a runtime variable yields nothing either (the static
    matcher cannot solve that; the Edit/Write tool gate is the right
    defense).

    Bodies up to ``_EVAL_BODY_SCAN_MAX_BYTES`` (1 MiB) are scanned
    end-to-end; over that we emit ``_EVAL_BODY_OVERFLOW_SENTINEL`` so
    ``protected_files`` denies instead of silently dropping content past
    the cap.

    Each target comes with the body text that named it, for the deny reason.
    """
    out: list[_Hit] = []
    active = patterns if patterns is not None else _effective_patterns()
    where = list(dirs) if dirs else [Path.cwd()]
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
                    out.extend(_eval_body_targets(rest[j + 1], active, where))
                    break
            break
    return out


# ``guard allowlist <verb>`` and ``guard mode <mode>`` rewrite the allowlist
# through guard's own CLI, so they count as a write to it. ``allow-command``
# and ``remove-command`` are retired, but an older guard on PATH still has them.
_GUARD_ALLOWLIST_FILE = ".claude/guard/allowlist.json"
_GUARD_ALLOWLIST_WRITES: frozenset[str] = frozenset(
    {"disable-rule", "enable-rule", "allow-command", "remove-command"}
)


# A redirect token: ``2>&1``, ``>out``, ``>>``, ``<in``, ``&>log``. A bare
# operator (empty group 1) takes the next token as its target.
_REDIRECT_TOKEN_RE = re.compile(r"^\d*(?:&>>?|>>?|<)(.*)$")


def _guard_cli_args(rest: list[str]) -> list[str]:
    """Positional arguments after ``guard``, with flags and redirects dropped."""
    args: list[str] = []
    skip_target = False
    for tok in rest:
        if skip_target:
            skip_target = False
            continue
        redirect = _REDIRECT_TOKEN_RE.match(tok)
        if redirect is not None:
            skip_target = not redirect.group(1)
            continue
        if not tok.startswith("-"):
            args.append(tok)
    return args


def _guard_cli_writes_allowlist(tokens: list[str]) -> bool:
    """Return True for a ``guard allowlist <write>`` or ``guard mode <mode>`` command.

    ``--help`` / ``-h`` only prints usage, and a redirect such as ``2>&1`` is
    not an argument, so ``guard mode --help 2>&1`` stays a read.
    """
    for i, tok in enumerate(tokens):
        if tok.rsplit("/", 1)[-1] != "guard":
            continue
        rest = tokens[i + 1 :]
        if any(t in {"-h", "--help"} for t in rest):
            return False
        args = _guard_cli_args(rest)
        if args[:1] == ["allowlist"]:
            return len(args) > 1 and args[1] in _GUARD_ALLOWLIST_WRITES
        if args[:1] == ["mode"]:
            return len(args) > 1
    return False


# === Matching what a word can name against the trust root ===


def _normalize_tail(tail: Sequence[str]) -> list[str]:
    """Drop ``.`` and empty parts; a leading ``..`` folds into the unknown part."""
    parts: list[str] = []
    for part in tail:
        if part == "..":
            if parts:
                parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    return parts


def _anchor_names_live(text: str) -> str | None:
    """Return the live entry ``text`` spells package-relative, else ``None``."""
    folded = _normcase(text)
    for match in _PKG_CHILD_RE.finditer(folded):
        child = match.group(1)
        if child not in {".", ".."} and _exists(_LIVE_PACKAGE / child):
            return _LIVE_TREE[0]
    return next((entry for entry, anchor in _LIVE_ANCHORS if anchor.search(folded)), None)


def _tail_names_live(tail: Sequence[str]) -> str | None:
    """Return the live entry a tail could be in, whatever its unknown part is.

    It counts when it is a file right under a live directory (the unknown
    part could be that directory) or spells the tree package-relative.
    Generic names (``__init__.py``, ``__pycache__``, a directory) don't
    count on their own: every Python package has them.
    """
    parts = _normalize_tail(tail)
    if not parts:
        return None
    if not parts[-1].startswith("__") and any(
        _is_file(root.joinpath(*parts)) for root in _LIVE_DIRS
    ):
        return _LIVE_TREE[0]
    return _anchor_names_live("/" + "/".join(parts))


def _tail_match(tail: Sequence[str], patterns: Sequence[str], *, live_only: bool) -> str | None:
    """Match a tail against the live tree, then (unless ``live_only``) the patterns.

    A trust-root pattern also matches when the tail is its end
    (``$DIR/allowlist.json``), since the unknown part could supply the rest.
    """
    parts = _normalize_tail(tail)
    if not parts:
        return None
    if _has_live(patterns):
        live = _tail_names_live(parts)
        if live is not None:
            return live
    if live_only:
        return None
    joined = _normcase("/" + "/".join(parts))
    matched = _pattern_match(joined, patterns)
    if matched is not None:
        return matched
    folded = joined.split("/")[1:]
    return next(
        (
            p
            for p in patterns
            if p in PROTECTED_PATTERNS
            and p not in _LIVE_TREE
            and _normcase(p).split("/")[-len(folded) :] == folded
        ),
        None,
    )


_WORD_RE = re.compile(r"[^\s'\"`;&|()<>,=]+")


# Calls in a script body that write a whole directory, not just a file.
_TREE_WRITE_RE = re.compile(
    r"rmtree|copytree|rmdir|removedirs|rename|move|rmSync|cpSync|rm_r|cp_r|\bmv\b|\brm\s+-"
)


def _word_names_live(word: str, dirs: Sequence[Path], *, whole_dirs: bool) -> str | None:
    """Return the live entry one script word can name.

    A word that resolves is checked as a path; one naming a live directory
    counts only with ``whole_dirs`` (``sys.path.insert(0, '<src>')`` is a
    read). A word with an unknown part, or an absolute-looking fragment
    such as ``/guard/_utils.py`` (code can join it onto anything), is
    checked as a tail.
    """
    where = _target_paths(word, dirs, cd_unknown=False)
    tails = where.tails
    for path in where.paths:
        resolved = _resolve(path)
        if resolved is None:
            continue
        live = _live_entry(resolved)
        if live is not None and (whole_dirs or not resolved.is_dir()):
            return live
    expanded = _expand_word(word)
    if expanded.startswith("/") and not _exists(Path("/", expanded.split("/")[1])):
        tails.append(expanded.split("/")[1:])
    return next((live for tail in tails if (live := _tail_names_live(tail)) is not None), None)


def _text_names_live(text: str, dirs: Sequence[Path], *, strict: bool = False) -> _Hit | None:
    """Return the live entry a script body or unparsed text names, and the word naming it.

    Every path-like word is checked (``_word_names_live``); bare words only
    from inside the live tree, where they resolve into it. A live directory
    counts when the text could write a whole tree, or when ``strict``.
    """
    inside = any(
        resolved is not None and _live_entry(resolved) is not None
        for resolved in map(_resolve, dirs)
    )
    whole_dirs = strict or bool(_TREE_WRITE_RE.search(text))
    for word in dict.fromkeys(_WORD_RE.findall(text)):
        if inside or "/" in word or word.startswith("~"):
            live = _word_names_live(word, dirs, whole_dirs=whole_dirs)
            if live is not None:
                return _Hit(live, word)
    return None


def _text_match(text: str, patterns: Sequence[str], dirs: Sequence[Path]) -> _Hit | None:
    """Return a trust-root pattern ``text`` names anywhere (fail closed)."""
    if _has_live(patterns):
        live = _text_names_live(text, dirs, strict=True)
        if live is not None:
            return live
    folded = _normcase(text)
    return next(
        (
            _Hit(p, p)
            for p in patterns
            if p in PROTECTED_PATTERNS and p not in _LIVE_TREE and _normcase(p) in folded
        ),
        None,
    )


# === Commands a bash command moves to, removes or hands on ===

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "su"})
_REMOVERS = frozenset({"rm", "rmdir", "unlink", "shred", "srm", "mv", "link"})
# Words that run the next word as a command (``sudo rm``, ``git mv``), with
# the flags of each that take a value (``sudo -u root rm``).
_PREFIX_WORDS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "--chdir", "--unset"}),
    "nice": frozenset({"-n"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "xargs": frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "git": frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"}),
    **dict.fromkeys(
        ("command", "builtin", "exec", "nohup", "time", "caffeinate"), frozenset[str]()
    ),
}
# Flags that run a command from another directory (``git -C``, ``env -C``).
_CHDIR_FLAGS = frozenset({"-C", "--chdir"})
_LEAD_WORDS = frozenset({"{", "!", "if", "then", "else", "elif", "do", "while", "until"})
_ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*=")
_MAX_PAYLOAD_DEPTH = 4


def _short_flag_has(token: str, letter: str) -> bool:
    return token.startswith("-") and not token.startswith("--") and letter in token[1:]


_DECLARE_WORDS = frozenset({"export", "declare", "local", "readonly", "typeset"})


def _assignments(tokens: list[str]) -> list[tuple[str, list[str]]]:
    """Return the variables a command sets and the words each can hold.

    ``X=v`` before the command or after ``export`` and the like, and the
    words of ``for X in ...``.
    """
    if len(tokens) > 2 and tokens[0] == "for" and tokens[2] == "in":  # noqa: PLR2004 -- for X in
        return [(tokens[1], tokens[3:])]
    found: list[tuple[str, list[str]]] = []
    for tok in tokens:
        if _ASSIGN_RE.match(tok):
            name, _, value = tok.partition("=")
            found.append((name, [value]))
        elif not (tok in _DECLARE_WORDS or tok in _LEAD_WORDS or tok.startswith("-")):
            break
    return found


def _record_assignments(tokens: list[str], env: dict[str, list[str]]) -> None:
    """Add what ``tokens`` assign to ``env``, keeping earlier values too (branches)."""
    for name, words in _assignments(tokens):
        values = [v for word in words for v in _substitute(word, env)]
        env[name] = list(dict.fromkeys([*env.get(name, []), *values]))[:_EXPANSION_LIMIT]


def _cd_moves(
    tokens: list[str], dirs: Sequence[Path], env: Mapping[str, Sequence[str]] | None = None
) -> tuple[list[Path], bool]:
    """Return where a ``cd``/``pushd`` in ``tokens`` can move, and whether one is unknown.

    ``git -C <dir>`` and ``env -C <dir>`` count too: the command they run
    resolves relative paths there.
    """
    moved: list[Path] = []
    lost = False
    for i, tok in enumerate(tokens):
        lost = lost or tok == "popd"
        arg: str | None
        if tok.startswith("--chdir="):
            arg = tok.partition("=")[2]
        elif tok in _CHDIR_FLAGS:
            arg = tokens[i + 1] if i + 1 < len(tokens) else ""
        elif tok in {"cd", "pushd"}:
            arg = next((t for t in tokens[i + 1 :] if t == "-" or not t.startswith("-")), None)
        else:
            continue
        if arg is None:
            moved.append(Path.home())
            continue
        where = _target_paths(arg, dirs, cd_unknown=False, env=env)
        moved.extend(where.paths)
        lost = lost or bool(where.tails) or arg == "-" or arg.startswith("+")
    return moved, lost


def _shell_payloads(tokens: list[str]) -> list[str]:
    """Return the command strings ``tokens`` hand to a shell (``bash -c '...'``, ``eval``)."""
    payloads: list[str] = []
    for i, tok in enumerate(tokens):
        head = tok.rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        if head == "eval":
            payloads.append(" ".join(rest))
            continue
        if head not in _SHELLS:
            continue
        flag = next((j for j, t in enumerate(rest) if _short_flag_has(t, "c")), None)
        if flag is not None:
            payloads.extend(itertools.islice((t for t in rest[flag + 1 :] if t[:1] != "-"), 1))
    return payloads


def _head_indices(tokens: list[str]) -> list[int]:
    """Return the indexes of words in command position (``rm`` in ``sudo -n rm x``)."""
    heads: list[int] = []
    i = 0
    while i < len(tokens):
        if tokens[i] in _LEAD_WORDS or _ASSIGN_RE.match(tokens[i]):
            i += 1
            continue
        heads.append(i)
        takes_value = _PREFIX_WORDS.get(tokens[i].rsplit("/", 1)[-1])
        if takes_value is None:
            break
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or tokens[i][:1].isdigit()):
            i += 2 if tokens[i] in takes_value else 1
    return heads


def _dest_and_sources(rest: list[str]) -> tuple[str | None, list[str]]:
    """Return the destination and sources of a ``cp``/``mv``/``install``."""
    for j, tok in enumerate(rest):
        if tok in {"-t", "--target-directory"} and j + 1 < len(rest):
            others = rest[:j] + rest[j + 2 :]
            return rest[j + 1], [t for t in others if not t.startswith("-")]
        if tok.startswith("--target-directory="):
            return tok.partition("=")[2], [t for t in rest if not t.startswith("-")]
    operands = [t for t in rest if not t.startswith("-")]
    if len(operands) < _CP_MV_INSTALL_MIN_OPERANDS:
        return None, []
    return operands[-1], operands[:-1]


def _copy_into_targets(tokens: list[str]) -> list[str]:
    """Return where a ``cp``/``mv``/``install`` lands if its destination is a directory.

    ``cp a b dir/`` writes ``dir/a`` and ``dir/b``; ``cp -r x/guard src/``
    writes ``src/guard``.
    """
    out: list[str] = []
    for i in _head_indices(tokens):
        if tokens[i].rsplit("/", 1)[-1] in {"cp", "mv", "install"}:
            dest, sources = _dest_and_sources(tokens[i + 1 :])
            base = (dest or "").rstrip("/") or "/"
            out.extend(f"{base}/{PurePosixPath(s.rstrip('/')).name}" for s in sources)
    return out


def _tree_targets(tokens: list[str]) -> list[str]:
    """Return paths a command removes, moves away, or hard-links.

    These count when they are in the live tree or hold it: ``rm -r`` or
    ``mv`` of a directory above it removes it, and a hard link shares a live
    file's inode.
    """
    out: list[str] = []
    for i in _head_indices(tokens):
        head = tokens[i].rsplit("/", 1)[-1]
        rest = tokens[i + 1 :]
        operands = [t for t in rest if not t.startswith("-")]
        flags = [t for t in rest if t.startswith("-")]
        symbolic = any(t == "--symbolic" or _short_flag_has(t, "s") for t in flags)
        hard_copy = any(t == "--link" or _short_flag_has(t, "l") for t in flags)
        if head in _REMOVERS or (head == "ln" and not symbolic) or (head == "cp" and hard_copy):
            out.extend(operands)
    return out


def _tar_extract_dirs(tokens: list[str]) -> list[str]:
    return [
        found
        for i, tok in enumerate(tokens)
        if tok.rsplit("/", 1)[-1] == "tar" and (found := _tar_extract_dir(tokens[i + 1 :]))
    ]


@dataclass
class _Scan:
    """What a bash scan knows so far.

    ``dirs`` are the directories the command may be in: where it started,
    plus every directory a literal ``cd`` or ``pushd`` can move it to.
    ``cd_unknown`` is set once a ``cd`` goes somewhere guard can't follow.
    ``env`` holds the variables the command has set so far.
    """

    patterns: Sequence[str]
    dirs: list[Path]
    cd_unknown: bool = False
    depth: int = 0
    env: dict[str, list[str]] = field(default_factory=dict)

    def nested(self) -> _Scan:
        """Return the scan for a command this one hands to a shell."""
        return _Scan(self.patterns, [*self.dirs], self.cd_unknown, self.depth + 1, {**self.env})


def _under_match(where: Path, patterns: Sequence[str], *, named: bool) -> str | None:
    """Return the trust root a name guard can't know, starting at ``where``, could reach.

    That is any name inside the live tree, one right beside a live entry
    when the command named that directory (``<checkout>/$X`` could be
    ``src``), or a trust-root file's name in its own directory.
    """
    resolved = _resolve(where)
    if resolved is None:
        return None
    if _has_live(patterns):
        folded = _normcase(str(resolved))
        beside = (e for e in _LIVE_TREE if named and _normcase(str(Path(e).parent)) == folded)
        live = _live_entry(resolved) or next(beside, None)
        if live is not None:
            return live
    roots = (p for p in patterns if p in PROTECTED_PATTERNS and p not in _LIVE_TREE)
    return next(
        (m for p in roots if (m := is_protected(str(resolved / PurePosixPath(p).name), patterns))),
        None,
    )


def _target_match(target: str, scan: _Scan, kind: str) -> str | None:
    """Match one target: ``kind`` is ``file``, ``dir`` (tar -C) or ``tree``."""
    where = _target_paths(target, scan.dirs, cd_unknown=scan.cd_unknown, env=scan.env)
    for under, named in where.under:
        matched = _under_match(under, scan.patterns, named=named)
        if matched is not None:
            return matched
    tails = where.tails
    for path in where.paths:
        if kind == "file":
            matched = is_protected(str(path), scan.patterns)
        elif kind == "dir":
            matched = is_protected_parent_dir(str(path), scan.patterns)
        else:
            resolved = _resolve(path)
            matched = None if resolved is None else _live_entry(resolved, ancestors=True)
        if matched is not None:
            return matched
    for tail in tails:
        matched = _tail_match(tail, scan.patterns, live_only=kind != "file")
        if matched is not None:
            return matched
    return None


def _segment_targets(
    segment: str, tokens: list[str], scan: _Scan
) -> Iterator[tuple[str, str, str]]:
    """Yield ``(target, kind, text)``: ``text`` is what the command says for it."""
    for target in _regex_write_targets(segment):
        yield target, "file", target
    for target in _command_write_targets(tokens, segment):
        yield target, "file", target
    # Interpreter bodies: ``python -c '...'``, ``php -r '...'``, etc.
    for target, text in _interpreter_eval_targets(tokens, scan.patterns, scan.dirs):
        yield target, "file", text
    # An extraction anywhere on a protected file's directory chain could
    # overwrite it.
    for target in _tar_extract_dirs(tokens):
        yield target, "dir", target
    args = _split_redirects(tokens)[0]
    copied_into = _copy_into_targets(args)
    for target in copied_into:
        yield target, "file", target
    # Removing, moving or copying over a directory that holds the live tree
    # reaches it too.
    if _has_live(scan.patterns):
        for target in (*_tree_targets(args), *copied_into):
            yield target, "tree", target


def _segment_match(segment: str, tokens: list[str], scan: _Scan) -> _Hit | None:
    """Return the first protected pattern one command writes, else ``None``."""
    if _guard_cli_writes_allowlist(tokens):
        return _Hit(_GUARD_ALLOWLIST_FILE, _GUARD_ALLOWLIST_FILE)
    for target, kind, text in _segment_targets(segment, tokens, scan):
        matched = _target_match(target, scan, kind)
        if matched is not None:
            return _Hit(matched, text)
    for payload in _shell_payloads(tokens):
        hit = _scan_command(payload, scan.nested())
        if hit is not None:
            return hit
    return None


# Readers whose heredoc is commands, and those whose heredoc is a program.
_SHELL_READER_RE = re.compile(r"(?<![\w.-])(?:bash|zsh|dash|ksh|sh|su|ssh|source)(?![\w.-])")
_PROGRAM_READER_RE = re.compile(
    r"(?<![\w.-])(?:python[\d.]*|node(?:js)?|deno|bun|perl|ruby|php|osascript)(?![\w.-])"
)


def _heredoc_match(heredoc: _Heredoc, scan: _Scan) -> _Hit | None:
    """Match a heredoc by what reads it.

    A shell runs it as commands, an interpreter as a program; anything else
    reads data, where only an unquoted body's substitutions run.
    """
    if _SHELL_READER_RE.search(heredoc.line):
        return _scan_command(heredoc.body, scan.nested())
    if _PROGRAM_READER_RE.search(heredoc.line):
        targets = _eval_body_targets(heredoc.body, scan.patterns, scan.dirs)
        return next(
            (_Hit(m, text) for t, text in targets if (m := _target_match(t, scan, "file"))), None
        )
    if heredoc.quoted:
        return None
    for inner in _expanded_substitutions(heredoc.body):
        hit = _scan_command(inner, scan.nested())
        if hit is not None:
            return hit
    return None


def _loose_tokens(segment: str) -> list[str]:
    """Words of a segment ``shlex`` can't split, quotes dropped."""
    return [w for w in (_unbracket(x.strip("'\"")) for x in segment.split()) if w]


def _scan_segments(flat: str, scan: _Scan) -> _Hit | None:
    for segment in _split_segments(flat):
        try:
            tokens = _tokens(segment)
        except ValueError:
            tokens = _loose_tokens(segment)
        _record_assignments(tokens, scan.env)
        moved, lost = _cd_moves(tokens, scan.dirs, scan.env)
        scan.dirs.extend(moved)
        scan.cd_unknown = scan.cd_unknown or lost
        hit = _segment_match(segment, tokens, scan)
        if hit is not None:
            return hit
    return None


def _scan_command(command: str, scan: _Scan) -> _Hit | None:
    """Return the first protected pattern ``command`` writes and the text naming it.

    Commands handed to another shell (``bash -c``, ``eval``, ``$(...)``,
    backticks, a heredoc a shell reads) are scanned the same way, from every
    directory the outer command can reach. When guard can't be sure it read
    the command as bash will (``_bash_lex._Lexed.unknown``), or past
    ``_MAX_PAYLOAD_DEPTH`` levels, any trust-root path the text names denies.
    """
    if scan.depth > _MAX_PAYLOAD_DEPTH:
        return _text_match(command, scan.patterns, scan.dirs)
    lexed = _lex(command)
    if lexed.unknown:
        matched = _text_match(command, scan.patterns, scan.dirs) or _text_match(
            lexed.flat, scan.patterns, scan.dirs
        )
        if matched is not None:
            return matched
    matched = _scan_segments(lexed.flat, scan)
    if matched is not None:
        return matched
    for body in lexed.bodies:
        matched = _scan_command(body, scan.nested())
        if matched is not None:
            return matched
    return next(
        (m for heredoc in lexed.heredocs if (m := _heredoc_match(heredoc, scan)) is not None),
        None,
    )


def _bash_first_protected_match(
    command: str, patterns: Sequence[str], dirs: Sequence[Path] = ()
) -> _Hit | None:
    """Return the first protected pattern a bash command writes and the text naming it.

    ``dirs`` are the directories the command may start in (the working
    directory by default).
    """
    return _scan_command(command, _Scan(patterns, [*dirs] or [Path.cwd()]))


_FILE_PATH_TOOLS: frozenset[str] = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})


def _match_for_tool(
    tool_name: str, tool_input: dict[str, Any], patterns: Sequence[str], cwd: object = None
) -> tuple[_Hit | None, str]:
    """Return ``(hit, excerpt)`` for the given Claude Code tool payload.

    Pure: no allowlist consultation. ``hit`` is ``None`` when nothing
    protected is written; ``excerpt`` is the human-readable string used in
    audit-log records.

    * ``Write`` / ``Edit`` / ``MultiEdit`` / ``NotebookEdit``: run
      ``is_protected`` on the ``file_path`` (or ``notebook_path``).
    * ``Bash``: extract write targets from the command. Relative ones
      resolve against the hook's directory and the payload's ``cwd``.
    * Everything else (``Read``, ``Grep``, ``Agent``, ``AskUserQuestion``,
      ...) never writes a file itself, so naming a protected path is fine.
    """
    if tool_name in _FILE_PATH_TOOLS:
        # NotebookEdit uses ``notebook_path``; the others use ``file_path``.
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        target = target if isinstance(target, str) else ""
        matched = is_protected(target, patterns)
        return (None if matched is None else _Hit(matched, target)), target
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        command = command if isinstance(command, str) else ""
        dirs = [Path.cwd()]
        if isinstance(cwd, str) and cwd.startswith("/"):
            dirs.append(Path(cwd))
        return _bash_first_protected_match(command, patterns, dirs), command
    return None, ""


_TELL_THE_USER = "Don't retry or route around it. Tell the user what you want to change and why"


def deny_reason(matched: str, text: str = "") -> str:
    """Return the steering deny reason for a protected-pattern match.

    ``text`` is what the tool input said that matched, named when it isn't
    the pattern itself.
    """
    named = f"{matched}, matched by `{text}`" if text and text != matched else matched
    if matched in _UN_OVERRIDABLE_PATTERNS:
        return (
            f"Protected file: {named}. The allowlist decides what guard lets "
            "through, so agents never change it, by editing the file or by "
            f"running `guard allowlist` or `guard mode`. {_TELL_THE_USER}; they "
            "can run the guard command themselves with `! guard ...`."
        )
    if matched in PROTECTED_PATTERNS:
        return (
            f"Protected path: {named}. guard blocks agent writes to the install it "
            "is running from and to the subagent scope file, so a session can't rewrite "
            f"its own guardrails. {_TELL_THE_USER}; they can make the edit."
        )
    if matched in LOCKDOWN_PATTERNS:
        return (
            f"Protected file: {named} (guard lockdown). Lockdown keeps agents off "
            "git hooks and config, agent instruction files, MCP registrations and "
            f"cloud profiles. {_TELL_THE_USER}; they can make the edit, or leave "
            "lockdown with `guard mode enforce`."
        )
    return (
        f"Protected file: {named} (project protected list). {_TELL_THE_USER}; "
        "they can make the edit."
    )


def decide(
    tool_name: str, tool_input: dict[str, Any], *, lockdown: bool = False
) -> dict[str, Any] | None:
    """Return a steering ``deny`` envelope when a protected path is written.

    Pure decision logic for the registry adapter (``guard test``): no
    logging, no allowlist, ``enforce`` patterns unless ``lockdown``.
    ``hook()`` shares ``_match_for_tool`` so the two can't drift.
    """
    patterns = _effective_patterns(mode="lockdown" if lockdown else "enforce")
    hit, _ = _match_for_tool(tool_name, tool_input, patterns)
    if hit is None:
        return None
    return emit_pretooluse_decision("deny", deny_reason(*hit))


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        return
    patterns = _effective_patterns(mode=load_allowlist().mode)
    hit, excerpt = _match_for_tool(tool_name, tool_input, patterns, payload.get("cwd"))
    if hit is None:
        return
    apply_decision(
        _HOOK_ID,
        payload,
        emit_pretooluse_decision("deny", deny_reason(*hit)),
        excerpt,
        trust_root=hit.pattern in PROTECTED_PATTERNS,
        overridable=hit.pattern not in _UN_OVERRIDABLE_PATTERNS,
    )


if __name__ == "__main__":
    safe_main(hook)
