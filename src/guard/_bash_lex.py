# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Read a bash command the way bash does, and expand its words to paths.

Shared lexing for the hooks: quote state (including ``$'...'``), comments,
command separators, substitution bodies, heredocs, line continuations, and
the expansion of a word (``~``, environment and in-command variables, brace
lists, globs) to the paths it can name. Nothing here decides anything.
"""

from __future__ import annotations

import contextlib
import glob
import itertools
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


# Characters that end a word, and those a comment's ``#`` can follow. After
# ``)`` or a redirect bash may still be in a word (``$(x)#``), so those
# leave the ``#`` as text: reading too much can't hide a command.
_WORD_BREAKS = frozenset(" \t\n;&|()<>")
_COMMENT_AFTER = frozenset(" \t\n;&|(")


def _escaped(text: str, i: int) -> bool:
    """Return whether a backslash escapes ``text[i]`` (an odd run of them before it)."""
    j = i
    while j > 0 and text[j - 1] == "\\":
        j -= 1
    return (i - j) % 2 == 1


def _starts_comment(text: str, i: int) -> bool:
    return text[i] == "#" and (
        i == 0 or (text[i - 1] in _COMMENT_AFTER and not _escaped(text, i - 1))
    )


def _step(text: str, i: int, quote: str) -> tuple[int, str]:
    """Move past ``text[i]`` as bash reads it: return the next index and quote state.

    ``quote`` is ``""``, ``"'"``, ``'"'`` or ``"$'"`` (where a backslash
    escapes, unlike in ``'...'``). A backslash takes the character after it,
    ``$$`` is one word part, and an unquoted comment runs to its newline.
    """
    ch = text[i]
    if quote == "'":
        return i + 1, "" if ch == "'" else quote
    if ch == "\\":
        return i + 2, quote
    if quote:
        return i + 1, "" if ch == quote[-1] else quote
    if _starts_comment(text, i):
        end = text.find("\n", i)
        return (len(text) if end < 0 else end), ""
    nxt = text[i + 1 : i + 2]
    if ch == "$" and nxt in {"'", "$"}:
        return i + 2, "$'" if nxt == "'" else ""
    return i + 1, ch if ch in "'\"" else ""


def _in_redirect(command: str, i: int) -> bool:
    """Return whether the ``|`` or ``&`` at ``i`` belongs to ``>|``, ``>&``, ``<&`` or ``&>``."""
    after_op = i > 0 and command[i - 1] in "<>" and not _escaped(command, i - 1)
    if command[i] == "|":
        return after_op and command[i - 1] == ">"
    return after_op or command[i + 1 : i + 2] == ">"


def _split_segments(command: str) -> list[str]:
    r"""Split ``command`` into raw command strings at unquoted ``; | & newline``.

    Splitting the raw string (not shlex tokens) keeps a quoted ``';'`` or an
    escaped ``\;`` as an operand and still splits an unspaced ``a;b``. The
    ``&`` and ``|`` in ``&>``, ``>&`` and ``>|`` are redirects, not operators.
    A ``#`` that starts a word comments out the rest of its line.
    """
    segments: list[str] = []
    start = i = 0
    quote = ""
    while i < len(command):
        ch = command[i]
        if not quote and _starts_comment(command, i):
            segments.append(command[start:i])
            start = len(command) if (end := command.find("\n", i)) < 0 else end
        elif not quote and (ch in ";\n" or (ch in "|&" and not _in_redirect(command, i))):
            segments.append(command[start:i])
            start = i + 1
        i, quote = _step(command, i, quote)
    segments.append(command[start:])
    return segments


# === Resolving a bash word to the paths it can name ===
#
# ``~`` and set environment variables expand; brace lists and globs expand
# against the filesystem. A word with a part guard can't know (an unset
# ``$VAR``, ``$(...)``, a backtick) keeps only its tail, the parts after the
# last unknown one, and so does a relative word after a ``cd`` guard can't
# follow. A tail is matched as if the unknown part could be any directory.

_UNKNOWN_PART_RE = re.compile(r"\$\([^()]*\)|`[^`]*`|\$\{[^}]*\}")
_BRACE_RE = re.compile(r"\{([^{}]*,[^{}]*)\}")
_GLOB_CHARS_RE = re.compile(r"[*?[]")
_EXPANSION_LIMIT = 64


def _expand_word(word: str) -> str:
    word = word.strip("'\"")
    if word.startswith("~"):
        # ``~nosuchuser`` stays literal, as in bash.
        with contextlib.suppress(RuntimeError):
            word = str(Path(word).expanduser())
    word = os.path.expandvars(word)
    while (collapsed := _UNKNOWN_PART_RE.sub("$", word)) != word:
        word = collapsed
    return word


def _expand_braces(word: str) -> list[str]:
    """Expand ``{a,b}`` lists the way bash does before it globs (capped)."""
    words = [word]
    while any(_BRACE_RE.search(w) for w in words) and len(words) < _EXPANSION_LIMIT:
        expanded: list[str] = []
        for w in words:
            match = _BRACE_RE.search(w)
            if match is None:
                expanded.append(w)
                continue
            head, tail = w[: match.start()], w[match.end() :]
            expanded.extend(head + alt + tail for alt in match.group(1).split(","))
        words = expanded
    return words[:_EXPANSION_LIMIT]


def _glob_matches(paths: Sequence[Path]) -> list[Path]:
    """Return what glob characters in ``paths`` match on disk (capped)."""
    found: list[Path] = []
    for path in paths:
        if _GLOB_CHARS_RE.search(str(path)):
            matches = glob.iglob(str(path))  # noqa: PTH207 -- an absolute shell word, not a Path pattern
            found.extend(Path(m) for m in itertools.islice(matches, _EXPANSION_LIMIT))
    return found


_VAR_RE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


def _substitute(word: str, env: Mapping[str, Sequence[str]]) -> list[str]:
    """Expand the variables in ``word`` that the command itself set (capped)."""
    pending, done = [word], list[str]()
    for _ in range(_EXPANSION_LIMIT * 4):
        if not pending or len(done) >= _EXPANSION_LIMIT:
            break
        current = pending.pop()
        match = next((m for m in _VAR_RE.finditer(current) if (m[1] or m[2]) in env), None)
        if match is None:
            done.append(current)
            continue
        head, tail = current[: match.start()], current[match.end() :]
        pending.extend(head + value + tail for value in env[match[1] or match[2]])
    return [*done, *pending][:_EXPANSION_LIMIT]


@dataclass
class _Where:
    """Where a target word can land."""

    paths: list[Path] = field(default_factory=list)  # the absolute paths it names
    tails: list[list[str]] = field(default_factory=list)  # known ends after an unknown part
    # Where its unknown part starts, and whether the word named that directory
    # (``$X`` alone starts in the working directory without naming it).
    under: list[tuple[Path, bool]] = field(default_factory=list)


def _target_paths(
    target: str,
    dirs: Sequence[Path],
    *,
    cd_unknown: bool,
    env: Mapping[str, Sequence[str]] | None = None,
) -> _Where:
    """Return where ``target`` can land, from any of ``dirs``."""
    where = _Where()
    words = _substitute(target, env) if env else [target]
    for word in itertools.chain.from_iterable(_expand_braces(_expand_word(w)) for w in words):
        parts = word.split("/")
        unknown = [i for i, part in enumerate(parts) if "$" in part or "`" in part]
        if unknown:
            where.tails.append(parts[unknown[-1] + 1 :])
            prefix = "/".join(parts[: unknown[0]])
            if word.startswith("/"):
                where.under.append((Path(prefix or "/"), True))
            elif not cd_unknown:
                where.under.extend((d / prefix, bool(prefix)) for d in dirs)
            continue
        if not word:
            continue
        found = [Path(word)] if word.startswith("/") else [d / word for d in dirs]
        if cd_unknown and not word.startswith("/"):
            where.tails.append(parts)
        where.paths.extend([*found, *_glob_matches(found)])
    return where


_ANSI_C_ESCAPE_RE = re.compile(
    r"\\(?:([abeEfnrtv\\'\"?])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})"
    r"|U([0-9A-Fa-f]{1,8})|c(.))",
    re.DOTALL,
)
_ANSI_C_CHARS = dict(zip("abeEfnrtv\\'\"?", "\a\b\x1b\x1b\f\n\r\t\v\\'\"?", strict=True))


def _ansi_c(body: str) -> str:
    """Decode the inside of a ``$'...'`` word with bash's escapes."""

    def one(match: re.Match[str]) -> str:
        char, octal, byte, short, long, ctrl = match.groups()
        if char is not None:
            return _ANSI_C_CHARS[char]
        if ctrl is not None:
            return chr(ord(ctrl) & 0x1F)
        code = int(octal, 8) & 0xFF if octal else int(byte or short or long, 16)
        return chr(code) if code <= sys.maxunicode else ""

    return _ANSI_C_ESCAPE_RE.sub(one, body)


def _heredoc_word(text: str, i: int) -> tuple[int, str, bool] | None:
    """Read the heredoc delimiter at ``text[i]``: ``(end, delimiter, quoted)``.

    ``None`` when there is none or guard can't be sure what bash makes of
    it. Any quoting in the word means the body doesn't expand.
    """
    while i < len(text) and text[i] in " \t":
        i += 1
    start, quote = i, ""
    while i < len(text) and (quote or text[i] not in _WORD_BREAKS):
        i, quote = _step(text, i, quote)
    word = text[start:i]
    if quote or not word or "$" in word or "`" in word:
        return None
    try:
        parts = shlex.split(word)
    except ValueError:
        return None
    if len(parts) != 1:
        return None
    return i, parts[0], any(c in word for c in "'\"\\")


@dataclass
class _Heredoc:
    body: str
    quoted: bool  # a quoted delimiter: nothing in the body expands
    line: str  # the line whose command reads it


@dataclass
class _Lexed:
    """One level of a command, read the way bash reads it.

    ``flat`` is the command with each substitution replaced by ``${}`` (a
    word part guard can't know), heredoc bodies, comments and line
    continuations cut, and each ``$'...'`` decoded into plain single quotes.
    ``bodies`` are the substitutions' commands, ``end`` where a substitution
    closes. ``unknown`` is set when guard can't be sure it read the command
    as bash will: an unterminated quote, substitution or heredoc, a
    delimiter it can't read, or nesting past ``_MAX_NESTING``.
    """

    flat: str = ""
    bodies: list[str] = field(default_factory=list)
    heredocs: list[_Heredoc] = field(default_factory=list)
    end: int = 0
    unknown: bool = False


_MAX_NESTING = 8


def _heredoc_bodies(text: str, i: int, pending: list[tuple[str, bool, bool]], lexed: _Lexed) -> int:
    """Cut the bodies of ``pending`` heredocs from ``text[i]``; return where code resumes."""
    line = text[text.rfind("\n", 0, i - 1) + 1 : i - 1]
    for delimiter, strip_tabs, quoted in pending:
        start = i
        while i < len(text):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            candidate = text[i:end]
            if (candidate.lstrip("\t") if strip_tabs else candidate) == delimiter:
                lexed.heredocs.append(_Heredoc(text[start:i], quoted, line))
                i = end + 1
                break
            i = end + 1
        else:
            lexed.heredocs.append(_Heredoc(text[start:], quoted, line))
            lexed.unknown = True
    return i


def _substitution(text: str, i: int, level: int, lexed: _Lexed) -> int:
    """Record the substitution opening at ``text[i]``; return the index of its close."""
    if text[i] == "`":
        start = i + 1
        close = text.find("`", start)
        close = len(text) if close < 0 else close
    else:
        start = i + 2
        inner = _lex(text, start, level + 1)
        close = inner.end
        lexed.unknown = lexed.unknown or inner.unknown
    lexed.bodies.append(text[start:close])
    lexed.unknown = lexed.unknown or close >= len(text)
    return close


def _heredoc_op(
    text: str, i: int, pending: list[tuple[str, bool, bool]], lexed: _Lexed
) -> tuple[int, str]:
    """Record the heredoc at ``text[i]`` in ``pending``; return the index past its delimiter.

    A here-string (``<<<``) is not a heredoc.
    """
    if text.startswith("<<<", i):
        return i + 3, "<<<"
    strip_tabs = text.startswith("<<-", i)
    word = _heredoc_word(text, i + 2 + strip_tabs)
    if word is None:
        lexed.unknown = True
        end = i + 2 + strip_tabs
    else:
        pending.append((word[1], strip_tabs, word[2]))
        end = word[0]
    return end, text[i:end]


def _unquoted_cut(
    text: str, i: int, pending: list[tuple[str, bool, bool]], lexed: _Lexed
) -> tuple[int, str] | None:
    """Return ``(resume, replacement)`` when unquoted ``text[i]`` starts text to rewrite.

    A comment goes, ``$'...'`` becomes plain quotes, a heredoc operator is
    recorded in ``pending``, and the newline after it drops the bodies.
    """
    if _starts_comment(text, i):
        end = text.find("\n", i)
        return (len(text) if end < 0 else end), ""
    if text.startswith("$'", i):
        j, quote = i + 2, "$'"
        while j < len(text) and quote:
            j, quote = _step(text, j, quote)
        if quote:
            lexed.unknown = True
            return len(text), text[i:]
        return j, "'" + _ansi_c(text[i + 2 : j - 1]).replace("'", "'\\''") + "'"
    if text.startswith("<<", i):
        return _heredoc_op(text, i, pending, lexed)
    if text[i] == "\n" and pending:
        resume = _heredoc_bodies(text, i + 1, pending, lexed)
        pending.clear()
        return resume, "\n"
    return None


def _lex(text: str, start: int = 0, level: int = 0) -> _Lexed:
    """Read ``text`` from ``start``; past level 0, up to the ``)`` closing a substitution.

    Single quotes hide ``$(...)`` and backticks; double quotes don't, but
    they do hide ``<(...)`` and ``>(...)``. A heredoc body
    starts after its operator's line, as in bash.
    """
    lexed = _Lexed(end=len(text))
    if level > _MAX_NESTING:
        lexed.flat, lexed.unknown = text[start:], True
        return lexed
    out: list[str] = []
    pending: list[tuple[str, bool, bool]] = []
    quote = ""
    depth = 1
    i = seg = start
    while i < len(text):
        ch = text[i]
        cut: tuple[int, str] | None = None
        if (quote in {"", '"'} and (ch == "`" or text.startswith("$(", i))) or (
            not quote and text.startswith(("<(", ">("), i)
        ):
            cut = (_substitution(text, i, level, lexed) + 1, "${}")
        elif quote in {"", '"'} and text.startswith("\\\n", i):
            cut = (i + 2, "")
        elif not quote:
            cut = _unquoted_cut(text, i, pending, lexed)
            if cut is None and level and ch in "()":
                depth += 1 if ch == "(" else -1
                if depth == 0:
                    out.append(text[seg:i])
                    lexed.flat, lexed.end = "".join(out), i
                    return lexed
        if cut is None:
            i, quote = _step(text, i, quote)
        else:
            out.extend((text[seg:i], cut[1]))
            i = seg = cut[0]
    out.append(text[seg:])
    lexed.flat = "".join(out)
    lexed.unknown = lexed.unknown or bool(quote) or bool(pending) or level > 0
    return lexed


def _expanded_substitutions(body: str) -> list[str]:
    """Return the commands an unquoted heredoc body runs.

    Quotes are plain text in a heredoc body, so only a backslash hides a
    ``$(`` or backtick.
    """
    found: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "\\":
            i += 2
        elif body.startswith("$(", i):
            end = _lex(body, i + 2, 1).end
            found.append(body[i + 2 : end])
            i = end + 1
        elif body[i] == "`":
            end = body.find("`", i + 1)
            end = len(body) if end < 0 else end
            found.append(body[i + 1 : end])
            i = end + 1
        else:
            i += 1
    return found
