# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""PreToolUse hook: keep subagent transcripts out of the main agent's context.

Claude Code writes two kinds of ``<id>.output`` file under
``/(private/)tmp/claude-<uid>/<project>/<session>/tasks/``:

* **Background Bash output** -- plain text the agent that started the command
  is meant to read (``cat`` / ``tail`` / ``grep`` / the Read tool).
* **Subagent transcripts** -- multi-MiB JSONL. Today each one is a symlink
  into ``~/.claude/projects/<project>/<session>/subagents/agent-<id>.jsonl``;
  older Claude Code builds wrote the JSONL in place.

Only the second kind is denied. For every ``tasks/*.output`` path in a tool
call the hook resolves it on disk and classifies it:

* a wildcard (``tasks/*.output``, ``claude-*/.../x.output``, ``tasks/*``)
  is denied because it can expand to a transcript;
* a symlink whose target is a ``.jsonl`` file or lives under ``subagents/``
  is a transcript;
* a regular file whose first line is a JSON object carrying transcript
  record keys (``parentUuid`` / ``isSidechain`` / ``sessionId`` /
  ``agentId``) is a transcript, whatever the link layout;
* a path guard cannot verify (missing, not a regular file, unreadable, or a
  mention the path tokenizer cannot split out) is denied, fail-closed;
* anything else is background command output and passes.

The structural checks key off how Claude Code stores transcripts (link into
``subagents/``, JSONL transcript records), not off file size or id shape: a
size threshold misfires both ways (a just-launched transcript is small, a
backgrounded ``gh api --paginate`` dump is large) and id formats are
internal to Claude Code.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from guard._safe_io import open_safe
from guard._utils import all_strings_in, emit_pretooluse_decision, safe_main
from guard.allowlist import apply_decision

if TYPE_CHECKING:
    from collections.abc import Iterator

_HOOK_ID = "guard.agent_output_guard"

# Broad detector: any mention of a session ``tasks/<x>.output`` path. The
# uid slot accepts digits AND glob metacharacters (``*``, ``?``) so
# ``cat /private/tmp/claude-*/proj/sess/tasks/*.output`` is still caught.
# The negative-lookahead trailing class keeps ``.output.bak``,
# ``.output_old``, ``.outputs``, ``.output2`` etc. out: only the bare
# ``.output`` filename (or one followed by a quote / whitespace / operator)
# is a task file. The class includes ``.`` so ``x.output.bak`` (extension
# suffix) is excluded.
AGENT_OUTPUT_PATTERN = re.compile(
    r"/(?:private/)?tmp/claude-[\d*?]+/.*/tasks/.*\.output(?![A-Za-z0-9_.])"
)

# One concrete path token: stops at whitespace, quotes and shell operators so
# two task paths in one command are classified separately. Glob
# metacharacters stay inside the token so ``classify`` sees them.
_TOK = r"[^\s'\"`;|&<>()]"
_NAME = r"[^\s'\"`;|&<>()/]"
_TASK_PATH_RE = re.compile(
    rf"/(?:private/)?tmp/claude-[\d*?]+/{_TOK}*/tasks/{_NAME}*\.output(?![A-Za-z0-9_.])"
)

# A wildcard in the filename slot under ``tasks/`` (``tasks/*``,
# ``tasks/a*``, ``tasks/{a,b}``) can expand to a transcript even without a
# literal ``.output`` suffix in the command.
_TASKS_GLOB_RE = re.compile(rf"/(?:private/)?tmp/claude-[\d*?]+/{_TOK}*/tasks/{_NAME}*[*?\[{{]")

# Detects a working directory inside a Claude Code session tmp tree. Used to
# resolve cwd-relative reads (``cat tasks/abc.output`` while cwd is
# ``/private/tmp/claude-501/proj/sess``) into absolute paths.
_AGENT_CWD_RE = re.compile(r"^/(?:private/)?tmp/claude-[\d*?]+/")

_GLOB_CHARS = frozenset("*?[]{}")

# Keys every Claude Code transcript record carries. One is enough: the
# sniff only runs on files already under a session ``tasks/`` dir.
_TRANSCRIPT_KEYS = frozenset({"parentUuid", "isSidechain", "sessionId", "agentId"})

# How much of a task file to read when sniffing its first line. Transcript
# first lines are a few KiB; a line longer than this falls back to a key
# substring search over the window.
_SNIFF_BYTES = 64 * 1024

Verdict = Literal["output", "transcript", "wildcard", "unverified"]

# Deny priority when one call names several task paths.
_SEVERITY: dict[Verdict, int] = {"output": 0, "unverified": 1, "wildcard": 2, "transcript": 3}

_ALTERNATIVE = (
    "Wait for the subagent's completion notification and use the result it "
    "returns. Background command output in the same tasks/ directory is fine "
    "to read by its exact path."
)

_DENY_REASONS: dict[Verdict, str] = {
    "transcript": (
        "This path is a subagent transcript (multi-MiB JSONL); reading it floods "
        "context. " + _ALTERNATIVE
    ),
    "wildcard": (
        "Wildcard reads over a session's tasks/ directory can expand to subagent "
        "transcripts (multi-MiB JSONL). Name the one background command output "
        "file you need by its exact path instead."
    ),
    "unverified": (
        "guard could not verify this tasks/*.output path is background command "
        "output (missing, not a regular file, or not a plain path), so it is "
        "treated as a subagent transcript. " + _ALTERNATIVE
    ),
}


def _cwd_is_agent_session(cwd: str | None) -> bool:
    """Return True if ``cwd`` is inside a Claude Code session tmp tree."""
    if not cwd:
        return False
    return bool(_AGENT_CWD_RE.match(cwd))


def _join_cwd(cwd: str, token: str) -> str:
    """Join ``cwd`` with a relative ``token``, preserving any glob metacharacters."""
    if token.startswith("/"):
        return token
    cleaned = token.removeprefix("./")
    return f"{cwd.rstrip('/')}/{cleaned}"


def _first_line_is_transcript(path: Path) -> bool | None:
    """Sniff the first line of ``path``; ``None`` when it cannot be read."""
    head = open_safe(path, _SNIFF_BYTES)
    if head is None:
        return None
    line = head[:_SNIFF_BYTES].split(b"\n", 1)[0].strip()
    if not line.startswith(b"{"):
        return False
    try:
        record = json.loads(line)
    except ValueError:
        # First line longer than the sniff window (or not JSON at all):
        # look for a transcript key in what we have.
        return any(f'"{key}"'.encode() in line for key in _TRANSCRIPT_KEYS)
    return isinstance(record, dict) and not _TRANSCRIPT_KEYS.isdisjoint(record)


def _sniff_target(path: str) -> Path | Verdict:
    """Return the regular file to sniff, or a verdict when the layout decides."""
    try:
        st = os.lstat(path)
    except OSError:
        return "unverified"
    target = Path(path)
    if stat.S_ISLNK(st.st_mode):
        target = Path(os.path.realpath(path))
        if target.suffix == ".jsonl" or "subagents" in target.parts:
            return "transcript"
        try:
            st = target.stat()
        except OSError:
            return "unverified"
    return target if stat.S_ISREG(st.st_mode) else "unverified"


def classify(path: str) -> Verdict:
    """Classify one concrete ``tasks/<x>.output`` path on disk."""
    if _GLOB_CHARS.intersection(path):
        return "wildcard"
    target = _sniff_target(path)
    if not isinstance(target, Path):
        return target
    sniff = _first_line_is_transcript(target)
    if sniff is None:
        return "unverified"
    return "transcript" if sniff else "output"


def _verdict_for_string(text: str) -> Verdict:
    """Return the worst verdict across every task path mentioned in ``text``."""
    worst: Verdict = "output"
    if _TASKS_GLOB_RE.search(text):
        worst = "wildcard"
    if not AGENT_OUTPUT_PATTERN.search(text):
        return worst
    for match in _TASK_PATH_RE.finditer(text):
        verdict = classify(match.group(0))
        if _SEVERITY[verdict] > _SEVERITY[worst]:
            worst = verdict
    # A mention the tokenizer could not split out (a quoted path with a
    # space, say) cannot be checked on disk: fail closed.
    residual = _TASK_PATH_RE.sub(" ", text)
    if AGENT_OUTPUT_PATTERN.search(residual) and _SEVERITY[worst] < _SEVERITY["unverified"]:
        worst = "unverified"
    return worst


def _candidate_strings(tool_input: dict[str, Any], cwd: str | None) -> Iterator[str]:
    """Yield every string in ``tool_input`` plus cwd-joined relative tokens."""
    strings = list(all_strings_in(tool_input))
    yield from strings
    if cwd is None or not _cwd_is_agent_session(cwd):
        return
    # Join each non-flag, non-absolute token with cwd so payloads like
    # ``cat tasks/abc.output`` (cwd inside the session) match the absolute
    # path pattern.
    for text in strings:
        for tok in text.split():
            stripped = tok.strip("'\"`")
            if stripped and not stripped.startswith(("/", "-")):
                yield _join_cwd(cwd, stripped)


def decide(
    tool_name: str,
    tool_input: dict[str, Any],
    cwd: str | None = None,
) -> dict[str, Any] | None:
    """Return a deny envelope if the call names a subagent transcript.

    The path is the signal, not the verb: every string anywhere in
    ``tool_input`` is scanned (``Read.file_path``, ``Grep.path``,
    ``WebFetch.url`` with ``file://``, the Bash command string, ...).
    Background command output passes; transcripts, wildcards and paths
    guard cannot verify are denied.
    """
    del tool_name  # verb-agnostic: the path decides
    worst: Verdict = "output"
    for text in _candidate_strings(tool_input, cwd):
        verdict = _verdict_for_string(text)
        if _SEVERITY[verdict] > _SEVERITY[worst]:
            worst = verdict
    if worst == "output":
        return None
    return emit_pretooluse_decision("deny", _DENY_REASONS[worst])


def hook(payload: dict[str, Any]) -> None:
    """Top-level hook entry point."""
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        return

    cwd = payload.get("cwd")
    cwd_str = cwd if isinstance(cwd, str) else None
    envelope = decide(tool_name, tool_input, cwd=cwd_str)
    if envelope is None:
        return  # Passthrough

    excerpt = tool_input.get("command" if tool_name == "Bash" else "file_path", "")
    excerpt = excerpt if isinstance(excerpt, str) else ""
    # Not allowlist-overridable (the registry sets supports_disable_hook=False).
    apply_decision(_HOOK_ID, payload, envelope, excerpt, overridable=False)


if __name__ == "__main__":
    safe_main(hook)
