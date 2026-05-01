"""Shared utilities for Claude Code guard hooks.

Provides:

- Standard stdin parsing and PreToolUse decision helpers
- Atomic JSONL append for the decision log at
  ``~/.claude/guard-decisions.jsonl`` (schema v1, see
  ``docs/output-format.md``)
- ``log_decision()`` — the single canonical writer hooks call when they
  emit an allow/deny/ask decision
- ``is_autonomous_mode()`` — driven-agent context detection
- ``sanitize_for_stderr()`` — strip control chars before writing user input
  to stderr

Usage in hooks::

    from guard._utils import (
        emit_pretooluse_decision,
        log_decision,
        safe_main,
    )

    def hook(payload):
        # ... decide ...
        log_decision(
            hook_id="guard.my_hook",
            event="PreToolUse",
            tool_name="Bash",
            decision="deny",
            reason="...",
            session_id=payload.get("session_id", ""),
            cwd=payload.get("cwd"),
        )
        print(json.dumps(emit_pretooluse_decision("deny", "...")))
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# Storage locations
GUARD_HOME = Path(os.environ.get("GUARD_DATA_DIR", str(Path.home() / ".claude" / "guard")))

# Decision JSONL log (env-overridable for tests)
GUARD_DECISIONS_PATH = os.environ.get(
    "GUARD_DECISIONS_PATH", str(Path("~/.claude/guard-decisions.jsonl").expanduser())
)

# Autonomous-mode denial queue (env-overridable for tests). Mirrors the
# GUARD_DECISIONS_PATH pattern — driven-agent contexts append denied commands
# here so a human can review them after the session ends.
GUARD_AUTONOMOUS_QUEUE_PATH: str = os.environ.get(
    "GUARD_AUTONOMOUS_QUEUE_PATH",
    str(Path("~/.claude/guard-autonomous-queue.jsonl").expanduser()),
)


def _env_int(name: str, default: int) -> int:
    """Parse int from environment variable, falling back to default on miss/invalid."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _log_debug(msg: str) -> None:
    """Emit a debug line to stderr when ``GUARD_DEBUG=1``."""
    if os.environ.get("GUARD_DEBUG") == "1":
        sys.stderr.write(f"[guard] {msg}\n")


_AUTONOMOUS_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def is_autonomous_mode() -> bool:
    """Return True when running in non-interactive / driven-agent context.

    Triggered by ``CLAUDE_AUTONOMOUS`` set to any of ``1``, ``true``, ``yes``,
    or ``on`` (case-insensitive). Set automatically by Claude Code when
    running subagents or any context where there's no human at the prompt to
    answer a permission ask. Hooks consult this to decide between strict
    default-deny mode and pass-through-to-user mode.
    """
    return os.environ.get("CLAUDE_AUTONOMOUS", "").strip().lower() in _AUTONOMOUS_TRUTHY


# Loop detection settings
LOOP_DETECTION_THRESHOLD = _env_int("GUARD_LOOP_THRESHOLD", 3)
LOOP_DETECTION_WINDOW_MINUTES = _env_int("GUARD_LOOP_WINDOW", 10)

# Context budget settings
CONTEXT_BUDGET_WARN_BYTES = _env_int("GUARD_CONTEXT_WARN", 500_000)
CONTEXT_BUDGET_HARD_BYTES = _env_int("GUARD_CONTEXT_HARD", 1_000_000)


# === Shared Hook Utilities ===
# Standard patterns for stdin parsing, decision output, and error handling.
# All hooks should use these instead of reimplementing the boilerplate.


_STDIN_LIMIT = 1 << 20  # 1 MiB
_JSONL_RECORD_MAX = 4096  # POSIX O_APPEND atomicity envelope on Linux
_REASON_MAX_CHARS = 1024  # schema v1 §3
_COMMAND_EXCERPT_MAX_CHARS = 4096  # schema v1 §3
_TRUNCATION_MARKER = "…[truncated]"


def token_basename(tok: str) -> str:
    """Return the basename of a shell token treated as a string, not a Path.

    Hooks operate on user-supplied command strings before any filesystem
    resolution. ``Path("/usr/bin/python3").name`` works but conflates real
    filesystem paths with shell tokens that may not exist on disk.
    """
    return os.path.basename(tok)  # noqa: PTH119 -- string-token basename, not a real path


def parse_hook_input() -> dict[str, Any] | None:
    """Read and parse hook stdin JSON, capped at 1 MiB.

    Returns ``None`` on missing/non-dict payload (fail-open). Exits with code 2
    on oversized stdin or malformed JSON (fail-closed deny). The 1 MiB cap
    matches the threat model: hook stdin is attacker-influenceable, so we bound
    regex cost and prevent soft-DoS.
    """
    try:
        raw = sys.stdin.buffer.read(_STDIN_LIMIT + 1)
    except OSError:
        return None
    if len(raw) > _STDIN_LIMIT:
        sys.stderr.write("guard: stdin exceeds 1 MiB; denying.\n")
        sys.exit(2)
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        sys.stderr.write("guard: malformed JSON on stdin; denying.\n")
        sys.exit(2)
    return data if isinstance(data, dict) else None


def _encode_line(entry: dict[str, Any]) -> bytes:
    return (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")


def _shrink_to_envelope(entry: dict[str, Any]) -> bytes:
    """Return the encoded JSONL line, ≤ 4 KiB and always valid JSON.

    If the encoded entry exceeds ``_JSONL_RECORD_MAX``, ``command_excerpt`` is
    truncated first (and tagged with the marker), then ``reason``. Required
    fields (``decision``, ``hook_id``, ``schema_version``, ``timestamp``,
    ``tool_name``, ``session_id``) are never modified.
    """
    line = _encode_line(entry)
    if len(line) <= _JSONL_RECORD_MAX:
        return line

    # Conservative budget: shrink each truncatable field to a length that
    # leaves room for the marker. We binary-search the field length so the
    # final encoded line fits the envelope without overshooting.
    for field in ("command_excerpt", "reason"):
        if field not in entry or not isinstance(entry[field], str):
            continue
        original = entry[field]
        if not original:
            continue
        lo, hi = 0, len(original)
        best_fit: str | None = None
        while lo <= hi:
            mid = (lo + hi) // 2
            entry[field] = original[:mid] + _TRUNCATION_MARKER
            candidate = _encode_line(entry)
            if len(candidate) <= _JSONL_RECORD_MAX:
                best_fit = entry[field]
                lo = mid + 1
            else:
                hi = mid - 1
        if best_fit is None:
            # Field plus marker can't fit — drop the field entirely with marker.
            entry[field] = _TRUNCATION_MARKER
        else:
            entry[field] = best_fit
        line = _encode_line(entry)
        if len(line) <= _JSONL_RECORD_MAX:
            return line

    # Last resort: even a bare marker overflowed — emit a minimal record so
    # downstream consumers can still parse a JSONL line.
    minimal = {
        "schema_version": entry.get("schema_version", 1),
        "timestamp": entry.get("timestamp", ""),
        "hook_id": entry.get("hook_id", ""),
        "decision": entry.get("decision", ""),
        "reason": _TRUNCATION_MARKER,
    }
    return _encode_line(minimal)


def append_jsonl(path: str | Path, entry: dict[str, Any]) -> None:
    """Atomically append a JSONL record, capped at 4096 bytes.

    Uses ``os.write()`` on an ``O_APPEND`` fd for true single-syscall
    atomicity per POSIX. The encoded record is shrunk by truncating
    ``command_excerpt`` then ``reason`` (with a ``…[truncated]`` marker) so
    the line is both valid JSON and ≤ 4 KiB. Fails open (silently) on
    ``OSError`` per the "guardrails not walls" doctrine — a logging failure
    must never block legitimate work.
    """
    line = _shrink_to_envelope(dict(entry))
    try:
        path_str = str(path)
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path_str, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except OSError:
        pass


def log_decision(  # noqa: PLR0913 -- spec-defined record fields per docs/output-format.md
    *,
    hook_id: str,
    event: str,
    tool_name: str | None,
    decision: Literal["allow", "deny", "ask", "pass", "defer"],
    reason: str,
    command_excerpt: str | None = None,
    session_id: str = "",
    cwd: str | None = None,
) -> None:
    """Append a spec-compliant decision record to the JSONL log.

    Conforms to ``docs/output-format.md`` schema v1. Truncates
    ``command_excerpt`` to 4096 chars and ``reason`` to 1024 chars to fit
    within the 4 KiB record envelope. Fail-safe: never raises; logging
    failures are silent.

    Args:
        hook_id: Namespaced hook id, e.g. ``"guard.bash_command_validator"``.
        event: Claude Code event name (typically ``"PreToolUse"``).
        tool_name: ``Bash``/``Edit``/``Read``/etc., or ``None``.
        decision: One of ``allow``/``deny``/``ask``/``pass``/``defer``.
        reason: Human-readable rationale (truncated to 1024 chars).
        command_excerpt: Optional bash-command excerpt (truncated to 4096).
        session_id: Claude Code session id.
        cwd: Optional working directory string.
    """
    timestamp = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    record: dict[str, Any] = {
        "schema_version": 1,
        "timestamp": timestamp,
        "hook_id": hook_id,
        "event": event,
        "tool_name": tool_name,
        "decision": decision,
        "reason": reason[:_REASON_MAX_CHARS],
        "session_id": session_id,
    }
    if command_excerpt is not None:
        record["command_excerpt"] = command_excerpt[:_COMMAND_EXCERPT_MAX_CHARS]
    if cwd is not None:
        record["cwd"] = cwd
    append_jsonl(GUARD_DECISIONS_PATH, record)


def make_decision(decision: str, reason: str) -> str:
    """Build a ``hookSpecificOutput`` JSON string for PreToolUse decisions.

    Args:
        decision: ``"allow"``, ``"deny"``, or ``"ask"``.
        reason: Human-readable explanation.

    Returns:
        JSON string ready to print to stdout.
    """
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(output)


def emit_pretooluse_decision(
    decision: Literal["allow", "deny", "ask"],
    reason: str,
    *,
    updated_input: dict[str, Any] | None = None,
    additional_context: str | None = None,
) -> dict[str, Any]:
    """Build a PreToolUse decision envelope.

    Args:
        decision: ``"allow"``, ``"deny"``, or ``"ask"``. ``"ask"`` is permitted
            because advisory hooks (e.g. ``protected_files``) exist precisely
            to surface a permission prompt; authoritative validators stick to
            ``"allow"``/``"deny"``.
        reason: Human-readable rationale surfaced to the user/agent.
        updated_input: Optional rewritten tool input merged into the envelope.
        additional_context: Optional extra context string for the agent.

    Returns:
        Decision envelope ready to ``json.dumps`` to stdout.
    """
    envelope: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    if updated_input is not None:
        envelope["hookSpecificOutput"]["updatedInput"] = updated_input
    if additional_context is not None:
        envelope["hookSpecificOutput"]["additionalContext"] = additional_context
    return envelope


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_for_stderr(text: str, *, max_len: int = 200) -> str:
    """Strip control characters and truncate text for safe stderr output.

    Replaces ASCII/C1 control chars with ``?`` so attacker-controlled command
    fragments cannot inject ANSI escape sequences, terminal title-setters, or
    other control sequences into developer terminals.
    """
    return _CONTROL_CHARS_RE.sub("?", text)[:max_len]


# === Path-token extraction (universal credential scanner) ===

# Matches path-like tokens in any string: absolute POSIX, ``~``-anchored,
# ``./``/``../``, ``$VAR``-prefixed, or relative paths containing a ``/``.
# Stops at whitespace and shell metacharacters that terminate a token.
# Variable-prefixed forms (``$HOME/...``, ``${HOME}/...``) are captured
# verbatim; the caller is responsible for expanding them when needed.
_PATH_LIKE_RE = re.compile(
    r"""(?x)
    (?:
        ~[A-Za-z0-9_]*(?:/[^\s'";|&<>()`*?\[\]{}]+)+   # ~/... or ~user/...
        |
        \$\{[A-Za-z_][A-Za-z0-9_]*\}/[^\s'";|&<>()`*?\[\]{}]+   # ${VAR}/...
        |
        \$[A-Za-z_][A-Za-z0-9_]*/[^\s'";|&<>()`*?\[\]{}]+       # $VAR/...
        |
        /[^\s'";|&<>()`*?\[\]{}]+                       # /abs/path
        |
        \.{1,2}/[^\s'";|&<>()`*?\[\]{}]+                # ./rel or ../rel
        |
        [A-Za-z0-9_.+\-]+/[^\s'";|&<>()`*?\[\]{}/]+(?:/[^\s'";|&<>()`*?\[\]{}]*)*  # a/b
    )
    """
)


def _expand_home_var(token: str) -> str | None:
    """Return ``token`` with a leading ``$HOME`` / ``${HOME}`` expanded, else ``None``.

    Pure string substitution — does not call ``os.path.expandvars`` to avoid
    unbounded variable expansion against the live process environment.
    """
    home = str(Path.home())
    if token.startswith("$HOME/"):
        return home + token[len("$HOME") :]
    if token.startswith("${HOME}/"):
        return home + token[len("${HOME}") :]
    return None


def all_strings_in(value: Any) -> Iterator[str]:  # noqa: ANN401 -- tool_input is genuinely Any
    """Yield every string contained in ``value`` recursively (dicts/lists/tuples).

    Used by hooks that need a verb-agnostic scan over any tool_input shape —
    matchers can regex-search each yielded string without re-deriving how
    paths/commands are nested. Complements ``all_paths_in`` (which extracts
    only the path-like substrings).
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from all_strings_in(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from all_strings_in(v)


_iter_strings = all_strings_in  # backwards-compat alias for in-module callers


def all_paths_in(value: Any) -> Iterator[str]:  # noqa: ANN401 -- tool_input is genuinely Any
    """Yield every path-like token contained in any tool_input shape.

    Recurses into dicts and lists, scanning each string with ``_PATH_LIKE_RE``.
    For variable-prefixed forms anchored at ``$HOME`` / ``${HOME}``, also
    yields the literal-expanded form so credential matchers anchored on
    ``$HOME`` (e.g. ``~/.aws/credentials``) hit the underlying file.

    Strings shorter than 2 chars and obvious URL schemes other than ``file://``
    are ignored. Duplicates within a single call are de-duplicated to keep
    downstream matchers tight.
    """
    seen: set[str] = set()
    for s in _iter_strings(value):
        if not s:
            continue
        # Strip a leading ``file://`` so URL payloads match path matchers.
        candidates = [s]
        if s.startswith("file://"):
            candidates.append(s[len("file://") :])
        for source in candidates:
            for match in _PATH_LIKE_RE.finditer(source):
                token = match.group(0)
                if token not in seen:
                    seen.add(token)
                    yield token
                expanded = _expand_home_var(token)
                if expanded is not None and expanded not in seen:
                    seen.add(expanded)
                    yield expanded


def safe_main(hook_fn: Callable[[dict[str, Any]], None]) -> None:
    """Wrap a hook function with stdin parsing and exception handling.

    Reads stdin JSON, calls ``hook_fn(payload)``. If stdin is invalid or
    ``hook_fn`` raises, exits silently (passthrough). Hooks should never
    block on errors.

    Args:
        hook_fn: Callable that takes a dict payload. May call
            ``sys.exit(2)`` for hard deny, or ``print(make_decision(...))``
            for decisions. No return value is required for passthrough.
    """
    try:
        payload = parse_hook_input()
        if payload is None:
            return
        hook_fn(payload)
    except SystemExit:
        raise  # Allow sys.exit() from hook_fn
    except Exception:  # noqa: BLE001 -- silent passthrough is the design contract
        if os.environ.get("GUARD_DEBUG") == "1":
            import traceback  # noqa: PLC0415 -- deferred import, only loaded on debug path

            _log_debug(f"hook crashed: {traceback.format_exc()}")
        # otherwise pass silently — guardrails not walls
