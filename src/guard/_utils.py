"""Shared utilities for Claude Code guard hooks.

Provides:

- Standard stdin parsing and PreToolUse decision helpers
- Atomic JSONL append for the decision log at
  ``~/.claude/guard-decisions.jsonl`` (schema v1, see
  ``docs/output-format.md``)
- ``log_decision()`` — the single canonical writer hooks call when they
  emit an allow/deny/ask decision
- ``read_permission_mode(hook_input)`` — extract the documented Claude Code
  ``permission_mode`` from a PreToolUse payload
- ``is_strict_mode(hook_input)`` — convenience predicate for
  ``permission_mode in {dontAsk, bypassPermissions}``
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

import contextlib
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
GUARD_STRICT_DENY_QUEUE_PATH: str = os.environ.get(
    "GUARD_STRICT_DENY_QUEUE_PATH",
    str(Path("~/.claude/guard-strict-deny-queue.jsonl").expanduser()),
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


# Strict modes route through guard's default-deny path; the rest pass through
# advisory-mode evaluation. The documented Claude Code permission_mode values
# are default / plan / acceptEdits / auto / dontAsk / bypassPermissions.
STRICT_PERMISSION_MODES: frozenset[str] = frozenset({"dontAsk", "bypassPermissions"})


def read_permission_mode(hook_input: dict[str, Any] | None) -> str:
    """Return ``permission_mode`` from a PreToolUse hook-input payload.

    Defaults to ``"default"`` when the field is absent or non-string.
    Unknown literal values are returned as-is so downstream callers can
    emit a one-line warning and treat them as advisory.
    """
    if hook_input is None:
        return "default"
    raw = hook_input.get("permission_mode")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return "default"


def is_strict_mode(hook_input: dict[str, Any] | None) -> bool:
    """Return True when ``permission_mode`` is a strict (default-deny) mode.

    Strict modes (``dontAsk``, ``bypassPermissions``) indicate the user has
    explicitly opted into unattended operation; guard escalates from
    advisory to default-deny. All other modes (including the documented
    ``auto`` classifier-mediated mode) stay in advisory evaluation.
    """
    return read_permission_mode(hook_input) in STRICT_PERMISSION_MODES


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

# Secret-shape redactors applied to ``command_excerpt`` and ``reason`` before
# they land in the JSONL log. The log is itself a credential-disclosure side
# channel: any process that can read ``~/.claude/guard-decisions.jsonl`` would
# otherwise harvest a curated transcript of every secret the agent typed,
# indexed by hook and timestamp. Keep the catalog focused on shapes that
# (a) are unambiguous (low false-positive rate) and (b) would be catastrophic
# in a log dump. Generic "high entropy" detection lives in ``credential_check``
# upstream — here we only sanitize what already slipped past detection.
_SECRET_REDACTORS: tuple[tuple[re.Pattern[str], str], ...] = (
    # AWS access-key IDs (AKIA = long-term, ASIA = session, AGPA/AROA/AIDA =
    # IAM principal IDs). Format: ``[A-Z0-9]{16}`` after the prefix.
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-ID]"),
    # Anthropic API keys.
    (re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{32,}"), "[REDACTED-ANTHROPIC-KEY]"),
    # OpenAI / project keys.
    (re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}"), "[REDACTED-OPENAI-PROJECT-KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}"), "[REDACTED-SK-KEY]"),
    # GitHub PAT shapes (fine-grained, classic, OAuth, server, refresh).
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}"), "[REDACTED-GITHUB-PAT]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "[REDACTED-GITHUB-TOKEN]"),
    # GitLab PAT.
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), "[REDACTED-GITLAB-PAT]"),
    # Slack tokens (xoxb/xoxp/xoxa/xoxe/xapp variants).
    (re.compile(r"\bxox[abeprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED-SLACK-TOKEN]"),
    # Stripe restricted/secret/publishable keys.
    (re.compile(r"\b(?:rk|sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"), "[REDACTED-STRIPE-KEY]"),
    # SendGrid.
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "[REDACTED-SENDGRID-KEY]"),
    # npm tokens.
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), "[REDACTED-NPM-TOKEN]"),
    # PyPI macaroons.
    (re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]+"), "[REDACTED-PYPI-TOKEN]"),
    # JWT bearer tokens (3 base64url segments).
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "[REDACTED-JWT]",
    ),
    # PEM private keys (any flavor, multi-line).
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED-PRIVATE-KEY]",
    ),
    # Generic ``Authorization: Bearer <token>`` headers.
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"), r"\1[REDACTED]"),
    # Generic ``KEY=value`` / ``KEY: value`` for credential-named keys.
    (
        re.compile(
            r"(?i)((?:api[_-]?key|access[_-]?key|secret[_-]?key|aws_secret_access_key|"
            r"private[_-]?key|password|passwd|pwd|token|auth|bearer)\s*[=:]\s*)"
            r"['\"]?[^\s'\"&,;]{6,}",
        ),
        r"\1[REDACTED]",
    ),
)


def _redact_secrets(text: str) -> str:
    """Replace recognized secret shapes with redaction placeholders.

    Applied to log-bound ``command_excerpt`` and ``reason`` strings before
    they are persisted to ``~/.claude/guard-decisions.jsonl``. Matches are
    conservative: we only replace shapes with vendor-specific prefixes or
    explicit credential-named key/value contexts. Unknown high-entropy
    strings are left in place — false-positive redactions in the audit
    log would damage forensics more than the (low) marginal leak risk.
    """
    if not text:
        return text
    for pat, repl in _SECRET_REDACTORS:
        text = pat.sub(repl, text)
    return text


# Schema-v1 envelope: every record carries ``v`` (short alias) and ``mode``
# (effective enforcement posture). See ``docs/JSONL_FORMAT.md``.
_SCHEMA_V = 1
_DEFAULT_MODE = "enforce"


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
        "v": entry.get("v", _SCHEMA_V),
        "schema_version": entry.get("schema_version", _SCHEMA_V),
        "mode": entry.get("mode", _DEFAULT_MODE),
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
        Path(path_str).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # O_NOFOLLOW: refuse to follow a pre-planted symlink at the log path
        # (e.g. ``~/.claude/guard-decisions.jsonl`` → ``/etc/cron.d/x``) which
        # would let an attacker turn guard's append into an arbitrary-write
        # primitive on a sensitive file. O_CLOEXEC: the fd never escapes to
        # subprocesses spawned by hooks. ``hasattr`` keeps the call portable
        # to platforms that lack the constants (e.g. older Windows builds).
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(path_str, flags, 0o600)
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
    extra: dict[str, Any] | None = None,
) -> None:
    """Append a spec-compliant decision record to the JSONL log.

    Conforms to ``docs/JSONL_FORMAT.md`` (schema v1). Every record carries:

    - ``v: 1`` -- short schema-version alias for fast consumers
    - ``schema_version: 1`` -- long form, kept for backward compatibility
    - ``mode: "enforce"`` -- effective enforcement posture; reserved for
      ``"shadow"`` / ``"off"`` once config-driven mode lands
    - ``timestamp`` -- ISO-8601 UTC with microsecond precision and ``Z`` suffix

    Truncates ``command_excerpt`` to 4096 chars and ``reason`` to 1024 chars
    to fit within the 4 KiB record envelope. Fail-safe: never raises; logging
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
        extra: Optional dict of additional fields merged into the record
            (e.g. ``{"unknown_flags": ["--foo", "--bar"]}``). Values are
            written verbatim; callers are responsible for not including
            secret material.
    """
    timestamp = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    redacted_reason = _redact_secrets(reason)
    record: dict[str, Any] = {
        "type": "decision",
        "v": _SCHEMA_V,
        "schema_version": _SCHEMA_V,
        "mode": _DEFAULT_MODE,
        "timestamp": timestamp,
        "hook_id": hook_id,
        "event": event,
        "tool_name": tool_name,
        "decision": decision,
        "reason": redacted_reason[:_REASON_MAX_CHARS],
        "session_id": session_id,
    }
    if command_excerpt is not None:
        redacted_excerpt = _redact_secrets(command_excerpt)
        record["command_excerpt"] = redacted_excerpt[:_COMMAND_EXCERPT_MAX_CHARS]
    if cwd is not None:
        record["cwd"] = cwd
    if extra:
        record.update(extra)
    append_jsonl(GUARD_DECISIONS_PATH, record)
    _maybe_emit_heartbeat(session_id)


GUARD_HEARTBEAT_EVERY = _env_int("GUARD_HEARTBEAT_EVERY", 100)
_HEARTBEAT_COUNTER: dict[str, int] = {"n": 0}


def _maybe_emit_heartbeat(session_id: str) -> None:
    """Emit a heartbeat JSONL record every N decisions.

    Cheap idempotent liveness signal so ``guard status`` can answer
    "is guard actually running?" instead of inferring from log freshness
    alone. Counter is process-local; cross-process aggregation is by
    timestamp on the consumer side.
    """
    if GUARD_HEARTBEAT_EVERY <= 0:
        return
    _HEARTBEAT_COUNTER["n"] += 1
    if _HEARTBEAT_COUNTER["n"] % GUARD_HEARTBEAT_EVERY != 0:
        return
    from guard import __version__ as _guard_version  # noqa: PLC0415

    append_jsonl(
        GUARD_DECISIONS_PATH,
        {
            "type": "heartbeat",
            "schema_version": _SCHEMA_V,
            "guard_version": _guard_version,
            "timestamp": _utc_now_iso(),
            "session_id": session_id,
        },
    )


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def log_internal_error(exc: BaseException, *, session_id: str = "") -> None:
    """Append a structured ``internal_error`` JSONL record.

    Called from ``safe_main`` before fail-open so a silent crash becomes an
    observable event. The traceback is hashed (not stored) to avoid leaking
    file paths or payload contents; operators bucket repeat failures by hash.
    """
    import hashlib  # noqa: PLC0415
    import traceback  # noqa: PLC0415

    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    tb_hash = "sha256:" + hashlib.sha256(tb_text.encode("utf-8")).hexdigest()[:16]
    append_jsonl(
        GUARD_DECISIONS_PATH,
        {
            "type": "internal_error",
            "schema_version": _SCHEMA_V,
            "exc_class": type(exc).__name__,
            "exc_msg": str(exc)[:_REASON_MAX_CHARS],
            "traceback_hash": tb_hash,
            "session_id": session_id,
            "timestamp": _utc_now_iso(),
        },
    )


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
    payload: dict[str, Any] | None = None
    try:
        payload = parse_hook_input()
        if payload is None:
            return
        hook_fn(payload)
    except SystemExit:
        raise  # Allow sys.exit() from hook_fn
    except Exception as exc:  # noqa: BLE001 -- silent passthrough is the design contract
        session_id = ""
        if isinstance(payload, dict):
            sid = payload.get("session_id")
            if isinstance(sid, str):
                session_id = sid
        with contextlib.suppress(Exception):
            log_internal_error(exc, session_id=session_id)
        if os.environ.get("GUARD_DEBUG") == "1":
            import traceback  # noqa: PLC0415 -- deferred import, only loaded on debug path

            _log_debug(f"hook crashed: {traceback.format_exc()}")
        # otherwise pass silently — guardrails not walls
