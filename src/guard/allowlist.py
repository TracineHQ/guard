"""Project + global allowlist for guard rules and exact commands.

Two override knobs, both read from JSON files:

1. **disable_rules** — a list of ``rule_id`` strings (e.g.
   ``"bash.disk_destruction"``, ``"guard.protected_files"``). When a hook is
   about to deny under one of these rule_ids, it falls through to
   allow instead. Useful when a matcher fires repeatedly on legitimate
   project workflows.
2. **allow_commands** — a list of ``{rule, command, reason}`` entries. When
   a deny is about to fire under ``rule`` AND the original input string
   exactly equals ``command``, the decision is downgraded to allow. The
   ``reason`` is included in the audit-log record so every bypass is
   traceable to a written justification.

Resolution order:

- Global file at ``~/.claude/guard/allowlist.json`` (overridable via
  ``GUARD_DATA_DIR``).
- Project file at ``<cwd>/.claude/guard/allowlist.json``.

The two are merged into a single effective allowlist — both
``disable_rules`` are unioned and both ``allow_commands`` lists are
concatenated. Project entries are listed first so they're easy to spot in
``guard allowlist list`` output, but match priority is irrelevant: any
rule on either list disables, any matching command on either list allows.

Project trust. Any repo someone clones can ship a project file, so guard
trusts it only when it is a regular file (no symlink below the working
directory) whose ``.claude`` directory sits directly in a git work-tree
root, and no path git tracks is that same file (compared by device and
inode, so case and Unicode-folding tricks can't hide it): untracked or
gitignored, the normal home for a user's own local entries. A trusted file
behaves as above. An untrusted one (tracked, below the repository root,
outside any work tree, behind a symlink, or unverifiable because git is
missing, fails or times out) can only tighten: its mode applies only when
stricter than the global/default mode (off < shadow < enforce < lockdown),
its ``disable_rules`` and ``allow_commands`` are ignored, and one stderr
warning per process says so. Git is consulted only when a project file
would loosen something, and its verdict is cached in
``project-trust-cache.json`` next to the global file, keyed on the file
path plus the file's and the git index's stat (a failed check is cached for
a minute so a broken or slow git isn't re-run on every hook).

Files are parsed with ``json.loads``; malformed JSON or non-object top-level
shape is logged as a stderr warning and the file is ignored. Individual
entries that fail validation are dropped with a warning emitted to stderr —
the goal is to keep guard running even if a user's allowlist is partially
broken (the worst-case fallback is "matcher fires", which is the safe
direction).
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from guard._utils import GUARD_HOME, log_decision, sanitize_for_stderr

if TYPE_CHECKING:
    import subprocess  # nosec B404 -- typing only; imported lazily where git runs

# ``lockdown`` is ``enforce`` plus strict default-deny for bash and the
# extended protected-file list. It is opt-in only: Claude Code's
# ``permission_mode`` never switches it on.
Mode = Literal["enforce", "shadow", "off", "lockdown"]
_VALID_MODES: frozenset[str] = frozenset(("enforce", "shadow", "off", "lockdown"))
_DEFAULT_MODE: Mode = "enforce"
# Strictness order. An untrusted project file may only move the mode up.
_MODE_RANK: dict[str, int] = {"off": 0, "shadow": 1, "enforce": 2, "lockdown": 3}

PROJECT_ALLOWLIST_RELPATH = Path(".claude") / "guard" / "allowlist.json"

# Project trust check. One ``git ls-files`` per cache miss, bounded by a
# short timeout; anything that isn't a clean answer is untrusted.
_GIT_TIMEOUT_S = 2.0
_TRUST_CACHE_NAME = "project-trust-cache.json"
_TRUST_CACHE_VERSION = 2
_TRUST_CACHE_MAX_ENTRIES = 32
_UNVERIFIABLE_TTL_S = 60.0
# Every tracked path that could be the project file under any case or
# Unicode spelling. Each is stat'ed and compared to the file guard read.
_TRACKED_CANDIDATES_PATHSPEC = (
    f":(top,icase,glob)**/{PROJECT_ALLOWLIST_RELPATH.parent.as_posix()}/*"
)
_HEX_OID_RE = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")

# Bash matcher rule_ids — fine-grained, one per matcher function. Keep in
# sync with the matchers in ``bash_command_validator.py``. The whole-hook
# rule_ids of the other hooks are appended below from
# ``hook_registry.disable_hook_ids()`` so there's exactly one place that
# enumerates hook ids — the registry.
_BASH_MATCHER_RULE_IDS: tuple[str, ...] = (
    # Bash: ALWAYS_DENY layer (coarse).
    "bash.always_deny",
    # Bash: synthetic matchers (fine-grained, one per matcher func).
    "bash.admin_default_deny",
    "bash.admin_forbidden_flag",
    "bash.admin_forbidden_subcommand",
    "bash.admin_sensitive_env_override",
    "bash.admin_unknown_flag_strict",
    "bash.aws_destructive",
    "bash.aws_s3_destructive",
    "bash.az_destructive",
    "bash.cargo_remote_install",
    "bash.chmod_dangerous",
    "bash.chmod_sensitive_target",
    "bash.chmod_setuid",
    "bash.command_too_long",
    "bash.conditional_denied_flag",
    "bash.credential_leak",
    "bash.dangerous_construct",
    "bash.dangerous_env_sink",
    "bash.dangerous_interpreter",
    "bash.dangerous_rm",
    "bash.db_cli_destructive",
    "bash.disk_destruction",
    "bash.dns_exfil",
    "bash.dropdb_or_mysqladmin",
    "bash.env_split_string",
    "bash.escalation_shell",
    "bash.eval_builtin",
    "bash.exec_wrapper",
    "bash.fs_attr_sensitive",
    "bash.function_definition",
    "bash.gcloud_destructive",
    "bash.gem_remote_install",
    "bash.gh_api_destructive",
    "bash.git_config_injection",
    "bash.git_force_push",
    "bash.git_read_exec",
    "bash.git_ref_mutation",
    "bash.git_force_refspec",
    "bash.git_submodule_add",
    "bash.git_worktree_add",
    "bash.glob_head",
    "bash.go_remote_install",
    "bash.gpg_secret_delete",
    "bash.helm_remote_install",
    "bash.host_control",
    "bash.iac_destruction",
    "bash.kernel_module_load",
    "bash.kubectl_destructive",
    "bash.mongo_destructive",
    "bash.network_policy_wipe",
    "bash.npm_url_install",
    "bash.npx_remote",
    "bash.persistence",
    "bash.pip_install_url",
    "bash.process_attach",
    "bash.process_tree_kill",
    "bash.registry_config",
    "bash.remote_shell_wrapper",
    "bash.secret_egress",
    "bash.secret_value",
    "bash.sensitive_write",
    "bash.shell_wrapper",
    "bash.strict_default_deny",
    "bash.strict_feedback",
    "bash.sudo_escalation",
    "bash.tool_alternative",
    "bash.trap_exploit",
    "bash.use_corpus_harness",
    "bash.var_expanded_head",
    "bash.wrapper_stacking",
)


def _build_known_rule_ids() -> tuple[str, ...]:
    """Bash matcher ids + whole-hook disable ids, in registration order."""
    # Local import to avoid a load-order cycle: hooks import this module for
    # ``hook_bypass_reason`` / ``load_allowlist``; the registry doesn't,
    # but importing it at module load would still surface as
    # ``allowlist -> guard.hooks._registry -> guard.hooks.<x>`` if anyone
    # ever extended the registry to do eager imports.
    from guard.hooks._registry import disable_hook_ids  # noqa: PLC0415 -- lazy: avoid cycle

    return _BASH_MATCHER_RULE_IDS + disable_hook_ids()


# All known rule_ids users can put on ``disable_rules`` / ``allow_commands.rule``.
# Sourced from the bash matcher list above plus the registry's whole-hook
# disable ids. Order is bash-matcher declaration order followed by
# registry-order whole-hook ids — stable across runs given the same source.
KNOWN_RULE_IDS: tuple[str, ...] = _build_known_rule_ids()


@dataclass(frozen=True)
class AllowEntry:
    """A single ``{rule, command, reason}`` allow_commands entry."""

    rule: str
    command: str
    reason: str
    source: str = "?"  # "global" / "project" / file path — for diagnostic display


@dataclass(frozen=True)
class Allowlist:
    """Effective merged allowlist (union of global and project entries)."""

    disable_rules: frozenset[str] = field(default_factory=frozenset)
    allow_commands: tuple[AllowEntry, ...] = ()
    sources: tuple[Path, ...] = ()  # files actually read (for diagnostics)
    mode: Mode = _DEFAULT_MODE  # enforce | shadow | off | lockdown; trusted project wins

    def is_rule_disabled(self, rule_id: str) -> bool:
        """True if ``rule_id`` is in ``disable_rules``."""
        return rule_id in self.disable_rules

    def find_command(self, rule_id: str, command: str) -> AllowEntry | None:
        """Return the first ``allow_commands`` entry matching ``rule_id`` and exact ``command``.

        ``command`` is compared with exact string equality (after .strip() on
        both sides) — no canonicalisation, no brace expansion. The user
        opted into a specific command, not a shape.
        """
        cmd = command.strip()
        for e in self.allow_commands:
            if e.rule == rule_id and e.command.strip() == cmd:
                return e
        return None


def _validate_mode(raw: Any, source: str) -> Mode | None:  # noqa: ANN401 -- JSON value is genuinely Any
    """Return a valid Mode or None (None means "key absent / invalid; skip")."""
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in _VALID_MODES:
        _warn(f"{source}: 'mode' must be one of {sorted(_VALID_MODES)}; ignoring (got {raw!r})")
        return None
    return cast("Mode", raw)


def _validate_disable_rules(raw: Any, source: str) -> list[str]:  # noqa: ANN401 -- JSON value is genuinely Any
    if raw is None:
        return []
    if not isinstance(raw, list):
        _warn(f"{source}: 'disable_rules' must be a list of strings; ignoring")
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            out.append(item)
        else:
            _warn(f"{source}: skipping non-string disable_rules entry: {item!r}")
    return out


def _validate_allow_commands(raw: Any, source: str) -> list[AllowEntry]:  # noqa: ANN401 -- JSON value is genuinely Any
    if raw is None:
        return []
    if not isinstance(raw, list):
        _warn(f"{source}: 'allow_commands' must be a list of objects; ignoring")
        return []
    out: list[AllowEntry] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            _warn(f"{source}: allow_commands[{idx}] is not an object; skipping")
            continue
        rule = item.get("rule")
        command = item.get("command")
        reason = item.get("reason")
        if not isinstance(rule, str) or not rule:
            _warn(f"{source}: allow_commands[{idx}] missing 'rule'; skipping")
            continue
        if not isinstance(command, str) or not command:
            _warn(f"{source}: allow_commands[{idx}] missing 'command'; skipping")
            continue
        if not isinstance(reason, str) or not reason:
            _warn(f"{source}: allow_commands[{idx}] missing 'reason'; skipping")
            continue
        out.append(AllowEntry(rule=rule, command=command, reason=reason, source=source))
    return out


def _warn(msg: str) -> None:
    """Emit a single-line warning to stderr (best-effort, never raises)."""
    with contextlib.suppress(OSError):
        sys.stderr.write(f"guard: allowlist: {msg}\n")
        sys.stderr.flush()


def _load_one(path: Path, source_label: str) -> tuple[list[str], list[AllowEntry], Mode | None]:
    """Parse one allowlist file. Returns ``([], [], None)`` if missing or unreadable."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], [], None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        _warn(f"{path}: invalid JSON: {exc}; ignoring file")
        return [], [], None
    if not isinstance(data, dict):
        _warn(f"{path}: top-level must be an object; ignoring file")
        return [], [], None
    rules = _validate_disable_rules(data.get("disable_rules"), source_label)
    cmds = _validate_allow_commands(data.get("allow_commands"), source_label)
    mode = _validate_mode(data.get("mode"), source_label)
    return rules, cmds, mode


def global_allowlist_path() -> Path:
    """Return the path of the global allowlist file (may not exist).

    Reads ``GUARD_DATA_DIR`` from the environment at call time so test
    fixtures that point it at a tmp dir post-import take effect (the
    module-level ``GUARD_HOME`` is fixed at import time and would
    otherwise cache the real ``~/.claude/guard``).
    """
    env_dir = os.environ.get("GUARD_DATA_DIR")
    base = Path(env_dir) if env_dir else GUARD_HOME
    return base / "allowlist.json"


def project_allowlist_path(cwd: Path | None = None) -> Path:
    """Return the path of the project allowlist file rooted at ``cwd`` (may not exist)."""
    base = cwd if cwd is not None else Path.cwd()
    return base / PROJECT_ALLOWLIST_RELPATH


# === Project allowlist trust ===


@dataclass(frozen=True)
class ProjectTrust:
    """Whether the project allowlist may loosen guard, and why.

    ``transient`` marks "couldn't ask git" verdicts: they are cached only
    briefly, so a broken git isn't re-run on every hook but isn't pinned.
    """

    trusted: bool
    reason: str
    transient: bool = False


_TRUSTED = ProjectTrust(trusted=True, reason="not tracked by git")
_GLOBAL_FILE = ProjectTrust(trusted=True, reason="it is the global allowlist")
_TRACKED = ProjectTrust(trusted=False, reason="tracked by git")
_NO_WORK_TREE = ProjectTrust(trusted=False, reason="not inside a git work tree")
_NOT_AT_ROOT = ProjectTrust(trusted=False, reason="not at the repository root")
_SYMLINKED = ProjectTrust(trusted=False, reason="reached through a symlink")

# Per-process state. Several hooks call ``load_allowlist`` more than once per
# run; the memo keeps that to one trust check and the set to one warning.
# Memo values are ``(cache key, verdict, expiry or None)``.
_TRUST_MEMO: dict[str, tuple[list[Any], ProjectTrust, float | None]] = {}
_WARNED_UNTRUSTED: set[str] = set()


def _unverifiable(why: str) -> ProjectTrust:
    return ProjectTrust(trusted=False, reason=f"unverifiable: {why}", transient=True)


def project_allowlist_trust(cwd: Path | None = None) -> ProjectTrust | None:
    """Return the trust verdict for the project allowlist, or None if there is none."""
    base = cwd if cwd is not None else Path.cwd()
    path = base / PROJECT_ALLOWLIST_RELPATH
    if not path.is_file():
        return None
    return _project_trust(base, path)


def _project_trust(base: Path, path: Path) -> ProjectTrust:
    """Trusted iff ``path`` is a regular file at a work-tree root that git does not track."""
    if _is_global_allowlist(path):
        return _GLOBAL_FILE  # with cwd = HOME the project path is the global file itself
    if _has_symlink(base):
        return _SYMLINKED
    try:
        real = path.resolve(strict=True)
        st = real.stat()
    except (OSError, RuntimeError):
        return _unverifiable("the file could not be resolved")
    found = _find_work_tree(real.parent)
    if found is None:
        return _NO_WORK_TREE
    root, index = found
    # Gitignored trees below the root (node_modules/, .venv/, vendored
    # archives) hold files nobody reviewed, so only the root's own counts.
    if root != real.parents[len(PROJECT_ALLOWLIST_RELPATH.parts) - 1]:
        return _NOT_AT_ROOT
    return _cached_git_trust(real, st, root, index)


def _is_global_allowlist(path: Path) -> bool:
    try:
        return path.samefile(global_allowlist_path())
    except OSError:
        return False


def _has_symlink(base: Path) -> bool:
    """True if any component of the project path below ``base`` is a symlink.

    A symlink can point at a tracked file git can't see through, or at a
    file git never lists (one under .git/), so any symlink is untrusted.
    """
    probe = base
    for part in PROJECT_ALLOWLIST_RELPATH.parts:
        probe /= part
        if probe.is_symlink():
            return True
    return False


def _cached_git_trust(real: Path, st: os.stat_result, root: Path, index: Path) -> ProjectTrust:
    """Per-process memo, then the on-disk cache, then git."""
    file_key = str(real)
    key = [*_stat_signature(real), str(index), *_stat_signature(index)]
    now = time.time()
    memo = _TRUST_MEMO.get(file_key)
    if memo is not None and memo[0] == key and (memo[2] is None or now < memo[2]):
        return memo[1]
    cached = _cache_lookup(file_key, key, now)
    if cached is not None:
        verdict, until = cached
    else:
        verdict = _git_trust(root, st)
        until = now + _UNVERIFIABLE_TTL_S if verdict.transient else None
        _cache_store(file_key, key, verdict, until)
    _TRUST_MEMO[file_key] = (key, verdict, until)
    return verdict


def _find_work_tree(start: Path) -> tuple[Path, Path] | None:
    """Return ``(work-tree root, index path)`` for the repo containing ``start``.

    Mirrors git's discovery: walk up to the first ``.git`` that is a valid
    git directory (a ``.git`` dir that isn't one is skipped, as git does) or
    a ``gitdir: <path>`` file (linked worktrees, submodules), where a bad
    one ends the search because git stops there with an error.
    """
    for directory in (start, *start.parents):
        dotgit = directory / ".git"
        if dotgit.is_file():
            gitdir = _read_gitfile(dotgit)
            if gitdir is None or not _is_git_dir(gitdir):
                return None
            return directory, gitdir / "index"
        if dotgit.is_dir() and _is_git_dir(dotgit):
            return directory, dotgit / "index"
    return None


def _read_gitfile(dotgit: Path) -> Path | None:
    try:
        first_line = dotgit.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, UnicodeDecodeError, IndexError):
        return None
    if not first_line.startswith("gitdir:"):
        return None
    target = first_line.removeprefix("gitdir:").strip()
    return dotgit.parent / target if target else None


def _is_git_dir(gitdir: Path) -> bool:
    """Mirror git's ``is_git_directory``: a valid HEAD, plus ``objects/`` and ``refs/``."""
    head = gitdir / "HEAD"
    try:
        if head.is_symlink():
            valid_head = head.readlink().as_posix().startswith("refs/")
        else:
            text = head.read_text(encoding="utf-8", errors="replace").strip()
            valid_head = (
                text.startswith("ref:") and text[4:].lstrip().startswith("refs/")
            ) or _HEX_OID_RE.fullmatch(text) is not None
        common = gitdir
        commondir = gitdir / "commondir"
        if commondir.is_file():
            common = gitdir / commondir.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return False
    return (
        valid_head
        and os.access(common / "objects", os.X_OK)
        and os.access(common / "refs", os.X_OK)
    )


def _stat_signature(path: Path) -> list[int]:
    try:
        st = path.stat()
    except OSError:
        return [0, 0, 0, 0]
    return [st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino]


def _git_trust(root: Path, st: os.stat_result) -> ProjectTrust:
    """Tracked iff some path in the index is the same file (device, inode) as ``st``.

    Comparing names can't work on a case- or normalization-insensitive
    filesystem: a clone whose index holds ``.claude/GUARD/a`` and
    ``.claude/guard/allowlist.json`` writes the tracked file into
    ``.claude/GUARD/``, where guard still reads it but no exact or
    ``icase`` name match finds it. So git lists every tracked path that
    could be the file under any spelling, and each one is stat'ed.
    """
    proc = _run_git_ls_files(root)
    if isinstance(proc, ProjectTrust):
        return proc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        if "not a git repository" in err:
            return _NO_WORK_TREE
        first = err.splitlines()[0] if err else f"exit {proc.returncode}"
        return _unverifiable(f"git failed ({sanitize_for_stderr(first, max_len=120)})")
    identity = (st.st_dev, st.st_ino)
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            candidate = (root / os.fsdecode(entry)).stat()
        except OSError:
            continue  # not checked out (sparse, deleted): can't be the file guard read
        if (candidate.st_dev, candidate.st_ino) == identity:
            return _TRACKED
    return _TRUSTED


def _run_git_ls_files(directory: Path) -> subprocess.CompletedProcess[bytes] | ProjectTrust:
    """List tracked project-file candidates, as paths relative to ``directory``.

    A ``ProjectTrust`` comes back when git couldn't run.
    """
    import subprocess  # noqa: PLC0415  # nosec B404 -- lazy: most hooks never get here

    argv = [
        "git",
        "-c",
        "core.fsmonitor=false",  # never run a repo-configured fsmonitor hook
        "--no-pager",
        "-C",
        str(directory),
        "ls-files",
        "-z",
        "--cached",
        "--",
        _TRACKED_CANDIDATES_PATHSPEC,
    ]
    # Drop GIT_DIR / GIT_INDEX_FILE / GIT_CONFIG_* and friends: inherited
    # overrides would make git answer about some other repo or config. The
    # C locale keeps the error text guard matches on in English.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["LC_ALL"] = "C"
    try:
        return subprocess.run(  # noqa: S603  # nosec B603 -- fixed argv list, no shell; only the cwd-derived dir varies
            argv,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError:
        return _unverifiable("git was not found")
    except subprocess.TimeoutExpired:
        return _unverifiable("the git check timed out")
    except OSError as exc:
        return _unverifiable(f"git could not run ({exc.strerror or type(exc).__name__})")


def _trust_cache_path() -> Path:
    return global_allowlist_path().parent / _TRUST_CACHE_NAME


def _cache_entries() -> dict[str, Any]:
    try:
        data = json.loads(_trust_cache_path().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version") != _TRUST_CACHE_VERSION:
        return {}
    entries = data.get("entries")
    return entries if isinstance(entries, dict) else {}


def _cache_lookup(
    file_key: str, key: list[Any], now: float
) -> tuple[ProjectTrust, float | None] | None:
    """Return ``(verdict, expiry)`` for a current entry, else None."""
    entry = _cache_entries().get(file_key)
    if not isinstance(entry, dict) or entry.get("key") != key:
        return None
    trusted = entry.get("trusted")
    reason = entry.get("reason")
    until = entry.get("until")
    if not isinstance(trusted, bool) or not isinstance(reason, str):
        return None
    if until is None:
        return ProjectTrust(trusted=trusted, reason=reason), None
    if not isinstance(until, (int, float)) or isinstance(until, bool) or now >= until:
        return None
    return ProjectTrust(trusted=trusted, reason=reason, transient=True), float(until)


def _cache_store(file_key: str, key: list[Any], verdict: ProjectTrust, until: float | None) -> None:
    """Best-effort atomic write; concurrent hooks may drop each other's entries."""
    entries = _cache_entries()
    entries.pop(file_key, None)
    entries[file_key] = {
        "key": key,
        "trusted": verdict.trusted,
        "reason": verdict.reason,
        "until": until,
    }
    while len(entries) > _TRUST_CACHE_MAX_ENTRIES:
        entries.pop(next(iter(entries)))
    path = _trust_cache_path()
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp_name = tempfile.mkstemp(prefix=".project-trust-", dir=path.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"version": _TRUST_CACHE_VERSION, "entries": entries}, fh)
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)


def _warn_untrusted(path: Path, trust: ProjectTrust, base_mode: Mode) -> None:
    """One stderr warning per process per file, never on stdout."""
    try:
        key = str(path.resolve())
    except (OSError, RuntimeError):
        key = str(path)
    if key in _WARNED_UNTRUSTED:
        return
    _WARNED_UNTRUSTED.add(key)
    shown = sanitize_for_stderr(str(path), max_len=400)
    # This can reach the model on a deny, so it says what and why but leaves
    # the way to make the file trusted to `guard status`.
    _warn(
        f"project allowlist at {shown} is untrusted ({trust.reason}), so its loosening "
        f"entries are ignored (disable_rules, allow_commands, and any mode looser than "
        f"{base_mode!r}). Run `guard status` for details."
    )


def hook_bypass_reason(allowlist: Allowlist, hook_id: str, excerpt: str) -> str | None:
    """Return an audit-log ``reason`` string if the hook should bypass, else ``None``.

    Convenience helper for hooks whose only rule_id is the hook_id itself
    (e.g. ``protected_files``, ``git_c_validator``). For each such hook,
    two allowlist mechanisms apply:

    1. ``disable_rules: ["<hook_id>"]`` — mute the whole hook.
    2. ``allow_commands: [{rule: "<hook_id>", command: "...", reason: ...}]``
       — mute when the file path / command excerpt matches exactly.

    Callers log a ``decision="pass"`` record with the returned string and
    skip emitting an envelope, letting Claude Code default-allow.
    """
    if allowlist.is_rule_disabled(hook_id):
        return f"allowlist: rule '{hook_id}' disabled by user config"
    entry = allowlist.find_command(hook_id, excerpt)
    if entry is not None:
        return f"allowlist: {entry.reason} (rule={hook_id})"
    return None


def apply_decision(  # noqa: PLR0913 -- hook id, payload, envelope, excerpt + two policy flags
    hook_id: str,
    payload: dict[str, Any],
    envelope: dict[str, Any],
    excerpt: str,
    *,
    trust_root: bool = False,
    overridable: bool = True,
) -> None:
    """Log a hook's decision and hand it to Claude Code, honoring guard mode.

    ``off`` emits nothing and ``shadow`` logs a deny without emitting it,
    except for ``trust_root`` decisions (guard's own files), which hold in
    every mode. An allowlist entry for ``hook_id`` turns the decision into
    a logged pass unless ``overridable`` is False. A deny exits 2.
    """
    allowlist = load_allowlist()
    hso = envelope["hookSpecificOutput"]
    decision = hso["permissionDecision"]
    if allowlist.mode == "off" and not trust_root:
        return
    tool_name = payload.get("tool_name")
    cwd = payload.get("cwd")
    record: dict[str, Any] = {
        "hook_id": hook_id,
        "event": "PreToolUse",
        "tool_name": tool_name if isinstance(tool_name, str) else None,
        "command_excerpt": excerpt,
        "session_id": str(payload.get("session_id", "")),
        "cwd": cwd if isinstance(cwd, str) else None,
        "mode": allowlist.mode,
    }
    bypass = hook_bypass_reason(allowlist, hook_id, excerpt) if overridable else None
    if bypass is not None:
        log_decision(decision="pass", reason=bypass, **record)
        return
    log_decision(decision=decision, reason=hso["permissionDecisionReason"], **record)
    if decision == "deny" and allowlist.mode == "shadow" and not trust_root:
        return
    sys.stdout.write(json.dumps(envelope))
    if decision == "deny":
        sys.exit(2)


# === Mutation API (CLI helpers) ===
#
# Each mutation reads the file, edits in-memory, writes back atomically. The
# format is human-friendly: 2-space indent, sorted keys at the top level,
# trailing newline. Files don't have to exist before mutation — they're
# created on first add. Empty after a remove? We leave the empty document
# rather than delete the file so users can git-track its presence.


_ALLOWLIST_FILE_TEMPLATE: dict[str, list[Any]] = {
    "disable_rules": [],
    "allow_commands": [],
}


def _read_raw(path: Path) -> dict[str, Any]:
    """Read+parse an allowlist file. Returns an empty template if absent.

    Preserves any top-level fields outside the known schema so that a
    mutation (e.g. ``add_disable_rule``) doesn't strip an unrelated field
    like ``mode``. Only ``disable_rules`` and ``allow_commands`` are
    normalised; everything else is passed through verbatim.
    """
    empty: dict[str, Any] = {"disable_rules": [], "allow_commands": []}
    if not path.exists():
        return empty
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return empty
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    rules = data.get("disable_rules") or []
    cmds = data.get("allow_commands") or []
    doc = dict(data)
    doc["disable_rules"] = list(rules) if isinstance(rules, list) else []
    doc["allow_commands"] = list(cmds) if isinstance(cmds, list) else []
    return doc


def _write_raw(path: Path, doc: dict[str, Any]) -> None:
    """Atomically write the doc with mode 0o600 inside a 0o700 parent dir."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def add_disable_rule(rule_id: str, *, scope: str = "project", cwd: Path | None = None) -> bool:
    """Add ``rule_id`` to the chosen scope's ``disable_rules``.

    Returns ``True`` if the rule was added, ``False`` if it was already
    present (idempotent).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id in rules:
        return False
    rules.append(rule_id)
    _write_raw(path, doc)
    return True


def remove_disable_rule(rule_id: str, *, scope: str = "project", cwd: Path | None = None) -> bool:
    """Remove ``rule_id`` from the chosen scope's ``disable_rules``.

    Returns ``True`` if the rule was removed, ``False`` if it wasn't
    present (idempotent).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    rules: list[Any] = doc["disable_rules"]
    if rule_id not in rules:
        return False
    doc["disable_rules"] = [r for r in rules if r != rule_id]
    _write_raw(path, doc)
    return True


def add_allow_command(
    *,
    rule: str,
    command: str,
    reason: str,
    scope: str = "project",
    cwd: Path | None = None,
) -> bool:
    """Add an exact-command override to the chosen scope's ``allow_commands``.

    Returns ``True`` if added, ``False`` if an entry with the same
    ``(rule, command)`` already exists (idempotent — does not update the
    reason; remove first to change a reason).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    cmds: list[Any] = doc["allow_commands"]
    for e in cmds:
        if isinstance(e, dict) and e.get("rule") == rule and e.get("command") == command:
            return False
    cmds.append({"rule": rule, "command": command, "reason": reason})
    _write_raw(path, doc)
    return True


def remove_allow_command(
    *,
    rule: str,
    command: str,
    scope: str = "project",
    cwd: Path | None = None,
) -> bool:
    """Remove an exact-command override matching ``(rule, command)``.

    Returns ``True`` if removed, ``False`` if no matching entry was found.
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    cmds: list[Any] = doc["allow_commands"]
    new = [
        e
        for e in cmds
        if not (isinstance(e, dict) and e.get("rule") == rule and e.get("command") == command)
    ]
    if len(new) == len(cmds):
        return False
    doc["allow_commands"] = new
    _write_raw(path, doc)
    return True


def set_mode(value: Mode, *, scope: str = "project", cwd: Path | None = None) -> Mode | None:
    """Write ``mode`` to the chosen scope's allowlist file.

    Returns the previous mode value (``None`` if absent / default).
    """
    path = _resolve_scope_path(scope, cwd)
    doc = _read_raw(path)
    previous = doc.get("mode")
    prev_validated = _validate_mode(previous, scope) if previous is not None else None
    doc["mode"] = value
    _write_raw(path, doc)
    return prev_validated


def _resolve_scope_path(scope: str, cwd: Path | None) -> Path:
    if scope == "global":
        return global_allowlist_path()
    if scope == "project":
        return project_allowlist_path(cwd)
    msg = f"unknown scope {scope!r} (expected 'global' or 'project')"
    raise ValueError(msg)


def load_allowlist(cwd: Path | None = None) -> Allowlist:
    """Load and merge the global + project allowlists.

    Order in the returned ``allow_commands`` tuple: project entries first,
    then global entries, preserving file order within each. Match priority
    is irrelevant for correctness (find_command returns the first hit),
    but project-first keeps ``guard allowlist list`` predictable.

    Missing files are silently skipped. Malformed files emit a warning to
    stderr and contribute nothing.

    An untrusted project file (see the module docstring) can only tighten:
    its lists are dropped and its mode counts only when stricter than the
    global/default mode. Trust is checked only when the file would loosen
    something, so a missing or tighten-only project file never spawns git.
    """
    sources: list[Path] = []
    base = cwd if cwd is not None else Path.cwd()
    project_path = base / PROJECT_ALLOWLIST_RELPATH
    project_rules, project_cmds, project_mode = _load_one(project_path, "project")
    if project_path.exists():
        sources.append(project_path)

    global_path = global_allowlist_path()
    global_rules, global_cmds, global_mode = _load_one(global_path, "global")
    if global_path.exists():
        sources.append(global_path)

    base_mode: Mode = global_mode or _DEFAULT_MODE
    looser_mode = project_mode is not None and _MODE_RANK[project_mode] < _MODE_RANK[base_mode]
    if project_rules or project_cmds or looser_mode:
        trust = _project_trust(base, project_path)
        if not trust.trusted:
            _warn_untrusted(project_path, trust, base_mode)
            project_rules, project_cmds = [], []
            if looser_mode:
                project_mode = None

    # Trusted project beats global beats default, so an operator flipping
    # their own project file to ``shadow`` doesn't leak the experiment
    # across the rest of their machine.
    effective_mode: Mode = project_mode or base_mode

    return Allowlist(
        disable_rules=frozenset(project_rules) | frozenset(global_rules),
        allow_commands=(*project_cmds, *global_cmds),
        sources=tuple(sources),
        mode=effective_mode,
    )
