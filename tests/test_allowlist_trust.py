"""Project allowlist trust: a git-tracked project file can only tighten.

A repo anyone can clone could ship ``.claude/guard/allowlist.json`` with
``{"mode": "off"}``. Guard trusts the project file only when it sits at a git
work-tree root and is not tracked (untracked or gitignored). Anything else may
only tighten the mode; its ``disable_rules`` and ``allow_commands`` are
ignored. Every test here uses a real temp git repo.
"""

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests._helpers import REPO_ROOT, decision_from_stdout, git, init_git_repo

_REL = Path(".claude") / "guard" / "allowlist.json"

_LOOSE_DOC: dict[str, Any] = {
    "mode": "off",
    "disable_rules": ["bash.disk_destruction"],
    "allow_commands": [
        {"rule": "bash.git_force_push", "command": "git push --force", "reason": "ship it"}
    ],
}


@pytest.fixture(autouse=True)
def _fresh_trust_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts like a new hook process: empty memo, no warnings yet."""
    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})
    monkeypatch.setattr("guard.allowlist._WARNED_UNTRUSTED", set())


def _write(path: Path, doc: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _project(repo: Path, doc: dict[str, Any], *, track: bool = False) -> Path:
    path = _write(repo / _REL, doc)
    if track:
        git(repo, "add", "-f", str(_REL))
    return path


def _global(doc: dict[str, Any]) -> None:
    _write(Path(os.environ["GUARD_DATA_DIR"]) / "allowlist.json", doc)


def _count_git_queries(
    monkeypatch: pytest.MonkeyPatch, envs: list[dict[str, str]] | None = None
) -> list[list[str]]:
    """Record every ``git ls-files`` trust query (and its env) while still running it."""
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spy(argv: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(argv, list) and "ls-files" in argv:
            calls.append(list(argv))
            if envs is not None:
                envs.append(dict(kwargs.get("env") or {}))
        return real_run(argv, *args, **kwargs)

    # Patch the module itself: guard imports subprocess lazily, on first use.
    monkeypatch.setattr(subprocess, "run", spy)
    return calls


def _patch_git(monkeypatch: pytest.MonkeyPatch, fake: Any) -> None:
    monkeypatch.setattr(subprocess, "run", fake)


def _add_index_entries(repo: Path, entries: list[str], *, precompose: bool = True) -> None:
    """Write ``entries`` (all ``{"mode": "off"}``) straight into the index.

    ``update-index`` takes any name, so entries can differ only in case or
    Unicode form, or carry characters a filesystem ignores, without the
    working tree ever holding them.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    argv = ["git", "-C", str(repo), "hash-object", "-w", "--stdin"]
    blob = (
        subprocess.run(
            argv,
            input=b'{"mode": "off"}',
            capture_output=True,
            env=env,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    cfg = ("-c", f"core.precomposeunicode={str(precompose).lower()}")
    for entry in entries:
        git(repo, *cfg, "update-index", "--add", "--cacheinfo", f"100644,{blob},{entry}")


def _clone_with_entries(tmp_path: Path, entries: list[str], *, precompose: bool = True) -> Path:
    """Clone a repo whose index holds ``entries`` (all ``{"mode": "off"}``).

    The entries can differ only in case or Unicode form, which a case- and
    normalization-insensitive filesystem (APFS) folds into one directory.
    """
    src = init_git_repo(tmp_path / "src")
    _add_index_entries(src, entries, precompose=precompose)
    cfg = ("-c", f"core.precomposeunicode={str(precompose).lower()}")
    git(
        src,
        *cfg,
        *("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"),
        *("commit", "-q", "--no-verify", "-m", "x"),
    )
    dst = tmp_path / "clone"
    git(tmp_path, "clone", "-q", str(src), str(dst))
    return dst


# === Untrusted (tracked) files can only tighten ===


def test_tracked_mode_off_is_ignored_and_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    path = _project(repo, {"mode": "off"}, track=True)

    al = load_allowlist(cwd=repo)

    assert al.mode == "enforce"
    err = capsys.readouterr().err
    assert str(path) in err
    assert "tracked by git" in err
    assert "guard status" in err
    # On a deny this reaches the model: never spell out the way to trust it.
    assert "git rm" not in err
    assert "gitignore" not in err


def test_tracked_mode_off_falls_back_to_global_mode(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"}, track=True)
    _global({"mode": "shadow"})

    assert load_allowlist(cwd=repo).mode == "shadow"


def test_tracked_lists_are_ignored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(
        repo,
        {
            "disable_rules": _LOOSE_DOC["disable_rules"],
            "allow_commands": _LOOSE_DOC["allow_commands"],
        },
        track=True,
    )

    al = load_allowlist(cwd=repo)

    assert al.disable_rules == frozenset()
    assert al.allow_commands == ()
    assert "tracked by git" in capsys.readouterr().err


def test_tracked_file_keeps_global_lists(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, _LOOSE_DOC, track=True)
    _global({"disable_rules": ["bash.npx_remote"]})

    al = load_allowlist(cwd=repo)

    assert al.disable_rules == {"bash.npx_remote"}
    assert al.allow_commands == ()


def test_tracked_lockdown_still_tightens(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "lockdown"}, track=True)

    assert load_allowlist(cwd=repo).mode == "lockdown"
    # Nothing was ignored, so there is nothing to warn about.
    assert "allowlist" not in capsys.readouterr().err


def test_tracked_enforce_tightens_a_shadow_global(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "enforce"}, track=True)
    _global({"mode": "shadow"})

    assert load_allowlist(cwd=repo).mode == "enforce"


def test_tightening_only_file_needs_no_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "lockdown"}, track=True)
    calls = _count_git_queries(monkeypatch)

    assert load_allowlist(cwd=repo).mode == "lockdown"
    assert calls == []


def test_warning_fires_once_per_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"}, track=True)

    load_allowlist(cwd=repo)
    load_allowlist(cwd=repo)
    load_allowlist(cwd=repo)

    assert capsys.readouterr().err.count("tracked by git") == 1


# === Trusted (not tracked) files behave exactly as before ===


def test_gitignored_file_is_fully_honored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text(".claude/\n", encoding="utf-8")
    _project(repo, _LOOSE_DOC)
    _global({"mode": "lockdown"})

    al = load_allowlist(cwd=repo)

    assert al.mode == "off"
    assert al.disable_rules == {"bash.disk_destruction"}
    assert al.find_command("bash.git_force_push", "git push --force") is not None
    assert capsys.readouterr().err == ""


def test_untracked_not_ignored_file_is_honored(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist, project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, _LOOSE_DOC)

    al = load_allowlist(cwd=repo)

    assert al.mode == "off"
    assert al.disable_rules == {"bash.disk_destruction"}
    trust = project_allowlist_trust(repo)
    assert trust is not None
    assert trust.trusted is True


def test_untracked_file_in_a_linked_worktree_is_honored(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    main = init_git_repo(tmp_path / "main")
    (main / "README").write_text("x\n", encoding="utf-8")
    git(main, "add", "README")
    git(
        main,
        *("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"),
        *("commit", "-q", "--no-verify", "-m", "x"),
    )
    wt = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "--detach", str(wt))
    _project(wt, {"mode": "shadow"})

    assert load_allowlist(cwd=wt).mode == "shadow"


# === Fail closed: anything we can't verify is untrusted ===


def test_file_outside_any_git_repo_is_untrusted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from guard.allowlist import load_allowlist, project_allowlist_trust

    project = tmp_path / "not-a-repo"
    _project(project, _LOOSE_DOC)

    al = load_allowlist(cwd=project)

    assert al.mode == "enforce"
    assert al.disable_rules == frozenset()
    assert "not inside a git work tree" in capsys.readouterr().err
    trust = project_allowlist_trust(project)
    assert trust is not None
    assert trust.trusted is False


@pytest.mark.parametrize(
    ("outcome", "reason_fragment"),
    [
        (FileNotFoundError("git"), "git was not found"),
        (subprocess.TimeoutExpired(["git"], 2.0), "timed out"),
        (
            subprocess.CompletedProcess(["git"], 128, b"", b"fatal: index file corrupt"),
            "git failed",
        ),
        (PermissionError(13, "Permission denied"), "git could not run"),
    ],
    ids=["missing", "timeout", "error", "oserror"],
)
def test_git_failure_means_untrusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: object,
    reason_fragment: str,
) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, _LOOSE_DOC)  # untracked: trusted if git could say so

    def broken_git(*_args: Any, **_kwargs: Any) -> Any:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    _patch_git(monkeypatch, broken_git)

    al = load_allowlist(cwd=repo)

    assert al.mode == "enforce"
    assert al.disable_rules == frozenset()
    assert reason_fragment in capsys.readouterr().err


def test_git_failure_is_cached_briefly_then_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow or broken git isn't re-run on every hook, but isn't pinned either."""
    import time

    from guard.allowlist import project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, _LOOSE_DOC)

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(["git"], 2.0)

    with monkeypatch.context() as m:
        m.setattr(subprocess, "run", timeout)
        first = project_allowlist_trust(repo)
    assert first is not None
    assert first.trusted is False

    calls = _count_git_queries(monkeypatch)
    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})  # next hook process
    second = project_allowlist_trust(repo)
    assert second == first
    assert calls == []  # still inside the short window: served from the cache

    later = time.time() + 61
    monkeypatch.setattr(time, "time", lambda: later)
    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})
    third = project_allowlist_trust(repo)
    assert third is not None
    assert third.trusted is True
    assert len(calls) == 1


def test_git_runs_with_c_locale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Error text guard inspects must not depend on the user's locale."""
    from guard.allowlist import project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, _LOOSE_DOC)
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    envs: list[dict[str, str]] = []
    _count_git_queries(monkeypatch, envs)

    project_allowlist_trust(repo)

    assert envs
    assert envs[0]["LC_ALL"] == "C"


# === Path tricks that would dodge a naive check ===


def test_tracked_symlinked_dir_is_untrusted(tmp_path: Path) -> None:
    """``.claude/guard`` as a tracked symlink: git can't see the file behind it."""
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _write(repo / "evil" / "allowlist.json", {"mode": "off"})
    (repo / ".claude").mkdir()
    (repo / ".claude" / "guard").symlink_to(Path("..") / "evil")
    git(repo, "add", ".")

    assert load_allowlist(cwd=repo).mode == "enforce"


def test_symlinked_file_is_untrusted_even_when_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A symlink can point at a file git never tracks, such as one under ``.git``."""
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text(".claude/\n", encoding="utf-8")
    _write(repo / ".git" / "lfs" / "evil.json", {"mode": "off"})
    (repo / ".claude" / "guard").mkdir(parents=True)
    (repo / _REL).symlink_to(Path("..") / ".." / ".git" / "lfs" / "evil.json")

    assert load_allowlist(cwd=repo).mode == "enforce"
    assert "symlink" in capsys.readouterr().err


def _case_insensitive_fs(probe_dir: Path) -> bool:
    probe = probe_dir / "CaseProbe"
    probe.write_text("", encoding="utf-8")
    try:
        return (probe_dir / "caseprobe").exists()
    finally:
        probe.unlink()


def test_tracked_file_under_other_case_is_untrusted(tmp_path: Path) -> None:
    """On macOS a tracked ``.CLAUDE/GUARD/allowlist.json`` is what guard reads."""
    from guard.allowlist import load_allowlist

    if not _case_insensitive_fs(tmp_path):
        pytest.skip("case-sensitive filesystem: the upper-case file is a different file")
    repo = init_git_repo(tmp_path / "repo")
    _write(repo / ".CLAUDE" / "GUARD" / "AllowList.JSON", {"mode": "off"})
    git(repo, "add", ".")

    assert (repo / _REL).exists()
    assert load_allowlist(cwd=repo).mode == "enforce"


# Case splits: the index tracks ``.claude/guard/allowlist.json``, but an
# earlier entry makes the clone create a parent directory under another case
# (or Unicode form). On APFS the tracked file then lands in that directory,
# where guard still reads it. On a case-sensitive filesystem these are
# separate directories, and the assertions hold trivially.


@pytest.mark.parametrize(
    "entries",
    [
        [".claude/GUARD/a", ".claude/guard/allowlist.json"],
        [".CLAUDE/x", ".claude/guard/allowlist.json"],
        [".claude/guard/allowli\u017ft.json"],  # APFS folds U+017F (long s) to "s"
    ],
    ids=["guard-dir-case", "claude-dir-case", "long-s-filename"],
)
def test_case_split_clone_is_untrusted(tmp_path: Path, entries: list[str]) -> None:
    from guard.allowlist import load_allowlist, project_allowlist_trust

    clone = _clone_with_entries(tmp_path, entries)
    if not (clone / _REL).exists():
        pytest.skip("this filesystem keeps the split names apart")

    assert load_allowlist(cwd=clone).mode == "enforce"
    trust = project_allowlist_trust(clone)
    assert trust is not None
    assert trust.trusted is False
    assert trust.reason == "tracked by git"


@pytest.mark.parametrize(
    ("entries", "precompose", "subdir"),
    [
        # U+017F (long s): APFS puts "\u017frc/" and "src/" in one directory.
        (["src/README", "\u017frc/.claude/guard/allowlist.json"], True, "src"),
        # NFC "\u00e9t\u00e9/" and NFD "e\u0301te\u0301/": one directory on APFS.
        (
            ["\u00e9t\u00e9/README", "e\u0301te\u0301/.claude/guard/allowlist.json"],
            False,
            "\u00e9t\u00e9",
        ),
    ],
    ids=["long-s-subdir", "nfd-subdir"],
)
def test_unicode_split_subdir_clone_is_untrusted(
    tmp_path: Path, entries: list[str], *, precompose: bool, subdir: str
) -> None:
    from guard.allowlist import load_allowlist

    clone = _clone_with_entries(tmp_path, entries, precompose=precompose)

    assert load_allowlist(cwd=clone / subdir).mode == "enforce"


# Case-insensitive HFS+ ignores U+200C-200F, U+202A-202E, U+206A-206F and
# U+FEFF in names, so a clone there writes these tracked entries to the very
# file guard reads. The identity check catches them only if git lists them.
_HFS_IGNORABLE_ENTRIES = [
    f".clau{chr(0x200C)}de/guard/allowlist.json",
    f".claude/gu{chr(0xFEFF)}ard/allowlist.json",
    f"{chr(0x206A)}.claude/guard/allowlist.json",
    f".claude{chr(0x202A)}/guard{chr(0x200F)}/allowlist.json",
]


@pytest.mark.parametrize(
    "entry", _HFS_IGNORABLE_ENTRIES, ids=["in-claude", "in-guard", "before-dot", "after-names"]
)
def test_hfs_ignorable_spellings_are_listed_for_the_identity_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    """No HFS+ volume needed: what matters is that git lists the entry to stat."""
    from guard.allowlist import ProjectTrust, _run_git_ls_files

    repo = init_git_repo(tmp_path / "repo")
    _add_index_entries(repo, [entry])

    def listed() -> set[bytes]:
        proc = _run_git_ls_files(repo)
        assert not isinstance(proc, ProjectTrust)
        assert proc.returncode == 0
        return {e for e in proc.stdout.split(b"\0") if e}

    assert entry.encode() in listed()
    # Control: a pathspec that spells the directory names out misses it.
    monkeypatch.setattr(
        "guard.allowlist._TRACKED_CANDIDATES_PATHSPEC", ":(top,icase,glob)**/.claude/guard/*"
    )
    assert entry.encode() not in listed()


# === Only a file at the repository root can be trusted ===


def test_gitignored_dependency_tree_is_untrusted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A package can ship the file inside a gitignored node_modules/ or .venv/."""
    from guard.allowlist import load_allowlist, project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    pkg = repo / "node_modules" / "evil-pkg"
    _project(pkg, _LOOSE_DOC)

    assert load_allowlist(cwd=pkg).mode == "enforce"
    assert "not at the repository root" in capsys.readouterr().err
    trust = project_allowlist_trust(pkg)
    assert trust is not None
    assert trust.trusted is False
    assert trust.reason == "not at the repository root"


def test_untracked_file_in_a_subdirectory_is_untrusted(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo / "pkg", {"mode": "off"})

    assert load_allowlist(cwd=repo / "pkg").mode == "enforce"


def test_invalid_git_dir_is_skipped_like_git_does(tmp_path: Path) -> None:
    """An empty ``proj/.git`` is not a repo: the real work tree is the parent."""
    from guard.allowlist import project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    proj = repo / "proj"
    _project(proj, {"mode": "off"})
    (proj / ".git").mkdir()

    trust = project_allowlist_trust(proj)
    assert trust is not None
    assert trust.reason == "not at the repository root"


def test_cache_keys_on_the_real_index_past_an_invalid_git_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty ``.git`` dir below the root must not become the cache key."""
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"})
    (repo / ".claude" / "guard" / ".git").mkdir()
    assert load_allowlist(cwd=repo).mode == "off"

    git(repo, "add", "-f", str(_REL))
    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})  # next hook process
    assert load_allowlist(cwd=repo).mode == "enforce"


def test_global_allowlist_read_as_project_file_is_not_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With cwd = HOME the project path is the global file itself."""
    from guard.allowlist import load_allowlist, project_allowlist_trust

    home = tmp_path / "home"
    monkeypatch.setenv("GUARD_DATA_DIR", str(home / ".claude" / "guard"))
    _global({"mode": "shadow", "disable_rules": ["bash.npx_remote"]})
    calls = _count_git_queries(monkeypatch)

    al = load_allowlist(cwd=home)

    assert al.mode == "shadow"
    assert al.disable_rules == {"bash.npx_remote"}
    assert capsys.readouterr().err == ""
    assert calls == []
    trust = project_allowlist_trust(home)
    assert trust is not None
    assert trust.trusted is True
    assert trust.reason == "it is the global allowlist"


# === Cost: git runs only when it matters, and its verdict is cached ===


def test_no_project_file_runs_no_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from guard.allowlist import load_allowlist, project_allowlist_trust

    repo = init_git_repo(tmp_path / "repo")
    _global({"mode": "shadow", "disable_rules": ["bash.npx_remote"]})

    def no_subprocess(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("no project allowlist, so guard must not spawn git")

    _patch_git(monkeypatch, no_subprocess)

    assert load_allowlist(cwd=repo).mode == "shadow"
    assert project_allowlist_trust(repo) is None


def test_loading_guard_allowlist_does_not_import_subprocess() -> None:
    """Hooks with no project file shouldn't pay for importing subprocess."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    probe = "import sys, guard.allowlist; print('subprocess' in sys.modules)"
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, env=env, check=True
    )
    assert out.stdout.strip() == "False"


def test_trust_verdict_cached_until_index_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"})
    calls = _count_git_queries(monkeypatch)

    assert load_allowlist(cwd=repo).mode == "off"
    assert len(calls) == 1

    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})  # next hook process
    assert load_allowlist(cwd=repo).mode == "off"
    assert len(calls) == 1  # served from the on-disk cache

    git(repo, "add", "-f", str(_REL))  # rewrites the index
    monkeypatch.setattr("guard.allowlist._TRUST_MEMO", {})
    assert load_allowlist(cwd=repo).mode == "enforce"
    assert len(calls) == 2


def test_trust_cache_lives_in_guard_data_dir(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"})
    load_allowlist(cwd=repo)

    cache = Path(os.environ["GUARD_DATA_DIR"]) / "project-trust-cache.json"
    assert cache.is_file()
    assert str((repo / _REL).resolve()) in json.loads(cache.read_text(encoding="utf-8"))["entries"]


def test_corrupt_trust_cache_is_a_miss(tmp_path: Path) -> None:
    from guard.allowlist import load_allowlist

    repo = init_git_repo(tmp_path / "repo")
    _project(repo, {"mode": "off"})
    _write(Path(os.environ["GUARD_DATA_DIR"]) / "project-trust-cache.json", {"entries": []})

    assert load_allowlist(cwd=repo).mode == "off"


# === End to end: the real hook in a repo that ships mode: off ===


def test_hook_in_repo_with_tracked_mode_off_still_denies(tmp_path: Path) -> None:
    repo = init_git_repo(tmp_path / "repo")
    path = _project(repo, {"mode": "off"}, track=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    env["GUARD_DATA_DIR"] = str(tmp_path / "guard-home")
    env["GUARD_DECISIONS_PATH"] = str(tmp_path / "decisions.jsonl")
    env["GUARD_STRICT_DENY_QUEUE_PATH"] = os.devnull
    payload = {
        "session_id": "trust-e2e",
        "tool_name": "Bash",
        "tool_input": {"command": "git push --force origin main"},
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "permission_mode": "default",
    }

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "src" / "guard" / "hooks" / "bash_command_validator.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=repo,
        timeout=30,
        check=False,
    )

    assert proc.returncode == 2
    assert decision_from_stdout(proc.stdout) == "deny"
    assert "tracked by git" not in proc.stdout
    assert proc.stderr.count(f"project allowlist at {path}") == 1
