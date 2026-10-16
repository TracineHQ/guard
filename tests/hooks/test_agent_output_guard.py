# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Tests for agent_output_guard hook.

The hook classifies ``tasks/*.output`` paths on disk, so most tests build a
real session tree under ``/tmp/claude-<n>/`` (the prefix the hook matches)
with background command output, symlinked subagent transcripts and legacy
in-place transcripts. Paths that do not exist exercise the fail-closed
"unverified" branch.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from guard.hooks.agent_output_guard import _SNIFF_BYTES, classify, decide, hook

if TYPE_CHECKING:
    from collections.abc import Iterator

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "guard" / "hooks" / "agent_output_guard.py"
)

_TRANSCRIPT_RECORD = {
    "parentUuid": None,
    "isSidechain": True,
    "agentId": "a00000000000000aa",
    "type": "user",
    "message": {"role": "user", "content": "do the thing"},
    "uuid": "u-1",
    "sessionId": "s-1",
}


def _is_deny(result) -> bool:
    return result is not None and result["hookSpecificOutput"]["permissionDecision"] == "deny"


def _reason(result) -> str:
    assert result is not None
    return result["hookSpecificOutput"]["permissionDecisionReason"]


class Session:
    """A real Claude Code-shaped session tree under ``/tmp/claude-<n>/``."""

    def __init__(self, root: Path, home: Path) -> None:
        self.root = root
        self.cwd = root / "proj" / "sess"
        self.tasks = self.cwd / "tasks"
        self.tasks.mkdir(parents=True)
        self.subagents = home / "projects" / "proj" / "sess" / "subagents"
        self.subagents.mkdir(parents=True)

    def background(self, name: str = "b9o35r1xd", text: str = "build ok\n") -> str:
        path = self.tasks / f"{name}.output"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def transcript_link(self, agent_id: str = "a00000000000000aa") -> str:
        target = self.subagents / f"agent-{agent_id}.jsonl"
        target.write_text(json.dumps(_TRANSCRIPT_RECORD) + "\n", encoding="utf-8")
        link = self.tasks / f"{agent_id}.output"
        link.symlink_to(target)
        return str(link)

    def legacy_transcript(self, name: str = "a00000000000000bb") -> str:
        path = self.tasks / f"{name}.output"
        lines = [json.dumps({**_TRANSCRIPT_RECORD, "uuid": f"u-{i}"}) for i in range(3)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    """Build a session tree under ``/tmp/claude-<n>/`` and remove it afterwards."""
    for _ in range(100):
        root = Path(f"/tmp/claude-9{os.getpid()}{random.randrange(10**6)}")  # noqa: S311 -- unique dir name, not crypto
        try:
            root.mkdir()
        except FileExistsError:
            continue
        break
    else:  # pragma: no cover -- 100 collisions in a row
        pytest.fail("could not create a /tmp/claude-<n> session dir")
    try:
        yield Session(root, tmp_path / "claude-home")
    finally:
        shutil.rmtree(root, ignore_errors=True)


class TestClassify:
    """On-disk classification of concrete tasks/*.output paths."""

    def test_background_output_is_output(self, session: Session):
        assert classify(session.background()) == "output"

    def test_empty_background_output_is_output(self, session: Session):
        assert classify(session.background(text="")) == "output"

    def test_large_plain_text_output_is_output(self, session: Session):
        big = "line of build log\n" * (3 * 1024 * 1024 // 18)
        path = session.background(text=big)
        assert Path(path).stat().st_size > 2 * 1024 * 1024
        assert classify(path) == "output"

    def test_json_background_output_is_output(self, session: Session):
        """A backgrounded ``gh api`` / ``jq`` dump is JSON but not a transcript."""
        body = json.dumps({"items": [{"id": i, "name": f"n{i}"} for i in range(5000)]})
        assert classify(session.background(text=body + "\n")) == "output"

    def test_symlinked_transcript_is_transcript(self, session: Session):
        assert classify(session.transcript_link()) == "transcript"

    def test_dangling_transcript_link_is_transcript(self, session: Session):
        link = session.transcript_link()
        Path(os.path.realpath(link)).unlink()
        assert classify(link) == "transcript"

    def test_link_into_subagents_dir_is_transcript(self, session: Session):
        """The target dir alone is enough, whatever the file suffix."""
        target = session.subagents / "agent-x.log"
        target.write_text("plain\n", encoding="utf-8")
        link = session.tasks / "ax.output"
        link.symlink_to(target)
        assert classify(str(link)) == "transcript"

    def test_legacy_in_place_transcript_is_transcript(self, session: Session):
        assert classify(session.legacy_transcript()) == "transcript"

    def test_transcript_with_huge_first_line_is_transcript(self, session: Session):
        record = {**_TRANSCRIPT_RECORD, "message": {"content": "x" * (2 * _SNIFF_BYTES)}}
        path = session.background(name="abig", text=json.dumps(record) + "\n")
        assert classify(path) == "transcript"

    def test_symlink_to_plain_text_is_sniffed(self, session: Session, tmp_path: Path):
        target = tmp_path / "log.txt"
        target.write_text("plain text\n", encoding="utf-8")
        link = session.tasks / "blink.output"
        link.symlink_to(target)
        assert classify(str(link)) == "output"

    def test_missing_file_is_unverified(self, session: Session):
        assert classify(str(session.tasks / "bnothere1.output")) == "unverified"

    def test_directory_is_unverified(self, session: Session):
        d = session.tasks / "bdir.output"
        d.mkdir()
        assert classify(str(d)) == "unverified"

    def test_unreadable_file_is_unverified(self, session: Session):
        if os.geteuid() == 0:
            pytest.skip("root reads mode-000 files")
        path = Path(session.background(name="blocked"))
        path.chmod(0)
        try:
            assert classify(str(path)) == "unverified"
        finally:
            path.chmod(0o600)

    @pytest.mark.parametrize("glob", ["*.output", "b?.output", "[ab]1.output", "{a,b}.output"])
    def test_glob_is_wildcard(self, session: Session, glob: str):
        assert classify(f"{session.tasks}/{glob}") == "wildcard"


class TestBackgroundOutputAllowed:
    """Agents may read the output of the background commands they started."""

    @pytest.mark.parametrize(
        "template",
        [
            "cat {p}",
            "tail -n 50 {p}",
            "head -20 {p}",
            "grep -n error {p}",
            "rg -n warn {p}",
            "wc -l {p}",
            'cat "{p}"',
            "cat {p} | tail -5",
            "tail -n 5 {p} 2>/dev/null; echo done",
        ],
    )
    def test_bash_read_allowed(self, session: Session, template: str):
        assert decide("Bash", {"command": template.format(p=session.background())}) is None

    def test_read_tool_allowed(self, session: Session):
        assert decide("Read", {"file_path": session.background()}) is None

    def test_grep_tool_allowed(self, session: Session):
        assert decide("Grep", {"pattern": "x", "path": session.background()}) is None

    def test_large_plain_text_read_allowed(self, session: Session):
        path = session.background(text="0123456789abcdef\n" * 200_000)
        assert decide("Read", {"file_path": path}) is None
        assert decide("Bash", {"command": f"tail -100 {path}"}) is None

    def test_two_background_outputs_allowed(self, session: Session):
        a = session.background(name="b1aaaaaaa")
        b = session.background(name="b2bbbbbbb")
        assert decide("Bash", {"command": f"cat {a} {b}"}) is None

    def test_cwd_relative_background_read_allowed(self, session: Session):
        session.background(name="brel00001")
        cmd = "cat tasks/brel00001.output"
        assert decide("Bash", {"command": cmd}, cwd=str(session.cwd)) is None

    def test_linux_style_tmp_prefix_allowed(self, session: Session):
        # The fixture already lives under /tmp/claude-<n>/, the Linux form.
        path = session.background()
        assert path.startswith("/tmp/claude-")
        assert decide("Read", {"file_path": path}) is None


class TestTranscriptDenied:
    """Any tool call naming a subagent transcript is denied, whatever the verb."""

    @pytest.mark.parametrize(
        "template",
        [
            "cat {p}",
            "head -5 {p}",
            "tail -1 {p}",
            "less {p}",
            "bat {p}",
            "more {p}",
            "vim {p}",
            "xxd {p}",
            "strings {p}",
            "rg foo {p}",
            "grep foo {p}",
            "tac {p}",
            " cat {p}",
            "/bin/cat {p}",
            "cp {p} /tmp/leak.txt",
            "mv {p} /tmp/leak.txt",
            "dd if={p} of=/tmp/leak",
            "wc -l {p}",
            "md5sum {p}",
            "diff {p} /tmp/other",
            "tee /tmp/leak < {p}",
            "python3 {p}",
            "< {p}",
            "while read l; do echo $l; done < {p}",
            'cat "{p}"',
        ],
    )
    def test_symlinked_transcript_bash_denied(self, session: Session, template: str):
        result = decide("Bash", {"command": template.format(p=session.transcript_link())})
        assert _is_deny(result), template
        assert "subagent transcript" in _reason(result)

    def test_read_symlinked_transcript_denied(self, session: Session):
        assert _is_deny(decide("Read", {"file_path": session.transcript_link()}))

    def test_read_legacy_transcript_denied(self, session: Session):
        assert _is_deny(decide("Read", {"file_path": session.legacy_transcript()}))

    def test_transcript_next_to_background_output_denied(self, session: Session):
        """One allowed path does not launder a transcript in the same command."""
        ok = session.background()
        bad = session.transcript_link()
        assert _is_deny(decide("Bash", {"command": f"cat {ok} {bad}"}))
        assert _is_deny(decide("Bash", {"command": f"cat {ok}; tail {bad}"}))

    def test_cwd_relative_transcript_denied(self, session: Session):
        session.transcript_link("a0000000000000001")
        cmd = "cat tasks/a0000000000000001.output"
        assert _is_deny(decide("Bash", {"command": cmd}, cwd=str(session.cwd)))

    def test_cwd_is_tasks_dir_bare_name_denied(self, session: Session):
        session.transcript_link("a0000000000000002")
        cmd = "tail a0000000000000002.output"
        assert _is_deny(decide("Bash", {"command": cmd}, cwd=str(session.tasks)))

    @pytest.mark.parametrize("tool", ["Grep", "Glob", "MultiEdit"])
    def test_other_tools_naming_transcript_denied(self, session: Session, tool: str):
        assert _is_deny(decide(tool, {"pattern": "x", "path": session.transcript_link()}))

    def test_webfetch_file_url_denied(self, session: Session):
        url = f"file://{session.transcript_link()}"
        assert _is_deny(decide("WebFetch", {"url": url, "prompt": "summarize"}))

    def test_deny_reason_steers(self, session: Session):
        reason = _reason(decide("Read", {"file_path": session.transcript_link()}))
        assert "completion notification" in reason
        assert "Background command output" in reason
        assert "—" not in reason  # no em dash


class TestWildcardDenied:
    """Globs under tasks/ can expand to a transcript, so they are denied."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat /private/tmp/claude-*/proj/sess/tasks/*.output",
            "cat /tmp/claude-*/proj/sess/tasks/abc.output",
            "cat /private/tmp/claude-?/proj/sess/tasks/abc.output",
            "cat /private/tmp/claude-12*4/proj/sess/tasks/abc.output",
            "cat /private/tmp/claude-501/proj/sess/tasks/*.output",
            "tail -n 5 /private/tmp/claude-501/proj/sess/tasks/*",
            "grep foo /tmp/claude-501/proj/*/tasks/b1.output",
            "cat /tmp/claude-501/proj/sess/tasks/{a,b}.output",
        ],
    )
    def test_glob_command_denied(self, command: str):
        result = decide("Bash", {"command": command})
        assert _is_deny(result), command
        assert "Wildcard" in _reason(result)

    def test_glob_via_read_denied(self):
        result = decide("Read", {"file_path": "/private/tmp/claude-*/proj/sess/tasks/abc.output"})
        assert _is_deny(result)

    def test_glob_in_real_session_denied(self, session: Session):
        session.background()
        assert _is_deny(decide("Bash", {"command": f"cat {session.tasks}/*.output"}))
        assert _is_deny(decide("Bash", {"command": f"cat {session.tasks}/*"}))

    def test_cwd_relative_glob_denied(self, session: Session):
        session.background()
        assert _is_deny(decide("Bash", {"command": "cat tasks/*.output"}, cwd=str(session.cwd)))


class TestUnverifiedDenied:
    """Paths guard cannot check on disk fail closed."""

    @pytest.mark.parametrize(
        "path",
        [
            "/private/tmp/claude-501/-Users-dev/abc123/tasks/xyz.output",
            "/tmp/claude-12345/proj/sess/tasks/abc.output",
            "/private/tmp/claude-1234/proj/sess/tasks/x.output",
        ],
    )
    def test_missing_file_denied(self, path: str):
        result = decide("Read", {"file_path": path})
        assert _is_deny(result)
        assert "could not verify" in _reason(result)

    def test_missing_file_in_real_session_denied(self, session: Session):
        path = session.tasks / "bmissing1.output"
        assert _is_deny(decide("Bash", {"command": f"cat {path}"}))

    def test_quoted_path_with_space_denied(self, session: Session):
        """A mention the tokenizer cannot split out is not checked on disk."""
        cmd = f'cat "{session.root}/my dir/tasks/b1.output"'
        assert _is_deny(decide("Bash", {"command": cmd}))

    def test_symlink_swap_after_missing_denied(self, session: Session):
        """``ln -s <transcript> tasks/bx.output && cat ...``: the target is missing at check time."""
        target = session.subagents / "agent-x.jsonl"
        target.write_text(json.dumps(_TRANSCRIPT_RECORD) + "\n", encoding="utf-8")
        link = session.tasks / "bswap0001.output"
        cmd = f"ln -s {target} {link} && cat {link}"
        assert _is_deny(decide("Bash", {"command": cmd}))


class TestPassthrough:
    def test_read_normal_file_passes(self):
        assert decide("Read", {"file_path": "/Users/dev/src/main.py"}) is None

    def test_cat_normal_file_passes(self):
        assert decide("Bash", {"command": "cat /Users/dev/src/main.py"}) is None

    def test_non_output_extension_passes(self):
        path = "/private/tmp/claude-501/proj/sess/tasks/config.json"
        assert decide("Read", {"file_path": path}) is None

    def test_other_tool_passes(self):
        assert decide("Grep", {"pattern": "test"}) is None

    def test_empty_inputs_pass(self):
        assert decide("Read", {}) is None
        assert decide("Bash", {}) is None

    def test_unrelated_dot_output_passes(self):
        """Paths containing .output mid-string outside /tasks/ must not match."""
        assert decide("Read", {"file_path": "/Users/dev/x.output.bak"}) is None
        assert decide("Read", {"file_path": "/var/log/foo.output_old"}) is None

    def test_session_dot_output_with_suffix_passes(self):
        """``<session>/tasks/x.output.bak`` is a backup file, not a task file."""
        assert decide("Read", {"file_path": "/tmp/claude-1/p/s/tasks/x.output.bak"}) is None
        assert decide("Read", {"file_path": "/tmp/claude-1/p/s/tasks/x.output.json"}) is None
        assert decide("Read", {"file_path": "/tmp/claude-1/p/s/tasks/x.output.tmp"}) is None

    def test_listing_tasks_dir_passes(self, session: Session):
        session.transcript_link()
        assert decide("Bash", {"command": f"ls -la {session.tasks}/"}) is None

    def test_cwd_outside_session_passes(self):
        result = decide("Bash", {"command": "cat tasks/abc.output"}, cwd="/Users/dev/develop/p")
        assert result is None

    def test_cwd_none_does_not_crash(self):
        assert decide("Bash", {"command": "cat tasks/abc.output"}) is None


class TestDecideRobustness:
    def test_numeric_file_path(self):
        with contextlib.suppress(TypeError):
            decide("Read", {"file_path": 12345})

    def test_empty_command_string(self):
        assert decide("Bash", {"command": ""}) is None

    def test_missing_file_path_key(self):
        assert decide("Read", {"other_key": "value"}) is None

    def test_missing_command_key(self):
        assert decide("Bash", {"other_key": "value"}) is None


class TestHookFunction:
    def test_agent_output_guard_imports(self):
        assert callable(hook)

    def test_agent_output_guard_allows_safe_input(self, capsys):
        hook({"tool_name": "Read", "tool_input": {"file_path": "/Users/dev/file.py"}})
        assert capsys.readouterr().out == ""

    def test_background_output_passes_through(self, capsys, session: Session):
        hook({"tool_name": "Read", "tool_input": {"file_path": session.background()}})
        assert capsys.readouterr().out == ""

    def test_agent_output_guard_denies_transcript(self, capsys, session: Session):
        with pytest.raises(SystemExit) as exc:
            hook({"tool_name": "Read", "tool_input": {"file_path": session.transcript_link()}})
        assert exc.value.code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.parametrize("malformed", [["not", "a", "dict"], "string", 42, None])
    def test_non_dict_tool_input_passthrough(self, capsys, malformed):
        """Malformed ``tool_input`` shapes silently passthrough rather than crash."""
        hook({"tool_name": "Read", "tool_input": malformed})
        assert capsys.readouterr().out == ""


class TestAutoPermissionMode:
    """The hook is FLOOR: Claude Code's ``auto`` mode changes nothing here."""

    @pytest.mark.parametrize("tool", ["Read", "Bash"])
    def test_transcript_read_still_denies_in_auto(self, capsys, session: Session, tool: str):
        path = session.transcript_link()
        tool_input = {"file_path": path} if tool == "Read" else {"command": f"cat {path}"}
        with pytest.raises(SystemExit) as exc:
            hook({"tool_name": tool, "tool_input": tool_input, "permission_mode": "auto"})
        assert exc.value.code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.parametrize("tool", ["Read", "Bash"])
    def test_background_output_read_passes_in_auto(self, capsys, session: Session, tool: str):
        path = session.background()
        tool_input = {"file_path": path} if tool == "Read" else {"command": f"tail -n 50 {path}"}
        hook({"tool_name": tool, "tool_input": tool_input, "permission_mode": "auto"})
        assert capsys.readouterr().out == ""


class TestSubprocess:
    def _run_hook(self, stdin_data):
        return subprocess.run(
            [sys.executable, str(HOOK_PATH)],
            input=stdin_data,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_empty_stdin(self):
        result = self._run_hook("")
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_malformed_json(self):
        result = self._run_hook("not json at all")
        assert result.returncode == 2

    def test_json_missing_keys(self):
        result = self._run_hook(json.dumps({"unexpected": "data"}))
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_subprocess_denies_transcript(self, session: Session):
        payload = json.dumps(
            {"tool_name": "Read", "tool_input": {"file_path": session.transcript_link()}}
        )
        result = self._run_hook(payload)
        assert result.returncode == 2
        envelope = json.loads(result.stdout)
        assert envelope["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_subprocess_allows_background_output(self, session: Session):
        payload = json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": f"tail -5 {session.background()}"}}
        )
        result = self._run_hook(payload)
        assert result.returncode == 0
        assert result.stdout.strip() == ""
