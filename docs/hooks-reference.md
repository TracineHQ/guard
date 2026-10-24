# Hooks reference

Guard ships seven PreToolUse hooks plus one PermissionRequest hook. Each
runs as a short Python subprocess that reads a JSON payload on stdin and
emits a permission decision (or, for the PermissionRequest hook, an
observation-only audit record) plus a JSONL record. This page documents
what each hook checks, when it fires, how to disable it, and what a typical
block looks like.

All hooks log to `~/.claude/guard-decisions.jsonl` (override with
`GUARD_DECISIONS_PATH`). See [output-format.md](output-format.md) for the
record schema.

To disable any hook, remove its entry from the `PreToolUse` block in
`~/.claude/settings.json`, or comment out the matching line in
`hooks/hooks.json` if you forked the plugin.

## Deny or no decision

Every hook either denies or gives no decision. Guard never approves a call
and never asks, so anything it doesn't deny goes on to Claude Code's own
permission step, auto mode's classifier included. The payload's
`permission_mode` is logged and never changes a decision. A rule turned off
with `guard allowlist disable-rule` is skipped the same way in every mode.

---

## bash_command_validator

- **Matcher:** `Bash`
- **Source:** `src/guard/hooks/bash_command_validator.py`

### What it checks

Validates the `command` string in `Bash` tool input. A segment no rule
matches gets no decision. The validator:

- Strips leading `#` comment lines.
- Splits on `|`, `&&`, `||`, `;`, and newlines -- quote- and
  substitution-aware, so operators inside `$(...)`, backticks, and quoted
  literals do not split. `>|` is a redirect, not a pipe.
- Peels wrappers before matching, options included: `env -i` / `-u NAME` /
  `-C DIR` / `--`, `bash -o pipefail -c`, `ssh host --`, so the wrapped
  command meets its own rule.
- Checks the payloads a command hides as commands of their own: a
  `$(...)` / `<(...)` body, a `bash -c` string, a function body, a `trap`
  handler, a `find -exec` command, an `ssh` / container `exec` / `nsenter`
  command. A `-c` string it cannot read (empty, a
  `{}` placeholder, or a command named by an expansion such as
  `bash -c "$X"`) is denied.
- Checks the commands an awk program runs (`system("...")`,
  `print | "..."`, `"..." | getline`) as commands of their own, and denies
  one built at run time (`system($0)`).
- Denies destructive commands (`rm -rf` of a root, `dd`, `mkfs`, fork
  bombs), force pushes, pipe-to-shell (`curl ... | sh`), inline programs it
  can't read (`python3 -c "$CODE"`, `node -e "$(cat x.js)"`, a program piped
  in), credential leaks (`gh auth token`), and high-entropy secret values.
- Leaves a literal inline program (`python3 -c 'print(1)'`), a script and a
  module run (`uv run python tools/dev.py`, `python -m pytest`) to Claude
  Code's own permission step.
- Denies escalation and host control with a specific rule_id: non-sudo
  escalation (`su`, `doas`, `pkexec`), host power control (`reboot`,
  `shutdown`), and package-registry redirection (`npm config set registry`).
- Denies a segment that starts with a registry `ALWAYS_DENY` prefix
  (`src/guard/registry.py`).

A substitution whose inner command is harmless (`echo $(git rev-parse HEAD)`)
passes; one whose inner command is dangerous is denied.

A `bash.dangerous_construct` deny names the construct that matched and the
route to take instead: output run as code (`bash <(curl ...)`,
`bash -c "$(curl ...)"`, a shell reading a here-string or process
substitution on stdin such as `{ bash; } <<< '...'`), or a `>` / `>>`
redirect into a sensitive path (`~/.ssh`, a shell rc file, `/etc`,
`.git/config`, `.git/hooks/`, `~/.gitconfig`). A redirect anywhere else
passes.

### Example block

```
guard [permission_mode=default] denied: bash.always_deny. Blocked: `git push
--force` is on the always-deny list (Force-rewrites remote history). Override:
`guard allowlist disable-rule bash.always_deny`. ...
```

```
guard [permission_mode=default] denied: bash.dangerous_construct. `echo hi >
~/.ssh/config` redirects into `~/.ssh/config`, a sensitive path (ssh keys,
shell rc files, /etc, launch agents, git config or hooks). ...
```

---

## git_c_validator

- **Matcher:** `Bash`
- **Source:** `src/guard/hooks/git_c_validator.py`

### What it checks

Two shapes deny; everything else gets no decision.

- **`git -c core.hooksPath=<value>` and `git -c core.attributesFile=<value>`**
  are denied regardless of the value, in any of the four argv shapes (bare
  `-c`, `-c key=val`, `-c key= val`, `-C path -c ...`). These config keys
  let an attacker point git at attacker-controlled hook scripts or
  smudge/clean filters.
- **`git -C <path>` read verbs that run a program or write a file**:
  `log --output=`, `diff --ext-diff`, `grep -O`, and `fetch --upload-pack` /
  `--exec` or an `ext::` remote.

If the command contains shell operators (`&&`, `||`, `;`, `|`) the hook
gives no decision.

### Example block

```
git -C: 'log --output' writes a file or execs and is blocked
```

---

## credential_check

- **Matcher:** `Edit | Write | Bash | Read | Glob | Grep | MultiEdit | NotebookEdit | WebFetch`
- **Source:** `src/guard/hooks/credential_check.py`

### What it checks

Denies any tool call that touches a known credential file.
A universal path scanner (`decide()`) extracts every path-like token in
`tool_input` regardless of `tool_name` and checks it against the credential
matchers; `Bash` additionally gets copy-source and variable-indirection
tiers. Patterns include `~/.aws/credentials`, `~/.aws/config`, `~/.netrc`,
`~/.ssh/id_*`, `.env`, `*.pem`, `*.key`, and `~/.config/gh/hosts.yml`.

The `Read` path is part of the matcher set specifically to close the
`Read({"file_path":"~/.aws/credentials"})` bypass, where an earlier
implementation that fired only on `Edit`/`Write`/`Bash` let a direct read
of credential material through silently (see the `credential_check.py`
module docstring and `decide()`).

The deny steers the agent to let the tool use its own auth, or to ask the
user for the specific non-secret value it needs.

### Example deny

```
Credential file access blocked. Touching credential material
(AWS/SSH/.env/*.pem/*.key/etc.) puts secrets in the transcript. Let the tool
use its own auth (aws, gh, ssh read their credentials themselves), or ask the
user for the specific non-secret value you need.
```

---

## commit_message_validator

- **Matcher:** `Bash`
- **Source:** `src/guard/hooks/commit_message_validator.py`

### What it checks

Intercepts `git commit` and rejects messages containing AI attribution.
Three layers stack:

1. Known AI tool emails (`noreply@anthropic.com`, `cursoragent@cursor.com`,
   github-copilot bot addresses, etc.).
2. Trailer patterns (`Co-Authored-By:` paired with an AI tool name).
3. "Generated by/with" footers.

Reads message content from `-m`/`-F` arguments or `COMMIT_EDITMSG`. The
hook caps file reads at 64 KiB to keep the regex pipeline bounded.

### Example block

```
Commit message contains AI attribution. Found: Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## agent_output_guard

- **Matcher:** `Read | Bash`
- **Source:** `src/guard/hooks/agent_output_guard.py`

### What it checks

Claude Code writes two kinds of file under
`/(private/)tmp/claude-<uid>/<project>/<session>/tasks/<id>.output`:
background Bash command output (plain text, meant to be read) and subagent
transcripts (multi-MiB JSONL, today a symlink into
`~/.claude/projects/<project>/<session>/subagents/agent-<id>.jsonl`).
Reading a transcript pulls the whole run into context, so the hook resolves
every `tasks/*.output` path in a tool call on disk and classifies it:

| Path | Decision |
|---|---|
| Regular file whose first line is plain text (or JSON that is not a transcript record) | pass: background command output, any size, any verb (`cat`, `tail`, `grep`, Read) |
| Symlink to a `.jsonl` file or into a `subagents/` dir | deny: subagent transcript |
| File whose first line is a JSON object with transcript keys (`parentUuid`, `isSidechain`, `sessionId`, `agentId`) | deny: subagent transcript (covers builds that wrote the JSONL in place) |
| Wildcard under `tasks/` (`tasks/*.output`, `tasks/*`, `claude-*/...`) | deny: can expand to a transcript |
| Missing, not a regular file, unreadable, or a mention the tokenizer cannot split out (a quoted path with a space) | deny: fail closed |

Detection keys off how Claude Code stores transcripts (the link into
`subagents/`, the transcript record keys), not file size or id shape: a size
threshold misfires both ways (a just-launched transcript is small, a
backgrounded `gh api --paginate` dump is large) and id formats are internal
to Claude Code. The hook is not allowlist-overridable. A transcript read
denies in every permission mode, and background command output passes in
every mode.

### Example block

```
This path is a subagent transcript (multi-MiB JSONL); reading it floods
context. Wait for the subagent's completion notification and use the result
it returns. Background command output in the same tasks/ directory is fine
to read by its exact path.
```

---

## protected_files

- **Matcher:** `Edit | Write | MultiEdit | NotebookEdit | Bash | Glob | Grep | WebFetch`
- **Source:** `src/guard/hooks/protected_files.py`

### What it checks

Denies writes to guard's trust root: the guard install that is running
(everything under its `src/`, `bin/run-hook` and `hooks/hooks.json` for a
source checkout, the package directory for a wheel),
`.claude/guard/allowlist.json` and `.claude/subagent-scope.json`. Guard's
install is matched by real path and inode, not by name, so a clone or
worktree of guard's source is ordinary code, while a hard link or a spelling
the volume folds is not. Removing, moving, hard-linking or copying into a
directory that holds the install counts as a write. Backwards-compat
patterns also cover hook scripts installed under `.claude/hooks/` by older
setups.
The trust root stays protected in every guard mode, `off` included. Project
patterns from `.claude/guard-protected.txt` and
`GUARD_PROTECTED_EXTRA` (both apply) count in every mode but `off`.

Bash writes are matched too. The command is read the way bash reads it
(quotes, `$'...'`, comments, line continuations, `$(...)` and backtick
bodies, heredocs), split at `;`, `&&`, `||`, `|` and newlines, and each
command's write targets (redirects, `tee`, `cp` / `mv` / `install`, `dd of=`,
in-place editors, removals, hard links) are resolved and checked.
`bash -c` and `eval` strings, substitution bodies and heredocs a shell
reads are scanned the same way. Operators inside quotes stay operands.
`guard allowlist <write>` and `guard mode <mode>` count as writes to the
allowlist, so the agent can't reconfigure guard through its CLI. Reads stay
reads: `--help` / `-h`, `guard status`, `guard allowlist list` and a bare
`guard mode`, and a redirect such as `2>&1` is never taken for a mode
argument. Every other
tool passes (`Read`, `Grep`, `Glob`, `WebFetch`, `Agent`, `AskUserQuestion`,
...), and interpreter bodies count only when they show write intent.

### Example deny

The reason names the protected path and, when they differ, the text in the
tool input that matched it.

```
Protected path: /home/me/.claude/plugins/cache/tracine/guard/1.5.0/src,
matched by `/home/me/.claude/plugins/cache/tracine/guard/1.5.0/src/guard/_utils.py`.
guard blocks agent writes to the install it is running from and to the
subagent scope file, so a session can't rewrite its own guardrails. Don't
retry or route around it. Tell the user what you want to change and why;
they can make the edit.
```

---

## subagent_scope

- **Matcher:** `Edit | Write | MultiEdit | NotebookEdit | Bash | Glob | Grep | WebFetch`
- **Source:** `src/guard/hooks/subagent_scope.py`

### What it checks

When `<cwd>/.claude/subagent-scope.json` exists, denies any `Edit`/`Write`
whose `file_path` falls outside the declared `allowed` list. `Bash`
write-target shapes are scope-checked too: each target from
`protected_files.bash_write_targets` (redirects, `cp`/`mv` destinations,
`tee`, `dd of=`, in-place editors) runs through the same `allowed` check,
closing the bypass where a scoped subagent shells out to
`echo > out-of-scope/file`. Pattern semantics:

- Trailing slash (`pkg/tests/`) — recursive directory match.
- Glob chars (`*`, `?`, `[`) — `fnmatch` against the relative path.
- Plain path — exact suffix match anchored on a `/` boundary.

A missing or malformed scope file results in silent passthrough so a
broken hook config never blocks legitimate work.

### Example block

```
Edit to src/other/module.py is outside subagent scope (task: "Task 2.1: stats refactor")
```

---

## permission_request_logger

- **Matcher:** `PermissionRequest *`
- **Source:** `src/guard/hooks/permission_request_logger.py`

### What it checks

Observation-only. This is a `PermissionRequest` hook, not a `PreToolUse`
hook: Claude Code fires it when it is about to surface a permission dialog
to the user (interactive modes only -- never `dontAsk` / `bypassPermissions`).
It never blocks and never replies. It appends a `permission_request` JSONL
record so operators can see what Claude Code prompted the user about, then
exits cleanly with empty stdout so the prompt proceeds normally. When the
effective allowlist mode is `off`, it short-circuits and writes nothing.
