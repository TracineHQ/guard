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

---

## bash_command_validator

- **Matcher:** `Bash`
- **Source:** `src/guard/hooks/bash_command_validator.py`

### What it checks

Validates the `command` string in `Bash` tool input. Behavior splits on
`permission_mode`:

- **Strict modes** (`auto`, `dontAsk`, `bypassPermissions` -- any unattended
  mode) are default-deny: a segment must match a known-safe registry prefix
  to pass, and `ASK`-tier commands are denied with a queued-for-session-end
  message instead of prompting.
- **Interactive modes** (`default`, `acceptEdits`) pass unknown segments
  through to Claude Code's normal permission prompt. Only the dangerous floor
  below forces a hard `deny`.

In both modes the validator:

- Strips leading `#` comment lines.
- Splits on `|`, `&&`, `||`, `;`, and newlines -- quote- and
  substitution-aware, so operators inside `$(...)`, backticks, and quoted
  literals do not split.
- Enforces a dangerous floor regardless of mode: destructive commands
  (`rm -rf`, `dd`, `mkfs`, fork bombs), pipe-to-shell (`curl ... | sh`),
  interpreter RCE (`python -c`, `node -e`, `python -m http.server` and other
  non-allowlisted `-m` modules), command substitution whose inner command is
  itself dangerous, heredoc bodies feeding a shell/eval sink, credential
  leaks (`gh auth token`), and high-entropy secret values.
- Looks up each segment in the registry (`src/guard/registry.py`) — `ALLOW`
  prefixes pass, `ASK` prefixes are surfaced (denied in strict mode), and
  `ALWAYS_DENY` prefixes block hard.

Read-only command substitution (e.g. `echo $(git rev-parse HEAD)`) passes in
interactive mode; the same construct is re-evaluated for a dangerous inner
command and denied if one is found, in either mode.

### Example block

```
git add -A is denied: stages all files indiscriminately
```

---

## git_c_validator

- **Matcher:** `Bash`
- **Source:** `src/guard/hooks/git_c_validator.py`

### What it checks

Catches `git -C <path> <subcommand>` invocations that ordinary glob-based
permission rules struggle to classify (because `*` does not cross `/`).
Read-only subcommands (`status`, `log`, `diff`, etc.) auto-allow.
Destructive ones (`reset`, `clean`) are denied; `stash pop`, `stash drop`,
and `stash clear` are denied as well.

Additional denials beyond the simple subcommand list:

- **`git -c core.hooksPath=<value>` and `git -c core.attributesFile=<value>`**
  are denied regardless of the value, in any of the four argv shapes (bare
  `-c`, `-c key=val`, `-c key= val`, `-C path -c ...`). These config keys
  let an attacker point git at attacker-controlled hook scripts or
  smudge/clean filters.
- **`git commit -C <ref>` and `git commit --reuse-message=<ref>`** are
  denied (silent message reuse — the commit-message validator can't see
  the reused body).
- **Ref creation and mutation** are denied, not merely ASK'd, via the shared
  `git_ref_violation` predicate (`include_creation=True`) -- the same ref-write
  floor the bare-`git` path enforces as `bash.git_ref_mutation`. Covers
  `branch <name>` / `tag <name>` creation, `branch -d/-D/-m/-M`, `tag -a/-d`,
  and `remote add/remove/rename/set-url`. Bare listing (`branch -a`, `tag -l`)
  still auto-allows.

If the command contains shell operators (`&&`, `||`, `;`, `|`) the hook
declines to auto-allow and falls through to the rest of the chain.

### Example block

```
git -C: 'reset' is destructive and blocked
```

---

## credential_check

- **Matcher:** `Edit | Write | Bash | Read | Glob | Grep | MultiEdit | NotebookEdit | WebFetch`
- **Source:** `src/guard/hooks/credential_check.py`

### What it checks

Surfaces an `ask` decision when any tool touches a known credential file.
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

The hook never blocks; it forces a human prompt so a misrouted edit can't
leak secrets silently.

### Example prompt

```
Credential file access — confirm intent. Touching credential material
(AWS/SSH/.env/*.pem/*.key/etc.) requires an explicit human OK so a
misrouted edit can't leak secrets.
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

Denies direct `Read` and `Bash(cat|head|tail)` calls against subagent
output transcripts (paths matching `/(private/)?tmp/claude-<pid>/.../tasks/<id>.output`).
Those files are large JSONL transcripts; pulling them straight into context
wastes the entire window. The deny message points the agent at the
appropriate query CLI instead.

### Example block

```
Direct reads on agent output files are not allowed — they are large JSONL
transcripts that waste context. Use the appropriate query CLI for this data.
```

---

## protected_files

- **Matcher:** `Edit | Write | MultiEdit | NotebookEdit | Bash | Glob | Grep | WebFetch`
- **Source:** `src/guard/hooks/protected_files.py`

### What it checks

Forces an `ask` decision on `Edit`/`Write` to security-critical files —
the validator modules themselves, `registry.py`, `_utils.py`, and the
Claude Code settings files (`.claude/settings.json`,
`.claude/settings.local.json`). Backwards-compat patterns also cover the
original `hooks/` layout for forks.

Bash write-redirects (`echo ... > .claude/settings.json`) are also matched:
`_match_for_tool` routes `Bash` payloads through `bash_write_targets`,
which extracts the redirect / `tee` / `cp` / `dd of=` / in-place-editor
targets and runs each through `is_protected`.

The hook never denies; it only surfaces edits to the policy surface for
review.

### Example prompt

```
Protected file: guard/registry.py — confirm edit
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
