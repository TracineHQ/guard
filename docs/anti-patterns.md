# Anti-patterns guard catches

Concrete Claude Code anti-patterns guard either denies outright or surfaces
for human confirmation. Each section gives an example, why the pattern is
problematic, and what guard does about it.

## `rm -rf /` (and friends)

```
rm -rf /
rm -rf /*
rm -rf ~
rm -rf $HOME
rm -fr /
rm -fr ~
rm -rf --no-preserve-root /
```

**Why it's bad.** Catastrophic, irreversible. A typoed path argument or a
hallucinated cleanup step can wipe a developer machine.

**What guard does.** Hard deny via `bash_command_validator`. These prefixes
are in the registry's `ALWAYS_DENY` set, so they block in both interactive
and strict (`auto`/`dontAsk`/`bypassPermissions`) modes. Any `rm -rf`
against a non-root path still goes through
the normal `ASK` tier.

## `git commit -C <ref>`

```
git commit -C HEAD
```

**Why it's bad.** `-C <ref>` reuses an existing commit's message silently —
no editor opens, no message is shown. An agent that picks the wrong ref will
land a commit with the wrong message and no obvious signal.

**What guard does.** `git_c_validator` denies the `commit -C` form
explicitly. Use `-c` (lowercase, opens an editor) or `-m "message"` instead.

## `cat` of multi-MiB JSONL into context

```
cat /tmp/claude-12345/tasks/some-id.output
```

**Why it's bad.** Subagent output transcripts are large NDJSON files.
Reading them whole burns the entire context window for a single tool call,
often without giving the model the structure it actually needs.

**What guard does.** `agent_output_guard` denies direct `Read` /
`cat|head|tail` calls against agent-output paths (`tasks/*.output`) and
points the agent at the appropriate query CLI.

Guard does NOT deny reading its own decision log
(`~/.claude/guard-decisions.jsonl`); the log is protected only against
truncation/overwrite by write verbs. Dumping it whole still burns context,
so prefer `tail -f | jq` or a query over `cat` -- that's advice, not
enforcement.

## Hardcoded API keys in tool inputs

```
Bash: curl -H "Authorization: Bearer sk-live-XXXXXXXXXXXXXXXX" https://api.example.com
Edit: file_path=~/.aws/credentials
```

**Why it's bad.** Two failure modes: secrets pasted into tool inputs leak
into transcripts and decision logs, and edits to credential stores can
overwrite real credentials with placeholder strings.

**What guard does.** `credential_check` forces an `ask` decision when an
edit targets a known credential file (`~/.aws/credentials`, `~/.ssh/id_*`,
`.env`, `*.pem`, `*.key`, etc.) or when a Bash command references one.
The decision log truncates large fields so a literal key in the command
excerpt is still capped — but the right answer is to never paste secrets
inline.

## Edits to `~/.claude/settings.json` from a subagent

```
Edit: file_path=~/.claude/settings.json
```

**Why it's bad.** `settings.json` is the ASK-gate that decides whether
guard's hooks fire at all. A subagent silently editing it can disable
every guardrail in one tool call.

**What guard does.** `protected_files` matches `.claude/settings.json` and
`.claude/settings.local.json` and forces an `ask` decision. Combined with
`subagent_scope`, edits originating from a scoped subagent are blocked
unless the scope file explicitly allows them.

## `git add -A` / `git add .` / `git add --all`

```
git add -A
git add --all
git add .
git add -a
```

**Why it's bad.** Bulk-staging picks up whatever happens to be in the
working tree — generated files, scratch notes, accidentally-checked-in
credentials. The user's review step gets bypassed.

**What guard does.** Hard deny in the registry (`git-deny` category).
Stage explicit paths (`git add path/to/file.py`) instead. The deny applies
even in interactive mode — it's not a confirmation prompt, it's a refusal.

## Interpreter RCE primitives

```
python -c '...'
python3 -c '...'
node -e '...'
node --eval '...'
python3 deploy.py          # bare script path — also denied
python3 -m http.server     # arbitrary module — also denied
uv run python deploy.py    # wrapped runner — also denied
env -i bash -c '...'
```

**Why it's bad.** These are canonical re-exec primitives. Guard sees only
the command line, never the script's contents, so any `python3 x.py` is an
opaque payload: an agent can write whatever it wants into `x.py` first, then
run it past every command-level matcher. That makes interpreter-exec
RCE-equivalent.

**What guard does.** Hard deny via `bash_command_validator`
(`bash.dangerous_interpreter`), in both interactive and strict modes. The
deny is *not* limited to eval flags. A bare script path (`python3
deploy.py`), an `-m <module>` form (except a curated stdin/stdout-only set
like `json.tool` / `venv`), and the wrapped runners (`uv run python x.py`,
`uvx python -c ...`) all deny too. Because the payload is opaque, this is a
floor rule, not an ASK: there is no "are you sure?", it refuses.

To run a *vetted* script you re-use, a human content-pins it:

```
guard trust-script path/to/script.py --reason "weekly inbox scan"
```

That pins the sha256 of the file's bytes, so the same script runs with
varying operands (`scan.py email-1.md`, `scan.py email-2.md`) while editing
the script revokes the trust. Granting trust is a human action -- an agent
can't self-grant (the command is not on any safe-prefix and the trust store
is a protected file). See [`decision-model.md`](decision-model.md) for the
full floor-vs-default-deny model. `env -i bash -c` is denied unconditionally
because clearing the environment is a common RCE wrapper.
