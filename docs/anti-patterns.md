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
head -n 10000 ~/.claude/guard-decisions.jsonl
```

**Why it's bad.** Subagent output transcripts and decision logs are large
NDJSON files. Reading them whole burns the entire context window for a
single tool call, often without giving the model the structure it actually
needs.

**What guard does.** `agent_output_guard` denies direct `Read` /
`cat|head|tail` calls against agent-output paths and points the agent at the
appropriate query CLI. For the decision log, use `tail -f | jq` or a
proper query rather than dumping the whole file.

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
env -i bash -c '...'
```

**Why it's bad.** These are canonical re-exec primitives. Once a `-c` /
`-e` form is allowed, every other validator in the chain can be bypassed
by stuffing the real command into the eval string.

**What guard does.** Hard deny in the registry. Bare `python` / `python3`
/ `node` / `env` are still allowed for legitimate uses (running a script,
inspecting environment) — only the re-exec flag forms are blocked. `env -i`
is denied unconditionally because clearing the environment is a common RCE
wrapper.
