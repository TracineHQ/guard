# Anti-patterns guard catches

Concrete Claude Code anti-patterns guard denies, each with a reason that
tells the agent what to do instead. Each section gives an example, why the
pattern is problematic, and what guard does about it.

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
are in the registry's `ALWAYS_DENY` set, so they deny in every permission
mode. An `rm -rf` against a non-root path gets no decision from guard and
goes on to Claude Code's own permission step.

## `cat` of multi-MiB JSONL into context

```
cat /tmp/claude-12345/tasks/some-id.output
```

**Why it's bad.** Subagent output transcripts are large NDJSON files.
Reading them whole burns the entire context window for a single tool call,
often without giving the model the structure it actually needs.

**What guard does.** `agent_output_guard` denies any tool call that names a
subagent transcript under `tasks/` (or a wildcard that could expand to one)
and points the agent at the subagent's returned result. Background Bash
command output in the same directory is plain text and stays readable.

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

**What guard does.** `credential_check` denies when an
edit targets a known credential file (`~/.aws/credentials`, `~/.ssh/id_*`,
`.env`, `*.pem`, `*.key`, etc.) or when a Bash command references one.
The decision log truncates large fields so a literal key in the command
excerpt is still capped — but the right answer is to never paste secrets
inline.

## Edits to guard's own allowlist or hook code

```
Edit: file_path=~/.claude/guard/allowlist.json
```

**Why it's bad.** The allowlist decides what guard lets through. An agent
that can write it grants itself any override, and one that can rewrite the
hook code can quietly remove a guardrail.

**What guard does.** `protected_files` denies agent writes to guard's trust
root (the running install's hook code, `registry.py` and `_utils.py`, the
allowlist and `.claude/subagent-scope.json`) in every guard mode, `off`
included. No allowlist entry unlocks `allowlist.json` itself; the deny tells the agent to
ask the user, who can run `guard allowlist`. Combined with `subagent_scope`,
edits originating from a scoped subagent are blocked unless the scope file
explicitly allows them.

## Inline programs guard can't read

```
python3 -c "$CODE"
node -e "$(cat x.js)"
cat x.py | python3
```

**Why it's bad.** An inline program can be anything. When the code is
written out on the command line, Claude Code's permission step can read it.
When it comes from a variable, a substitution or a pipe, nobody sees what
runs until it runs.

**What guard does.** A literal program (`python3 -c 'print(1)'`, `node -e
'...'`, `python3 - <<'EOF'`) passes, like a script file. A program guard
can't read (`python3 -c "$CODE"`, `node -e "$(cat x.js)"`, `cat x.py |
python3`) is denied, and so is one that evaluates what it reads on stdin.
The deny tells the agent to write the code to a script file and run that.
`env -i` is peeled like any other wrapper, so `env -i bash -c '...'` is
judged by the command it runs.
