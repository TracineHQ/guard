# Dangerous commands

This page is a human-readable summary of what guard denies. **The registry
(`src/guard/registry.py`) and the bash validator are the source of truth;
this doc summarizes them.** When they disagree, the code wins.

Guard denies or stays out of the way. It never approves a call and never
asks: anything it doesn't deny goes on to Claude Code's own permission step,
auto mode's classifier included. Claude Code's `permission_mode` is logged
and never changes a decision. Where this is headed is in
[rules-design.md](rules-design.md).

## What guard looks inside

Every segment of a command (split on `;`, `&&`, `||`, `|` and newlines) is
checked, not only the first. Guard also checks the payloads a command hides,
each as a command of its own: a `$(...)` or `<(...)` body, a `bash -c`
string, a function body, a `trap` handler, a `find -exec` command, and the
command an `ssh` / container `exec` / `nsenter` runs elsewhere. A
substitution is also re-checked with `/` in its place, so `rm -rf $(echo /)`
still denies. Wrapper options are peeled first (`env -i`, `env -u NAME`,
`bash -o pipefail -c`, `ssh host --`), so a wrapper never hides the command
it runs. A `-c` string guard cannot read (empty, an `xargs -I{}` placeholder, or a
command named by an expansion such as `bash -c "$X"`) is denied; `$` in an
argument (`bash -c 'echo $HOME'`) is fine. awk is checked too: a command in
`system()`, `print | cmd` or `cmd | getline` that opens with a literal
(`"wc -l " $1`, or a variable the program assigns one) is checked with its
run-time parts stood in for by `/` and by an expansion, and one whose command
word is only known at run time (`system($0)`) is denied.

An inline program written out literally (`python3 -c '...'`, `python3 -
<<'EOF'`, `node -e` / `--eval` / `-p`, `node --input-type=module < x.mjs`,
`osascript -e`, `ruby -e`, `perl -e`) passes, like a script file
(`python3 x.py`): the code is right there for Claude Code to read. The program
is denied when it comes from a pipe (`curl ... | python3`), a variable or a
substitution (`python3 -c "$CODE"`), a here-string, or an unquoted heredoc whose
body expands. It is also denied when it evaluates what it reads on stdin,
which is pipe-to-shell with an extra step: a code sink (`exec` / `eval` /
`compile` / `os.system`, `eval` / `new Function` / `vm`, ruby / perl `eval` /
`system`) together with a stdin source (`input()`, `sys.stdin`, `open(0)`,
`readFileSync(0)`, `STDIN`, `<STDIN>`, or a perl / ruby `-n` / `-p` loop).
`osascript -e` is checked further: each `do shell script` (Terminal's
`do script`, iTerm's `write text`, JXA `doShellScript` / `doScript`) string
literal is checked like a `bash -c` string, as `sudo sh -c` when the program
asks for administrator privileges. An argument built at run time (a variable,
a concatenation), `run script` / `load script`, a raw Apple event
(`«event sysoexec»`), an `NSTask` launch and JXA `eval` / `$.system` are
denied, since guard can't read what they run. An AppleScript read from a
heredoc or a file is denied for the same reason.

Heredoc bodies are data: a body written to a file or fed to a filter
(`cat > notes.md <<'EOF'`) is taken out before the command is split into
lines, so a prose or config line (`at noon`, `[tool.ruff]`, a backtick fence)
is not read as a command. A body stays commands when the command can run it
as shell (`bash <<EOF`, `ssh host <<EOF`, `script` or `expect` on the
heredoc, `xargs` turning its words into a command line, a `cat > x.sh <<EOF`
followed by `bash x.sh`). A body that is an interpreter's program on stdin
(`python3 - <<'EOF'`) is that interpreter's code, judged by its own rule, even
when a shell runs elsewhere in the command. In an unquoted body, `$(...)` and
backticks still run and are checked.

Pipe-to-shell (`curl ... | sh`) carries no rule id and can't be turned off: a
shell or interpreter that reads its program from the pipe. A pipe into a
script or module (`printf '{}' | python3 tool.py`, `cat x.json | python3 -m
json.tool`) reads stdin as data and is not pipe-to-shell, unless the data
comes off the network: network output (`curl`, `wget`, `nc` / `ncat`,
`socat`, `http`, `xh`, `aria2c`, `fetch`, `ssh`, `gh api`, `aws s3 cp ... -`,
`gsutil cat`) piped into any shell or interpreter, whatever its arguments
(`wget -qO- x | python3 tool.py`), is denied too, as is network output reaching
one through a substitution (`python3 tool.py < <(curl x)`,
`echo "$(curl x)" | python3 tool.py`). A data-only module (`curl ... | python3
-m json.tool`), a literal `-c` / `-e` program with no code sink and a
non-interpreter (`curl ... | jq .`) only parse the output, so they pass.

## Rules

`guard allowlist disable-rule <rule_id>` turns one off. Guard then skips that
rule and keeps scanning, so any other rule in the same command still denies,
and logs a `pass` with the reason `allowlist: rule '<id>' disabled by user
config` when nothing else does.

| Rule | Denies |
|---|---|
| `bash.always_deny` | a registry literal (below) |
| `bash.admin_forbidden_flag` | cloud CLI flag that redirects the endpoint, swaps credentials or drops TLS |
| `bash.admin_forbidden_subcommand` | raw REST / credential-swap subcommand that skips the destructive-verb rules |
| `bash.admin_sensitive_env_override` | inline env that redirects a cloud CLI's endpoint or credentials |
| `bash.admin_default_deny` | cloud CLI verb off the read-only catalog: secret reads, IAM grants, public access, key minting |
| `bash.aws_destructive`, `bash.az_destructive`, `bash.gcloud_destructive` | irreversible cloud resource deletion |
| `bash.aws_s3_destructive` | irreversible bucket / object deletion |
| `bash.cargo_remote_install`, `bash.gem_remote_install`, `bash.go_remote_install`, `bash.helm_remote_install` | installs code from an arbitrary remote source |
| `bash.registry_config` | repoints every later install at another registry |
| `bash.chmod_dangerous` | recursive 777 on a system root |
| `bash.chmod_setuid` | setuid / setgid bit |
| `bash.chmod_sensitive_target` | opens a credential store to other users |
| `bash.fs_attr_sensitive` | ownership / immutability change on a credential store |
| `bash.command_too_long` | a command past the 8 KiB scan budget |
| `bash.credential_leak` | prints a credential into the transcript |
| `bash.secret_value` | literal secret on the command line |
| `bash.secret_egress` | uploads a credential file |
| `bash.dns_exfil` | DNS-tunnel exfiltration shape |
| `bash.dangerous_interpreter` | an inline program guard can't read (see above) |
| `bash.eval_builtin` | `eval` runs a string as code |
| `bash.dangerous_construct` | output run as code (`bash -c "$(curl ...)"`, `source <(...)`, a shell fed by `<<<`), awk / osascript running a command built at run time, or `>` / `>>` / `>\|` into `~/.ssh`, a shell rc file, `/etc`, a launch agent, git config or a git hook |
| `bash.shell_wrapper` | a `-c` string that is empty, a `{}` placeholder or a command named by an expansion |
| `bash.env_split_string` | `env -S` rebuilds argv guard cannot see |
| `bash.wrapper_stacking` | nesting past the unwrap limit hides the inner command |
| `bash.dangerous_rm` | recursive rm of `/`, `~`, `$HOME` or the cwd |
| `bash.function_definition` | a fork bomb: a function that pipes into or backgrounds a call back to itself |
| `bash.conditional_denied_flag` | `find -delete` / `-exec` rooted at `/`, a home dir or a system directory, or an unfiltered delete of `.` or `..` |
| `bash.disk_destruction` | disk / partition / filesystem destruction |
| `bash.db_cli_destructive`, `bash.dropdb_or_mysqladmin`, `bash.mongo_destructive` | irreversible database destruction |
| `bash.iac_destruction` | tears down a whole IaC stack |
| `bash.kubectl_destructive` | cluster-wide kubectl deletion |
| `bash.gh_api_destructive` | raw `gh api` mutation (DELETE / PATCH / PUT / graphql mutation) |
| `bash.gpg_secret_delete` | destroys private key material |
| `bash.git_force_push` | rewrites shared remote history |
| `bash.git_force_refspec` | `+refspec` force-push |
| `bash.git_read_exec` | read-only git verb coerced into exec or a file write (`log --output=`, `diff --ext-diff`, `grep -O`) |
| `bash.escalation_shell` | `su` / `doas` / `pkexec` / `runuser` / `setpriv` / `machinectl shell`, also behind `chroot` / `flock` / `unshare` |
| `bash.sudo_escalation` | root shell or env transfer through `sudo` |
| `bash.host_control` | reboot / shutdown / runlevel change |
| `bash.kernel_module_load` | loads code into the kernel |
| `bash.network_policy_wipe` | firewall wipe |
| `bash.process_attach` | reads another process's memory |
| `bash.process_tree_kill` | kills every process the user owns |
| `bash.sensitive_write` | writes to `~/.ssh`, shell rc files, `/etc` or launch agents |
| `guard.git_c_validator` | `git -c core.hooksPath` / `core.attributesFile` overrides; `git -C` read verbs coerced into exec or a file write, `fetch --upload-pack` / `--exec` / `ext::` |
| `guard.protected_files` | guard's own install, its allowlist and your protected list |
| `guard.credential_check` | credential material in a tool input |
| `guard.commit_message_validator` | AI attribution in a commit message |
| `guard.subagent_scope` | edits outside a declared subagent scope |
| `guard.agent_output_guard` | reads of subagent transcripts (background output passes) |

## Always-deny literals

`ALWAYS_DENY` prefixes (`bash.always_deny`), matched at the start of any segment.

| Prefix | Reason |
|---|---|
| `rm -rf /`, `rm -rf /*`, `rm -fr /`, `rm -rf --no-preserve-root /` | Recursive root deletion |
| `rm -rf ~`, `rm -rf $HOME`, `rm -fr ~` | Recursive home deletion |
| `git push --force`, `-f`, `--force-with-lease`, `--force-if-includes` | Force-rewrites remote history |
| `git push --mirror` | Mirrors local refs to remote, deleting any remote-only refs |
| `git filter-branch`, `git filter-repo` | Rewrites history |
| `git reflog expire`, `git reflog delete` | Drops recovery points |
| `git gc --prune=now` | Permanently removes unreachable objects |
| `python -c`, `python3 -c`, `node -e`, `node --eval` | Runs code from the command line (a literal program passes) |
| `kubectl delete --all`, `kubectl delete pods --all`, `kubectl delete namespace` | Cluster-wide deletion |
| `aws s3 rb`, `gh repo delete`, `gh release delete` | Irreversible remote deletion |
| `gpg --delete-secret-key`, `gpg --delete-secret-and-public-keys` | Destroys private key material |
| `chmod -R 777 /`, `chmod -R 777 /*` | Opens the whole filesystem |
| `terraform destroy` | Destroys infrastructure |

The inline-interpreter rule (`bash.dangerous_interpreter`) covers absolute
paths (`/usr/bin/python3 -c`), version suffixes (`python3.11 -c`) and runner
wrappers (`uvx python -c`, `uv run python -c`, `pipx run python -c`). Running a
script path (`python3 scripts/x.py --flag`, `node build.js`) or a module
(`python -m pytest`) is not denied, and flags after the script path or
`-m <module>` belong to that program, so `python3 x.py -c cfg` is not an eval
flag. After a flag the scan can't parse (it might take the next token as its
value), every remaining token is checked for an eval flag or a stdin
redirect, so `node --title ./x.js -e "$X"` still denies.

## Verifying classifications

The intended decision for every shape above is pinned by a fixture corpus
under `tests/corpus/*.jsonl` (one row per command, with its expected
`allow`/`deny` and mode, where `allow` means guard gave no decision). Run the
whole corpus through the live matcher in one process with `guard corpus`
(exit 1 on any mismatch); CI enforces the same rows. Add a row there rather
than testing ad hoc; see `tests/corpus/README.md`.

## Adding to the registry

To add a new dangerous prefix:

1. Add a `CommandRule` to `COMMANDS` in `src/guard/registry.py` with
   `Safety.DENY` and a `category`.
2. Make sure the prefix is exact-match-or-followed-by-space (the matcher uses
   `_match_always_deny`).
3. Add corpus rows and tests for the new entry.
4. Re-run `just check`.

This doc doesn't auto-regenerate; update it when a rule changes.
