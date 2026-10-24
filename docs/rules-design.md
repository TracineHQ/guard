# Rules design

Every session now runs in Claude Code's auto mode. The classifier already judges intent,
scope and shell shapes. Guard's job shrinks to two things:

- a small deterministic floor the classifier can't be talked out of;
- checks that need local knowledge the classifier doesn't have.

Five rules make the floor. Every other rule is deleted. Guard stops approving anything.

Evidence: guard's decision log from 2026-04-30 to 2026-10-23, real sessions only (UUID
session ids; test fixtures excluded), enforce and shadow rows. Counts are deny rows.
Probes ran commands through each hook's `decide()`; nothing was executed.

## The floor

| Rule | Denies |
|---|---|
| `bash.dangerous_rm` | recursive `rm` of `/`, home, the cwd or an ancestor of it |
| `bash.git_force_push` | a push that overwrites or deletes a shared branch, and `--mirror` |
| `guard.credential_check` | reading, copying or sending a credential store; printing a live credential |
| `guard.protected_files` | changes to the running guard, its config, its hook registration, your own list |
| `guard.commit_message_validator` | AI attribution in a commit message; a commit message guard can't read |

### bash.dangerous_rm

- `rm`: any word whose basename is `rm`, at any position in a segment or a payload word
  (see the contract), so `sudo`, `timeout`, `watch -n 1`, `parallel` and `find -exec` need no list.
- Recursive: `-r`, `-R`, `--recursive`, or a short cluster containing `r` or `R`, before `--`.
- Roots: `/`, home, the session cwd (the hook's cwd) and every ancestor of it, each also with
  `/*` or `/.*` appended.
- Operands resolve against the effective cwd: the session cwd, moved by each literal `cd` earlier
  in the command. So `.`, `*`, `..`, `$PWD`, `$(pwd)`, `~`, `$HOME`, `${HOME}` and absolute forms
  all reach the same set, while `cd build && rm -rf *` passes. A `cd` guard can't resolve makes
  the effective cwd unknown, and then any relative or glob operand counts as a root.
- Variables: in-command assignments, then the hook's environment, else empty. Each Bash call is a
  fresh shell, so `rm -rf "$X/"` with `X` unset is `rm -rf /`.
- Not claimed: operands from stdin (`xargs`), substitution output other than `pwd`, `find -delete`,
  interpreter code. Claude Code's own critical-path check and the classifier see those.

### bash.git_force_push

- `git`: any word whose basename is `git`, anywhere, then git's global options (`-C`, `-c`,
  `--git-dir`, `--work-tree`, `--namespace`, `-P`, `--no-pager`, `--exec-path`, `--bare`), then `push`.
- `--mirror`: always denied.
- Force: `-f`, `--force`, `--force-with-lease[=...]`, `--force-if-includes`, a short cluster with
  `f`, or a refspec starting with `+`. Delete: `-d`, `--delete`, or a refspec `:dst`.
- Shared: `main`, `master`, `develop`, `trunk`, `staging`, `release*`, `prod*`, and the remote's
  default branch when `refs/remotes/<remote>/HEAD` names one. Matched on the refspec destination
  (`dst`, `src:dst`, `refs/heads/dst`). With no refspec, or `--all`, the destination is the
  current branch read from the effective repo's HEAD; an unreadable HEAD counts as shared.
- `--force-with-lease` on a shared branch is still denied. Feature branches pass.
- Not claimed: ref updates through `gh api`.

### guard.credential_check

- Stores, after `~`, `$HOME` and environment expansion, symlink resolution and glob expansion
  against the filesystem:
  - `~/.ssh/*` except `*.pub`, `config`, `config.d/`, `known_hosts*`, `authorized_keys`
  - `~/.aws/credentials`, `~/.aws/sso/cache/`, `~/.aws/cli/cache/`
  - `~/.netrc`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.config/gh/hosts.yml`
  - `~/.docker/config.json`, `~/.kube/config`, `~/.npmrc`, `~/.pypirc`
  - `~/.gnupg/private-keys-v1.d/`, `~/.gnupg/secring.gpg`
  - gcloud's `credentials.db`, `access_tokens.db`, `application_default_credentials.json`,
    `legacy_credentials/`; wrangler's `config/default.toml`; `~/Library/Keychains/`;
    `~/.claude/.credentials.json`
- Store directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gh`,
  `~/.config/gcloud`) count as stores for every command except `ls`, `stat`, `du`, `test` and `[`.
- Printers: `gh auth token`, `gh auth status -t|--show-token`, `aws configure get <secret key>`,
  `aws configure export-credentials`, `aws sts get-session-token|assume-role|get-federation-token`,
  `gcloud auth [application-default] print-access-token|print-identity-token`,
  `az account get-access-token`, `security find-generic-password|find-internet-password` with `-w`
  or `-g`, `security dump-keychain -d`, `kubectl config view --raw`, `kubectl get secret(s) -o ...`,
  `op read`, `op item get --reveal`, `git credential fill`.
- Bash: a store named in any word, redirect target, heredoc body or payload word denies, wherever
  its bytes go, so exfiltration needs no sink list. A printer anywhere denies. Exempt: a store that
  is the value of a consumer flag (`ssh`/`scp`/`sftp -i`, `ssh-add <key>`, `ssh-keygen -l|-y -f`,
  `kubectl --kubeconfig`, `KUBECONFIG=`); the tool reads the key without printing it.
- File tools: Read, Grep, Glob, Edit, Write, MultiEdit and NotebookEdit on a store path, or with a
  pattern that can match one.
- Dropped: project `.env` (the classifier allows an agent's own config), `*.pem` and `*.key`
  anywhere, filename keywords, WebFetch, the "reader with a variable argument" ask.
- Not claimed: secrets in environment variables, recursive reads of an ancestor (`grep -r x ~`),
  paths an interpreter builds at run time.

### guard.protected_files

- Protected: the live root (the git work tree holding the running package, found from the hook's
  own resolved path, or the package directory for a wheel install), guard's data dir
  (`~/.claude/guard/` or `GUARD_DATA_DIR`), and your patterns from `GUARD_PROTECTED_EXTRA` and
  `<cwd>/.claude/guard-protected.txt`. Worktrees and clones of guard stay editable.
- File tools: Edit, Write, MultiEdit and NotebookEdit whose target resolves inside a protected path.
- Bash: a segment that names a protected path (word, redirect target, heredoc body or payload word;
  absolute, `~`, `$HOME` or cwd-relative) denies unless its command is a reader: `cat`, `head`,
  `tail`, `less`, `wc`, `ls`, `stat`, `file`, `du`, `diff`, `cmp`, `shasum`, `md5`, `grep`, `rg`,
  `jq`, `sed -n` with print-only scripts, or a read-only `git` verb.
- Git in the live root (by `-C`, `--git-dir`, `--work-tree` or effective cwd): read verbs, `fetch`,
  `pull --ff-only` and `worktree add|list|prune|remove` pass; everything else denies.
- Guard's own write verbs (`guard mode <mode>`, `guard allowlist disable-rule|enable-rule`,
  `guard migrate-log`) deny; `--help` and read verbs pass.
- Hook registration: an Edit or MultiEdit of `~/.claude/settings.json` whose old text holds a guard
  `run-hook` command, or a Write that drops one, denies. Other settings edits stay with Claude
  Code, which routes `.claude` writes to the classifier.
- Dropped: lockdown patterns (Claude Code already treats `.git`, `.claude`, shell rc files and
  `.gitconfig` as protected paths), `.claude/subagent-scope.json`.

### guard.commit_message_validator

- Attribution: `Co-Authored-By:`, `Assisted-by:` or `Signed-off-by:` naming an AI tool, vendor or
  AI noreply address; `Claude-Session:` lines; "Generated with" footers; an AI address as
  `user.email` in the effective repo.
- Commands: `git commit`, `git merge` with a message, `git commit-tree`. `git` is found as in
  `bash.git_force_push`, so `git -C <repo> commit` is checked.
- Message sources: every `-m`/`--message`; `-F`/`--file <path>` (64 KiB cap); `-F -` or
  `-F /dev/stdin` fed by a heredoc or here-string in the same command (read from the command
  text); `-c`/`-C`/`--reuse-message`/`--reedit-message <rev>` (read with `git log -1 --format=%B`);
  `-t`/`--template <file>`.
- `--amend`, `--fixup`, `--squash` or `--no-edit` with no new message pass.
- Unreadable sources (a pipe into `-F -`, `-F $(...)`, a missing or oversize file, an editor set
  in the same command) deny with "use -m or -F <file>".
- Backstop: any command with a git commit verb and an attribution line in its text denies,
  whether or not the parse found the message.

## How a kept rule fails

1. **Deny or nothing.** Guard never returns `allow` or `ask`. A parser miss can only lose a deny;
   Claude Code's own checks and the classifier still run. Decisions no longer depend on the
   permission mode.
2. **One lexer, faithful to bash.** Quotes (`'...'`, `"..."`, `$'...'` decoded with bash's escapes
   and only outside quotes, `$"..."`), backslashes and line continuations, comments (`#` at word
   start; blanks are space and tab only, never NBSP), separators (`;` `&` `&&` `||` `|` `|&`
   newline), groups and subshells, substitutions (`$()`, backticks, `<()`, `>()`, bodies lexed in
   turn), heredocs (body kept with its command), unquoted brace expansion, tilde, and parameter
   expansion against in-command assignments and the hook's environment.
3. **Payloads.** A word that lexes as a command (it holds a blank or a separator and parses) is
   checked as one, recursively to depth 8. That covers `bash -c`, `watch`, `script -c`,
   `parallel`, `ssh`, `su -c`, `xargs sh -c`, `git rebase --exec` and `git -c alias.x='!...'`
   without a wrapper list.
4. **Unknown.** Anything the lexer can't model exactly (an unterminated quote, heredoc or
   substitution, expansion syntax it doesn't implement, nesting past depth 8, text past 64 KiB)
   makes the command unknown.
5. **Triggers.** Each rule has a text trigger, checked on the raw command and on decoded readings
   (quotes removed, backslashes removed, `$'...'` decoded): `rm`; `push`; a store path or printer;
   a protected path, `settings.json` or `guard`; a commit verb with an attribution line. Unknown plus any
   trigger denies. Unknown with no trigger is no decision, so a long heredoc of prose passes.
6. **Crashes.** An exception in a hook denies when the payload has a trigger, and is no decision
   otherwise. Both log `internal_error`.
7. **Tests.** Each rule gets deny rows for every pattern above and every bypass shape (quoting,
   newline, comment, wrapper, payload, git global option, unknown plus trigger), and pass rows for
   the false positives in the evidence below.

A crude version of these position-free checks over 29,859 distinct real commands from the last
30 days fired 4 times for push (2 force pushes to main, 1 `--mirror`, 1 lease push to a feature
branch, which now passes), 0 times for rm roots, and 5 times for credential paths (all guard
development).

## Every current rule

| Rule or feature | Verdict | Evidence |
|---|---|---|
| `bash.dangerous_rm`, always-deny `rm -rf /`, `/*`, `~`, `$HOME`, `rm -fr` forms | floor | 1 deny (a probe). Pass today: `rm -rf ~/`, `rm -rf ./*`, `rm -rf "$PWD"`, `rm -rf "$X/"`, `watch -n 1 '...'`, `script -c`, `parallel ::: ...`, `git rebase --exec`, the `$'...'`, quoted-newline and NBSP-comment splits. `echo / \| xargs rm -rf` returns allow |
| `bash.git_force_push`, `bash.git_force_refspec`, always-deny `git push --force`, `-f`, `--force-with-lease`, `--force-if-includes`, `--mirror` | floor, narrowed to shared branches | 5 denies: 2 lease pushes to main, 1 to a feature branch, 1 `--mirror` to a new empty repo, 1 test. Pass today: `push origin --delete main`, `push origin :main` |
| `guard.credential_check`, `bash.credential_leak`, `bash.secret_egress` | floor, one rule | credential_check disabled by its owner since 2026-09-30 after about 1,300 asks and denies, nearly all false: name keywords (`token`, `key`, `secret`), `.env`, `*.pem`, 449 "variable argument" asks. credential_leak and secret_egress 18 denies: 1 a token piped into a tool's env, the rest guard development. `echo ~128GB/s ; cat ~/.aws/credentials` crashes credential_check and gets allow from the validator; `cat <key> \| curl` passes secret_egress |
| `guard.protected_files` | floor, narrowed and completed | 63 denies. Since 2026-10-15: 1 real (an agent running `guard allowlist allow-command`), 3 `guard ... --help` reads and 12 edits to worktree copies (false; the copies are fixed by keying on the live path). Older settings.json, CLAUDE.md and `.git/hooks` denies came from the retired unattended mode. Pass today: writes to `bin/run-hook`, `allowlist.py`, `_registry.py`; `git -C <live> checkout` |
| `guard.commit_message_validator` | floor, fixed | 76 denies: 18 commands carried a trailer, 58 didn't (mostly "cannot be parsed" and clean `-F -` heredocs). Missed: a `git -C <repo> commit` with a Claude trailer passed on 2026-10-20 |
| Shape rules: `dangerous_construct` (all shapes), `dangerous_interpreter` (all shapes), always-deny `python -c`, `python3 -c`, `node -e`, `node --eval`, `eval_builtin`, `function_definition`, `trap_exploit`, `shell_wrapper`, `exec_wrapper`, `wrapper_stacking`, `env_split_string`, `var_expanded_head`, `glob_head`, `command_too_long`, `remote_shell_wrapper`, pipe-to-shell | delete | 4,880 denies, 0 real catches. Their one floor job, seeing inside payloads, moves to the contract above. The classifier covers `curl \| sh` (Code from External) |
| Git: always-deny `git add -A/./--all/-a`, `git branch -D`, `filter-branch`, `filter-repo`, `reflog expire/delete`, `gc --prune=now`, `git remote add/set-url/rename/remove/rm/prune/update/set-head/set-branches`, `env -i`; `git_ref_mutation`, `git_worktree_add`, `git_submodule_add`, `git_config_injection`, `git_read_exec`, `dangerous_env_sink`; the `git_c_validator` hook | delete | 161 denies, 0 real catches (`GIT_EDITOR=true`, `core.fsmonitor=false`, `--output=<scratch file>`, branch cleanup, a repo's first `remote add`). Classifier: Git Destructive, Remote Repoint, Irreversible Local Destruction, Untrusted Code Integration |
| Supply chain: `npx_remote`, `npm_url_install`, `pip_install_url`, `cargo/gem/go/helm_remote_install`, `registry_config`, ASK `pip install`, `uv pip install`, `make install` | delete | 1,060 denies (`npx wrangler`, `npx vitest`, `npm i -D`, `uv pip install -e <local>`), 0 catches. Classifier: Code from External, Package Registry Bypass |
| Cloud, cluster, database: `aws/az/gcloud_destructive`, `aws_s3_destructive`, all `admin_*`, `kubectl_destructive`, `iac_destruction`, `terraform destroy`, `db_cli_destructive`, `dropdb_or_mysqladmin`, `mongo_destructive`, `gh_api_destructive`, `gh repo delete`, `gh release delete`, `gpg_secret_delete` | delete | 15 denies (`gh api -X PUT` repo settings the owner asked for, `launchctl kickstart`, a SQLite WAL checkpoint), 0 catches. Classifier: Irreversible Deletion, Shared Cluster Mutation, Permission Grant. Drops the admin CLI catalog |
| Host: `disk_destruction`, `host_control`, `kernel_module_load`, `network_policy_wipe`, `process_attach`, `process_tree_kill`, all `chmod_*`, `fs_attr_sensitive`, `sudo_escalation`, `escalation_shell`, `sensitive_write`, `dangerous_construct:sensitive_target`, `persistence`, fork bomb, `conditional_denied_flag` | delete | 91 denies (`dd` into a scratch file, `crontab -l`, `find -exec cat {}`), 0 catches. Claude Code protects rc files and `.gitconfig`; classifier: Unauthorized Persistence |
| `secret_value`, `dns_exfil` | delete | 11 denies (a local database URL, a path in an env var, tests). Entropy guesses can't be exact. Classifier: Credential Leakage |
| Nudges: `tool_alternative`, `use_corpus_harness` | delete | 77 denies, advisory by design |
| Lockdown: `strict_default_deny`, `strict_feedback`, `guard mode lockdown`, lockdown patterns, the strict deny queue | delete | 14,672 denies in unattended loop runs, none since 2026-10-16. Auto mode replaced it |
| `agent_output_guard` | delete | 650 denies before background output was let through; 4 since, all false. Context hygiene, not safety |
| `subagent_scope` | delete | 3 denies, all in May; no scope file in use |
| `permission_request_logger` | keep | logs prompts, never decides |
| `allow` decisions and the ALLOW/ASK registry | delete | Guard returns allow when every segment looks read-only. A hook allow skips Claude Code's prompt step, which in auto mode is the classifier, so a misparse becomes an approval (see the rm and credential rows) |
| STEER tier, `RULE_TIERS` | delete | nothing left to steer |
| `enforce`, `shadow`, `off`, `disable_rules` | keep | `off` is the kill switch; `shadow` trials a rule change on live traffic |
| Silent pass on a hook crash | replace | about 430 real-session crashes since May, 373 from `~word` tokens (`Path.expanduser` raises), each one an unguarded call |

## Order of work

0. Lockfile: bump `filelock` and `virtualenv` so the CVE audit goes green on main.
1. Retire allowlisting (#87) and the parser fixes (#86).
2. This doc. Guard stops returning allow. STEER rules, the tier table and lockdown go.
3. The rest of the deleted rules, the admin catalog, and the `git_c_validator`,
   `agent_output_guard` and `subagent_scope` hooks (left as no-op stubs for a release so old
   settings don't error).
4. The lexer contract: unknown, triggers, payload scan, crashes.
5. `bash.dangerous_rm`. 6. `bash.git_force_push`. 7. `guard.commit_message_validator`.
8. `guard.protected_files`. 9. `guard.credential_check`, then it can be enabled again.

Each step is one PR with tests, a CHANGELOG entry and a re-baselined corpus.
