# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — orchestration destruction coverage

- `bash_command_validator`: ~30 new synthetic-deny matchers covering
  - **Cloud destruction**: `aws iam/ec2/rds/lambda/dynamodb/eks/ecr/ecs/kms/secretsmanager/ssm/s3` destructive verbs;
    `gcloud projects/iam/secrets/sql/run/storage delete`; `az group/aks/vm/storage/keyvault/sql delete`.
  - **DB CLIs**: `psql/mysql/mariadb/cqlsh/sqlite3 -c "DROP|DELETE FROM|TRUNCATE|ALTER|GRANT|REVOKE"`;
    `sqlite3 <db> "<destructive SQL>"` (no -c form); `redis-cli FLUSHALL/FLUSHDB/CONFIG/SAVE/SHUTDOWN`;
    `dropdb`, `mysqladmin drop`; `mongo --eval` with destructive ops.
  - **Disk / FS / network destruction**: `mkfs`, `dd of=/dev/...`, `shred /dev/...`, `parted/fdisk/wipefs`,
    `diskutil eraseDisk`; `iptables -F`, `nft flush ruleset`, `ufw reset`.
  - **Persistence + privilege escalation**: writes to `~/.bashrc`, `~/.ssh/authorized_keys`, `/etc/sudoers`,
    `/etc/profile.d/*`, `/etc/cron.d/*`, `~/Library/LaunchAgents/*`, `/etc/systemd/system/*`,
    PATH-hijack writes to `/usr/local/bin/`; `crontab -e/-r`, `at`, `systemctl enable/start/link/mask`,
    `launchctl load`, `visudo`; chmod setuid/setgid; chmod against sensitive targets;
    `sudo -i/-s/su`; `insmod/modprobe`; `gdb -p`/`strace -p`/`ptrace`.
  - **IaC destruction**: `terraform apply -destroy`, `pulumi destroy`, `cdk destroy`,
    `helm uninstall`, `vault {kv,secrets,token,policy} {delete,destroy,revoke}`, `argocd app delete`.
  - **Remote-package install**: `npm/yarn/pnpm/bun install <URL|git+|github:|local>`;
    `npx/pnpx/bunx <pkg>`; `cargo install --git/--path/--registry`;
    `go install/run/get <pkg-with-@version>`; `gem install --source <url>`;
    `helm install <URL>`; `helm repo add <URL>`.
  - **Pipeline-to-interpreter**: `curl evil | python|ruby|perl|php|lua|bun|deno`.
  - **Encoding evasion**: `trap '<cmd>' EXIT`, `env -S '<cmd>'`, `function-def + invoke`,
    glob in command head, `stdbuf/watch/flock/chrt/taskset/runuser/chroot/unshare/firejail` wrappers
    around dangerous payloads.
  - **Remote-shell wrappers**: `ssh host '<cmd>'`, `docker/podman/lxc/kubectl exec`, `nsenter`.
  - **DNS exfil heuristic**: `ping/dig/host/nslookup` with DNS labels >50 chars.
  - **Git history destruction**: `git filter-branch`, `git filter-repo`,
    `git reflog expire/delete`, `git gc --prune=now`,
    `git push --force-with-lease`, `--force-if-includes`, `--mirror`, `+<refspec>`.
  - **Git submodule/worktree path scoping**: `git submodule add <url>` denied;
    `git worktree add` denied only when target resolves under a system root.
- `git_c_validator`: detects fused `-c<key>=val` (no-space), `-c=key=val`,
  and `--config-env=key=ENV` forms — closes the bypass where the previous
  parser only handled `-c key=val` (separate tokens).
- `commit_message_validator`: refuses `git commit -F <path>` when the path
  resolves outside cwd or under sensitive system roots (/etc, /proc,
  ~/.ssh, ~/.aws, ~/.gnupg). Opens the resolved file with `O_NOFOLLOW`
  to close the symlink-TOCTOU window. Prevents `-F /etc/passwd`
  content-disclosure into commit body.
- `protected_files`: adds `.git/hooks`, `.git/config`, `.git/info/attributes`,
  `.git/info/exclude`, `.gitmodules`, `.gitattributes`. Directory-pattern
  matching scoped to patterns whose last segment has no `.`.
- Registry: `GIT_CONFIG_EXEC_SINKS` extended with `core.attributesfile`,
  `color.pager`, `uploadpack.packobjectshook`, `protocol.allow`,
  `receive.procreceiverefs`. Glob patterns extended with `pager.*` and
  `protocol.*.allow`.
- Test surface: 500+ parametrized cases in
  `tests/integration/test_synth_matchers_coverage.py` exercising every
  matcher family with paired DENY / LEGIT cases.

### Fixed (review pass 2)

- `_is_git_worktree_add` no longer denies `git worktree add /Users/...` /
  `/home/...` — pass-1 reused `_DANGEROUS_PATH_PREFIXES` which includes user
  home roots, breaking the canonical worktree shape on macOS/Linux. New
  `_WORKTREE_DANGEROUS_PREFIXES` excludes `/Users/`, `/home/`, `/private/`.
- `_is_chmod_sensitive_target` no longer denies hardening commands like
  `chmod 600 ~/.ssh/id_rsa`. Now: any chmod against system roots
  (`/etc/sudoers`) denies; chmod against home subset (`~/.ssh`, `~/.aws`,
  `~/.gnupg`) denies only when the mode grants group/other access.
- New `_SYNTH_CHMOD_SENSITIVE_TARGET_DENY` label so the audit-log reason
  no longer claims "setuid/setgid bit" when the trigger was a permissive
  mode against a sensitive path.
- CI smoke jobs (`install-smoke`, `testpypi-smoke`) now install
  `pytest-xdist` so the suite-wide `addopts = -n auto --dist loadfile`
  doesn't fail with `unrecognized arguments`.

### Fixed (review pass)

- `_match_always_deny_literal` recognises `prefix=value` form
  (`git push --force-with-lease=ref` was bypassing the literal DENY).
- `git push +HEAD:main` (3-token, no remote) now denied (was missing the
  refspec-force matcher).
- `bun run /tmp/x.js` / `bun test ./script.ts` denied (was exempted as
  package subcommand; now distinguishes script-name from script-path).
- `chmod 666 /etc/sudoers` denied (was passing because `_is_chmod_dangerous`
  required recursive AND 777).
- `docker exec --help <container> rm -rf /` denied (the `--help`
  short-circuit was positional-blind; now requires `--help` to stand alone).
- `_is_pipe_to_interpreter` wired into the dispatcher (was orphan).

## [1.0.0] - 2026-04-30

First stable release. Guard ships seven stdlib-only `PreToolUse` hooks that
sit between Claude Code and the tool surface, denying high-risk actions
before they reach the host. The hook contract, decision-log schema, and
autonomous-mode behavior are now considered stable for the 1.x line.

### Added

- `bash_command_validator` — denies dangerous shell shapes (rm -rf,
  fork bombs, curl|sh, interpreter `-c` eval, runner-prefix bypasses).
- `git_c_validator` — blocks `git -c <key>=<val>` injection of executable
  config keys (alias.\*, core.pager, core.editor, filter.\*).
- `credential_check` — scans tool inputs for API keys, tokens, private
  keys, and provider-specific secret shapes before they leave the agent.
- `commit_message_validator` — rejects commit messages that leak
  AI-tool attribution markers (Co-Authored-By footers, generated-with
  notices, named tool branding).
- `agent_output_guard` — denies direct reads of dispatched-subagent
  output transcripts so context is preserved for the orchestrator.
- `protected_files` — forces an ASK confirmation on edits to guard's
  own validator files and to the Claude Code settings files that
  govern hook activation.
- `subagent_scope` — restricts what a dispatched subagent can read or
  modify based on a per-task allowlist.
- JSONL decision log (schema v1) at `~/.claude/guard-decisions.jsonl`
  for after-the-fact audit of every allow/deny.
- Autonomous-mode strict default-deny: when `CLAUDE_AUTONOMOUS=1` is set
  the hooks switch to fail-closed semantics for ambiguous inputs.

### Security

- Defense-in-depth posture: each hook is independent, and a deny from
  any hook short-circuits the tool call. See [SECURITY.md](SECURITY.md)
  for the threat model and reporting policy.
- Mitigates the class of agent-confusion bypasses tracked under
  CVE-2025-59356 by validating the literal command shape rather than
  trusting model-emitted intent.

[Unreleased]: https://github.com/TracineHQ/guard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/TracineHQ/guard/releases/tag/v1.0.0
