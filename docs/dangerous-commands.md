# Dangerous commands

This page is a human-readable summary of guard's command classifications.
**The registry (`src/guard/registry.py`) is the source of truth; this doc
summarizes it.** When the two disagree, the registry wins.

Commands are classified into four tiers:

- **ALLOW** — auto-permitted. Read-only or otherwise safe by construction.
- **ASK** — surfaced for human confirmation. Most write operations.
- **DENY** — refused unconditionally, even with a human in the loop.
- **CLASSIFIER** — bare prefix is allowed but routed through a custom
  classifier (because flag forms re-exec arbitrary code).

This doc focuses on the DENY tier and the riskier ASK entries. The ALLOW
tier is large and uninteresting — read the registry directly if you need
the full list.

## Always-deny

These prefixes are in `ALWAYS_DENY` and block in both interactive and
autonomous mode.

### Filesystem destruction (`rm-deny`)

| Prefix | Reason |
|---|---|
| `rm -rf /` | Recursive root deletion |
| `rm -rf /*` | Recursive root deletion |
| `rm -rf ~` | Recursive home deletion |
| `rm -rf $HOME` | Recursive home deletion |
| `rm -fr /` | Variant — recursive root deletion |
| `rm -fr ~` | Variant — recursive home deletion |
| `rm -rf --no-preserve-root /` | Bypass attempt against `--preserve-root` |

### Indiscriminate git staging (`git-deny`)

| Prefix | Reason |
|---|---|
| `git add -A` | Stages all files indiscriminately |
| `git add --all` | Stages all files indiscriminately |
| `git add .` | Stages all files indiscriminately |
| `git add -a` | Stages all files indiscriminately |
| `git branch -D` | Force-deletes a branch (data loss risk) |

### Interpreter re-exec (`interpreter-deny`)

| Prefix | Reason |
|---|---|
| `python -c` | Re-execs arbitrary code |
| `python3 -c` | Re-execs arbitrary code |
| `node -e` | Re-execs arbitrary code |
| `node --eval` | Re-execs arbitrary code |

### Environment-clearing wrappers (`env-deny`)

| Prefix | Reason |
|---|---|
| `env -i` | Commonly used to wrap RCE (e.g. `env -i bash -c '...'`) |

### Infrastructure destruction (`terraform-deny`)

| Prefix | Reason |
|---|---|
| `terraform destroy` | Destroys infrastructure |

## Classifier-routed prefixes

These appear in the registry as ALLOW for permission generation but are
routed through a custom classifier in `bash_command_validator` because
naive prefix matching would let attacker-controlled flags re-exec code.

| Prefix | Classifier | Why |
|---|---|---|
| `env` | `_is_safe_env` | `env -i bash -c ...` is a canonical RCE wrapper |
| `python` | `_is_safe_interpreter` | `python -c '...'` re-execs arbitrary code |
| `python3` | `_is_safe_interpreter` | Same as `python` |
| `node` | `_is_safe_interpreter` | `node -e '...'` and `--eval` are RCE primitives |

## High-risk ASK commands

These are not denied but are surfaced for human confirmation. In autonomous
mode (`CLAUDE_AUTONOMOUS=1`) they are denied with a queued-for-session-end
message.

### Filesystem writes

`rm`, `rm -rf` (against non-root paths), `rmdir`, `mv`.

### Git writes

`git add` (explicit paths), `git commit`, `git push`, `git pull`, `git
fetch`, `git checkout`, `git switch`, `git merge`, `git rebase`, `git
reset`, `git revert`, `git stash`, `git clean`, `git restore`, `git
cherry-pick`, `git branch -d`, `git branch -m`, `git tag -a`, `git tag -d`.

### Cloud writes

`gcloud secrets versions access`, `gcloud secrets create`, `gcloud secrets
versions add`, `gcloud services enable`, `gcloud iam`, `gcloud auth
print-access-token`, `gcloud auth print-identity-token`, `gcloud run
deploy`, `gcloud app deploy`.

### Docker writes

`docker run`, `docker stop`, `docker rm`, `docker rmi`, `docker build`,
`docker push`, `docker pull`, `docker compose up`, `docker compose down`,
`docker system prune`.

### GitHub CLI writes

`gh pr create|merge|close|comment|review|edit|reopen`, `gh issue
create|close|comment|edit`, `gh release create`, `gh run cancel|rerun`,
`gh workflow run`.

### Terraform writes

`terraform apply`, `terraform import`, `terraform state mv|rm`, `terraform
taint|untaint`, `terraform workspace new|select|delete`.

### Package installs

`pip install`, `pip uninstall`, `uv pip install`, `make install`.

### Chrome CLI writes

`chrome launch|stop|navigate|click|fill|eval|wait|fetch|open|close|reload`.

## Adding to the registry

To add a new dangerous prefix:

1. Add a `CommandRule` to `COMMANDS` in `src/guard/registry.py` with the
   appropriate `Safety` tier and `category`.
2. For DENY entries, ensure the prefix is exact-match-or-followed-by-space
   (the matcher uses `_match_always_deny`).
3. Update tests under `tests/` to cover the new entry.
4. Re-run `just check`.

This doc doesn't auto-regenerate; update it when the registry changes if
the new entry belongs in one of the categories above.
