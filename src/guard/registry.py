# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Single source of truth for command safety classifications.

Imported by ``bash_command_validator`` for ``SAFE_PREFIXES``,
``STRICT_FEEDBACK`` and the synthetic-deny lookup tables.
"""
# The COMMANDS table is the contract for this module. Lints that would force
# restructuring it are silenced:
#   D101: Safety/CommandRule are self-describing; docstrings would just restate names.
#   E501: a few strict_feedback strings are slightly over 100 chars; rewriting
#         them changes the user-visible message.
# ruff: noqa: D101, E501

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Safety(Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass
class CommandRule:
    prefix: str
    safety: Safety
    reason: str
    category: str
    pipe_safe: bool = False
    strict_feedback: str = ""
    # When True, the command is documented as ALLOW for permission generation
    # but is NOT exported via SAFE_PREFIXES. Bash command validation must route
    # the prefix through a custom classifier (e.g. `_is_safe_env`,
    # `_is_safe_interpreter`) because a bare prefix match would let attacker-
    # controlled flags re-exec arbitrary code (`env -i bash -c ...`,
    # `python -c '...'`, `node -e '...'`).
    requires_classifier: bool = False


# === Registry ===

COMMANDS: list[CommandRule] = [
    # --- Git Read (ALLOW) ---
    CommandRule("git status", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git log", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git diff", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git show", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git branch", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git remote", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git blame", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git rev-parse", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git describe", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git tag", Safety.ALLOW, "Read-only git (listing)", "git-read"),
    CommandRule("git ls-files", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git grep", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git stash list", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git stash show", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git config --get", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git config --list", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git shortlog", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git rev-list", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git name-rev", Safety.ALLOW, "Read-only git", "git-read"),
    CommandRule("git mv", Safety.ALLOW, "Renames files (safe)", "git-write-safe"),
    CommandRule("git worktree", Safety.ALLOW, "Worktree management for agents", "git-write-safe"),
    # --- Git Write (ASK) ---
    CommandRule(
        "git add",
        Safety.ASK,
        "Stages files",
        "git-write",
        strict_feedback="Queue git add for session end. Continue implementing.",
    ),
    CommandRule(
        "git commit",
        Safety.ASK,
        "Creates commit",
        "git-write",
        strict_feedback="Queue git commit for session end. Continue implementing.",
    ),
    CommandRule(
        "git push",
        Safety.ASK,
        "Pushes to remote",
        "git-write",
        strict_feedback="Queue git push for session end. Complete all work first.",
    ),
    CommandRule(
        "git pull",
        Safety.ASK,
        "Pulls from remote",
        "git-write",
        strict_feedback="Git pull requires confirmation. Note it for session end.",
    ),
    CommandRule(
        "git fetch",
        Safety.ASK,
        "Fetches from remote",
        "git-write",
        strict_feedback="Queue git fetch for session end.",
    ),
    CommandRule(
        "git checkout",
        Safety.ASK,
        "Switches branches",
        "git-write",
        strict_feedback="Use 'git branch' to check branches. Queue checkout for session end.",
    ),
    CommandRule(
        "git switch",
        Safety.ASK,
        "Switches branches",
        "git-write",
        strict_feedback="Queue branch switch for session end.",
    ),
    CommandRule(
        "git merge",
        Safety.ASK,
        "Merges branches",
        "git-write",
        strict_feedback="Queue merge for session end.",
    ),
    CommandRule(
        "git rebase",
        Safety.ASK,
        "Rebases commits",
        "git-write",
        strict_feedback="Queue rebase for session end.",
    ),
    CommandRule(
        "git reset",
        Safety.ASK,
        "Resets state",
        "git-write",
        strict_feedback="Git reset is destructive. Flag for human review.",
    ),
    CommandRule(
        "git revert",
        Safety.ASK,
        "Reverts commits",
        "git-write",
        strict_feedback="Queue revert for session end.",
    ),
    CommandRule(
        "git stash",
        Safety.ASK,
        "Stashes changes",
        "git-write",
        strict_feedback="Use Write tool to save state to a file instead.",
    ),
    CommandRule(
        "git stash pop",
        Safety.ASK,
        "Pops stash",
        "git-write",
        strict_feedback="Queue stash pop for session end.",
    ),
    CommandRule(
        "git stash drop",
        Safety.ASK,
        "Drops stash",
        "git-write",
        strict_feedback="Queue stash drop for session end.",
    ),
    CommandRule(
        "git clean",
        Safety.ASK,
        "Removes untracked files",
        "git-write",
        strict_feedback="Git clean is destructive. Flag for human review.",
    ),
    CommandRule(
        "git restore",
        Safety.ASK,
        "Discards changes",
        "git-write",
        strict_feedback="Git restore discards work. Flag for human review.",
    ),
    CommandRule(
        "git cherry-pick",
        Safety.ASK,
        "Cherry-picks commits",
        "git-write",
        strict_feedback="Queue cherry-pick for session end.",
    ),
    # git branch -d/-m and git tag -a/-d (and bare ``tag/branch <name>`` creation,
    # remote write-actions) are denied in BOTH modes by the ``git_ref_violation``
    # predicate via the ``bash.git_ref_mutation`` synthetic matcher -- a ref
    # mutation under a read-only listing prefix. They are intentionally NOT ASK
    # rules: a local ref write should not auto-run unattended, nor silently in an
    # interactive agent session.
    # --- Git DENY ---
    CommandRule("git add -A", Safety.DENY, "Adds all files indiscriminately", "git-deny"),
    CommandRule("git add --all", Safety.DENY, "Adds all files indiscriminately", "git-deny"),
    CommandRule("git add .", Safety.DENY, "Adds all files indiscriminately", "git-deny"),
    CommandRule("git add -a", Safety.DENY, "Adds all files indiscriminately", "git-deny"),
    CommandRule("git branch -D", Safety.DENY, "Force-deletes branch", "git-deny"),
    # --- Git history destruction (DENY) ---
    # ``filter-branch`` / ``filter-repo`` rewrite every commit and force-push
    # the result. ``reflog expire --expire=now --all`` + ``gc --prune=now``
    # destroys the safety net for recovery. None of these have a non-recovery
    # use case in agent context.
    CommandRule("git filter-branch", Safety.DENY, "Rewrites history irreversibly", "git-deny"),
    CommandRule("git filter-repo", Safety.DENY, "Rewrites history irreversibly", "git-deny"),
    CommandRule(
        "git reflog expire",
        Safety.DENY,
        "Destroys reflog (recovery safety net)",
        "git-deny",
    ),
    CommandRule(
        "git reflog delete",
        Safety.DENY,
        "Destroys reflog entries",
        "git-deny",
    ),
    CommandRule(
        "git gc --prune=now", Safety.DENY, "Permanently removes unreachable objects", "git-deny"
    ),
    CommandRule(
        "git gc --aggressive --prune=now",
        Safety.DENY,
        "Permanently removes unreachable objects",
        "git-deny",
    ),
    # --- Force-push variants (DENY) ---
    # All force-push shapes rewrite remote history and are denied. ``--force``
    # / ``-f`` are the bare forms; ``--force-with-lease`` is the "safer"
    # lease-checked variant that still rewrites; ``--mirror`` overwrites every
    # remote ref; ``+HEAD:main`` is the refspec form (matched by a separate
    # synthetic-deny matcher in bash_command_validator).
    CommandRule(
        "git push --force",
        Safety.DENY,
        "Force-rewrites remote history",
        "git-deny",
    ),
    CommandRule(
        "git push -f",
        Safety.DENY,
        "Force-rewrites remote history (-f short form of --force)",
        "git-deny",
    ),
    CommandRule(
        "git push --force-with-lease",
        Safety.DENY,
        "Force-rewrites remote history (lease-checked, but still destructive)",
        "git-deny",
    ),
    CommandRule(
        "git push --force-if-includes",
        Safety.DENY,
        "Force-rewrites remote history",
        "git-deny",
    ),
    CommandRule(
        "git push --mirror",
        Safety.DENY,
        "Mirrors local refs to remote, deleting any remote-only refs",
        "git-deny",
    ),
    # --- Git remote mutations (DENY) ---
    # Bare ``git remote`` lists remotes (read-only) and stays ALLOW above. The
    # write-side subcommands re-point ``origin`` to attacker-controlled URLs;
    # the follow-on ``git push origin main`` then goes to the attacker.
    # Read-only forms (``git remote -v``, ``git remote show``,
    # ``git remote get-url``) still fall through to the bare ALLOW.
    CommandRule("git remote add", Safety.DENY, "Adds a remote URL", "git-deny"),
    CommandRule("git remote set-url", Safety.DENY, "Re-points an existing remote", "git-deny"),
    CommandRule("git remote rename", Safety.DENY, "Renames a remote", "git-deny"),
    CommandRule("git remote remove", Safety.DENY, "Removes a remote", "git-deny"),
    CommandRule("git remote rm", Safety.DENY, "Removes a remote (rm alias)", "git-deny"),
    CommandRule("git remote prune", Safety.DENY, "Prunes remote-tracking refs", "git-deny"),
    CommandRule("git remote update", Safety.DENY, "Fetches all configured remotes", "git-deny"),
    CommandRule(
        "git remote set-head", Safety.DENY, "Resets the remote's default branch", "git-deny"
    ),
    CommandRule(
        "git remote set-branches",
        Safety.DENY,
        "Restricts the branches fetched from a remote",
        "git-deny",
    ),
    # --- File Read (ALLOW) ---
    CommandRule("cat", Safety.ALLOW, "Read file", "file-read", pipe_safe=True),
    CommandRule("head", Safety.ALLOW, "Read file head", "file-read", pipe_safe=True),
    CommandRule("tail", Safety.ALLOW, "Read file tail", "file-read", pipe_safe=True),
    CommandRule("less", Safety.ALLOW, "Pager", "file-read", pipe_safe=True),
    CommandRule("wc", Safety.ALLOW, "Word count", "file-read", pipe_safe=True),
    CommandRule("file", Safety.ALLOW, "File type", "file-read"),
    CommandRule("stat", Safety.ALLOW, "File stats", "file-read"),
    CommandRule("ls", Safety.ALLOW, "List directory", "file-read"),
    CommandRule("tree", Safety.ALLOW, "Tree view", "file-read"),
    CommandRule("du", Safety.ALLOW, "Disk usage", "file-read"),
    CommandRule("df", Safety.ALLOW, "Disk free", "file-read"),
    # --- Search (ALLOW) ---
    CommandRule("grep", Safety.ALLOW, "Text search", "search", pipe_safe=True),
    CommandRule("rg", Safety.ALLOW, "Ripgrep search", "search", pipe_safe=True),
    CommandRule("ag", Safety.ALLOW, "Silver searcher", "search"),
    CommandRule("ack", Safety.ALLOW, "Ack search", "search"),
    # --- Text Processing (ALLOW, pipe-safe) ---
    CommandRule("jq", Safety.ALLOW, "JSON processing", "text", pipe_safe=True),
    CommandRule("sort", Safety.ALLOW, "Sort lines", "text", pipe_safe=True),
    CommandRule("uniq", Safety.ALLOW, "Unique lines", "text", pipe_safe=True),
    CommandRule("cut", Safety.ALLOW, "Cut fields", "text", pipe_safe=True),
    CommandRule("tr", Safety.ALLOW, "Translate chars", "text", pipe_safe=True),
    # --- General Utilities (ALLOW) ---
    CommandRule("date", Safety.ALLOW, "Date/time", "util"),
    # `env` is ALLOW but routed through `_is_safe_env` because `env -i bash -c`
    # is the canonical shell-recursion bypass; bare prefix matching is unsafe.
    CommandRule("env", Safety.ALLOW, "Environment vars", "util", requires_classifier=True),
    CommandRule("which", Safety.ALLOW, "Find executable", "util"),
    CommandRule("whereis", Safety.ALLOW, "Find executable", "util"),
    CommandRule("type", Safety.ALLOW, "Command type", "util"),
    CommandRule("pwd", Safety.ALLOW, "Print working dir", "util"),
    CommandRule("ps", Safety.ALLOW, "Process list", "util"),
    CommandRule("true", Safety.ALLOW, "No-op", "util"),
    CommandRule("false", Safety.ALLOW, "No-op", "util"),
    CommandRule("test", Safety.ALLOW, "Test expression", "util"),
    CommandRule("bc", Safety.ALLOW, "Calculator", "util"),
    CommandRule("cd", Safety.ALLOW, "Change directory", "util"),
    CommandRule("mkdir -p", Safety.ALLOW, "Create directory", "util"),
    # --- Read-only diagnostics (ALLOW) ---
    # Genuinely read-only; previously hard-denied by strict default-deny. `fd`
    # is intentionally absent (it has --exec/-x, an RCE sink like find -exec).
    CommandRule("hostname", Safety.ALLOW, "Hostname", "util"),
    CommandRule("whoami", Safety.ALLOW, "Current user", "util"),
    CommandRule("id", Safety.ALLOW, "User/group ids", "util"),
    CommandRule("uname", Safety.ALLOW, "System info", "util"),
    CommandRule("diff", Safety.ALLOW, "Compare files", "file-read", pipe_safe=True),
    CommandRule("cmp", Safety.ALLOW, "Compare files", "file-read"),
    CommandRule("basename", Safety.ALLOW, "Strip path", "util"),
    CommandRule("dirname", Safety.ALLOW, "Path directory", "util"),
    CommandRule("realpath", Safety.ALLOW, "Resolve path", "util"),
    CommandRule("comm", Safety.ALLOW, "Compare sorted files", "text"),
    CommandRule("column", Safety.ALLOW, "Columnate text", "text", pipe_safe=True),
    CommandRule("printenv", Safety.ALLOW, "Print env var", "util"),
    # POSIX test builtin (`[`) and bash conditional (`[[`) — read-only
    # predicates, peers of the already-allowed `test`.
    CommandRule("[", Safety.ALLOW, "Test expression", "util"),
    CommandRule("[[", Safety.ALLOW, "Conditional expression", "util"),
    # --- Python (ALLOW) ---
    # Bare `python`/`python3` are routed through `_is_safe_interpreter` because
    # `python -c '...'` / `-m <module>` re-exec arbitrary code; bare prefix
    # matching would allow attacker-controlled flag forms.
    CommandRule("python3", Safety.ALLOW, "Python execution", "python", requires_classifier=True),
    CommandRule("python", Safety.ALLOW, "Python execution", "python", requires_classifier=True),
    CommandRule(".venv/bin/python", Safety.ALLOW, "Venv python", "python"),
    CommandRule("uv run python", Safety.ALLOW, "UV python", "python"),
    # --- Testing (ALLOW) ---
    CommandRule("pytest", Safety.ALLOW, "Python tests", "testing"),
    CommandRule("python -m pytest", Safety.ALLOW, "Python tests", "testing"),
    CommandRule("python3 -m pytest", Safety.ALLOW, "Python tests", "testing"),
    CommandRule(".venv/bin/pytest", Safety.ALLOW, "Venv pytest", "testing"),
    CommandRule("uv run pytest", Safety.ALLOW, "UV pytest", "testing"),
    CommandRule("npx vitest", Safety.ALLOW, "Node tests", "testing"),
    CommandRule("uvx pytest", Safety.ALLOW, "UVX pytest", "testing"),
    # --- Linting (ALLOW) ---
    CommandRule("uvx semgrep", Safety.ALLOW, "Semgrep analysis", "linting"),
    CommandRule("uvx ruff", Safety.ALLOW, "UVX ruff", "linting"),
    CommandRule("uvx mypy", Safety.ALLOW, "UVX mypy", "linting"),
    CommandRule("uvx black", Safety.ALLOW, "UVX black", "linting"),
    CommandRule("uvx pyright", Safety.ALLOW, "UVX pyright", "linting"),
    CommandRule("ruff", Safety.ALLOW, "Ruff linter", "linting"),
    CommandRule("uv run ruff", Safety.ALLOW, "UV ruff", "linting"),
    CommandRule("mypy", Safety.ALLOW, "Type checker", "linting"),
    CommandRule("uv run mypy", Safety.ALLOW, "UV mypy", "linting"),
    CommandRule("pyright", Safety.ALLOW, "Type checker", "linting"),
    CommandRule("npx eslint", Safety.ALLOW, "ESLint", "linting"),
    CommandRule("npx tsc", Safety.ALLOW, "TypeScript compiler", "linting"),
    CommandRule("uvx vulture", Safety.ALLOW, "Dead code detection", "linting"),
    CommandRule("uvx pre-commit run", Safety.ALLOW, "Pre-commit checks", "linting"),
    CommandRule("pre-commit run", Safety.ALLOW, "Pre-commit checks", "linting"),
    CommandRule("uvx pip-audit", Safety.ALLOW, "Security audit", "linting"),
    # --- Node (ALLOW) ---
    # Bare `node` is routed through `_is_safe_interpreter` — `node -e '...'`
    # and `node --eval` are RCE primitives that bypass bare prefix matching.
    CommandRule("node", Safety.ALLOW, "Node execution", "node", requires_classifier=True),
    CommandRule("npm run", Safety.ALLOW, "NPM scripts", "node"),
    CommandRule("npm test", Safety.ALLOW, "NPM test", "node"),
    CommandRule("npm list", Safety.ALLOW, "NPM list", "node"),
    CommandRule("npm ls", Safety.ALLOW, "NPM list", "node"),
    CommandRule("npm view", Safety.ALLOW, "NPM view", "node"),
    CommandRule("npm outdated", Safety.ALLOW, "NPM outdated", "node"),
    CommandRule("npm run build", Safety.ALLOW, "NPM build", "node"),
    CommandRule("npm run dev", Safety.ALLOW, "NPM dev server", "node"),
    # --- Cloud Read (ALLOW) ---
    CommandRule("gcloud secrets list", Safety.ALLOW, "List secrets", "cloud-read"),
    CommandRule("gcloud config list", Safety.ALLOW, "Show config", "cloud-read"),
    CommandRule("gcloud config get", Safety.ALLOW, "Get config", "cloud-read"),
    CommandRule("gcloud logging read", Safety.ALLOW, "Read logs", "cloud-read"),
    CommandRule("gcloud storage ls", Safety.ALLOW, "List storage", "cloud-read"),
    CommandRule("gcloud projects list", Safety.ALLOW, "List projects", "cloud-read"),
    CommandRule("gcloud projects describe", Safety.ALLOW, "Describe project", "cloud-read"),
    CommandRule("gcloud services list", Safety.ALLOW, "List services", "cloud-read"),
    CommandRule("gcloud run services list", Safety.ALLOW, "List Cloud Run", "cloud-read"),
    CommandRule("gcloud run services describe", Safety.ALLOW, "Describe Cloud Run", "cloud-read"),
    CommandRule("gcloud auth list", Safety.ALLOW, "List auth", "cloud-read"),
    CommandRule("gsutil ls", Safety.ALLOW, "List GCS", "cloud-read"),
    # --- Docker Read (ALLOW) ---
    CommandRule("docker ps", Safety.ALLOW, "List containers", "docker-read"),
    CommandRule("docker logs", Safety.ALLOW, "Container logs", "docker-read"),
    CommandRule("docker images", Safety.ALLOW, "List images", "docker-read"),
    CommandRule("docker inspect", Safety.ALLOW, "Inspect container", "docker-read"),
    # --- Destructive File Ops (ASK) ---
    CommandRule(
        "rm",
        Safety.ASK,
        "Delete files",
        "file-write",
        strict_feedback="File deletion requires confirmation. Flag files for deletion at session end.",
    ),
    CommandRule(
        "rm -rf",
        Safety.ASK,
        "Force delete files",
        "file-write",
        strict_feedback="Recursive deletion requires confirmation. Flag for session end.",
    ),
    CommandRule(
        "rmdir",
        Safety.ASK,
        "Delete directory",
        "file-write",
        strict_feedback="Directory deletion requires confirmation. Flag for session end.",
    ),
    CommandRule(
        "mv",
        Safety.ASK,
        "Move/rename files",
        "file-write",
        strict_feedback="Use Write tool to create new file, flag old for deletion at session end.",
    ),
    # --- GitHub CLI Write (ASK) ---
    CommandRule(
        "gh pr create",
        Safety.ASK,
        "Create PR",
        "gh-write",
        strict_feedback="Queue PR creation for session end.",
    ),
    CommandRule(
        "gh pr merge",
        Safety.ASK,
        "Merge PR",
        "gh-write",
        strict_feedback="Queue PR merge for session end.",
    ),
    CommandRule(
        "gh pr close",
        Safety.ASK,
        "Close PR",
        "gh-write",
        strict_feedback="Queue PR close for session end.",
    ),
    CommandRule(
        "gh pr comment",
        Safety.ASK,
        "Comment on PR",
        "gh-write",
        strict_feedback="Queue PR comment for session end.",
    ),
    CommandRule(
        "gh pr review",
        Safety.ASK,
        "Review PR",
        "gh-write",
        strict_feedback="Queue PR review for session end.",
    ),
    CommandRule(
        "gh pr edit",
        Safety.ASK,
        "Edit PR",
        "gh-write",
        strict_feedback="Queue PR edit for session end.",
    ),
    CommandRule(
        "gh pr reopen",
        Safety.ASK,
        "Reopen PR",
        "gh-write",
        strict_feedback="Queue PR reopen for session end.",
    ),
    CommandRule(
        "gh issue create",
        Safety.ASK,
        "Create issue",
        "gh-write",
        strict_feedback="Queue issue creation for session end.",
    ),
    CommandRule(
        "gh issue close",
        Safety.ASK,
        "Close issue",
        "gh-write",
        strict_feedback="Queue issue close for session end.",
    ),
    CommandRule(
        "gh issue comment",
        Safety.ASK,
        "Comment on issue",
        "gh-write",
        strict_feedback="Queue issue comment for session end.",
    ),
    CommandRule(
        "gh issue edit",
        Safety.ASK,
        "Edit issue",
        "gh-write",
        strict_feedback="Queue issue edit for session end.",
    ),
    CommandRule(
        "gh release create",
        Safety.ASK,
        "Create release",
        "gh-write",
        strict_feedback="Queue release creation for session end.",
    ),
    CommandRule(
        "gh run cancel",
        Safety.ASK,
        "Cancel workflow run",
        "gh-write",
        strict_feedback="Queue run cancellation for session end.",
    ),
    CommandRule(
        "gh run rerun",
        Safety.ASK,
        "Rerun workflow",
        "gh-write",
        strict_feedback="Queue workflow rerun for session end.",
    ),
    CommandRule(
        "gh workflow run",
        Safety.ASK,
        "Trigger workflow",
        "gh-write",
        strict_feedback="Queue workflow trigger for session end.",
    ),
    # --- Docker Write (ASK) ---
    CommandRule(
        "docker run",
        Safety.ASK,
        "Run container",
        "docker-write",
        strict_feedback="Container execution requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "docker stop",
        Safety.ASK,
        "Stop container",
        "docker-write",
        strict_feedback="Queue container stop for session end.",
    ),
    CommandRule(
        "docker rm",
        Safety.ASK,
        "Remove container",
        "docker-write",
        strict_feedback="Queue container removal for session end.",
    ),
    CommandRule(
        "docker rmi",
        Safety.ASK,
        "Remove image",
        "docker-write",
        strict_feedback="Queue image removal for session end.",
    ),
    CommandRule(
        "docker build",
        Safety.ASK,
        "Build image",
        "docker-write",
        strict_feedback="Queue docker build for session end.",
    ),
    CommandRule(
        "docker push",
        Safety.ASK,
        "Push image",
        "docker-write",
        strict_feedback="Queue image push for session end.",
    ),
    CommandRule(
        "docker pull",
        Safety.ASK,
        "Pull image",
        "docker-write",
        strict_feedback="Queue image pull for session end.",
    ),
    CommandRule(
        "docker compose up",
        Safety.ASK,
        "Start compose",
        "docker-write",
        strict_feedback="Queue compose up for session end.",
    ),
    CommandRule(
        "docker compose down",
        Safety.ASK,
        "Stop compose",
        "docker-write",
        strict_feedback="Queue compose down for session end.",
    ),
    CommandRule(
        "docker system prune",
        Safety.ASK,
        "Prune docker",
        "docker-write",
        strict_feedback="Docker prune is destructive. Flag for human review.",
    ),
    # --- Cloud Write (ASK) ---
    CommandRule(
        "gcloud secrets versions access",
        Safety.ASK,
        "Access secret",
        "cloud-write",
        strict_feedback="Secret access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud secrets create",
        Safety.ASK,
        "Create secret",
        "cloud-write",
        strict_feedback="Queue secret creation for session end.",
    ),
    CommandRule(
        "gcloud secrets versions add",
        Safety.ASK,
        "Add secret version",
        "cloud-write",
        strict_feedback="Queue secret version add for session end.",
    ),
    CommandRule(
        "gcloud services enable",
        Safety.ASK,
        "Enable service",
        "cloud-write",
        strict_feedback="Queue service enable for session end.",
    ),
    CommandRule(
        "gcloud iam",
        Safety.ASK,
        "IAM operations",
        "cloud-write",
        strict_feedback="IAM changes require confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud auth print-access-token",
        Safety.ASK,
        "Print access token",
        "cloud-write",
        strict_feedback="Token access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud auth print-identity-token",
        Safety.ASK,
        "Print identity token",
        "cloud-write",
        strict_feedback="Token access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud run deploy",
        Safety.ASK,
        "Deploy Cloud Run",
        "cloud-write",
        strict_feedback="Deployment requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud app deploy",
        Safety.ASK,
        "Deploy App Engine",
        "cloud-write",
        strict_feedback="Deployment requires confirmation. Queue for session end.",
    ),
    # --- Terraform Write (ASK) ---
    CommandRule(
        "terraform apply",
        Safety.ASK,
        "Apply terraform",
        "terraform-write",
        strict_feedback="Terraform apply requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "terraform import",
        Safety.ASK,
        "Import resource",
        "terraform-write",
        strict_feedback="Queue terraform import for session end.",
    ),
    CommandRule(
        "terraform state mv",
        Safety.ASK,
        "Move state",
        "terraform-write",
        strict_feedback="Queue state move for session end.",
    ),
    CommandRule(
        "terraform state rm",
        Safety.ASK,
        "Remove from state",
        "terraform-write",
        strict_feedback="Queue state removal for session end.",
    ),
    CommandRule(
        "terraform taint",
        Safety.ASK,
        "Taint resource",
        "terraform-write",
        strict_feedback="Queue taint for session end.",
    ),
    CommandRule(
        "terraform untaint",
        Safety.ASK,
        "Untaint resource",
        "terraform-write",
        strict_feedback="Queue untaint for session end.",
    ),
    CommandRule(
        "terraform workspace new",
        Safety.ASK,
        "New workspace",
        "terraform-write",
        strict_feedback="Queue workspace creation for session end.",
    ),
    CommandRule(
        "terraform workspace select",
        Safety.ASK,
        "Select workspace",
        "terraform-write",
        strict_feedback="Queue workspace switch for session end.",
    ),
    CommandRule(
        "terraform workspace delete",
        Safety.ASK,
        "Delete workspace",
        "terraform-write",
        strict_feedback="Queue workspace deletion for session end.",
    ),
    # --- Terraform DENY ---
    CommandRule("terraform destroy", Safety.DENY, "Destroys infrastructure", "terraform-deny"),
    # --- Catastrophic-deletion DENY ---
    # Each prefix is matched as an exact-or-followed-by-space token (see
    # bash_command_validator._match_always_deny). Variants below cover the
    # common typos / re-orderings that all map to the same outcome.
    CommandRule(
        "rm -rf /",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -rf /*",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -rf ~",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -rf $HOME",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -fr /",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -fr ~",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    CommandRule(
        "rm -rf --no-preserve-root /",
        Safety.DENY,
        "Recursive root/home deletion is never allowed.",
        "rm-deny",
    ),
    # --- Interpreter RCE DENY ---
    # `python -c`, `python3 -c`, `node -e`, `node --eval` are canonical RCE
    # primitives — denied under enforce and lockdown. Note:
    # `_is_safe_interpreter` further restricts ANY flagged form in lockdown;
    # these entries exist so enforce denies them too.
    CommandRule(
        "python -c",
        Safety.DENY,
        "python -c re-execs arbitrary code; not allowed.",
        "interpreter-deny",
    ),
    CommandRule(
        "python3 -c",
        Safety.DENY,
        "python3 -c re-execs arbitrary code; not allowed.",
        "interpreter-deny",
    ),
    CommandRule(
        "node -e",
        Safety.DENY,
        "node -e re-execs arbitrary code; not allowed.",
        "interpreter-deny",
    ),
    CommandRule(
        "node --eval",
        Safety.DENY,
        "node --eval re-execs arbitrary code; not allowed.",
        "interpreter-deny",
    ),
    # --- env -i DENY ---
    # `env -i` clears the environment and is commonly used to wrap RCE
    # (e.g. `env -i bash -c '...'`). Always deny — bare `env` and
    # `env K=V cmd` forms are still routed through _is_safe_env.
    CommandRule(
        "env -i",
        Safety.DENY,
        "env -i clears the environment and is commonly used to wrap RCE; not allowed.",
        "env-deny",
    ),
    # --- Python Package Install (ASK) ---
    CommandRule(
        "pip install",
        Safety.ASK,
        "Install package",
        "package-mgmt",
        strict_feedback="Package install requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "pip uninstall",
        Safety.ASK,
        "Uninstall package",
        "package-mgmt",
        strict_feedback="Package uninstall requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "uv pip install",
        Safety.ASK,
        "UV install package",
        "package-mgmt",
        strict_feedback="Package install requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "make install",
        Safety.ASK,
        "Make install",
        "package-mgmt",
        strict_feedback="Package install requires confirmation. Queue for session end.",
    ),
    # --- Orchestration Destruction (DENY) ---
    # Each shape below has no legitimate dev-time variant. The literal-prefix
    # matcher catches subcommand args (`gh repo delete owner/repo --yes`,
    # `kubectl delete --all -n production`, etc.) — extra flags after the
    # prefix do not change the verdict.
    CommandRule(
        "kubectl delete --all",
        Safety.DENY,
        "Cluster-wide resource deletion is never a single-step dev op.",
        "k8s-deny",
    ),
    CommandRule(
        "kubectl delete pods --all",
        Safety.DENY,
        "Cluster-wide pod deletion is never a single-step dev op.",
        "k8s-deny",
    ),
    CommandRule(
        "kubectl delete namespace",
        Safety.DENY,
        "Namespace deletion cascades to every resource in it.",
        "k8s-deny",
    ),
    CommandRule(
        "aws s3 rb",
        Safety.DENY,
        "Bucket removal — irreversible, often paired with --force to wipe contents.",
        "aws-deny",
    ),
    CommandRule(
        "gh repo delete",
        Safety.DENY,
        "Repo deletion is irreversible and never a single-step dev op.",
        "gh-deny",
    ),
    CommandRule(
        "gh release delete",
        Safety.DENY,
        "Release deletion removes published artifacts; never a single-step dev op.",
        "gh-deny",
    ),
    CommandRule(
        "gpg --delete-secret-key",
        Safety.DENY,
        "Secret-key deletion is irreversible and unrecoverable.",
        "gpg-deny",
    ),
    CommandRule(
        "gpg --delete-secret-and-public-keys",
        Safety.DENY,
        "Secret-key deletion is irreversible and unrecoverable.",
        "gpg-deny",
    ),
    CommandRule(
        "chmod -R 777 /",
        Safety.DENY,
        "World-writable recursion against / is catastrophic.",
        "chmod-deny",
    ),
    CommandRule(
        "chmod -R 777 /*",
        Safety.DENY,
        "World-writable recursion against /* is catastrophic.",
        "chmod-deny",
    ),
    # --- Orchestration Destruction (ASK) ---
    # Documented for permission generation; have legitimate variants but
    # warrant explicit user confirmation. (Runtime ASK behavior in interactive
    # mode falls through to passthrough; these entries primarily document
    # intent for the marketplace permission manifest.)
    CommandRule(
        "docker container prune",
        Safety.ASK,
        "Prunes stopped containers",
        "docker-mgmt",
        strict_feedback="Docker prune is destructive. Flag for human review.",
    ),
    CommandRule(
        "docker volume prune",
        Safety.ASK,
        "Prunes unused volumes (data loss risk)",
        "docker-mgmt",
        strict_feedback="Docker volume prune deletes data. Flag for human review.",
    ),
    CommandRule(
        "aws s3 rm",
        Safety.ASK,
        "S3 object removal",
        "aws-mgmt",
        strict_feedback="S3 deletion requires confirmation. Queue for session end.",
    ),
]


# === Guard's own read-only CLI subcommands (auto-registered, drift-tested) ===
# These guard subcommands are dry-run / read-only by construction: they print or
# inspect state, and ``guard test <cmd>`` analyzes a command string WITHOUT
# executing it. Registering them keeps lockdown's default-deny from blocking
# guard's own diagnostic tooling -- the friction that made
# ``uv run guard test`` itself undeniable in an unattended session. WRITE
# subcommands (``mode``, ``migrate-log``, and the ``allowlist`` mutators) are
# excluded: they change guard's config and must not be blanket-allowed. The
# allowlist's read-only sub-subcommands (``list`` / ``rules``) are registered
# explicitly. Drift-proof: a CLI-introspection test asserts every subcommand is
# classified in exactly one of the read-only / write sets, so a new subcommand
# cannot silently ship unclassified.
GUARD_READ_ONLY_SUBCOMMANDS: frozenset[str] = frozenset(
    {"status", "healthcheck", "noisy", "silent", "trace", "test", "diff", "corpus"}
)
GUARD_WRITE_SUBCOMMANDS: frozenset[str] = frozenset({"allowlist", "migrate-log", "mode"})
_GUARD_READ_ONLY_SUBPREFIXES: frozenset[str] = GUARD_READ_ONLY_SUBCOMMANDS | {
    "allowlist list",
    "allowlist rules",
}
# Invocation forms: bare (on PATH) and via uv/uvx, since guard is typically run
# as ``uv run guard`` from a project venv.
_GUARD_INVOCATIONS: tuple[str, ...] = ("guard", "uv run guard", "uvx guard")
_GUARD_SAFE_PREFIXES: frozenset[str] = frozenset(
    f"{inv} {sub}" for inv in _GUARD_INVOCATIONS for sub in _GUARD_READ_ONLY_SUBPREFIXES
)


# === convo: first-party read-only conversation-history CLI ===
# convo (TracineHQ/convo) is guard's sibling diagnostic -- it queries an index of
# Claude Code transcripts. Its query subcommands print analytics and mutate no
# repo or system state, so registering them keeps lockdown from default-denying
# the agent's (and the control plane's) own introspection tooling -- the same
# friction guard's own ``test`` / ``corpus`` subcommands hit before they were
# registered. Unlike GUARD_READ_ONLY_SUBCOMMANDS, this list is NOT drift-tested
# against a live parser (guard cannot import convo's CLI), so it is deliberately
# fail-safe: write-side subcommands (``backup`` / ``restore`` / ``index`` /
# ``index-guard``, which rebuild or restore convo's local DB cache) and any
# future convo subcommand are simply
# absent, which means lockdown still denies them (enforce passes them through) --
# drift can only under-permit, never silently auto-allow something new. The
# behavior is pinned by tests/corpus/convo.jsonl.
CONVO_READ_ONLY_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "summary",
        "search",
        "stats",
        "diff",
        "inspect",
        "info",
        "snapshots",
        "projects",
        "tools",
        "sessions",
    }
)
_CONVO_INVOCATIONS: tuple[str, ...] = ("convo", "uv run convo", "uvx convo")
_CONVO_SAFE_PREFIXES: frozenset[str] = frozenset(
    f"{inv} {sub}" for inv in _CONVO_INVOCATIONS for sub in CONVO_READ_ONLY_SUBCOMMANDS
)


# === Derived Data Structures ===

SAFE_PREFIXES: frozenset[str] = (
    frozenset(
        cmd.prefix for cmd in COMMANDS if cmd.safety == Safety.ALLOW and not cmd.requires_classifier
    )
    | _GUARD_SAFE_PREFIXES
    | _CONVO_SAFE_PREFIXES
)

SAFE_PIPE_COMMANDS: frozenset[str] = frozenset(cmd.prefix for cmd in COMMANDS if cmd.pipe_safe)

STRICT_FEEDBACK: dict[str, str] = {
    cmd.prefix: cmd.strict_feedback
    for cmd in COMMANDS
    if cmd.safety == Safety.ASK and cmd.strict_feedback
}

ALWAYS_DENY: frozenset[str] = frozenset(cmd.prefix for cmd in COMMANDS if cmd.safety == Safety.DENY)


# === Synthetic-deny catalogues (used by bash_command_validator matchers) ===
# These parallel ALWAYS_DENY but are too combinatorial to express as literal
# prefix entries. The bash command validator imports each set and either
# compiles a regex or does a frozenset lookup.

# Interpreter binary basenames whose ``-c`` / ``-e`` / ``--eval`` / ``eval``
# invocations re-execute arbitrary code. The validator compiles a regex from
# this set that matches optional version suffix (``python3.11``) and fully
# qualified paths (``/usr/bin/python3``).
DANGEROUS_INTERPRETERS: frozenset[str] = frozenset(
    {
        "python",
        "python3",
        "node",
        "nodejs",
        "pypy",
        "pypy3",
        "bun",
        "deno",
        # macOS shell-exec primitive: ``osascript -e 'do shell script "..."'``
        # is equivalent to ``sh -c``. ``-l JavaScript`` switches language
        # but ``-e`` still triggers the eval-flag matcher.
        "osascript",
    }
)

# Flags / subcommands that re-execute arbitrary code under any
# DANGEROUS_INTERPRETERS binary.
INTERPRETER_EVAL_FLAGS: frozenset[str] = frozenset({"-c", "-e", "--eval", "eval"})

# Wrapper runners that exec a tool from a downloaded or project environment.
# The validator unwraps these and re-runs the dangerous-interpreter check on
# the inner command (``uvx <tool>``, ``pipx run <tool>``, ``uv run <tool>``).
INTERPRETER_RUNNER_WRAPPERS: frozenset[str] = frozenset({"uvx", "pipx", "uv"})

# Catastrophic operands for recursive ``rm``. Any of these as an operand to
# a recursive ``rm`` form is denied regardless of flag ordering. Top-level
# system subtrees (``/etc``, ``/usr``, ``/home``, ``/Users``, ``/var``, ...)
# are explicitly enumerated here so ``rm -rf /home/*`` and ``rm -rf /Users/*``
# trip the matcher even though they aren't bare ``/`` / ``/*``.
DANGEROUS_RM_OPERANDS: frozenset[str] = frozenset(
    {
        "/",
        "/*",
        "~",
        "~/*",
        "~/.ssh",
        "~/.aws",
        "~/.config",
        "~/.gnupg",
        "$HOME",
        "$HOME/*",
        "$HOME/.ssh",
        "$HOME/.aws",
        "$HOME/.config",
        "$HOME/.gnupg",
        "/.",
        "/..",
        ".",
        "./",
        "*",
        "/etc",
        "/etc/",
        "/etc/*",
        "/usr",
        "/usr/",
        "/usr/*",
        "/var",
        "/var/",
        "/var/*",
        "/bin",
        "/bin/",
        "/bin/*",
        "/sbin",
        "/sbin/",
        "/sbin/*",
        "/lib",
        "/lib/",
        "/lib/*",
        "/lib64",
        "/lib64/",
        "/lib64/*",
        "/boot",
        "/boot/",
        "/boot/*",
        "/home",
        "/home/",
        "/home/*",
        "/Users",
        "/Users/",
        "/Users/*",
        "/opt",
        "/opt/",
        "/opt/*",
        "/root",
        "/root/",
        "/root/*",
        "/System",
        "/System/",
        "/System/*",
        "/Library",
        "/Library/",
        "/Library/*",
    }
)

# Shell-wrapper basenames. ``<shell> -c "..."`` is the canonical RCE wrapper.
DANGEROUS_SHELL_WRAPPERS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
)

# Plain runner prefixes (no ``-c``) that prepend execution of an arbitrary
# command. The validator strips these and re-evaluates the remainder.
PLAIN_RUNNER_PREFIXES: frozenset[str] = frozenset(
    {
        "command",
        "exec",
        "time",
        "nohup",
        "setsid",
        "unbuffer",
        "busybox",
        "toybox",
    }
)

# Shell builtins that execute their argument as code. ``eval`` runs its arg as
# a shell command; ``source`` and ``.`` read and execute a script file.
# All three trivially defeat any per-segment validator if used as the head
# token, so we deny them outright in agent contexts.
EVAL_BUILTINS: frozenset[str] = frozenset({"eval", "source", "."})

# Environment variables whose values are passed through to internal exec sinks
# (git transports, dynamic loaders, language interpreters). Setting any of
# these as a ``K=V`` prefix on a command lets an attacker hijack the resulting
# subprocess. ``PATH`` is intentionally absent — too noisy in normal use.
DANGEROUS_ENV_SINKS: frozenset[str] = frozenset(
    {
        # git: shell-escaped exec sinks
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_INDEX_FILE",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        # dynamic-linker hijack vectors (linux + darwin)
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FORCE_FLAT_NAMESPACE",
        # language-interpreter import-path hijacks
        "PYTHONPATH",
        "NODE_PATH",
        "PERL5LIB",
        "RUBYLIB",
        "BASH_ENV",
        "ENV",
    }
)

# Git config keys whose values can contain ``!cmd`` shell escapes (alias.*),
# external programs run by git internals (core.pager / core.editor / ...),
# or filter commands. Setting these via ``git -c key=value`` or
# ``git config key value`` is a command-execution sink.
GIT_CONFIG_EXEC_SINKS: frozenset[str] = frozenset(
    {
        "core.pager",
        "core.editor",
        "core.askpass",
        "core.sshcommand",
        "core.fsmonitor",
        "core.hookspath",
        # ``core.attributesFile=/tmp/evil`` points the next subcommand at an
        # attacker-controlled .gitattributes that can register filter.* exec
        # sinks for the very same command.
        "core.attributesfile",
        "help.format",
        "sequence.editor",
        "gpg.program",
        "gpg.openpgp.program",
        "gpg.x509.program",
        "diff.external",
        "merge.tool",
        "http.proxy",
        "ssh.variant",
        # Pager / color.pager — same risk surface as core.pager: git pipes
        # output through these binaries, so an attacker-controlled path is RCE.
        "color.pager",
        # Server-side hook git invokes during ``git fetch`` / ``git push``;
        # an override forces the local git to execute attacker bytes.
        "uploadpack.packobjectshook",
        # ``protocol.allow=always`` re-enables disabled-by-default transports
        # like ext:: which run a shell command per fetch — RCE on ``git fetch``.
        "protocol.allow",
        # Receive-side execution sinks: ``receive.shallowupdatehook`` etc.
        "receive.procreceiverefs",
    }
)

# Git config key glob patterns that are command-execution sinks. These are
# matched as ``<prefix>.<anything>.<suffix>`` (case-insensitive). E.g.
# ``alias.*`` matches ``alias.x``, ``alias.foo-bar``.
GIT_CONFIG_EXEC_SINK_GLOBS: tuple[tuple[str, str], ...] = (
    ("alias.", ""),
    ("mergetool.", ".cmd"),
    ("difftool.", ".cmd"),
    ("filter.", ".clean"),
    ("filter.", ".smudge"),
    # ``includeIf.<gitdir-condition>.path=/path/to/.gitconfig`` tells git to
    # load an attacker-controlled config file conditionally. The middle
    # segment is opaque (``gitdir:/path``, ``onbranch:foo``); we only check
    # the prefix/suffix bookends.
    ("includeif.", ".path"),
    # Per-command pager overrides: ``pager.log=/tmp/evil`` etc. git looks up
    # ``pager.<cmd>`` for each subcommand; any value is an exec sink.
    ("pager.", ""),
    # Per-protocol allowlists: ``protocol.ext.allow=always`` re-enables ext::
    # transport (RCE on fetch). Match ``protocol.<scheme>.allow``.
    ("protocol.", ".allow"),
)


# --- Read-only git subcommands coerced into write/exec/ref-mutation ----------
#
# The read-only git allowlist (status/log/diff/show/branch/tag/grep/remote ...)
# matches on the bare subcommand. But several of those subcommands write a file,
# exec an external program, or create/mutate a ref when given certain flags or a
# positional. Two severity tiers, two predicates -- each the SINGLE source of
# truth shared by the bash matcher and git_c_validator so they cannot drift:
#   git_read_exec_violation -- RCE-class file-write/exec flags. Hard-deny.
#   git_ref_violation       -- low-severity local ref create/mutate. Strict-gated.

# diff-like subcommands: ``--output[=path]`` writes a file; ``--ext-diff`` runs
# the configured external diff (GIT_EXTERNAL_DIFF / diff.external) = exec.
_GIT_DIFFLIKE_SUBCOMMANDS: frozenset[str] = frozenset({"log", "show", "diff", "whatchanged"})

# branch/tag are read-only when listing but mutate a ref with a positional name
# or any of these flags. ``-l``/``--list`` (and the other list/query flags) keep
# them in read mode -- with one of those present a positional is a pattern.
_GIT_BRANCH_MUTATING_FLAGS: frozenset[str] = frozenset(
    {
        "-d",
        "-D",
        "-m",
        "-M",
        "-c",
        "-C",
        "--delete",
        "--move",
        "--copy",
        "--force",
        "-f",
        "--edit-description",
        "--set-upstream-to",
        "-u",
        "--unset-upstream",
        "--track",
    }
)
_GIT_TAG_MUTATING_FLAGS: frozenset[str] = frozenset(
    {
        "-d",
        "--delete",
        "-a",
        "--annotate",
        "-s",
        "--sign",
        "-u",
        "--local-user",
        "-m",
        "--message",
        "-F",
        "--file",
        "-f",
        "--force",
        "--create-reflog",
        "-e",
        "--edit",
    }
)
_GIT_REF_LIST_FLAGS: frozenset[str] = frozenset(
    {
        "-l",
        "--list",
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-v",
        "-vv",
        "--verbose",
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--points-at",
        "--sort",
        "--format",
        "--color",
        "--no-color",
        "--column",
        "--no-column",
        "--show-current",
        "-i",
        "--ignore-case",
        "-n",
        "--omit-empty",
    }
)
# ``git remote <action>`` actions that write config (vs. bare/``-v``/``show``/
# ``get-url`` which are read-only).
_GIT_REMOTE_WRITE_ACTIONS: frozenset[str] = frozenset(
    {"add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune", "update"}
)


def _git_difflike_exec_violation(args: list[str]) -> str | None:
    """diff-like helper: ``--output[=path]`` writes a file, ``--ext-diff`` execs."""
    for tok in args:
        if tok in {"--output", "--ext-diff"} or tok.startswith("--output="):
            return tok
    return None


def _git_grep_exec_violation(args: list[str]) -> str | None:
    """Grep helper: ``--open-files-in-pager``/``-O<cmd>``/``--output`` exec a pager."""
    for tok in args:
        if tok in {"--open-files-in-pager", "--output", "-O"}:
            return tok
        if tok.startswith(("--open-files-in-pager=", "--output=")):
            return tok
        if tok.startswith("-O") and tok != "-O":
            return tok
    return None


def git_read_exec_violation(subcommand: str, args: list[str]) -> str | None:
    """Offending token if a read-only git subcommand is coerced into a write/exec.

    RCE-class (``git log --output=<path>`` writes anywhere, ``--ext-diff`` /
    ``git grep --open-files-in-pager`` run an external program). ``args`` are the
    tokens AFTER the subcommand. Shared by the bash matcher (hard-deny, both
    modes) and git_c_validator so the two cannot drift. Distinct from
    :func:`git_ref_violation` -- ref creation is a low-severity local write, not
    an exec, and is gated separately.
    """
    if subcommand in _GIT_DIFFLIKE_SUBCOMMANDS:
        return _git_difflike_exec_violation(args)
    if subcommand == "grep":
        return _git_grep_exec_violation(args)
    # ``git stash show`` forwards diff options to ``git diff`` -- the same
    # ``--output=<path>`` (file write) and ``--ext-diff`` (external program)
    # vectors. ``git stash show`` is on the read-only allowlist, so its diff
    # flags must be vetoed too, scanning the tokens after the ``show`` word.
    if subcommand == "stash" and args[:1] == ["show"]:
        return _git_difflike_exec_violation(args[1:])
    return None


def _git_ref_mutation(
    args: list[str], mutating_flags: frozenset[str], *, include_creation: bool
) -> str | None:
    """branch/tag helper: offending token if the args mutate/create a ref."""
    for tok in args:
        if tok.split("=", 1)[0] in mutating_flags:
            return tok
    if not include_creation:
        return None
    if any(tok.split("=", 1)[0] in _GIT_REF_LIST_FLAGS for tok in args):
        return None  # a list/query flag is present -> positionals are patterns
    for tok in args:
        if not tok.startswith("-"):
            return tok  # bare positional = ref name to create
    return None


def git_ref_violation(
    subcommand: str, args: list[str], *, include_creation: bool = True
) -> str | None:
    """Offending token if a read-only-listing git subcommand mutates a ref.

    Low-severity local writes (``git tag <name>``, ``git branch -d``,
    ``git remote add``). ``include_creation=True`` (bash strict allow-path veto)
    also flags bare ref *creation*; ``include_creation=False`` (interactive
    ``git -C`` deny) flags only destructive flags/actions and lets bare creation
    fall through to an ASK prompt. Returns ``None`` for any subcommand it does
    not model.
    """
    if subcommand == "branch":
        return _git_ref_mutation(
            args, _GIT_BRANCH_MUTATING_FLAGS, include_creation=include_creation
        )
    if subcommand == "tag":
        return _git_ref_mutation(args, _GIT_TAG_MUTATING_FLAGS, include_creation=include_creation)
    if subcommand == "remote":
        if args and not args[0].startswith("-") and args[0] in _GIT_REMOTE_WRITE_ACTIONS:
            return args[0]
        return None
    return None


def get_rules_by_safety(safety: Safety) -> list[CommandRule]:
    """Get all rules with a given safety classification."""
    return [cmd for cmd in COMMANDS if cmd.safety == safety]


def get_rules_by_category(category: str) -> list[CommandRule]:
    """Get all rules in a given category."""
    return [cmd for cmd in COMMANDS if cmd.category == category]


# === Hard floor vs steering (Claude Code ``auto`` permission mode) ===
#
# In ``auto`` mode Claude Code's own classifier reviews every action with the
# full conversation in view; guard sees one tool call. So in ``auto`` guard
# keeps only its hard floor: FLOOR rules deny exactly as in every other mode,
# STEER rules return no decision (logged as a ``pass``) and leave the call to
# Claude Code's flow. Every other permission mode, and ``guard mode lockdown``,
# denies on both tiers as before.
#
# FLOOR: irreversible or catastrophic, code injection, hook / guard evasion,
# supply chain, credential exfiltration, and boundaries the auto classifier
# cannot see (guard's trust root, the user's protected list, subagent scope,
# the commit-attribution policy). STEER: shape and style rules, plus the shape
# detectors whose real-session denies were almost all harmless commands
# (variable / glob command names, exec env vars, pip / npm / npx installs, git
# config exec keys, cron / launchd writes). The classifier sees the whole
# command and the conversation, so it makes those calls better than a pattern.
#
# Keys are rule ids (``bash.*``), hook ids (``guard.*``), or ``<id>:<shape>``
# for a sub-shape whose tier differs from its rule's. The allowlist key a user
# sees stays the plain rule id. A key missing here is FLOOR (fail closed).


class Tier(Enum):
    FLOOR = "floor"
    STEER = "steer"


@dataclass(frozen=True)
class TierEntry:
    tier: Tier
    why: str


_F = Tier.FLOOR
_S = Tier.STEER

RULE_TIERS: dict[str, TierEntry] = {
    # --- bash_command_validator: FLOOR ---
    "bash.always_deny": TierEntry(_F, "registry literal; ALWAYS_DENY_TIERS decides per prefix"),
    "bash.admin_forbidden_flag": TierEntry(
        _F, "cloud CLI flag redirects endpoint, swaps credentials or drops TLS"
    ),
    "bash.admin_forbidden_subcommand": TierEntry(
        _F, "raw REST / credential-swap subcommand skips the destructive-verb rules"
    ),
    "bash.admin_sensitive_env_override": TierEntry(
        _F, "inline env redirects a cloud CLI's endpoint or credentials"
    ),
    "bash.aws_destructive": TierEntry(_F, "irreversible cloud resource deletion"),
    "bash.aws_s3_destructive": TierEntry(_F, "irreversible bucket / object deletion"),
    "bash.az_destructive": TierEntry(_F, "irreversible cloud resource deletion"),
    "bash.gcloud_destructive": TierEntry(_F, "irreversible cloud resource deletion"),
    "bash.cargo_remote_install": TierEntry(
        _F, "supply chain: installs code from an arbitrary remote source"
    ),
    "bash.gem_remote_install": TierEntry(
        _F, "supply chain: installs code from an arbitrary remote source"
    ),
    "bash.go_remote_install": TierEntry(
        _F, "supply chain: installs code from an arbitrary remote source"
    ),
    "bash.helm_remote_install": TierEntry(
        _F, "supply chain: installs charts from an arbitrary remote source"
    ),
    "bash.registry_config": TierEntry(
        _F, "supply chain: repoints every later install at another registry"
    ),
    "bash.chmod_dangerous": TierEntry(_F, "recursive 777 on a system root"),
    "bash.chmod_setuid": TierEntry(_F, "setuid / setgid bit is a privilege-escalation primitive"),
    "bash.chmod_sensitive_target": TierEntry(_F, "opens a credential store to other users"),
    "bash.fs_attr_sensitive": TierEntry(
        _F, "ownership / immutability change on a credential store"
    ),
    "bash.command_too_long": TierEntry(_F, "past the scan budget no floor rule can be checked"),
    "bash.credential_leak": TierEntry(_F, "prints a credential into the transcript"),
    "bash.secret_value": TierEntry(_F, "literal secret on the command line"),
    "bash.secret_egress": TierEntry(_F, "uploads a credential file"),
    "bash.dns_exfil": TierEntry(_F, "DNS-tunnel exfiltration shape"),
    "bash.dangerous_interpreter": TierEntry(_F, "inline interpreter code"),
    "bash.eval_builtin": TierEntry(_F, "eval runs an arbitrary string as code"),
    "bash.dangerous_construct:executed": TierEntry(
        _F,
        'output run as code (bash -c "$(curl ...)", source <(...), a shell fed by <<<), '
        "or awk / osascript running a command built at run time",
    ),
    "bash.dangerous_construct:sensitive_target": TierEntry(
        _F,
        "> / >> / >| into ~/.ssh, a shell rc file, /etc, a launch agent, git config or a git hook",
    ),
    "bash.shell_wrapper:opaque": TierEntry(
        _F, "-c string that is empty, a {} placeholder or runs a command named by an expansion"
    ),
    "bash.env_split_string": TierEntry(_F, "env -S rebuilds argv guard cannot see"),
    "bash.wrapper_stacking": TierEntry(_F, "nesting past the unwrap limit hides the inner command"),
    "bash.dangerous_rm": TierEntry(_F, "recursive rm of /, ~, $HOME or cwd"),
    "bash.function_definition:fork_bomb": TierEntry(
        _F,
        "a function whose body pipes into or backgrounds a call back to itself exhausts the process table",
    ),
    "bash.conditional_denied_flag:root": TierEntry(
        _F,
        "find -delete / -exec rooted at /, a home dir or a system directory, "
        "or an unfiltered delete of . or ..",
    ),
    "bash.disk_destruction": TierEntry(_F, "disk / partition / filesystem destruction"),
    "bash.db_cli_destructive": TierEntry(_F, "irreversible database destruction"),
    "bash.dropdb_or_mysqladmin": TierEntry(_F, "irreversible database destruction"),
    "bash.mongo_destructive": TierEntry(_F, "irreversible database destruction"),
    "bash.iac_destruction": TierEntry(_F, "tears down a whole IaC stack"),
    "bash.kubectl_destructive": TierEntry(_F, "cluster-wide kubectl deletion"),
    "bash.gh_api_destructive": TierEntry(
        _F, "raw gh api mutation (DELETE / PATCH / PUT / graphql mutation)"
    ),
    "bash.gpg_secret_delete": TierEntry(_F, "destroys private key material"),
    "bash.git_force_push": TierEntry(_F, "rewrites shared remote history"),
    "bash.git_force_refspec": TierEntry(_F, "+refspec force-push rewrites shared remote history"),
    "bash.git_read_exec": TierEntry(
        _F, "read-only git verb coerced into exec or an arbitrary file write"
    ),
    "bash.escalation_shell": TierEntry(_F, "su / doas / pkexec shell outside guard's view"),
    "bash.sudo_escalation": TierEntry(_F, "root shell or env transfer outside guard's view"),
    "bash.host_control": TierEntry(_F, "reboot / shutdown kills the session and the host"),
    "bash.kernel_module_load": TierEntry(_F, "loads code into the kernel"),
    "bash.network_policy_wipe": TierEntry(_F, "firewall wipe can lock the operator out"),
    "bash.process_attach": TierEntry(_F, "reads another process's memory"),
    "bash.process_tree_kill": TierEntry(_F, "kills every process the user owns"),
    "bash.sensitive_write": TierEntry(
        _F, "writes to ~/.ssh, shell rc files, /etc or launch agents"
    ),
    "bash.admin_default_deny": TierEntry(
        _F,
        "cloud CLI verb off the read-only catalog: secret reads, IAM grants, public access, key minting",
    ),
    # --- bash_command_validator: STEER ---
    "bash.var_expanded_head": TierEntry(
        _S, "variable-named command ($R, $1, $@); the auto classifier sees what the variable holds"
    ),
    "bash.glob_head": TierEntry(
        _S, "glob in the command name (/bin/r?); the auto classifier sees the whole command"
    ),
    "bash.dangerous_env_sink": TierEntry(
        _S,
        "exec / loader env (GIT_SSH_COMMAND, LD_PRELOAD, ...); the auto classifier judges the value",
    ),
    "bash.git_config_injection": TierEntry(
        _S,
        "git config exec key (core.hooksPath, alias !cmd, ...); the auto classifier judges the value",
    ),
    "bash.npm_url_install": TierEntry(
        _S, "install from a URL or git source; the auto classifier judges the source"
    ),
    "bash.npx_remote": TierEntry(
        _S, "runs a remote package; the auto classifier judges the package"
    ),
    "bash.pip_install_url": TierEntry(
        _S, "install from a URL or VCS source; the auto classifier judges the source"
    ),
    "bash.persistence": TierEntry(
        _S,
        "schedules code past the session (cron, launchd, systemd); the classifier judges the job",
    ),
    "bash.admin_unknown_flag_strict": TierEntry(_S, "lockdown-only unknown-flag escalation"),
    "bash.conditional_denied_flag": TierEntry(_S, "find -exec / -delete, yq -i on a project path"),
    "bash.dangerous_construct": TierEntry(
        _S,
        "command / process substitution, here-string, file redirect; bodies are still floor-checked",
    ),
    "bash.dangerous_interpreter:literal": TierEntry(
        _S,
        "inline program written out literally (python3 -c '...', python3 - <<'EOF', node -e, "
        "osascript / ruby / perl -e): as visible as a script file, which already passes. "
        "A program from a pipe, a variable or a substitution, or one that evals stdin, stays "
        "FLOOR; an osascript do shell script string is floor-checked like bash -c",
    ),
    "bash.eval_builtin:source": TierEntry(_S, "source / . of a file, e.g. loading a .env"),
    "bash.exec_wrapper": TierEntry(_S, "the peeled inner command is matched by its own rule"),
    "bash.function_definition": TierEntry(_S, "shell function; the body is still floor-checked"),
    "bash.trap_exploit": TierEntry(_S, "trap handler; the handler body is still floor-checked"),
    "bash.shell_wrapper": TierEntry(_S, "bash -c payload is re-split and floor-checked"),
    "bash.remote_shell_wrapper": TierEntry(
        _S, "ssh / container exec / nsenter; the remote payload is still floor-checked"
    ),
    "bash.git_ref_mutation": TierEntry(_S, "local branch / tag / remote-config write"),
    "bash.git_worktree_add": TierEntry(
        _S, "worktree add -b creates a local branch; a system-root target needs root anyway"
    ),
    "bash.git_submodule_add": TierEntry(
        _S, "adds a submodule; nothing runs until it is initialized"
    ),
    "bash.tool_alternative": TierEntry(_S, "prefer-a-dedicated-tool nudge"),
    "bash.use_corpus_harness": TierEntry(_S, "guard-checkout workflow nudge"),
    "bash.strict_default_deny": TierEntry(_S, "lockdown-only default deny"),
    "bash.strict_feedback": TierEntry(_S, "lockdown-only feedback deny"),
    # --- git_c_validator (sub-shapes; the allowlist key is the hook id) ---
    "guard.git_c_validator": TierEntry(_F, "unclassified git -C deny fails closed"),
    "guard.git_c_validator:paths_config": TierEntry(
        _F, "-c core.hooksPath / core.attributesFile loads hooks from elsewhere"
    ),
    "guard.git_c_validator:read_exec": TierEntry(
        _F, "read verb coerced into exec or a file write; fetch --upload-pack"
    ),
    "guard.git_c_validator:config_write": TierEntry(
        _S, "git -C config write; exec-sink keys are matched by bash.git_config_injection"
    ),
    "guard.git_c_validator:commit_reuse": TierEntry(_S, "git commit -C / --reuse-message"),
    "guard.git_c_validator:destructive": TierEntry(
        _S, "reset / clean under -C, which guard does not block without -C"
    ),
    "guard.git_c_validator:stash": TierEntry(_S, "stash pop / drop / clear"),
    "guard.git_c_validator:ref_mutation": TierEntry(_S, "local branch / tag / remote-config write"),
    "guard.git_c_validator:not_read_only": TierEntry(
        _S, "subcommand off the git -C read-only list"
    ),
    # --- whole hooks ---
    "guard.protected_files": TierEntry(
        _F, "guard's trust root, its allowlist and the user's protected list"
    ),
    "guard.credential_check": TierEntry(_F, "credential material in a tool input"),
    "guard.commit_message_validator": TierEntry(
        _F,
        "AI attribution policy the auto classifier cannot know; a pushed trailer needs a history rewrite",
    ),
    "guard.subagent_scope": TierEntry(_F, "declared subagent scope the auto classifier cannot see"),
    "guard.agent_output_guard": TierEntry(
        _F,
        "only subagent transcripts deny (background output passes); a transcript floods context",
    ),
}

# Per-prefix tiers for the ALWAYS_DENY registry literals (rule
# ``bash.always_deny``). The CommandRule ``reason`` is the rationale.
_ALWAYS_DENY_STEER: frozenset[str] = frozenset(
    {
        "git add -A",
        "git add --all",
        "git add .",
        "git add -a",
        "git branch -D",
        "git remote add",
        "git remote set-url",
        "git remote rename",
        "git remote remove",
        "git remote rm",
        "git remote prune",
        "git remote update",
        "git remote set-head",
        "git remote set-branches",
        "env -i",
    }
)

ALWAYS_DENY_TIERS: dict[str, TierEntry] = {
    cmd.prefix: TierEntry(_S if cmd.prefix in _ALWAYS_DENY_STEER else _F, cmd.reason)
    for cmd in COMMANDS
    if cmd.safety == Safety.DENY
}

AUTO_PERMISSION_MODE = "auto"
_ALWAYS_DENY_KEY_PREFIX = "bash.always_deny:"


def always_deny_key(prefix: str) -> str:
    """Tier key for one ALWAYS_DENY registry literal."""
    return f"{_ALWAYS_DENY_KEY_PREFIX}{prefix}"


def rule_tier(key: str) -> Tier:
    """Return the tier for a rule key; anything unclassified is FLOOR."""
    if key.startswith(_ALWAYS_DENY_KEY_PREFIX):
        entry = ALWAYS_DENY_TIERS.get(key[len(_ALWAYS_DENY_KEY_PREFIX) :])
    else:
        entry = RULE_TIERS.get(key)
    return entry.tier if entry is not None else Tier.FLOOR


def defers_steer(permission_mode: str | None, *, lockdown: bool) -> bool:
    """True when STEER rules hand the call to Claude Code (``auto``, not lockdown)."""
    return permission_mode == AUTO_PERMISSION_MODE and not lockdown


def is_deferred_to_auto(key: str, permission_mode: str | None, *, lockdown: bool) -> bool:
    """True when a deny under ``key`` becomes an auto-mode pass."""
    return defers_steer(permission_mode, lockdown=lockdown) and rule_tier(key) is Tier.STEER


def auto_pass_reason(key: str) -> str:
    """Decision-log reason for a STEER deny deferred to auto mode."""
    return f"deferred to auto mode (steer rule {key})"
