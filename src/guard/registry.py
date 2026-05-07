# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Single source of truth for command safety classifications.

Imported by ``bash_command_validator`` for ``SAFE_PREFIXES``,
``AUTONOMOUS_FEEDBACK`` and the synthetic-deny lookup tables.
"""
# The COMMANDS table is the contract for this module. Lints that would force
# restructuring it are silenced:
#   D101: Safety/CommandRule are self-describing; docstrings would just restate names.
#   E501: a few autonomous_feedback strings are slightly over 100 chars; rewriting
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
    autonomous_feedback: str = ""
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
        autonomous_feedback="Queue git add for session end. Continue implementing.",
    ),
    CommandRule(
        "git commit",
        Safety.ASK,
        "Creates commit",
        "git-write",
        autonomous_feedback="Queue git commit for session end. Continue implementing.",
    ),
    CommandRule(
        "git push",
        Safety.ASK,
        "Pushes to remote",
        "git-write",
        autonomous_feedback="Queue git push for session end. Complete all work first.",
    ),
    CommandRule(
        "git pull",
        Safety.ASK,
        "Pulls from remote",
        "git-write",
        autonomous_feedback="Git pull requires confirmation. Note it for session end.",
    ),
    CommandRule(
        "git fetch",
        Safety.ASK,
        "Fetches from remote",
        "git-write",
        autonomous_feedback="Queue git fetch for session end.",
    ),
    CommandRule(
        "git checkout",
        Safety.ASK,
        "Switches branches",
        "git-write",
        autonomous_feedback="Use 'git branch' to check branches. Queue checkout for session end.",
    ),
    CommandRule(
        "git switch",
        Safety.ASK,
        "Switches branches",
        "git-write",
        autonomous_feedback="Queue branch switch for session end.",
    ),
    CommandRule(
        "git merge",
        Safety.ASK,
        "Merges branches",
        "git-write",
        autonomous_feedback="Queue merge for session end.",
    ),
    CommandRule(
        "git rebase",
        Safety.ASK,
        "Rebases commits",
        "git-write",
        autonomous_feedback="Queue rebase for session end.",
    ),
    CommandRule(
        "git reset",
        Safety.ASK,
        "Resets state",
        "git-write",
        autonomous_feedback="Git reset is destructive. Flag for human review.",
    ),
    CommandRule(
        "git revert",
        Safety.ASK,
        "Reverts commits",
        "git-write",
        autonomous_feedback="Queue revert for session end.",
    ),
    CommandRule(
        "git stash",
        Safety.ASK,
        "Stashes changes",
        "git-write",
        autonomous_feedback="Use Write tool to save state to a file instead.",
    ),
    CommandRule(
        "git stash pop",
        Safety.ASK,
        "Pops stash",
        "git-write",
        autonomous_feedback="Queue stash pop for session end.",
    ),
    CommandRule(
        "git stash drop",
        Safety.ASK,
        "Drops stash",
        "git-write",
        autonomous_feedback="Queue stash drop for session end.",
    ),
    CommandRule(
        "git clean",
        Safety.ASK,
        "Removes untracked files",
        "git-write",
        autonomous_feedback="Git clean is destructive. Flag for human review.",
    ),
    CommandRule(
        "git restore",
        Safety.ASK,
        "Discards changes",
        "git-write",
        autonomous_feedback="Git restore discards work. Flag for human review.",
    ),
    CommandRule(
        "git cherry-pick",
        Safety.ASK,
        "Cherry-picks commits",
        "git-write",
        autonomous_feedback="Queue cherry-pick for session end.",
    ),
    CommandRule(
        "git branch -d",
        Safety.ASK,
        "Deletes branch (safe)",
        "git-branch",
        autonomous_feedback="Queue branch deletion for session end.",
    ),
    CommandRule(
        "git branch -m",
        Safety.ASK,
        "Renames branch",
        "git-branch",
        autonomous_feedback="Queue branch rename for session end.",
    ),
    CommandRule(
        "git tag -a",
        Safety.ASK,
        "Creates annotated tag",
        "git-branch",
        autonomous_feedback="Queue tag creation for session end.",
    ),
    CommandRule(
        "git tag -d",
        Safety.ASK,
        "Deletes tag",
        "git-branch",
        autonomous_feedback="Queue tag deletion for session end.",
    ),
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
    # ``--force`` and ``-f`` are already blocked. These are the click-fatigue
    # variants that get past the ASK that bare ``git push`` triggers:
    # ``--force-with-lease`` is "safer" force-push but still rewrites remote
    # history; ``--mirror`` overwrites every remote ref; ``+HEAD:main`` is the
    # refspec form of force-push.
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
        autonomous_feedback="File deletion requires confirmation. Flag files for deletion at session end.",
    ),
    CommandRule(
        "rm -rf",
        Safety.ASK,
        "Force delete files",
        "file-write",
        autonomous_feedback="Recursive deletion requires confirmation. Flag for session end.",
    ),
    CommandRule(
        "rmdir",
        Safety.ASK,
        "Delete directory",
        "file-write",
        autonomous_feedback="Directory deletion requires confirmation. Flag for session end.",
    ),
    CommandRule(
        "mv",
        Safety.ASK,
        "Move/rename files",
        "file-write",
        autonomous_feedback="Use Write tool to create new file, flag old for deletion at session end.",
    ),
    # --- GitHub CLI Write (ASK) ---
    CommandRule(
        "gh pr create",
        Safety.ASK,
        "Create PR",
        "gh-write",
        autonomous_feedback="Queue PR creation for session end.",
    ),
    CommandRule(
        "gh pr merge",
        Safety.ASK,
        "Merge PR",
        "gh-write",
        autonomous_feedback="Queue PR merge for session end.",
    ),
    CommandRule(
        "gh pr close",
        Safety.ASK,
        "Close PR",
        "gh-write",
        autonomous_feedback="Queue PR close for session end.",
    ),
    CommandRule(
        "gh pr comment",
        Safety.ASK,
        "Comment on PR",
        "gh-write",
        autonomous_feedback="Queue PR comment for session end.",
    ),
    CommandRule(
        "gh pr review",
        Safety.ASK,
        "Review PR",
        "gh-write",
        autonomous_feedback="Queue PR review for session end.",
    ),
    CommandRule(
        "gh pr edit",
        Safety.ASK,
        "Edit PR",
        "gh-write",
        autonomous_feedback="Queue PR edit for session end.",
    ),
    CommandRule(
        "gh pr reopen",
        Safety.ASK,
        "Reopen PR",
        "gh-write",
        autonomous_feedback="Queue PR reopen for session end.",
    ),
    CommandRule(
        "gh issue create",
        Safety.ASK,
        "Create issue",
        "gh-write",
        autonomous_feedback="Queue issue creation for session end.",
    ),
    CommandRule(
        "gh issue close",
        Safety.ASK,
        "Close issue",
        "gh-write",
        autonomous_feedback="Queue issue close for session end.",
    ),
    CommandRule(
        "gh issue comment",
        Safety.ASK,
        "Comment on issue",
        "gh-write",
        autonomous_feedback="Queue issue comment for session end.",
    ),
    CommandRule(
        "gh issue edit",
        Safety.ASK,
        "Edit issue",
        "gh-write",
        autonomous_feedback="Queue issue edit for session end.",
    ),
    CommandRule(
        "gh release create",
        Safety.ASK,
        "Create release",
        "gh-write",
        autonomous_feedback="Queue release creation for session end.",
    ),
    CommandRule(
        "gh run cancel",
        Safety.ASK,
        "Cancel workflow run",
        "gh-write",
        autonomous_feedback="Queue run cancellation for session end.",
    ),
    CommandRule(
        "gh run rerun",
        Safety.ASK,
        "Rerun workflow",
        "gh-write",
        autonomous_feedback="Queue workflow rerun for session end.",
    ),
    CommandRule(
        "gh workflow run",
        Safety.ASK,
        "Trigger workflow",
        "gh-write",
        autonomous_feedback="Queue workflow trigger for session end.",
    ),
    # --- Docker Write (ASK) ---
    CommandRule(
        "docker run",
        Safety.ASK,
        "Run container",
        "docker-write",
        autonomous_feedback="Container execution requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "docker stop",
        Safety.ASK,
        "Stop container",
        "docker-write",
        autonomous_feedback="Queue container stop for session end.",
    ),
    CommandRule(
        "docker rm",
        Safety.ASK,
        "Remove container",
        "docker-write",
        autonomous_feedback="Queue container removal for session end.",
    ),
    CommandRule(
        "docker rmi",
        Safety.ASK,
        "Remove image",
        "docker-write",
        autonomous_feedback="Queue image removal for session end.",
    ),
    CommandRule(
        "docker build",
        Safety.ASK,
        "Build image",
        "docker-write",
        autonomous_feedback="Queue docker build for session end.",
    ),
    CommandRule(
        "docker push",
        Safety.ASK,
        "Push image",
        "docker-write",
        autonomous_feedback="Queue image push for session end.",
    ),
    CommandRule(
        "docker pull",
        Safety.ASK,
        "Pull image",
        "docker-write",
        autonomous_feedback="Queue image pull for session end.",
    ),
    CommandRule(
        "docker compose up",
        Safety.ASK,
        "Start compose",
        "docker-write",
        autonomous_feedback="Queue compose up for session end.",
    ),
    CommandRule(
        "docker compose down",
        Safety.ASK,
        "Stop compose",
        "docker-write",
        autonomous_feedback="Queue compose down for session end.",
    ),
    CommandRule(
        "docker system prune",
        Safety.ASK,
        "Prune docker",
        "docker-write",
        autonomous_feedback="Docker prune is destructive. Flag for human review.",
    ),
    # --- Cloud Write (ASK) ---
    CommandRule(
        "gcloud secrets versions access",
        Safety.ASK,
        "Access secret",
        "cloud-write",
        autonomous_feedback="Secret access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud secrets create",
        Safety.ASK,
        "Create secret",
        "cloud-write",
        autonomous_feedback="Queue secret creation for session end.",
    ),
    CommandRule(
        "gcloud secrets versions add",
        Safety.ASK,
        "Add secret version",
        "cloud-write",
        autonomous_feedback="Queue secret version add for session end.",
    ),
    CommandRule(
        "gcloud services enable",
        Safety.ASK,
        "Enable service",
        "cloud-write",
        autonomous_feedback="Queue service enable for session end.",
    ),
    CommandRule(
        "gcloud iam",
        Safety.ASK,
        "IAM operations",
        "cloud-write",
        autonomous_feedback="IAM changes require confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud auth print-access-token",
        Safety.ASK,
        "Print access token",
        "cloud-write",
        autonomous_feedback="Token access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud auth print-identity-token",
        Safety.ASK,
        "Print identity token",
        "cloud-write",
        autonomous_feedback="Token access requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud run deploy",
        Safety.ASK,
        "Deploy Cloud Run",
        "cloud-write",
        autonomous_feedback="Deployment requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "gcloud app deploy",
        Safety.ASK,
        "Deploy App Engine",
        "cloud-write",
        autonomous_feedback="Deployment requires confirmation. Queue for session end.",
    ),
    # --- Terraform Write (ASK) ---
    CommandRule(
        "terraform apply",
        Safety.ASK,
        "Apply terraform",
        "terraform-write",
        autonomous_feedback="Terraform apply requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "terraform import",
        Safety.ASK,
        "Import resource",
        "terraform-write",
        autonomous_feedback="Queue terraform import for session end.",
    ),
    CommandRule(
        "terraform state mv",
        Safety.ASK,
        "Move state",
        "terraform-write",
        autonomous_feedback="Queue state move for session end.",
    ),
    CommandRule(
        "terraform state rm",
        Safety.ASK,
        "Remove from state",
        "terraform-write",
        autonomous_feedback="Queue state removal for session end.",
    ),
    CommandRule(
        "terraform taint",
        Safety.ASK,
        "Taint resource",
        "terraform-write",
        autonomous_feedback="Queue taint for session end.",
    ),
    CommandRule(
        "terraform untaint",
        Safety.ASK,
        "Untaint resource",
        "terraform-write",
        autonomous_feedback="Queue untaint for session end.",
    ),
    CommandRule(
        "terraform workspace new",
        Safety.ASK,
        "New workspace",
        "terraform-write",
        autonomous_feedback="Queue workspace creation for session end.",
    ),
    CommandRule(
        "terraform workspace select",
        Safety.ASK,
        "Select workspace",
        "terraform-write",
        autonomous_feedback="Queue workspace switch for session end.",
    ),
    CommandRule(
        "terraform workspace delete",
        Safety.ASK,
        "Delete workspace",
        "terraform-write",
        autonomous_feedback="Queue workspace deletion for session end.",
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
    # primitives — denied unconditionally in both interactive and autonomous
    # modes. Note: `_is_safe_interpreter` further restricts ANY flagged form
    # in autonomous mode; these entries exist so even interactive mode denies.
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
        autonomous_feedback="Package install requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "pip uninstall",
        Safety.ASK,
        "Uninstall package",
        "package-mgmt",
        autonomous_feedback="Package uninstall requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "uv pip install",
        Safety.ASK,
        "UV install package",
        "package-mgmt",
        autonomous_feedback="Package install requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "make install",
        Safety.ASK,
        "Make install",
        "package-mgmt",
        autonomous_feedback="Package install requires confirmation. Queue for session end.",
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
        autonomous_feedback="Docker prune is destructive. Flag for human review.",
    ),
    CommandRule(
        "docker volume prune",
        Safety.ASK,
        "Prunes unused volumes (data loss risk)",
        "docker-mgmt",
        autonomous_feedback="Docker volume prune deletes data. Flag for human review.",
    ),
    CommandRule(
        "aws s3 rm",
        Safety.ASK,
        "S3 object removal",
        "aws-mgmt",
        autonomous_feedback="S3 deletion requires confirmation. Queue for session end.",
    ),
]


# === Derived Data Structures ===

SAFE_PREFIXES: frozenset[str] = frozenset(
    cmd.prefix for cmd in COMMANDS if cmd.safety == Safety.ALLOW and not cmd.requires_classifier
)

SAFE_PIPE_COMMANDS: frozenset[str] = frozenset(cmd.prefix for cmd in COMMANDS if cmd.pipe_safe)

AUTONOMOUS_FEEDBACK: dict[str, str] = {
    cmd.prefix: cmd.autonomous_feedback
    for cmd in COMMANDS
    if cmd.safety == Safety.ASK and cmd.autonomous_feedback
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
    {"python", "python3", "node", "nodejs", "pypy", "pypy3", "bun", "deno"}
)

# Flags / subcommands that re-execute arbitrary code under any
# DANGEROUS_INTERPRETERS binary.
INTERPRETER_EVAL_FLAGS: frozenset[str] = frozenset({"-c", "-e", "--eval", "eval"})

# Wrapper runners that exec a tool from a downloaded environment. The
# validator unwraps these and re-runs the dangerous-interpreter check on
# the inner command.
INTERPRETER_RUNNER_WRAPPERS: frozenset[str] = frozenset({"uvx", "pipx"})

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


def get_rules_by_safety(safety: Safety) -> list[CommandRule]:
    """Get all rules with a given safety classification."""
    return [cmd for cmd in COMMANDS if cmd.safety == safety]


def get_rules_by_category(category: str) -> list[CommandRule]:
    """Get all rules in a given category."""
    return [cmd for cmd in COMMANDS if cmd.category == category]
