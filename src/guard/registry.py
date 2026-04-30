# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TracineHQ contributors
"""Single source of truth for command safety classifications.

Used by:
- bash_command_validator.py (imports SAFE_PREFIXES, AUTONOMOUS_FEEDBACK, etc.)
- generate_settings.py (generates settings.json permissions from registry)
"""
# Verbatim port from upstream registry (AD-6): the COMMANDS table is the contract,
# so we suppress purely-cosmetic lints that would force restructuring/edits.
#   D101: Safety/CommandRule are self-describing; docstrings would just restate names.
#   E501: a few autonomous_feedback strings are slightly over 100 chars; rewriting
#         them changes the user-visible message and is out of scope for this port.
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
    CommandRule("env", Safety.ALLOW, "Environment vars", "util"),
    CommandRule("which", Safety.ALLOW, "Find executable", "util"),
    CommandRule("whereis", Safety.ALLOW, "Find executable", "util"),
    CommandRule("type", Safety.ALLOW, "Command type", "util"),
    CommandRule("pwd", Safety.ALLOW, "Print working dir", "util"),
    CommandRule("ps", Safety.ALLOW, "Process list", "util"),
    CommandRule("true", Safety.ALLOW, "No-op", "util"),
    CommandRule("false", Safety.ALLOW, "No-op", "util"),
    CommandRule("test", Safety.ALLOW, "Test expression", "util"),
    CommandRule("bc", Safety.ALLOW, "Calculator", "util"),
    # --- Python (ALLOW) ---
    CommandRule("python3", Safety.ALLOW, "Python execution", "python"),
    CommandRule("python", Safety.ALLOW, "Python execution", "python"),
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
    CommandRule("node", Safety.ALLOW, "Node execution", "node"),
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
    # --- Chrome CLI Read (ALLOW) ---
    CommandRule("chrome status", Safety.ALLOW, "Read-only Chrome status", "chrome-read"),
    CommandRule("chrome tabs", Safety.ALLOW, "Read-only tab listing", "chrome-read"),
    CommandRule("chrome tree", Safety.ALLOW, "Read-only DOM tree", "chrome-read"),
    CommandRule("chrome query", Safety.ALLOW, "Read-only DOM query", "chrome-read"),
    CommandRule("chrome inspect", Safety.ALLOW, "Read-only element inspection", "chrome-read"),
    CommandRule("chrome page", Safety.ALLOW, "Read-only page summary", "chrome-read"),
    CommandRule("chrome text", Safety.ALLOW, "Read-only text extraction", "chrome-read"),
    CommandRule("chrome screenshot", Safety.ALLOW, "Read-only screenshot capture", "chrome-read"),
    CommandRule("chrome console", Safety.ALLOW, "Read-only console messages", "chrome-read"),
    CommandRule("chrome network", Safety.ALLOW, "Read-only network requests", "chrome-read"),
    CommandRule("chrome snapshot", Safety.ALLOW, "Read-only accessibility snapshot", "chrome-read"),
    CommandRule("chrome stats", Safety.ALLOW, "Read-only session stats", "chrome-read"),
    CommandRule("chrome log", Safety.ALLOW, "Read-only command log", "chrome-read"),
    CommandRule("chrome session", Safety.ALLOW, "Read-only session overview", "chrome-read"),
    CommandRule("chrome note", Safety.ALLOW, "Session note management", "chrome-read"),
    CommandRule("chrome focus", Safety.ALLOW, "Session focus management", "chrome-read"),
    CommandRule("chrome tab-note", Safety.ALLOW, "Tab annotation", "chrome-read"),
    CommandRule("chrome clear-session", Safety.ALLOW, "Clear session state", "chrome-read"),
    # --- Chrome CLI Write (ASK) ---
    CommandRule(
        "chrome launch",
        Safety.ASK,
        "Launches Chrome process",
        "chrome-write",
        autonomous_feedback="Chrome launch requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "chrome stop",
        Safety.ASK,
        "Stops Chrome process",
        "chrome-write",
        autonomous_feedback="Chrome stop requires confirmation. Queue for session end.",
    ),
    CommandRule(
        "chrome navigate",
        Safety.ASK,
        "Navigates to URL",
        "chrome-write",
        autonomous_feedback="Navigation requires confirmation. Describe what to navigate to.",
    ),
    CommandRule(
        "chrome click",
        Safety.ASK,
        "Clicks DOM element",
        "chrome-write",
        autonomous_feedback="Click requires confirmation. Describe the interaction.",
    ),
    CommandRule(
        "chrome fill",
        Safety.ASK,
        "Fills form input",
        "chrome-write",
        autonomous_feedback="Form fill requires confirmation. Describe what to fill.",
    ),
    CommandRule(
        "chrome eval",
        Safety.ASK,
        "Evaluates JavaScript",
        "chrome-write",
        autonomous_feedback="JS eval requires human review. Describe the intent.",
    ),
    CommandRule(
        "chrome wait",
        Safety.ASK,
        "Waits for element",
        "chrome-write",
        autonomous_feedback="Wait requires confirmation.",
    ),
    CommandRule(
        "chrome fetch",
        Safety.ASK,
        "Fetches URL via browser session",
        "chrome-write",
        autonomous_feedback="Fetch requires human review. The browser session may contain credentials.",
    ),
    CommandRule(
        "chrome open",
        Safety.ASK,
        "Opens new tab",
        "chrome-write",
        autonomous_feedback="Tab open requires confirmation.",
    ),
    CommandRule(
        "chrome close",
        Safety.ASK,
        "Closes tab",
        "chrome-write",
        autonomous_feedback="Tab close requires confirmation.",
    ),
    CommandRule(
        "chrome reload",
        Safety.ASK,
        "Reloads tab",
        "chrome-write",
        autonomous_feedback="Tab reload requires confirmation.",
    ),
]


# === Derived Data Structures ===

SAFE_PREFIXES: frozenset[str] = frozenset(
    cmd.prefix for cmd in COMMANDS if cmd.safety == Safety.ALLOW
)

SAFE_PIPE_COMMANDS: frozenset[str] = frozenset(cmd.prefix for cmd in COMMANDS if cmd.pipe_safe)

AUTONOMOUS_FEEDBACK: dict[str, str] = {
    cmd.prefix: cmd.autonomous_feedback
    for cmd in COMMANDS
    if cmd.safety == Safety.ASK and cmd.autonomous_feedback
}

ALWAYS_DENY: frozenset[str] = frozenset(cmd.prefix for cmd in COMMANDS if cmd.safety == Safety.DENY)


def get_rules_by_safety(safety: Safety) -> list[CommandRule]:
    """Get all rules with a given safety classification."""
    return [cmd for cmd in COMMANDS if cmd.safety == safety]


def get_rules_by_category(category: str) -> list[CommandRule]:
    """Get all rules in a given category."""
    return [cmd for cmd in COMMANDS if cmd.category == category]
