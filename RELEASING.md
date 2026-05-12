# Releasing guard

Maintainer-facing checklist for cutting a release. Follow top to bottom; do not
skip steps. `X.Y.Z` below means the version you are releasing (no leading `v`).
Tags are `vX.Y.Z`.

This repo's convention: `pyproject.toml` `version` always reflects the
**last released version** on `main`. Bump only when the next release is
actually being prepared. No `-dev0` suffix on `main` between releases.

## 1. Pre-tag checklist

- [ ] `main` is green: every required workflow on the commit you intend to
      tag is passing -- `CI`, `CodeQL`, `Scorecard`, `plugin-install`, and any
      others listed under branch protection's required checks.
- [ ] Working tree clean: `git status` shows nothing to commit.
- [ ] `CHANGELOG.md` has a real `## [X.Y.Z] - YYYY-MM-DD` heading directly above
      `## [Unreleased]`. The entry covers user-facing notes under the relevant
      Keep-a-Changelog buckets: Added / Changed / Fixed / Removed / Deprecated /
      Security. No empty buckets.
- [ ] `pyproject.toml` `version = "X.Y.Z"` matches the planned tag (no `v`,
      no `-dev` suffix).
- [ ] `.claude-plugin/plugin.json` `version` matches `X.Y.Z`.
- [ ] `.claude-plugin/marketplace.json` plugin entry `version` and
      `metadata.version` both match `X.Y.Z`.
- [ ] Version-consistency test passes:
      `uv run pytest tests/test_version_consistency.py`.
- [ ] Full local check is clean: `just check` (ruff + mypy + pytest). For
      coverage, run `just test-cov` separately.
- [ ] Local wheel build reports the right CLI version:

      ```bash
      uv build
      uv tool install ./dist/tracine_guard-X.Y.Z-*.whl --reinstall
      guard --version    # expect: guard X.Y.Z
      uv tool uninstall guard
      ```

## 2. Tag and push

- [ ] Create a **signed** tag. Guard's whole pitch is supply-chain safety; an
      unsigned release tag undercuts that. One-time setup: configure
      `git config user.signingkey` (GPG or SSH) and `git config tag.gpgsign true`.

      ```bash
      git tag -s vX.Y.Z -m "vX.Y.Z"
      ```

- [ ] Push the tag:

      ```bash
      git push origin vX.Y.Z
      ```

- [ ] The release workflow (`.github/workflows/release.yml`) fires on tag push
      matching `v[0-9]*.[0-9]*.[0-9]*`. Pipeline:

      `detect-prerelease` -> `build` (sdist + wheel + sha256 manifest) ->
      `testpypi-publish` (OIDC to TestPyPI) -> `testpypi-smoke` (matrix:
      py3.11 / 3.12 / 3.13 x ubuntu / macos, hash-pinned install, hook deny
      payload test, full pytest re-run against the installed wheel) ->
      `pypi-publish` (production, OIDC, skipped for prereleases) ->
      `gh-release` (uploads `.whl` and `.tar.gz`, posts auto-generated notes).

- [ ] **Release notes come from `gh release create --generate-notes`** (the PR
      and commit list since the previous tag). They do NOT come from
      `CHANGELOG.md`. Keep PR titles clean -- they become the release body.
      `CHANGELOG.md` is your curated historical record, separate from the
      auto-generated GitHub Release body.

### Prereleases

To cut an rc / alpha / beta / dev, tag with a PEP 440 suffix:

```bash
git tag -s vX.Y.Zrc1 -m "vX.Y.Zrc1"
```

`detect-prerelease` flags any tag with a suffix and skips `pypi-publish`.
TestPyPI publish + smoke still run, and `gh-release` still fires with the
`--prerelease` flag set so the GitHub Release is marked accordingly.

## 3. Post-tag verification

- [ ] Open the run under the **Release** workflow in GitHub Actions.
- [ ] **Two environment approvals are required**, in order:
  - [ ] `TestPyPi` (before `testpypi-publish` runs). Approve it; the
        `testpypi-smoke` matrix (6 jobs across py3.11 / 3.12 / 3.13 x ubuntu
        / macos) gates everything downstream.
  - [ ] `PyPi` (before `pypi-publish` runs). Only reachable after smoke
        passes. Skipped automatically for prerelease tags.
- [ ] Verify the release on [pypi.org/project/tracine-guard](https://pypi.org/project/tracine-guard/).
      The new version must be the latest. Both wheel and sdist must be
      present.
- [ ] Verify the GitHub Release exists at
      `https://github.com/TracineHQ/guard/releases/tag/vX.Y.Z` with:
  - [ ] `tracine_guard-X.Y.Z-py3-none-any.whl` attached.
  - [ ] `tracine_guard-X.Y.Z.tar.gz` attached.
  - [ ] Body populated with auto-generated notes (PR / commit list since the
        previous tag). Sanity-check the list looks right; if a PR title was
        wrong, you can edit the release body manually.
  - [ ] If it landed as draft, click **Publish release**.
- [ ] Smoke-install from PyPI in a clean shell:

      ```bash
      pipx install tracine-guard==X.Y.Z
      guard --version    # expect: guard X.Y.Z

      # Deterministic deny check: feed a dangerous payload to the bash
      # validator hook; it must exit 2 with permissionDecision: deny.
      echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
        | python -m guard.hooks.bash_command_validator
      echo "exit=$?"   # expect: exit=2

      pipx uninstall tracine-guard
      ```

## 4. Claude Code marketplace submission

The community marketplace mirror at
[anthropics/claude-plugins-community](https://github.com/anthropics/claude-plugins-community)
is read-only and synced nightly from Anthropic's internal review pipeline.
**PRs opened against that repo are auto-closed.** Submit via the in-app form
instead.

### Pre-submission checks

- [ ] `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`
      reflect the released `X.Y.Z` (already validated in section 1).
- [ ] Local plugin smoke (in any Claude Code session, against the source tree):
      ```
      claude --plugin-dir /path/to/guard
      ```
      Confirm `guard --version` in that session reports the source-tree
      version. For a deterministic deny check that doesn't depend on a live
      Claude session, run the hook directly (same recipe as section 3):

      ```bash
      echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
        | python -m guard.hooks.bash_command_validator
      ```

      To inspect a real session's decisions, run `guard status` to list
      session ids, then `guard trace <session-id>` to print the JSONL
      records for that session.
- [ ] PyPI publish is live at
      [pypi.org/project/tracine-guard](https://pypi.org/project/tracine-guard/).
      The marketplace listing assumes users can `pipx install tracine-guard`
      to get the `guard` binary the plugin shells out to.

### Submit via the in-app form

Pick one entrypoint (both submit to the same review pipeline):

- **Claude.ai**: [claude.ai/settings/plugins/submit](https://claude.ai/settings/plugins/submit)
- **Console**: [platform.claude.com/plugins/submit](https://platform.claude.com/plugins/submit)

Submission inputs (have these ready):

- Public repo URL: `https://github.com/TracineHQ/guard`
- Path to plugin manifest: `.claude-plugin/plugin.json`
- Path to marketplace manifest: `.claude-plugin/marketplace.json`
- Released version: matches the `version` field in both manifests and the git
  tag `vX.Y.Z`
- Description: pulled from `marketplace.json` `plugins[0].description`
- Category: `security` (already set in `marketplace.json`)
- License: `Apache-2.0` (already in `plugin.json`)

### After submission

- [ ] Plugins go through automated security scanning before being added to
      the community marketplace. Wait for the acceptance email / GitHub
      notification.
- [ ] Once listed, smoke from a clean Claude Code session:

      ```
      /plugin marketplace add TracineHQ/guard
      /plugin install guard@tracinehq
      ```

      Confirm the plugin appears in `/plugin list` and the installed version
      matches `X.Y.Z`.

- [ ] "Anthropic Verified" status is a separate, additional review and is not
      automatic on first listing. Apply later via the same in-app form once
      the plugin has community traction.

### Updating after listing

The community-marketplace `marketplace.json` is synced nightly from
Anthropic's internal pipeline. To ship an update:

1. Cut a new release through this checklist (section 1 onward).
2. Re-run the submission form for the new version (or follow whatever
   "update existing listing" path the form provides; check before
   re-submitting from scratch).
3. The synced mirror picks up the new version on its next nightly sync.

## 5. Post-release housekeeping

- [ ] Add a fresh `## [Unreleased]` heading to the top of `CHANGELOG.md` with
      empty Added / Changed / Fixed buckets ready to receive entries.
- [ ] **Do not** bump `pyproject.toml` `version` here. This repo keeps `main`
      at the last released version; the bump happens at the start of the next
      release in section 1.
- [ ] If a breaking change is anticipated for the next release, open a
      `vX.(Y+1).0` milestone now and pin the relevant issues to it.
- [ ] Commit:

      ```
      Open X.Y.(Z+1) development
      ```

      (or `Open X.(Y+1).0 development` for the next minor.)

## 6. Backout / hotfix procedure

If `X.Y.Z` ships with a critical bug after PyPI publish:

- [ ] **Yank, do not delete.** Yanking hides the version from resolvers but
      preserves the artifact for anyone who pinned it explicitly. Deletion is
      irreversible and breaks reproducibility. See
      [PyPI yanking docs](https://docs.pypi.org/project-management/yanking/)
      and [PEP 592](https://peps.python.org/pep-0592/).
- [ ] Yank via the PyPI web UI:
      `https://pypi.org/manage/project/tracine-guard/release/X.Y.Z/` →
      **Options** → **Yank**. `uv publish` does not expose a yank command.
- [ ] **Do not delete the git tag.** Leave `vX.Y.Z` in history so the bug is
      traceable.
- [ ] Cut a hotfix:
  1. Branch from `main` (or from `vX.Y.Z` if `main` has already moved).
  2. Fix the bug, add a test, update `CHANGELOG.md` under a new
     `## [X.Y.(Z+1)] - YYYY-MM-DD` entry describing what broke and what was
     fixed under **Fixed** (and **Security** if applicable).
  3. Bump `pyproject.toml`, `plugin.json`, and `marketplace.json` to
     `X.Y.(Z+1)`.
  4. Run section 1 in full, then section 2 with the new tag.
- [ ] After the fix is live on PyPI, optionally update the yanked release's
      yank reason via the PyPI UI to point at the replacement version.

## Quick reference: files that carry the version

| File                                | Field                                     |
|-------------------------------------|-------------------------------------------|
| `pyproject.toml`                    | `[project] version`                       |
| `uv.lock`                           | `[[package]] version` for `tracine-guard` |
| `.claude-plugin/plugin.json`        | `version`                                 |
| `.claude-plugin/marketplace.json`   | `metadata.version` + `plugins[0].version` |
| `CHANGELOG.md`                      | `## [X.Y.Z] - YYYY-MM-DD`                 |
| `src/guard/__init__.py`             | `__version__` (read from pkg)             |

`tests/test_version_consistency.py` enforces `pyproject.toml`,
`plugin.json`, and `marketplace.json` against `guard.__version__`. It does
NOT check `uv.lock` or `CHANGELOG.md`; those two are on you.
