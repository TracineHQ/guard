# guard integrity runbook

Install + operate the integrity layer that keeps a coding agent from neutering
its own guardrails.

## Why this exists

Claude Code hooks **fail open**: only exit code 2 is fail-closed, and there is no
documented way for a hook to fail-closed on its *own* error. A broken, removed, or
rewritten guard hook therefore stops protecting silently. The integrity layer
closes that gap with three pieces, anchored outside the agent's write surface:

| Piece | What it is | When it runs |
|---|---|---|
| `bin/guard-sentinel` | dependency-free POSIX-sh check + self-heal | SessionStart hook |
| `bin/guard-integrity-monitor` | root daemon wrapper (reuses the sentinel) | every 5 min, out of band |
| manifest + `canonical/` | sha256 trust anchor + known-good copies | built by `guard integrity build` |

The manifest sha256 is the trust anchor. A live file must match it; a heal
restores it from the canonical copy (which must *also* match the anchor, so a
poisoned canonical can never heal a file to a bad state). Response is
**self-heal + advisory, not hard-fail** -- a tampered session is repaired and
logged, never bricked.

## The ownership boundary (what protects what)

- `/opt/guard/bin/*`, the manifest, and `canonical/` are **root-owned**
  (`root:wheel`, agent runs as you). The agent cannot write them at all.
- The files the agent *can* write -- your live guard hook scripts and
  `~/.claude/settings.json` -- are protected by the **integrity manifest**: if
  they drift, the sentinel/monitor restores them from the root-owned canonical.

So filesystem ownership protects the enforcement machinery; the manifest protects
the user-writable config the machinery guards.

## Layout (defaults)

```
/opt/guard/bin/guard-sentinel            # copied from this repo's bin/
/opt/guard/bin/guard-integrity-monitor   # copied from this repo's bin/
/opt/guard/integrity/manifest            # built by `guard integrity build`
/opt/guard/integrity/canonical/          # known-good copies
/var/log/guard-integrity.log             # append-only advisory log
```

Adjust paths to taste, but keep everything under a **root-owned** tree.

## 1. Stage the root-owned machinery

```sh
sudo install -d -o root -g wheel -m 0755 /opt/guard/bin /opt/guard/integrity
sudo install -o root -g wheel -m 0755 bin/guard-sentinel /opt/guard/bin/
sudo install -o root -g wheel -m 0755 bin/guard-integrity-monitor /opt/guard/bin/
```

(On Linux/WSL use `-g root` instead of `-g wheel`.)

## 2. Choose the protected set

The files whose integrity you want anchored. Discover your live guard hooks with
`guard status` (it prints the wired hook paths). A sensible starting set:

- your live guard hook scripts (e.g. the installed `bash_command_validator.py`,
  `run-hook`),
- `~/.claude/settings.json` (so the agent cannot unwire the hooks),
- any shell-init or PATH file you treat as security-relevant.

> Build records the file's **current** bytes as canonical -- only run it when the
> protected files are in a known-good state.

## 3. Build the manifest (as root)

```sh
sudo guard integrity build --root /opt/guard/integrity \
    ~/.claude/settings.json \
    /path/to/live/bash_command_validator.py
sudo guard integrity verify --root /opt/guard/integrity   # expect: OK
```

`build` writes the manifest + a canonical copy per file; `verify` is a
non-healing diagnostic (exit 1 on any drift).

## 4. Register the SessionStart sentinel -- the minimal anchor

The anchor is the one thing that must be un-removable by the agent. Use
**managed settings** (root-owned, highest precedence, cannot be overridden or
disabled by user/project/local config). Add *only* the SessionStart entry; do
**not** set `allowManagedHooksOnly` -- that would disable your other hooks.

macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
Linux/WSL: `/etc/claude-code/managed-settings.json` (confirm against your Claude
Code version)

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "GUARD_INTEGRITY_ROOT=/opt/guard/integrity /bin/sh /opt/guard/bin/guard-sentinel"
          }
        ]
      }
    ]
  }
}
```

Write the file as root, `0644`:

```sh
sudo install -o root -g wheel -m 0644 managed-settings.json \
    "/Library/Application Support/ClaudeCode/managed-settings.json"
```

**Alternative anchor (no managed settings):** add the SessionStart entry to a
normal settings file, then make that file immutable so the agent cannot revert
it -- `sudo chflags schg <file>` (macOS) or `sudo chattr +i <file>`
(Linux/WSL). Managed settings is preferred because it also wins on precedence.

## 5. Install the out-of-band daemon -- the real enforcer

Independent of Claude Code hooks, so it heals even if the SessionStart hook is
removed or fails open.

### macOS (LaunchDaemon)

```sh
sudo install -o root -g wheel -m 0644 deploy/com.tracinehq.guard-integrity.plist \
    /Library/LaunchDaemons/com.tracinehq.guard-integrity.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.tracinehq.guard-integrity.plist
sudo launchctl kickstart -p system/com.tracinehq.guard-integrity   # run once now
```

### Linux / WSL (systemd)

WSL needs systemd enabled (`[boot]\nsystemd=true` in `/etc/wsl.conf`, then
`wsl --shutdown`).

```sh
sudo install -o root -g root -m 0644 deploy/guard-integrity.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/guard-integrity.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now guard-integrity.timer
```

## 6. Verify end to end (benign)

```sh
# Tamper a protected file, then let the layer heal it:
echo '# tampered' | sudo tee -a ~/.claude/settings.json >/dev/null
sudo /opt/guard/bin/guard-integrity-monitor          # heals + logs
sudo guard integrity verify --root /opt/guard/integrity   # expect: OK again
tail -n 3 /var/log/guard-integrity.log               # see the timestamped advisory
```

A new Claude Code session triggers the same heal via the SessionStart sentinel.

## Cross-platform reference

| Concern | macOS | Linux / WSL |
|---|---|---|
| Managed settings | `/Library/Application Support/ClaudeCode/managed-settings.json` | `/etc/claude-code/managed-settings.json` |
| Daemon | LaunchDaemon (`StartInterval`) | systemd `.service` + `.timer` |
| Immutability flag | `chflags schg` | `chattr +i` |
| Root-owned group | `wheel` | `root` |
| WSL note | n/a | requires `systemd=true` in `/etc/wsl.conf` |

## Rollback / kill switches (each < 30s, root)

- **Daemon:** `sudo launchctl bootout system/com.tracinehq.guard-integrity`
  (macOS) / `sudo systemctl disable --now guard-integrity.timer` (Linux/WSL).
- **Sentinel anchor:** remove the SessionStart entry from managed settings, or
  `sudo chflags noschg <file>` / `sudo chattr -i <file>` if you used the
  immutability anchor.
- **Whole layer:** `sudo rm -rf /opt/guard/integrity` (drops the anchor; the
  sentinel then reports a missing manifest and no longer heals).

## Operating notes

- **After a legitimate change** to a protected file, rebuild: re-run
  `guard integrity build` so the new bytes become the canonical baseline.
  Otherwise the layer will faithfully revert your change.
- **TAMPER advisories** (canonical missing or also off-anchor) are unhealable by
  design and require out-of-band intervention -- rebuild from a trusted source.
- The monitor log is append-only; rotate it with your normal logrotate/newsyslog
  policy if it grows.
