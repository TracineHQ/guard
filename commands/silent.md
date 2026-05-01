---
description: Rules that haven't fired in --since but have fired at some point. Defaults to 30d.
argument-hint: [--since SPAN]
allowed-tools: Bash(guard silent *)
disable-model-invocation: true
---

# /guard:silent

Print `(hook_id, decision)` pairs that have not fired in the recency window
but exist somewhere in the log. Useful for finding rules that may be dead
weight or have been bypassed by upstream changes.

```!
guard silent ${ARGUMENTS:---since 30d}
```

Display the output above to the user verbatim.
