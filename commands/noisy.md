---
description: Top N rules by hit count, grouped by (hook_id, decision). Defaults to 7d / top 10.
argument-hint: [--since SPAN] [--limit N]
allowed-tools: Bash(guard noisy *)
disable-model-invocation: true
---

# /guard:noisy

Print the top hit rules from guard's decision log, grouped by
`(hook_id, decision)`. Useful for finding rules that fire too often (good
candidates for tightening or removal).

```!
guard noisy ${ARGUMENTS:---since 7d}
```

Display the output above to the user verbatim.
