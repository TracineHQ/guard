---
description: Print every record matching a session-id, in chronological order.
argument-hint: <session-id>
allowed-tools: Bash(guard trace *)
disable-model-invocation: true
---

# /guard:trace

Print all decision-log records for a given Claude Code session, sorted by
timestamp.

```!
guard trace $ARGUMENTS
```

Display the output above to the user verbatim.
