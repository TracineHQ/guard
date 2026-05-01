---
description: In-process invocation of each hook's decide() on a given bash command.
argument-hint: "<command>"
allowed-tools: Bash(guard test *)
disable-model-invocation: true
---

# /guard:test

Invoke `bash_command_validator.decide()`, `git_c_validator.decide()`, and
`commit_message_validator.decide()` directly on the supplied command and
print what each hook would decide. No log access, no subprocess.

```!
guard test "$ARGUMENTS"
```

Display the output above to the user verbatim.
