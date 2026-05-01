"""Top-level smoke test: critical guard modules load and expose the symbols
that the hooks and external consumers depend on."""

from __future__ import annotations


def test_critical_imports_resolve() -> None:
    from guard import _utils, registry
    from guard.hooks import (
        agent_output_guard,
        bash_command_validator,
        chrome_safety_validator,
        commit_message_validator,
        credential_check,
        git_c_validator,
        protected_files,
        subagent_scope,
    )

    # Each hook module must export `hook` (the entry point).
    for module in (
        agent_output_guard,
        bash_command_validator,
        chrome_safety_validator,
        commit_message_validator,
        credential_check,
        git_c_validator,
        protected_files,
        subagent_scope,
    ):
        assert callable(getattr(module, "hook", None)), f"{module.__name__} missing hook()"
    # Registry must expose the load-bearing rule sets.
    assert registry.COMMANDS, "registry.COMMANDS empty"
    assert registry.ALWAYS_DENY, "registry.ALWAYS_DENY empty"
    assert registry.AUTONOMOUS_FEEDBACK, "registry.AUTONOMOUS_FEEDBACK empty"
    # _utils must expose the JSONL writer + decision helpers.
    assert callable(_utils.append_jsonl)
    assert callable(_utils.log_decision)
    assert callable(_utils.emit_pretooluse_decision)
    assert callable(_utils.is_autonomous_mode)
