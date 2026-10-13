# One bounded queue cycle

The explicit mock lifecycle CLI now accepts `{next_prompt: true, plan: ...}`.
The trusted Linux operator validates the complete terminal plan before discovery,
reads the configured human policy, and checks the native Stop generation before
and after protected discovery. An empty queue produces a null task without work.
Otherwise only the oldest received prompt is passed to the existing dispatcher.

The dispatcher atomically claims the prompt, provisions its task, and runs the
fixed restricted core entry point. A lost claim race, launch failure, or uncertain
result aborts this invocation. It does not retry or advance to another prompt.
No caller-selected prompt ID, account, workspace, or command for root is accepted
by this queue selection path. Mock terminal arguments still require broker/PAM
authorization before execution.

This is one administrative queue cycle, not a recurring daemon or a real model.
After the initial cycle, continuation uses the saved prompt ID and task context;
claimed prompts do not reappear in discovery. Unit tests cover empty discovery,
pre-allocation plan validation, Stop changes, non-root denial, and no retry.
