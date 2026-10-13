# Authenticated human prompt intent

Default mano-prompt submission now uses the protected native human socket. Native
op5 carries a32hex request key and bounded8192-byte UTF8 prompt; op6 queries a
prompt ID. The adapter derives the human UID from kernel connection/message
credentials and its protected policy, then forwards typed root-only control to the
broker. Core/delegate callers cannot submit on the public broker route or forge
human identity. Invalid length, NUL, truncation, rights and malformed UTF8 fail closed.

The private broker journal stores received intent with human/request-key/boot
binding and a256-entry lifetime ceiling. Exact duplicate submission is idempotent;
changed text/boot conflicts. Status returns only ID/state/task ID to the original
human. It issues no grant, creates no account and runs no action. Worker claim/task
creation and full prompt-to-agent routing remain separate integration work.

The UI acknowledges only a protected received response and retains its request key
across an uncertain acknowledgement. It clears text only after success. The Phase0
layout/focus witness explicitly injects the existing local-data recorder because
those initial boot probes precede broker installation; production defaults have no
silent local success fallback. Phase0 proof remains layout/input isolation only.

Tests cover literal command-like intent, no grants/actions, exact replay/conflict,
wrong human, public/non-root control denial, packet bounds and UI key reuse. The
installed VM uses the actual native human client and checks duplicate/status,
malformed byte/length and untrusted actor/public route denial. Native C strict
compilation and all prior security gates must pass exact-head CI before acceptance.
