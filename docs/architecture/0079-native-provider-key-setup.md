# Native terminal provider key installation

`python3 -m mano_broker.provider_setup` accepts no arguments and runs only as
Linux Root with native terminal input/output. The operator must first invoke
native Stop: its Root latch must be set and the core cgroup must be drained.
The same Stop generation is checked again immediately before publication.

The fixed destination is /etc/mano/credentials/openai. Root-owned ancestors and
an exact0700 credential directory are required. Any existing destination,
including a symlink, is refused before prompting. Two non-echoed entries must
match and satisfy a bounded ASCII credential format. No environment variable,
command argument or piped secret input is supported.

A private0600 exclusive staging file is fully written and fsynced. A hard link
publishes it atomically without replacing a concurrent destination; only this
invocation's staging file is then removed and the directory fsynced. Normal
completion leaves a single-link Root credential. A crash between linking and
unlinking can leave two links; the provider's single-link check then fails closed.
Recovery and key rotation require a separate operator procedure. Python strings
are not a claim of guaranteed memory zeroization.

This command changes no activation, pricing, controller or egress configuration,
restarts no service, rearms no Stop latch and performs no network/model call.
Success reports installation only. The operator must separately review those
policies before enabling anything that can spend money or disclose a prompt.

Unit tests cover private atomic publication, invalid input, Stop-check failure,
concurrent destination preservation, symlink refusal and nonterminal/nonroot
rejection. The guarded Debian VM additionally runs the actual CLI through a
controlling pseudo-terminal with a synthetic key, verifies no echo, Root0600
single-link ownership, refusal before prompting on repeat, piped-input denial,
and unchanged activation policies and Stop generation. A pseudo-terminal test
proves Linux terminal behavior, not physical keyboard provenance. No real key or
paid provider call is part of this evidence.
