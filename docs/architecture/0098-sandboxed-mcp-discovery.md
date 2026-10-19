# 0098: Approved local MCP metadata discovery

The new `mcp.discover` action starts one exact approved executable/argv, pinned
working directory, deadline and protocol revision. Starting a server is arbitrary
code execution, even when the intended request only lists metadata. This action
therefore always needs its own native PAM approval; Auto/Full workspace profiles
do not include it. Version 2026-07-28 is explicit. No legacy initialization,
compatibility probe, second process, automatic restart, or uncertainty retry is
hidden under the approval.

The existing Registry/Root admission pins workspace and cwd descriptors. The
normal dropped Task UID, delegated cgroup, namespaces, native kernel guard,
minimal environment and Stop contract remain in force. Both workspace aliases
are remounted read-only for discovery; temporary files and a synthetic home remain
private. Coding delegate profiles are rejected. No host credentials, host IPC or
network route is supplied. The fixed trusted worker chooses this adapter only
from the validated capability after durable start authorization.

MCP uses separate stdin/stdout pipes and stderr diagnostics, not the coding PTY.
The adapter sends only `server/discover` and bounded `tools/list` pages, with the
required per-request modern `_meta` fields. It rejects unmatched/early responses,
server requests, interactive input, duplicate JSON keys, nonfinite numbers,
unsupported versions, bad schemas, duplicate tool names and cursor cycles.
Bounded notifications are discarded as data. JSON Schema 2020-12 checking uses
bundled metaschemas and rejects external references; it never fetches schemas.
Quotas: 32 KiB line, 64 KiB wire and manifest, 64 messages, four list pages,
32 tools, bounded structure/depth and a 1–300 second approved deadline. Writes
advance after each partial delivery. Nothing resends bytes after uncertainty.

Closing stdin initiates shutdown after metadata completion. Success additionally
requires complete stdout EOF, no partial trailing frame and server exit zero.
Ignoring EOF, exceeding quotas, protocol errors and deadline/Stop all fail the
adapter. The Root supervisor drains its cgroup, including detached descendants.
The private output table is shared with RUN, retaining caller/task/action/boot
binding, hashes, lifetime quota and atomic capture/outcome. Its return code for
MCP is the adapter outcome (zero only on successful discovery); actual server
return code is separately recorded in the manifest/error, never verification.
The SDK binds every status to the original proposal digest, exposes metadata as
untrusted, and always reports invocation_authorized=false/effect_verified=false.
RUN-only model feedback explicitly rejects MCP adapter outcomes.

CI installs the official Python MCP SDK 2.3.0 into a separate guest-only venv
using a hash-pinned dependency lock. The fixture runs as a sandboxed Task UID,
never Root; it checks both workspace aliases, network and hidden host endpoints,
then returns a tool with a hostile description through the actual SDK transport.
Additional installed native-PAM/public-SDK cases cover malformed/partial/noisy
frames, callbacks, wrong IDs, quotas, ignored EOF and a detached-child deadline.
A live MCP job with an identified detached server child joins the replacement
launcher native Stop probe with its authorities frozen. The earlier recorded RUN
and public PTY Stop probe remains unchanged, preserving the two-job ceiling. Each completed action is replayed only as the original journal row.
Exact-head CI and independent artifact inspection remain acceptance requirements.

This is local stdio discovery, not tools/call, remote HTTP MCP, authorization of
returned descriptions, model integration, authenticated provider work, or a
complete Phase 2. The optional SDK/fixture is excluded from the runtime package;
production schema checking uses Debian's python3-jsonschema dependency.

Primary protocol references:
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- https://modelcontextprotocol.io/specification/2026-07-28/server/discover
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0
