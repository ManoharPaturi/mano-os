# ADR0014: separate protected approval control transport

Status: candidate until current-head CI. Native PAM adapter remains next.

The non-root broker now receives two explicitly named systemd packet listeners:
request and control. It validates activation PID/count/names and both fixed paths,
listening state and per-message credentials. Request socket remains root/group0660;
control is root/root0600 with backlog8. Only the inherited listening descriptor
lets the non-root service receive control traffic; it cannot grant socket access
through its public protocol. Unknown/missing/duplicate listener names fail startup.

Control checks connection and per-message PID/UID/GID through the existing receive
path, then requires UID0. It exposes only approval_view and confirm_approval. View
is bound to a known task human; confirmation accepts only approvalID, humanUID,
nonce and operation digest, never password, arbitrary args, command or approval flag.
The queue rechecks expiry/boot/epoch/human and atomically consumes one challenge.
Untrusted callers cannot access this endpoint even if they know an approvalID.
Root is trusted by the OS boundary: root confirmation alone is not PAM proof.

Separate connection budgets and control-first readiness processing reduce public
queue interference; each handler retains the two-second I/O timeout. Requests stay
64KiB, private view responses bounded128KiB to allow trusted metadata around the
validated operation. Both listeners are fixed and non-inheritable inside the service.
Watchdog/restart and private journal/service limits remain unchanged.

CI installs both real units and verifies mode0600/root control socket. Agent/core/
worker/human connection attempts get kernel EACCES. Root view/confirmation must reject
wrong human, nonce, digest and injected password fields, deny second consumption,
return one grant, and allow only its exact operation on the public channel. Existing
private pending-state SIGKILL recovery and all VM/stop/security tests still run.
This root fixture performs no PAM authentication and records that fact explicitly.

Next: small native PAM adapter, root-owned human-UID mapping and separate protected
human UI channel. It must derive user identity from kernel credentials, render only
broker-owned structured view, authenticate via PAM, zero password buffers and send
only the bound confirmation over control. No arbitrary privileged execution, raw
credential injection or root shell. Then FD resources, actual sandbox/native stop/
verifier, minimal model/golden Phase1 gate and remaining original v2.1 release scope.
