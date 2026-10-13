# Threat model and current proof limits

## Assets and adversary

Protect user files/input/desktop, broker policy/grants/secrets/journal, devices,
startup paths, network destinations and recovery controls. Assume the entire planner,
repository, model response, coding delegate, MCP server and GUI app can be malicious.
Root compromise is outside this model. External content remains data, not authority.

## Verified feasibility boundaries

Real disposable Debian13 guest tests execute a positive workspace artifact before
asserting denied host filesystem writes, hidden session/control/device/cgroup paths,
cleared poisoned auth/display environment, closed inherited FD and denied egress.
Distinct human/agent/worker/core identities, runtime access permissions and private
network namespaces separate graphical domains. Ordinary workers receive restricted
Wayland protocols; forged privileged binds fail. XWayland has task-only cookies and
namespace-isolated abstract sockets. Actual Chromium sandbox and Writer private
AT-SPI/GUI save contracts pass. Concurrent human focus/text/receipt remain unchanged.

Approval uses the original specification's request-bound OS-authenticated fallback:
per-request PAM on genuine human ttyS0, broker-supplied digest/nonce/expiry/scope,
wrong password/modified request/expiry/replay negatives, protected root journal and
kernel-denied agent-side IPC/uinput access. Physical input provenance is null.
Native stop watchdog and trusted TTY route kill all active fixture tasks and revoke
grants/input with core/authority frozen and real pids saturation; TTY recovery survives.
Btrfs data/root restore and original-disk preservation are demonstrated across boots.

These are scoped experiments. Actual denials rely on kernel credentials, namespaces,
mounts, cgroups and compositor enforcement, not Python predicates or model behavior.
ADR0008/evidence audit covers every original Phase0 requirement before Phase1 work.
Cloud kernel lacks usable uinput driver: actual virtual-device behavior is unverified;
node access is denied, and no physical guarantee is claimed.

## Unproven production and release requirements

- Production broker IPC, operation-scoped grants, authoritative journal and lifecycle.
- Race-proof descriptor-pinned paths/mount topology; lab path checks are insufficient.
- Production input/capture mediation, sandbox resource supervision and identity policy.
- Seccomp/Landlock defense in depth and versioned coding/delegate/MCP attack corpus.
- Credential/network destination mediation, side-effect recovery and durable replay.
- Physical display/input/performance, signed updates, installer/firmware/recovery boot.

No model-facing executor, credentialed external request or hardware operation exists.
Phase0 GO permits developing Phase1 boundaries. It is not production certification
or an execution grant. Every wider capability retains its own implementation,
negative-test, resource and release gates. Full v2.1 goal remains unfinished.
