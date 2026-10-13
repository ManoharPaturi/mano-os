# Explicit rearm and replacement acceptance gates

Extend the real native/PAM VM protocol with three remaining explicit checks:

- Mint a generation-bound challenge, wait61 real monotonic seconds, and require
  PAM-authenticated confirmation to be denied while the native latch stays set.
- Root operator fault injection creates one known task-shaped cgroup with a
  blocked-then-unprivileged sleeping child. A correct PAM confirmation must be
  denied while populated1. After killing/reaping/removing only this fixture group,
  a fresh challenge may rearm. Production preparation rules are unchanged.
- Replace the launcher process/cgroup while the native Stop process stays alive.
  Explicitly restart the broker's pinned transport, reprovision the workspace and
  approve a new real task. Human Stop must drain the replacement task group.

A separate trusted read-only journal observer checks the original grant is revoked
and the broker recorded the new native generation after frozen-broker rearm. It
never issues a grant or changes State. This strengthens the earlier old-grant
negative, which also changed provisioning identity.

The fixture child's error path always exits directly; it cannot execute the
operator parent's cleanup. Every injected PID/group belongs to this disposable
VM test, and services stop before final fixture cleanup. No new production
permission, capability, limit, timeout shortcut or user-controlled path is added.
The real61-second wait preserves the actual expiry policy. Kernel drain observation
accepts either populated0 or removal by the owning controller, with a bounded
three-second wait and no permission-error waiver.

All checks are pending actual CI. Native Stop/full version/physical/performance
acceptance must not be inferred from local Python tests. Async transport, sealed
artifacts, minimal agent and the full original later phases remain required.
