# Own-child credential transition

The reusable drop helper accepts an action ID, allocated task UID and original
supervisor PID supplied by trusted launch code. It requires Linux/root, its own
kernel PPid, the exact action task cgroup and the parent's manager-control cgroup.
The restricted locked-account checks are shared with launch admission, including
unique task primary group, request-only supplementary group, non-login shell and
absent home. No model-selected identity, groups or credential options are added.

After placement, it clears supplementary groups to the request group, changes
GID then UID, lowers all capability sets, sets NNP and configures SIGKILL on parent
death. UID changes clear that signal configuration, so it is applied after the
drop. PPid is rechecked afterward to detect parent loss during setup. The final
UID/GID fields, groups, NNP and effective/permitted/inheritable/ambient sets are
verified before returning. Failure aborts before any task argv may execute.

This provides a checked transition, not a process launcher or grant/start gate.
Parent-death protection covers the direct child; independent cgroup cleanup and
emergency stop must still handle all descendants. The bounding set remains the
service's two-capability bound, while all usable child sets are zero and NNP
prevents gaining file privileges. No SYS_ADMIN/SETPCAP/KILL/DAC capability is added.

The real delegated-service fixture now allocates a fresh locked task account,
uses this helper after placement, checks the configured parent-death signal via
prctl, forks a confirmed detached child and performs the existing group cleanup
tests. The fixture never executes caller task argv or declares synthetic action
IDs authorized. Account deletion is fixture cleanup after service termination,
not production identity recycling. Live broker grants/start handshake, independent
stop/revoke, crash reconciliation and artifact verification remain later gates.
