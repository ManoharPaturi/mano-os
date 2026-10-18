# PAM-approved bounded workspace profiles

Permission mode becomes explicit authority through policy.set_profile. A task
can propose exact mode/duration/action-count/timeout arguments, but cannot approve
them. The existing separate native PAM view/confirmation authenticates the task's
human and consumes one exact challenge. The protected view includes compiled scope:
allocated workspace only, no networking, no automatic model disclosure/budget,
allowed entrypoints and expiry semantics. The library alone is not PAM proof.

The first profile implementation deliberately grants only the already allocated
workspace resource. Supervised can automatically issue read/health grants; Auto
adds workspace writes and Python/Git/Make/Node/pytest entrypoints; Full Access adds
absolute entrypoints under /usr/bin, /bin and /workspace. Each automatic decision
still creates one exact-argument, single-use, human/task/resource-bound grant and
journal approval record. Entry admission is not a per-binary confinement claim:
interpreters and child processes remain inside the same kernel sandbox. Full is
not Root, and this implementation does not add host-data mounts, external network,
credentials, devices or irreversible-effect authority. Wider scopes remain later
requirements, not demonstrated by this feature.

Limits are at most32 automatic grants per lease,900 seconds (Full300 seconds) and
300-second per-action runtime ceiling, bounded further by exact requested values.
Default tasks have no lease: existing per-action approval behavior is preserved.
Profile changes, model budgets and model disclosure never approve themselves.
Out-of-scope/exhausted/expired requests remain pending for explicit approval; old
pending requests are not retroactively approved. Lifetime approval quotas remain.

Issuance decrements remaining count atomically; idempotent replay cannot replenish
it. Grants retain the source profile/PAM approval for audit. Authorization and
dispatch recheck origin, expiry, boot, epoch and native Stop generation. Replacing
a profile revokes its old automatic grants. Changing profile during an executing
action denies; independent Stop remains available. Lease expiry prevents new
authorization/dispatch, while already-running actions retain their original cgroup
runtime limits. Broker recovery invalidates leases; Stop revokes all grants.
Renewal requires another exact PAM approval and cannot replay an old challenge.

Unit tests cover profile bounds, missing PAM authority, mode differences, no
budget/disclosure/elevation, exact args/resource binding, count/idempotence, expiry,
generation, recovery, Stop, replacement, queued dispatch and idle-change behavior.
The guarded Debian VM must prove actual native wrong-password/no-profile-change,
PAM approval, mode admission/count/real expiry, automatically granted terminal
writes, Full protected-policy/journal isolation and native Stop revocation.
Required flags: permission_profiles_native_pam_count_expiry_and_exact_grants,
full_workspace_profile_protected_policy_kernel_denial,
native_stop_revokes_permission_profile_authority.

Live broker-restart-with-active-lease acceptance is not supplied by the new VM
sequence; recovery invalidation currently has unit coverage plus the existing
installed broker recovery regression suite. No new GUI mode command is claimed.
Interactive permission management, broader data/network policies, live model
execution and all remaining original version gates are still required.
