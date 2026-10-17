# Explicitly enabled recurring controller service

mano-controller.timer runs a bounded oneshot every five seconds after the previous
unit exits. The service accepts no arguments or stdin task data. It loads only the
fixed config credential from /run/credentials/mano-controller.service; the Root
source is /etc/mano/controller.json. Strict schema permits only enabled/model/output
metadata, never a provider key or endpoint. The shipped policy is disabled with
null model metadata, so timer activation alone allocates no tasks or grants.

The controller runs as Root because the existing task factory creates locked
accounts and broker-owned workspaces. Its capabilities are limited to CHOWN,
DAC_OVERRIDE, FOWNER, SETGID and SETUID; no SYS_ADMIN or network capabilities.
NoNewPrivileges, seccomp, Unix-only sockets, private network/devices/tmp, a strict
read-only system, 128MiB/16-PID/20%-CPU limits and a forty-second hard start timeout
bound the oneshot. Unchanged queued/running terminal actions and unverified results
do not cause repeated core/checkpoint writes; the broker waits for a journal state
change or independent verification before claiming another cycle. It lives in the native Stop core slice. The core remains a
separate cap-zero task-UID service with its original independent limits.

Account tools require writable /etc for atomic account database replacement. This
is a trusted Root component with that access; /etc/mano, PAM, systemd and sudo policy
are separately mounted read-only. Outside /etc, write mounts are only the fixed
allocation lock and workspace tree. useradd no longer initializes login logs or
mail spools for locked non-login task identities. tmpfiles creates the Root-owned
workspace parent and allocation lock before service startup; it preserves existing
contents. Packaging must install default controller policy as Root0600 only when
absent, never overwrite an operator policy, and apply these prerequisites first.

Startup verifies exact Root identity, capability mask, NNP/seccomp and Stop cgroup.
It attempts write-only opens of policy/PAM files without writing or truncating, and
requires EROFS. It attempts an unconnected Internet socket and requires kernel
denial. An unexpected success is closed immediately and fails startup. No probe
sends network traffic or changes a policy file.

The Debian witness starts the installed service disabled, then explicitly enables
synthetic model metadata in the disposable guest. A new authenticated prompt must
allocate one task and wait for model disclosure approval. The actual timer must
resume that same task with a fresh journal cycle nonce, without any model grant or
provider job. It stops the timer/service and restores the disabled source afterward.
Required flags: installed_recurring_controller_service and
controller_root_policy_and_network_kernel_denials. Until final CI these are pending.
This is not live provider execution, physical input or frozen-controller validation.
Pricing/provider generation and provider Internet access remain disabled.
