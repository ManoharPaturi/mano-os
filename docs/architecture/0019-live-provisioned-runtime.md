# ADR0019: daemon provisioning and descriptor-backed request preparation

Status: candidate until current-head Linux/real service CI. No executor yet.

Broker activation now requires three named fixed listeners: request/control/
provision. Provision socket is root/root0600 and uses the tested root directory-FD
receiver. Runtime owns the live Registry; public propose is routed through registry
preparation before grant/intent reservation. Approval requests require an actual live
provisioned task/resource. Public output still contains metadata only, never FDs.

Startup preserves history but reconciles executing to unknown, queued intents to
failed, revokes old grants and advances the epoch. Lost process-local descriptors
cannot be restored from model/journal paths. Pending approval epoch becomes revoked;
fresh root FD provision and fresh approval are required. Historical status remains
available to the bound caller. Startup does not clear an emergency stop latch.

Provisioning alone is trusted operator metadata, not PAM consent. PAM remains the
separate human authentication path. Native helper confirms only broker-owned exact
view; Runtime additionally requires live resource authority before public preparation.
Directories and target objects remain pinned across name replacement. No file reads,
writes, terminal commands or model tools execute in this PR.

Service fixture now uses actual root-provisioned workspace IDs instead of fake a32
resource IDs. It validates three socket permissions/credential sources,14kernel
socket/journal denials,4control binding denials, nativePAMwrong password/nonce/replay,
valid exact grant and actual target FD held in broker /proc. Target name is replaced
with a protected sentinel symlink; replay does not repin. Restart is real SIGKILL,
while an executing journal state is explicitly seeded for recovery testing (no
operation ran). Unknown status, revoked pending approval, denied old resource/grant
and fresh distinct provision IDs are required. Broker/native UID/capability/NNP/
seccomp/settings and slow-client timeout remain checked. All prior VM/security/stop
probes remain required; old metadata-only service fixture is superseded by this flow.

Linux unit tests cover the Runtime facade, preparation-before-replay, malformed IDs,
wrong caller and startup invalidation. Mac skips Linux resource tests. Synthetic
PAM account only; manualTTY/GUI/physical provenance remains unverified. No host install.

Next: controlled workspace provisioner/job UID/DAC/ACL policy, actual sandbox/cgroup/
seccomp/Landlock executor using held descriptors and live stop leases, independent
verifier/prompt/minimalmodelLangGraph and originalPhase1goldenOSgate. Full original
v2.1 later physical/installer/release requirements remain active.
