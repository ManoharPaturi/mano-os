# ADR 0001: keep production execution disabled until boundary proof

Status: superseded for Phase0 feasibility by ADR0008; production restriction retained.

The original specification orders feasibility/security before runtime. The ARM Mac
has low spare disk capacity, so Linux integration runs in disposable remote QEMU
without local VM/model downloads. Root setup helpers are guest fixtures, not agent APIs.

PRs1–16 proved actual btrfs root/recovery, native human prompt, restricted agent
Wayland/XWayland, real Chromium/Writer contracts, concurrent focus isolation,
request-bound OS-authenticated approval and native independent stop/revocation.
Read ADR0008 and current run artifacts for the full original-spec review and limits.
Physical provenance remains unmeasured; the specification's authenticated fallback
is the chosen strategy. Physical8GB/installer/firmware gates remain later requirements.

The lab is not a production broker. Its workspace resolver is not race-proof;
production must pin resources by descriptors and use broker-owned topology. Typed
IPC/grants/journal, production cgroups, seccomp/Landlock, network and credential
mediation are Phase1/later gates before tools can be exposed to a model. Phase0 GO
permits their development; it never authorizes arbitrary or unrestricted execution.
