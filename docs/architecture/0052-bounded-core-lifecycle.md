# Bounded core lifecycle controller

Root-only mano-core-step/python -m mano_broker.lifecycle --mock validates trusted
managed task context, locked/nologin account, fixed workspace prefix and owner/group/
privacy before constructing one fixed systemd core service. No caller-selected
root command or arbitrary filesystem scope is executed. The same tested cap-zero/
NNP/seccomp/read-only/Unix-only/core-slice/resource/deadline profile is preserved.
Input is structured and bounded; the mock adapter remains explicit.

Native Stop must be armed before launch and its generation unchanged afterward.
An uncertain/failed result is not retried. The private checkpoint and broker action
journal reconcile subsequent operator cycles. Core stdout cannot establish task
completion: the controller queries root-only inspect_action, requiring original
task/current boot and an exact proposal digest built from the trusted plan/context.
Done without broker verification remains verifying; unknown remains unknown_effect.

Tests cover unprivileged/root-identity denial, latched/changed Stop, one launch,
returned context mismatch, authority fields and forged core completion. The actual
VM persistent workflow now uses this installed controller instead of duplicating
its service command in the fixture. Native PAM, task claim, restricted execution,
checkpoint, exact-file verifier, Stop and replay gates must all remain green.

This is an administrative lifecycle cycle, not yet an automatic queue worker or
real-model service. Actual enforcement is pending final-head CI. No privilege,
capability, sandbox or verification guard is relaxed to enable the controller.
