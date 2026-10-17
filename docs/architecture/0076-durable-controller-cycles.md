# Durable claims for bounded controller cycles

A controller must not allocate another identity or repeat an uncertain core step
when its process restarts. The broker now records one Root-only core-cycle claim
before the Root controller creates a task or launches the core. The claim binds
original prompt, human, boot, native Stop generation, journal epoch, model metadata
and a fresh nonce. Only one cycle may be running globally. Discovery/claim creates
no grant, action, model reservation or provider job.

The Root controller command performs one bounded cycle. New received prompts use
the existing atomic task factory; waiting cycles reuse the original broker-stored
managed context. The controller validates prompt/operation identity and Stop before
and after its bounded broker-planner step, then records the reconciled status.
Waiting work has a broker-owned five-second minimum interval. An original model
choice cannot change on resume. Completed, failed and uncertain states are not
rescheduled. Interrupted task creation is never reclaimed. Broker recovery or native
Stop invalidates outstanding cycle authority; rearm cannot restore it.

The journal tests cover single claim, cooldown, nonce replay, model binding, Stop,
recovery, public/non-Root denial and absence of execution authority. Root-controller
tests cover one creation/step, failed creation without retry, Stop and identity.
The guarded Debian witness submits a fresh authenticated human prompt and runs the
actual Root controller command twice, reopening the same task/checkpoint. It must
observe one task and waiting disclosure approval with zero grants/provider jobs.
Required witness: installed_durable_controller_cycle.

This commit implements the durable one-cycle command. Recurring systemd activation
and its Root profile/configuration still require implementation and VM acceptance.
It does not install a timer, enable pricing/provider generation, permit Internet
access or prove approved/live provider execution. A claimed/unknown cycle needs
operator recovery; no timeout steals a possibly interrupted external effect.
