# Durable prompt-to-task handoff

Protected root control claims a received human prompt exactly once before the
factory allocates an account or workspace. The broker commits creating_task and
an event first. A matching-human/current-boot provisioned task can then be attached
once, returning task_created to native human status. No grant or action is issued
by this transition. The workflow operation key is the original prompt ID.

Broker restart, native Stop and explicit uncertain-response handling turn an
outstanding claim into unknown_task_creation. It cannot be claimed or allocated
again automatically. The factory preserves uncertain identities/workspaces, never
retries a claim/allocation, and does not recursively delete data. Lost attachment
acks can be inspected through protected status rather than guessed or replayed.

UI duplicate submission accepts an already-advanced state for the same original
key, so a lost acknowledgement cannot create a second intent. This acknowledgement
still reports only journal reception/creation, not task execution or completion.

Local tests cover exact claim, wrong human/boot, one attachment, no grants, Stop/
restart uncertainty, and an uncertain claim not calling account allocation. The
actual VM's factory now takes the real native-human receipt ID, attaches its task,
queries human status and denies duplicate creation before the full existing
PAM/core/sandbox/checkpoint/verifier/Stop workflow. Acceptance requires final-head CI.
Automatic worker/lifecycle service, real providers and full user workflow remain
separate requirements; the administrative factory is still root-only.
