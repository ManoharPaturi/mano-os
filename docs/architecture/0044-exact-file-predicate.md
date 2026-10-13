# Preapproval exact-file verification

Trusted root control declares one immutable expected workspace-relative file path,
byte count and SHA256 for a pending terminal approval before it can issue a grant.
The contract is tied to the original approval, boot and permission epoch. Declaration
rejects traversal, invalid values, expiry, Stop, changed contracts and posthoc claims;
a lifetime quota of64 contracts bounds journal growth.

After that approved action finishes, protected control checks its captured artifact
against the original contract. It requires the same journal action, original grant
and task, current boot/epoch, declared source-relative path and actual stored byte
hash/length. The trusted journal's separate custody guard checks integrity again
before the action verification transition. The predicate and original approval ID
are recorded. Public/model callers cannot declare or perform this check.

This predicate proves exactly the declared file content. It does not prove general
program correctness, a trustworthy test suite, application behavior or broader task
intent. Capture still returns effect_verified=false; the action only changes after
the separate predicate passes. More outcome-specific verifiers remain required.

The deterministic VM golden project declares calc.py's known addition source before
PAM approval. The broker later captures it; a wrong-action artifact and public check
are denied, the actual expected source passes, and AgentRuntime then observes the
journal verification result. CI must establish this complete path before acceptance.
Unit tests cover immutable declarations, no posthoc contract, bytes mismatch,
wrong boot, expired/invalid inputs and Stop revocation. No physical or real-model
acceptance is implied.
