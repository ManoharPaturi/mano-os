# Reuse original prompt launch context

The protected broker stores immutable launch context after a prompt's matching
managed task attaches. Context binds the original human/boot/task/resource/caller/
prompt/operation key and fixed workspace prefix. Exact repeated storage is
idempotent; changes or wrong bindings are denied. Only protected root control can
store or retrieve it. Lifecycle still verifies actual account/workspace before launch.

A prompt-ID dispatcher cycle reads journal status. Received intent can be claimed
once by the existing factory; task_created uses its stored context without allocating
another account. Creating/unknown states refuse automatic continuation. Missing
context after an uncertain attachment requires operator recovery rather than guessing
or recreating resources. The administrative CLI retains explicit --mock.

The actual VM now invokes every persistent cycle with the original human prompt ID,
retrieves original context and runs the bounded controller. Native PAM, sandboxed
project/test execution, checkpoint reopening, exact proposal/status verification,
independent file predicate, lost-response replay and frozen-core Stop remain in
scope. Unit tests close/reopen stored context, reject changed/wrong binding, and
prove a created prompt does not call the allocator again. Exact-head CI must pass.

This adds durable dispatcher plumbing, not the final automatic queue daemon or
real-provider workflow. Those and all later original version gates remain required.
