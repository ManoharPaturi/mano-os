# Native Stop generations and atomic state

Native authority is now an exact versioned record: v1:<generation>:armed or
v1:<generation>:latched followed by one newline. Generations are canonical decimal
integers bounded to signed64-bit range. Each Stop publishes a newer latched
record. Existing valid legacy armed/latched records migrate without clearing Stop;
corrupt committed records never become implicitly armed.

The native writer creates root-owned mode0644 state.pending with no-follow and
exclusive flags, writes the complete record, fsyncs file and parent, renames it
over state, then fsyncs parent again. Readers deny authority while any pending
write exists, checking before and after the bounded committed-state read.

Startup recognizes trusted interrupted pending writes. It recovers into a newer
latched generation, including a valid interrupted armed record. A partial pending
record uses the last valid committed generation; malformed ownership/type/mode
fails closed. Recovery overwrites the trusted pending file then uses the same
atomic publication. It never deletes pending intent before publishing recovery.
If durable publication fails during Stop, the backend still attempts task kill,
reports failure and exits so systemd retries fail-closed recovery.

Portable tests reject malformed/noncanonical/overflow generations, metadata and
pending authority. The actual VM injects a partial pending record and a complete
pending armed record while the daemon is stopped, then requires newer latched
recovery and old request denial. Native compile and VM acceptance are pending CI.

This supplies the generation boundary required for future request-bound PAM
rearm. It does not implement rearm, asynchronous transport, sealed artifacts or
physical/golden/OS acceptance. The complete original version remains unfinished.
