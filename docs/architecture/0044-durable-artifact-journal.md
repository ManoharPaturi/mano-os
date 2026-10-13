# Durable artifact custody in the private journal

Persist sealed captured bytes into the broker's existing SQLite database, whose
owner/mode/parent protection and synchronousEXTRA transaction policy are already
validated. Artifacts bind broker-issued artifact/action IDs and exact metadata;
completed original action/task ownership is required. At most8 artifacts of8MiB
are retained. No model-selected destination path or storage mutation API is added.

Persistence checks the live sealed copy's size/SHA256 and records metadata+bytes
atomically with an artifact-custody event. Repeated persistence of the same exact
identity is idempotent; conflicting metadata is denied. Hash capture alone still
never calls record_verification or marks an outcome verified.

Trusted chunk retrieval requires task ID, caller UID and current boot matching
journal ownership. It rejects bool/negative/oversize ranges, reads at most the
existing8MiB byte ceiling to recheck integrity, and returns only a4096-byte chunk.
Wrong caller/boot and corruption fail closed. This is a trusted library function,
not a public IPC endpoint yet; its caller must derive UID from the kernel.

Linux tests close custody and reopen the database, require original bytes and
unverified metadata, and check ownership/range/corruption denials. The VM closes
all sealed artifacts and reads the preserved output from a fresh broker-UID Python
process. Actual Linux/VM acceptance is pending CI. Production broker-filter
coverage, public retrieval and independent outcome checks remain required.
Durability here is process restart/SQLite persistence, not a physical power-cut or
filesystem-corruption recovery proof. Full original agent/golden/OS gates remain.
