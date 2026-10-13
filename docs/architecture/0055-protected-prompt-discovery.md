# Protected pending prompt discovery

The future queue worker needs to discover received human intent without accepting
model-supplied task identities or inspecting private journal files. A root-only
control operation returns at most 256 receipts for the requested human UID and
the broker's current boot, in insertion order. Receipts contain only the prompt
ID, state, and empty task ID. Text remains behind the one-shot claim operation.

Discovery is read-only. It allocates no account, task, grant, or action. Claimed,
uncertain, and attached prompts are excluded; Stop disables discovery. Concurrent
discoverers must still use the existing atomic claim, which accepts only one
winner. This change supplies discovery, not an automatic worker or real model.

Unit checks cover identity, boot, state, ordering, repeated reads, strict fields,
root access, and Stop. The disposable VM checks the installed protected socket,
public-route rejection, and disappearance after actual task creation. Physical
input provenance and real cloud execution remain separate acceptance gates.
