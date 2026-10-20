# 0102: Source restoration preserves private runtime journals

The packaged core keeps its LangGraph journal in `.mano-agent`, owned by the
task UID with mode 0700. Source snapshot traversal previously tried to enter
that journal and correctly hit EACCES. Earlier isolated checkpoint probes had
no core journal, so they did not cover this integration boundary. Do not relax
the journal's permissions or grant the broker access to private agent state.

New source checkpoint requests explicitly exclude `.mano-agent`, `.git` and
`.mano-write-staging` at every depth. The native human approval view carries
the exact exclusions. The bounded source walker skips the private journal before
pinning/opening it, records its presence in the before layout, and captures the
same complete source-file scope otherwise. Restoration preserves that entry and
any containing directories; native restore publication/mkdir/remove helpers also
reject the private leaf name. Archive decoding rejects reserved journal paths.
The journal is runtime state, not a source artifact to disclose or overwrite.

Legacy saved checkpoints remain readable within their existing caller/task/boot
scope and usable as restore sources under fresh same-human consent. Only trusted
historical-record parsing accepts the old two-exclusion request. Public proposal,
new approval and new execution parsing require the current three exclusions.
Metadata accepts only the two known historical/current scopes; restore source
loading also requires the archived receipt's exclusions to match its original
stored request. Legacy archives containing now-reserved runtime paths fail
closed in the bounded decoder. No old grant or execution permission is renewed.

Regression tests make the source walker fail if it ever pins the private name,
restore with a private canary journal present, and load a legacy saved source
while refusing a new legacy-scope capture. The pristine packaged runtime test
must show the broker cannot read/search the private journal before capture,
then capture and restore through native PAM/public SDK across actual poweroff.
Independent observation requires destination journal bytes, owner and mode to
remain unchanged. Full exact-head CI, artifact and raw screenshot gates remain.
