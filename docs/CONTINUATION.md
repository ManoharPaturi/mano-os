PR119 run39448926739 catalog passed; worker failed before JSON. Static nativeguard review: Landlock denies old top-level mounts. Move exact RO solver/catalog inside already masked /usr/lib/mano-os under existing read policy; no nativeguard changes. 454 local tests/46 skips; native acceptance pending.

PR119 third run39447006196 FAILED at security signed Components=updates/main. Correct suite-specific label; signed SHA256 path still main/binary-amd64/Packages. 454 local tests/46 skips, native acceptance pending.

PR119 second run39445095664 FAILED closed at cloud mirror+file cache identity. Add only fixed Debian cloud aliases; normalize snapshot names to official URI; keep original source identities. 453 local tests/46 skips, native acceptance pending.

PR119 correction: first run 39442986898 rejected Debian keyring .gpg symlink. Fixed host input uses regular .pgp without weakening trust. 452 local tests/46 skips; new native CI pending.

# Current package forecasts — not yet accepted

PR118 mergedbf25d57828dae429114b8009c4813491c07a98c1 after final35b19f9/
CI39390053998 ALLSUCCESS/artifact12250475386,54hashes/38flags/package/actual
poweroff source recovery/privatejournalpreservation/all6rawGUI accepted.
Postmain39392442977 verifiedSUCCESS. Fullphases0–7 remainACTIVE/incomplete.

Currentfeat/approved-package-plans adds ADR0103 typed packages.plan_install with
exactnames/catalogID, nativePAM separatefromAuto/Full, Root-onlyoffline signed
catalogsnapshot refresh, existingreadonly network-off sandbox/cgroup/Stop solver,
strictresult/durablecustody/SDK/core package_plan_ready receipt, nonexecuting
providercontract, packageCLI/dependencies and guardedCIprobes including independent
apt-getsimulation, corrupt/stalecatalog, unknownpkg, configinjection, frozenactual
solver+broker+launcherStop/restartunknown, stockSDK/corePAM before/afterrealboot.
Local451testsPASS/46Linuxskips andRuff; actualnewguestproofnotyetexecuted. No install/
applyhelper, modelcall/key/disclosure, hostcredential or servicefilterbypass.
CI/artifacts/all6freshpixels required beforemerge. Disk25GiBfree88%.
Detailedcontinuation/evidence in outputs/CONTINUATION.md. Do notdeclarefullversion
complete fromreadonlypackageplan; privilegedapply/snapshots/recovery remain.

# Current recorded developer workflow (under review)

Branch feat/durable-developer-workflow adds WRITE to strict typed/provider/core
plans, protected lifecycle receipt revalidation, broker-owned immutable recorded
workflow definitions and Root --recorded step operator. ADR0095.2..8 steps/16
workflows; derived keys, real broker exits and output hashes select recorded fixes;
unknown/unexpected/Stop/boot/lost-custody halt. Each effect still nativePAM granted.
Final predicate declared against broker-bound pending approval beforePAM, sealed
capture/check afterpassingtest; verifiedevidenceID/hash is authoritative. Metadata
historicalsnapshot/current_file_reverifiedFalse; no provider disclosure or paidcalls.
Supervisedrecordedmode explicit; changingpermissionmode revokes workflow. ActualVM
four-stepcreate/fail/fix/pass +checkpointreplay +nativeStop workflowtest added.
Local398 tests PASS/45Linuxskips, plus8newjournaltests and3targetedchecks. Ruff/
compile/shell/diff/embeddedprogram pass. FirstCI39209791923 qualitypassed butVM
bootstrapfailed onDebianlibeot download connectionreset beforeprojectprobes. Bounded
Acquire::Retries=3 nowused in guardedCIguestAPTcommands; validation unchanged.
PR111 remainsdraft/unaccepted; actualVM required beforemerge.
PR110postmain39208018349 now verifiedSUCCESS. Mainf9a3ef1 remains acceptedbase.
Disk18GiBfree92% warned. Full phases0-7 ACTIVE/incomplete.

# Current direct workspace writes (under review)

Branch feat/authorized-workspace-writes adds actual files.write executor, native
private staged creation/atomic renameat2 publication, scoped historical receipt
and SDK. ADR0094 explicitly supersedes old proposed in-place pinned-inode write
policy; the pinned parent remains authority, old external inode aliases unchanged.
Initial absent target is no-replace. Reserved broker-private0700 staging dir with
fixed0660 published files/taskGID; native scoped umask restores immediately, no
service policy relaxation.64 lifetime attempts include failures; empty internal
staging directories retained safely. Stop/expiry checks before and after mutation,
uncertain publication unknown/no replay. READ/WRITE reject reserved staging path.
Local389 tests pass/45 Linux skips. Linux native cases and actual PAM/SDK CI pending.
Recovery fixture now non-dispatched INSPECT; native target pin/rename check moved
to separate explicit Root-supervised broker-UID native-library process. Actual
writes get production create/replace/empty/replay/caller SDK checks. Full scope
ACTIVE. PR109 merged0d20fd3; postmain39191601068 stillrunning at lastcheck.
Disk20GiBfree90% warning, no local VM downloads or data deletion.

# Current public broker PTY implementation

Branch feat/broker-pty-sessions adds terminal.open_pty/native PAM, Root-supervised
dropped TaskPTY worker, durable at-most-once input journal, combined bounded output
and public SDK. ADR0093. Local381 tests pass/38 Linux skips. Actual CI VM acceptance
is still REQUIRED; no merge until every exact-head CI check and artifact/pixel
acceptance succeeds. Full phases0-7 goal ACTIVE/incomplete. PR108 postmain
39186591131 verified SUCCESS. Disk23GiB free89%; no local VM downloads/deletion.

# mano-OS continuation

Current task-owned-pty-worker implementsunprivilegedTaskPTYprimitive+privateguard
mode requiringexactsame taskUID-ownedslaveon0/1/2; setsidonlyifneeded/TIOCSCTTY0
neversteals. StandardRUNunchanged/--new-session retained/allkernelguardsretained.
Boundedinteractiveinput/read/resize/EOF/timeout/revocation/combinedoutput +CIactual
taskcontract/foreignsyntheticslavedenial/frozenPTYnativeStop added. This iskernel
boundaryprerequisite, NOTpublicterminal.open_pty orcompletePhase2. ExactheadCI+
actualartifactacceptance requiredbeforemerge. ADR0092. PR107merged7ed2bf8 after
CI39161087759 allSUCCESS; postmain39162163562 verifiedSUCCESS. FullgoalACTIVE.

Current durable-terminal-output reusesownedprivate launcherread_output: fixed64KiB
streams, one4096chunk/tick, Stop/grantrecheck, atomicdurablebytes+done/failed. New
private64resultSQLitecustody, scopedreadonlymetadata/chunk APIs, SDKbinaryretrieval
withhash/EOF/bounds+pacing, metadataonlycore/checkpoint andRootreconciliation.
Missingoutputexplicitnull, failedcommandsretainoutput, no reexecution/disclosure.
InstallednativePAMactualtask binaryfailure/replay andfreshstockpackagedstdout/stderr
before/afterboot added; mustpass exactheadCI/artifact acceptancebeforemerge. ADR0091.
PR106 merged6356c34 afterCI39159249171 allSUCCESS; fullv2.1ACTIVE, physical/paid/
fullreleaseunproved. Disk21GiB90%warning, builds/imagesremainCIonly.

Current typed-core-workspace-reads adds shared strict terminal/READ plans, two
strict provider proposal tools, separate broker-approved read execution and
bounded immutable result retrieval. Core checkpoint/stdout keeps metadata only;
read_ready is not verifiedtaskcompletion and no bytes are sent to a model.
Root lifecycle independently reconstructs metadata via protectedinspect_file_read,
and controller settles onecycle atread_ready. Actual allocated-task coreCLI/PAM/
SQLite-reopen/sourcemutationreplay witness and exact-headCI required beforemerge.
See architecture/0090. PR105 alreadymergedb7330209 afterCI39157530116 ALLSUCCESS;
full originalgoal ACTIVE, postmain39158576226 stillpending lastcheck. Disk21GiB90%.

Latest accepted: PR104 merged0647830b1fa42406bf91b4d20bfc4af90ca02efa after
CI39155979584 all3SUCCESS/art12147163329; 54 architecture hashes, package SHA and
six individually inspected raw GUI captures accepted. Clean stock Debian ordinary
login install/nativePAM/mock + real reboot/boot target/unused-unexpired oldgrant
revocation/data retention/newtask/Stop proved. Headless full-frame redraw only;
incremental/default/physical renderer and full release remain unaccepted.

Current bounded-workspace-read work adds actual scheduled files.read execution,
original pinned inode/sealed32KiB result, Stop/expiry recheck and atomic done+saved
artifact, caller/task/action/boot-bound file_result chunks. No file writer or core
planner extension. See architecture/0089. Exact-head CI, real installed-task read
and relevant artifact acceptance required before merge. Latest disk21GiBfree90%,
warning active; CI images/builds remain remote. Fullgoal ACTIVE.

Original v2.1 phases 0–7 remain active and incomplete. Frozen specification:
docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
The architecture verdict is only go-for-phase1-development; no release claim.

Main through PR94: dda429d4a21981c01b5211b40429359e7a7c8afa.
PR93 proved installed recurring Root controller/timer resume with protected
policy, hidden key source and kernel network denial in the Debian CI VM.
PR94 proved the fixed provider-only Unix TLS route through a separate keyless
network UID, disabled policy/wrong-UID/key-source denial and a public certificate
handshake without HTTP, prompt, Authorization, API key or paid model invocation.
Defaults for controller, provider, pricing and egress remain disabled.

Current native-provider-key-setup work adds a fixed-path Linux Root TTY command,
Stop-latched/drained checks, non-echoed confirmation and private atomic no-replace
credential publication. No activation/rearm/restart/network call. CI must prove
actual controlling-terminal behavior using only a synthetic key, private single
link, pipe/repeat denial and unchanged policies/latch. Local tests are not proof
of those installed guest behaviors. See architecture/0079-native-provider-key-setup.md.

Merge commits only after every check on the exact final PR head succeeds, actual
relevant artifact acceptance and a fresh ready/clean/current-main gate. Never
bypass a failed probe or protection. Use CI VMs; no local VM/model/ISO downloads.
Root/service/account changes belong only in guarded disposable Debian guests.
Physical input and physical 8 GB performance are deferred, not demonstrated.
No real provider key supplied; no paid/API/model execution accepted.

Remaining: approved live provider flow and independently verified model/pricing,
full policy profiles, approval/task UI, coding delegates/PTY/MCP, GUI workflows,
hardware/physical8GB, runtime package, signed installer/ISO/updates and release.
Do not narrow completion to CI components. Preserve unknown-effect/no-retry rules.

Local checks: .venv unittest discovery with PYTHONPATH=src, Ruff, diff whitespace,
shell syntax and Python compilation. Linux-only tests must actually execute in CI.
Check disk before builds/downloads; warn below20GiB or at90%, halt large downloads
below10GiB, never delete user data. Last observation30GiB free85% on2026-10-18.
No agent /compact tool is available; use concise handoffs for automatic compaction.
The task workspace outputs/ contains the full acceptance ledger, accepted artifact
reports and authoritative operational continuation; older source notes are archived
there under continuation-history/repo-through-pr54.md.

Next checkpoint: PR95 merged d1dff576374bb2456f576b5cc523f08494abb923 after
CI39083234775 all checks success and artifact12120320000/53hashes acceptance.
Native Root TTY key setup is now demonstrated with synthetic input only; real key,
activation and live paid API flow remain pending. Crash may leave a private source
staging link; systemd copies sources, so provider link checks do not detect it.
Current prompt-intake-status work adds a read-only GTK view and fixed native status
client. It shows only queue/provisioning state, not execution completion. Slow
refreshes are off the UI thread and cannot replace a newer acknowledged request.
The GTK/AT-SPI fixture is synthetic; separate installed broker tests must prove the
production status client/native transport. Local298tests/28Linux skips pass;
final-head CI/artifact acceptance remains required. See architecture/0080.

PR96 merged2e76f5be167feea2878e3fbaa7142c9bf25600a6 after exact-final-head
CI39084715416 all success, artifact12120402273/53hashes, synthetic GTK status and
visually inspected final PNG. Current human-task-status work extends protected
native operation07 to a human/boot/prompt/task-bound read-only journal snapshot:
latest16 actions with total count and all64 bounded approval records. No args,
reason, nonce/digest/grant IDs or credentials. Existing PAM view/confirm unchanged.
GTK uses fixed labels, revision/task binding and a bounded scroll region; status
reads cannot submit, approve or execute. Approvals schema now initializes with
State, so the first empty status read needs no DDL. Local306tests pass/28Linux skips.
Installed native scope/redaction/pending/done/verified and Stop-unknown/revoked
witnesses plus separate synthetic GTK text/responsiveness/screenshot need final CI.
Full original version, real provider execution, policy profiles and release remain
incomplete. See architecture/0081-human-task-journal.md and task workspace outputs.

PR97 merged e4848e1f820f554d948cedf728f5408c4b076e93 after exact-head
CI39085949215 all success, artifact12120753199/53hashes and native journal +
separate synthetic GTK/visual evidence. Current pam-permission-profiles work adds
policy.set_profile exact native PAM approval, task-bound workspace leases and
single-use exact automatic grants; no automatic profile/budget/model disclosure.
Supervised read/health; Auto adds writes/selected development entrypoints; Full
admits additional immutable/workspace tool entrypoints inside the SAME sandbox.
PAM view explicitly shows workspace-only/no-network scope. Entry policy does not
constrain child exec; kernel workspace/IPC/network isolation remains the boundary.
Limits32 grants,900s (Full300s),300s runtime cap. New authorization/dispatch checks
lease expiry/epoch/native generation/provenance. Replacement revokes prior leases'
grants; changing mode while executing denies; running actions keep original runtime
bounds, Stop stays independent. Broker recovery invalidates profiles. No host-data
or network widening, no mode UI command/full profile product claim. Local312tests
pass/28Linux skips; native PAM/count/expiry/Full protected-path/Stop VM witnesses
pending. See architecture/0082-pam-workspace-profiles.md and workspace outputs.

PR98 merged20ed8728d7576df38b5ea0c482b46024fb70f076 after finalCI39087071159
all success, artifact12120534310/53hashes; postmain39087623623 passed this turn.
Current trusted-mode-selection work adds native08 pending-only profile request,
09 effective read-only status and human TTY mano_prompt.mode command. Scope/task/
args checked before password; separate native PAM activates; cancel/wrongpass/noecho
failure do not. Print/reuse request key for explicit uncertain-ack retry; no automatic
retry. Existing approve/rearm refactored to shared guarded review; packet clear kept.
Local319tests pass/28Linux skips,Ruff/diff/shell/compile. Actual human-UID PTY CLI,
active unexpired-lease installed SIGKILL/restart and live-before-Stop/rearm rejection
witnesses await finalCI. No physical keyboard/GUI mode/host-network/release claim.
See architecture/0083-trusted-mode-selection.md and workspace outputs for live state.

First PR99 head6830b78 CI39107689316 failed restart witness expecting pending; actual Runtime.live_task correctly denies orphaned task after lost descriptors. Preserve denial, require fresh provisioning. Human mode requests now require the same live runtime before creating a challenge. Regression test added; all319localtests pass. Final-head CI still required.

PR99 merged466d0d985c1eeec96853dc58566b14cd7510ecb8 after finalhead80e197c,
CI39111620796 allsuccess/artifact12130479427/53hashes. Current gui-permission-
management work adds a modal bound to acknowledged prompt/task/revision, native09
status and native08 pending requests only. No GUI password/confirmation/rearm.
Initial status validated; uncertain request keeps exact args/key and locks edits;
late closed/stale replies ignored. Full duration clamps300s; scoped status and
terminal review ID/command shown. Existing mode validators split into pure parsers
for both native clients and injected GUI fixtures. Pure model tests324local/28Linux
skips pass; Ruff/diff/shell/compile pass. New synthetic GTK/AT-SPI interaction/
responsiveness/noactivation/no-password screenshot acceptance pending. New
human-permissions.png added to referenced artifact hashes. Final screenshots must
be visually inspected; live GUI/broker integration/physical/release not claimed.
See architecture/0084-gui-permission-management.md and workspace outputs.

PR100 head5fb CI39113742648 passed all jobs and54 artifact hashes, but visual
inspection rejected acceptance: modal screenshot showed only the parent. Sway's
app-wide fullscreen rule also matched the transient. Scope fullscreen to the main
window title and float the transient. Require compositor visible/focused/nonfullscreen
dialog before screenshot. New head CI and actual pixels required before merge.

PR100 b8f620e/run39114543246 failed the new compositor visibility assertion;
no merge. Explicitly leave main fullscreen while the modal exists, restore main
fullscreen/focus on close using GTK. Retain strict visibility assertion and include
full compositor tree on failure. New exact-head VM and pixel acceptance required.

PR100 merged7fd7239 after final38348e3/CI39114869208 all3SUCCESS, artifact12132410882,
54hashes and actual visiblemodal/restoredfullscreen PNGs accepted. The earlier
5fb green-but-parent-only screenshot was rejected; b8 visibility assertion failed.
Postmain39115563601 pending verification. Full original scope remains active.

Current live-human-permissions integration uses production Prompt() defaults after
installed native broker/PAM setup, separate private Sway/runtime, accessible submit,
exact task factory, pending profile and separate human-UID TTY cancel/wrongpassword/
PAM then actual GUI refresh. Root-only harness holds the synthetic guest password;
UI driver receives no password/grant/control socket. Pending/effective PNG hashes
and new broker flag require exact-head CI and actual visual acceptance. No model
call, physical provenance or release completion claim. See ADR0085.

PR101 initial1415a09 CI39115820972 all3SUCCESS/artifact12132955703,54architecture
hashes+2livePNG hashes verified; actual production GUI/PAM workflow passed. Both
pixels viewed; effective status was correct but pending-review text looked current.
Label pending text as acknowledgement history, since status refresh reads profile
not approval record. New final-head CI/artifact/pixels required before merge.

PR101 merged8c311f4, finalcf54f7c/CI39116481401 ALL3SUCCESS, artifact12132817197,
54architecture+2livePNGhashes and actual pending/effective GUI screenshots accepted.
Postmain39130852493 stillrunning lastcheck. Fullv2.1incomplete.

Current native-human-stop-client work: fixed no-arg nonsetuid C /usr/libexec/mano-stop,
Rootlistener+actualRootSCMreply, exactstopped/onecredential/noFDs/truncation/timeouts.
HumanSway Super+Shift+Backspace invokesbinary independentlyofGTK/Python. Ack means
latch+killwrites, NOTprovenprocess exit; VM retaineddrainchecks separately. Private
mountnamespace replyfixture valid/denied/extra/truncated/rights/nonRootsender/timeout.
Productionclient replaces test-onlyPython for actualfrozenbroker/launcher/core/provider
Stop event; wrongUID/extraargs noarmchange; no rearm/passwordUI. See ADR0086.
Exact-headCI/nativecompile/actualVM acceptance required before merge. Disk23GiB89%.

PR102 merged8453cec after finalda19289/CI39131232314 all3SUCCESS/art12138123420;
54hashes+8replycases/actualnativeStop/frozenservices/drain/revocation accepted.
Postmain39131966023 pending verification. Full v2.1 still incomplete.

Current runtime-debian-package work adds an actual unsigned Debian13/amd64/CPython3.13
.deb builder,41 tested dependency versions+PyPI wheel hashes, package-owned vendor
path (core now systemPython), native adapters/systemd/PAM/default-disabled configs,
private sysusers/tmpfiles and Root-TTY existing-human enrollment. Install never
starts services; --start currentboot, --enable explicitpersistent target. No key,
no Rootdefault humanUID, no automatic paid/controller activation. Account collision
preflight, durable no-rebind UID, fixed env/-P Rootwrappers, remove/upgrade Stop and
data retention. Old manual runtime paths firstinstall refused. ADR0087 details scope.

GuestLab now hashes/downloads wheels once and uses vendor target; reusable ci_tty
helper preserves prior actual PTY semantics with explicit guestRoot guard. Full old
broker/core tests retained against package-owned-path architecture. Last guest step
builds twice, verifies payload, disables old lab paths, dpkg installs, actual production
GUI/PAM plus LangGraph mock effect, editedconffile/data/enable-state reinstall and
noauthority resurrection, removal/no data deletion. New runtime-package.json/.deb
artifacts required; exact-headCI/allchecks/full artifact acceptance BEFORE merge.
No local Linux build/install attempted. Local330tests/28Linuxskips/Ruff/shell/compile
pass so far. Packaging remains unaccepted until actual CI passes.

PR103 merged37f7fde after final29fa56f/CI39133946798 ALL3SUCCESS/art12138669855;
54architecture+2packagedGUI hashes and9.54MBprototype1.deb accepted. Two sameguest
builds matched,1716payloadfilesverified; package install/GUI/PAM/mock/reinstall/
remove passed. Postmain39134831166 pendingverification. Fullgoal stillACTIVE.

Current clean-debian-runtime-reboot work preserves pristine verifiedcloudbase before
lab preparation, then separate freshoverlay boot with only genericCIlogin/marker.
Only.deb+explicittestwhitelist enter; no src/labconfig/externalvendor. Apt install
--no-install-recommends then driver-onlypyatspi. Prototype2 explicitlydependsPAM
modules/CAcerts. Genericloginlab UID1000 (no mano-human account), fixedgroup via
RootTTYenrollment --enable. Actualunmodified packagedSway/Prompt wrapper noobserver/
PYTHONPATH override; AT-SPIreadsvisibleIDs, nativeRootview/PAM cancels+wrongpass+success,
actualmockfileeffect. Prebootunusedunrevoked/unexpiredexactgrant savedprivateRoot0600
NEVERexported. Realpoweroff+bootIDchange: targetandStopmustactivatewithoutsetup,
oldprompt/grant replaydenied andgrantrevoked whiledeadlinefuture, taskdataretained;
newGUI/PAM/mocktask+nativeStop.900spreboot/120spostlease excludesexpiryconfound.
Pristineimagehashunchanged, noVMimage/key uploaded. Freshheadlessmanualuserlaunch,
NOTphysical/displaymanager/8GB/livepaid/signedimage proof. Exact-headCI/artifacts
and new before/after screenshots required before merge. See ADR0088.

PR104 initial79a4b94/CI39136499881 FAILED during ordinary-login TTY cancellation.
Freshimage/packageAPTinstall/UI/nativepending succeeded. ci_tty helper clearedall
supplementarygroups, previouslyhiddenbecause mano-human primarygroup=socketgroup;
normalLab's human socket membership is supplementary. ReplaceinheritedRootgroups
with os.initgroups(targetname,primarygid) then dropgid/uid, matching actuallogin.
Addreturncode/permission-error-only diagnostics, no nonce/password/transcript dump.
Keepallsocket/PAM/boot/grant checks; newheadCIrequired, failedheadunmerged.

PR104 8954dd8/CI39137448469 ALL3SUCCESS/art12140284002; functionalfresh/reboot,
54architecture+package+6GUI hashes verified. GenericUID1000/targetboot/noOldGrant
whenfuturedeadline/data/newtask/nativeStop passed. VisualQA REJECTED postbootpending
PNG: partiallydrawn/missingletters/digits; other3stockstatesclear. Capture nowwaits1s
then requiresconsecutiveidenticalPNGframes (8sbounded), unchangedunmodifiedapp/
allfunctionalassertions. NewexactheadCI/pixelsrequired;8954notmerged.

PR10495b40fb/CI39138555266 ALL3SUCCESS/art12141131665, fullfunctional/boot/hashes
verified, but visualQA REJECTED stockafterpending +preparedpending persistentmissing
glyphs evenidenticalframes. Notcapturetiming. OfficialGTK4.18 sourcegskrenderer.c
full-redraw skips render-node diff; wlroots0.18.2scene fullrerender skipsdamage.
Nowallhumanheadlessharnesses setGSK_DEBUG=full-redraw andWLR_SCENE_DEBUG_DAMAGE=rerender
onlyalongsideexistingCairo/Pixmanprofile. No productconfig/permissions/GUI observer
changes. Reportexplicitrenderingprofile+incrementalvisualacceptanceFalse; no physical/
defaultbackend claim. NewheadCI/pixelsrequired;95b NOTmerged. PrimarysourceslinksADR88.

Current work: isolated-coding-delegates, based on accepted PR111 main c80db7e.
PR111 post-main CI39211933892 completed SUCCESS. ADR0096 documents optional
Antigravity1.4.2/Codex0.163.0 fixed public PTY SDK, sealed synthetic homes and
hash-pinned CI-only installation. Local404tests passed/46Linux skips; Ruff,
compileall, shell and diff checks passed. Actual new VM evidence still pending;
no authenticated coding/paid calls/actual authenticated soft-denial claims.
Disk18GiB free91%; vendor binaries/VM downloads remain CI-only. Goal ACTIVE.

PR112 remains draft/unaccepted. Actual Antigravity1.4.2 ignores our malformed
settings until authentication, so prior vendor-parse expectation failed. Added
strict adapter-side JSON/default-policy validation before launch and an actual
semantic config-consumption probe using documented modelProvider=gemini with NO
GEMINI_API_KEY: must reject missing key, not OAuth. Codex vendor malformed-TOML
probe retained. Collect partial diagnostics and independent public native-PAM SDK
version witnesses before rejecting configuration failure. No failed head merged,
no key/sign-in/paid call. All existing25 flags +2 delegate flags, full artifact and
pixel gates remain required. Full v2.1 goal ACTIVE; physical/authenticated work
unproved. Vendor binaries/VM work CI-only; latest disk17GiBfree92% warning.

Current feature: approved-execution-feedback, based on accepted PR112 main6289d85.
ADR0097 adds optional explicit feedback_action_id, complete bounded UTF8 failure
snapshot and broker custody reconciliation before disclosure approval/authorize/
model attempt. Separate native PAM model.plan consent binds exact readable logs;
provider frames them as untrusted user data without action/boot IDs or duplicate
base64. Default planner sends no feedback. Strict provider proposals still need
separate effect grants. Installed VM probe and unit/recorded-response tests added;
no live provider call or full repair claim. Full CI/artifact acceptance pending.

Current sandboxed-mcp-discovery based on accepted PR113 mainceff547. Postmain
CI39257600583 verifiedSUCCESS. ADR0098 adds explicit mcp.discover/nativePAM,
modern2026-07-28 metadata-only pipes, readonlyworkspace aliases, untrusted schemas,
fixed one-process/no callback/retry/invocation, common capacity/Rootcgroup/Stop,
proposal-bound public SDK and durable bounded output. RUN-only model feedback
explicitly rejects MCP outcomes. Hash-pinned officialPythonSDK2.3.0 installed only
in guardedCIguest; real interoperability/hostile/EOF/deadline/frozenStop witnesses
added but UNACCEPTED until actual final-head CI/artifacts/pixels. FullgoalACTIVE.
Disk18GiBfree91%warning; no localVM/vendor/model downloads/deletion.

PR114 initialea2abd6/CI39260334290 FAILED at MCPStop harness startup: existing
recordedRUN+publicPTY alreadyoccupied bothpublicjobslots; MCPcorrectlyqueued.
ActualofficialSDK+allhostilecases reached/passed beforelaterharnessfailure; no
fullacceptance/merge. MoveMCPStop to replacementlauncher RUN+MCP pair (two slots),
freezeMCPandbothauthorities, actualnativeCStop/drain/unknown andidentifieddetached
serverchild. KeeporiginalRUN+PTYStop regressionunchanged; noquota/guardweakening.
Addexplicitmcp-discovery.json to evidence transfer. NewheadCI/artifactsrequired.

PR114 mergedbc4d67b after head0ba2d74/CI39261999490 ALL3SUCCESS/art12190909682,
54hashes/31flags/package/freshstock-reboot/all6rawGUI individuallyaccepted.
Subsequentwitnessreview foundcommandline-onlychildidentity canmatchbwrapwrapper.
Wholeobserved5-PIDgroupdrained, but actualPythonchildidentityrequiresstrongerproof.
Immediatefollowup pins childANDparent /proc/exe tosamePython3interpreter, samecode
argv andownSID; recordsparent/executable/SID. ExactnewheadCI/artifactsrequiredbefore
accepting refinedidentity. Noquota/Stop/productauthoritychange. FullgoalACTIVE.

Current git-workspace-checkpoints based on acceptedPR115 main d0e0bb9; postmain
39266836249 verifiedSUCCESS. ADR0099 adds fullboundedroot sourcecheckpoint Git
objects/archive inprivateSQLite, explicitnativePAM/caller-task-boot identity,
readonlydescriptorwalk/sealedreads/Stop/deadline checks, sourceidentityrechecks,
limits/retention/freespace, scopedSDKexport and noGit/config/hooks/filterexecution.
NativeGitstrictfsck/byte/mode recovery and actualPAM/SDK/symlink/replay/Stop pending
approvalprobes added. Capture is NOTatomicFSsnapshot or in-place restore; latter
remains nextintegration. Existing mano_core.checkpoints.Session was preserved;
newSDK is mano_core.workspace_checkpoints. Local/actualCI acceptance stillrequired.
FullgoalACTIVE; latestdisk28GiBfree86%, allVM/buildsremainremote.

Current workspace-checkpoint-restore uncommitted branch basedonPR116a03ed81;
postmain39374700360 verifiedSUCCESS. NewboundedcanonicalGitdecoder, privatebefore
layoutcustody, explicitnativePAM5referencehashrestoreargs/protectedoperationview,
asynconechunk/operationpertickRestorer, fixednonRootnativehelpers forbinary/modes/
dirs/delete, per-stepintent/ack/unknownjournal, finalseparatecapturechecks and
proposal-bound SDK. Local440testsPASS/46Linuxskips; actualnewnative/guestproofnotrun.
NoPR117yet. Seeoutputs/CONTINUATION.md forprecisewipandrequirednativeCI/Stoptests.
FullversionACTIVE; noatomicFS/current-content/crossboot-nativeproofclaim.

Approved-source-restoration integration now includes guardedCI probes for native
PAM/publicSDK binary/exec/dir-file/deletion restore, stale-before refusal, different
TaskUID sameHumanfreshconsent transfer with oldsource directreaddenied, and frozen
broker mid-restore nativeStop/partialunknown/hash/restart/no-replay. ADR0100.
Local441testsPASS/46Linuxskips,Ruff/compile/shell/diffPASS; no actualnewguestproofyet.
ActualpoweroffSourceRestore remainsUNPROVEN (olderboot provenanceunitonly). GoalACTIVE.

PR117 d599a81/CI39377915649 FAILED innewStopobserver: attemptedjournalrownotyet
createdwhileactionacknowledged/queued. PositiveactualnativePAMrestore/stalerefusal/
differentUIDcross-taskconsentreached/passed beforeharnessfailure. Observernowwaits
forrealattemptrow (terminalnorecordstillfails), then>=1doneStep/executing/freeze.
FixCIidentitycleanupcallbacktoappendaccountNAME perexistingcleanupcontract, not
TaskIdentityobject. NoStopassertion/quota/permissionweakening; newheadCIrequired.

PR117 accepted and merged47d24b04824ace098095bcf674cda6a5de6e6082 after finalhead
887e7f0/CI39378958394 attempt2 ALL3SUCCESS/artifact12245745038. Accepted54hashes/
38flags/package/pristinestockrealreboot/all6freshrawGUI; local442PASS/46Linuxskips.
Actual native PAM binary/mode/dir/delete restore, stale refusal, crossTaskUID
consent and partial nativeStop/restart/no-replay proved. Actualpoweroff restore
not yet proved. Followup ADR0101 extends existing stock before/after driver:
installed public SDK capture and native PAM before real QEMU poweroff, old-source
read/grant denial after boot, new TaskUID/fresh native PAM restore, independent
exact source checks and replay-canary. Root seeds/observes only nonsecret fixture;
Root never restores or modifies broker journal. CI/artifact/pixel acceptance
required. Full phases0–7 ACTIVE/incomplete; disk27GiBfree87%.

PR118 remains draft/unmerged. First3edfa22 and diagnosticc1786ae heads failed
stock sourcecheckpoint with unknown/PermissionError errno13. Head65f6586 creates
fixture through approved task RUN, confirms taskUID ownership; same failure
stack execute/capture/walk/walk proves nested traversal. Current followup adds
bounded function+line diagnostic and fixed nonsecret fixture permission/ACL
record, without chmod/chown or service policy relaxation. Still need exact cause,
targeted fix and actualfinalheadCI/artifact/pixelacceptance. Local443PASS/46skips.
Root only observes and simulates postcaptureedit, neverperformsrestore. PR117
postmerge39381340108 attempt2 verifiedSUCCESS; firstOffice timeout preserved.

PR118 integration cause found: actual core creates task-owned0700 .mano-agent
insideworkspace, while sourcewalk excludedonly.git/privateWRITE. Root'spermission
record proved normalnested source readable; exactwalk72failed openingprivate
runtimejournal. ADR0102 adds explicit3rd exclusion/privateentrylayoutpreservation,
nativeleafguard, and historical-only legacy2scope parsing for savedcustody. New
wireproposals/approvals/execution stillrequire current3scope. Legacyreceipt/request
scope mustmatch; decoderrejectsnowreservedruntimepaths. Nojournalchmod/chown or
servicepolicyrelaxation. Local444PASS/46skips. Nativepackagedrealpowerofftest now
assertsbrokerdeniedprivatejournalbeforecapture and preservesprivatebytes/UID/700
throughrestore. Need actualnewheadCI/artifacts/all6pixels beforeacceptance/merge.
