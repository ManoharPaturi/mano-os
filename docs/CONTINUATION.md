## Independent Broker-death interruption fixture (native validation pending)

The actual-dpkg fixture now has two faults: native Stop, and pinned SIGKILL of
frozen Broker while Root controller/dpkg/launcher stay frozen. The second must
drain via production BindsTo without nativeStopgeneration changing, preserve
unknown after Broker restart, and refuse replay. Both use explicit CI-admin
same-signed-sl repair/purge plus typedRootTTY acknowledgement; neither claims
product automatic repair or all-effects reversal. New artifact package-apply-lost-
reply.json exported. Successful-commit reply loss remains separately unverified.

## Additional packaged apply fixture (native acceptance pending)

Current local follow-up requires actual --unpack argv (not any dpkg query),
exports unknown/intent and full database comparison for independent acceptance,
and tolerates only helpers that exit and leave final cgroup membership before
freeze. New probe_packaged_apply.py uses installed SDK/native human TTY/PAM
(including cancellation), signed sl apply on btrfs after real .deb install, before
existing reinstall/removal checks. Retires only checkpoint metadata explicitly;
never deletes snapshots or claims automatic repair/all-effects rollback.
New native CI is mandatory; local checks do not establish these runtime claims.

## PR134 payload and actual-dpkg interruption fixtures (2026-10-23)

Base implementation bd7aa20 CI39991219242 completed all three jobs SUCCESS;
independent full acceptance54hashes/45flags+approved apply passed. Six fresh GUI
originals and four numeric crops viewed; after-stock pending clips final digit.
Receipts in workspace outputs/pr134-full-acceptance.json and acceptance-pr134/.
New fixture adds signed archive vs installed cowsay bytes/mode/UID comparison.
New scripts/probe_package_apply_stop.py (CI-only, not shipped) observes real dpkg,
freezes Root package controller/all members+Broker/launcher, invokes native Stop,
requires drained domain/dead pidfds, restart unknown/no replay, explicit narrow
CI-admin signed sl repair/purge, and Root-TTY acknowledge/metadata retirement.
No product automatic repair or all-effects-reversed claim. Controller reply lost
with Stop is distinct from independent lost reply. Native validation pending for
these new changes; PR remains draft. Full v2.1 phases0-7 remain active/incomplete.

# CI8GiB fixture guard correction

9903ebb run39901316581 failed during migration, before Root/APT execution.
Initial normal Snapper warning was misleading: artifact snapper.txt/mounts.json/
memory-before.txt prove exact sentinel restore and guest setup passed. Actual
failure: migrate_btrfs_root.sh exact blank-device guard still expected6442450944
bytes after image grew8GiB. Change guard to exact8589934592; keepblank/unmounted/
disposable checks. Rawlogoutputs/pr134-8g-native-failure.log; smallartifact
pr134-8g-prepare-failure.zip. No recoveryprobe or productreserve relaxation.
PR123 MERGED65fdfc0; postmain39902326558 live. Merge origin/main CODEOWNERS into
134 before nextCI. Fullapplynativevalidation still pending, remainsDRAFT.

# Latest: CI capacity denial identified; approved-apply evidence expanded

PR134 remains DRAFT. bef95ec run39899264546 failed BEFORE acquisition/install:
Root space-reserve diagnostic available2101223424 < required2147599228 bytes.
No layout-policy or reserve bypass. Disposable CI root qcow2 grows6G->8G so
retained recovery snapshots and unchanged2GiB reserve fit. No local VM assets.
Previous eccde72 APT initialization correction remains native-unproven because
this capacity denial occurs first. Raw log outputs/pr134-space-diagnostic-failure.log.

New fixture captures/exports full raw dpkg databases before/after approved apply
and the exact approved request. Outside independent checker compares all package
states/versions, plan/request digests, bounded acquisition and namespace witnesses.
Synthetic checker positive+6 altered-case negatives passed; NOT native proof.
Universal acceptance now has --package-apply; new proof/Stop/restart/lostack and
packaged lifecycle still required before merge. All prior gates remain.

PR123 CODEOWNERS explicitly authorized for admin review override by user; fresh
head453b01b7d72121245aa27360d6bdd5848b666f64 CI39899110758 qualitySUCCESS,
security-lab live. Poll same handle; do not merge until all CI and artifacts pass.
Base/main542b926cd67c9f4fba56c20bd09b2b845d676ea1 contains external README PR135.
No reviewer notifications or protection changes. Latest disk25GiB/88%;3untracked
unrelated duplicate files preserved. Goal active, full original scope incomplete.

--- Historical implementation notes ---

# Native apply fixture now wired; draft remains unvalidated

Local534tests48Linuxskips +staticchecks pass after wiring the actual btrfs
publicSDK/nativePAM/Root service fixture. Prior draft head78ad23b CI39891652319
qualitySUCCESS (including new native C guard compilation); security-lab live.
New fixture goes immediately after the existing readonly package plan witness.
It shares that existing task/resource to avoid increasing live-resource quotas.
Operator Root controlling-PTY acknowledges fixtureunknown14 against originalA,
archives coherentB metadata without snapshot deletion, then forecasts cowsay,
preserves one fixture cache archive in a holdingdir to force bounded real HTTPS,
rejects private-socket untrustedUID +forecastgrant +wrongPAMpassword, obtainsfresh
nativePAM apply approval, runspublicSDK, requiresactualinstallation/newcatalog/
namespaceboundary/emptyRootStopdomain/scopedreceipt/replay-noeffect/unknownkept.

Source fixture now compiles/installs guard+new private socket/unit and cleansonly
those fixture-owned resources. Parent unit cannot add a mount within /usr because
recovery.layout rejects split critical trees; module capability remains absent,
and child native guard denies module syscalls. Archive offsets reset beforebwrap.
Acquisition receipt nowrecords actual network-used/downloadedSHA/bytes. Rootworker
host workspaces masked. This native proof has NOT run on the new head yet.
DO NOT merge or claim validated privileged execution before it and allgatespass.

# Current: approved package apply integration DRAFT

Base/main800b72a1f29340495d5c0add3aeda2fd9ff25d89 PR133; exact post-main
run39830257817 VERIFIED all3SUCCESS. Branch feat/approved-package-apply contains
new protocol/native approval + Broker scheduler + private Root transaction +
fixed APT worker/native seccomp guard + operator acknowledgement/retirement.
ADR0116 explicitly lists native validation still required. Local534tests with
48Linux-only skips and Ruff/compile/shell/diff pass. Native C not compiled or
executed on Mac; all Root/VM execution remains CI-only. No paid/key operations.

This branch must stay DRAFT/unmerged until real btrfs Broker/PAM/Root positive,
namespace/Stop/cancel/lost-ack/packaging evidence is accepted. Do not equate baseline
CI or unit mocks with privileged execution proof. No new Root grant issuer:
Broker is trusted authority, fresh separate native apply approval mandatory.
No model paths/commands/env, no profile auto-approval, no retry on unknown.

Native fixture integration next: probe_broker_service.py runs AFTER actual Root
recovery, so btrfs Snapper storage already exists but unknown attempt14 blocks
new effects. In the existing disposable Root controlling-PTY harness explicitly
acknowledge attempt14 against original checkpointA (preserve unknown), explicitly
retire coherent checkpointB metadata to free an active slot (retain snapshot),
then run the real public SDK forecast/fresh native PAM apply of cowsay and verify
full effects/new catalog/scoped receipt/replay denial. Existing readonly forecast
witnesses must keep their no-effect claims. Use a separate apply witness. Compile
and install the new guard and socket/unit in the existing source native fixture;
clean only those fixture-owned files. Keep all previous Root recovery artifacts
as historical observations. Do not delete/reset attempts or relax quota/CI.

Three unrelated duplicate-suffix ' 2' files remain untracked; stage only intended
paths. No Root work or VM/model downloads on Mac. Full goal ACTIVE/incomplete.

## Historical notes (superseded where above differs)

# PR133 native dependency-set correction

Initial b911bf3 CI39825969416 failed before effects: fixture assumed exactly one
sl change, but real APT solution contains dependencies. Raw log preserved in
outputs/pr133-first-ci-failure.log. Fixture now requires the full bounded signed
install solution, finds each exact archive by SHA256 and length, and installs all
approved archives. No omitted dependencies or postcondition relaxation. Audit and
independent acceptance compare every approved transition and all unrelated states.
CI rerun on new head pending. No merge on failed initial head.

# Current: durable package database postconditions

Main23c41d9e1129e896c564a667fbb5b626b0f743af includes PR132. Exact post-main
run39821675553 VERIFIED all3SUCCESS; save authoritative receipt in outputs.
Branch feat/package-postconditions adds private Root complete_locked over the
owned backend-held scope, original request/current boot/RO checkpoint, clean dpkg
journal and exact before/after database transitions. Verified history allows a
new separately approved attempt ID; unknown/partial/corrupt outcomes stay blocked.
Historical receipts never authorize execution or prove state after rollback.

Native guarded CI now uses a real signed sl forecast/intent/controlled dpkg commit,
rejects completion before effect/during handoff, verifies postconditions, then
runs existing interrupted-dpkg fixture. Real recovery must preserve both receipts
while restoring pre-sl status. Existing unknown attempt remains first (id14),
verified id16 second. Native CI pending. ADR0115; full apply integration still
unfinished, not redefined around these prerequisites. Keep all prior gates.
No Root/VM experiments on Mac, no paid-provider/key operations or deletions.
Three unrelated duplicate-suffix files remain untracked; selective stage only.

## Historical notes (superseded where above differs)

# Current work: live APT package marks

Main PR131 merged at febab37bd4ac6811f3d8055b8cbd84790bb32bc4 after all three
exact-head CI jobs and full artifact/GUI acceptance. Post-main run 39816404372
is live; poll that same run to terminal. Review override was user-authorized;
branch protection and CI remain required. Three unrelated duplicate-suffix
untracked files are preserved; stage only named intended paths.

Branch fix/package-mark-freshness closes a live-input freshness gap before apply:
APT automatic/manual package marks now bind catalog identity by presence, size,
and SHA256. Creation rechecks them; existing catalog admission compares the live
input, so approval/review/Root resolution/archive custody reject stale marks.
Disposable CI changes marks without changing dpkg status, rejects the old plan,
restores exact bytes and verifies admission again. ADR0114. Native CI pending.

Full privileged apply, fresh native approval, isolated executor, acquisition,
space admission, postconditions and durable recovery remain unfinished. Broker
is the trusted grant authority; no parallel Root policy issuer. All Root and VM
experiments remain CI-only. No provider/key experiments or local VM downloads.
Disk last checked 29 GiB free / 86%; no cleanup. Goal remains active.

## Historical notes (superseded where above differs)

# Current work: coherent package transaction scope

Main2e1eb27a3bfe0bcc65758d8d363f903bf4f565c8 includesmergedPR130 sealedarchives
(accepted621c6a7CI39707159259/all45flags/54hashes/6freshGUI). Postmain130
CI39804921537 verifiedSUCCESS exact2e1eb27 (APIrun_attempt1); savefinalreceipt.
Branchfeat/coherent-package-transaction addsprocess/thread-ownedPackageLocks:
frontend/APTlocksretained, backendtemporarilyreleasedfordpkgwithdocumented
DPKG_FRONTEND_LOCKED=1, reacquirebeforeproceeding, failclosedifbusy. create_locked
andbegin_locked requireactiveownedbackend-heldscope; CLIforegroundRootguards
preserved. Publicwrappersretainownscopes. No nestedlocking/reopeningbackendfds.
NativeCIcreatescoherentcheckpoint+intent afterseparatesignedslfixture, immediately
beforecontrolledunsigneddpkg/postinst underonescope. OtherPIDbackendacquiremust
workbeforechild, directdpkgdeniedfrontend, operationsdeniedduringhandoff, /proc/locks
pinsfrontenddriver/backendactualdpkgPID, backendreacquiredafterSIGKILL. Original
RootTTYcheckpointremainsrecoverytarget; unknownintentrefersadditionalcheckpoint,
preservedacrossrealboot. Architectureauditrequiresnewproof. ADR0113.
Local505tests/48Linuxskips+Ruff/compile/shell/diffpass; nativeCI/acceptancepending.
Spec'strustedbrokerispolicyauthority: distinctfreshnativePAMapplycapability
throughprotectedexistingchannel, notanewparallelRootpolicy/grantissuer. Roothelper
willauthenticateBrokerpeerandtypedrequest; existingforecast/profilecannotapply.
Fullprivilegedexecutor/isolation/acquisition/space/postconditions/Stop/boot still
unfinished. Broaderliveprovider/authenticatedcoding/apps/hardware/physical8GB/
input/signedOSreleasealsoopen. GoalACTIVE/incomplete. No RootMac/localVM/paid/
secrets/agentmessages/deletions. Preserve3untracked' 2'files, selectivestageonly.

Historicalnotesbelow; outputs/CONTINUATION.md currentruntimehandoff.

# Current work: verified package archive custody

Mainb755d910b670e256d27f4e9506020adcb417a55d containsmergedPR129 Rootresolution
(accepted456b1f1CI39701965902/all44flags/54hashes/6freshGUI). Postmain129
CI39704065843 currentlyrunning; pollSAMErununtilterminal.
Branchfeat/verified-package-archives addsRoot-only verified_archives context over
freshcurrent_plan/locks: fixedRootAPTcache, boundedscan, exactsignedcatalogSHA/size,
sealedmemfdcopies, dpkg-deb name/version/archmatch, sourceidentityrecheck, nativeStop
checks, closeFDsonexit. No download/install/grant/servicelistener. Admission64MiB/
archive128MiBtotal256MiBscan256entries; missingarchivesfailclosed. Peakinstallspace
unknown. Finalproductauthorizedacquisition/spacepolicy stillrequired (notanoffline
onlyscope). Rootchildren remaintrusted/unconfined, notbrokerexposed. ADR0112.
NativeCI fixtureexplicitlyprefetchesfixedversionsoutsideproductcode, thenchecks
realSHA/metadata/seals/Rootwrite+truncatedenial/cachemutationunchangedsealedbytes,
corrupt/symlink/missingdenials/FDclosure/noFDleak/dpkgstatusunchanged. New45thflag.
Local500tests/48Linuxskips + Ruff/compile/shell/diffpassed; twoactualmemfdtestsrun
LinuxCIwithoutRoot. Native/artifact/6freshGUI stillpending beforeanymerge.
Preserve3untracked ' 2'files; selectivecommitonly. Disk25GiBfree88%.
Fulloriginalv2.1ACTIVE/incomplete: exactnativePAMapply, verifiedauthorizedacquisition,
space/checkpoint/commit, constrainedRootStopdomainexecutor, verifiedoutcomes/
registryrefresh/recovery, liveprovider/authenticatedcoding/apps/hardware,
physical8GB/input,signedOSrelease. No RootMac/paid/secrets/localVM/deletions.

Historical notesbelow; outputs/CONTINUATION.md iscurrentruntimehandoff.

# Current work: locked Root package re-resolution

Main4a85548a19c7aa72fc62105db271fdfb7ef953ff includes merged PR128 attemptcustody
(accepted488tests/46skips, exact7d50452CI39697785239/all43flags/54hashes/
all6freshGUI accepted). Postmain128CI39699941820 currentlyrunning; pollSAMErun.
Branchfeat/root-package-resolution adds LinuxRoot-only current_plan context:
fulltypedforecast, supportedbtrfs, nativeStop, coherentpackage locks, currentRoot
catalog/status/index/keyring checks, freshfixedPythonAPT calculation with explicit
Rootownedsourcepath/clearedambientconfig, fullresult equality, finalcustody/Stop
recheck, lockscopeheldthroughyield. SharedreadonlyAPTalgorithm; normalTaskCLI
stillrefusesRoot/fixedmount/sandbox. No publicendpoint/service/grant/apply added.
Rootchild currentlytrusted/unconfined; no cancellation/frozenStopdomain claim.
Must enforceprocess/capability/IPC/resource/Stop isolation beforebrokerexposure.
ADR0111. CI addsactualRootdependency/noopresolution, deltadenial, actualotherPID
lockdenial, hostileambientAPT_CONFIG, stale/corruptinputs andlatchedStop. Stock
installedmodule before/afterboot mustdenyext4 andunprivilegedcaller. New44thflag.
Local495tests/46Linuxskips + Ruff/compile/shell/diff pass. Native/artifact/6freshGUI
pending. Preserve3untracked ' 2'files, selectivecommitonly. Disk25GiBfree88%.
Fullv2.1active/incomplete: exactnativePAMapply, verifiedarchives/download+space,
same-scopecheckpoint/commit, realRootStopexecutor/postconditions/reconciliation,
liveprovider/authenticatedcoding, apps/hardware, physical8GB/input,signedrelease.

Historical notes below; outputs/CONTINUATION.md is currentruntimehandoff.

# Current work: package-attempt custody

Main 65e9661c425c5a5179e58dccb91ebb02a6dae64e includes merged PR127 with
accepted native/installed Root Stop evidence. Its post-main CI39696070999 is
still running; poll the same run to terminal, do not restart on observer timeout.
Branch feat/package-attempt-journal adds Root-private immutable write-ahead
intent under the persistent snapshot subvolume, bound to a fresh current-boot
checkpoint/current layout/status. Exclusive ID reservation and fsync precede
return. Unknown outcomes block new IDs; no retry, clear, success, CLI, service,
public endpoint or apply authority is added. Partial/corrupt custody fails closed.
Nonreentrant package-manager lock scope prevents POSIX-lock release by nesting.
CI records intent before controlled package changes, requires duplicate denial
and outer-lock preservation, reconciles after actual interrupted dpkg, then
requires identical custody after real clean recovery-clone boot. ADR0110.
Local 488 tests/46 Linux skips plus Ruff/compile/shell/diff passed. New native
CI and complete artifact/six-original-GUI acceptance still required before merge.
Disk 25GiB free/88%. Three unrelated untracked files with suffix ' 2' appeared;
preserve them and commit only this change's explicit paths. No local VM/model
assets, Root experiments on Mac, reviewer requests or silent deletion.
Full original v2.1 goal remains ACTIVE/incomplete: fresh native-PAM apply consent,
current independent Root resolution, archives/space, same-scope checkpoint and
commit, actual execution inside Stop domain, postconditions/service reconciliation,
live provider/authenticated coding, apps/hardware, physical8GB/input, signed release.

Historical notes below; outputs/CONTINUATION.md is the current runtime handoff.

# Current work: privileged package Stop domain

Main3a860c5e87bea2ca60e36284edd0913755c0047b includes package-install-review
(PR126; GitHub also auto-marked original125 merged). Postmain126 CI39630028188
nowverifiedSUCCESS onexactmain (outputs/pr126-postmerge-ci.json).
Currentbranchfeat/privileged-package-stop-domain adds emptyreserved
mano-package.slice and extends nativeCStop/rearm to wholefixedRootdomain. Stopd
requiresnewSlice, Rootcapabilitysetunchangedempty. Runtime disable/removal stops
newSlice. No packageexecutor/socket/grant/permission/installer added. ADR0109.
NativeCIprobe verifies RootUID0parent+detachedsessionchild, CapEff0/NNP1/cgroupRO
writeEROFS, pidfd/kernelT forRootpair+broker+launcher, populateddomainnativePAM
rearmrefusal, nativehumanStopdrain/Rootpidfdexit/stablecanary/controllersstillT,
staleviewrefusal/freshPAMrearm/noRootrestart/survivingnativeStopdaemon+Rootobserver.
Repeat sameprobe against installed runtime afterstockactualreboot, allowedCI
driveronly copied. RuntimeMax60/read-onlysystem/privateIPC/network forfixture.
No productionmaintainerscripts/fullyprivilegedhostileRoot/kernelDstate proof;
fullRootapply/freshconsent/Rootreresolve/archives/space/snapshot/crashremaining.
Local478tests/46Linuxskips+Ruff/compile/shell/diff pass. NewnativeCcompile/probe/
43rdflag/artifacts/sixfreshGUI acceptance stillpending. Disk17GiBfree92% warning,
no silentdeletion/localVM/modeldownloads. Fullv2.1 goalACTIVE/incomplete.

Older historical notes below; outputs/CONTINUATION.md is currentruntimehandoff.

# Current work: exact package installation review

PR122 and124 merged with explicit user-authorized admin review bypass only; all
exact-head CI/artifact/GUI gates preserved. Main5f07825decbce07c5e02e68429adf568abda9873.
Postmain124CI39620541362 still running at last poll; poll SAMErun untilterminal.
Current branch feat/package-install-review adds read-only package_install_review
for owned current task/resource/action and exact durable forecast digest, current
catalog checks, short lifetime and boot/epoch/Stop binding. SDK validatesresponse.
No installation/Rootresolution/locks/space reservation/grant/action/process/new
apply authority. Explicit false fields and fresh_apply_approval_required=true.
ADR0108. Local478tests run/46Linuxskips +staticpass; final native CI pending.
Native/publicSDK and installedstockbefore/after clients nowreview forecasts,
with wrongscope/hash/extra/stalecatalog denials and existing no-effect/Stop gates.
42ndflag package_install_review_owned_digest_and_stale_denials added. Fullv2.1
remains incomplete. Disk22GiBfree90%, no silentdeletion/localVM/modeldownloads.

Older historical notes below. outputs/CONTINUATION.md is runtimehandoff.

# Current PR124 integration after PR122 merge

Repository We-build-AI-Stuff/mano-os. User explicitly authorized admin review
bypass for PR122 and124, with merge commits and all CI gates retained. No branch
protection or review policy changed. PR122 merged3190ce53454e2d286c21268d0c69193e572f1e00
after exacthead5df915a4a9baab31296e2b5328b73d162da11f42/all3CI39529689174,
artifact12315019184/54hashes/41flags and six actual original GUI views accepted.
Real controlled unsigned dpkg interruption, held-lock recovery refusal, clean
recovery boot and changed-source journal/payload preservation proved; no product
Stop, production maintainer-script or agent install-authority claim.

PR124 preintegration6450d34c74cd1e86ec13555b245db8319d653d56 passed all3CI39603741295,
artifact12347793789/54hashes/41flags/final resolution checks and six originals.
Requested rows now describe final APT resolution and must match changes; new
installs classified by absent installed version before APT upgrade flags.

Merge latest main into PR124; only continuation notes conflicted, now reconciled.
All final combined-head CI/artifact/6freshGUI acceptance must pass again before
admin merge with exact expected head. Postmain122 run39617543369 queued; verify
terminal status. Keep protected rules active. ADR0106/0107 scopes preserved.
Disk21GiBfree90%, warn/no silentdeletion/localVM/modeldownloads. Full v2.1 remains
incomplete: privileged packageapply/productionStop/reconciliation, liveprovider/
authenticatedcoding, physical8GB/input, broadapps/hardware and signedOS/release.

Older historical entries below; outputs/CONTINUATION.md is runtime handoff.

# Current PR121 work — dirty live package journal recovery

PR120 merged8a787c6ccc3cb66111d51aba64a6d127439e96d8 after exacthead7ad2f45,
CI39524189782 ALLSUCCESS artifact12313486648 54hashes/41flags/newRootproof/all6GUI
accepted. Postmain39526482746 still running; inspect terminal before green claim.
Branch fix/dirty-package-recovery: prepare-boot may recover a verified clean saved
snapshot while live journal is dirty, with all package-manager locks held. Create
still refuses dirty state. Reject dirty saved snapshot, preserve live journal,
no parsing/repair/delete/overwrite/new agent authority. ADR0105. CI explicit dirty
journal fixture after real successful sl change, actual_dpkg_interruption=false;
newboot clean exactbeforestate, changedsource retains journalhash. Actual dpkg
interruption/agentapply still unproved. 467localtests/46Linuxskips +staticchecks pass.
Native finalheadCI pending. Disk19GiBfree91% warning sent, no userdata deletion or
localVM/modeldownloads. Full v2.1 phases0–7 goal ACTIVE/incomplete.

Older notes below are historical, current outputs/CONTINUATION.md is authoritative.

PR120 MCP observer additionally refreshes membership, pidfd-freezes and waits kernelT. Required server/child/broker/launcher must all be present; only exited setup processes tolerated. Actualnative acceptance pending; no production Stop changes.

PR120 run39522700440 failed pre-existing MCP Stop observer PID vanished before /proc/exe. Bounded retry only exited-process races, exact live server/parent/session/cgroup criteria unchanged. 465 local tests/46 skips; final native acceptance pending.

PR120 CI39471840714 failed stock baseline because installed-helper ext4 denial ran before install. Move to installed before-reboot phase, preserve pristine baseline. Root recovery and installed package stages reached; exact new final-head proof still required. Disk18GiB91% warning sent; no large localdownloads/deletion.

PR120 CI39470715507 failed first lock-negative without denial transcript. Fix invalid os.tcgetsid API -> documented tcgetpgrp/getpgrp foreground check. Regression full guard branch; preserve denial/early failure artifacts. 465 local tests/46 skips; actual native acceptance pending.

# Current PR120 work — Root package recovery prerequisite

PR119 merged cfe944709e2ee04ef02ec3adfc98f7d19550a0d8 after exacthead91319f1,
CI39456370571/54hashes/41flags/all6freshrawGUI accepted. Postmain39459074461 SUCCESS.
New branch feat/root-package-recovery adds Root-terminal mano-package-recovery
create/prepare-boot: private Snapper read-only snapshot and fixed @recovery clone,
Root package-manager locks, mount/subvolume/space/retention/config/fstab checks.
No agent install permission, public endpoint, auto boot/delete/overwrite. ADR0104.
CI extends real pre-package recovery to signed sl install and actual recoveryboot,
plus installed .deb btrfs positive/pristine ext4 refusal. Source root preserved.
464 localtests/46Linux skips pass; all static checks pass. New native CI pending.
Disk21GiBfree90%; warning sent, no local VM/model download or user data deletion.
Full phases0–7 goal ACTIVE/incomplete; native approval/apply/peakspace, physical
8GB/input, live provider, broad apps and signed OS/release remain unaccepted.

Older notes below are historical; current evidence is outputs/PACKAGE_PLAN_PROGRESS.md.

PR119 run39453988077 reached final package Stop; immediate SIGSTOP-state assertion raced asynchronous delivery. Bounded wait for kernel T + exact argv/UID/exe recheck, wait authorities frozen before nativeStop. Add package-plans.json to host evidence export. 455 local tests/46 skips; full guest acceptance pending.

PR119 run39452513187 cache FileNotFoundError: Python-APT dpkg_journal_dirty enumerates private var/lib/dpkg/updates. Add private empty directory; independent current_status host dirty-journal checks unchanged. 455 local tests/46 skips, native acceptance pending.

PR119 run39450820576 reached cache; private lists directory must include writable scratch partial, not symlink entire directory to RO catalog. Individual signed-file symlinks/private config before APT import. Nativeguard unchanged. 455 local tests/46 skips, guest acceptance pending.

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
