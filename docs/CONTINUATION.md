# Continuation after compaction

Full original mano-OS v2.1 goal remains active. Original spec hash
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace matches supplied README.
Private repo https://github.com/ManoharPaturi/mano-os; checkout work/mano-os.
User authorized mostly merges, only after all final-head checks pass. Strict main
protection includes admins. CI VMs for now, no local VM/model images. No subagents.
Direct agent /compact unavailable; keep this note for automatic compaction.

PRs1-19 merged. Main77e29d3af4322b433e71184a5bcc3bf4514b3fe4. PR19 accepted
CI38333478816 all3success, actual broker journal permissions/restart/latch passed.
Post-main38333924532 still running when this note was written; check authoritative
status, not intent. Watch log work/broker-state-main-watch.log and session57664.
Phase0 35pass/0fail/0pending GO-for-Phase1-development only; production_execution
unauthorized. PR18 closed missing app startup observations, no cold-cache/physical claim.

Current branch feat/phase1-authenticated-ipc: request-only SOCK_SEQPACKET handler,
connection plus per-message Linux credentials, propose/status only. Close/deny
passed FDs, inherited connection and truncated packets. CI fixture deliberately
reachable by all actors to prove caller auth, one reservation, no FD leak. ADR0010.
42 local tests pass with1 Linux-only skip; Ubuntu CI must actually run that test.
Need commit/PR attach, real Debian probe, all-current-head checks before merge.

Next: protected non-root broker systemd socket/service and lifecycle bounds,
separate request-bound PAM approval channel, FD-pinned resources, real cgroup/
bwrap/seccomp/Landlock executor, native stop integration, independent verifier,
terminal/model/LangGraph minimal agent and Phase1 golden project/policy attacks.
Existing State is trusted library; no approval/execution/verification wire bypass.
Native Phase0 stop/PAM probes are fixed disposable fixtures, not production helpers.

All later original phases remain: coding delegates, durable workflows, GUI/browser/
office integration, credentials/network/device mediation, runtime.deb, physical8GB
Phase6, signed firmware/installer/ISO Phase7. Never narrow full goal to lab subset.
Disk last13GiB free94% used: warn below20GiB or>=90%; stop new large downloads
below10GiB. Never delete user data or reformat prepared/recovered guest disks.
Outputs contain accepted PR19 broker-state evidence; no unverified IPC proof.

Latest: PR20 merged27d3e3a7b6b4be705e277cf6d6b56edb8d3b7797 after accepted
CI38334308001 all3success, actual13IPCattacks denied and42Ubuntu tests no skip.
Post-main38334806117 FAILED in stop observer ProcessLookupError reading vanished
/proc PID after cgroup emptied. Current feat/phase1-broker-service includes narrow
ESRCH/ENOENT observer fix (live/permission errors stillfail) and regressiontest.
Also non-root systemd request-only service, fixed activation listener, hardening/
limits, bounded client/global admission, actual guest start/UID/DAC/slow/SIGKILL
restart fixture. ADR0011. Local44tests pass with1MacLinuxskip. No CI yet.
Need PR with full real VM checks; no merge before allfinalheadSUCCESS. Fullscopeactive.
Disk11-12GiB free94-95%, no newlarge downloads below10GiB.

Latest PR21 mergedc631672d3aef0b0ce59728c644ecadba66035243 after accepted
CI38335723301 all3success. ActualUID999/NNP/seccomp/zero caps,6DACdenials,
slowclient1.836s,SIGKILLrestartunknown proved. Post-main38336185993 stillpending
when lastchecked; inspect authoritative state. Current feat/phase1-exact-grants
requires canonical approved_args at every grant issuance and reservation/dispatch.
Legacy journals upgrade revokeall/unknownexecuting/failedintent without deletion.
Unit48tests pass1MacLinuxskip; actualmigration and changed-target IPC/service probes
added. ADR0012. TrustedPAMcontrol not integrated yet; nextwork. Need freshCI/PR
all-current-head checks beforemerge, then postmain. Disk13GiB94%last.

Latest PR22 main30bfa59a3b1f72e98c4747fd9f602a6efe95d3dc, acceptedCI38337001596
all3success, post-main38337436583 all3success nowverified. Current branch
feat/phase1-approval-queue: durable private pending challenge, publicrequest/status
only, trustedconfirmation atomicallyconsume+one exactgrant, nonce/digest/time/boot/
epoch/human binding, quota64/task, trustednestedSavepoints.57localtests inclrace/
rollback/expiry-status passed; guestservicepending/selfapprovaldeny/restart added.
No PAM/rootcontrol transport yet; ADR0013. NeednewPR/allCIbeforemerge. Fullgoalactive.

Disknow9.3GiB free96%: NO newlarge localdownloads below10GiB, no data deletion.

Latest PR23 merged205a70a6551323cc83bd31a7986e091302e1abfe after accepted
CI38338470385 all3success; actualpending/selfapprovaldenial/restart verified,
15IPCattacks denied and57Linux tests. Post-main38339110162 running lastchecked.
Currentfeat/phase1-approval-control: root0600 separate control listener, activation
2namedFDs/selectors/controlpriority/separatebudgets, view/confirm onlykernelUID0,
strictfields/replay/binding tests. Actualguest4controlDACdenials + rootconfirmation
exactonegrant added.58localtests1MacLinuxskip pass. NO PAMadapter yet; fixture
explicitcontrol_pam_authenticated=false. ADR0014. NeednewPR/allCI beforemerge.
Disk7.4GiBfree97%: no newlarge localdownloads, no userdata deletion.
Earlier optionalGitindexwrite timedout; read-only status succeeded, no stale lock
remained; source/controlfiles preserved, no lock deletion was necessary.

Latest PR24 merged314232044517d351be59ef9060b5cb3b87d3053f after accepted
CI38341706730 all3success; correctedcreator/reply credentials,10kerneldenials,
4confirmationbindings/single-use verified. Post-main38342328797 pendinglastcheck.
Current feat/phase1-native-pam includes native/mano_approve.c + rootunit/humansocket/
PAM config + TTYclient+binaryv1codec(34view/164confirmheader).60localtests pass
1MacLinuxskip. NativecompileUNVERIFIED on Mac; CIqualityandDebianstrictcompile
added libjson-c-dev onlyincloud. ActualnativePAMfixture root/humanUIDmapping,
wrongpass/nonce/replay/validexactgrant/zeroCapsNNPSeccomp+hash added.
NeednativewarningsfixifCIrejects; neverdisableWerror/tests. Nativehelperownbuffer
wipeonly, PAM/Pythoncopies notguaranteederased. ADR0015 documentspending scopes.
No hostservices/models installed, fullPhase1goldengate/alllateroriginalscope active.

Latest PR25 mergedad7eff9bbcd3786b09b63407e6b66f6e07da53e5 after accepted
CI38342918494 all3success. ActualnativePAMwrongpass/nonce/replay denied, valid
exactgrant used, rootZeroCapsNNPSeccomp/hash verified. PhysicalTTY null.
Postmain pendingIDneedlookup. Currentfeat/phase1-resource-pins root-installed
openat2 DSOnofallback, trustedDirectoryFDanchor andretained targetinodes,
symlink/magic/mount rejection/type/hardlink policy. No registry/executor/readwrite
wire yet.61localtests2MacLinuxskips pass; LinuxCI installsDSO/runs test, actual
Debianroot/mount/sentinel probeadded. ADR0016 limitsmutablecontent/hardlinkraces
and lostFDrestart. NeednewPR/allcurrentheadCIbeforemerge. Disk14GiB93%last.

Latest PR26 main70f89fd64c5c307d14c651a964d4889779d8f694, postmain38345354682
all3success verified. Currentfeat/phase1-resource-registry trustedFD→opaqueID
subject/task/boot binding, exactgrant prepare/read/cwd/writeparent pins, parent-race
fix, one start metadata, replaynofreshFD, release/lostregistry/quota boundaries.
66localtests7MacLinuxskips pass. LinuxCI and actualDebianregistryproof pending.
NO provisioningwire/executor yet; publicpropose metadata mustrouteRegistry.prepare
beforeState.authorize oncewired, notpretendpre-reserved intentsacquiredFDs.
READMEstalePAMclaim fixed. ADR0017. NeednewPR/allCIbeforemerge. Fullgoalactive.

Latest PR27 mainfb0b3add89c1df196bf22ce33d21e966f7fbaba3 accepted
CI38346608528 all3success; postmain38347435709 stillpendinglastcheck.
Currentfeat/phase1-provision-receiver rootkernelpeer+message1directoryFD
O_PATH/CLOEXEC/schema/owner==broker/gid==caller/mode0770or2770 validation,
registryTaskcreation andcleanup. NewDebianprobe realnonrootreceiver/rootFD
plus11denials/per-requestFDdeltas. No daemon/publicprepare wiring yet.
ADR0018 boundaries; local67tests8MacLinuxskips pendingrerun. NeedallCIbeforemerge.
Full original goalactive. Disk14GiB93%last, no localimages oruserdata deletion.

Latest PR28 main691440ce3e5e0e43f4978585dbdbe9ad2617ec1e post-main38349318031
all3success nowverified. Currentfeat/phase1-live-runtime Runtime+thirdroot0600
provision listener actualservice integration. Proposeprepares liveFDs beforeintent;
approvalrequestrequiresliveTask. Startup revokesgrants/failsintent/unknownexecuting/
epoch++ preserveshistory/latch.69localtests10MacLinuxskips passed; realLinuxCI
pending. Actualservicefixture rewritten liveFDprovision/nativePAM/heldFD/symlink
replay/SIGKILL revokeoldIDs and freshrootprovision. Seededexecutingstate explicitly
metadataonly/nooperation. ADR0019. NeedallCI beforemerge, no skip/rootbypass.
No executor yet; nextsandbox/jobUID/ACL/nativeStop/verifier/model/goldengate.
# Workspace continuation

PR #29 merged at 8e74341e2600715d157210a6adc3206fe80fa2c5 after all three
checks passed on 54a03db (run 38352199729). Accepted VM broker report proves
real descriptor preparation, mutation-syscall EPERM, native PAM, held inode,
SIGKILL restart and fresh provisioning. No actual operation/model ran.

Next branch feat/phase1-workspace-acl adds root administrative workspace creation
and actual VM default ACL tests. Local 70 tests pass with 10 Linux-only skips.
Linux workspace evidence is pending CI; do not claim its gate passed yet.
Continue with task UID allocation and actual sandbox/executor after acceptance.
Full original version goal remains active. Physical gates remain unmeasured.
Disk 14 GiB free / 94 percent used; no local VM images or model downloads.
# Task identity continuation

PR30 merged at 33d71f0f8a9c2b98ad5e74d641e92bd02ae92676 after all three
current-head checks passed, run38353159570. Actual workspace report accepted:
four cross-identity EACCES, default broker/human nested access and private-mode
restriction. PR29 post-main38352940988 passed all three checks.
Next branch feat/phase1-task-identities adds a bounded root-only allocator and
two real allocated identity workspace tests. Local71 tests pass/10Linux skips;
real Linux identity tests pending. Do not claim executor or fullPhase1 complete.
