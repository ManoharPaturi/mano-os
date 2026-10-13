# Continuation after compaction

Full original mano-OS v2.1 goal remains active. Original spec hash
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace matches supplied README.
Public repo https://github.com/ManoharPaturi/mano-os; checkout work/mano-os.
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
# Descriptor sandbox continuation

PR31 merged c0e3aebabc37ba2bcd327fa5ac2f9ec122296935 after accepted run38353924283
all3success. Post-main38354466056 now all3success. Latest workspaces.json actual
distinct locked task accounts, correct groups, contention denial, five kernel
cross-task denials plus prior ACL checks. No runtime account reuse/retirement.
Current feat/phase1-fd-sandbox adds trusted unprivileged command compiler and
operator-driven real VM descriptor/cgroup/mount/network/environment tests.
Local72 tests pass/10LinuxMacskips; real sandbox CI pending. Seccomp/Landlock and
broker executor integration remain unimplemented; never claim fullPhase1 done.
# Kernel guard continuation

PR32 merged9e5e9ec483994cd883ae057ece053c30095f0733 after run38356193540 all3success.
Actual fd-sandbox report accepted: held workspace/cwd mount after name replacement,
minimal exact4env, host network/IPC/inherited socket denied, NNP/caps0, output,
128MiB24pids20CPU actual scope membership. Seccomp/Landlock then null.
Current feat/phase1-kernel-guard adds mandatory root-installed UNPRIVILEGED Cguard,
Landlock ABI>=5 fixedFS/TCP policy, seccomp denyprofile and startup kernel probes,
child inheritance tests. Local73 tests pass/10LinuxMacskips; native compilation
and real enforcement NOT verified yet. GitHub DNS unavailable on this Mac at last
check; preserve local commit and push/create PR when access returns. Main postmerge
cannot currently be queried. No root endpoint/model/broker executor connected.
Disk16GiB92percent; no local VM/models. Full original goal remains active.
# Bounded runner continuation

PR33 merged5e2fb8e7ee63cfaa3925100623c79de783e80fe9 after all3currenthead checks
SUCCESS in38359708133. ConnectedGitHub GET verifiedexacthead7097e5a/allchecks,
no commitstatuses, cleanmergebase thenmatch-head merge, no bypass. Actualguard
report accepted: seccomp2/no-changeEPERM, Landlock writable/etcEACCES, normal
subprocess andchildinheritance pluspriorFD/network/IPC/env/cgroupchecks.
Current feat/phase1-bounded-runner adds unprivileged bounded-output/deadline/
revocation ProcessResult runner and actualcgroupcleanup VMcases. Local75tests
pass10MacLinuxskips; real runnerVMtests pending. No brokerexecutor/modelendpoint.
Use connected GitHub tools while CLI API DNS fails; gittransport still works.
# Launch admission continuation

PR34 merged a081e5fc4fc2d3f8d412ac55925cc34e43c5eddc after run38360737222 all3SUCCESS,
exactheadb53c1dc checks/commitstatusesempty/cleanbase verified throughGitHubconnector.
Actualrunnerreport accepted:64KiB bothstreams, fork andclosedpipe timeout cleanup,
active revocation reaped, beforelaunchnoeffect, baselinecgrouprestored. No verified
taskeffects inferred. Currentfeat/phase1-launch-admission adds privatebroker→root
kernelpeer/twoFD admission library and14case real VM test. Local76tests10Linux
Macskips pass; admissionVMproof pending. No rootexecutionservice/listener installed.
Nextactualroot lifecycle/cgroup/drop/one-shotaction+livegrant/stopintegration.
# Delegation continuation

PR35 merged0c2014d040569a20872d08004700bd62d8999a16 after all3currenthead checks
SUCCESS run38362982094 (headb6ed889). Actualknowncontroller/transientPID observer
andallboundedrunner cases passed; rootadmission1positive13deny/noleak passed.
Originalpost-main34 failureprecisePIDdifference unknown; observernowstricterinitial
drain/exactknown2controllers. Needpostmain35 result beforeclaimmainstable.
Currentfeat/phase1-delegated-cgroups addsfixedrootservice delegatedgroupcustody and
actualephemeralservice test of placementbeforedrop/cgroupkilldetachedUID1004children/
quota/actionreuse/arbitraryPIDdenial. Local77tests10MacLinuxskips pass; VMpending.
No productionrootlaunchservice/modelendpoint installed. Fulloriginalgoalactive.
# Credential transition continuation

PR36 mergeda68bd9ad7c2cdab02145a59a8c663276fd16221a after all3currenthead checks
SUCCESS run38366463779/head23d0c6e. Actualdelegatedservice proofzerochildcapsets,
confirmedSIDdetachment/cgroupkill/groupremove/manageralive/quotaPIDreuse denial.
SourceverifiedsystemdSETUIDdroponexec; ambientSETUIDonly/boundc0 required; noextra
caps added. Currentfeat/phase1-credential-drop sharesrestrictedtaskidentityvalidator
and own-child/cgroup credentialhelper withNNP/capclear/PDEATHSIG afterUIDdrop and
PPid recheck. Fixtureusesfreshallocatedidentity instead offixedworker1004.
Local78tests10MacLinuxskips pass; realhelperVMproofpending. No processlaunchendpoint.
# Supervised child continuation

PR37 mergedc7fff122fd286264fab1592ccece58495b7420df after all3currenthead checks
SUCCESS run38368015498. ActualfreshUID1005drop/zero4capsets/NNP/PDEATHSIGconfigured/
detachedcgroupkill/cleanup allpassed. Currentfeat/phase1-supervised-child adds
one-shotblockedRootchild/cgroupplacement/drop/READY/authority-start/reportdrain/
cancelunknown lifecycle library. Actualoperatorargvexec fixture pendingCI;
operatorcallback authority ONLY, notbrokergrant/epoch integration. Local78tests
10MacLinuxskips/Ruffpass. No productionlistener/modelendpoint orverifiedeffects.
# Private controller continuation

Post-main38 run38377627167 all3SUCCESS verified. Currentfeat/phase1-launch-controller
addsinstance/job/action/ownerPeer+pidfd custody, brokeronly metadata control and
boundedoutputchunks/effect_verifiedFalse. AdmissioncarriesownerPeer fromreceiver.
Actualrootservicefixture usesexplicitlysyntheticoperatorpeer withrealsupervised
children fordispatcher/state/chunkchecks; no kernelbrokergranttransportclaimed.
Local81tests10MacLinuxskips pass. No activationlistener/modelendpoint installed.
Next privateactivation +realpersistentbrokertransport/grantjournal/epoch integration.
# Activation transport continuation

PR39 mergeda10e3dbf83c088bff95ecbd1512a4c00d4cfac11 after all3currenthead checks
SUCCESS run38400943127; controllerdispatcher/chunks againstsyntheticoperatorpeer
passed. Currentfeat/phase1-private-transport addsfixed2listener activationvalidation
and realpersistentbrokerUID/PID/socketrights/replycredentials servicefixture.
Admissioncwd pin read-only asfixedbroker EUID in singlethread thenfinallyrootrestore,
noDACoverride. Tests secondpin whilejobrunning toverifychilddeathflag unaffected.
Local82tests10MacLinuxskips pass; realtransport proofpending. No productionmodel/
hostlistener or journalgrant/epoch integration claimed. Allfullversiongates remain.

# Reusable launcher client continuation

PR40 merged1cc222f6c1d46b9703ba72f0d42bba4fd2a7d9f5 after all3 current-head
checksSUCCESS run38403286626. Accepted real persistent broker transport/root
message credentials/minimum-capability cwd pin/second pin while running evidence.
Post-main run38404236483 still in progress at this writing. Current branch
feat/phase1-launch-client replaces ad hoc fixture RPC with reusable private Client,
fixed paths, bounded messages, rights closure, root creator and message credentials,
pidfd lifetime identity and no implicit launch retry/recovery. Grant journal,
epoch/Stop coupling and production daemon remain required. Linux credential
response tests run in CI, not macOS. Full original version remains incomplete.

# Journal executor continuation

PR41 current CI38404746333 all3SUCCESS observed; merge gate/evidence verification
still required before merge. Current feat/phase1-journal-executor adds trusted
Executor real journal lease/start/lifecycle library with real SQLite tests and
actual root-service VM fixture. No public Runtime execution or production daemon
integration yet; grants in the VM originate from trusted operator fixture, notPAM.
Fixed launcher ceilings require grant>=128MiB24pids20CPU; narrower grants denied.
Local91tests12MacLinuxskips pass. Actual executor VM acceptance pending.

PR41 now verified merged by GitHub accountManoharPaturi at13:29:57UTC,
merge8e0e96a51be134dc0539f54d422757ebcab5e0c3, all3currentheadchecksSUCCESS.
Accepted production_client_transport=true artifact11819101273. Local executor
branch merged origin/main (36aec19) to stay current, no protection bypass.

PR42 initialVM38405746717 FAILED atStateconstructor: journalunderworkspace
inheritedsetgid/ACL soexact0700checkdenied. Fixedfixtureprovisionsseparate
/run/mano-journal-ci broker-owned0700 outsideworkspace, unitReadWritePathallows
proxy journalwrites, Rootoutercleanupafterstop. Statechecksunchanged.
Launcher-service draftstashed onfeat/phase1-launcher-service pendingPR42fix.

# Launcher service draft continuation

Currentfeat/phase1-launcher-service has production module, fixedpackagedsocket/
serviceunits, disconnectedreplysurvival and actualstandalone daemon VMphase.
Local93tests12MacLinuxskips/Ruff/shell/diffpass. NewproofNOTaccepteduntilCI.
PR42 initialrunfailedstrictjournalmode; fixedheadbe8ed3a run38406670474 LIVE.
This branchcherrypickedfixe78c7d6; afterPR42merge mergeoriginmain beforePR43publish.
Standalone daemonproxy uses /run/mano-journal-ci/daemon (not taskworkspace),
actualjournal/Registry/nativepins/start/completion/output/Stopcancel; operator
approvalonly, noPAM/publicRuntime/frozenbrokerStop claims. Productionunitreplaces
fixtureunit ONLYindisposableVM; no host service installation.

PR42 merged7258a6406e6df9ab1d73b36de81af9522b71a8d5 after exactheadbe8ed3a
all3SUCCESS run38406670474. Artifact11818304235 accepted realjournalexecutor/
Stopcancelunknown, PAMfalse. PR43 mergescurrentmain; onlydocscontinuationconflict
resolvedpreservingbothnotes. Fresh final-head CI required before ready/merge.

# Runtime scheduling draft continuation

Currentfeat/phase1-runtime-execution adds Runtime optionaltrustedClient/Executor,
freshRUN-onlyqueuedactionID, tickpoll+onependinglaunch/max2active, closecancel/
unknown/lease/clientclosure. ServicepassesClient, ticksafterrequests/control and
WATCHDOGnotify. No newpublicStart/grantendpoint. Replaynoenqueue. SynchronousRPC
bounded8secs can triggerunchanged6secondbrokerwatchdog; no latency/frozenStopclaim.
Portable96tests12MacLinuxskips pass. Standalone daemonprobe uses Runtime.dispatch
withEXPLICITsynthetic callerPeer(operatorfixture) andoperatorgrant, actualscheduler/
Registry/executor/rootservice. Not actualkernelbrokerrequest/PAMacceptance.
PR42merged7258a64 acceptedjournalVM. PR43freshhead6482552 CI38407737065 LIVE;
old38407162561 auto-supersededcancelled, notaccepted. Postmain42 38407624336 LIVE.

# Native PAM terminal integration draft

PR43merged0053fcdacf1670819f4d872e678d7108e2e20406 afterall3SUCCESSrun38407737065.
Acceptedartifact11820206179 productiondaemon/journalexecution/Stopcancellationtrue,
PAMfalse. PR44oldhead743799a run38408278683 all3SUCCESS butnotfinalhead; branch
mergedoriginmain to6f650b9, freshCI38409320590 LIVE. Postmain43 38409267628 LIVE.
Currentfeat/phase1-pam-terminal-flow extends existingrealbroker/PAMfixture with
actualRootpackagedlauncher+guard+mano_labcode andRootallocatedtask/workspace.
Real taskUIDcallsrequest_approval, humanPAMwrongpwnoeffect/correctpwgrant,
changedargsdeny/exactproposalintent/runtimeexec/doneknownfile/verified0/replay/
wrongcallerstatusdenied. No directgrantinjection; physicalinputnull/fixturepassword
inmemory only. Cleanupstopsallunits beforeownworkspace/identity/nativecleanup.
ActualVMproofpending, fullversiongatesstillactive. No physical/verifiedartifactclaims.
PR44 fresh38409320590 failedinstalledclient; subprocesscapture hidinnerstderr,
exactinitialfailureunknown. Added bounded error-type/errno journalevents andstderr
exposure. Sourceinspectionalsofoundobserverrace: Rootstatus couldfinishafter
Runtime.tick poll but beforesecondcontrolRPC, so testbroke beforeSQLitebecamedone.
Fixture nowawaits BOTHRootfinishedANDjournal(done,0) withinSAME5seconddeadline,
thenassertsboth. No productionexit/grantchecksweakened. NewCIrequired.

PR44diagnosticrun38410509463 FAILED clientline72 recvmsg ECONNRESET whileRoot
servicehealthy. Sourcepoll2controlRPCs/0.01secs exceedsfixed10/secbudget. Fixprobe
0.25sec(<=8/sec), SAME5secdeadline/bothRootfinish+journaldone. Broker service now
pacesRuntime.tick>=0.5sec independentofrequestbursts; Root10/secbudgetunchanged.
Rootrate-deniedevent added withoutarguments. Resource-limitsWIPstashed.

# Approved limits draft continuation

Currentfeat/phase1-grant-resource-limits changes trustedLimits frozen3ints;
Executor derivesmin(grant,128MiB24pids20CPU) into privatepreparebodylimits.
RootAdmission strictoptionaltypedlimits (legacyoperatorfixtures defaultceilings),
ChildpassesLimits toManager.create, writes/readbackchecksactualkernel ceilings
BEFOREattach/drop. Tinypositivebudgets canOOM/fail but cannotexceedgrant.
VMsecondgroup actual64MiB16pids10CPU exactreadback; actualjournalwire fixture
now64MiB16pids10CPU andmustcomplete/Stopcancel. Tests98/12LinuxMacskipspass,
realenforcementpending. No publiclimits/pathfield or extraRootcapability.
PR44latestpollpacingfix5163264 andPR45merges8b49b2d pushed; freshCIpending.
Prior45run38410592981 failedSAMEcontrolECONNRESET inlaterdaemonprobe, no actual
PAMfailure inferred. Rootbudgetunchanged, probe0.25sec/BrokerTick0.5sec.
