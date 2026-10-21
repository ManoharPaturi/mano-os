# 0104: Root-terminal package-state recovery prerequisite

`mano-package-recovery create` and `prepare-boot RECOVERY_ID` are explicit Debian13
Root controlling-terminal administration. They expose no model/broker capability,
package install, arbitrary argv/path/source/mount target, profile grant, delete,
boot selection or reboot. This is recovery infrastructure toward privileged apply;
it does not complete the agent package-management workflow.

Require one writable named btrfs root subvolume, fixed mano-root Snapper config
for /, separate persistent same-filesystem /.snapshots, private Root-only storage,
and package/boot paths in the same root. Reject ancestor/descendant mounts and
nested subvolumes under /usr,/etc,/var/lib/dpkg,/var/lib/apt,/var/cache/apt,/boot.
Btrfs snapshots do not recursively include nested subvolumes. Other mounted
filesystems, physical-disk failures and external effects are outside recovery.

Hold advisory POSIX dpkg frontend/backend and APT list/archive locks, reject dirty
dpkg journal, require >=1GiB free and bounded retention (four metadata records,
sixteen existing Snapper numeric entries maximum before refusing more creation).
This is a staging floor, not sufficient peak package-change space. Never delete
snapshots or user data automatically. Preserve failed/partial creations for Root
inspection; no automatic retry. Snapper plugins/configuration are trusted Root
administration; no task supplies them and no service is given extra capabilities.

Create a read-only Snapper snapshot, verify parent UUID, exact captured/live dpkg
status hash, stable layout and read-only property. Save fsync'd private metadata
outside the snapshotted root in /.snapshots. A snapshot is a local recovery point,
not an independent backup or proof of full application/database quiescence.

Prepare revalidates immutable source identity/status, filesystem UUID and supported
root fstab before mounting the same filesystem's top level at a fixed private
/run path. Refuse an existing @recovery target. Create a separate writable clone,
adjust only that fresh clone's root fstab, verify parent UUID, sync and unmount.
Never alter the source snapshot/current root, set-default, bootloader, firmware,
installed kernel/initrd selection or boot automatically. A Root operator must
select the compatible recovery boot. A crash can leave a prepared/partial clone;
repeat preparation refuses overwrite and requires operator reconciliation.

Whole-root recovery also restores local logs, journals and other files contained
in that root; it cannot undo remote pushes, uploads, payments or actuator effects.
Existing boot-scoped task/grant reconciliation remains necessary. No old action
is authorized merely because files were restored. Live runtime/credentials and
broader device/firmware recovery remain separate gates.

Guarded CI retains prior Snapper proof and adds Root-terminal create, real signed
Debian sl installation by the disposable test driver, binary /etc change, fixed
clone preparation, actual poweroff and a distinct recovery boot. Verify exact
dpkg before-hash, absent executable and original binary canary; changed source
root retains the installed package and changed state. Test non-Root/no-TTY,
real dpkg lock conflict, nested critical subvolume and duplicate clone refusals.
Runtime .deb positive proof invokes its installed helper on btrfs; pristine ext4
with a Root terminal refuses before snapshot creation. No native experiment on Mac.
Local: 464 tests,46 Linux-only skips; Ruff/compile/shell/diff pass. Native CI pending.
All prior 41 security flags/package/stock/reboot/source-restore and six fresh raw
GUI inspections remain merge gates. Full v2.1 phases0–7 stay incomplete.

Primary contracts: [btrfs subvolumes and nested snapshot boundaries](https://btrfs.readthedocs.io/en/latest/btrfs-subvolume.html),
[Debian Snapper CLI and Root-controlled plugins](https://manpages.debian.org/trixie/snapper/snapper.8.en.html).

First CI39470715507 stopped at lock-negative assertion without its rejection
transcript. Retain bounded denial text and preserve/export early-stage failure
evidence without hiding the original SSH failure status. Static review found
Python has no os.tcgetsid; use documented tcgetpgrp/getpgrp to require the Root
terminal's foreground process group. Add a fully mocked admission regression;
actual Root-terminal acceptance remains pending. 465 local tests/46 skips.

CI39471840714 passed the Root recovery/package stages and reached pristine-stock
setup. The new installed-helper ext4 refusal test was incorrectly run during
pre-install baseline, so it exercised a missing module. Move it to the installed
before-reboot phase; preserve the pristine no-code/no-accounts baseline. Include
the bounded rejection transcript in any assertion failure. No product policy
or filesystem admission check changes. Actual final-head acceptance pending.
