# ADR 0003: validate root recovery by booting the snapshot clone

Status: implemented for CI acceptance; not a production rollback helper.

Undoing one data file does not prove root/boot recovery. After the actual btrfs
root boot passes the complete security suite, configure Snapper on `/`, keep its
snapshot store in an independently mounted `@snapshots` subvolume, and create a
read-only root snapshot containing a protected sentinel. Change the live `@`
sentinel, clone the snapshot into writable `@recovery`, and boot that clone.

Acceptance checks the actual root FSROOT, a different kernel boot ID, restored
sentinel content, the changed source root's retained content, and the independent
snapshot-store mount. It then reruns all filesystem/IPC/network/device, desktop,
OOM and stop probes from newly allocated workspaces. Prior root/disk/workspace
artifacts are preserved. The first-root report and all its referenced artifacts
are kept together so later observations cannot invalidate its hashes.

The copied recovery root gets an explicit fstab matching `@recovery`; the source
snapshot remains read-only. The original cloud disk is kept read-only and its
hash is compared after both real btrfs boots. The guarded guest scripts refuse
non-lab contexts or implicit destructive replays.

This proves a bounded root-snapshot recovery experiment in QEMU. It does not
prove firmware/installer boot, every package-upgrade rollback, physical recovery,
or an authentic user approval/stop service. Those gates remain explicit.
