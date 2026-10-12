# ADR 0002: test the real btrfs root before runtime integration

Status: implementation in CI; acceptance requires actual second-boot evidence.

The initial lab had an ext4 cloud root and separate btrfs data volume. That does
not satisfy the btrfs-root feasibility requirement. Preserve that bootstrap disk,
prepare a third 6 GiB sparse disk as btrfs with an `@` root subvolume, and copy the
prepared Debian installation with ownership, ACLs and extended attributes intact.
Include btrfs and virtio modules in the Debian initramfs, boot the installed
kernel/initrd directly through QEMU, and rerun the entire security suite there.

The verifier checks the live `/` filesystem and UUID, kernel root flags, and the
read-only original block device. The runner compares the original disk's SHA256
before and after. The preparer refuses any target with a filesystem or mount and
cannot be replayed as an implicit destructive reset. Guest-only mutation scripts
require a root caller, a CI marker and QEMU/KVM virtualization. These checks prevent
accidental host use; they do not constrain a malicious root principal.

This tests a real root mount/boot, not a chroot simulation. Direct kernel boot does
not verify a firmware bootloader, installer, secure boot or physical recovery.
Root snapshot boot/restore is the next P0-11 experiment and remains incomplete.
No production broker, model execution or unrestricted delegate is introduced.

References checked before implementation:

- [QEMU system options](https://www.qemu.org/docs/master/system/qemu-manpage.html)
- [btrfs subvolume semantics](https://btrfs.readthedocs.io/en/latest/btrfs-subvolume.html)
- [Debian update-initramfs](https://manpages.debian.org/trixie/initramfs-tools/update-initramfs.8.en.html)
- [rsync metadata and one-filesystem options](https://download.samba.org/pub/rsync/rsync.1)
