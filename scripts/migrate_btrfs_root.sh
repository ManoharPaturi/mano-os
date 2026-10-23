#!/usr/bin/env bash
# Format only the explicitly blank third disk in the disposable lab VM.
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
cd /opt/mano-lab
test -f /etc/mano-lab-prepared
test "$(findmnt -n -o FSTYPE /)" = ext4
test -b /dev/vdc
test "$(blockdev --getsize64 /dev/vdc)" = 8589934592
# Refuse replay on any formatted/mounted target; no mkfs --force escape hatch.
if blkid /dev/vdc >/dev/null 2>&1 || findmnt -rn -S /dev/vdc >/dev/null; then
  echo 'Root target already has a filesystem or mount; refusing format.' >&2
  exit 2
fi
printf 'btrfs\nvirtio_blk\n' >> /etc/initramfs-tools/modules
update-initramfs -u -k all
kernels=(/boot/vmlinuz-*)
kernel_path=$(printf '%s\n' "${kernels[@]}" | sort -V | tail -n 1)
kernel_version=${kernel_path##*/vmlinuz-}
initrd_path="/boot/initrd.img-$kernel_version"
test -f "$kernel_path"
test -f "$initrd_path"
lsinitramfs "$initrd_path" | awk '/btrfs\.ko/ {found=1} END {exit !found}'
mkfs.btrfs -L MANO_LAB_ROOT /dev/vdc
root_uuid=$(blkid -s UUID -o value /dev/vdc)
printf '%s\n' "$root_uuid" > /etc/mano-lab-root-uuid
mkdir -p /mnt/mano-root
mount /dev/vdc /mnt/mano-root
trap 'umount /mnt/mano-root 2>/dev/null || true' EXIT
btrfs subvolume create /mnt/mano-root/@
rsync -aHAXx --numeric-ids \
  --exclude='/mnt/mano-root/***' --exclude='/tmp/***' --exclude='/run/***' \
  --exclude='/dev/***' --exclude='/proc/***' --exclude='/sys/***' \
  / /mnt/mano-root/@/
mkdir -p /mnt/mano-root/@/{dev,proc,sys,run,tmp,mnt,lab-btrfs}
chmod 1777 /mnt/mano-root/@/tmp
# Firmware/EFI installation is a later gate; this lab boots the installed kernel directly.
printf 'UUID=%s / btrfs defaults,subvol=@ 0 0\n/dev/vdb /lab-btrfs btrfs defaults 0 0\n' \
  "$root_uuid" > /mnt/mano-root/@/etc/fstab
printf 'direct-kernel-btrfs\n' > /mnt/mano-root/@/etc/mano-lab-root-mode
mkdir -p /tmp/mano-boot-export
cp "$kernel_path" /tmp/mano-boot-export/vmlinuz
cp "$initrd_path" /tmp/mano-boot-export/initrd.img
printf '%s\n' "$root_uuid" > /tmp/mano-boot-export/root-uuid
sha256sum /tmp/mano-boot-export/vmlinuz /tmp/mano-boot-export/initrd.img \
  > evidence/boot-input-sha256.txt
findmnt --json > evidence/bootstrap-mounts.json
btrfs filesystem usage /mnt/mano-root > evidence/btrfs-root-layout.txt
sync
