#!/usr/bin/env bash
# Preserve the changed @ root and create a separately bootable snapshot clone.
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
cd /opt/mano-lab
test "$(findmnt -n -o FSTYPE /)" = btrfs
test "$(findmnt -n -o FSROOT /)" = /@
test ! -e /etc/snapper/configs/mano-root
test ! -e /.snapshots
mkdir -p /mnt/mano-root
mount -o subvolid=5 /dev/vdc /mnt/mano-root
trap 'umount /mnt/mano-root 2>/dev/null || true' EXIT
test ! -e /mnt/mano-root/@snapshots
test ! -e /mnt/mano-root/@recovery
snapper --no-dbus -c mano-root create-config /
# Snapshot storage must survive a switch of the root subvolume.
mv /mnt/mano-root/@/.snapshots /mnt/mano-root/@snapshots
mkdir -m 700 /.snapshots
mount -o subvol=@snapshots /dev/vdc /.snapshots
printf 'UUID=%s /.snapshots btrfs defaults,subvol=@snapshots 0 0\n' \
  "$(cat /etc/mano-lab-root-uuid)" >> /etc/fstab
printf 'before\n' > /etc/mano/recovery-sentinel
chmod 600 /etc/mano/recovery-sentinel
snapshot=$(snapper --no-dbus -c mano-root create --print-number --description phase0-root)
case "$snapshot" in ''|*[!0-9]*) echo 'Invalid snapshot number' >&2; exit 1 ;; esac
test "$(btrfs property get "/.snapshots/$snapshot/snapshot" ro)" = ro=true
printf 'after\n' > /etc/mano/recovery-sentinel
btrfs subvolume snapshot "/.snapshots/$snapshot/snapshot" /mnt/mano-root/@recovery
# Match the recovery clone's fstab to the actual root selected for its next boot.
sed -i 's/subvol=@ /subvol=@recovery /' /mnt/mano-root/@recovery/etc/fstab
python3 - "$snapshot" <<'PY'
import json,sys
from pathlib import Path
Path('evidence/root-snapshot.json').write_text(json.dumps({
    'snapshot_id':int(sys.argv[1]),'source_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'live_sentinel':Path('/etc/mano/recovery-sentinel').read_text(),
    'snapshot_sentinel':Path('/.snapshots',sys.argv[1],'snapshot/etc/mano/recovery-sentinel').read_text(),
    'snapshot_readonly':True,'source_root_preserved':True,
},indent=2)+'\n')
PY
snapper --no-dbus -c mano-root list > evidence/root-snapper.txt
btrfs subvolume show /mnt/mano-root/@recovery > evidence/recovery-subvolume.txt
sync
