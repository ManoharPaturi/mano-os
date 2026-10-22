#!/usr/bin/env bash
# Called only after the second, real boot. Never invokes initial formatting/setup.
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
cd /opt/mano-lab
root_subvol=${1:-@}
case "$root_subvol" in
  @|@recovery) ;;
  *) echo 'Unexpected root subvolume' >&2; exit 2 ;;
esac
test "$(findmnt -n -o FSTYPE /)" = btrfs
test "$(findmnt -n -o UUID /)" = "$(cat /etc/mano-lab-root-uuid)"
test "$(blockdev --getro /dev/vda)" = 1
test "$(cat /etc/mano-lab-root-mode)" = direct-kernel-btrfs
systemd-tmpfiles --create /etc/tmpfiles.d/mano-lab.conf
python3 - "$root_subvol" <<'PY'
import json, subprocess, sys
from pathlib import Path
root=json.loads(subprocess.check_output(['findmnt','--json','--target','/','-o','TARGET,SOURCE,FSTYPE,FSROOT,UUID,OPTIONS'],text=True))
cmdline=Path('/proc/cmdline').read_text().strip()
assert 'rootflags=subvol='+sys.argv[1] in cmdline,cmdline
assert root['filesystems'][0]['fsroot'] == '/'+sys.argv[1],root
Path('evidence/root-boot.json').write_text(json.dumps({
    'root_mount':root,'cmdline':cmdline,'original_disk_readonly':True,
    'boot_method':'installed Debian kernel/initrd launched directly by QEMU',
    'firmware_installer_verified':False,
},indent=2)+'\n')
PY
uname -a > evidence/kernel.txt
findmnt --json > evidence/mounts.json
free -b > evidence/memory-before.txt
if [ "$root_subvol" = @recovery ]; then PYTHONPATH=src python3 scripts/verify_root_recovery.py; fi
PYTHONPATH=src python3 scripts/probe_lab.py
free -b > evidence/memory-after.txt
