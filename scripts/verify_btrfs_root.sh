#!/usr/bin/env bash
# Called only after the second, real boot. Never invokes initial formatting/setup.
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
cd /opt/mano-lab
test "$(findmnt -n -o FSTYPE /)" = btrfs
test "$(findmnt -n -o UUID /)" = "$(cat /etc/mano-lab-root-uuid)"
test "$(blockdev --getro /dev/vda)" = 1
test "$(cat /etc/mano-lab-root-mode)" = direct-kernel-btrfs
systemd-tmpfiles --create /etc/tmpfiles.d/mano-lab.conf
python3 - <<'PY'
import json, subprocess
from pathlib import Path
root=json.loads(subprocess.check_output(['findmnt','--json','--target','/'],text=True))
cmdline=Path('/proc/cmdline').read_text().strip()
assert 'rootflags=subvol=@' in cmdline,cmdline
Path('evidence/root-boot.json').write_text(json.dumps({
    'root_mount':root,'cmdline':cmdline,'original_disk_readonly':True,
    'boot_method':'installed Debian kernel/initrd launched directly by QEMU',
    'firmware_installer_verified':False,
},indent=2)+'\n')
PY
uname -a > evidence/kernel.txt
findmnt --json > evidence/mounts.json
free -b > evidence/memory-before.txt
PYTHONPATH=src python3 scripts/probe_lab.py
free -b > evidence/memory-after.txt
