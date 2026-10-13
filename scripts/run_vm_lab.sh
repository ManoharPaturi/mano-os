#!/usr/bin/env bash
# CI-owned disposable VM only. Never install packages on the user's machine.
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
lab_dir="$repo_root/work/vm"
mkdir -p "$lab_dir" "$repo_root/evidence"
free_kib=$(df -Pk "$repo_root" | awk 'NR==2 {print $4}')
if [ "$free_kib" -lt 10485760 ]; then
  echo 'Stop: less than 10 GiB free; VM download refused.' >&2
  exit 2
fi
if [ "${MANO_DISPOSABLE_CI:-}" != 1 ]; then
  echo 'This script runs only in an explicitly marked disposable CI runner.' >&2
  exit 2
fi
command -v qemu-system-x86_64 >/dev/null
base=https://cloud.debian.org/images/cloud/trixie/latest
image=debian-13-genericcloud-amd64.qcow2
curl --fail --location --retry 3 "$base/SHA512SUMS" -o "$lab_dir/SHA512SUMS"
curl --fail --location --retry 3 "$base/$image" -o "$lab_dir/$image"
(cd "$lab_dir"; awk '$2 == "debian-13-genericcloud-amd64.qcow2"' SHA512SUMS | sha512sum -c -)
cp "$lab_dir/SHA512SUMS" "$repo_root/evidence/image-SHA512SUMS"
qemu-img resize "$lab_dir/$image" 12G
qemu-img create -f qcow2 "$lab_dir/data.qcow2" 2G
qemu-img create -f qcow2 "$lab_dir/root.qcow2" 6G
ssh-keygen -q -t ed25519 -N '' -f "$lab_dir/key"
cat > "$lab_dir/user-data" <<EOF
#cloud-config
users:
  - name: lab
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$lab_dir/key.pub")
ssh_pwauth: false
disable_root: true
write_files:
  - path: /etc/mano-lab-disposable
    permissions: '0600'
    content: mano-phase0-ci
EOF
printf 'instance-id: mano-phase0
local-hostname: mano-phase0
' > "$lab_dir/meta-data"
cloud-localds "$lab_dir/seed.img" "$lab_dir/user-data" "$lab_dir/meta-data"
accel=tcg
cpu_model=max
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=kvm; cpu_model=host; fi
printf 'QEMU accelerator: %s\n' "$accel" | tee "$repo_root/evidence/accelerator.txt"
printf '%s\n' "$cpu_model" > "$repo_root/evidence/cpu-model.txt"
start_vm() {
  local stage=$1
  shift
  if [ "$accel" = kvm ]; then
    # Hosted runner device ACLs may be reset between separate QEMU lifetimes.
    getfacl /dev/kvm > "$repo_root/evidence/kvm-$stage-before.acl"
    sudo setfacl -m "u:$(id -un):rw" /dev/kvm
    getfacl /dev/kvm > "$repo_root/evidence/kvm-$stage-after.acl"
    test -r /dev/kvm && test -w /dev/kvm
  fi
  qemu-system-x86_64 -accel "$accel" -cpu "$cpu_model" -m 4096 -smp 2 -display none \
    -chardev "socket,id=console,path=$lab_dir/serial-$stage.sock,server=on,wait=off,logfile=$repo_root/evidence/serial-$stage.log" \
    -serial chardev:console \
    -drive "file=$lab_dir/$image,format=qcow2,if=virtio$bootstrap_readonly" \
    -drive "file=$lab_dir/data.qcow2,format=qcow2,if=virtio" \
    -drive "file=$lab_dir/root.qcow2,format=qcow2,if=virtio" \
    -drive "file=$lab_dir/seed.img,format=raw,if=virtio" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
    "$@" > "$repo_root/evidence/qemu-$stage.log" 2>&1 &
  vm_pid=$!
}
bootstrap_readonly=
vm_pid=
trap 'if [ -n "$vm_pid" ]; then kill "$vm_pid" 2>/dev/null || true; fi' EXIT
start_vm bootstrap
ssh_opts=(-i "$lab_dir/key" -p 2222 -o BatchMode=yes -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$lab_dir/known_hosts")
wait_ssh() {
  local ready=0
  for _ in $(seq 1 90); do
    if ssh "${ssh_opts[@]}" lab@127.0.0.1 true 2>/dev/null; then ready=1; break; fi
    kill -0 "$vm_pid"
    sleep 5
  done
  if [ "$ready" != 1 ]; then echo 'VM SSH boot timed out' >&2; exit 1; fi
}
wait_ssh
ssh "${ssh_opts[@]}" lab@127.0.0.1 'sudo cloud-init status --wait'
# Transfer only the tracked checkout; never CI credentials or host home.
git -C "$repo_root" archive HEAD | ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo mkdir -p /opt/mano-lab; sudo tar -xf - -C /opt/mano-lab'
set +e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo bash /opt/mano-lab/scripts/guest_lab.sh && sudo bash /opt/mano-lab/scripts/migrate_btrfs_root.sh' \
  2>&1 | tee "$repo_root/evidence/guest-prepare.log"
prepare_result=${PIPESTATUS[0]}
set -e
# Export root-side evidence even when preparation fails; never hide its exit status.
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
if [ "$prepare_result" != 0 ]; then exit "$prepare_result"; fi
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /tmp/mano-boot-export .' | tar -xf - -C "$lab_dir"
# Preserve preparation diagnostics before shutdown, even if the next boot fails.
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
stop_vm() {
  ssh "${ssh_opts[@]}" lab@127.0.0.1 'sudo sync; sudo systemctl poweroff' || true
  for _ in $(seq 1 30); do
    if ! kill -0 "$vm_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if kill -0 "$vm_pid" 2>/dev/null; then echo 'Guest did not shut down cleanly' >&2; exit 1; fi
  wait "$vm_pid"
}
stop_vm
sha256sum "$lab_dir/$image" > "$repo_root/evidence/bootstrap-preserved-before.sha256"
root_uuid=$(cat "$lab_dir/root-uuid")
if [[ ! "$root_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo 'Invalid root UUID from prepared guest' >&2; exit 1
fi
bootstrap_readonly=,readonly=on
start_vm btrfs -kernel "$lab_dir/vmlinuz" -initrd "$lab_dir/initrd.img" \
  -append "root=UUID=$root_uuid rootfstype=btrfs rootflags=subvol=@ rw console=ttyS0"
wait_ssh
set +e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo bash /opt/mano-lab/scripts/verify_btrfs_root.sh' \
  2>&1 | tee "$repo_root/evidence/guest-verify.log"
result=${PIPESTATUS[0]}
set -e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
if [ "$result" != 0 ]; then exit "$result"; fi
set +e
PYTHONPATH="$repo_root/src" python3 "$repo_root/scripts/serial_rescue.py" \
  --socket "$lab_dir/serial-btrfs.sock" --key "$lab_dir/key" \
  --known-hosts "$lab_dir/known_hosts" --out "$repo_root/evidence"
serial_result=$?
set -e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar --exclude=./report.json -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
if [ "$serial_result" != 0 ]; then exit "$serial_result"; fi
# Preserve first-root report separately; recovered-root observations are a new run.
python3 - "$repo_root/evidence" <<'PY_COPY'
import shutil,sys
from pathlib import Path
root=Path(sys.argv[1])
shutil.copytree(root,root/'first-root',ignore=shutil.ignore_patterns('first-root'))
PY_COPY
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo bash /opt/mano-lab/scripts/prepare_root_recovery.sh' \
  2>&1 | tee "$repo_root/evidence/guest-snapshot.log"
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
stop_vm
start_vm recovery -kernel "$lab_dir/vmlinuz" -initrd "$lab_dir/initrd.img" \
  -append "root=UUID=$root_uuid rootfstype=btrfs rootflags=subvol=@recovery rw console=ttyS0"
wait_ssh
set +e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo bash /opt/mano-lab/scripts/verify_btrfs_root.sh @recovery' \
  2>&1 | tee "$repo_root/evidence/guest-recovery.log"
result=${PIPESTATUS[0]}
set -e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
if [ "$result" = 0 ]; then
  set +e
  PYTHONPATH="$repo_root/src" python3 "$repo_root/scripts/serial_rescue.py" \
    --socket "$lab_dir/serial-recovery.sock" --key "$lab_dir/key" \
    --known-hosts "$lab_dir/known_hosts" --out "$repo_root/evidence"
  result=$?
  set -e
  ssh "${ssh_opts[@]}" lab@127.0.0.1 \
    'sudo tar --exclude=./report.json -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
fi
sha256sum "$lab_dir/$image" > "$repo_root/evidence/bootstrap-preserved-after.sha256"
cmp "$repo_root/evidence/bootstrap-preserved-before.sha256" \
  "$repo_root/evidence/bootstrap-preserved-after.sha256"
if [ "$result" = 0 ]; then
  PYTHONPATH="$repo_root/src" python3 "$repo_root/scripts/audit_phase0.py" \
    --evidence "$repo_root/evidence"
  ssh "${ssh_opts[@]}" lab@127.0.0.1 \
    'sudo env PYTHONPATH=/opt/mano-lab/src python3 /opt/mano-lab/scripts/probe_broker_state.py' \
    > "$repo_root/evidence/broker-state.json"
  ssh "${ssh_opts[@]}" lab@127.0.0.1 \
    'sudo env PYTHONPATH=/opt/mano-lab/src python3 /opt/mano-lab/scripts/probe_broker_ipc.py' \
    > "$repo_root/evidence/broker-ipc.json"
  ssh "${ssh_opts[@]}" lab@127.0.0.1 \
    'sudo env PYTHONPATH=/opt/mano-lab/src python3 /opt/mano-lab/scripts/probe_broker_service.py' \
    > "$repo_root/evidence/broker-service.json"
  ssh "${ssh_opts[@]}" lab@127.0.0.1 \
    'sudo env PYTHONPATH=/opt/mano-lab/src python3 /opt/mano-lab/scripts/probe_resource_pins.py' \
    > "$repo_root/evidence/resource-pins.json"
fi
exit "$result"
