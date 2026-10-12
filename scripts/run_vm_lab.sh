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
EOF
printf 'instance-id: mano-phase0
local-hostname: mano-phase0
' > "$lab_dir/meta-data"
cloud-localds "$lab_dir/seed.img" "$lab_dir/user-data" "$lab_dir/meta-data"
accel=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=kvm; fi
printf 'QEMU accelerator: %s\n' "$accel" | tee "$repo_root/evidence/accelerator.txt"
qemu-system-x86_64 -accel "$accel" -m 4096 -smp 2 -display none \
  -serial "file:$repo_root/evidence/serial.log" \
  -drive "file=$lab_dir/$image,format=qcow2,if=virtio" \
  -drive "file=$lab_dir/data.qcow2,format=qcow2,if=virtio" \
  -drive "file=$lab_dir/seed.img,format=raw,if=virtio" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
  > "$repo_root/evidence/qemu.log" 2>&1 &
vm_pid=$!
trap 'kill "$vm_pid" 2>/dev/null || true' EXIT
ssh_opts=(-i "$lab_dir/key" -p 2222 -o BatchMode=yes -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$lab_dir/known_hosts")
ready=0
for _ in $(seq 1 90); do
  if ssh "${ssh_opts[@]}" lab@127.0.0.1 true 2>/dev/null; then ready=1; break; fi
  kill -0 "$vm_pid"
  sleep 5
done
if [ "$ready" != 1 ]; then echo 'VM SSH boot timed out' >&2; exit 1; fi
ssh "${ssh_opts[@]}" lab@127.0.0.1 'sudo cloud-init status --wait'
# Transfer only the tracked checkout; never CI credentials or host home.
git -C "$repo_root" archive HEAD | ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo mkdir -p /opt/mano-lab; sudo tar -xf - -C /opt/mano-lab'
set +e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo bash /opt/mano-lab/scripts/guest_lab.sh' 2>&1 | tee "$repo_root/evidence/guest.log"
result=${PIPESTATUS[0]}
set -e
ssh "${ssh_opts[@]}" lab@127.0.0.1 \
  'sudo tar -cf - -C /opt/mano-lab/evidence .' | tar -xf - -C "$repo_root/evidence"
exit "$result"
