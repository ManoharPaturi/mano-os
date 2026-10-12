#!/usr/bin/env bash
# Root setup is scoped to the throwaway guest. No installed mano runtime yet.
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
test ! -f /etc/mano-lab-prepared
cd /opt/mano-lab
mkdir -p evidence
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends python3 python3-venv bubblewrap \
  sway xwayland foot grim wayland-utils dbus-user-session at-spi2-core \
  python3-pyatspi xdg-dbus-proxy btrfs-progs snapper chromium libreoffice-writer \
  libreoffice-calc fonts-dejavu-core jq procps rsync gcc libc6-dev pkg-config libwayland-dev wayland-protocols xauth x11-utils xfonts-base
apt-get clean
# Use system Chromium; never run playwright install/download a separate browser.
python3 -m venv /usr/local/lib/mano-browser
/usr/local/lib/mano-browser/bin/pip install playwright==1.63.0
/usr/local/lib/mano-browser/bin/pip freeze > evidence/browser-python-packages.txt
# Every installed package is recorded; no security floor downgrade.
dpkg-query -W > evidence/packages.tsv
uname -a > evidence/kernel.txt
python3 -c 'import sys; sys.path.insert(0,"src"); from mano_lab.sandbox import require_patched; print(require_patched())'
proxy_version=$(dpkg-query -W '-f=${Version}' xdg-dbus-proxy)
dpkg --compare-versions "$proxy_version" ge '0.1.6-1+deb13u3'
useradd -m -s /bin/bash mano-agent
useradd -m -s /bin/bash mano-human
useradd -m -s /bin/bash mano-core
useradd -m -s /bin/bash mano-worker
cat > /etc/tmpfiles.d/mano-lab.conf <<'TMPFILES'
d /run/mano-agent 0700 mano-agent mano-agent -
d /run/mano-human 0700 mano-human mano-human -
d /run/mano-worker 0700 mano-worker mano-worker -
TMPFILES
mkdir -p /run/mano-agent /run/mano-human /var/lib/mano-broker /etc/mano
chown mano-agent:mano-agent /run/mano-agent
chown mano-human:mano-human /run/mano-human
chmod 700 /run/mano-agent /run/mano-human /var/lib/mano-broker
printf 'protected-policy
' > /etc/mano/sentinel
printf 'protected-journal
' > /var/lib/mano-broker/sentinel
chmod 600 /etc/mano/sentinel /var/lib/mano-broker/sentinel
# Only the second virtio disk is formatted, and only in this guest.
test "$(lsblk -dn -o SIZE /dev/vdb | tr -d ' ')" = 2G
if blkid /dev/vdb >/dev/null 2>&1 || findmnt -rn -S /dev/vdb >/dev/null; then
  echo 'Data target already has a filesystem or mount; refusing format.' >&2
  exit 2
fi
mkfs.btrfs /dev/vdb
mkdir -p /lab-btrfs
mount /dev/vdb /lab-btrfs
btrfs subvolume create /lab-btrfs/work
snapper --no-dbus -c mano-lab create-config /lab-btrfs/work
printf 'before
' > /lab-btrfs/work/sentinel
snapshot=$(snapper --no-dbus -c mano-lab create --print-number --description phase0)
printf 'after
' > /lab-btrfs/work/sentinel
snapper --no-dbus -c mano-lab undochange "$snapshot..0" /lab-btrfs/work/sentinel
# Exact content is required; reporting an exit code is not sufficient.
test "$(cat /lab-btrfs/work/sentinel)" = before
snapper --no-dbus -c mano-lab list > evidence/snapper.txt
findmnt --json > evidence/mounts.json
free -b > evidence/memory-before.txt
chmod 0755 scripts/xwayland_lab_wrapper.sh
bash scripts/build_wayland_probe.sh
touch /etc/mano-lab-prepared
