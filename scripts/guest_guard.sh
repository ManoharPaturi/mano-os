#!/usr/bin/env bash
# Accident-prevention guard, NOT a boundary against a malicious root principal.
require_disposable_guest() {
  if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
    echo 'Disposable Linux guest root context required.' >&2
    return 2
  fi
  if [ ! -f /etc/mano-lab-disposable ] || \
     [ "$(cat /etc/mano-lab-disposable)" != mano-phase0-ci ]; then
    echo 'CI guest marker absent; refusing host changes.' >&2
    return 2
  fi
  case "$(systemd-detect-virt --vm)" in
    kvm|qemu) ;;
    *) echo 'This experiment requires its disposable QEMU guest.' >&2; return 2 ;;
  esac
}
