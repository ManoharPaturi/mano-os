#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/guest_guard.sh"
require_disposable_guest
cd /opt/mano-lab
mkdir -p work/wayland-build
protocol=/usr/share/wayland-protocols/staging/security-context/security-context-v1.xml
test -f "$protocol"
sha256sum "$protocol" > evidence/security-context-protocol.sha256
wayland-scanner client-header "$protocol" work/wayland-build/security-context-v1-client-protocol.h
wayland-scanner private-code "$protocol" work/wayland-build/security-context-v1-protocol.c
cc -std=c11 -Wall -Wextra -Werror -Iwork/wayland-build \
  tests/desktop/wayland_context_probe.c work/wayland-build/security-context-v1-protocol.c \
  $(pkg-config --cflags --libs wayland-client) -o work/wayland-build/wayland-context-probe
install -m 0755 work/wayland-build/wayland-context-probe /usr/local/bin/mano-wayland-probe
