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
pointer_protocol=tests/desktop/protocols/wlr-virtual-pointer-unstable-v1.xml
sha256sum "$pointer_protocol" > evidence/virtual-pointer-protocol.sha256
wayland-scanner client-header "$pointer_protocol" work/wayland-build/wlr-virtual-pointer-unstable-v1-client-protocol.h
wayland-scanner private-code "$pointer_protocol" work/wayland-build/wlr-virtual-pointer-unstable-v1-protocol.c
keyboard_protocol=tests/desktop/protocols/virtual-keyboard-unstable-v1.xml
sha256sum "$keyboard_protocol" > evidence/virtual-keyboard-protocol.sha256
wayland-scanner client-header "$keyboard_protocol" work/wayland-build/virtual-keyboard-unstable-v1-client-protocol.h
wayland-scanner private-code "$keyboard_protocol" work/wayland-build/virtual-keyboard-unstable-v1-protocol.c
cc -std=c11 -Wall -Wextra -Werror -Iwork/wayland-build \
  tests/desktop/wayland_context_probe.c work/wayland-build/security-context-v1-protocol.c \
  work/wayland-build/wlr-virtual-pointer-unstable-v1-protocol.c \
  work/wayland-build/virtual-keyboard-unstable-v1-protocol.c \
  $(pkg-config --cflags --libs wayland-client xkbcommon) -o work/wayland-build/wayland-context-probe
install -m 0755 work/wayland-build/wayland-context-probe /usr/local/bin/mano-wayland-probe
