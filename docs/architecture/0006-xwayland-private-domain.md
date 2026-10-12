# ADR 0006: grant task X11 explicitly without sharing raw desktop authority

Status: implemented for CI acceptance; no production GUI capability is enabled.

Linux abstract UNIX sockets do not use filesystem permissions. Put the trusted
compositor/internal XWayland server in a private network namespace so its abstract
X11 endpoint is unreachable from the supervisor and other task namespaces. Move
its file socket into a root-controlled parent and grant only that socket plus a
generated task-only MIT-MAGIC-COOKIE Xauthority file to the worker sandbox.

The wrapper keeps the internal wlroots/Sway XWayland relationship and adds `-auth`
with a fresh session cookie; it never uses blanket `-ac` or a human user's cookie.
Cookie bytes travel to xauth on stdin and are never logged or uploaded as evidence.
Workers receive no raw Wayland/Sway IPC/human runtime path. Distinct task principals
remain required; this lab fixture tests one dedicated task desktop.

Require an actual X11 query and mapped X11 window, different network namespace IDs,
abstract socket denial outside plus a positive connection inside the server's
namespace, and a filesystem socket denial for the separate core principal. Rerun
all Wayland forged-bind and legacy security/boot/recovery tests in the same CI.

This is a bounded XWayland contract, not general compatibility, authenticated user
approval, physical input provenance or arbitrary application automation.

Primary references:
- [Linux UNIX socket semantics](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Debian XWayland options](https://manpages.debian.org/trixie/xwayland/Xwayland.1.en.html)
