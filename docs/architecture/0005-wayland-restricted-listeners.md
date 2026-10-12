# ADR 0005: test privileged protocol denial through restricted Wayland listeners

Status: implementation in CI; architecture remains NO-GO pending all Phase 0 proof.

Sway 1.10.1's `filter_global` denies its privileged globals for clients attached
through security-context listeners. Merely hiding globals in a registry dump is
insufficient: an attacker can guess a raw global number and try to bind it.

The lab's display/controller principal owns the raw compositor runtime. A separate
`mano-worker` principal cannot traverse that runtime and receives only a
security-context listener. Bubblewrap mounts the single restricted socket, not
its parent directory, raw Sway IPC, human runtime, X11 server or input devices.
The worker must create an ordinary surface successfully, see no privileged globals,
and receive server protocol errors when binding the controller's real privileged
IDs. A trusted raw client must still bind a harmless virtual-keyboard manager as a
positive control, without creating an input device or synthesizing events.

The installed protocol XML generates the C client definitions; its digest and
all actual raw/restricted inventories and bind-attempt results are retained.
Listener lifetime is held by the controller's private close FD. The worker gets
neither that FD nor the security-context manager, including by forged numeric bind.

This is a lab fixture, not a production broker, grant or input service. Actual
XWayland client isolation, full app/browser contracts, authentic approvals and
trusted stop remain explicit gates. Denying all X11 sockets to this particular
worker does not claim that authorized XWayland applications already work.

Primary sources inspected:
- [Sway 1.10.1 server filtering](https://github.com/swaywm/sway/blob/1.10.1/sway/server.c)
- [Wayland protocol source](https://gitlab.freedesktop.org/wayland/wayland-protocols/-/blob/main/staging/security-context/security-context-v1.xml)
