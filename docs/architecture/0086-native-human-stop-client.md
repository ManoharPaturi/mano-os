# Fixed human Stop client and independent shortcut

Install a non-setuid C executable at /usr/libexec/mano-stop. It accepts no arguments,
connects only to /run/mano-stopd/human.sock, sends exactly S, and requires a Root-owned
listener plus exactly one Root sender credential and the exact stopped response.
It rejects denied, extra/truncated payloads, ancillary descriptors, wrong senders
and timeouts. Received descriptors are closed. The listener may belong to systemd
while the actual reply comes from the Root stop daemon; their PIDs need not match.
Two-second socket timeouts bound communication. There is no rearm or password path.

The Sway human configuration binds Super+Shift+Backspace directly to the fixed native
client, independently of GTK and the Python core. The command can also run from the
human terminal, where it prints acknowledgement or an explicit unacknowledged error.
Shortcut output goes to the compositor's logs; it is not a visual Stop-status UI.
Rearm remains a separate PAM-authenticated protected terminal operation.

A stopped reply proves the daemon durably latched Stop and accepted the kernel kill
writes. It does not independently prove process exit. Client output therefore says
termination was requested. The installed VM witness separately checks task/core
cgroup emptiness, detached child and provider exit, grant revocation and frozen
broker/launcher state after invoking the production executable as the human UID.

A private mount namespace in the disposable guest exercises fake Root replies for
valid, denied, extra bytes, truncation, passed descriptors, a non-Root sender on a
Root-created connection, a non-Root listener, and timeout. These fixture permissions do not replace the
real protected socket. Real wrong-task-UID execution and extra arguments must fail
without changing the armed generation. The normal Sway session parses the added
binding, but physical key provenance and keyboard behavior remain unverified.
