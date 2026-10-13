# ADR0015: native OS-authenticated approval adapter

Status: candidate; native compilation and real PAM runtime evidence pending CI.

A small root native daemon receives one fixed named human systemd packet listener.
It accepts only the UID in root-owned mode0600 /etc/mano/human.uid under a protected
root directory. Policy excludes root/system and named agent/core/worker/broker
accounts. Kernel connection plus per-message credentials must match; passed FDs,
truncation, inherited connections and unknown frame versions are denied.

Binary version1 uses one version byte and one opcode: view1 followed by32ASCII
approval-ID hex bytes (34total); confirm2 followed by32ID+64nonce+64digest hex,
2-byte big-endian password byte length and1-256UTF8 password bytes (164-byte header).
No UID, username, paths or command are provided by the client. Native helper maps
kernel UID to the OS username; PAM service is fixed mano-approve. It authenticates,
checks account policy and unchanged PAM_USER, then sends only bound confirmation
through the root control socket. Nonce/digest are checked against a fresh broker view
before PAM, and broker rechecks expiry/epoch/boot/single-use after authentication.

The control client validates root socket creator plus the non-root broker's actual
per-message reply UID. Human client validates root creator/reply credentials. Root
and broker paths/units/code are protected; no arbitrary root helper, command execution
or credential environment is added. Native service has zero capabilities, NNP,
seccomp/address-family/filesystem restrictions,16tasks/64MiB/20%CPU/128FD limits,
20-second watchdog and no core dumps. Installed binary is0755, not setuid.

Native helper wipes its own received password buffer on every completed request.
PAM owns successful conversation response copies; this does not guarantee erasure
inside PAM/libc. Python human UI keeps an ephemeral password string and wipes its
mutable packet; immutable runtime copies cannot be guaranteed erased. No password
is logged or stored in the broker journal, arguments or environment.

Human CLI requires TTY input/output, displays escaped broker-owned structured JSON
and explicit yes plus OS password. The explanation is labeled untrusted. GUI prompt
integration and manual/physical TTY test remain additional Phase1 work.

CI compiles native code with C11/strict warnings/fortify/stack protector/RELRO on
Ubuntu and Debian. Disposable Debian installs actual units/PAM config and sets a
random synthetic human password by stdin, then tests wrong identity/password/nonce,
valid PAM grant issuance, replay denial and exact grant use. Native UID/capability/
NNP/seccomp/binary hash recorded. Password never enters evidence; account re-locked
and fixed fixtures removed. This is synthetic OS authentication, not physical-input
provenance or a real operator's consent. Full existing VM/stop tests still required.

Next: pinned resources, actual sandbox/cgroup/seccomp/Landlock execution, native
stop/verifier, prompt UI integration and minimal terminal/model/LangGraph with the
original Phase1 golden task/OS-boundary gate. Full v2.1 and later physical/installer
requirements remain active. No host service or model is installed by development.
