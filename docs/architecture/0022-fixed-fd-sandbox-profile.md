# Fixed descriptor sandbox profile

The trusted launcher command compiler requires a real unprivileged allocated task
identity, broker-owned private workspace O_PATH FD and separate broker-held cwd
O_PATH FD. It accepts argv only after the option terminator. Root invocation is
rejected. Descriptor ancestry and current action/grant/epoch authority belong to
the trusted registry/launcher; this compiler alone does not establish either.

The initial profile has mandatory user/cgroup, PID, mount, IPC and network
namespaces, no further user namespaces, zero capabilities and a cleared minimal
environment. OS runtime files are read-only; mano code/native helper locations
are hidden. Host /etc, /var, /run/user, input devices and session sockets are not
mounted. Only the supplied workspace/cwd directories are writable host mounts.
Temporary directories and a private /dev are task-local.

Bubblewrap 0.12.0 bind-fd uses the supplied descriptor and compares the mounted
device/inode against it, aborting a substitution race. The profile requires the
patched Debian package gate, uses no fallback and retains no task-supplied host
paths. The trusted launching process must pass exactly the two descriptors and
close all other FDs. Bubblewrap consumes the mount descriptors before task exec.
Primary source:
https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c

The disposable CI fixture places the whole operator probe in a 128 MiB/24-process/
20-percent-CPU systemd scope before it allocates or drops to a task identity. It
opens descriptors, renames the workspace and replaces its old name with /etc,
then launches fixed test code as the unprivileged task. The test checks retained
workspace/cwd identity, actual output, protected-host hash, read-only OS tree,
an unreachable live host listener, absent host IPC/device paths, synthetic secret
environment removal, inherited socket closure, NNP and zero effective caps.

This is operator-driven CI execution, not the broker executor or a model tool.
Seccomp and Landlock are explicitly unmeasured here. Runtime cgroup creation,
bounded output, trusted root launch protocol, live lease consumption, independent
stop/revoke, effect journal transitions and verification remain required before
connecting public terminal requests or satisfying the Phase 1 golden gate.
