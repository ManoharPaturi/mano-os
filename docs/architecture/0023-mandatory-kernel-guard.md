# Mandatory unprivileged kernel guard

The fixed sandbox command now enters a root-installed, read-only native guard
before task argv. The compiler rejects non-root-owned, writable or symlinked
guard paths. The guard itself refuses root/mismatched effective identity or
missing NNP, closes all extra descriptors, and enforces Landlock and seccomp
before exec. No root privilege or model-facing root endpoint is added.

Landlock requires ABI 5 or newer, including truncate/refer/device ioctl rights.
All known ABI-5 filesystem rights are handled. Reading/executing is limited to
the OS runtime; /proc is readable; private /dev allows device reads/writes and
ioctl. Only workspace/cwd and private temp/home directories permit ordinary
creation/removal/write/execute. Device node creation remains denied. TCP bind
and connect have no Landlock grants. Newer ABI-specific rights are not claimed.
The helper never drops unsupported required rights or runs without Landlock.

Seccomp uses a native-architecture deny profile, with incompatible architecture
execution killed. It denies namespace/mount, keyring, ptrace/process-memory,
BPF/perf, io_uring, kernel/module/device mutation and credential-changing calls.
INET/INET6/NETLINK/PACKET socket creation is denied. Normal fork/clone execution
is permitted inside the cgroup, but all namespace clone flags are rejected.
clone3 returns ENOSYS so libc can use the filtered clone path; that path still
rejects namespaces. This is defense in depth, not a universal syscall allowlist.

The native single-thread guard requires /etc to be writable before enforcement,
then requires an actual EACCES on private /etc file creation. It also requires
EPERM for harmless unshare(0) and no-change setresuid calls after seccomp loads.
Failures exit 125 before task exec. The VM test independently checks those
denials, Seccomp=2, allowed workspace writes/subprocesses and child inheritance.
All earlier descriptor, namespace, network, host-IPC and cgroup checks remain.

Primary Landlock design reference:
https://docs.kernel.org/userspace-api/landlock.html
ABI-5 ioctl UAPI bit 15 is declared when older Ubuntu build headers lack the
symbol; runtime ABI >= 5 remains mandatory. CI compiles with strict warnings on
Ubuntu and compiles/runs the real guard on the disposable Debian guest.

Current local Python checks do not verify native Linux enforcement. Real CI is
required before acceptance or merge. Broker lease/epoch/stop integration,
production launch lifecycle and independent effect verification remain pending.
