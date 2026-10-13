# ADR0016: kernel-pinned resource object custody

Status: candidate until Linux unit and real Debian kernel CI.

Workspace accepts only a trusted, already-provisioned directory descriptor. It
retains a non-inheritable duplicate, not a path name supplied by an agent. A small
root-installed native library uses SYS_openat2 from Linux headers, O_PATH/CLOEXEC
and RESOLVE_BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV. Unsupported kernels fail;
there is no weaker pathname fallback. Native library and all parent directories
must be root-owned, not writable by group/others or symlinks.

Each requested relative path is strictly parsed, then opened under the pinned root
in one kernel operation. fstat validates target type; regular hardlinked files deny.
O_PATH avoids opening FIFO/device I/O before type checking. Directory descriptors
support approved cwd/mount construction. Targets and root retain their actual
inode identity after name replacement/rename. FDs are closed deterministically.

This is object custody, not immutable content or a complete write policy. A file
can change after pinning; the initial hardlink check does not prevent later link
creation by another writer. Namespace/DAC/export restrictions, trusted registration,
lease checks, controlled read/write descriptors and independent snapshots/verifiers
remain required. There is no executor, public registration endpoint, auto FD recovery
or resource-ID mapping wired here. Lost descriptors must not be reconstructed from
agent paths; production restart needs explicit authority renewal/registration.

Linux CI installs the root-owned library and actually runs resource tests (Mac
skips Linux-only tests). Debian probe validates target/root replacement, symlink
and hardlink/FIFO denial, no FD inheritance, unchanged external sentinel and actual
tmpfs mount-crossing EXDEV. Existing full VM/PAM/stop/security suites remain required.
No local VM, mounts or library installation occurs on the development Mac.

Next: trusted resource registry/provisioning and actual sandbox/cgroup/seccomp/
Landlock execution tied to grants and stop leases. Then verifier, prompt/model/
LangGraph and original Phase1 golden OS-boundary gate; full v2.1 scope remains active.

Reference: [Linux openat2 resolution and error semantics](https://man7.org/linux/man-pages/man2/openat2.2.html).
