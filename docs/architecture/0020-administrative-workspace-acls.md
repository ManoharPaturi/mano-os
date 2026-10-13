# Fresh workspaces with inherited access

The trusted Linux root operator can create a fresh workspace under the fixed
root-owned `/var/lib/mano-workspaces` parent. This function is not setuid, is not
exposed to a model, and does not create accounts or execute requested commands.
It accepts existing validated human and worker identities and returns a fresh
path plus a non-inheritable O_PATH descriptor for the provisioning adapter.

The broker owns the directory; the assigned worker's primary group provides
task access. The human has a named ACL entry. Default ACLs preserve broker and
human access to ordinarily created output files and nested directories. Other
task identities must be denied by the kernel. Explicit private creation modes
can reduce the ACL mask, and subsequent chmod can remove access: this is not a
guarantee of immutable artifact custody or independent verification.

The helper checks fixed parent ownership and permissions, opens directories
without following symlinks, creates a random fresh name, and uses a retained
directory descriptor with the fixed system setfacl executable. Failure cleanup
only attempts to remove that new empty directory. It never recursively deletes
existing data. The caller owns the returned descriptor and must close it.

The disposable CI fixture creates two distinct workspaces, tests actual worker
and human output, nested inheritance, private-mode denial, cross-task EACCES,
and invalid identity rejection without new directories. This establishes DAC
and ACL behavior only. Separate task accounts, sandbox launch, cgroups, seccomp,
Landlock, stop/revoke, operation execution and artifact verification remain
required before the Phase 1 gate.
