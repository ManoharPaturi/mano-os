# Administrative task factory

mano-task / python -m mano_broker.task_factory is a trusted Linux root operator
entry point that accepts only bounded prompt text on stdin. It reads the protected
human UID policy, requires a login identity, allocates a fresh locked nologin task
account through the existing quota/lock-guarded allocator, creates the fixed-parent
private workspace and sends its O_PATH FD to the broker's protected provision
socket. Caller UID, human UID, workspace pathname and host commands cannot be
selected by a model input.

The factory authenticates root socket activation and the actual broker UID/GID
reply. It returns task/resource/context plus operator workspace/account metadata;
it neither issues a grant nor runs an agent or command. Normal users are denied
before allocation. The initial profile is supervised/internal. Authenticated human
prompt routing and a narrowly hardened lifecycle service remain separate work.

On an uncertain reply the factory never retries allocation/provisioning or deletes
user data. It closes the held descriptor and preserves the locked identity and
workspace for operator recovery; UIDs are never silently recycled. Tests cover
unprivileged/malformed input and one-shot uncertain-response FD closure/preservation.

The actual installed VM fixture now invokes the factory instead of manually
allocating/provisioning its main terminal task. Native PAM, core CLI, sandbox,
checkpoint, exact-file, Stop and rearm gates continue from that real task context.
This operator interface is not yet a human-session Send button or a model tool.
Acceptance requires current-head VM evidence and all previous security checks.
