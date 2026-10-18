"""Race-safe Linux process-exit observation, not an execution authority."""

from pathlib import Path


def exited_or_zombie(pid):
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True  # Reaped during open/read; other errors remain failures.
    # Linux reports both Z (zombie) and X (dead); a reaped zombie can briefly
    # transition through X while /proc still exists. See proc_pid_status(5).
    for line in status.splitlines():
        if line.startswith('State:'):
            fields = line.partition(':')[2].split()
            return bool(fields) and fields[0] in {'Z', 'X'}
    return False  # Missing/malformed status is not evidence of process exit.
