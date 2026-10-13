"""Race-safe Linux process-exit observation, not an execution authority."""

from pathlib import Path


def exited_or_zombie(pid):
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True  # Reaped during open/read; other errors remain failures.
    return "\nState:\tZ" in status
