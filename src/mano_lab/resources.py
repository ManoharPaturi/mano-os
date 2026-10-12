"""Parse kernel counters without inventing performance or task-success claims."""

from pathlib import Path


def memory_counters(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        name, separator, values = line.partition(":")
        if not separator:
            continue
        parts = values.split()
        if len(parts) == 2 and parts[1] == "kB" and parts[0].isdigit():
            result[name] = int(parts[0]) * 1024
    return result


def system_memory() -> dict[str, int]:
    counters = memory_counters(Path("/proc/meminfo").read_text())
    required = ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")
    if not all(name in counters for name in required):
        raise RuntimeError("Required Linux memory counters unavailable")
    return {name: counters[name] for name in required}


def process_memory(pid: int) -> dict[str, int]:
    if pid <= 0:
        raise ValueError("Expected live process ID")
    counters = memory_counters(Path(f"/proc/{pid}/status").read_text())
    return {name: counters[name] for name in ("VmRSS", "VmHWM") if name in counters}
