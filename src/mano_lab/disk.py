"""Read-only storage accounting; no cleanup or filesystem mutation."""

import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

GIB = 1024**3


@dataclass(frozen=True)
class DiskStatus:
    total_bytes: int
    free_bytes: int
    used_percent: float
    level: str

    @property
    def can_download(self) -> bool:
        return self.level != "critical"

    def to_dict(self) -> dict:
        return asdict(self)


def classify(total: int, used: int, free: int) -> DiskStatus:
    if total <= 0 or min(used, free) < 0 or used + free > total:
        raise ValueError("Invalid disk counters")
    percent = used / total * 100
    level = (
        "critical" if free < 10 * GIB else "warning" if (free < 20 * GIB or percent >= 90) else "ok"
    )
    return DiskStatus(total, free, round(percent, 2), level)


def inspect(path: Path) -> DiskStatus:
    usage = shutil.disk_usage(path)
    return classify(usage.total, usage.used, usage.free)
