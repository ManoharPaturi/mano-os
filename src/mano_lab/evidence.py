"""Conservative phase gates. Reports are evidence indexes, not grant authority."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REQUIRED = tuple(f"P0-{i:02d}" for i in range(1, 13))


@dataclass(frozen=True)
class Probe:
    issue: str
    name: str
    status: str
    detail: str
    artifacts: tuple[str, ...] = ()

    def __post_init__(self):
        if self.issue not in REQUIRED or self.status not in {"pass", "fail", "pending"}:
            raise ValueError("Invalid probe")
        if self.status == "pass" and not self.artifacts:
            raise ValueError("Passing evidence must reference artifacts")


def gate(probes: list[Probe]) -> dict:
    missing = []
    for issue in REQUIRED:
        matches = [p for p in probes if p.issue == issue]
        if not matches or any(p.status != "pass" for p in matches):
            missing.append(issue)
    return {"decision": "go" if not missing else "no-go", "incomplete_issues": missing}


def write_report(directory: Path, probes: list[Probe], environment: dict) -> dict:
    # Hash referenced artifacts, refusing path escapes and missing files.
    directory.mkdir(parents=True, exist_ok=True)
    root = directory.resolve()
    hashes = {}
    for probe in probes:
        for name in probe.artifacts:
            artifact = (root / name).resolve()
            if not artifact.is_relative_to(root) or not artifact.is_file():
                raise ValueError(f"Missing or off-directory evidence: {name}")
            hashes[name] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    report = {
        "schema_version": "1.0",
        "recorded_at": datetime.now(UTC).isoformat(),
        "environment": environment,
        "gate": gate(probes),
        "probes": [asdict(p) for p in probes],
        "artifact_sha256": hashes,
        "production_security_claim": False,
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
