#!/usr/bin/env python3
"""Audit the recovered CI evidence, not an operator's execution authorization."""

import argparse
import json
from pathlib import Path

from mano_lab.architecture import audit
from mano_lab.evidence import Probe, write_report

parser = argparse.ArgumentParser()
parser.add_argument("--evidence", type=Path, required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
result = audit(
    args.evidence,
    repo / "docs/spec-v2.1.md",
    repo / "docs/architecture/0008-phase0-original-spec-audit.md",
)
(args.evidence / "architecture-audit.json").write_text(json.dumps(result, indent=2) + "\n")
prior = json.loads((args.evidence / "report.json").read_text())
probes = [Probe(**p) for p in prior["probes"] if p["name"] != "full-phase0-architecture-audit"]
probes.append(
    Probe(
        "P0-12",
        "full-phase0-architecture-audit",
        "pass",
        "Original-spec evidence audit; GO for Phase1 development only",
        ("architecture-audit.json",),
    )
)
write_report(args.evidence, probes, prior["environment"])
print(json.dumps({"decision": result["decision"], "production_execution_authorized": False}))
