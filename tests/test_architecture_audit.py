import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from mano_lab.architecture import audit, verify_hashes


class AuditIntegrityTests(unittest.TestCase):
    def test_tamper_and_unhashed_evidence_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "evidence"
            file.write_text("real recorded result")
            report = {
                "artifact_sha256": {"evidence": hashlib.sha256(file.read_bytes()).hexdigest()},
                "probes": [{"name": "probe", "status": "pass", "artifacts": ["evidence"]}],
            }
            verify_hashes(root, report)
            file.write_text("changed result")
            with self.assertRaisesRegex(ValueError, "Artifact changed"):
                verify_hashes(root, report)
            report["artifact_sha256"] = {}
            with self.assertRaisesRegex(ValueError, "Unhashed"):
                verify_hashes(root, report)

    def test_escaped_artifact_rejected_even_with_matching_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "inner"
            root.mkdir()
            outside = root.parent / "outside"
            outside.write_text("outside")
            report = {
                "artifact_sha256": {"../outside": hashlib.sha256(outside.read_bytes()).hexdigest()},
                "probes": [],
            }
            with self.assertRaisesRegex(ValueError, "Invalid artifact path"):
                verify_hashes(root, report)

    def test_missing_coverage_and_specification_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text(json.dumps({"artifact_sha256": {}, "probes": []}))
            (root / "first-root").mkdir()
            (root / "first-root/report.json").write_text(
                json.dumps({"artifact_sha256": {}, "probes": []})
            )
            spec = Path("docs/spec-v2.1.md")
            adr = root / "adr"
            adr.write_text("review")
            with self.assertRaisesRegex(ValueError, "Missing requirement"):
                audit(root, spec, adr)
            changed = root / "changed-spec"
            changed.write_text(spec.read_text() + "changed\n")
            with self.assertRaisesRegex(ValueError, "specification changed"):
                audit(root, changed, adr)


class StartupEvidenceTests(unittest.TestCase):
    def test_missing_invalid_and_misordered_measurements_fail_closed(self):
        from mano_lab.architecture import validate_startup

        browser = {
            "clock": "monotonic",
            "cold_start_verified": False,
            "process_launch_to_control_ready_seconds": 1.0,
            "process_launch_to_page_ready_seconds": 2.0,
        }
        office = {
            "clock": "monotonic",
            "cold_start_verified": False,
            "process_launch_to_document_ready_seconds": 3.0,
        }
        validate_startup(browser, office)
        for value in (None, 0, -1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_startup(
                    browser, {**office, "process_launch_to_document_ready_seconds": value}
                )
        with self.assertRaises(ValueError):
            validate_startup(None, office)
        with self.assertRaises(ValueError):
            validate_startup({**browser, "process_launch_to_page_ready_seconds": 0.5}, office)
        with self.assertRaises(ValueError):
            validate_startup(browser, {**office, "cold_start_verified": True})
