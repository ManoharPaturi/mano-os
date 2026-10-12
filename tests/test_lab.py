import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_lab.disk import GIB, classify
from mano_lab.evidence import REQUIRED, Probe, gate, write_report
from mano_lab.sandbox import command, require_patched


class DiskTests(unittest.TestCase):
    def test_thresholds(self):
        self.assertFalse(classify(100 * GIB, 91 * GIB, 9 * GIB).can_download)
        self.assertEqual(classify(100 * GIB, 84 * GIB, 16 * GIB).level, "warning")
        self.assertEqual(classify(1000 * GIB, 910 * GIB, 90 * GIB).level, "warning")
        self.assertEqual(classify(100 * GIB, 70 * GIB, 30 * GIB).level, "ok")

    def test_invalid(self):
        for counters in [(0, 0, 0), (10, -1, 2), (10, 9, 3)]:
            with self.assertRaises(ValueError):
                classify(*counters)


class EvidenceTests(unittest.TestCase):
    def test_pending_never_promotes(self):
        self.assertEqual(gate([])["decision"], "no-go")
        probes = [Probe(i, i, "pass", "real", ("log",)) for i in REQUIRED]
        self.assertEqual(gate(probes)["decision"], "go")
        probes.append(Probe("P0-09", "physical", "pending", "requires hardware"))
        self.assertEqual(gate(probes)["decision"], "no-go")

    def test_artifacts_required_and_validated(self):
        with self.assertRaises(ValueError):
            Probe("P0-01", "VM", "pass", "model says yes")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "log").write_text("real output")
            report = write_report(root, [Probe("P0-01", "VM", "pass", "x", ("log",))], {})
            self.assertEqual(len(report["artifact_sha256"]["log"]), 64)
            self.assertFalse(report["production_security_claim"])
            for name in ["missing", "../outside"]:
                with self.assertRaises(ValueError):
                    write_report(root, [Probe("P0-01", "VM", "pass", "x", (name,))], {})


class SandboxTests(unittest.TestCase):
    def test_no_fallback(self):
        with patch("mano_lab.sandbox.platform.system", return_value="Darwin"):
            with self.assertRaises(RuntimeError):
                require_patched()

    def test_mounts(self):
        with tempfile.TemporaryDirectory() as d:
            args = command(Path(d).resolve(), ["python3", "-c", "print(1)"])
            self.assertIn("--unshare-all", args)
            self.assertIn("--clearenv", args)
            self.assertNotIn("--share-net", args)
            self.assertNotIn("/run/user", args)
            self.assertEqual(args[-3:], ["python3", "-c", "print(1)"])

    def test_rejections(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            for target, argv in [
                (link, ["true"]),
                (Path("/"), ["true"]),
                (root, []),
                (root, ["bad\x00arg"]),
            ]:
                with self.assertRaises(ValueError):
                    command(target, argv)


class MergeTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("merge", "scripts/merge_checked.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.pr = {
            "state": "OPEN",
            "isDraft": False,
            "baseRefName": "main",
            "headRefOid": "abc",
            "mergeStateStatus": "CLEAN",
            "statusCheckRollup": [
                {
                    "__typename": "CheckRun",
                    "name": n,
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                }
                for n in self.module.EXPECTED
            ],
        }

    def test_success(self):
        self.assertEqual(self.module.validate(self.pr), "abc")

    def test_non_success_blocks(self):
        for conclusion in ["FAILURE", "SKIPPED", "CANCELLED", None]:
            self.pr["statusCheckRollup"][0]["conclusion"] = conclusion
            with self.assertRaises(ValueError):
                self.module.validate(self.pr)
        self.pr["statusCheckRollup"][0]["conclusion"] = "SUCCESS"
        self.pr["statusCheckRollup"].append(
            {"__typename": "StatusContext", "context": "extra", "state": "FAILURE"}
        )
        with self.assertRaises(ValueError):
            self.module.validate(self.pr)

    def test_missing_and_stale_block(self):
        self.pr["statusCheckRollup"].pop()
        with self.assertRaises(ValueError):
            self.module.validate(self.pr)
