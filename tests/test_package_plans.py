import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_broker import package_catalog
from mano_core.packages import PackagePlan, proposal
from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.packages import arguments, result
from mano_runtime.package_catalog import guard


class PackageProtocolTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(names=["sl"], catalog_id="a" * 64)
        self.proposed = proposal(
            task_id="b" * 32,
            resource_id="c" * 32,
            names=["sl"],
            catalog_id="a" * 64,
            key="package-plan",
            reason="Preview dependencies",
        )
        self.plan = dict(
            schema_version="1.0",
            names=["sl"],
            catalog_id="a" * 64,
            status_sha256="d" * 64,
            solver="python3-apt/3.0.0",
            requested=[dict(name="sl", installed=None, candidate="1:5.02-1")],
            changes=[
                dict(
                    name="sl",
                    operation="install",
                    installed=None,
                    candidate="1:5.02-1",
                    architecture="amd64",
                    archive_sha256="e" * 64,
                    download_bytes=100,
                    installed_bytes=400,
                )
            ],
            download_bytes=100,
            net_installed_bytes=400,
            peak_space_bytes=None,
            free_space_bytes_at_catalog=1024**3,
            catalog_expires_at=2000,
            install_authorized=False,
            effect_verified=False,
            host_archive_cache_considered=False,
            network_used=False,
            maintainer_scripts_executed=False,
        )

    def test_typed_names_reject_options_sources_paths_versions_and_duplicate_scope(self):
        self.assertEqual(arguments(self.args), self.args)
        for names in (
            ["-y"],
            ["a/b"],
            ["sl=1"],
            ["sl:amd64"],
            ["https://example/sl"],
            ["sl\n"],
            ["sl", "sl"],
            ["sl", "bash"],
            ["sl"] * 9,
            [],
            [True],
        ):
            with self.subTest(names=names), self.assertRaises(ValueError):
                arguments(self.args | dict(names=names))
        for extra in (
            dict(argv=["apt-get"]),
            dict(options=["-y"]),
            dict(apply=True),
            dict(cwd="/"),
        ):
            with self.assertRaises(ValueError):
                ActionRequest.parse(
                    canonical(
                        self.proposed | dict(grant_id="f" * 32, args=self.args | extra)
                    ).encode()
                )

    def test_result_cannot_claim_install_authority_hide_downloads_or_change_names(self):
        self.assertEqual(result(self.plan, expected=self.args), self.plan)
        for mutation in (
            dict(install_authorized=True),
            dict(network_used=0),
            dict(download_bytes=0),
            dict(names=["bash"]),
            dict(peak_space_bytes=0),
            dict(effect_verified=True),
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                result(self.plan | mutation, expected=self.args)
        changed = copy.deepcopy(self.plan)
        changed["changes"][0]["archive_sha256"] = None
        with self.assertRaises(ValueError):
            result(changed, expected=self.args)

    def test_sdk_uncertain_start_is_not_retried(self):
        calls = []

        def denied(packet):
            calls.append(packet)
            return dict(schema_version="1.0", ok=False, error="denied")

        with self.assertRaises(ValueError):
            PackagePlan.start(denied, proposed=self.proposed, grant_id="f" * 32)
        self.assertEqual(len(calls), 1)

    def test_catalog_administration_rejects_mac_or_unprivileged_identity(self):
        with (
            patch("mano_runtime.package_catalog.sys.platform", "darwin"),
            self.assertRaises(PermissionError),
        ):
            guard()
        with (
            patch("mano_runtime.package_catalog.sys.platform", "linux"),
            patch("mano_runtime.package_catalog.os.geteuid", return_value=1000),
            self.assertRaises(PermissionError),
        ):
            guard()


class CatalogStalenessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base, self.lists = self.root / "catalog", self.root / "lists"
        self.base.mkdir()
        self.lists.mkdir()
        self.source = self.lists / "deb.debian.org_debian_dists_trixie_InRelease"
        self.source.write_bytes(b"input metadata")
        self.status, self.keys, self.updates = (
            self.root / "status",
            self.root / "keys",
            self.root / "updates",
        )
        self.status.write_bytes(b"installed state")
        self.keys.write_bytes(b"keyring")
        self.updates.mkdir()
        self.patches = [
            patch.object(package_catalog, "BASE", self.base),
            patch.object(package_catalog, "STATUS", self.status),
            patch.object(package_catalog, "KEYRING", self.keys),
            patch.object(package_catalog, "LISTS", self.lists),
            patch.object(package_catalog, "UPDATES", self.updates),
            patch.object(package_catalog, "trusted", side_effect=lambda p, **_: p.lstat()),
            patch.object(package_catalog.time, "time", return_value=1001),
        ]
        for mocked in self.patches:
            mocked.start()
        self.body = dict(
            format="debian13-amd64-main-v1",
            created_at=1000,
            expires_at=2000,
            signed_indexes_verified=True,
            architecture="amd64",
            solver="fixture",
            status_sha256=hashlib.sha256(self.status.read_bytes()).hexdigest(),
            source_inputs={self.source.name: package_catalog.source_identity(self.source)},
            files={
                "inputs/debian-archive-keyring.gpg": dict(
                    sha256=hashlib.sha256(self.keys.read_bytes()).hexdigest(), bytes=7
                )
            },
        )
        self.identifier = hashlib.sha256(canonical(self.body).encode()).hexdigest()
        target = self.base / "catalogs" / self.identifier
        target.mkdir(parents=True)
        (target / "manifest.json").write_text(
            canonical(self.body | dict(catalog_id=self.identifier))
        )
        (self.base / "active.json").write_text(json.dumps(dict(catalog_id=self.identifier)))

    def tearDown(self):
        for mocked in reversed(self.patches):
            mocked.stop()
        self.temp.cleanup()

    def test_status_index_keyring_expiry_and_supersession_refuse_stale_approval(self):
        self.assertEqual(package_catalog.load(self.identifier)[1]["catalog_id"], self.identifier)
        for path in (self.status, self.keys, self.source):
            data = path.read_bytes()
            path.write_bytes(b"changed")
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                package_catalog.load(self.identifier)
            path.write_bytes(data)
        # Rebuild no authority here: freshness, active ID and dirty journal are
        # independently rejected before any forecast can start.
        with (
            patch.object(package_catalog.time, "time", return_value=2001),
            self.assertRaises(ValueError),
        ):
            package_catalog.load(self.identifier)
        with self.assertRaises(ValueError):
            package_catalog.load("0" * 64)
        (self.updates / "0000").write_bytes(b"pending")
        with self.assertRaises(ValueError):
            package_catalog.current_status()
