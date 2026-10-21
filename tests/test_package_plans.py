import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def test_requested_rows_must_match_final_changes(self):
        for field, replacement in (("candidate", "9.0"), ("installed", "0.1")):
            plan = copy.deepcopy(self.plan)
            plan["requested"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                result(plan, expected=self.args)
        missing = self.plan | dict(changes=[], download_bytes=0)
        with self.assertRaises(ValueError):
            result(missing, expected=self.args)
        removed = copy.deepcopy(self.plan)
        removed["requested"][0]["installed"] = "1:5.02-1"
        removed["changes"][0].update(operation="remove", installed="1:5.02-1",
                                     candidate=None, archive_sha256=None, download_bytes=0)
        removed["download_bytes"] = 0
        with self.assertRaises(ValueError):
            result(removed, expected=self.args)

    def test_no_change_requires_already_installed_requested_candidate(self):
        plan = copy.deepcopy(self.plan)
        plan.update(changes=[], download_bytes=0, net_installed_bytes=0)
        plan["requested"][0]["installed"] = plan["requested"][0]["candidate"]
        self.assertEqual(result(plan, expected=self.args), plan)

    def test_operation_requires_consistent_version_transition(self):
        for operation, installed, candidate in (
            ("install", "1", "2"), ("reinstall", None, "2"),
            ("reinstall", "1", "2"), ("upgrade", None, "2"),
            ("upgrade", "2", "2"), ("downgrade", None, "2"),
            ("downgrade", "2", "2"),
        ):
            plan = copy.deepcopy(self.plan)
            plan["requested"][0].update(installed=installed, candidate=candidate)
            plan["changes"][0].update(operation=operation, installed=installed,
                                      candidate=candidate)
            with self.subTest(operation=operation, installed=installed), \
                    self.assertRaises(ValueError):
                result(plan, expected=self.args)
        for operation, installed, candidate in (
            ("install", None, "2"), ("reinstall", "2", "2"),
            ("upgrade", "1", "2"), ("downgrade", "2", "1"),
        ):
            plan = copy.deepcopy(self.plan)
            plan["requested"][0].update(installed=installed, candidate=candidate)
            plan["changes"][0].update(operation=operation, installed=installed,
                                      candidate=candidate)
            self.assertEqual(result(plan, expected=self.args), plan)

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


class FinalResolutionTests(unittest.TestCase):
    def test_native_apt_upgrade_flag_for_absent_package_means_new_install(self):
        from mano_broker.package_solver import change_operation

        package = SimpleNamespace(installed=None, marked_delete=False,
                                  marked_downgrade=False, marked_upgrade=True,
                                  marked_reinstall=False)
        self.assertEqual(change_operation(package), "install")
        package.installed = SimpleNamespace(version="1")
        self.assertEqual(change_operation(package), "upgrade")
        package.marked_upgrade = False
        package.marked_reinstall = True
        self.assertEqual(change_operation(package), "reinstall")
        package.marked_reinstall = False
        with self.assertRaises(ValueError):
            change_operation(package)
        package.marked_delete = True
        self.assertEqual(change_operation(package), "remove")

    def cache(self, later_mark):
        first = SimpleNamespace(candidate=SimpleNamespace(version="1", downloadable=True),
                                installed=None, marked_delete=False,
                                mark_install=lambda **_: None)
        second = SimpleNamespace(candidate=SimpleNamespace(version="2", downloadable=True),
                                 installed=None, marked_delete=False,
                                 mark_install=lambda **_: later_mark(first))

        class Cache(dict):
            broken_count = 0

        return Cache(alpha=first, bravo=second)

    def test_later_resolution_changes_are_reflected_in_requested_versions(self):
        from mano_broker.package_solver import resolve_requests

        cache = self.cache(lambda first: setattr(first.candidate, "version", "3"))
        rows = resolve_requests(cache, ["alpha", "bravo"])
        self.assertEqual([row["candidate"] for row in rows], ["3", "2"])

    def test_later_resolution_cannot_remove_requested_package(self):
        from mano_broker.package_solver import resolve_requests

        for mutate in (
            lambda first: setattr(first, "marked_delete", True),
            lambda first: setattr(first, "candidate", None),
            lambda first: setattr(first.candidate, "downloadable", False),
        ):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                resolve_requests(self.cache(mutate), ["alpha", "bravo"])


class DebianKeyringPolicyTests(unittest.TestCase):
    def test_fixed_regular_keyring_target_without_symlink_exception(self):
        from mano_runtime import package_catalog as refresh

        expected = Path("/usr/share/keyrings/debian-archive-keyring.pgp")
        self.assertEqual(package_catalog.KEYRING, expected)
        self.assertEqual(refresh.KEYRING, expected)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "keyring.pgp"
            target.write_bytes(b"keyring")
            link = Path(directory) / "keyring.gpg"
            link.symlink_to(target.name)
            # The target policy changes; the no-symlink boundary does not.
            with self.assertRaises(ValueError):
                package_catalog.trusted(link)


class DebianCloudRepositoryTests(unittest.TestCase):
    def test_fixed_cloud_aliases_require_one_unambiguous_suite(self):
        from mano_runtime import package_catalog as refresh

        with tempfile.TemporaryDirectory() as directory:
            lists = Path(directory)
            with patch.object(refresh, "LISTS", lists):
                for suite, prefixes, uri in refresh.REPOS:
                    self.assertTrue(uri.startswith("http://deb.debian.org/"))
                    cloud = next(p for p in prefixes if p.startswith("_etc_apt_mirrors_"))
                    filename = lists / (cloud + "_dists_" + suite + "_InRelease")
                    filename.write_bytes(b"signed metadata requires later verification")
                    self.assertEqual(refresh.repository_prefix(suite, prefixes),
                                     cloud + "_dists_" + suite)
                    duplicate = lists / (prefixes[0] + "_dists_" + suite + "_InRelease")
                    duplicate.write_bytes(b"ambiguous")
                    with self.assertRaises(ValueError):
                        refresh.repository_prefix(suite, prefixes)
                    duplicate.unlink()
                    filename.unlink()
                    (lists / ("unapproved_dists_" + suite + "_InRelease")).touch()
                    with self.assertRaises(ValueError):
                        refresh.repository_prefix(suite, prefixes)


class SignedReleaseMetadataTests(unittest.TestCase):
    def test_security_component_and_signed_index_path_are_distinct(self):
        from mano_runtime import package_catalog as refresh

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "input", root / "signed"
            for suite, component in (("trixie", "main"), ("trixie-updates", "main"),
                                     ("trixie-security", "updates/main")):
                plain = root / (suite + ".verified-release")
                for accepted, observed in ((True, component), (False, "contrib")):
                    target = root / (suite + str(accepted) + ".signed")
                    metadata = (
                        f"Origin: Debian\nCodename: {suite}\nArchitectures: amd64 all\n"
                        f"Components: {observed}\nDate: Tue, 20 Oct 2026 00:00:00 UTC\n"
                        "Valid-Until: Tue, 27 Oct 2026 00:00:00 UTC\nSHA256:\n "
                        + "a" * 64 + " 42 main/binary-amd64/Packages\n"
                    )
                    def verify(*args, plain=plain, metadata=metadata, **kwargs):
                        self.assertEqual(args[0], "/usr/bin/gpgv")
                        self.assertEqual(args[args.index("--keyring") + 1], str(refresh.KEYRING))
                        plain.write_text(metadata)
                    with patch.object(refresh, "read", return_value=b"signed packet"), \
                         patch.object(refresh, "command", side_effect=verify):
                        if accepted:
                            repo, expected, _ = refresh.signed_release(
                                source, target, suite, 1792454400)
                            self.assertEqual(repo["suite"], suite)
                            self.assertEqual(expected, ("a" * 64, 42))
                        else:
                            with self.assertRaises(ValueError):
                                refresh.signed_release(source, target, suite, 1792454400)


class PrivateAptRootTests(unittest.TestCase):
    def test_cache_scratch_does_not_follow_catalog_directory(self):
        from mano_broker import package_solver

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            catalog, root = base / "catalog", base / "scratch"
            lists = catalog / "inputs/lists"
            lists.mkdir(parents=True)
            root.mkdir()
            for name in ("sources.list", "debian-archive-keyring.gpg", "status", "extended_states"):
                (catalog / "inputs" / name).write_bytes(name.encode())
            index = lists / "debian_dists_trixie_main_binary-amd64_Packages"
            index.write_bytes(b"signed immutable index")
            before = {p.name: p.read_bytes() for p in lists.iterdir()}
            with patch.object(package_solver, "CATALOG", catalog):
                package_solver.prepare_apt_root(root)
            private = root / "var/lib/apt/lists"
            self.assertFalse(private.is_symlink())
            self.assertTrue((private / index.name).is_symlink())
            self.assertEqual((private / index.name).resolve(), index)
            (private / "partial/cache-scratch").write_bytes(b"temporary")
            self.assertEqual(before, {p.name: p.read_bytes() for p in lists.iterdir()})
            self.assertEqual(list((root / "etc/apt/apt.conf.d").iterdir()), [])
            self.assertEqual(list((root / "var/lib/dpkg/updates").iterdir()), [])
            self.assertEqual((root / "var/lib/dpkg/status").resolve(),
                             catalog / "inputs/status")


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
