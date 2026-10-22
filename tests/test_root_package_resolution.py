import contextlib
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_protocol.actions import canonical
from mano_protocol.stop_state import Snapshot
from mano_runtime import package_resolution as resolution


class RootResolutionTests(unittest.TestCase):
    def setUp(self):
        from test_package_plans import PackageProtocolTests

        fixture = PackageProtocolTests()
        fixture.setUp()
        self.plan, self.args = fixture.plan, fixture.args
        self.addCleanup(patch.stopall)
        for target, kwargs in (
            ("guard", dict(return_value=None)),
            ("snapshot", dict(return_value=Snapshot(3, False))),
            ("boot", dict(return_value="01234567-89ab-cdef-0123-456789abcdef")),
            ("isolated", dict(return_value=self.plan)),
        ):
            patch.object(resolution, target, **kwargs).start()
        patch.object(resolution.recovery, "layout", return_value={}).start()
        patch.object(resolution.recovery, "locked", side_effect=contextlib.nullcontext).start()
        patch.object(resolution.package_catalog, "load", return_value=({}, {})).start()

    def test_full_resolution_matches_only_inside_lock_context(self):
        events = []

        @contextlib.contextmanager
        def held():
            events.append("locked")
            yield
            events.append("released")

        with patch.object(resolution.recovery, "locked", side_effect=held):
            with resolution.current_plan(self.plan) as receipt:
                self.assertEqual(events, ["locked"])
                self.assertIs(receipt["independent_root_resolution"], True)
                self.assertIs(receipt["install_authorized"], False)
                self.assertIs(receipt["approval_authenticated"], False)
            self.assertEqual(events, ["locked", "released"])
        self.assertEqual(resolution.package_catalog.load.call_count, 2)

    def test_noop_or_byte_delta_is_not_silently_accepted(self):
        altered = self.plan | dict(net_installed_bytes=self.plan["net_installed_bytes"] + 1)
        with self.assertRaisesRegex(ValueError, "Root resolution differs"):
            with resolution.current_plan(altered):
                self.fail("Changed forecast was yielded")

    def test_native_stop_or_generation_change_never_yields_context(self):
        for states in (
            [Snapshot(3, True)],
            [Snapshot(3, False), Snapshot(4, False)],
            [Snapshot(3, False), Snapshot(3, True)],
        ):
            with (
                self.subTest(states=states),
                patch.object(resolution, "snapshot", side_effect=states),
            ):
                with self.assertRaises(PermissionError):
                    with resolution.current_plan(self.plan):
                        self.fail("Native Stop admitted")

    def test_catalog_rechecked_after_worker_before_yield(self):
        with patch.object(
            resolution.package_catalog, "load", side_effect=[({}, {}), ValueError("Changed state")]
        ):
            with self.assertRaisesRegex(ValueError, "Changed state"):
                with resolution.current_plan(self.plan):
                    self.fail("Changed state admitted")

    def test_invalid_scope_never_starts_worker(self):
        for plan in (
            None,
            self.plan | dict(install_authorized=True),
            self.plan | dict(argv=["dpkg"]),
        ):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                with resolution.current_plan(plan):
                    self.fail("Invalid scope admitted")
        resolution.isolated.assert_not_called()


class IsolatedRootWorkerTests(unittest.TestCase):
    def test_ambient_config_and_import_paths_do_not_reach_worker(self):
        from test_package_plans import PackageProtocolTests

        fixture = PackageProtocolTests()
        fixture.setUp()
        packet = SimpleNamespace(
            returncode=0, stderr=b"", stdout=canonical(fixture.plan).encode() + b"\n"
        )
        with (
            patch.object(resolution.package_catalog, "trusted"),
            patch.object(resolution.subprocess, "run", return_value=packet) as run,
            patch.dict(
                os.environ,
                dict(APT_CONFIG="/tmp/hostile", PYTHONPATH="/tmp/hostile", http_proxy="hostile"),
            ),
        ):
            self.assertEqual(resolution.isolated(fixture.args), fixture.plan)
        kwargs = run.call_args.kwargs
        self.assertNotIn("APT_CONFIG", kwargs["env"])
        self.assertNotIn("http_proxy", kwargs["env"])
        self.assertNotEqual(kwargs["env"]["PYTHONPATH"], "/tmp/hostile")
        self.assertEqual(json.loads(kwargs["input"]), fixture.args)
        self.assertEqual(run.call_args.args[0][:3], ["/usr/bin/python3", "-P", "-m"])

    def test_mac_guard_before_layout_or_worker(self):
        with (
            patch.object(resolution.sys, "platform", "darwin"),
            patch.object(resolution.recovery, "layout") as layout,
        ):
            with self.assertRaises(PermissionError):
                with resolution.current_plan({}):
                    self.fail("Root helper admitted on Mac")
            layout.assert_not_called()
