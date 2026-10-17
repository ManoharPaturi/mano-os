import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.price_config import load_policy, parse
from mano_broker.state import Denied
from mano_protocol.actions import canonical


class RootPricingTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(
            schema_version="1.0",
            provider="openai",
            enabled=True,
            price=dict(
                model="synthetic",
                revision="ci-only",
                expires_unix=1000,
                input_context_tokens=1000,
                max_output_tokens=100,
                input_micro_usd_per_million=1001,
                output_micro_usd_per_million=2001,
            ),
        )

    def test_exact_root_price_policy_and_disabled_shipped_default(self):
        policy = parse(canonical(self.policy).encode(), wall_time=100)
        self.assertEqual(policy.model, "synthetic")
        default = (
            Path(__file__).resolve().parents[1] / "packaging/config/pricing.json"
        ).read_bytes()
        with self.assertRaises(Denied):
            parse(default, wall_time=100)

    def test_malformed_stale_or_unbounded_root_policy_is_denied(self):
        for change in (
            dict(expires_unix=100),
            dict(max_output_tokens=True),
            dict(input_context_tokens=-1),
            dict(input_micro_usd_per_million=1.5),
            dict(unknown="field"),
        ):
            value = self.policy | {"price": self.policy["price"] | change}
            with self.assertRaises((ValueError, TypeError)):
                parse(canonical(value).encode(), wall_time=100)
        with self.assertRaises(ValueError):
            parse(b'{"enabled":true,"enabled":false}', wall_time=100)
        with self.assertRaises(ValueError):
            parse(canonical(self.policy | {"enabled": 1}).encode(), wall_time=100)

    def test_wrong_identity_or_directory_cannot_read_pricing_credential(self):
        with (
            patch(
                "mano_broker.price_config.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=999)
            ),
            patch("mano_broker.price_config.os.geteuid", return_value=1004),
            patch("mano_broker.price_config.private_file") as read,
        ):
            with self.assertRaises(Denied):
                load_policy(wall_time=100)
            read.assert_not_called()
        with (
            patch(
                "mano_broker.price_config.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=999)
            ),
            patch("mano_broker.price_config.os.geteuid", return_value=999),
            patch.dict("os.environ", {"CREDENTIALS_DIRECTORY": "/tmp/agent-pricing"}),
            patch("mano_broker.price_config.private_file") as read,
        ):
            with self.assertRaises(Denied):
                load_policy(wall_time=100)
            read.assert_not_called()

    def test_loader_uses_only_fixed_credential_name_and_bound(self):
        directory = "/run/credentials/mano-broker.service"
        root = SimpleNamespace(st_mode=0o40755, st_uid=0)
        with (
            patch(
                "mano_broker.price_config.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=999)
            ),
            patch("mano_broker.price_config.os.geteuid", return_value=999),
            patch.dict("os.environ", {"CREDENTIALS_DIRECTORY": directory}),
            patch("mano_broker.price_config.Path.lstat", return_value=root),
            patch(
                "mano_broker.price_config.private_file",
                return_value=json.dumps(self.policy).encode(),
            ) as read,
        ):
            self.assertEqual(load_policy(wall_time=100).revision, "ci-only")
            read.assert_called_once_with(Path(directory), "pricing", 4096)
