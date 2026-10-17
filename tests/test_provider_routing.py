import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mano_protocol.actions import canonical
from mano_protocol.transport import Peer
from mano_provider.service import generation, main


class ProviderRoutingTests(unittest.TestCase):
    def setUp(self):
        self.packet = canonical(dict(schema_version="1.0", operation="generate", body={})).encode()
        self.broker = SimpleNamespace(pw_uid=999, pw_gid=999)
        self.config = dict(
            provider="openai", model="synthetic", max_output_tokens=100, enabled=False
        )

    def test_wrong_actor_never_reads_policy_or_key(self):
        with (
            patch("mano_provider.service.pwd.getpwnam", return_value=self.broker),
            patch("mano_provider.service.load_policy") as policy,
            patch("mano_provider.service.load_key") as key,
        ):
            with self.assertRaises(ValueError):
                generation(object(), self.packet, Peer(42, 1004, 1004))
            policy.assert_not_called()
            key.assert_not_called()

    def test_disabled_or_invalid_job_never_reads_key_or_invokes_provider(self):
        with (
            patch("mano_provider.service.pwd.getpwnam", return_value=self.broker),
            patch("mano_provider.service.load_policy", return_value=self.config) as policy,
            patch("mano_provider.service.current_boot", return_value="boot"),
            patch("mano_provider.service.load_key") as key,
            patch("mano_provider.service.execute") as execute,
        ):
            for enabled in (False, True):
                policy.return_value = self.config | {"enabled": enabled}
                with self.assertRaises(ValueError):
                    generation(object(), self.packet, Peer(42, 999, 999))
            key.assert_not_called()
            execute.assert_not_called()

    def test_validated_route_loads_key_only_after_authorization(self):
        events = []
        connection = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        with (
            patch("mano_provider.service.pwd.getpwnam", return_value=self.broker),
            patch(
                "mano_provider.service.load_policy", return_value=self.config | {"enabled": True}
            ),
            patch("mano_provider.service.current_boot", return_value="boot"),
            patch(
                "mano_provider.service.authorize",
                side_effect=lambda *a, **k: events.append("check"),
            ),
            patch(
                "mano_provider.service.load_key",
                side_effect=lambda: events.append("key") or "ci-synthetic-key",
            ),
            patch("mano_provider.service.execute") as execute,
        ):
            generation(connection, self.packet, Peer(42, 999, 999))
            self.assertEqual(events, ["check", "key"])
            execute.assert_called_once_with(
                connection,
                self.packet,
                Peer(42, 999, 999),
                config=self.config | {"enabled": True},
                credential="ci-synthetic-key",
                boot_id="boot",
            )

    def test_main_successful_sealed_route_does_not_send_extra_plain_json(self):
        connection = Mock()
        with (
            patch("mano_provider.service.verify_current"),
            patch("mano_provider.service.socket.fromfd", return_value=connection),
            patch("mano_provider.service.receive", return_value=(Peer(42, 999, 999), self.packet)),
            patch("mano_provider.service.generation") as generate,
        ):
            self.assertEqual(main(), 0)
            generate.assert_called_once_with(connection, self.packet, Peer(42, 999, 999))
            connection.send.assert_not_called()
            connection.close.assert_called_once()
